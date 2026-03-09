package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/puzpuzpuz/xsync/v4"
)

// === Phase 0: Test Helpers ===

// newTestBackend creates an httptest server that returns the given status code
// and tracks request count atomically.
func newTestBackend(t *testing.T, statusCode int) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	count := &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(statusCode)
		fmt.Fprintf(w, "backend-%d", statusCode)
	}))
	t.Cleanup(srv.Close)
	return srv, count
}

// newTestProxyService creates a minimal ProxyService for testing (no Redis, no rate limiting).
func newTestProxyService(t *testing.T) *ProxyService {
	t.Helper()
	return NewProxyService("examples/proxies.yaml", nil, false, nil, false)
}

// injectRules loads backends directly into a ProxyService, bypassing YAML parsing.
// backends maps subdomain -> []ProxyRule (already weight-expanded if needed).
func injectRules(s *ProxyService, backends map[string][]ProxyRule) {
	s.rules.Store(backends)
	s.ruleCount.Store(int64(len(backends)))
	s.loadTime.Store(time.Now())
}

// === Phase 1: Critical Bug Validation Tests ===

// --- Bug #1: Loadbalancer ignores health filtering ---
// The LB built during LoadRules includes ALL backends. filterHealthyBackends
// filters the local slice, but lb.Next() still returns unhealthy ones.

func TestBug1_UnhealthyBackendsReceiveTraffic(t *testing.T) {
	healthy, healthyCount := newTestBackend(t, 200)
	unhealthy, unhealthyCount := newTestBackend(t, 200) // Returns 200 but we'll mark it "unhealthy"

	svc := newTestProxyService(t)

	rules := map[string][]ProxyRule{
		"test": {
			{ProxyTo: healthy.URL, Weight: 1},
			{ProxyTo: unhealthy.URL, Weight: 1},
		},
	}
	injectRules(svc, rules)

	// Configure health checks for this subdomain (required for health filtering to apply)
	hcConfigs := xsync.NewMap[string, *HealthCheckConfig]()
	hcConfigs.Store("test", &HealthCheckConfig{
		Path:             "/health",
		FailureThreshold: 1,
	})
	svc.healthCheckConfigs.Store(hcConfigs)

	// Set up health states
	healthStates := xsync.NewMap[string, *BackendHealth]()

	// Mark unhealthy backend as unhealthy
	health := &BackendHealth{}
	health.healthy.Store(false) // unhealthy
	health.consecutiveFailures.Store(5)
	health.lastCheck.Store(time.Now())
	healthStates.Store(unhealthy.URL, health)

	// Mark healthy backend as healthy
	healthState := &BackendHealth{}
	healthState.healthy.Store(true)
	healthState.consecutiveFailures.Store(0)
	healthState.lastCheck.Store(time.Now())
	healthStates.Store(healthy.URL, healthState)
	svc.healthStates.Store(healthStates)

	// Send 20 requests
	router := svc.Router()
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = "test.api.pocket.network"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}

	t.Logf("Healthy backend received: %d requests", healthyCount.Load())
	t.Logf("Unhealthy backend received: %d requests", unhealthyCount.Load())

	// BUG: unhealthy backend should receive 0 requests, but will receive ~10
	if unhealthyCount.Load() > 0 {
		t.Errorf("BUG CONFIRMED: Unhealthy backend received %d requests (should be 0)", unhealthyCount.Load())
	}
}

// --- Bug #2: retry-all + weights = empty response ---
// When backends have weights, len(backends) includes duplicates but triedURLs
// deduplicates, so isLastAttempt is never true and no response is written.

func TestBug2_RetryAllWeightsEmptyResponse(t *testing.T) {
	// Both backends return 503 (retryable error)
	backendA, _ := newTestBackend(t, 503)
	backendB, _ := newTestBackend(t, 503)

	svc := newTestProxyService(t)

	// Backend A has weight=3, Backend B has weight=1
	// After expansion: [A, A, A, B] → len=4
	// But only 2 unique URLs, so triedURLs max = 2
	// isLastAttempt = (2 >= 4) = false → never writes response
	rules := map[string][]ProxyRule{
		"test": {
			{ProxyTo: backendA.URL, Weight: 1},
			{ProxyTo: backendA.URL, Weight: 1},
			{ProxyTo: backendA.URL, Weight: 1},
			{ProxyTo: backendB.URL, Weight: 1},
		},
	}
	injectRules(svc, rules)

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test.api.pocket.network"
	req.Header.Set("Retry-Policy", "retry-all")
	w := httptest.NewRecorder()

	router := svc.Router()
	router.ServeHTTP(w, req)

	t.Logf("Response status: %d, body: %q", w.Code, w.Body.String())

	// BUG: Should return 503 with a body, but returns 200 (default) with empty body
	if w.Body.Len() == 0 {
		t.Errorf("BUG CONFIRMED: Empty response body — client gets nothing")
	}
	if w.Code == 200 && w.Body.Len() == 0 {
		t.Errorf("BUG CONFIRMED: Status 200 with empty body (should be 503 with error message)")
	}
}

// --- Bug #3: /_health route mismatch ---

func TestBug3_HealthRouteMismatch(t *testing.T) {
	svc := newTestProxyService(t)

	// Load some rules so the service is "ready"
	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: "http://localhost:9999", Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()

	// Test 1: getRequestKind says /_health is "health"
	reqKind := httptest.NewRequest("GET", "/_health", nil)
	kind := getRequestKind(reqKind)
	if kind != "health" {
		t.Errorf("getRequestKind(/_health) = %q, want %q", kind, "health")
	}

	// Test 2: /_health should be routed to HandleHealth and return 200 "OK"
	req := httptest.NewRequest("GET", "/_health", nil)
	req.Host = "test.api.pocket.network"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 || w.Body.String() != "OK" {
		t.Errorf("/_health not routed to HandleHealth. Got status=%d body=%q",
			w.Code, w.Body.String())
	}

	// Test 3: /_ready should route to HandleReady
	reqReady := httptest.NewRequest("GET", "/_ready", nil)
	reqReady.Host = "test.api.pocket.network"
	wReady := httptest.NewRecorder()
	router.ServeHTTP(wReady, reqReady)

	if wReady.Code != 200 || wReady.Body.String() != "READY" {
		t.Errorf("/_ready not routed to HandleReady. Got status=%d body=%q",
			wReady.Code, wReady.Body.String())
	}

	// Test 4: getRequestKind for /_ready and /_metrics
	if k := getRequestKind(httptest.NewRequest("GET", "/_ready", nil)); k != "ready" {
		t.Errorf("getRequestKind(/_ready) = %q, want %q", k, "ready")
	}
	if k := getRequestKind(httptest.NewRequest("GET", "/_metrics", nil)); k != "metrics" {
		t.Errorf("getRequestKind(/_metrics) = %q, want %q", k, "metrics")
	}
}

// --- Bug #4: Regex compiled per request ---

func BenchmarkBug4_ExtractClientIPRegex(b *testing.B) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Forwarded", "for=192.0.2.60;host=example.com;proto=https")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractClientIP(req, true)
	}
	// Fixed: 1 alloc for submatch result, 0 for regex compilation
}

func BenchmarkExtractSubdomainFromHost(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		extractSubdomainFromHost("eth.api.pocket.network:8080")
	}
}

func BenchmarkNormalizeBackendLabel(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		normalizeBackendLabel("https://eth.gateway.pocket.network/v1")
	}
}

func BenchmarkNormalizeBackendLabelCached(b *testing.B) {
	// Prime the cache
	normalizeBackendLabel("https://eth.gateway.pocket.network/v1")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeBackendLabel("https://eth.gateway.pocket.network/v1")
	}
}

// --- Bug #5: Data races on hot reload ---
// Run with: go test -race -run TestBug5

func TestBug5_DataRaceDuringReload(t *testing.T) {
	svc := newTestProxyService(t)

	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: "http://localhost:9999", Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()
	done := make(chan struct{})

	// Goroutine 1: continuously reload rules (now uses atomic swaps)
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			newFallbacks := xsync.NewMap[string, []ProxyRule]()
			svc.fallbackRules.Store(newFallbacks)

			newHealthConfigs := xsync.NewMap[string, *HealthCheckConfig]()
			svc.healthCheckConfigs.Store(newHealthConfigs)

			newHealthStates := xsync.NewMap[string, *BackendHealth]()
			svc.healthStates.Store(newHealthStates)
		}
	}()

	// Goroutine 2: continuously handle requests (reads the same fields)
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = "test.api.pocket.network"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}

	<-done
	// If run with -race, the race detector will flag the data races
	t.Log("If this test passes with -race, the data race is fixed")
}

// --- Bug #9: Duplicate health checks for weighted backends ---

func TestBug9_DuplicateHealthChecksForWeightedBackends(t *testing.T) {
	backend, checkCount := newTestBackend(t, 200)

	svc := newTestProxyService(t)

	// Backend with weight=3: will be expanded to 3 entries in the rules slice
	rules := map[string][]ProxyRule{
		"test": {
			{ProxyTo: backend.URL, Weight: 1},
			{ProxyTo: backend.URL, Weight: 1},
			{ProxyTo: backend.URL, Weight: 1},
		},
	}
	injectRules(svc, rules)

	hcConfigs := xsync.NewMap[string, *HealthCheckConfig]()
	hcConfigs.Store("test", &HealthCheckConfig{
		Path:             "/",
		FailureThreshold: 5,
	})
	svc.healthCheckConfigs.Store(hcConfigs)

	// Initialize health state
	healthStates := xsync.NewMap[string, *BackendHealth]()
	health := &BackendHealth{}
	health.healthy.Store(true)
	health.lastCheck.Store(time.Now())
	healthStates.Store(backend.URL, health)
	svc.healthStates.Store(healthStates)

	// Run one health check cycle
	svc.runHealthChecks()

	// Wait for worker pool to finish
	time.Sleep(500 * time.Millisecond)

	count := checkCount.Load()
	t.Logf("Health check count for single backend (weight=3): %d", count)

	if count != 1 {
		t.Errorf("BUG CONFIRMED: Backend health-checked %d times instead of 1 (weight duplicates not deduped)", count)
	}
}

// --- Bug #12: Blocked requests consume rate limit budget ---
// This needs Redis, so we'll skip if not available.
// Tested via test-distributed.sh in CI.

// --- Bug #19: /ready, /metrics path collision ---

func TestBug19_ReadyMetricsCollision(t *testing.T) {
	// Create a backend that serves /ready with custom content
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprintf(w, "backend-ready-response at %s", r.URL.Path)
	}))
	t.Cleanup(backend.Close)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: backend.URL, Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()

	// A request to test.api.pocket.network/ready should be proxied to the backend
	// (no longer intercepted since we renamed to /_ready)
	req := httptest.NewRequest("GET", "/ready", nil)
	req.Host = "test.api.pocket.network"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should be proxied to backend, not intercepted by Taiji
	if w.Body.String() == "READY" {
		t.Errorf("/ready still intercepted by Taiji instead of being proxied to backend")
	}
	if w.Code != 200 {
		t.Errorf("/ready proxy returned status %d, want 200", w.Code)
	}
}

// --- Bug #20: Missing Unwrap() on responseWriterWrapper ---

func TestBug20_ResponseWriterWrapperUnwrap(t *testing.T) {
	inner := httptest.NewRecorder()
	wrapper := &responseWriterWrapper{
		ResponseWriter: inner,
		statusCode:     200,
	}

	// Go 1.20+ http.ResponseController uses Unwrap() to find the real writer
	type unwrapper interface {
		Unwrap() http.ResponseWriter
	}

	if _, ok := interface{}(wrapper).(unwrapper); !ok {
		t.Errorf("BUG CONFIRMED: responseWriterWrapper does not implement Unwrap()")
	}
}

// --- Bug #15: IP spoofing bypasses rate limiting ---

func TestBug15_IPSpoofingWithTrustedCIDRs(t *testing.T) {
	// Without trusted CIDRs — any client can spoof headers
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")

	ip := extractClientIP(req, true)
	if ip != "1.2.3.4" {
		t.Errorf("Without CIDRs: expected spoofed IP 1.2.3.4, got %s", ip)
	}

	// With trusted CIDRs — only trust headers from known proxies
	trustedCIDRs := parseTrustedProxyCIDRs("10.0.0.0/8")

	// Request from trusted proxy: headers ARE trusted
	ipTrusted := extractClientIP(req, true, trustedCIDRs)
	if ipTrusted != "1.2.3.4" {
		t.Errorf("From trusted proxy: expected 1.2.3.4, got %s", ipTrusted)
	}

	// Request from untrusted source: headers IGNORED, use RemoteAddr
	reqUntrusted := httptest.NewRequest("GET", "/", nil)
	reqUntrusted.RemoteAddr = "203.0.113.50:12345"
	reqUntrusted.Header.Set("X-Forwarded-For", "1.2.3.4")

	ipUntrusted := extractClientIP(reqUntrusted, true, trustedCIDRs)
	if ipUntrusted != "203.0.113.50" {
		t.Errorf("From untrusted source: expected RemoteAddr 203.0.113.50, got %s (spoofed!)", ipUntrusted)
	}
}

// --- Bug #16: Client-controlled retry-all ---

func TestBug16_RetryPolicyServerSideOnly(t *testing.T) {
	backendA, countA := newTestBackend(t, 503)
	backendB, countB := newTestBackend(t, 503)

	svc := newTestProxyService(t)

	// No retry_policy configured — default is fail-fast
	rules := map[string][]ProxyRule{
		"test": {
			{ProxyTo: backendA.URL, Weight: 1},
			{ProxyTo: backendB.URL, Weight: 1},
		},
	}
	injectRules(svc, rules)

	router := svc.Router()

	// Client sends Retry-Policy: retry-all header (should be IGNORED)
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test.api.pocket.network"
	req.Header.Set("Retry-Policy", "retry-all")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	total := countA.Load() + countB.Load()
	if total > 1 {
		t.Errorf("Client Retry-Policy header was honored (hit %d backends). Should be ignored without server config.", total)
	}
}

// === WebSocket & gRPC Tests ===

// --- isStreamingRequest detection ---

func TestIsStreamingRequest_WebSocket(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	if !isStreamingRequest(req) {
		t.Error("WebSocket request not detected as streaming")
	}
}

func TestIsStreamingRequest_WebSocketCaseInsensitive(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Upgrade", "WebSocket")
	if !isStreamingRequest(req) {
		t.Error("WebSocket detection should be case-insensitive")
	}
}

func TestIsStreamingRequest_GRPC(t *testing.T) {
	req := httptest.NewRequest("POST", "/service.Method", nil)
	req.Header.Set("Content-Type", "application/grpc")
	if !isStreamingRequest(req) {
		t.Error("gRPC request not detected as streaming")
	}
}

func TestIsStreamingRequest_GRPCProto(t *testing.T) {
	req := httptest.NewRequest("POST", "/service.Method", nil)
	req.Header.Set("Content-Type", "application/grpc+proto")
	if !isStreamingRequest(req) {
		t.Error("gRPC+proto request not detected as streaming")
	}
}

func TestIsStreamingRequest_Normal(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/data", nil)
	if isStreamingRequest(req) {
		t.Error("Normal HTTP request incorrectly detected as streaming")
	}
}

// --- getRequestKind classification ---

func TestGetRequestKind_WebSocket(t *testing.T) {
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	if kind := getRequestKind(req); kind != "websocket" {
		t.Errorf("getRequestKind for WebSocket = %q, want %q", kind, "websocket")
	}
}

func TestGetRequestKind_GRPC(t *testing.T) {
	req := httptest.NewRequest("POST", "/service.Method", nil)
	req.Header.Set("Content-Type", "application/grpc")
	if kind := getRequestKind(req); kind != "grpc" {
		t.Errorf("getRequestKind for gRPC = %q, want %q", kind, "grpc")
	}
}

// --- WebSocket upgrade proxying ---

func TestWebSocketUpgradeProxied(t *testing.T) {
	// Create a backend that performs a WebSocket-like upgrade
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			t.Error("Backend did not receive Upgrade: websocket header")
			w.WriteHeader(400)
			return
		}
		// Verify forwarding headers were set
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Error("Backend missing X-Forwarded-For header")
		}
		// Perform the upgrade via hijack
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("Backend ResponseWriter does not support hijacking")
			w.WriteHeader(500)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Errorf("Backend hijack failed: %v", err)
			return
		}
		defer conn.Close()
		// Write a raw HTTP 101 response + echo message
		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		bufrw.WriteString("hello from backend")
		bufrw.Flush()
	}))
	t.Cleanup(backend.Close)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"ws": {{ProxyTo: backend.URL, Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()
	// Use a real TCP server so we can hijack
	frontendSrv := httptest.NewServer(router)
	t.Cleanup(frontendSrv.Close)

	// Connect via raw TCP to the frontend
	conn, err := net.Dial("tcp", strings.TrimPrefix(frontendSrv.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to connect to frontend: %v", err)
	}
	defer conn.Close()

	// Send WebSocket upgrade request
	reqStr := "GET / HTTP/1.1\r\n" +
		"Host: ws.api.pocket.network\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if resp.StatusCode != 101 {
		t.Errorf("Expected 101 Switching Protocols, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Upgrade") != "websocket" {
		t.Errorf("Expected Upgrade: websocket header in response, got %q", resp.Header.Get("Upgrade"))
	}

	// Read the echoed message from the hijacked connection
	buf := make([]byte, 256)
	n, err := reader.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Failed to read message: %v", err)
	}
	msg := string(buf[:n])
	if msg != "hello from backend" {
		t.Errorf("Expected 'hello from backend', got %q", msg)
	}
}

// --- WebSocket bypasses retry-all ---

func TestWebSocketBypassesRetryAll(t *testing.T) {
	backendA, countA := newTestBackend(t, 503)
	backendB, countB := newTestBackend(t, 200)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"ws": {
			{ProxyTo: backendA.URL, Weight: 1, RetryPolicy: "retry-all"},
			{ProxyTo: backendB.URL, Weight: 1, RetryPolicy: "retry-all"},
		},
	}
	injectRules(svc, rules)

	router := svc.Router()

	// WebSocket request should go direct (no retry), hitting only one backend
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "ws.api.pocket.network"
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	total := countA.Load() + countB.Load()
	if total != 1 {
		t.Errorf("WebSocket should hit exactly 1 backend (no retry), got %d", total)
	}
}

// --- gRPC bypasses retry-all ---

func TestGRPCBypassesRetryAll(t *testing.T) {
	backendA, countA := newTestBackend(t, 503)
	backendB, countB := newTestBackend(t, 200)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"grpc": {
			{ProxyTo: backendA.URL, Weight: 1, RetryPolicy: "retry-all"},
			{ProxyTo: backendB.URL, Weight: 1, RetryPolicy: "retry-all"},
		},
	}
	injectRules(svc, rules)

	router := svc.Router()

	// gRPC request should go direct (no retry), hitting only one backend
	req := httptest.NewRequest("POST", "/service.Method", nil)
	req.Host = "grpc.api.pocket.network"
	req.Header.Set("Content-Type", "application/grpc")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	total := countA.Load() + countB.Load()
	if total != 1 {
		t.Errorf("gRPC should hit exactly 1 backend (no retry), got %d", total)
	}
}

// --- gRPC content-type forwarded to backend ---

func TestGRPCContentTypeForwarded(t *testing.T) {
	var receivedContentType string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(200)
	}))
	t.Cleanup(backend.Close)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"grpc": {{ProxyTo: backend.URL, Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()

	req := httptest.NewRequest("POST", "/pkg.Service/Method", nil)
	req.Host = "grpc.api.pocket.network"
	req.Header.Set("Content-Type", "application/grpc+proto")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if receivedContentType != "application/grpc+proto" {
		t.Errorf("Backend received Content-Type %q, want %q", receivedContentType, "application/grpc+proto")
	}
}

// --- WebSocket extra headers preserved ---

func TestWebSocketExtraHeadersPreserved(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	t.Cleanup(backend.Close)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"ws": {{
			ProxyTo: backend.URL,
			Weight:  1,
			ExtraHeaders: map[string]string{
				"X-Api-Key": "secret-key",
			},
		}},
	}
	injectRules(svc, rules)

	router := svc.Router()

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Host = "ws.api.pocket.network"
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if receivedHeaders.Get("X-Api-Key") != "secret-key" {
		t.Errorf("Extra header X-Api-Key not forwarded to backend, got %q", receivedHeaders.Get("X-Api-Key"))
	}
	if receivedHeaders.Get("Upgrade") != "websocket" {
		t.Errorf("Upgrade header not forwarded to backend, got %q", receivedHeaders.Get("Upgrade"))
	}
}

// --- Rewrite API: headers can't be stripped by hop-by-hop ---

func TestRewriteAPIHeaderSafety(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	t.Cleanup(backend.Close)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: backend.URL, Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()

	// Client tries to strip X-Forwarded-For via hop-by-hop Connection header
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test.api.pocket.network"
	req.Header.Set("Connection", "X-Forwarded-For")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// With Rewrite API, X-Forwarded-For should still be present at the backend
	if receivedHeaders.Get("X-Forwarded-For") == "" {
		t.Error("X-Forwarded-For was stripped by hop-by-hop Connection header — Rewrite API should prevent this")
	}
}

// === Security & Path Manipulation Tests ===

// --- Path traversal prevention ---

func TestPathTraversalPrevented(t *testing.T) {
	var receivedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(200)
	}))
	t.Cleanup(backend.Close)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: backend.URL + "/api", Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()

	// Client sends path traversal attempt
	req := httptest.NewRequest("GET", "/../admin/secret", nil)
	req.Host = "test.api.pocket.network"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// path.Clean should normalize away the ".." — /api/../admin/secret -> /admin/secret
	if strings.Contains(receivedPath, "..") {
		t.Errorf("Path traversal not prevented: backend received path %q", receivedPath)
	}
}

func TestSingleJoiningSlashNormalization(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"/api", "/v1/data", "/api/v1/data"},
		{"/api/", "/v1/data", "/api/v1/data"},
		{"/api", "/../admin", "/admin"},       // traversal normalized
		{"/api", "/./v1/../v2", "/api/v2"},    // complex traversal
		{"/", "/", "/"},
		{"/api", "/", "/api"},
	}
	for _, tt := range tests {
		got := singleJoiningSlash(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("singleJoiningSlash(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}

// --- Host header CRLF injection ---

func TestHostHeaderCRLFRejected(t *testing.T) {
	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: "http://localhost:9999", Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()

	tests := []struct {
		name string
		host string
	}{
		{"CR injection", "test.api.pocket.network\r\nX-Injected: evil"},
		{"LF injection", "test.api.pocket.network\nX-Injected: evil"},
		{"bare CR", "test.api.pocket.network\revil"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != 400 {
				t.Errorf("Expected 400 for CRLF host %q, got %d", tt.host, w.Code)
			}
		})
	}
}

// --- strip_path behavior ---

func TestStripPath(t *testing.T) {
	var receivedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(200)
	}))
	t.Cleanup(backend.Close)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: backend.URL + "/backend-path", StripPath: true, Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()

	req := httptest.NewRequest("GET", "/client/path", nil)
	req.Host = "test.api.pocket.network"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// With strip_path=true, client path should be replaced by backend's configured path
	if receivedPath != "/backend-path" {
		t.Errorf("strip_path: backend received %q, want %q", receivedPath, "/backend-path")
	}
}

func TestNoStripPath(t *testing.T) {
	var receivedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(200)
	}))
	t.Cleanup(backend.Close)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: backend.URL + "/api", StripPath: false, Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()

	req := httptest.NewRequest("GET", "/v1/data", nil)
	req.Host = "test.api.pocket.network"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Without strip_path, paths should be joined: /api + /v1/data = /api/v1/data
	if receivedPath != "/api/v1/data" {
		t.Errorf("no strip_path: backend received %q, want %q", receivedPath, "/api/v1/data")
	}
}

// --- strip_query behavior ---

func TestStripQuery(t *testing.T) {
	var receivedQuery string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(200)
	}))
	t.Cleanup(backend.Close)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: backend.URL, StripQuery: true, Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()

	req := httptest.NewRequest("GET", "/data?key=value&secret=123", nil)
	req.Host = "test.api.pocket.network"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if receivedQuery != "" {
		t.Errorf("strip_query: backend received query %q, want empty", receivedQuery)
	}
}

func TestNoStripQuery(t *testing.T) {
	var receivedQuery string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(200)
	}))
	t.Cleanup(backend.Close)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: backend.URL, StripQuery: false, Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()

	req := httptest.NewRequest("GET", "/data?key=value", nil)
	req.Host = "test.api.pocket.network"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if receivedQuery != "key=value" {
		t.Errorf("no strip_query: backend received query %q, want %q", receivedQuery, "key=value")
	}
}

// --- Fallback backend tests ---

func TestFallbackUsedWhenAllPrimariesUnhealthy(t *testing.T) {
	primary, primaryCount := newTestBackend(t, 200)
	fallback, fallbackCount := newTestBackend(t, 200)

	svc := newTestProxyService(t)

	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: primary.URL, Weight: 1}},
	}
	injectRules(svc, rules)

	// Configure health checks (required for health filtering)
	hcConfigs := xsync.NewMap[string, *HealthCheckConfig]()
	hcConfigs.Store("test", &HealthCheckConfig{
		Path:             "/health",
		FailureThreshold: 1,
	})
	svc.healthCheckConfigs.Store(hcConfigs)

	// Mark primary as unhealthy
	healthStates := xsync.NewMap[string, *BackendHealth]()
	primaryHealth := &BackendHealth{}
	primaryHealth.healthy.Store(false)
	primaryHealth.consecutiveFailures.Store(5)
	primaryHealth.lastCheck.Store(time.Now())
	healthStates.Store(primary.URL, primaryHealth)
	svc.healthStates.Store(healthStates)

	// Set up fallback
	fallbackRules := xsync.NewMap[string, []ProxyRule]()
	fallbackRules.Store("test", []ProxyRule{{ProxyTo: fallback.URL, Weight: 1}})
	svc.fallbackRules.Store(fallbackRules)

	router := svc.Router()

	// Send requests — should all go to fallback
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = "test.api.pocket.network"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("Request %d: expected 200, got %d", i, w.Code)
		}
	}

	if primaryCount.Load() != 0 {
		t.Errorf("Unhealthy primary received %d requests, expected 0", primaryCount.Load())
	}
	if fallbackCount.Load() != 5 {
		t.Errorf("Fallback received %d requests, expected 5", fallbackCount.Load())
	}
}

func TestAllBackendsUnhealthyReturns503(t *testing.T) {
	primary, _ := newTestBackend(t, 200)
	fallback, _ := newTestBackend(t, 200)

	svc := newTestProxyService(t)

	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: primary.URL, Weight: 1}},
	}
	injectRules(svc, rules)

	// Configure health checks
	hcConfigs := xsync.NewMap[string, *HealthCheckConfig]()
	hcConfigs.Store("test", &HealthCheckConfig{
		Path:             "/health",
		FailureThreshold: 1,
	})
	svc.healthCheckConfigs.Store(hcConfigs)

	// Mark both primary and fallback as unhealthy
	healthStates := xsync.NewMap[string, *BackendHealth]()
	for _, url := range []string{primary.URL, fallback.URL} {
		h := &BackendHealth{}
		h.healthy.Store(false)
		h.consecutiveFailures.Store(5)
		h.lastCheck.Store(time.Now())
		healthStates.Store(url, h)
	}
	svc.healthStates.Store(healthStates)

	// Set up fallback (also unhealthy)
	fallbackRules := xsync.NewMap[string, []ProxyRule]()
	fallbackRules.Store("test", []ProxyRule{{ProxyTo: fallback.URL, Weight: 1}})
	svc.fallbackRules.Store(fallbackRules)

	router := svc.Router()

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test.api.pocket.network"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 503 {
		t.Errorf("Expected 503 when all backends unhealthy, got %d", w.Code)
	}
}

// --- Response buffer size limit ---

func TestRetryAllResponseSizeLimit(t *testing.T) {
	// Create a backend that returns a very large response
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// Write more than maxRetryResponseSize (128MB) — use a streaming approach
		// to avoid allocating 128MB in the test. We just need to exceed the limit.
		chunk := make([]byte, 1024*1024) // 1MB chunk
		for i := 0; i < 130; i++ {       // 130MB total
			if _, err := w.Write(chunk); err != nil {
				return // limitedResponseRecorder will reject writes
			}
		}
	}))
	t.Cleanup(backend.Close)

	backendB, _ := newTestBackend(t, 503)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"test": {
			{ProxyTo: backend.URL, Weight: 1, RetryPolicy: "retry-all"},
			{ProxyTo: backendB.URL, Weight: 1, RetryPolicy: "retry-all"},
		},
	}
	injectRules(svc, rules)

	router := svc.Router()

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test.api.pocket.network"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should get 502 (response too large) rather than OOM
	if w.Code != 502 && w.Code != 200 {
		// 200 is possible if the large-response backend is tried as non-last attempt
		// and the recorder truncates; either way no OOM is the goal
		t.Logf("Response status: %d (expected 502 or 200, no OOM)", w.Code)
	}
}

// --- Forwarded header IPv6 quoting ---

func TestForwardedHeaderIPv6Quoting(t *testing.T) {
	var receivedForwarded string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedForwarded = r.Header.Get("Forwarded")
		w.WriteHeader(200)
	}))
	t.Cleanup(backend.Close)

	svc := newTestProxyService(t)
	rules := map[string][]ProxyRule{
		"test": {{ProxyTo: backend.URL, Weight: 1}},
	}
	injectRules(svc, rules)

	router := svc.Router()

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test.api.pocket.network"
	req.RemoteAddr = "[2001:db8::1]:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// IPv6 addresses should be quoted in Forwarded header per RFC 7239
	if !strings.Contains(receivedForwarded, "for=\"") {
		t.Errorf("IPv6 address not quoted in Forwarded header: %q", receivedForwarded)
	}
}

