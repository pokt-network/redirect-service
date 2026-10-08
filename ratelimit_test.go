package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/redis/go-redis/v9"
)

// newTestRateLimiter returns a RateLimiter backed by an in-process miniredis.
//
// The tests below deliberately exercise CheckLimit — the function the request
// path actually calls — rather than the Lua script or the returned count in
// isolation. The bug this file pins shipped with the script and the count both
// looking correct; only the allowed/blocked decision handed back to the caller
// was wrong.
func newTestRateLimiter(t *testing.T) *RateLimiter {
	t.Helper()
	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return &RateLimiter{redis: client}
}

// TestRateLimiterBlocksAtLimit is the regression pin for the production defect
// where the limiter never blocked anything.
//
// A full window skips the ZADD, so the script's count could never exceed the
// limit; the caller then tested `count <= limit`, which is true at capacity.
// Every request was allowed at every limit value on every service — the symptom
// was a permanent 429 rate of exactly zero while traffic ran above the cap.
func TestRateLimiterBlocksAtLimit(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()

	const limit = 5
	const window = time.Minute

	for i := 1; i <= limit; i++ {
		allowed, remaining, _, err := rl.CheckLimit(ctx, "1.2.3.4", "solana", limit, window)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
		if !allowed {
			t.Fatalf("request %d of %d: allowed=false, want true (limit not reached yet)", i, limit)
		}
		if want := limit - i; remaining != want {
			t.Errorf("request %d: remaining=%d, want %d", i, remaining, want)
		}
	}

	// The (limit+1)th request must be rejected. This is the assertion that fails
	// on the pre-fix code.
	allowed, remaining, _, err := rl.CheckLimit(ctx, "1.2.3.4", "solana", limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("request %d of %d: allowed=true, want false — limiter is not blocking at capacity", limit+1, limit)
	}
	if remaining != 0 {
		t.Errorf("blocked request: remaining=%d, want 0", remaining)
	}
}

// TestRateLimiterBlockedRequestsDoNotConsumeBudget guards the optimization that
// caused the defect: rejecting without a ZADD is correct and must stay, so a
// client hammering a saturated window cannot push its own reset further out.
func TestRateLimiterBlockedRequestsDoNotConsumeBudget(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()

	const limit = 3
	const window = time.Minute

	for i := 0; i < limit; i++ {
		if allowed, _, _, err := rl.CheckLimit(ctx, "1.2.3.4", "eth", limit, window); err != nil || !allowed {
			t.Fatalf("fill request %d: allowed=%v err=%v", i, allowed, err)
		}
	}

	for i := 0; i < 20; i++ {
		allowed, _, _, err := rl.CheckLimit(ctx, "1.2.3.4", "eth", limit, window)
		if err != nil {
			t.Fatalf("blocked request %d: unexpected error: %v", i, err)
		}
		if allowed {
			t.Fatalf("blocked request %d: allowed=true, want false", i)
		}
	}

	card := rl.redis.ZCard(ctx, "ratelimit:eth:1.2.3.4").Val()
	if card != limit {
		t.Errorf("window holds %d entries after 20 blocked requests, want %d — blocked requests consumed budget", card, limit)
	}
}

// TestRateLimiterWindowSlides confirms a blocked client recovers once its window
// drains, rather than being latched off.
func TestRateLimiterWindowSlides(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()

	const limit = 2
	const window = 400 * time.Millisecond

	for i := 0; i < limit; i++ {
		if allowed, _, _, err := rl.CheckLimit(ctx, "1.2.3.4", "poly", limit, window); err != nil || !allowed {
			t.Fatalf("fill request %d: allowed=%v err=%v", i, allowed, err)
		}
	}
	if allowed, _, _, _ := rl.CheckLimit(ctx, "1.2.3.4", "poly", limit, window); allowed {
		t.Fatalf("request over limit: allowed=true, want false")
	}

	time.Sleep(window + 100*time.Millisecond)

	allowed, remaining, _, err := rl.CheckLimit(ctx, "1.2.3.4", "poly", limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("after window drained: allowed=false, want true")
	}
	if want := limit - 1; remaining != want {
		t.Errorf("after window drained: remaining=%d, want %d", remaining, want)
	}
}

// TestRateLimiterLoweredLimitBlocksOversizedWindow covers what production showed
// on 2026-08-19 09:20 UTC: lowering a service's limit left a window already
// holding more entries than the new limit, so the limiter blocked for the ~2
// minutes the oversized window took to drain and then went silent forever.
// That burst was the only evidence the plumbing worked at all, so keep it honest.
func TestRateLimiterLoweredLimitBlocksOversizedWindow(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()

	const oldLimit = 10
	const newLimit = 4
	const window = time.Minute

	for i := 0; i < oldLimit; i++ {
		if allowed, _, _, err := rl.CheckLimit(ctx, "1.2.3.4", "solana", oldLimit, window); err != nil || !allowed {
			t.Fatalf("fill request %d: allowed=%v err=%v", i, allowed, err)
		}
	}

	allowed, remaining, _, err := rl.CheckLimit(ctx, "1.2.3.4", "solana", newLimit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("window holds %d entries against a limit of %d: allowed=true, want false", oldLimit, newLimit)
	}
	if remaining != 0 {
		t.Errorf("remaining=%d, want 0 (must clamp, not go negative)", remaining)
	}
}

// TestRateLimiterKeysAreIsolated pins the key shape "ratelimit:<subdomain>:<ip>".
// Per-service budgets are the whole reason a solana limit can be tightened
// without touching eth, and a per-IP limit is meaningless if IPs share a bucket.
func TestRateLimiterKeysAreIsolated(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()

	const limit = 1
	const window = time.Minute

	if allowed, _, _, _ := rl.CheckLimit(ctx, "1.2.3.4", "solana", limit, window); !allowed {
		t.Fatal("first request: allowed=false, want true")
	}
	if allowed, _, _, _ := rl.CheckLimit(ctx, "1.2.3.4", "solana", limit, window); allowed {
		t.Fatal("same ip + same subdomain: allowed=true, want false")
	}
	if allowed, _, _, _ := rl.CheckLimit(ctx, "1.2.3.4", "eth", limit, window); !allowed {
		t.Error("same ip, different subdomain: allowed=false, want true (budgets are per-service)")
	}
	if allowed, _, _, _ := rl.CheckLimit(ctx, "5.6.7.8", "solana", limit, window); !allowed {
		t.Error("different ip, same subdomain: allowed=false, want true (budgets are per-IP)")
	}
}

// TestRateLimiterDisabledAllowsEverything covers the nil-Redis path, which the
// request handler relies on when rate limiting is turned off.
func TestRateLimiterDisabledAllowsEverything(t *testing.T) {
	ctx := context.Background()
	var rl *RateLimiter

	for i := 0; i < 3; i++ {
		allowed, remaining, _, err := rl.CheckLimit(ctx, "1.2.3.4", "solana", 1, time.Minute)
		if err != nil || !allowed {
			t.Fatalf("nil limiter: allowed=%v err=%v, want allowed=true", allowed, err)
		}
		if remaining != 1 {
			t.Errorf("nil limiter: remaining=%d, want 1 (full budget)", remaining)
		}
	}
}

// TestRateLimiterUnreachableRedisFailsFast pins the 2026-10-02 incident: Redis
// was black-holed (its node went dark, so connections were never
// answered), each check blocked on go-redis timeouts and retries, and taiji's
// "fail open" cost ~30s per request. A check must give up within
// redisCheckTimeout, and after redisFailuresToSkip consecutive failures later
// checks must skip Redis entirely.
func TestRateLimiterUnreachableRedisFailsFast(t *testing.T) {
	// A listener that accepts connections and never replies stands in for a
	// Redis whose node has gone dark.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()

	client := newRedisClient(ln.Addr().String(), "", 0)
	t.Cleanup(func() { _ = client.Close() })
	rl := &RateLimiter{redis: client}
	ctx := context.Background()

	// The first redisFailuresToSkip checks each try Redis and give up within
	// the bound. Fewer failures must not switch rate limiting off.
	for i := 1; i <= redisFailuresToSkip; i++ {
		start := time.Now()
		_, _, _, err := rl.CheckLimit(ctx, "1.2.3.4", "eth", 10, time.Minute)
		if err == nil || errors.Is(err, errRedisUnavailable) {
			t.Fatalf("check %d: err=%v, want a Redis timeout", i, err)
		}
		if took := time.Since(start); took > 4*redisCheckTimeout {
			t.Fatalf("check %d took %s, want under %s", i, took, 4*redisCheckTimeout)
		}
	}

	start := time.Now()
	_, _, _, err = rl.CheckLimit(ctx, "1.2.3.4", "eth", 10, time.Minute)
	if !errors.Is(err, errRedisUnavailable) {
		t.Fatalf("check after %d failures: err=%v, want errRedisUnavailable", redisFailuresToSkip, err)
	}
	if took := time.Since(start); took > 10*time.Millisecond {
		t.Fatalf("check after %d failures took %s, want Redis skipped", redisFailuresToSkip, took)
	}
}

// TestRateLimiterBurstDoesNotTripSkip pins the 2026-10-07 mainnet finding: on
// pods off Redis's node, a short network stall failed many in-flight checks at
// once, tripped the Redis skip 2-4 times per 30m, and each trip turned rate
// limiting off for redisBackoff (~1% of requests failed open). A burst of
// failures right after a success must keep checking Redis; the same failures
// with no success for redisTripAfter must still skip it.
func TestRateLimiterBurstDoesNotTripSkip(t *testing.T) {
	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	rl := &RateLimiter{redis: client}
	ctx := context.Background()
	check := func() error {
		_, _, _, err := rl.CheckLimit(ctx, "1.2.3.4", "eth", 100, time.Minute)
		return err
	}

	if err := check(); err != nil {
		t.Fatal(err)
	}
	srv.SetError("stall")
	for i := 1; i <= 2*redisFailuresToSkip; i++ {
		if err := check(); err == nil || errors.Is(err, errRedisUnavailable) {
			t.Fatalf("burst failure %d: err=%v, want a Redis error", i, err)
		}
	}
	srv.SetError("")
	if err := check(); err != nil {
		t.Fatalf("after the burst: err=%v, want Redis checked again", err)
	}

	srv.SetError("down")
	rl.lastOK.Store(time.Now().Add(-redisTripAfter).UnixNano())
	for i := 0; i < redisFailuresToSkip; i++ {
		_ = check()
	}
	if err := check(); !errors.Is(err, errRedisUnavailable) {
		t.Fatalf("sustained failure: err=%v, want errRedisUnavailable", err)
	}
}

// TestRateLimiterWeightedBatch pins CheckLimitN: a request charges its whole
// weight, is rejected when the weight does not fit, and a rejected batch costs
// nothing.
func TestRateLimiterWeightedBatch(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()
	const limit = 10
	window := time.Minute

	allowed, remaining, _, err := rl.CheckLimitN(ctx, "1.2.3.4", "eth", limit, window, 7)
	if err != nil || !allowed || remaining != 3 {
		t.Fatalf("batch of 7: allowed=%v remaining=%d err=%v, want true 3 nil", allowed, remaining, err)
	}
	// 4 more do not fit in the 3 left: rejected, no budget consumed, and the
	// 3 still left are reported.
	if allowed, remaining, _, _ := rl.CheckLimitN(ctx, "1.2.3.4", "eth", limit, window, 4); allowed || remaining != 3 {
		t.Fatalf("batch of 4 with 3 left: allowed=%v remaining=%d, want false 3", allowed, remaining)
	}
	if card := rl.redis.ZCard(ctx, "ratelimit:eth:1.2.3.4").Val(); card != 7 {
		t.Fatalf("window holds %d entries after a rejected batch, want 7", card)
	}
	// A single request still fits.
	if allowed, remaining, _, _ := rl.CheckLimit(ctx, "1.2.3.4", "eth", limit, window); !allowed || remaining != 2 {
		t.Fatalf("single request: allowed=%v remaining=%d, want true 2", allowed, remaining)
	}
	// A batch larger than the limit itself never fits.
	if allowed, _, _, _ := rl.CheckLimitN(ctx, "5.6.7.8", "eth", limit, window, limit+1); allowed {
		t.Fatal("batch larger than the limit was allowed")
	}
}

// TestRateLimitScriptExactMembers pins the members the script writes to the
// exact ARGV[1] string. Built from the Lua number instead, real Redis prints 14
// significant digits, so batches ~100µs apart wrote the same members and a
// burst of 50 five-item batches got 14 through a 10/min limit. miniredis keeps
// more digits than Redis, so only an unrepresentable timestamp shows it here.
func TestRateLimitScriptExactMembers(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()
	const now = "1759600000123456789" // not representable in float64
	if err := rateLimitScript.Run(ctx, rl.redis, []string{"k"}, now, 0, 10, 60, 2).Err(); err != nil {
		t.Fatal(err)
	}
	got := rl.redis.ZRange(ctx, "k", 0, -1).Val()
	if len(got) != 2 || got[0] != now+":1" || got[1] != now+":2" {
		t.Fatalf("members %v, want [%s:1 %s:2]", got, now, now)
	}
}

// TestBatchWeight counts top-level array items, refuses arrays it cannot count
// to the end, and leaves the body intact either way.
func TestBatchWeight(t *testing.T) {
	pad := strings.Repeat(" ", maxBatchPeekBytes)
	items := strings.Repeat(`{"id":1},`, 999) + `{"id":1}`
	cases := []struct {
		name   string
		body   string
		want   int
		wantOK bool
	}{
		{"single call", `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}`, 1, true},
		{"batch", `[{"id":1},{"id":2},{"id":3}]`, 3, true},
		{"nested and spaced", ` [ {"id":1, "params":["a",[1,2]]} , {"id":2} ] `, 2, true},
		{"empty batch", `[]`, 1, true},
		{"not json", `not json`, 1, true},
		{"whitespace only", `   `, 1, true},
		{"truncated", `[{"id":1},{"id":`, 0, false},
		{"missing comma", `[{"id":1} {"id":2}]`, 0, false},
		{"padding inside the array", "[" + pad + items + "]", 0, false},
		{"padding before the array", pad + "[" + items + "]", 0, false},
		{"array past the bound", "[" + strings.Repeat(`{"id":1},`, maxBatchPeekBytes/9) + `{"id":2}]`, 0, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(c.body))
		if got, ok := batchWeight(r); got != c.want || ok != c.wantOK {
			t.Errorf("%s: batchWeight = %d, %v, want %d, %v", c.name, got, ok, c.want, c.wantOK)
		}
		if rest, _ := io.ReadAll(r.Body); string(rest) != c.body {
			t.Errorf("%s: body changed", c.name)
		}
	}
}

// TestBatchRateLimitThroughProxy drives batch counting through the handler: a
// batch charges its items, reaches the backend unchanged, and a batch that can
// never fit, or cannot be counted, gets 413 rather than a retryable 429.
func TestBatchRateLimitThroughProxy(t *testing.T) {
	var gotBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	t.Cleanup(backend.Close)

	limit := &RateLimitConfig{Requests: 5, Window: time.Minute, CountBatchItems: true}
	svc := NewProxyService("examples/proxies.yaml", newTestRateLimiter(t), true, limit, false)
	injectRules(svc, map[string][]ProxyRule{"test": {{ProxyTo: backend.URL, Weight: 1}}})

	steps := []struct {
		body          string
		wantStatus    int
		wantRemaining string
	}{
		{`[{"id":1},{"id":2},{"id":3}]`, http.StatusOK, "2"},
		{`[{"id":1},{"id":2},{"id":3},{"id":4},{"id":5},{"id":6}]`, http.StatusRequestEntityTooLarge, ""},
		{"[" + strings.Repeat(" ", maxBatchPeekBytes) + `{"id":1}]`, http.StatusRequestEntityTooLarge, ""},
		{`[{"id":1},{"id":2},{"id":3}]`, http.StatusTooManyRequests, "2"},
		{`{"id":1}`, http.StatusOK, "1"},
	}
	for i, st := range steps {
		gotBody = ""
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(st.body))
		req.Host = "test.api.pocket.network"
		rec := httptest.NewRecorder()
		svc.Router().ServeHTTP(rec, req)
		if rec.Code != st.wantStatus || rec.Header().Get("X-RateLimit-Remaining") != st.wantRemaining {
			t.Fatalf("step %d: status %d remaining %q, want %d %q", i, rec.Code, rec.Header().Get("X-RateLimit-Remaining"), st.wantStatus, st.wantRemaining)
		}
		if st.wantStatus == http.StatusOK && gotBody != st.body {
			t.Fatalf("step %d: backend got %q, want %q", i, gotBody, st.body)
		}
	}
}

// TestPreflightSkipsLimiter: a CORS preflight is answered by taiji, cacheable,
// and charges neither limit nor reaches the backend; a plain OPTIONS still does.
func TestPreflightSkipsLimiter(t *testing.T) {
	hits := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	t.Cleanup(backend.Close)

	limit := &RateLimitConfig{Requests: 1, Window: time.Minute}
	svc := NewProxyService("examples/proxies.yaml", newTestRateLimiter(t), true, limit, false)
	injectRules(svc, map[string][]ProxyRule{"test": {{ProxyTo: backend.URL, Weight: 1, GlobalLimit: limit}}})

	send := func(method string, preflight bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/", nil)
		req.Host = "test.api.pocket.network"
		if preflight {
			req.Header.Set("Origin", "https://app.example")
			req.Header.Set("Access-Control-Request-Method", "POST")
			req.Header.Set("Access-Control-Request-Headers", "content-type")
		}
		rec := httptest.NewRecorder()
		svc.Router().ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < 3; i++ {
		rec := send(http.MethodOptions, true)
		h := rec.Header()
		if rec.Code != http.StatusNoContent || h.Get("Access-Control-Allow-Origin") != "https://app.example" ||
			h.Get("Access-Control-Allow-Headers") != "content-type" || h.Get("Access-Control-Max-Age") != "86400" ||
			h.Get("X-RateLimit-Remaining") != "" {
			t.Fatalf("preflight %d: status %d headers %v", i, rec.Code, h)
		}
	}
	if rec := send(http.MethodPost, false); rec.Code != http.StatusOK {
		t.Fatalf("POST after preflights: status %d, want 200 (preflights must not charge the limit)", rec.Code)
	}
	if rec := send(http.MethodOptions, false); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("plain OPTIONS: status %d, want 429 (still limited)", rec.Code)
	}
	if hits != 1 {
		t.Fatalf("backend hits = %d, want 1 (only the POST)", hits)
	}
}

// TestBatchRateLimitRealServer runs the peek on a real connection: the body
// reaches the backend byte-identical, and a body that stalls inside a batch hits
// the read deadline and gets 413 instead of holding the handler.
func TestBatchRateLimitRealServer(t *testing.T) {
	defer func(d time.Duration) { batchPeekTimeout = d }(batchPeekTimeout)
	batchPeekTimeout = 100 * time.Millisecond // set before any server goroutine reads it

	var gotBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer backend.Close()
	limit := &RateLimitConfig{Requests: 5, Window: time.Minute, CountBatchItems: true}
	svc := NewProxyService("examples/proxies.yaml", newTestRateLimiter(t), true, limit, false)
	injectRules(svc, map[string][]ProxyRule{"test": {{ProxyTo: backend.URL, Weight: 1}}})
	proxy := httptest.NewServer(svc.Router())
	defer proxy.Close()

	post := func(body io.Reader) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, proxy.URL, body)
		req.Host = "test.api.pocket.network"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}

	const batch = `[{"id":1},{"id":2},{"id":3}]`
	if resp := post(strings.NewReader(batch)); resp.StatusCode != http.StatusOK ||
		resp.Header.Get("X-RateLimit-Remaining") != "2" || gotBody != batch {
		t.Fatalf("batch: status %d remaining %q backend got %q", resp.StatusCode, resp.Header.Get("X-RateLimit-Remaining"), gotBody)
	}

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	go func() { _, _ = pw.Write([]byte(`[{"id":1},`)) }() // then stalls
	start := time.Now()
	if resp := post(pr); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("stalled batch: status %d, want 413", resp.StatusCode)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("stalled batch held the handler for %s", took)
	}
}

// TestGlobalBatchCountingIsSeparate pins the two flags apart: per-IP counting
// alone leaves the global limit at one unit per request, and global counting
// charges every item against the service-wide budget, across client IPs.
func TestGlobalBatchCountingIsSeparate(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(backend.Close)
	const batch = `[{"id":1},{"id":2},{"id":3}]`
	post := func(svc *ProxyService, ip, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Host = "test.api.pocket.network"
		req.RemoteAddr = ip + ":1234"
		rec := httptest.NewRecorder()
		svc.Router().ServeHTTP(rec, req)
		return rec.Code
	}
	newSvc := func(perIP, global *RateLimitConfig) *ProxyService {
		svc := NewProxyService("examples/proxies.yaml", newTestRateLimiter(t), true, nil, false)
		injectRules(svc, map[string][]ProxyRule{"test": {{ProxyTo: backend.URL, Weight: 1, RateLimit: perIP, GlobalLimit: global}}})
		return svc
	}

	// Per-IP counting only: a global limit of 5 admits five 3-item batches.
	svc := newSvc(&RateLimitConfig{Requests: 100, Window: time.Minute, CountBatchItems: true},
		&RateLimitConfig{Requests: 5, Window: time.Minute})
	for i := 1; i <= 5; i++ {
		if code := post(svc, "192.0.2.1", batch); code != http.StatusOK {
			t.Fatalf("per-IP counting, batch %d: status %d, want 200", i, code)
		}
	}
	if code := post(svc, "192.0.2.1", batch); code != http.StatusTooManyRequests {
		t.Fatalf("per-IP counting, batch 6: status %d, want 429", code)
	}

	// Global counting: 3 items from one IP leave 2 for everyone else.
	svc = newSvc(nil, &RateLimitConfig{Requests: 5, Window: time.Minute, CountBatchItems: true})
	steps := []struct {
		ip, body string
		want     int
	}{
		{"192.0.2.1", batch, http.StatusOK},
		{"192.0.2.2", batch, http.StatusTooManyRequests},
		{"192.0.2.2", `{"id":1}`, http.StatusOK},
		{"192.0.2.3", `[{"id":1},{"id":2},{"id":3},{"id":4},{"id":5},{"id":6}]`, http.StatusRequestEntityTooLarge},
	}
	for i, st := range steps {
		if code := post(svc, st.ip, st.body); code != st.want {
			t.Fatalf("global counting, step %d: status %d, want %d", i, code, st.want)
		}
	}
}

// counterValue reads a Prometheus counter's current value.
func counterValue(c prometheus.Counter) float64 {
	var m dto.Metric
	_ = c.Write(&m)
	return m.GetCounter().GetValue()
}

// TestClientGoneIsNotARedisFailure pins the 1.7.0 mainnet finding: with batch
// counting on, reading the body lets the server notice a closed client before
// the rate-limit check, and the cancelled check was counted and logged as a
// Redis failure (0.2-1.2% "fail-open" per pod, thousands of ERROR lines). A
// request whose client is gone gets 499, is not proxied, and touches neither
// the Redis error metric nor the skip.
func TestClientGoneIsNotARedisFailure(t *testing.T) {
	reached := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	t.Cleanup(backend.Close)
	rl := newTestRateLimiter(t)
	svc := NewProxyService("examples/proxies.yaml", rl, true, &RateLimitConfig{Requests: 100, Window: time.Minute}, false)
	injectRules(svc, map[string][]ProxyRule{"test": {{ProxyTo: backend.URL, Weight: 1,
		GlobalLimit: &RateLimitConfig{Requests: 1000, Window: time.Minute}}}})

	redisErrors := counterValue(proxyRateLimitRedisErrorsTotal)
	closed := proxyRequestsTotal.WithLabelValues("test", normalizeBackendLabel("unknown"), "499", "rpc", "false")
	before := counterValue(closed)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"id":1}`)).WithContext(ctx)
	req.Host = "test.api.pocket.network"
	svc.Router().ServeHTTP(httptest.NewRecorder(), req)

	if reached {
		t.Error("request from a gone client was proxied")
	}
	if got := counterValue(proxyRateLimitRedisErrorsTotal) - redisErrors; got != 0 {
		t.Errorf("redis errors metric rose by %v, want 0", got)
	}
	if got := counterValue(closed) - before; got != 1 {
		t.Errorf("499 requests rose by %v, want 1", got)
	}
	if f := rl.failures.Load(); f != 0 {
		t.Errorf("skip failure count %d, want 0", f)
	}
}

// TestClientGoneDuringBackendCallRecords499 pins the metrics wrapper keeping
// the 499 the proxy's ErrorHandler sets: it used to overwrite it with the
// wrapper's default 200, counting abandoned requests as successes.
func TestClientGoneDuringBackendCallRecords499(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body) // lets the server notice the proxy hanging up
		cancel()                  // the client leaves while the backend is working
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(backend.Close)
	svc := NewProxyService("examples/proxies.yaml", nil, false, nil, false)
	injectRules(svc, map[string][]ProxyRule{"test": {{ProxyTo: backend.URL, Weight: 1}}})

	closed := proxyRequestsTotal.WithLabelValues("test", normalizeBackendLabel(strings.TrimPrefix(backend.URL, "http://")), "499", "rpc", "false")
	before := counterValue(closed)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"id":1}`)).WithContext(ctx)
	req.Host = "test.api.pocket.network"
	svc.Router().ServeHTTP(httptest.NewRecorder(), req)

	if got := counterValue(closed) - before; got != 1 {
		t.Errorf("499 requests rose by %v, want 1", got)
	}
}

// TestCheckLimitsAllOrNothing pins the combined check: a request one limit
// rejects consumes no budget on the other. When global and per-IP were two
// calls, a request the per-IP limit rejected had already been charged to the
// global limit.
func TestCheckLimitsAllOrNothing(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()
	card := func(ip string) int64 { return rl.redis.ZCard(ctx, "ratelimit:eth:"+ip).Val() }
	check := func(ip string, global int) (bool, []limitResult) {
		allowed, res, err := rl.CheckLimits(ctx, "eth", []limitCheck{
			{"global", global, time.Minute, 1},
			{ip, 3, time.Minute, 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		return allowed, res
	}

	for i := 1; i <= 3; i++ {
		if allowed, _ := check("1.2.3.4", 10); !allowed {
			t.Fatalf("request %d rejected", i)
		}
	}
	// Per-IP full: rejected, and the global limit that had room is not charged.
	allowed, res := check("1.2.3.4", 10)
	if allowed || !res[0].allowed || res[1].allowed || res[0].remaining != 7 || card("global") != 3 {
		t.Fatalf("per-IP rejection: allowed=%v results=%+v global card=%d, want false, global fits with 7 left and card 3", allowed, res, card("global"))
	}
	// Global full: rejected, and the per-IP limit that had room is not charged.
	allowed, res = check("5.6.7.8", 3)
	if allowed || res[0].allowed || !res[1].allowed || card("5.6.7.8") != 0 {
		t.Fatalf("global rejection: allowed=%v results=%+v per-IP card=%d, want false, per-IP fits and card 0", allowed, res, card("5.6.7.8"))
	}
}

// countRoundTrips counts the commands a go-redis client sends.
type countRoundTrips struct{ n atomic.Int32 }

func (h *countRoundTrips) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *countRoundTrips) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error { h.n.Add(1); return next(ctx, cmd) }
}
func (h *countRoundTrips) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// TestGlobalAndPerIPOneRoundTrip pins that a request with both limits costs one
// Redis command: on 2026-10-07 pods off Redis's node paid two cross-node round
// trips per request (p50 ~2-3ms each) and twice the exposure to stalls.
func TestGlobalAndPerIPOneRoundTrip(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(backend.Close)
	rl := newTestRateLimiter(t)
	hook := &countRoundTrips{}
	rl.redis.AddHook(hook)
	svc := NewProxyService("examples/proxies.yaml", rl, true, &RateLimitConfig{Requests: 100, Window: time.Minute}, false)
	injectRules(svc, map[string][]ProxyRule{"test": {{ProxyTo: backend.URL, Weight: 1,
		GlobalLimit: &RateLimitConfig{Requests: 1000, Window: time.Minute}}}})
	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "test.api.pocket.network"
		rec := httptest.NewRecorder()
		svc.Router().ServeHTTP(rec, req)
		return rec
	}

	get() // loads the script (EVALSHA, then EVAL on NOSCRIPT)
	before := hook.n.Load()
	rec := get()
	if got := hook.n.Load() - before; got != 1 {
		t.Fatalf("request with global and per-IP limits sent %d Redis commands, want 1", got)
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "98" || rec.Header().Get("X-RateLimit-Remaining-Global") != "998" {
		t.Fatalf("remaining per-IP %q global %q, want 98 and 998", rec.Header().Get("X-RateLimit-Remaining"), rec.Header().Get("X-RateLimit-Remaining-Global"))
	}
}
