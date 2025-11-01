package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"atomicgo.dev/robin"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/http2"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	defaultCSVPath        = "examples/proxies.csv"
	defaultPort           = "8080"
	proxyMetadataField    = contextKey("proxy_metadata")
	backendStartTimeField = contextKey("backend_start_time")
)

// Pre-allocated status code strings to avoid allocations in hot path
var statusCodeStrings = map[int]string{
	200: "200",
	400: "400",
	404: "404",
	429: "429",
	500: "500",
	502: "502",
	503: "503",
}

// statusCodeToString converts status code to string using pre-allocated strings when possible
func statusCodeToString(code int) string {
	if s, ok := statusCodeStrings[code]; ok {
		return s
	}
	return strconv.Itoa(code)
}

// BufferPool is a sync.Pool of byte slices for use in httputil.ReverseProxy
// This reduces allocations and GC pressure when copying response bodies
type BufferPool struct {
	pool sync.Pool
}

// Get returns a buffer from the pool, or allocates a new 32KB buffer
func (bp *BufferPool) Get() []byte {
	buf := bp.pool.Get()
	if buf == nil {
		return make([]byte, 32*1024) // 32KB - same as io.Copy default
	}
	return buf.([]byte)
}

// Put returns a buffer to the pool for reuse
func (bp *BufferPool) Put(buf []byte) {
	bp.pool.Put(buf) //nolint:staticcheck // SA6002: slices are pointer-like and this is the idiomatic way to use sync.Pool with byte slices
}

var (
	// Prometheus metrics
	proxyRulesTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "proxy_rules_total",
		Help: "Total number of proxy rules loaded",
	})

	proxyRulesLastLoadTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "proxy_rules_last_load_timestamp_seconds",
		Help: "Timestamp of last successful rule load",
	})

	// Per-subdomain active metric (shows which subdomains are configured)
	proxyRuleActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "proxy_rule_active",
		Help: "Whether a proxy rule is active for a subdomain (1 = active, 0 = removed)",
	}, []string{"subdomain"})

	// Request metrics by subdomain and backend
	proxyRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_requests_total",
		Help: "Total number of proxy requests by subdomain, backend, and status code",
	}, []string{"subdomain", "backend", "status_code"})

	proxyRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_request_duration_seconds",
		Help:    "Total proxy request duration in seconds (includes rate limiting, routing, backend, response) by subdomain, backend, and status code",
		Buckets: prometheus.DefBuckets, // 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
	}, []string{"subdomain", "backend", "status_code"})

	proxyBackendDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_backend_duration_seconds",
		Help:    "Backend response time in seconds (time from sending request to backend until response received) by subdomain, backend, and status code",
		Buckets: prometheus.DefBuckets, // 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
	}, []string{"subdomain", "backend", "status_code"})

	proxyOverheadDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_overhead_duration_seconds",
		Help:    "Taiji proxy overhead in seconds (total time minus backend time, includes routing, header processing, streaming) by subdomain, backend, and status code",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1}, // 0.1ms to 100ms
	}, []string{"subdomain", "backend", "status_code"})

	// Last successful request timestamp by subdomain and backend
	proxyLastRequestTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "proxy_last_request_timestamp_seconds",
		Help: "Timestamp of last successful proxy request by subdomain and backend",
	}, []string{"subdomain", "backend"})

	// CSV reload metrics
	proxyCSVReloadTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxy_csv_reload_total",
		Help: "Total number of CSV reload attempts",
	})

	proxyCSVReloadErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxy_csv_reload_errors_total",
		Help: "Total number of CSV reload errors",
	})

	proxyWatcherRestarts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxy_watcher_restarts_total",
		Help: "Total number of file watcher restarts",
	})

	// Retry metrics
	proxyRetryAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_retry_attempts_total",
		Help: "Total number of backend retry attempts by subdomain and outcome",
	}, []string{"subdomain", "outcome"}) // outcome: "success" or "all_failed"

	proxyBackendFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_backend_failures_total",
		Help: "Total number of backend failures that triggered retries by subdomain and backend",
	}, []string{"subdomain", "backend"})

	// Rate limiting metrics
	proxyRateLimitRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_ratelimit_requests_total",
		Help: "Total number of rate limit checks by subdomain and action",
	}, []string{"subdomain", "action"}) // action: "allowed" or "blocked"

	proxyRateLimitRemaining = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "proxy_ratelimit_remaining",
		Help: "Remaining requests in rate limit window by subdomain",
	}, []string{"subdomain"})

	proxyRateLimitRedisErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxy_ratelimit_redis_errors_total",
		Help: "Total number of Redis errors during rate limiting",
	})

	proxyRateLimitCheckDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "proxy_ratelimit_check_duration_seconds",
		Help:    "Duration of rate limit checks (Redis latency)",
		Buckets: []float64{0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1}, // 1ms to 100ms
	})
)

type RateLimitConfig struct {
	Requests int           // Number of requests allowed
	Window   time.Duration // Time window for rate limit
}

type ProxyRule struct {
	ProxyTo      string
	StripPath    bool
	StripQuery   bool
	ExtraHeaders map[string]string
	RateLimit    *RateLimitConfig // Optional per-subdomain rate limit
}

type ProxyService struct {
	rules            atomic.Value // map[string][]ProxyRule - multiple backends per subdomain
	csvPath          string
	loadTime         atomic.Value // time.Time
	ruleCount        atomic.Int64
	transport        *http.Transport
	proxies          sync.Map                                           // map[string]*httputil.ReverseProxy - cached per backend
	loadbalancers    *xsync.Map[string, *robin.Loadbalancer[ProxyRule]] // round-robin loadbalancer per subdomain
	rateLimiter      *RateLimiter
	rateLimitEnabled bool
	defaultRateLimit *RateLimitConfig
	trustProxy       bool
}

type RateLimiter struct {
	redis *redis.Client
}

// CheckLimit checks if the request is within rate limit using sliding window algorithm
// Returns: allowed (bool), remaining (int), resetAt (time.Time), error
func (rl *RateLimiter) CheckLimit(ctx context.Context, ip, subdomain string, limit int, window time.Duration) (bool, int, time.Time, error) {
	if rl == nil || rl.redis == nil {
		// Rate limiting disabled or Redis not available - allow request
		return true, limit, time.Now().Add(window), nil
	}

	// Track Redis latency
	checkStart := time.Now()
	defer func() {
		proxyRateLimitCheckDuration.Observe(time.Since(checkStart).Seconds())
	}()

	now := time.Now()
	key := fmt.Sprintf("ratelimit:%s:%s", subdomain, ip)
	windowStart := now.Add(-window)

	// Use pipeline for atomic operations
	pipe := rl.redis.Pipeline()

	// 1. Add current request timestamp to sorted set
	pipe.ZAdd(ctx, key, redis.Z{
		Score:  float64(now.UnixNano()),
		Member: now.UnixNano(),
	})

	// 2. Remove timestamps older than window (CRITICAL for accuracy!)
	// TTL only removes the entire key when idle - doesn't clean old entries within the sorted set
	// Without this: sorted set accumulates old timestamps → inaccurate counts → wrong rate limit enforcement
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart.UnixNano()))

	// 3. Count requests in current window
	zCard := pipe.ZCard(ctx, key)

	// 4. Set TTL to window duration (memory cleanup for idle keys)
	pipe.Expire(ctx, key, window)

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, time.Time{}, fmt.Errorf("redis pipeline error: %w", err)
	}

	// Get count result
	count, err := zCard.Result()
	if err != nil {
		return false, 0, time.Time{}, fmt.Errorf("failed to get request count: %w", err)
	}

	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}

	// Calculate reset time (when oldest request will age out)
	resetAt := now.Add(window)
	allowed := count <= int64(limit)

	return allowed, remaining, resetAt, nil
}

type proxyMetadata struct {
	subdomain     string
	startTime     time.Time
	rule          ProxyRule
	targetURL     *url.URL
	backend       string // backend host for metrics (e.g., "akash.api.raidguild.com")
	scheme        string
	host          string
	clientIP      string
	originalPath  string
	originalQuery string
}

// extractClientIP extracts the real client IP from request headers
// Priority: Forwarded (RFC 7239) > CF-Connecting-IP > True-Client-IP > X-Forwarded-For > X-Real-IP > RemoteAddr
func extractClientIP(r *http.Request, trustProxy bool) string {
	if !trustProxy {
		// In development or when not behind a proxy, use RemoteAddr directly
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			return r.RemoteAddr
		}
		return ip
	}

	// 1. Check RFC 7239 Forwarded header (standard)
	if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
		// Parse "for=xxx" from Forwarded header
		// Example: "for=192.0.2.60;host=example.com;proto=https"
		forRegex := regexp.MustCompile(`for=([^;,\s]+)`)
		if matches := forRegex.FindStringSubmatch(forwarded); len(matches) > 1 {
			ip := strings.Trim(matches[1], "\"[]")
			if validIP := net.ParseIP(ip); validIP != nil {
				return ip
			}
		}
	}

	// 2. Check Cloudflare headers (no X- prefix, modern standard)
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		if validIP := net.ParseIP(cfIP); validIP != nil {
			return cfIP
		}
	}

	if trueClientIP := r.Header.Get("True-Client-IP"); trueClientIP != "" {
		if validIP := net.ParseIP(trueClientIP); validIP != nil {
			return trueClientIP
		}
	}

	// 3. Check X-Forwarded-For (legacy but widely used)
	// Format: "client, proxy1, proxy2"
	// Take the rightmost IP that's not a known proxy (or just the first IP for simplicity)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		// Take the first IP (original client) after trimming
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if validIP := net.ParseIP(ip); validIP != nil {
				return ip
			}
		}
	}

	// 4. Check X-Real-IP (legacy)
	if xRealIP := r.Header.Get("X-Real-IP"); xRealIP != "" {
		if validIP := net.ParseIP(xRealIP); validIP != nil {
			return xRealIP
		}
	}

	// 5. Fallback to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		return r.RemoteAddr
	}
	return ip
}

// parseRateLimit parses rate limit string format "requests/duration" (e.g., "100/1m", "1000/1h")
func parseRateLimit(rateLimitStr string) (*RateLimitConfig, error) {
	parts := strings.Split(rateLimitStr, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid rate limit format, expected 'requests/duration' (e.g., '100/1m')")
	}

	requests, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid requests count: %w", err)
	}

	durationStr := strings.TrimSpace(parts[1])
	var duration time.Duration

	// Parse duration with support for s, m, h
	if strings.HasSuffix(durationStr, "s") {
		seconds, err := strconv.Atoi(strings.TrimSuffix(durationStr, "s"))
		if err != nil {
			return nil, fmt.Errorf("invalid duration: %w", err)
		}
		duration = time.Duration(seconds) * time.Second
	} else if strings.HasSuffix(durationStr, "m") {
		minutes, err := strconv.Atoi(strings.TrimSuffix(durationStr, "m"))
		if err != nil {
			return nil, fmt.Errorf("invalid duration: %w", err)
		}
		duration = time.Duration(minutes) * time.Minute
	} else if strings.HasSuffix(durationStr, "h") {
		hours, err := strconv.Atoi(strings.TrimSuffix(durationStr, "h"))
		if err != nil {
			return nil, fmt.Errorf("invalid duration: %w", err)
		}
		duration = time.Duration(hours) * time.Hour
	} else {
		return nil, fmt.Errorf("invalid duration format, use s/m/h suffix (e.g., '60s', '1m', '1h')")
	}

	if requests <= 0 || duration <= 0 {
		return nil, fmt.Errorf("requests and duration must be positive")
	}

	return &RateLimitConfig{
		Requests: requests,
		Window:   duration,
	}, nil
}

func NewProxyService(csvPath string, rateLimiter *RateLimiter, rateLimitEnabled bool, defaultRateLimit *RateLimitConfig, trustProxy bool) *ProxyService {
	// Create dialer with TCP buffer optimizations
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 90 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var syscallErr error
			err := c.Control(func(fd uintptr) {
				// Set read buffer to 128KB (default is ~4KB)
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 128*1024)
				if syscallErr != nil {
					return
				}
				// Set write buffer to 128KB (default is ~4KB)
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 128*1024)
			})
			if err != nil {
				return err
			}
			return syscallErr
		},
	}

	transport := &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: dialer.DialContext,

		// HTTP/2 settings
		ForceAttemptHTTP2: true,

		// Connection pooling (already optimized)
		MaxIdleConns:        0,    // No limit on total idle connections
		MaxIdleConnsPerHost: 1000, // Very generous per-host
		MaxConnsPerHost:     0,    // No limit on connections per host
		IdleConnTimeout:     90 * time.Second,

		// Timeouts
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 0, // No timeout - support long-running requests

		// Proxy settings
		DisableKeepAlives:  false,
		DisableCompression: true, // Don't decompress - just proxy as-is
	}

	// Configure HTTP/2 with larger frame size (256KB vs default 16KB)
	// This can improve throughput significantly (benchmark: 8 Gbps -> 38 Gbps)
	if err := http2.ConfigureTransport(transport); err != nil {
		log.Printf("main.go:456: WARN: Failed to configure HTTP/2 transport: %v", err)
	}

	s := &ProxyService{
		csvPath:          csvPath,
		rateLimiter:      rateLimiter,
		rateLimitEnabled: rateLimitEnabled,
		defaultRateLimit: defaultRateLimit,
		trustProxy:       trustProxy,
		loadbalancers:    xsync.NewMap[string, *robin.Loadbalancer[ProxyRule]](),
		transport:        transport,
	}
	s.rules.Store(make(map[string][]ProxyRule))
	s.loadTime.Store(time.Now())
	return s
}

// LoadRules parses CSV and loads proxy rules with full validation
func (s *ProxyService) LoadRules() error {
	proxyCSVReloadTotal.Inc()

	file, err := os.Open(s.csvPath)
	if err != nil {
		proxyCSVReloadErrorsTotal.Inc()
		return fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	reader := csv.NewReader(bufio.NewReader(file))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1 // Accept variable number of fields (4, 5, or 6)
	reader.LazyQuotes = true    // Allow lazy quote handling for JSON strings

	newRules := make(map[string][]ProxyRule)
	lineNum := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			proxyCSVReloadErrorsTotal.Inc()
			return fmt.Errorf("CSV parse error at line %d: %w", lineNum, err)
		}

		lineNum++

		// Skip header
		if lineNum == 1 && record[0] == "subdomain" {
			continue
		}

		// Validate field count (4, 5, or 6 columns)
		if len(record) < 4 || len(record) > 6 {
			log.Printf("WARN: Invalid field count at line %d (expected 4-6, got %d), skipping", lineNum, len(record))
			continue
		}

		// Validate subdomain (no empty, no wildcards, no dots)
		subdomain := strings.TrimSpace(record[0])
		if subdomain == "" || strings.Contains(subdomain, ".") || strings.Contains(subdomain, "*") {
			log.Printf("WARN: Invalid subdomain '%s' at line %d, skipping", subdomain, lineNum)
			continue
		}

		// Validate proxy_to (must not be empty)
		proxyTo := strings.TrimSpace(record[1])
		if proxyTo == "" {
			log.Printf("WARN: Empty proxy_to for subdomain '%s' at line %d, skipping", subdomain, lineNum)
			continue
		}

		// Parse booleans with error handling
		stripPath, err := strconv.ParseBool(strings.TrimSpace(record[2]))
		if err != nil {
			log.Printf("WARN: Invalid strip_path '%s' for subdomain '%s' at line %d, defaulting to false", record[2], subdomain, lineNum)
			stripPath = false
		}

		stripQuery, err := strconv.ParseBool(strings.TrimSpace(record[3]))
		if err != nil {
			log.Printf("WARN: Invalid strip_query '%s' for subdomain '%s' at line %d, defaulting to false", record[3], subdomain, lineNum)
			stripQuery = false
		}

		// Parse extra_headers JSON (5th column, optional)
		var extraHeaders map[string]string
		if len(record) >= 5 {
			extraHeadersStr := strings.TrimSpace(record[4])
			if extraHeadersStr != "" {
				if err := json.Unmarshal([]byte(extraHeadersStr), &extraHeaders); err != nil {
					log.Printf("WARN: Invalid extra_headers JSON for subdomain '%s' at line %d: %v, skipping extra headers", subdomain, lineNum, err)
					extraHeaders = nil
				}
			}
		}

		// Parse rate_limit (6th column, optional)
		var rateLimit *RateLimitConfig
		if len(record) == 6 {
			rateLimitStr := strings.TrimSpace(record[5])
			if rateLimitStr != "" {
				parsedLimit, err := parseRateLimit(rateLimitStr)
				if err != nil {
					log.Printf("WARN: Invalid rate_limit '%s' for subdomain '%s' at line %d: %v, using default", rateLimitStr, subdomain, lineNum, err)
					rateLimit = nil
				} else {
					rateLimit = parsedLimit
				}
			}
		}

		// Append rule to subdomain's backend list
		newRules[subdomain] = append(newRules[subdomain], ProxyRule{
			ProxyTo:      proxyTo,
			StripPath:    stripPath,
			StripQuery:   stripQuery,
			ExtraHeaders: extraHeaders,
			RateLimit:    rateLimit,
		})
	}

	if len(newRules) == 0 {
		proxyCSVReloadErrorsTotal.Inc()
		return fmt.Errorf("no valid proxy rules loaded from CSV")
	}

	// Count total backends across all subdomains
	totalBackends := 0
	for _, backends := range newRules {
		totalBackends += len(backends)
	}

	// Atomic swap
	s.rules.Store(newRules)
	now := time.Now()
	s.loadTime.Store(now)
	s.ruleCount.Store(int64(len(newRules)))

	// Rebuild loadbalancers for all subdomains (happens on CSV reload only, rare)
	newLoadbalancers := xsync.NewMap[string, *robin.Loadbalancer[ProxyRule]]()
	for subdomain, backends := range newRules {
		if len(backends) > 0 {
			newLoadbalancers.Store(subdomain, robin.NewLoadbalancer(backends))
		}
	}
	// Atomic swap - old loadbalancers will be GC'd when no requests reference them
	s.loadbalancers = newLoadbalancers

	// Update Prometheus metrics
	proxyRulesTotal.Set(float64(totalBackends))
	proxyRulesLastLoadTimestamp.Set(float64(now.Unix()))

	// Reset and update per-subdomain active metrics
	proxyRuleActive.Reset()
	for subdomain := range newRules {
		proxyRuleActive.WithLabelValues(subdomain).Set(1)
	}

	log.Printf("INFO: Loaded %d subdomains with %d total backends from %s", len(newRules), totalBackends, s.csvPath)
	return nil
}

// GetRules returns current rules (thread-safe)
func (s *ProxyService) GetRules() map[string][]ProxyRule {
	return s.rules.Load().(map[string][]ProxyRule)
}

// HandleProxy processes incoming requests and proxies them to the configured backend(s)
// Supports multiple backends per subdomain with round-robin load balancing and retry policies
func (s *ProxyService) HandleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Extract subdomain from Host header
	host := r.Host
	if host == "" {
		proxyRequestsTotal.WithLabelValues("unknown", "unknown", "400").Inc()
		http.Error(w, "Bad Request: Missing Host header", http.StatusBadRequest)
		return
	}

	// Parse subdomain (format: subdomain.api.pocket.network or subdomain.test-api.pocket.network)
	// Optimized: use IndexByte instead of Split to avoid allocation
	firstDot := strings.IndexByte(host, '.')
	if firstDot == -1 {
		proxyRequestsTotal.WithLabelValues("unknown", "unknown", "400").Inc()
		http.Error(w, "Bad Request: Invalid hostname format", http.StatusBadRequest)
		return
	}

	// Verify we have at least subdomain.x.y format
	secondDot := strings.IndexByte(host[firstDot+1:], '.')
	if secondDot == -1 {
		proxyRequestsTotal.WithLabelValues("unknown", "unknown", "400").Inc()
		http.Error(w, "Bad Request: Invalid hostname format", http.StatusBadRequest)
		return
	}

	subdomain := host[:firstDot]

	// Lookup backends for subdomain
	rules := s.GetRules()
	backends, exists := rules[subdomain]
	if !exists || len(backends) == 0 {
		proxyRequestsTotal.WithLabelValues(subdomain, "unknown", "404").Inc()
		http.Error(w, "Not Found: No proxy rule for this subdomain", http.StatusNotFound)
		return
	}

	// Get client IP using proper extraction (handles HAProxy/Cloudflare headers)
	clientIP := extractClientIP(r, s.trustProxy)

	// Check rate limit if enabled
	if s.rateLimitEnabled && s.rateLimiter != nil {
		// Determine rate limit config (per-subdomain override or global default)
		var rateLimitConfig *RateLimitConfig
		if len(backends) > 0 && backends[0].RateLimit != nil {
			rateLimitConfig = backends[0].RateLimit
		} else if s.defaultRateLimit != nil {
			rateLimitConfig = s.defaultRateLimit
		}

		if rateLimitConfig != nil {
			allowed, remaining, resetAt, err := s.rateLimiter.CheckLimit(
				r.Context(),
				clientIP,
				subdomain,
				rateLimitConfig.Requests,
				rateLimitConfig.Window,
			)

			// Add rate limit headers to response
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rateLimitConfig.Requests))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAt.Unix(), 10))

			if err != nil {
				// Redis error - log and fail open (allow request)
				log.Printf("ERROR: Rate limit check failed for IP %s, subdomain %s: %v (failing open)", clientIP, subdomain, err)
				proxyRateLimitRedisErrorsTotal.Inc()
			} else if !allowed {
				// Rate limit exceeded - return 429
				proxyRateLimitRequestsTotal.WithLabelValues(subdomain, "blocked").Inc()
				proxyRateLimitRemaining.WithLabelValues(subdomain).Set(float64(remaining))

				retryAfter := int(time.Until(resetAt).Seconds())
				if retryAfter < 0 {
					retryAfter = 0
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))

				http.Error(w, "Too Many Requests: Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			// Rate limit check passed
			proxyRateLimitRequestsTotal.WithLabelValues(subdomain, "allowed").Inc()
			proxyRateLimitRemaining.WithLabelValues(subdomain).Set(float64(remaining))
		}
	}

	// Check retry policy from header (default: retry-all)
	retryPolicy := r.Header.Get("Retry-Policy")
	if retryPolicy == "" {
		retryPolicy = "retry-all"
	} else {
		retryPolicy = strings.ToLower(strings.TrimSpace(retryPolicy))
	}

	// Round-robin: get loadbalancer for this subdomain (using atomicgo/robin)
	lb, exists := s.loadbalancers.Load(subdomain)
	if !exists {
		// This shouldn't happen since we rebuild loadbalancers on CSV load, but fallback to first backend
		http.Error(w, "Internal Server Error: No loadbalancer found", http.StatusInternalServerError)
		return
	}

	if retryPolicy == "retry-all" && len(backends) > 1 {
		// Try all backends until success (2xx) or all exhausted
		attemptCount := 0
		for i := 0; i < len(backends); i++ {
			rule := lb.Next()

			success, _, shouldReturn := s.tryBackend(w, r, subdomain, rule, start, host, clientIP, i == len(backends)-1)
			attemptCount++

			if success {
				// Track retry outcome - successful after trying multiple backends
				if attemptCount > 1 {
					proxyRetryAttemptsTotal.WithLabelValues(subdomain, "success").Inc()
				}
				return
			}

			if shouldReturn {
				// This was the last attempt and it failed
				if attemptCount > 1 {
					proxyRetryAttemptsTotal.WithLabelValues(subdomain, "all_failed").Inc()
				}
				return
			}
			// Continue to next backend
		}
		// All backends exhausted without response (shouldn't reach here)
		return
	}

	// Default: fail-fast - use single backend via round-robin
	rule := lb.Next()
	s.tryBackend(w, r, subdomain, rule, start, host, clientIP, true)
}

// tryBackend attempts to proxy to a single backend
// Returns (success, statusCode, shouldReturn) where:
// - success: true if the request succeeded (2xx status)
// - statusCode: the HTTP status code returned by the backend (0 if error before proxy)
// - shouldReturn: true if we should stop trying more backends (error was written to response)
func (s *ProxyService) tryBackend(w http.ResponseWriter, r *http.Request, subdomain string, rule ProxyRule, start time.Time, host string, clientIP string, isLastAttempt bool) (bool, int, bool) {
	// Parse backend URL
	targetURL, err := url.Parse(rule.ProxyTo)
	if err != nil {
		log.Printf("ERROR: Invalid proxy_to URL for subdomain '%s': %v", subdomain, err)
		if isLastAttempt {
			proxyRequestsTotal.WithLabelValues(subdomain, "unknown", "500").Inc()
			http.Error(w, "Internal Server Error: Invalid backend URL", http.StatusInternalServerError)
			return false, 500, true
		}
		return false, 0, false
	}

	backend := targetURL.Host

	// Store all metadata in the request context
	ctx := context.WithValue(r.Context(), proxyMetadataField, proxyMetadata{
		subdomain:     subdomain,
		startTime:     start,
		rule:          rule,
		targetURL:     targetURL,
		backend:       backend,
		scheme:        targetURL.Scheme,
		host:          host,
		clientIP:      clientIP,
		originalPath:  r.URL.Path,
		originalQuery: r.URL.RawQuery,
	})
	r = r.WithContext(ctx)

	// Get or create a cached proxy for this backend
	cacheKey := targetURL.Scheme + "://" + targetURL.Host
	var proxy *httputil.ReverseProxy

	if cached, ok := s.proxies.Load(cacheKey); ok {
		proxy = cached.(*httputil.ReverseProxy)
	} else {
		// Create a new reverse proxy
		proxy = s.createReverseProxy()
		s.proxies.Store(cacheKey, proxy)
	}

	// For retry-all on non-last attempts, we need to capture the response to check status
	if !isLastAttempt {
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, r)

		// Check if successful (2xx status)
		if rec.Code >= 200 && rec.Code < 300 {
			// Success! Copy to real response writer
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			if _, err := w.Write(rec.Body.Bytes()); err != nil {
				log.Printf("WARN: Failed to write response body: %v", err)
			}
			return true, rec.Code, true
		}

		// Check if error is retryable (5xx or 429 rate limit)
		isRetryable := rec.Code >= 500 || rec.Code == 429
		if !isRetryable {
			// 4xx client error (except 429) - don't retry, return immediately
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			if _, err := w.Write(rec.Body.Bytes()); err != nil {
				log.Printf("WARN: Failed to write response body: %v", err)
			}
			log.Printf("INFO: Backend %s returned non-retryable status %d for subdomain '%s', not retrying", backend, rec.Code, subdomain)
			return false, rec.Code, true
		}

		// Retryable error (5xx or 429), track backend failure and continue to next backend
		proxyBackendFailuresTotal.WithLabelValues(subdomain, backend).Inc()
		log.Printf("WARN: Backend %s failed for subdomain '%s' with status %d (retryable), trying next backend", backend, subdomain, rec.Code)
		return false, rec.Code, false
	}

	// Last attempt or fail-fast: use recorder to capture status code
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, r)

	// Copy to real response writer
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.Code)
	if _, err := w.Write(rec.Body.Bytes()); err != nil {
		log.Printf("WARN: Failed to write response body: %v", err)
	}

	// Return success only if 2xx
	success := rec.Code >= 200 && rec.Code < 300
	return success, rec.Code, true
}

// createReverseProxy creates a new httputil.ReverseProxy with custom Director, ModifyResponse, and ErrorHandler
func (s *ProxyService) createReverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Get metadata from context
			meta, ok := req.Context().Value(proxyMetadataField).(proxyMetadata)
			if !ok {
				return
			}

			// Record backend start time (after Taiji routing/header processing, before sending to backend)
			ctx := context.WithValue(req.Context(), backendStartTimeField, time.Now())
			*req = *req.WithContext(ctx)

			// Set backend URL
			req.URL.Scheme = meta.targetURL.Scheme
			req.URL.Host = meta.targetURL.Host

			// Set Host header - check if custom Host is in extra_headers first
			if customHost, hasCustomHost := meta.rule.ExtraHeaders["Host"]; hasCustomHost {
				req.Host = customHost
			} else {
				req.Host = meta.targetURL.Host
			}

			// Handle path
			if meta.rule.StripPath {
				req.URL.Path = meta.targetURL.Path
			} else {
				if meta.targetURL.Path != "" {
					req.URL.Path = singleJoiningSlash(meta.targetURL.Path, meta.originalPath)
				} else {
					req.URL.Path = meta.originalPath
				}
			}

			// Handle query string
			if meta.rule.StripQuery {
				req.URL.RawQuery = ""
			} else if meta.targetURL.RawQuery != "" {
				if meta.originalQuery != "" {
					req.URL.RawQuery = meta.targetURL.RawQuery + "&" + meta.originalQuery
				} else {
					req.URL.RawQuery = meta.targetURL.RawQuery
				}
			} else {
				req.URL.RawQuery = meta.originalQuery
			}

			// Apply extra headers from backend config (except Host which was already set)
			for k, v := range meta.rule.ExtraHeaders {
				if k == "Host" {
					// Host was already set via req.Host above
					continue
				}
				req.Header.Set(k, v)
			}

			// Add X-Forwarded-* headers (legacy, but widely supported)
			if prior, ok := req.Header["X-Forwarded-For"]; ok {
				req.Header.Set("X-Forwarded-For", strings.Join(prior, ", ")+", "+meta.clientIP)
			} else {
				req.Header.Set("X-Forwarded-For", meta.clientIP)
			}
			req.Header.Set("X-Real-IP", meta.clientIP)
			req.Header.Set("X-Forwarded-Proto", meta.scheme)
			req.Header.Set("X-Forwarded-Host", meta.host)

			// Add standard Forwarded header (RFC 7239)
			forwardedValue := fmt.Sprintf("for=%s;host=%s;proto=%s", meta.clientIP, meta.host, meta.scheme)
			if prior, ok := req.Header["Forwarded"]; ok {
				req.Header.Set("Forwarded", strings.Join(prior, ", ")+", "+forwardedValue)
			} else {
				req.Header.Set("Forwarded", forwardedValue)
			}
		},
		Transport:  s.transport,
		BufferPool: &BufferPool{}, // Reuse buffers across requests (reduces allocations & GC pressure)
		ModifyResponse: func(resp *http.Response) error {
			// Get metadata from context and update metrics
			if meta, ok := resp.Request.Context().Value(proxyMetadataField).(proxyMetadata); ok {
				now := time.Now()
				totalDuration := now.Sub(meta.startTime).Seconds()

				// Calculate backend duration (from Director start to ModifyResponse)
				backendDuration := 0.0
				if backendStartVal := resp.Request.Context().Value(backendStartTimeField); backendStartVal != nil {
					if backendStart, ok := backendStartVal.(time.Time); ok {
						backendDuration = now.Sub(backendStart).Seconds()
					}
				}

				// Calculate proxy overhead (total - backend)
				proxyOverhead := totalDuration - backendDuration
				if proxyOverhead < 0 {
					proxyOverhead = 0 // Safety check for clock skew
				}

				// Record metrics
				statusCode := resp.StatusCode
				statusCodeStr := statusCodeToString(statusCode)
				proxyRequestsTotal.WithLabelValues(meta.subdomain, meta.backend, statusCodeStr).Inc()
				proxyRequestDuration.WithLabelValues(meta.subdomain, meta.backend, statusCodeStr).Observe(totalDuration)
				proxyBackendDuration.WithLabelValues(meta.subdomain, meta.backend, statusCodeStr).Observe(backendDuration)
				proxyOverheadDuration.WithLabelValues(meta.subdomain, meta.backend, statusCodeStr).Observe(proxyOverhead)
				proxyLastRequestTimestamp.WithLabelValues(meta.subdomain, meta.backend).Set(float64(now.Unix()))
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			// Get metadata from context
			if meta, ok := req.Context().Value(proxyMetadataField).(proxyMetadata); ok {
				log.Printf("ERROR: Backend request failed for subdomain '%s' backend '%s': %v", meta.subdomain, meta.backend, err)
				proxyRequestsTotal.WithLabelValues(meta.subdomain, meta.backend, statusCodeStrings[502]).Inc()
			}
			http.Error(w, "Bad Gateway: Backend request failed", http.StatusBadGateway)
		},
		FlushInterval: -1, // Flush immediately for streaming
	}
}

// singleJoiningSlash joins two URL paths with a single slash
func singleJoiningSlash(a, b string) string {
	aSlash := strings.HasSuffix(a, "/")
	bSlash := strings.HasPrefix(b, "/")
	switch {
	case aSlash && bSlash:
		return a + b[1:]
	case !aSlash && !bSlash:
		return a + "/" + b
	}
	return a + b
}

// HandleHealth health check endpoint
func (s *ProxyService) HandleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("OK"))
	if err != nil {
		log.Printf("ERROR: fail to write health response: %v", err)
		return
	}
}

// HandleReady Readiness check endpoint
func (s *ProxyService) HandleReady(w http.ResponseWriter, _ *http.Request) {
	ruleCount := s.ruleCount.Load()
	if ruleCount == 0 {
		http.Error(w, "Not Ready: No rules loaded", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("READY"))
	if err != nil {
		log.Printf("ERROR: fail to write ready response: %v", err)
		return
	}
}

// Router multiplexes requests to appropriate handlers
func (s *ProxyService) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.HandleHealth)
	mux.HandleFunc("/healthz", s.HandleHealth)
	mux.HandleFunc("/ready", s.HandleReady)
	mux.HandleFunc("/readyz", s.HandleReady)
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/", s.HandleProxy)
	return mux
}

// WatchConfigFile watches for changes to the CSV file and reloads
// This function includes panic recovery and will return on error or context cancellation
func (s *ProxyService) WatchConfigFile(ctx context.Context) error {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: Panic in WatchConfigFile: %v", r)
		}
	}()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	defer func(watcher *fsnotify.Watcher) {
		_ = watcher.Close()
	}(watcher)

	// Watch the directory containing the CSV file (ConfigMaps update via symlink swap)
	// Extract directory from CSV path
	watchDir := "/config" // Default for Kubernetes
	if len(s.csvPath) > 0 {
		// Get directory from the actual CSV path
		lastSlash := strings.LastIndex(s.csvPath, "/")
		if lastSlash > 0 {
			watchDir = s.csvPath[:lastSlash]
		}
	}

	// Check if a directory exists before watching
	if _, err := os.Stat(watchDir); os.IsNotExist(err) {
		return fmt.Errorf("watch directory does not exist: %s (this is normal for local development)", watchDir)
	}

	if err := watcher.Add(watchDir); err != nil {
		return fmt.Errorf("failed to watch directory %s: %w", watchDir, err)
	}

	log.Printf("INFO: Watching %s for configuration changes", watchDir)

	for {
		select {
		case <-ctx.Done():
			log.Println("INFO: Config watcher shutting down (context canceled)")
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("watcher events channel closed")
			}
			// ConfigMap updates trigger Create or Write events
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				log.Printf("INFO: Configuration change detected, reloading rules...")
				time.Sleep(1 * time.Second) // Debounce
				if err := s.LoadRules(); err != nil {
					log.Printf("ERROR: Failed to reload rules: %v", err)
				} else {
					log.Printf("INFO: Rules reloaded successfully")
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return fmt.Errorf("watcher errors channel closed")
			}
			log.Printf("ERROR: File watcher error: %v", err)
		}
	}
}

// StartWatcherWithRestart runs the file watcher and automatically restarts it on failure
func (s *ProxyService) StartWatcherWithRestart(ctx context.Context) {
	go func() {
		attempt := 0
		maxBackoff := 5 * time.Minute
		consecutiveFailures := 0

		for {
			select {
			case <-ctx.Done():
				log.Println("INFO: Watcher restart loop shutting down")
				return
			default:
			}

			attempt++
			if attempt > 1 {
				proxyWatcherRestarts.Inc()
				log.Printf("INFO: Restarting file watcher (attempt %d)", attempt)
			}

			// Run watcher (blocks until error or context cancel)
			err := s.WatchConfigFile(ctx)

			// If context was canceled, exit cleanly
			if ctx.Err() != nil {
				log.Println("INFO: Watcher stopped due to context cancellation")
				return
			}

			// Check if this is a "directory does not exist" error (normal for local dev)
			if err != nil && strings.Contains(err.Error(), "does not exist") {
				consecutiveFailures++
				if consecutiveFailures == 1 {
					log.Printf("WARN: File watcher disabled - %v", err)
				}
				// After 3 failures with a non-existent directory, stop trying (a local dev scenario)
				if consecutiveFailures >= 3 {
					log.Println("INFO: File watcher permanently disabled (directory does not exist)")
					return
				}
				// Use longer backoff for "does not exist" errors
				backoff := 30 * time.Second
				select {
				case <-time.After(backoff):
					// Continue to retry
				case <-ctx.Done():
					log.Println("INFO: Watcher restart canceled")
					return
				}
				continue
			}

			// Reset consecutive failures on different error type
			consecutiveFailures = 0

			// Watcher failed for other reasons, calculate backoff and retry
			backoff := time.Duration(math.Min(float64(time.Second)*math.Pow(2, float64(attempt-1)), float64(maxBackoff)))
			log.Printf("ERROR: File watcher stopped: %v. Restarting in %v...", err, backoff)

			select {
			case <-time.After(backoff):
				// Continue to restart
			case <-ctx.Done():
				log.Println("INFO: Watcher restart canceled")
				return
			}
		}
	}()
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("INFO: Starting Taiji (太极) - High-performance reverse proxy...")

	// Enable pprof profiling
	runtime.SetMutexProfileFraction(1) // Enable mutex profiling
	runtime.SetBlockProfileRate(1)     // Enable block profiling

	// Start pprof server on port 6060
	go func() {
		log.Println("INFO: Starting pprof server on :6060")
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// Get configuration from the environment
	csvPath := os.Getenv("CSV_PATH")
	if csvPath == "" {
		csvPath = defaultCSVPath
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	// Rate limiting configuration
	rateLimitEnabled := true
	if rateLimitEnv := os.Getenv("RATE_LIMIT_ENABLED"); rateLimitEnv != "" {
		var err error
		rateLimitEnabled, err = strconv.ParseBool(rateLimitEnv)
		if err != nil {
			log.Printf("WARN: Invalid RATE_LIMIT_ENABLED value '%s', defaulting to true", rateLimitEnv)
			rateLimitEnabled = true
		}
	}

	trustProxy := true
	if trustProxyEnv := os.Getenv("RATE_LIMIT_TRUST_PROXY"); trustProxyEnv != "" {
		var err error
		trustProxy, err = strconv.ParseBool(trustProxyEnv)
		if err != nil {
			log.Printf("WARN: Invalid RATE_LIMIT_TRUST_PROXY value '%s', defaulting to true", trustProxyEnv)
			trustProxy = true
		}
	}

	// Parse default rate limit
	var defaultRateLimit *RateLimitConfig
	defaultRateLimitStr := os.Getenv("RATE_LIMIT_DEFAULT")
	if defaultRateLimitStr == "" {
		defaultRateLimitStr = "100/1m"
	}
	parsedDefault, err := parseRateLimit(defaultRateLimitStr)
	if err != nil {
		log.Printf("WARN: Invalid RATE_LIMIT_DEFAULT '%s': %v, using 100/1m", defaultRateLimitStr, err)
		defaultRateLimit = &RateLimitConfig{Requests: 100, Window: time.Minute}
	} else {
		defaultRateLimit = parsedDefault
	}

	// Initialize Redis client for rate limiting
	var rateLimiter *RateLimiter
	if rateLimitEnabled {
		redisAddr := os.Getenv("REDIS_ADDR")
		if redisAddr == "" {
			redisAddr = "localhost:6379"
		}
		redisPassword := os.Getenv("REDIS_PASSWORD")
		redisDB := 0
		if redisDBStr := os.Getenv("REDIS_DB"); redisDBStr != "" {
			parsedDB, err := strconv.Atoi(redisDBStr)
			if err != nil {
				log.Printf("WARN: Invalid REDIS_DB value '%s', using 0", redisDBStr)
			} else {
				redisDB = parsedDB
			}
		}

		redisClient := redis.NewClient(&redis.Options{
			Addr:         redisAddr,
			Password:     redisPassword,
			DB:           redisDB,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			PoolSize:     100,
			MinIdleConns: 10,
		})

		// Test Redis connection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			log.Printf("WARN: Failed to connect to Redis at %s: %v (rate limiting will be disabled)", redisAddr, err)
			rateLimitEnabled = false
		} else {
			log.Printf("INFO: Connected to Redis at %s for rate limiting", redisAddr)
			rateLimiter = &RateLimiter{redis: redisClient}
		}
	}

	if rateLimitEnabled && rateLimiter != nil {
		log.Printf("INFO: Rate limiting enabled: %d requests per %s (default)", defaultRateLimit.Requests, defaultRateLimit.Window)
	} else {
		log.Println("INFO: Rate limiting disabled")
	}

	// Initialize service
	service := NewProxyService(csvPath, rateLimiter, rateLimitEnabled, defaultRateLimit, trustProxy)

	// Initial load
	if err := service.LoadRules(); err != nil {
		log.Fatalf("FATAL: Failed to load initial rules: %v", err)
	}

	// Set up a graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the config file watcher with auto-restart
	service.StartWatcherWithRestart(ctx)

	// Configure HTTP server with VERY generous settings for streaming/long-running requests
	// We don't control what backends or clients expect, so timeouts are minimal
	server := &http.Server{
		Addr:    ":" + port,
		Handler: service.Router(),
		// ReadTimeout covers: time to read request headers + body
		// Set to 0 to support long-running uploads (e.g., large file uploads, streaming requests)
		ReadTimeout: 0,
		// ReadHeaderTimeout prevents Slowloris attacks while allowing streaming body
		ReadHeaderTimeout: 30 * time.Second,
		// WriteTimeout covers: time to write response
		// Set to 0 to support long-running responses (e.g., SSE, large downloads, streaming)
		WriteTimeout: 0,
		// IdleTimeout for keep-alive connections
		IdleTimeout: 120 * time.Second,
		// MaxHeaderBytes prevents huge headers
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Handle a graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		log.Printf("INFO: Server listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("FATAL: Server error: %v", err)
		}
	}()

	// Wait for a shutdown signal
	sig := <-sigChan
	log.Printf("INFO: Received signal %v, shutting down gracefully...", sig)

	// Cancel context to stop watchers
	cancel()

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("ERROR: Server shutdown error: %v", err)
	}

	log.Println("INFO: Server stopped")
}
