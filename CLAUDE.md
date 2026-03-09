# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Taiji (太极) is a high-performance HTTP reverse proxy built in Go that routes requests from wildcard subdomains to backend services. The project emphasizes performance (zero-copy streaming, ~1-2ms latency), simplicity (single-file architecture), and production-readiness (health checks, distributed rate limiting, hot reloading).

## Commands

### Development
```bash
# Run locally with default config (examples/proxies.yaml)
make run

# Build binary (output: bin/taiji)
make build

# Format code
make fmt

# Lint code (requires golangci-lint)
make lint

# Tidy modules
make mod-tidy
```

### Testing
```bash
# Go unit tests (run with race detector)
go test -race -count=1 -timeout 60s

# Basic integration tests (uses test.sh script)
./test.sh

# Test with docker-compose services (httpbin + redis)
make test-local

# Test distributed rate limiting (2 Taiji instances + HAProxy + Redis)
make test-distributed

# Health check tests
./test-health.sh
```

### Load Testing
```bash
# Quick load test (100 req, 10 concurrent, 10s)
make load-test-quick

# Stress test (10k req, 200 concurrent, 60s)
make load-test-stress

# Custom load test
make load-test LOAD_TEST_URL=... LOAD_TEST_REQUESTS=... LOAD_TEST_CONCURRENCY=...
```

### Docker
```bash
# Build Docker image
make docker-build

# Run Docker container locally
make docker-run

# Build multi-platform (arm64/amd64)
make docker-buildx
```

## Architecture

### Single-File Design
All application logic lives in `main.go` (~2,300 lines). This is intentional for simplicity and performance. There are no separate packages or subdirectories for core logic. Tests live in `main_test.go`.

### Core Components

**Configuration (YAML-based)**
- Lives in `examples/proxies.yaml` by default
- Hot-reloads via fsnotify file watcher (1s debounce)
- Preserves health states across reloads (atomic pointer swaps, no data races)
- Supports per-service rate limits, health checks, primary/fallback backends
- Backends can have weights for load balancing (weight=3 means 3x traffic)

**Load Balancing**
- Round-robin using `atomicgo.dev/robin` package
- Per-request loadbalancers built from healthy backends only (unhealthy backends never receive traffic)
- Weight-based distribution via entry duplication (weight=3 creates 3 entries)
- Health-filtered LBs ensure retry loops don't distort distribution for concurrent requests

**Health Checking (Dual-Mode)**
- **Active checks**: Cron-based (every 10s), configurable HTTP method/payload/timeout/failure threshold
- **Passive checks**: Traffic-based, triggered on 5xx errors during proxying for faster failure detection
- Health state tracked with atomic operations (`atomic.Bool`, `atomic.Int32`) for thread-safety
- Backends without health check config are always considered healthy
- Weighted backends are deduplicated before health checking (weight=3 only checks once)

**Rate Limiting**
- Redis-backed sliding window algorithm using atomic Lua script
- Per-IP, per-subdomain tracking across all Taiji instances
- Lua script ensures atomicity across pods (no race between count check and add)
- Blocked requests do NOT consume rate limit budget
- Fails open if Redis unavailable (allows requests)
- Returns standard `X-RateLimit-*` headers and `Retry-After` on 429s
- Format: `100/1m`, `1000/1h`, `10/30s`

**Request Handling**
- **Streaming requests** (WebSocket, gRPC): Direct proxy, no buffering, no retry
- **Retry-all policy**: Server-side config only (`retry_policy: retry-all` in YAML). Buffers response, retries on 5xx/429. Client `Retry-Policy` header is ignored for security.
- **Fail-fast/default**: Zero-copy streaming, optimal performance (`FlushInterval: -1`)

**Metrics**
- Comprehensive Prometheus metrics (~20 metrics)
- Pre-configured Grafana dashboard in `monitoring/grafana/taiji-dashboard.yaml`
- Prometheus alerts in `monitoring/prometheus/taiji-alerts.yaml`
- Key metrics: request counts, latency histograms (total/backend/overhead), health status, rate limit stats
- Backend label normalization cached via `sync.Map` (avoids URL parsing per request)

### Internal Endpoints (underscore-prefixed to avoid collision with proxied paths)
- `/_health`, `/healthz`: Liveness probe
- `/_ready`, `/readyz`: Readiness probe (returns 503 if no rules loaded)
- `/_metrics`: Prometheus metrics

### Thread-Safety Patterns
- `atomic.Value` for rules map, load time, and default rate limit message
- `atomic.Pointer` for health states, fallback rules, health check configs (safe hot-reload swaps)
- `atomic.Bool/Int32` for health state (lock-free)
- `sync.Map` for ReverseProxy cache and backend label normalization cache
- `sync.Pool` for 32KB buffer reuse (reduces GC pressure)

### Performance Optimizations
- **Zero-copy streaming**: `FlushInterval: -1` for immediate flushing
- **Connection pooling**: 1000 idle conns per host, optimized TCP buffers (128KB)
- **HTTP/2 tuning**: 256KB frame size (vs default 16KB)
- **Buffer pooling**: `sync.Pool` for httputil.ReverseProxy buffers
- **Pre-allocated strings**: Status code strings and health response bytes to avoid allocations
- **Pre-compiled regex**: Forwarded header regex compiled once at package level
- **Zero-alloc subdomain extraction**: `strings.IndexByte` instead of `strings.Split`
- **Cached backend normalization**: `normalizeBackendLabel` results cached in `sync.Map`
- **String concatenation**: Hot-path key building uses `+` instead of `fmt.Sprintf`
- **Server timeouts**: `ReadTimeout: 0`, `WriteTimeout: 0` for unlimited streaming support

### Request Flow
```
Request -> metricsWrapper middleware
  -> Extract subdomain from Host header
  -> Lookup backends for subdomain
  -> Filter to healthy backends only
  -> Try fallback backends if all primaries unhealthy
  -> Build per-request loadbalancer from healthy backends
  -> Check rate limit (Redis Lua script)
  -> Select backend via round-robin
  -> [If streaming] -> Direct proxy (no buffering)
  -> [If retry-all] -> Buffer with httptest.NewRecorder, retry on 5xx/429
  -> [Default] -> Direct proxy (zero-copy)
  -> ReverseProxy (Director, ModifyResponse, ErrorHandler)
  -> Record metrics in deferred function
```

## Configuration Details

### Environment Variables
- `CONFIG_PATH`: Path to YAML config (default: `examples/proxies.yaml`)
- `PORT`: Server port (default: `8080`)
- `RATE_LIMIT_ENABLED`: Enable rate limiting (default: `true`)
- `RATE_LIMIT_DEFAULT`: Default rate limit (default: `100/1m`)
- `RATE_LIMIT_TRUST_PROXY`: Trust proxy headers for IP extraction (default: `true`)
- `TRUSTED_PROXY_CIDRS`: Comma-separated CIDRs for trusted proxies (e.g., `10.0.0.0/8,172.16.0.0/12`). When set, proxy headers like `X-Forwarded-For` are only trusted from these source IPs. When unset, all sources are trusted (backward compatible).
- `REDIS_ADDR`: Redis address (default: `localhost:6379`)
- `REDIS_PASSWORD`: Redis password (optional)
- `REDIS_DB`: Redis database number (default: `0`)
- `PPROF_DISABLED`: Set to `true` to disable pprof profiling on `:6060` (default: enabled for K8s debugging)

### YAML Configuration
See `examples/proxies.yaml` for format. Key fields:
- `services[].name`: Subdomain to match (e.g., "eth" matches eth.api.pocket.network)
- `services[].rate_limit`: Per-service override (e.g., `100/1m`)
- `services[].retry_policy`: Server-side retry policy — `"fail-fast"` (default) or `"retry-all"`
- `services[].health_check`: Optional health check config (path, method, timeout, failure_threshold)
- `services[].backends[]`: Primary backends with URL, strip_path, strip_query, extra_headers, weight
- `services[].fallbacks[]`: Fallback backends (used when all primaries unhealthy)

### Retry Policy
Retry behavior is configured per-service in YAML (not via client headers):
- `retry_policy: fail-fast` (default): Try one backend, fail immediately on error
- `retry_policy: retry-all`: Try all backends until one succeeds (5xx/429 are retryable, 4xx are not)

The client `Retry-Policy` header is ignored to prevent DoS amplification attacks.

## Testing Strategy

Testing uses both Go unit tests and shell script integration tests:
1. **Go unit tests**: `main_test.go` — validates critical bugs (health filtering, retry logic, data races, route matching, IP extraction)
2. **Shell script integration tests**: `test.sh`, `test-health.sh`, `test-distributed.sh`, `test-stage.sh`
3. **Docker Compose**: Multi-service testing with httpbin, redis, HAProxy
4. **Prometheus metrics**: Runtime observability
5. **Load testing**: Using `hey` tool via Makefile targets

Always run `go test -race` to catch data races.

## Key Files
- `main.go`: All application logic (~2,300 lines)
- `main_test.go`: Go unit tests and benchmarks
- `examples/proxies.yaml`: Configuration example
- `Dockerfile`: Container build
- `docker-compose.yml`: Multi-service test environment
- `monitoring/grafana/taiji-dashboard.yaml`: Pre-configured dashboard
- `monitoring/prometheus/taiji-alerts.yaml`: Alert rules
- `test*.sh`: Integration test scripts

## Dependencies
All managed via `go.mod`:
- `fsnotify/fsnotify`: File watching for hot reload
- `prometheus/client_golang`: Metrics
- `atomicgo.dev/robin`: Round-robin load balancing
- `alitto/pond`: Worker pool for health checks
- `redis/go-redis`: Redis client for rate limiting
- `robfig/cron`: Cron scheduler for health checks
- `puzpuzpuz/xsync`: Lock-free concurrent maps
- `golang.org/x/net/http2`: HTTP/2 and h2c support
- `gopkg.in/yaml.v3`: YAML parsing

## Important Implementation Details

**Health Check Recovery**: One successful active check marks backend healthy. Failure threshold is configurable (default: 5 consecutive failures).

**Passive Health Checks**: Only tracked for services that have `health_check` configured. Backends without health checks are never marked unhealthy.

**Path/Query Handling**: `strip_path` and `strip_query` flags control how incoming paths/queries are forwarded. Backend URLs can include paths that are joined with incoming paths.

**Client IP Extraction**: Priority order: `Forwarded` (RFC 7239) -> `CF-Connecting-IP` -> `True-Client-IP` -> `X-Forwarded-For` -> `X-Real-IP` -> `RemoteAddr`. When `TRUSTED_PROXY_CIDRS` is set, headers are only trusted from connections originating from those CIDRs.

**Backend Metrics Normalization**: Backend labels extract last 2 domain parts (e.g., "eth.gateway.pocket.network" -> "pocket.network") to reduce cardinality. Results are cached in a `sync.Map`.

**WebSocket/gRPC Support**: Detected via `Upgrade: websocket` header or `Content-Type: application/grpc`. These bypass retry logic and use direct proxy with hijacking support.

**HTTP/2 Cleartext**: h2c handler wraps the router to support both HTTP/1.1 and HTTP/2 on the same port (needed for gRPC).

**Graceful Shutdown**: Handles SIGINT/SIGTERM, stops health checker (cron + worker pool), shuts down server with 30s timeout, cancels file watcher context.

**ResponseHeaderTimeout**: Set to 5 minutes to prevent hanging backends from holding goroutines forever while still supporting long-running requests.
