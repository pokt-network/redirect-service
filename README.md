# Taiji (太极)

High-performance HTTP reverse proxy with wildcard subdomain routing, health checks, distributed rate limiting, and zero-copy streaming.

*Like the martial art, Taiji smoothly redirects incoming requests with effortless flow and zero resistance.*

## What is Taiji?

Taiji is a production-ready reverse proxy that routes requests from wildcard subdomains (e.g., `*.api.pocket.network`) to backend services based on YAML configuration. Built on Go's `net/http` and `httputil.ReverseProxy`, it handles high-throughput traffic with minimal latency.

### Core Capabilities

- **Health Checks** - Active (periodic) + passive (traffic-based) health monitoring with configurable failure thresholds and fallback backends
- **Zero-Copy Streaming** - True streaming with no buffering. Supports uploads/downloads of any size, SSE, WebSockets, chunked encoding, and long-running connections
- **Distributed Rate Limiting** - Redis-backed sliding window algorithm with per-IP tracking across all instances
- **Load Balancing** - Round-robin across multiple backends with configurable retry policies
- **Hot Reloading** - YAML configuration updates apply automatically without restart, preserving health states
- **Production-Grade** - ~1-2ms added latency, unlimited timeouts for streaming, connection pooling, Prometheus metrics

### How It Works

```
Request: https://eth.api.pocket.network/v1/relay?chain=1
         ↓
Taiji: Extracts subdomain "eth", looks up backend in YAML
         ↓
Health Check: Filters out unhealthy backends
         ↓
Load Balancer: Selects healthy backend (round-robin)
         ↓
Backend: https://backend.example.com/api/v1/relay?chain=1
         ↓
Response: Streams backend response to client
         ↓
Passive Check: Tracks 5xx errors, marks backend unhealthy after threshold
```

## Quick Start

```bash
# Start backend services (httpbin + redis)
docker compose up -d

# Run Taiji
go run main.go

# Test it
curl http://localhost:8080/get -H "Host: httpbin.test-api.pocket.network"
```

## Configuration

### YAML Format

```yaml
services:
  - name: eth
    rate_limit: "100/1m"
    health_check:
      path: "/health"
      method: "GET"              # HTTP method (default: GET)
      timeout: 5                 # Timeout in seconds (default: 5)
      failure_threshold: 3       # Consecutive failures before unhealthy (default: 5)
    backends:
      - url: "https://backend1.example.com/api"
        strip_path: false
        strip_query: false
      - url: "https://backend2.example.com/api"
        strip_path: false
        strip_query: false
        extra_headers: '{"Authorization": "Bearer token"}'
    fallbacks:
      - url: "https://fallback.example.com/api"
        strip_path: false
        strip_query: false
```

**Service Fields:**
- `name` - Subdomain to match (e.g., "eth" matches eth.api.pocket.network)
- `rate_limit` - Per-subdomain limit (e.g., `100/1m`, `1000/1h`) or omit for default
- `health_check` - Optional health check configuration
- `backends` - List of primary backends (load balanced with round-robin)
- `fallbacks` - Optional fallback backends (used when all primaries unhealthy)

**Backend Fields:**
- `url` - Backend URL with optional path (must include http:// or https://)
- `strip_path` - Remove incoming path before forwarding (default: false)
- `strip_query` - Remove incoming query string before forwarding (default: false)
- `extra_headers` - JSON object with custom headers (optional)

**Health Check Fields:**
- `path` - Health check endpoint path
- `method` - HTTP method: GET, POST, PUT, etc. (default: GET)
- `timeout` - Request timeout in seconds (default: 5)
- `payload` - Request body for POST/PUT (optional)
- `failure_threshold` - Consecutive failures before marking unhealthy (default: 5)

**Path/Query Examples:**

| strip_path | strip_query | Request: `/foo?bar=1` | Forwarded to backend |
|------------|-------------|-----------------------|----------------------|
| `true`     | `true`      | `/foo?bar=1`          | `/`                  |
| `false`    | `true`      | `/foo?bar=1`          | `/foo`               |
| `false`    | `false`     | `/foo?bar=1`          | `/foo?bar=1`         |
| `true`     | `false`     | `/foo?bar=1`          | `/?bar=1`            |

**Health Check Behavior:**
- **Active Checks**: Run every 10 seconds for all backends with health_check configured
- **Passive Checks**: Track 5xx errors and connection failures from real traffic
- **Recovery**: One successful active check marks backend healthy again
- **Fallbacks**: Automatically used when all primary backends are unhealthy
- **No Health Check**: Backends always considered healthy, no passive tracking

Control retry behavior with `Retry-Policy` header:
- `Retry-Policy: fail-fast` (default) - Try one backend, fail immediately if it errors
- `Retry-Policy: retry-all` - Try all backends until one succeeds

### Environment Variables

| Variable                  | Default                 | Description                                          |
|---------------------------|-------------------------|------------------------------------------------------|
| `CONFIG_PATH`             | `examples/proxies.yaml` | Path to YAML configuration file                      |
| `PORT`                    | `8080`                 | HTTP server port                                     |
| `RATE_LIMIT_ENABLED`      | `true`                 | Enable/disable rate limiting                         |
| `RATE_LIMIT_DEFAULT`      | `100/1m`               | Default rate limit (requests/duration)               |
| `RATE_LIMIT_TRUST_PROXY`  | `true`                 | Trust proxy headers for IP extraction                |
| `REDIS_ADDR`              | `localhost:6379`       | Redis server address for rate limiting               |
| `REDIS_PASSWORD`          | (empty)                | Redis password (optional)                            |
| `REDIS_DB`                | `0`                    | Redis database number                                |

YAML changes are detected automatically and reload within ~1 second (no restart needed). Health states are preserved across reloads.

### Rate Limiting

Distributed IP-based rate limiting using Redis with sliding window algorithm:

**How it works:**
- Per-IP tracking across all Taiji instances via shared Redis state
- Sliding window algorithm prevents boundary exploits
- Extracts real client IP from `Forwarded`, `CF-Connecting-IP`, `X-Forwarded-For`, etc.
- Returns standard `X-RateLimit-*` headers and `Retry-After` on 429s
- Fails open if Redis unavailable (allows requests)

**Rate limit format:** `{requests}/{duration}` - e.g., `100/1m`, `1000/1h`, `10/30s`

**Example response headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 47
X-RateLimit-Reset: 1704067200
```

**Test distributed rate limiting:**
```bash
make test-distributed  # 2 Taiji instances + HAProxy + Redis
```

### Headers & Forwarding

Taiji forwards all client headers to backends plus:
- `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host` (legacy)
- `Forwarded: for=<clientIP>;host=<host>;proto=<scheme>` (RFC 7239)

## Deployment

**Docker:**
```bash
docker run -d -p 8080:8080 \
  -v $(pwd)/proxies.yaml:/config/proxies.yaml:ro \
  -e REDIS_ADDR=redis:6379 \
  ghcr.io/pokt-network/taiji:latest
```

**Kubernetes:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: taiji
spec:
  template:
    spec:
      containers:
      - name: taiji
        image: ghcr.io/pokt-network/taiji:latest
        env:
        - name: REDIS_ADDR
          value: "redis:6379"
        - name: RATE_LIMIT_DEFAULT
          value: "100/1m"
```

**Binary:**
```bash
make build
CONFIG_PATH=/path/to/proxies.yaml ./bin/taiji
```

## API Endpoints

| Endpoint       | Description                                               |
|----------------|-----------------------------------------------------------|
| `GET /health`  | Health check (always returns 200 OK)                      |
| `GET /ready`   | Readiness check (returns 503 if no rules loaded)          |
| `GET /metrics` | Prometheus metrics                                        |
| `* /*`         | Proxy handler (subdomain-based routing, all HTTP methods) |

## Monitoring

**Pre-configured resources:** `monitoring/grafana/taiji-dashboard.yaml` and `monitoring/prometheus/taiji-alerts.yaml`

**Key Prometheus metrics:**
```
proxy_requests_total{subdomain,backend,status_code}    # Request counts
proxy_request_duration_seconds{subdomain,backend}      # Latency histogram
proxy_backend_health_status{subdomain,backend}         # Backend health (1=healthy, 0=unhealthy)
proxy_health_checks_total{subdomain,backend,result}    # Health check results
proxy_fallback_requests_total{subdomain}               # Requests routed to fallbacks
proxy_all_backends_unhealthy_total{subdomain}          # 503 responses (all backends down)
proxy_ratelimit_requests_total{subdomain,action}       # Rate limit allowed/blocked
proxy_ratelimit_check_duration_seconds                 # Redis latency
proxy_rules_total                                      # Loaded backends
```

**Deploy monitoring:**
```bash
kubectl apply -f monitoring/grafana/taiji-dashboard.yaml
kubectl apply -f monitoring/prometheus/taiji-alerts.yaml
```

## Testing & Development

**Run tests:**
```bash
./test.sh                   # Basic test suite
make test-distributed       # Distributed rate limiting (2 instances + HAProxy + Redis)
```

**Load testing:**
```bash
make load-test-quick        # 100 req, 10 concurrent, 10s
make load-test-stress       # 10k req, 200 concurrent, 60s
make load-test LOAD_TEST_URL=... LOAD_TEST_REQUESTS=... LOAD_TEST_CONCURRENCY=...
```

**Build commands:**
```bash
make build          # Build binary (output: bin/taiji)
make docker-build   # Build Docker image
make run            # Run locally with examples/proxies.yaml
```

## License

Copyright © 2025 Pocket Network

## Support

For issues, questions, or contributions, please open an issue in the repository.
