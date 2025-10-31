# Taiji (太极)

High-performance HTTP reverse proxy with wildcard subdomain routing, distributed rate limiting, and zero-copy streaming.

*Like the martial art, Taiji smoothly redirects incoming requests with effortless flow and zero resistance.*

## What is Taiji?

Taiji is a production-ready reverse proxy that routes requests from wildcard subdomains (e.g., `*.api.pocket.network`) to backend services based on CSV configuration. Built on Go's `net/http` and `httputil.ReverseProxy`, it handles high-throughput traffic with minimal latency.

### Core Capabilities

- **Zero-Copy Streaming** - True streaming with no buffering. Supports uploads/downloads of any size, SSE, WebSockets, chunked encoding, and long-running connections
- **Distributed Rate Limiting** - Redis-backed sliding window algorithm with per-IP tracking across all instances
- **Load Balancing** - Round-robin across multiple backends with configurable retry policies
- **Hot Reloading** - CSV configuration updates apply automatically without restart
- **Production-Grade** - ~1-2ms added latency, unlimited timeouts for streaming, connection pooling, Prometheus metrics

### How It Works

```
Request: https://eth.api.pocket.network/v1/relay?chain=1
         ↓
Taiji: Extracts subdomain "eth", looks up backend in CSV
         ↓
CSV: eth,https://backend.example.com/api,false,false
         ↓
Backend: https://backend.example.com/api/v1/relay?chain=1
         ↓
Response: Streams backend response to client
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

### CSV Format

```csv
subdomain,proxy_to,strip_path,strip_query,extra_headers,rate_limit
eth,https://backend.example.com/api,false,false,"",100/1m
```

**Fields:**
- `subdomain` - Subdomain to match (e.g., "eth" matches eth.api.pocket.network)
- `proxy_to` - Backend URL with optional path (must include http:// or https://)
- `strip_path` - Remove incoming path before forwarding (true/false)
- `strip_query` - Remove incoming query string before forwarding (true/false)
- `extra_headers` - JSON object with custom headers (e.g., `{"Authorization": "Bearer token"}`)
- `rate_limit` - Per-subdomain limit (e.g., `100/1m`, `1000/1h`) or empty for default

**Path/Query Examples:**

| strip_path | strip_query | Request: `/foo?bar=1` | Forwarded to backend |
|------------|-------------|----------------------|----------------------|
| `true`     | `true`      | `/foo?bar=1`         | `/`                  |
| `false`    | `true`      | `/foo?bar=1`         | `/foo`               |
| `false`    | `false`     | `/foo?bar=1`         | `/foo?bar=1`         |
| `true`     | `false`     | `/foo?bar=1`         | `/?bar=1`            |

**Load Balancing:**
Add multiple rows with the same subdomain for round-robin load balancing:

```csv
subdomain,proxy_to,strip_path,strip_query,extra_headers,rate_limit
eth,https://backend1.example.com,false,false,"",100/1m
eth,https://backend2.example.com,false,false,"{""Auth"": ""token""}",100/1m
eth,https://backend3.example.com,false,false,"",100/1m
```

Control retry behavior with `Retry-Policy` header:
- `Retry-Policy: fail-fast` (default) - Try one backend, fail immediately if it errors
- `Retry-Policy: retry-all` - Try all backends until one succeeds

### Environment Variables

| Variable                  | Default                | Description                                          |
|---------------------------|------------------------|------------------------------------------------------|
| `CSV_PATH`                | `examples/proxies.csv` | Path to CSV configuration file                       |
| `PORT`                    | `8080`                 | HTTP server port                                     |
| `RATE_LIMIT_ENABLED`      | `true`                 | Enable/disable rate limiting                         |
| `RATE_LIMIT_DEFAULT`      | `100/1m`               | Default rate limit (requests/duration)               |
| `RATE_LIMIT_TRUST_PROXY`  | `true`                 | Trust proxy headers for IP extraction                |
| `REDIS_ADDR`              | `localhost:6379`       | Redis server address for rate limiting               |
| `REDIS_PASSWORD`          | (empty)                | Redis password (optional)                            |
| `REDIS_DB`                | `0`                    | Redis database number                                |

CSV changes are detected automatically and reload within ~1 second (no restart needed).

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
  -v $(pwd)/proxies.csv:/config/proxies.csv:ro \
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
CSV_PATH=/path/to/proxies.csv ./bin/taiji
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
proxy_requests_total{subdomain,backend,status_code}  # Request counts
proxy_request_duration_seconds{subdomain,backend}    # Latency histogram
proxy_ratelimit_requests_total{subdomain,action}     # Rate limit allowed/blocked
proxy_ratelimit_check_duration_seconds               # Redis latency
proxy_rules_total                                    # Loaded backends
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
make run            # Run locally with examples/proxies.csv
```

## License

Copyright © 2025 Pocket Network

## Support

For issues, questions, or contributions, please open an issue in the repository.
