# Taiji (太极)

High-performance HTTP reverse proxy service for wildcard subdomain routing with per-rule configuration.

*Like the martial art, Taiji smoothly redirects incoming requests with effortless flow and zero resistance.*

## Overview

This service acts as a reverse proxy from `*.test-api.pocket.network` (or `*.api.pocket.network` in production) to destination backends configured via a CSV file. Built with Go's standard library `net/http` and `httputil.ReverseProxy` for proper streaming support, maximum reliability, and minimal latency.

### Features

- **True Streaming**: Zero-copy streaming with `httputil.ReverseProxy` - request/response bodies are NEVER buffered
- **Minimal Latency**: ~1-2ms added latency for typical requests
- **Supports All Traffic**:
  - Large file uploads/downloads (no size limits)
  - Server-Sent Events (SSE)
  - WebSocket upgrades
  - Chunked transfer encoding
  - Long-running requests
  - Video/audio streaming
- **Full Request Forwarding**: Forwards all headers, body, path, query parameters, and client IP
- **Per-Rule Configuration**: Each subdomain can have a unique proxy behavior
- **Hot Reload**: Automatically reloads CSV configuration without restart
- **Production Ready**: Battle-tested Go standard library, no body size limits, generous timeouts
- **Observable**: Prometheus metrics, structured logging
- **Deployment Flexible**: Deploy anywhere - bare metal, containers, VMs, or orchestrators
- **Connection Pooling**: Optimized HTTP client with connection reuse for backend requests

### How It Works

```
Request: https://eth.test-api.pocket.network/v1/relay?chain=1
         ↓
Service: Extracts subdomain "eth", looks up in CSV
         ↓
CSV Rule: eth,backend.example.com/api
         ↓
Proxy:   Forwards request → https://backend.example.com/api/v1/relay?chain=1
         ↓
Response: Returns backend response to client
```

## CSV Configuration Format

```csv
subdomain,proxy_to,strip_path,strip_query
eth,https://backend.example.com/api,false,false
```

### Fields

- **subdomain**: Subdomain to match (without domain suffix)
- **proxy_to**: Backend destination host/path (without a scheme - HTTPS is used by default)
- **strip_path**: Remove an incoming path before forwarding? (true/false)
- **strip_query**: Remove incoming query string before forwarding? (true/false)

### Examples

| Configuration                                        | Incoming Request                                | Proxied Request                                |
|------------------------------------------------------|-------------------------------------------------|------------------------------------------------|
| `eth,https://backend.example.com/v1/abc,true,true`   | `https://eth.test-api.pocket.network/foo?bar=1` | `https://backend.example.com/v1/abc`           |
| `eth,https://backend.example.com/v1/abc,false,true`  | `https://eth.test-api.pocket.network/foo?bar=1` | `https://backend.example.com/v1/abc/foo`       |
| `eth,https://backend.example.com/v1/abc,false,false` | `https://eth.test-api.pocket.network/foo?bar=1` | `https://backend.example.com/v1/abc/foo?bar=1` |
| `eth,https://backend.example.com/v1/abc,true,false`  | `https://eth.test-api.pocket.network/foo?bar=1` | `https://backend.example.com/v1/abc?bar=1`     |

### Header Forwarding

The proxy automatically adds the following headers to backend requests:

#### Legacy Headers (X-Forwarded-*)
- **X-Forwarded-For**: Client IP address (appended to existing value if present)
- **X-Real-IP**: Original client IP address
- **X-Forwarded-Proto**: Original request protocol (http/https)
- **X-Forwarded-Host**: Original Host header value

#### Standard Header (RFC 7239)
- **Forwarded**: Standardized header containing `for=<clientIP>;host=<originalHost>;proto=<scheme>`
  - Example: `Forwarded: for=192.0.2.60;host=api.example.com;proto=https`
  - Properly appended when multiple proxies are chained

#### All Original Headers
- All incoming headers are forwarded to the backend (except hop-by-hop headers like Connection, Keep-Alive, Transfer-Encoding, etc.)

## Streaming Architecture

This proxy is built on Go's `httputil.ReverseProxy` which provides **true zero-copy streaming**:

- **Request bodies** are streamed directly from a client → backend (never read into memory)
- **Response bodies** are streamed directly from the backend → client (never buffered)
- **No size limits** on request or response bodies
- **Chunked transfer encoding** is preserved and forwarded correctly
- **WebSocket upgrades** are supported via the `Upgrade` header
- **Long-running connections** (SSE, streaming APIs) work perfectly

### Timeout Configuration

Very generous timeout settings since we don't control what backends or clients expect:

- **ReadTimeout**: `0` (unlimited) - supports long-running uploads
- **WriteTimeout**: `0` (unlimited) - supports long-running responses
- **ReadHeaderTimeout**: `30s` - prevents Slowloris attacks while allowing streaming
- **IdleTimeout**: `120s` - keep-alive connections
- **Backend ResponseHeaderTimeout**: `0` (unlimited) - supports slow backends
- **No connection limits** - maxed out for production workloads

## Quick Start

### Prerequisites

- Go 1.23+ (for building from source)
- Docker (optional, for containerized deployment)

### Local Development

```bash
# The service uses examples/proxies.csv by default
# Just run it directly:
make run

# Or with go run:
go run main.go

# Optional: Run local httpbin for faster/more reliable testing
# In a separate terminal:
docker run -p 4040:80 kennethreitz/httpbin
# Then update examples/proxies.csv to use localhost:4040 instead of httpbin.org

# Test basic proxy (strips path/query)
curl -v http://localhost:8080/anything -H "Host: httpbin_strip.test-api.pocket.network"

# Test with path preservation
curl -v http://localhost:8080/v1/test -H "Host: httpbin_path.test-api.pocket.network"

# Test full preservation with httpbin endpoints:
curl -v http://localhost:8080/get -H "Host: httpbin.test-api.pocket.network"
curl -v http://localhost:8080/post -H "Host: httpbin.test-api.pocket.network" -X POST -d '{"test":true}'

# Test streaming (see data arrive in real-time):
curl --no-buffer http://localhost:8080/stream/10 -H "Host: httpbin.test-api.pocket.network"
time curl --no-buffer "http://localhost:8080/drip?duration=3&numbytes=500" -H "Host: httpbin.test-api.pocket.network"
```

### Building

```bash
# Build binary locally
make build
# Output: bin/taiji

# Build Docker image
make docker-build

# Run Docker container locally
make docker-run

# Push Docker image to registry
make docker-push
```

### Deployment Options

Taiji can be deployed in many ways:

**Binary Deployment:**
```bash
# Build and run directly
./bin/taiji

# With custom configuration
CSV_PATH=/path/to/proxies.csv PORT=8080 ./bin/taiji
```

**Docker Deployment:**
```bash
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/proxies.csv:/config/proxies.csv:ro \
  -e CSV_PATH=/config/proxies.csv \
  ghcr.io/pokt-network/taiji:latest
```

**Systemd Service:**
```bash
# Create /etc/systemd/system/taiji.service
[Unit]
Description=Taiji Reverse Proxy
After=network.target

[Service]
Type=simple
User=taiji
Environment="CSV_PATH=/etc/taiji/proxies.csv"
Environment="PORT=8080"
ExecStart=/usr/local/bin/taiji
Restart=always

[Install]
WantedBy=multi-user.target
```

**Container Orchestrators:**
- Kubernetes, Docker Compose, Docker Swarm, Nomad, etc. - standard container deployment

## Configuration

### Environment Variables

| Variable   | Default                | Description                    |
|------------|------------------------|--------------------------------|
| `CSV_PATH` | `examples/proxies.csv` | Path to CSV configuration file |
| `PORT`     | `8080`                 | HTTP server port               |

### Updating Proxy Rules

Edit the CSV file specified in `CSV_PATH` and the service automatically detects changes and reloads within ~1 second. No restart required!

## Endpoints

| Endpoint       | Description                                               |
|----------------|-----------------------------------------------------------|
| `GET /health`  | Health check (always returns 200 OK)                      |
| `GET /ready`   | Readiness check (returns 503 if no rules loaded)          |
| `GET /metrics` | Prometheus metrics                                        |
| `* /*`         | Proxy handler (subdomain-based routing, all HTTP methods) |

## Monitoring

### Prometheus Metrics

```
# Number of proxy rules loaded
proxy_rules_total

# Last successful rule load timestamp
proxy_rules_last_load_timestamp_seconds

# Total proxy requests by subdomain and status code
proxy_requests_total{subdomain="eth",status_code="200"}

# Proxy request duration by subdomain
proxy_request_duration_seconds{subdomain="eth"}

# Last successful proxy request timestamp
proxy_last_request_timestamp_seconds{subdomain="eth"}

# Active proxy rules by subdomain
proxy_rule_active{subdomain="eth"}

# CSV reload attempts and errors
proxy_csv_reload_total
proxy_csv_reload_errors_total

# File watcher restarts
proxy_watcher_restarts_total
```

### Logs

Structured logs with log levels:

- `INFO`: Normal operations
- `WARN`: Non-fatal issues (invalid CSV rows)
- `ERROR`: Errors that need attention
- `FATAL`: Critical errors (service won't start)

## Development

### Project Structure

```
taiji/
├── main.go                 # Single-file Go application
├── go.mod                  # Go module definition
├── go.sum                  # Dependency checksums
├── Dockerfile              # Multi-stage Docker build
├── Makefile                # Build automation
├── test.sh                 # Test suite
├── README.md               # This file
└── examples/
    ├── proxies.csv         # Example proxy configurations
    └── README.md           # Testing examples
```

### Make Targets

Run `make help` to see all available targets:

```
  build                 Build the Go binary locally
  run                   Run the service locally
  clean                 Clean build artifacts
  docker-build          Build Docker image
  docker-push           Push Docker image to registry
  docker-run            Run Docker container locally
  docker-buildx         Build multi-platform image (arm64/amd64)
  fmt                   Format Go code
  lint                  Run linter
  security-scan         Scan Docker image for vulnerabilities
```

### Running Tests

```bash
# Run the test suite (requires service to be running)
./test.sh

# Or test against a specific endpoint
./test.sh http://localhost:8080
```

## License

Copyright © 2025 Pocket Network

## Support

For issues, questions, or contributions, please open an issue in the repository.
