# Taiji (太极) Examples

This directory contains example proxy configurations using httpbin.org for testing and development.

## Running Local httpbin for Testing

For more reliable and faster testing, you can run a local httpbin instance:

```bash
# Pull the httpbin Docker image
docker pull kennethreitz/httpbin

# Run httpbin on port 4040
docker run -p 4040:80 kennethreitz/httpbin
```

Then update your `proxies.csv` to point to `localhost:4040` instead of `httpbin.org` for faster local testing.

## proxies.csv

Example subdomain configurations demonstrating different strip_path/strip_query combinations:

| Subdomain       | Backend                | strip_path | strip_query | Description                                         |
|-----------------|------------------------|------------|-------------|-----------------------------------------------------|
| `httpbin_strip` | `httpbin.org/get`      | `true`     | `true`      | Strips path and query - always goes to /get         |
| `httpbin_path`  | `httpbin.org/anything` | `false`    | `true`      | Preserves path, strips query - appends to /anything |
| `httpbin`       | `httpbin.org`          | `false`    | `false`     | Full preservation - access any httpbin endpoint     |

## Testing Examples

### 1. Strip Everything (httpbin_strip)

```bash
# All requests go to httpbin.org/get regardless of path/query
curl "http://localhost:8080/ignored/path?ignored=query" -H "Host: httpbin_strip.test-api.pocket.network"
# → proxies to: https://httpbin.org/get

curl "http://localhost:8080/something/else?foo=bar" -H "Host: httpbin_strip.test-api.pocket.network"
# → proxies to: https://httpbin.org/get
```

### 2. Preserve Path, Strip Query (httpbin_path)

```bash
# Path is preserved and appended to /anything
curl "http://localhost:8080/v1/test?ignored=query" -H "Host: httpbin_path.test-api.pocket.network"
# → proxies to: https://httpbin.org/anything/v1/test

curl http://localhost:8080/foo/bar -H "Host: httpbin_path.test-api.pocket.network"
# → proxies to: https://httpbin.org/anything/foo/bar
```

### 3. Full Preservation (httpbin)

Access any httpbin.org endpoint with a full path and query:

```bash
# GET request
curl http://localhost:8080/get -H "Host: httpbin.test-api.pocket.network"
# → proxies to: https://httpbin.org/get

# POST request
curl http://localhost:8080/post -H "Host: httpbin.test-api.pocket.network" \
  -X POST -d '{"test":true}'
# → proxies to: https://httpbin.org/post

# Status codes
curl http://localhost:8080/status/418 -H "Host: httpbin.test-api.pocket.network"
# → proxies to: https://httpbin.org/status/418 (I'm a teapot!)

# With query parameters
curl "http://localhost:8080/get?foo=bar&baz=qux" -H "Host: httpbin.test-api.pocket.network"
# → proxies to: https://httpbin.org/get?foo=bar&baz=qux
```

## Streaming Tests

httpbin.org has excellent streaming endpoints:

```bash
# Stream JSON responses (one per line)
curl --no-buffer http://localhost:8080/stream/10 -H "Host: httpbin.test-api.pocket.network"
# → proxies to: https://httpbin.org/stream/10

# Stream random bytes
curl --no-buffer http://localhost:8080/stream-bytes/5000 -H "Host: httpbin.test-api.pocket.network"
# → proxies to: https://httpbin.org/stream-bytes/5000

# Drip data slowly (duration=5sec, numbytes=500, delay=100ms between chunks)
time curl --no-buffer "http://localhost:8080/drip?duration=5&numbytes=500&delay=100" \
  -H "Host: httpbin.test-api.pocket.network"
# → proxies to: https://httpbin.org/drip?duration=5&numbytes=500&delay=100

# Delayed response
time curl http://localhost:8080/delay/3 -H "Host: httpbin.test-api.pocket.network"
# → proxies to: https://httpbin.org/delay/3 (waits 3 seconds)
```

## Other Useful httpbin Endpoints

```bash
# Headers inspection - see all forwarded headers
curl http://localhost:8080/headers -H "Host: httpbin.test-api.pocket.network" \
  -H "X-Custom-Header: test"
# → See all forwarded headers including:
#   - X-Forwarded-For, X-Real-IP, X-Forwarded-Proto, X-Forwarded-Host (legacy)
#   - Forwarded: for=<ip>;host=<host>;proto=<scheme> (RFC 7239 standard)

# IP address
curl http://localhost:8080/ip -H "Host: httpbin.test-api.pocket.network"
# → Shows your IP as seen by backend

# Response formats
curl http://localhost:8080/json -H "Host: httpbin.test-api.pocket.network"
curl http://localhost:8080/xml -H "Host: httpbin.test-api.pocket.network"
curl http://localhost:8080/html -H "Host: httpbin.test-api.pocket.network"

# Large responses
curl http://localhost:8080/bytes/10000 -H "Host: httpbin.test-api.pocket.network"
# → 10KB of random data
```

## Production Examples

For production blockchain RPC endpoints, add entries like:

```csv
subdomain,proxy_to,strip_path,strip_query
eth,eth-mainnet.example.com/v1,false,false
bsc,bsc-mainnet.example.com/v1,false,false
polygon,polygon-mainnet.example.com/v1,false,false
```

Then access via:
```bash
curl https://eth.api.pocket.network/relay -H "Content-Type: application/json" -d '{...}'
# → proxies to: https://eth-mainnet.example.com/v1/relay
```
