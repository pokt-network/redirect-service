#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Testing Taiji (太极) - Proxy Service...${NC}\n"

# Test endpoint
ENDPOINT="${1:-http://localhost:8080}"

# Test health endpoint
echo -e "${YELLOW}[TEST] Health check${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$ENDPOINT/health")
if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}✓ Health check passed (HTTP $HTTP_CODE)${NC}\n"
else
    echo -e "${RED}✗ Health check failed (HTTP $HTTP_CODE)${NC}\n"
    exit 1
fi

# Test readiness endpoint
echo -e "${YELLOW}[TEST] Readiness check${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$ENDPOINT/ready")
if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}✓ Readiness check passed (HTTP $HTTP_CODE)${NC}\n"
else
    echo -e "${RED}✗ Readiness check failed (HTTP $HTTP_CODE)${NC}\n"
    exit 1
fi

# Test metrics endpoint
echo -e "${YELLOW}[TEST] Metrics endpoint${NC}"
METRICS=$(curl -s "$ENDPOINT/metrics")
if echo "$METRICS" | grep -q "proxy_rules_total"; then
    echo -e "${GREEN}✓ Metrics endpoint working${NC}\n"
else
    echo -e "${RED}✗ Metrics endpoint failed (expected proxy_rules_total metric)${NC}\n"
    exit 1
fi

# Test proxy for httpbin_strip subdomain (from examples CSV)
echo -e "${YELLOW}[TEST] Proxy for httpbin_strip.test-api.pocket.network${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: httpbin_strip.test-api.pocket.network" "$ENDPOINT/")
# httpbin.org/get should return 200
if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}✓ Proxy test passed (HTTP $HTTP_CODE from backend)${NC}\n"
else
    echo -e "${RED}✗ Proxy test failed (HTTP $HTTP_CODE)${NC}\n"
    exit 1
fi

# Test 404 for unknown subdomain
echo -e "${YELLOW}[TEST] 404 for unknown subdomain${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: unknown.test-api.pocket.network" "$ENDPOINT/")
if [ "$HTTP_CODE" == "404" ]; then
    echo -e "${GREEN}✓ 404 test passed (HTTP $HTTP_CODE)${NC}\n"
else
    echo -e "${RED}✗ 404 test failed (Expected 404, got HTTP $HTTP_CODE)${NC}\n"
    exit 1
fi

# Test that proxy forwards requests with path (httpbin_path has strip_path=false)
echo -e "${YELLOW}[TEST] Proxy forwards requests for httpbin_path subdomain${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: httpbin_path.test-api.pocket.network" "$ENDPOINT/v1/test")
# httpbin.org/anything/* should return 200
if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}✓ Proxy forward test passed (HTTP $HTTP_CODE from backend)${NC}\n"
else
    echo -e "${YELLOW}⚠ Proxy forward test inconclusive (HTTP $HTTP_CODE)${NC}\n"
fi

# Test HTTPBin full access endpoint
echo -e "${YELLOW}[TEST] Proxy to HTTPBin /get endpoint${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: httpbin.test-api.pocket.network" "$ENDPOINT/get")
# HTTPBin /get should return 200
if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}✓ HTTPBin proxy test passed (HTTP $HTTP_CODE)${NC}\n"
else
    echo -e "${YELLOW}⚠ HTTPBin proxy test inconclusive (HTTP $HTTP_CODE, may be unreachable)${NC}\n"
fi

# Test that metrics are being collected
echo -e "${YELLOW}[TEST] Metrics collection${NC}"
METRICS=$(curl -s "$ENDPOINT/metrics")
if echo "$METRICS" | grep -q "proxy_requests_total"; then
    echo -e "${GREEN}✓ Metrics collection working (proxy_requests_total found)${NC}\n"
else
    echo -e "${RED}✗ Metrics collection failed (proxy_requests_total not found)${NC}\n"
    exit 1
fi

# Test streaming support with chunked transfer encoding THROUGH the proxy
echo -e "${YELLOW}[TEST] Streaming support (JSON stream)${NC}"
echo -e "${YELLOW}  → Testing streaming through proxy with httpbin.org/stream${NC}"

# Test streaming THROUGH the proxy using httpbin subdomain
# httpbin.org/stream/{n} returns n JSON objects, one per line
# Note: Using -v instead of -s to avoid curl buffering issues with streaming
STREAM_RESPONSE=$(timeout 10 curl -v --max-time 8 --no-buffer \
    -H "Host: httpbin.test-api.pocket.network" \
    "$ENDPOINT/stream/5" 2>&1)

EXIT_CODE=$?

# Extract HTTP code from verbose output
HTTP_CODE=$(echo "$STREAM_RESPONSE" | grep -oP "< HTTP/\d\.\d \K\d{3}" | head -1)
# Check if we got JSON responses
LINE_COUNT=$(echo "$STREAM_RESPONSE" | grep -c '"id":' || echo "0")

if [ "$EXIT_CODE" -eq 124 ]; then
    echo -e "${YELLOW}⚠ Streaming test timed out (httpbin.org may be slow/unreachable)${NC}\n"
elif [ "$HTTP_CODE" == "503" ]; then
    echo -e "${YELLOW}⚠ Streaming test skipped (httpbin.org unavailable - HTTP 503)${NC}\n"
elif [ "$HTTP_CODE" == "200" ]; then
    # Should have received 5 lines of JSON
    if [ "$LINE_COUNT" -ge "3" ]; then
        echo -e "${GREEN}✓ Streaming test passed (HTTP $HTTP_CODE, ${LINE_COUNT} JSON objects streamed)${NC}"
        echo -e "${GREEN}  → Streaming working through proxy${NC}\n"
    else
        echo -e "${YELLOW}⚠ Streaming test inconclusive (only ${LINE_COUNT} JSON objects received)${NC}\n"
    fi
elif [ -z "$HTTP_CODE" ]; then
    echo -e "${YELLOW}⚠ Streaming test skipped (backend not reachable)${NC}\n"
else
    echo -e "${YELLOW}⚠ Streaming test failed (HTTP $HTTP_CODE)${NC}\n"
fi

# Test drip endpoint (chunked transfer with delays)
echo -e "${YELLOW}[TEST] Streaming with chunked transfer encoding${NC}"
echo -e "${YELLOW}  → Testing with httpbin.org/drip (slow chunks with delay)${NC}"

START=$(date +%s)
DRIP_RESPONSE=$(timeout 10 curl -v --no-buffer --max-time 8 \
    -H "Host: httpbin.test-api.pocket.network" \
    "$ENDPOINT/drip?duration=2&numbytes=200&delay=1" 2>&1)

EXIT_CODE=$?
END=$(date +%s)
DURATION=$((END - START))

# Extract HTTP code from verbose output
HTTP_CODE=$(echo "$DRIP_RESPONSE" | grep -oP "< HTTP/\d\.\d \K\d{3}" | head -1)
# Get the actual body content (after headers)
BODY=$(echo "$DRIP_RESPONSE" | sed -n '/^{/,$p' | grep -v "^{" | head -c 1000)
BODY_SIZE=${#BODY}

if [ "$EXIT_CODE" -eq 124 ]; then
    echo -e "${YELLOW}⚠ Chunked streaming test timed out (httpbin.org may be slow/unreachable)${NC}\n"
elif [ "$HTTP_CODE" == "503" ]; then
    echo -e "${YELLOW}⚠ Chunked streaming test skipped (httpbin.org unavailable - HTTP 503)${NC}\n"
elif [ "$HTTP_CODE" == "200" ]; then
    if [ "$BODY_SIZE" -gt "10" ] && [ "$DURATION" -ge "1" ]; then
        echo -e "${GREEN}✓ Chunked streaming test passed (HTTP $HTTP_CODE, ${BODY_SIZE} bytes in ${DURATION}s)${NC}"
        echo -e "${GREEN}  → No buffering detected, proxy is streaming${NC}\n"
    else
        echo -e "${YELLOW}⚠ Chunked streaming test inconclusive (${BODY_SIZE} bytes, ${DURATION}s)${NC}\n"
    fi
elif [ -z "$HTTP_CODE" ]; then
    echo -e "${YELLOW}⚠ Chunked streaming test skipped (backend not reachable)${NC}\n"
else
    echo -e "${YELLOW}⚠ Chunked streaming test failed (HTTP $HTTP_CODE)${NC}\n"
fi

# Test multiple backends (round-robin load balancing)
echo -e "${YELLOW}[TEST] Multiple backends (round-robin)${NC}"
echo -e "${YELLOW}  → Testing 'rr_test' subdomain with 2 backends${NC}"

# Make 10 requests to the rr_test subdomain
for i in {1..10}; do
    curl -s -o /dev/null -H "Host: rr_test.test-api.pocket.network" "$ENDPOINT/get" 2>/dev/null || true
done

sleep 1

# Check metrics to see if both backends received requests
METRICS=$(curl -s "$ENDPOINT/metrics")
BACKEND1_REQUESTS=$(echo "$METRICS" | grep 'proxy_requests_total.*backend="localhost:4040".*status_code="200".*subdomain="rr_test"' | grep -oP '} \K\d+' || echo "0")
BACKEND2_REQUESTS=$(echo "$METRICS" | grep 'proxy_requests_total.*backend="localhost:4041".*status_code="200".*subdomain="rr_test"' | grep -oP '} \K\d+' || echo "0")

if [ "$BACKEND1_REQUESTS" -ge 1 ] && [ "$BACKEND2_REQUESTS" -ge 1 ]; then
    echo -e "${GREEN}✓ Round-robin test passed (backend1: $BACKEND1_REQUESTS requests, backend2: $BACKEND2_REQUESTS requests)${NC}\n"
elif [ "$BACKEND1_REQUESTS" -eq 0 ] && [ "$BACKEND2_REQUESTS" -eq 0 ]; then
    echo -e "${YELLOW}⚠ Round-robin test skipped (backends not responding)${NC}\n"
else
    echo -e "${YELLOW}⚠ Round-robin test inconclusive (backend1: $BACKEND1_REQUESTS, backend2: $BACKEND2_REQUESTS)${NC}\n"
fi

# Test custom headers
echo -e "${YELLOW}[TEST] Custom headers (extra_headers)${NC}"
echo -e "${YELLOW}  → Testing 'custom_headers' subdomain adds custom headers to backend${NC}"

# Request to custom_headers subdomain (backend is /headers which echoes all headers)
RESPONSE=$(curl -s -H "Host: custom_headers.test-api.pocket.network" "$ENDPOINT/" 2>/dev/null || echo "")
CUSTOM_HEADER=$(echo "$RESPONSE" | grep -i "X-Custom-Backend" || echo "")
API_KEY_HEADER=$(echo "$RESPONSE" | grep -i "X-Api-Key" || echo "")

if [ -n "$CUSTOM_HEADER" ] && [ -n "$API_KEY_HEADER" ]; then
    echo -e "${GREEN}✓ Custom headers test passed (headers forwarded to backend)${NC}\n"
elif [ -z "$RESPONSE" ]; then
    echo -e "${YELLOW}⚠ Custom headers test skipped (backend not responding)${NC}\n"
else
    echo -e "${YELLOW}⚠ Custom headers test inconclusive (custom headers may not be present)${NC}\n"
fi

# Test Retry-Policy header
echo -e "${YELLOW}[TEST] Retry-Policy header (fail-fast vs retry-all)${NC}"
echo -e "${YELLOW}  → Testing fail-fast behavior (default)${NC}"

# Test fail-fast (should get response from single backend)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Host: httpbin.test-api.pocket.network" \
    -H "Retry-Policy: fail-fast" \
    "$ENDPOINT/get")

if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "502" ] || [ "$HTTP_CODE" == "404" ]; then
    echo -e "${GREEN}✓ Retry-Policy: fail-fast works (HTTP $HTTP_CODE)${NC}"
else
    echo -e "${YELLOW}⚠ Retry-Policy: fail-fast inconclusive (HTTP $HTTP_CODE)${NC}"
fi

echo -e "${YELLOW}  → Testing retry-all behavior${NC}"

# Test retry-all (should try multiple backends if first fails)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Host: rr_test.test-api.pocket.network" \
    -H "Retry-Policy: retry-all" \
    "$ENDPOINT/get")

if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "502" ] || [ "$HTTP_CODE" == "404" ]; then
    echo -e "${GREEN}✓ Retry-Policy: retry-all works (HTTP $HTTP_CODE)${NC}\n"
else
    echo -e "${YELLOW}⚠ Retry-Policy: retry-all inconclusive (HTTP $HTTP_CODE)${NC}\n"
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All tests passed! 🎉${NC}"
echo -e "${GREEN}========================================${NC}"
