#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║        Taiji v1.3.0 - Health Check & Fallback Test              ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
check_health() {
    local subdomain=$1
    local backend=$2
    curl -s http://localhost:8080/metrics | grep "proxy_backend_health_status{backend=\"${backend}\",subdomain=\"${subdomain}\"}" | awk '{print $2}'
}

test_request() {
    local subdomain=$1
    echo -n "Testing request to ${subdomain}... "
    response=$(curl -s -w "\n%{http_code}" -H "Host: ${subdomain}.test-api.pocket.network" http://localhost:8080/get 2>&1)
    status=$(echo "$response" | tail -1)
    echo "Status: $status"
    echo "$response" | head -5
    echo ""
}

wait_for_health_check() {
    echo "⏳ Waiting for health check cycle (30 seconds)..."
    sleep 35
}

echo "📋 Step 1: Starting services with test configuration..."
docker-compose down -v 2>/dev/null || true
export CONFIG_PATH=/config/test-health-fallback.yaml
docker-compose up -d
sleep 8

echo ""
echo "✅ Step 2: Verify initial health - all backends should be healthy"
echo "────────────────────────────────────────────────────────────────"
health1=$(check_health "test_health_fallback" "http://httpbin1")
health2=$(check_health "test_health_fallback" "http://httpbin2")
echo "httpbin1 health: $health1 (expected: 1)"
echo "httpbin2 health: $health2 (expected: 1)"
test_request "test_health_fallback"

echo ""
echo "🔴 Step 3: Simulate httpbin1 failure"
echo "────────────────────────────────────────────────────────────────"
docker stop taiji-httpbin1
wait_for_health_check

echo "Checking health after httpbin1 failure..."
health1=$(check_health "test_health_fallback" "http://httpbin1")
health2=$(check_health "test_health_fallback" "http://httpbin2")
echo "httpbin1 health: $health1 (expected: 0 after 3 failures)"
echo "httpbin2 health: $health2 (expected: 1 - still healthy)"
echo ""
echo "Request should still work (using httpbin2):"
test_request "test_health_fallback"

echo ""
echo "🔴🔴 Step 4: Simulate BOTH primary backends failing"
echo "────────────────────────────────────────────────────────────────"
docker stop taiji-httpbin2
wait_for_health_check

echo "Checking health after both primaries failed..."
health1=$(check_health "test_health_fallback" "http://httpbin1")
health2=$(check_health "test_health_fallback" "http://httpbin2")
echo "httpbin1 health: $health1 (expected: 0)"
echo "httpbin2 health: $health2 (expected: 0)"
echo ""
echo "Request should use FALLBACK or return 503:"
test_request "test_health_fallback"

echo ""
echo "📊 Step 5: Check fallback metrics"
echo "────────────────────────────────────────────────────────────────"
curl -s http://localhost:8080/metrics | grep -E "proxy_fallback|proxy_all_backends_unhealthy"

echo ""
echo "♻️  Step 6: Restart httpbin1 and verify recovery"
echo "────────────────────────────────────────────────────────────────"
docker start taiji-httpbin1
wait_for_health_check

health1=$(check_health "test_health_fallback" "http://httpbin1")
echo "httpbin1 health after restart: $health1 (expected: 1 - recovered)"
echo ""
echo "Request should work again (using httpbin1):"
test_request "test_health_fallback"

echo ""
echo "♻️  Step 7: Restart httpbin2"
echo "────────────────────────────────────────────────────────────────"
docker start taiji-httpbin2
sleep 5

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                    Test Complete!                                ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Cleanup: docker-compose down"
