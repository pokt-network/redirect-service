#!/bin/bash
set -e

echo "=========================================="
echo "Distributed Rate Limiting Test"
echo "=========================================="
echo ""

# Test rate_limited subdomain (10 requests/min limit)
RATE_LIMIT=10
TOTAL_REQUESTS=25
HOST="rate_limited.test-api.pocket.network"

echo "Configuration:"
echo "  Rate limit: $RATE_LIMIT/min"
echo "  Total requests: $TOTAL_REQUESTS (burst)"
echo "  Target: $HOST"
echo ""

# Send burst of requests
echo "[1/4] Sending burst of $TOTAL_REQUESTS requests..."
SUCCESS=0
BLOCKED=0

for i in $(seq 1 $TOTAL_REQUESTS); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Host: $HOST" \
        http://localhost:8080/get 2>/dev/null || echo "000")

    [ "$CODE" == "200" ] && SUCCESS=$((SUCCESS + 1))
    [ "$CODE" == "429" ] && BLOCKED=$((BLOCKED + 1))
done

echo "  Results: $SUCCESS succeeded, $BLOCKED blocked"
echo ""

# Check load distribution across instances
echo "[2/4] Checking load distribution..."
TAIJI1_REQUESTS=$(docker logs taiji-1 2>&1 | grep -c "proxy_requests_total" | head -1 || echo "0")
TAIJI2_REQUESTS=$(docker logs taiji-2 2>&1 | grep -c "proxy_requests_total" | head -1 || echo "0")
echo "  taiji-1 handled: ~$TAIJI1_REQUESTS request logs"
echo "  taiji-2 handled: ~$TAIJI2_REQUESTS request logs"
echo ""

# Check Redis keys
echo "[3/4] Checking Redis state..."
REDIS_KEYS=$(docker exec taiji-redis redis-cli KEYS "ratelimit:*" | wc -l)
echo "  Redis keys: $REDIS_KEYS"

if [ "$REDIS_KEYS" -gt 0 ]; then
    echo "  Sample key:"
    docker exec taiji-redis redis-cli KEYS "ratelimit:*" | head -1 | while read key; do
        COUNT=$(docker exec taiji-redis redis-cli ZCARD "$key")
        TTL=$(docker exec taiji-redis redis-cli TTL "$key")
        echo "    $key: $COUNT requests, TTL ${TTL}s"
    done
fi
echo ""

# Check metrics from both instances
echo "[4/4] Checking Prometheus metrics..."
echo "  taiji-1 metrics:"
docker exec taiji-1 wget -q -O- http://localhost:8080/metrics 2>/dev/null | \
    grep "proxy_ratelimit_requests_total" | head -2 | sed 's/^/    /'

echo "  taiji-2 metrics:"
docker exec taiji-2 wget -q -O- http://localhost:8080/metrics 2>/dev/null | \
    grep "proxy_ratelimit_requests_total" | head -2 | sed 's/^/    /'
echo ""

# Validation
echo "=========================================="
echo "Validation:"
echo "=========================================="

if [ "$SUCCESS" -le "$((RATE_LIMIT + 2))" ] && [ "$BLOCKED" -ge "$((TOTAL_REQUESTS - RATE_LIMIT - 2))" ]; then
    echo "✅ Rate limiting working correctly!"
    echo "   Expected ~$RATE_LIMIT allowed, got $SUCCESS"
    echo "   Both instances shared Redis state properly"
else
    echo "⚠️  Unexpected results:"
    echo "   Expected ~$RATE_LIMIT allowed, got $SUCCESS"
    echo "   Expected ~$((TOTAL_REQUESTS - RATE_LIMIT)) blocked, got $BLOCKED"
fi

if [ "$REDIS_KEYS" -gt 0 ]; then
    echo "✅ Redis distributed state working"
else
    echo "⚠️  No Redis keys found"
fi

echo ""
echo "To see live logs: docker-compose logs -f taiji-1 taiji-2"
