#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration - AGGRESSIVE MODE
DURATION=${DURATION:-120}  # 2 minutes default (configurable via env var)
WORKERS=${WORKERS:-5}  # Number of concurrent workers
RATE_PER_WORKER=${RATE_PER_WORKER:-30}  # 30 requests per minute per worker
RETRY_POLICY=${RETRY_POLICY:-}  # Optional: "fail-fast" or "retry-all"
INTERVAL=$(echo "scale=3; 60 / $RATE_PER_WORKER" | bc)  # seconds between requests per worker
STAGE_URL="https://eth.stage.api.pocket.network"
PAYLOAD='{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Calculate total rate
TOTAL_RATE=$((WORKERS * RATE_PER_WORKER))

# Output files
LOG_DIR="/tmp/taiji-stage-test"
REPORT_FILE="stage-test-results.txt"

# Cleanup old logs and create fresh directory
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"
rm -f "$REPORT_FILE"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          Taiji v1.3.0 - AGGRESSIVE Stage Load Test              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${RED}⚡ AGGRESSIVE LOAD TEST MODE ⚡${NC}"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo "  Duration:         ${DURATION}s"
echo "  Workers:          ${WORKERS} concurrent"
echo "  Rate/Worker:      ${RATE_PER_WORKER} req/min"
echo "  Total Rate:       ${TOTAL_RATE} req/min (${WORKERS} x ${RATE_PER_WORKER})"
echo "  Interval:         ${INTERVAL}s between requests per worker"
echo "  Target:           $STAGE_URL"
echo "  Method:           eth_blockNumber"
if [ -n "$RETRY_POLICY" ]; then
    echo "  Retry-Policy:     $RETRY_POLICY"
else
    echo "  Retry-Policy:     (default/none)"
fi
echo "  Expected Total:   ~$((DURATION / 60 * TOTAL_RATE)) requests"
echo ""
echo -e "${YELLOW}Tip: Customize with env vars:${NC}"
echo "  DURATION=300 WORKERS=10 RATE_PER_WORKER=60 ./test-stage.sh"
echo "  RETRY_POLICY=fail-fast ./test-stage.sh    # Fail on first backend error"
echo "  RETRY_POLICY=retry-all ./test-stage.sh    # Try all backends until success"
echo ""

# Function to send requests at controlled rate
send_requests() {
    local worker_id=$1
    local log_file="${LOG_DIR}/worker-${worker_id}.log"
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION))
    local request_count=0

    echo "[$(date +%H:%M:%S)] Worker $worker_id starting..." >> "$log_file"

    while [ $(date +%s) -lt $end_time ]; do
        request_count=$((request_count + 1))
        local req_start=$(date +%s.%N)

        # Build curl command with optional Retry-Policy header
        local curl_cmd="curl -s -w \"\nHTTP_CODE:%{http_code}\nTIME_TOTAL:%{time_total}\nTIME_CONNECT:%{time_connect}\nTIME_STARTTRANSFER:%{time_starttransfer}\n\" -X POST -H \"Content-Type: application/json\""

        if [ -n "$RETRY_POLICY" ]; then
            curl_cmd="$curl_cmd -H \"Retry-Policy: $RETRY_POLICY\""
        fi

        curl_cmd="$curl_cmd -d '$PAYLOAD' '$STAGE_URL' 2>&1"

        # Send request and capture response with timing
        response=$(eval $curl_cmd)

        local req_end=$(date +%s.%N)

        # Extract metrics
        http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
        time_total=$(echo "$response" | grep "TIME_TOTAL:" | cut -d: -f2)
        time_connect=$(echo "$response" | grep "TIME_CONNECT:" | cut -d: -f2)
        time_starttransfer=$(echo "$response" | grep "TIME_STARTTRANSFER:" | cut -d: -f2)

        # Extract response body (everything before metrics)
        body=$(echo "$response" | sed '/HTTP_CODE:/,$d')

        # Log result
        echo "REQ:$request_count|WORKER:$worker_id|TIME:$time_total|CONNECT:$time_connect|TTFB:$time_starttransfer|CODE:$http_code|TIMESTAMP:$(date +%s.%N)|BODY:$body" >> "$log_file"

        # Sleep to maintain rate
        sleep "$INTERVAL"
    done

    echo "[$(date +%H:%M:%S)] Worker $worker_id completed: $request_count requests" >> "$log_file"
}

# Start all workers in parallel
echo -e "${YELLOW}⏳ Starting ${WORKERS} workers at $(date +%H:%M:%S)...${NC}"
echo -e "${RED}🔥 Sending ${TOTAL_RATE} req/min to staging...${NC}"
echo ""

WORKER_PIDS=()
for i in $(seq 1 $WORKERS); do
    send_requests "$i" &
    WORKER_PIDS+=($!)
    # Stagger worker starts slightly to spread initial load
    sleep 0.1
done

# Progress indicator with live stats
echo -e "${BLUE}Running... Press Ctrl+C to stop${NC}"
for i in $(seq 1 $DURATION); do
    if [ $((i % 10)) -eq 0 ]; then
        total_count=0
        total_200=0
        total_429=0
        total_5xx=0

        for worker_log in "$LOG_DIR"/worker-*.log; do
            if [ -f "$worker_log" ]; then
                count=$(grep -c "^REQ:" "$worker_log" 2>/dev/null || echo 0)
                code_200=$(grep "CODE:200" "$worker_log" 2>/dev/null | wc -l || echo 0)
                code_429=$(grep "CODE:429" "$worker_log" 2>/dev/null | wc -l || echo 0)
                code_5xx=$(grep -E "CODE:5[0-9]{2}" "$worker_log" 2>/dev/null | wc -l || echo 0)

                total_count=$((total_count + count))
                total_200=$((total_200 + code_200))
                total_429=$((total_429 + code_429))
                total_5xx=$((total_5xx + code_5xx))
            fi
        done

        elapsed=$i
        current_rate=$(echo "scale=1; $total_count * 60 / $elapsed" | bc)
        success_pct=$(echo "scale=1; $total_200 * 100 / $total_count" | bc 2>/dev/null || echo 0)

        echo -e "${BLUE}[$elapsed/${DURATION}s] Total: $total_count reqs (${current_rate}/min) | ✓ $total_200 (${success_pct}%) | 429: $total_429 | 5xx: $total_5xx${NC}"
    fi
    sleep 1
done

# Wait for all workers to complete
for pid in "${WORKER_PIDS[@]}"; do
    wait $pid
done

echo ""
echo -e "${GREEN}✓ Test completed at $(date +%H:%M:%S)${NC}"
echo ""
echo -e "${YELLOW}Generating report...${NC}"

# Analysis function
analyze_results() {
    echo "═══════════════════════════════════════════════════════════════"
    echo "  STAGING ENVIRONMENT - AGGRESSIVE LOAD TEST RESULTS"
    echo "═══════════════════════════════════════════════════════════════"

    # Combine all worker logs
    combined_log="${LOG_DIR}/combined.log"
    cat "$LOG_DIR"/worker-*.log | grep "^REQ:" > "$combined_log" 2>/dev/null || true

    # Total requests
    total=$(wc -l < "$combined_log" || echo 0)
    echo "Total Requests: $total"
    echo "Workers: $WORKERS"
    echo "Duration: ${DURATION}s"

    # Per-worker breakdown
    echo ""
    echo "Per-Worker Stats:"
    for i in $(seq 1 $WORKERS); do
        worker_log="${LOG_DIR}/worker-${i}.log"
        if [ -f "$worker_log" ]; then
            worker_count=$(grep -c "^REQ:" "$worker_log" 2>/dev/null || echo 0)
            worker_200=$(grep "CODE:200" "$worker_log" 2>/dev/null | wc -l || echo 0)
            worker_429=$(grep "CODE:429" "$worker_log" 2>/dev/null | wc -l || echo 0)
            echo "  Worker $i: $worker_count reqs ($worker_200 success, $worker_429 rate limited)"
        fi
    done

    # Status code distribution
    echo ""
    echo "Overall Status Codes:"
    status_200=$(grep "CODE:200" "$combined_log" 2>/dev/null | wc -l || echo 0)
    status_429=$(grep "CODE:429" "$combined_log" 2>/dev/null | wc -l || echo 0)
    status_4xx=$(grep -E "CODE:4[0-9]{2}" "$combined_log" 2>/dev/null | grep -v "CODE:429" | wc -l || echo 0)
    status_5xx=$(grep -E "CODE:5[0-9]{2}" "$combined_log" 2>/dev/null | wc -l || echo 0)
    status_other=$((total - status_200 - status_429 - status_4xx - status_5xx))

    if [ $total -gt 0 ]; then
        echo "  200 Success:        $status_200 ($((status_200 * 100 / total))%)"
        if [ "$status_429" -gt 0 ]; then
            echo "  429 Rate Limited:   $status_429 ($((status_429 * 100 / total))%)"
        fi
        if [ "$status_4xx" -gt 0 ]; then
            echo "  4xx Client Error:   $status_4xx ($((status_4xx * 100 / total))%)"
        fi
        if [ "$status_5xx" -gt 0 ]; then
            echo "  5xx Server Error:   $status_5xx ($((status_5xx * 100 / total))%)"
        fi
        if [ "$status_other" -gt 0 ]; then
            echo "  Other/Failed:       $status_other ($((status_other * 100 / total))%)"
        fi
    fi

    # Response time statistics
    echo ""
    echo "Response Times (seconds):"
    times=$(cut -d'|' -f3 "$combined_log" | cut -d: -f2 | grep -E '^[0-9.]+$' | sort -n)
    ttfb=$(cut -d'|' -f5 "$combined_log" | cut -d: -f2 | grep -E '^[0-9.]+$' | sort -n)

    if [ -n "$times" ]; then
        # Calculate percentiles
        total_count=$(echo "$times" | wc -l)
        p50_idx=$((total_count / 2))
        p95_idx=$((total_count * 95 / 100))
        p99_idx=$((total_count * 99 / 100))

        p50=$(echo "$times" | sed -n "${p50_idx}p")
        p95=$(echo "$times" | sed -n "${p95_idx}p")
        p99=$(echo "$times" | sed -n "${p99_idx}p")
        min=$(echo "$times" | head -1)
        max=$(echo "$times" | tail -1)

        ttfb_p50=$(echo "$ttfb" | sed -n "${p50_idx}p" 2>/dev/null || echo "N/A")
        ttfb_p95=$(echo "$ttfb" | sed -n "${p95_idx}p" 2>/dev/null || echo "N/A")

        echo "  Total Time:"
        echo "    Min:  ${min}s"
        echo "    p50:  ${p50}s"
        echo "    p95:  ${p95}s"
        echo "    p99:  ${p99}s"
        echo "    Max:  ${max}s"
        echo ""
        echo "  Time to First Byte (TTFB):"
        echo "    p50:  ${ttfb_p50}s"
        echo "    p95:  ${ttfb_p95}s"
    else
        echo "  No timing data available"
    fi

    # Actual rate achieved
    echo ""
    first_ts=$(head -1 "$combined_log" | cut -d'|' -f7 | cut -d: -f2)
    last_ts=$(tail -1 "$combined_log" | cut -d'|' -f7 | cut -d: -f2)

    if [ -n "$first_ts" ] && [ -n "$last_ts" ]; then
        duration=$(echo "$last_ts - $first_ts" | bc)
        actual_rate=$(echo "scale=2; $total * 60 / $duration" | bc)
        echo "Actual Rate: ${actual_rate} req/min (target: ${TOTAL_RATE} req/min)"
        echo "Achievement: $(echo "scale=1; $actual_rate * 100 / $TOTAL_RATE" | bc)% of target rate"
    fi

    # Error analysis
    if [ "$status_429" -gt 0 ] || [ "$status_5xx" -gt 0 ]; then
        echo ""
        echo "⚠️  ERRORS DETECTED:"
        if [ "$status_429" -gt 0 ]; then
            echo "  - Rate limiting kicked in ($status_429 requests)"
            echo "    This is expected under aggressive load"
        fi
        if [ "$status_5xx" -gt 0 ]; then
            echo "  - Server errors occurred ($status_5xx requests)"
            echo "    Consider reducing load or investigating backend issues"
        fi
    fi

    # Sample responses
    echo ""
    echo "Sample Successful Response:"
    grep "CODE:200" "$combined_log" 2>/dev/null | head -1 | cut -d'|' -f8 | cut -d: -f2- | head -c 150 || echo "  No successful responses"
    echo ""
}

# Generate report
{
    echo "Taiji v1.3.0 - Aggressive Staging Load Test Report"
    echo "Generated: $(date)"
    echo ""
    echo "Test Parameters:"
    echo "  Target:       $STAGE_URL"
    echo "  Workers:      $WORKERS concurrent"
    echo "  Rate:         $TOTAL_RATE req/min total ($RATE_PER_WORKER req/min per worker)"
    echo "  Duration:     ${DURATION}s"
    if [ -n "$RETRY_POLICY" ]; then
        echo "  Retry-Policy: $RETRY_POLICY"
    else
        echo "  Retry-Policy: (default)"
    fi
    echo ""

    analyze_results

} | tee "$REPORT_FILE"

echo -e "${GREEN}✓ Report saved to: $REPORT_FILE${NC}"
echo -e "${YELLOW}Worker logs available at: $LOG_DIR/${NC}"
echo ""

# Quick summary
success=$(grep "CODE:200" "$LOG_DIR"/combined.log 2>/dev/null | wc -l || echo 0)
total=$(wc -l < "$LOG_DIR"/combined.log 2>/dev/null || echo 1)
success_rate=$(echo "scale=1; $success * 100 / $total" | bc 2>/dev/null || echo 0)

if [ $(echo "$success_rate > 95" | bc) -eq 1 ]; then
    echo -e "${GREEN}✓ Test passed: ${success_rate}% success rate${NC}"
elif [ $(echo "$success_rate > 80" | bc) -eq 1 ]; then
    echo -e "${YELLOW}⚠ Test marginal: ${success_rate}% success rate${NC}"
else
    echo -e "${RED}✗ Test failed: ${success_rate}% success rate${NC}"
fi