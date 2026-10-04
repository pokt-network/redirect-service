package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newTestRateLimiter returns a RateLimiter backed by an in-process miniredis.
//
// The tests below deliberately exercise CheckLimit — the function the request
// path actually calls — rather than the Lua script or the returned count in
// isolation. The bug this file pins shipped with the script and the count both
// looking correct; only the allowed/blocked decision handed back to the caller
// was wrong.
func newTestRateLimiter(t *testing.T) *RateLimiter {
	t.Helper()
	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return &RateLimiter{redis: client}
}

// TestRateLimiterBlocksAtLimit is the regression pin for the production defect
// where the limiter never blocked anything.
//
// A full window skips the ZADD, so the script's count could never exceed the
// limit; the caller then tested `count <= limit`, which is true at capacity.
// Every request was allowed at every limit value on every service — the symptom
// was a permanent 429 rate of exactly zero while traffic ran above the cap.
func TestRateLimiterBlocksAtLimit(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()

	const limit = 5
	const window = time.Minute

	for i := 1; i <= limit; i++ {
		allowed, remaining, _, err := rl.CheckLimit(ctx, "1.2.3.4", "solana", limit, window)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
		if !allowed {
			t.Fatalf("request %d of %d: allowed=false, want true (limit not reached yet)", i, limit)
		}
		if want := limit - i; remaining != want {
			t.Errorf("request %d: remaining=%d, want %d", i, remaining, want)
		}
	}

	// The (limit+1)th request must be rejected. This is the assertion that fails
	// on the pre-fix code.
	allowed, remaining, _, err := rl.CheckLimit(ctx, "1.2.3.4", "solana", limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("request %d of %d: allowed=true, want false — limiter is not blocking at capacity", limit+1, limit)
	}
	if remaining != 0 {
		t.Errorf("blocked request: remaining=%d, want 0", remaining)
	}
}

// TestRateLimiterBlockedRequestsDoNotConsumeBudget guards the optimization that
// caused the defect: rejecting without a ZADD is correct and must stay, so a
// client hammering a saturated window cannot push its own reset further out.
func TestRateLimiterBlockedRequestsDoNotConsumeBudget(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()

	const limit = 3
	const window = time.Minute

	for i := 0; i < limit; i++ {
		if allowed, _, _, err := rl.CheckLimit(ctx, "1.2.3.4", "eth", limit, window); err != nil || !allowed {
			t.Fatalf("fill request %d: allowed=%v err=%v", i, allowed, err)
		}
	}

	for i := 0; i < 20; i++ {
		allowed, _, _, err := rl.CheckLimit(ctx, "1.2.3.4", "eth", limit, window)
		if err != nil {
			t.Fatalf("blocked request %d: unexpected error: %v", i, err)
		}
		if allowed {
			t.Fatalf("blocked request %d: allowed=true, want false", i)
		}
	}

	card := rl.redis.ZCard(ctx, "ratelimit:eth:1.2.3.4").Val()
	if card != limit {
		t.Errorf("window holds %d entries after 20 blocked requests, want %d — blocked requests consumed budget", card, limit)
	}
}

// TestRateLimiterWindowSlides confirms a blocked client recovers once its window
// drains, rather than being latched off.
func TestRateLimiterWindowSlides(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()

	const limit = 2
	const window = 400 * time.Millisecond

	for i := 0; i < limit; i++ {
		if allowed, _, _, err := rl.CheckLimit(ctx, "1.2.3.4", "poly", limit, window); err != nil || !allowed {
			t.Fatalf("fill request %d: allowed=%v err=%v", i, allowed, err)
		}
	}
	if allowed, _, _, _ := rl.CheckLimit(ctx, "1.2.3.4", "poly", limit, window); allowed {
		t.Fatalf("request over limit: allowed=true, want false")
	}

	time.Sleep(window + 100*time.Millisecond)

	allowed, remaining, _, err := rl.CheckLimit(ctx, "1.2.3.4", "poly", limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("after window drained: allowed=false, want true")
	}
	if want := limit - 1; remaining != want {
		t.Errorf("after window drained: remaining=%d, want %d", remaining, want)
	}
}

// TestRateLimiterLoweredLimitBlocksOversizedWindow covers what production showed
// on 2026-08-19 09:20 UTC: lowering a service's limit left a window already
// holding more entries than the new limit, so the limiter blocked for the ~2
// minutes the oversized window took to drain and then went silent forever.
// That burst was the only evidence the plumbing worked at all, so keep it honest.
func TestRateLimiterLoweredLimitBlocksOversizedWindow(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()

	const oldLimit = 10
	const newLimit = 4
	const window = time.Minute

	for i := 0; i < oldLimit; i++ {
		if allowed, _, _, err := rl.CheckLimit(ctx, "1.2.3.4", "solana", oldLimit, window); err != nil || !allowed {
			t.Fatalf("fill request %d: allowed=%v err=%v", i, allowed, err)
		}
	}

	allowed, remaining, _, err := rl.CheckLimit(ctx, "1.2.3.4", "solana", newLimit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("window holds %d entries against a limit of %d: allowed=true, want false", oldLimit, newLimit)
	}
	if remaining != 0 {
		t.Errorf("remaining=%d, want 0 (must clamp, not go negative)", remaining)
	}
}

// TestRateLimiterKeysAreIsolated pins the key shape "ratelimit:<subdomain>:<ip>".
// Per-service budgets are the whole reason a solana limit can be tightened
// without touching eth, and a per-IP limit is meaningless if IPs share a bucket.
func TestRateLimiterKeysAreIsolated(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()

	const limit = 1
	const window = time.Minute

	if allowed, _, _, _ := rl.CheckLimit(ctx, "1.2.3.4", "solana", limit, window); !allowed {
		t.Fatal("first request: allowed=false, want true")
	}
	if allowed, _, _, _ := rl.CheckLimit(ctx, "1.2.3.4", "solana", limit, window); allowed {
		t.Fatal("same ip + same subdomain: allowed=true, want false")
	}
	if allowed, _, _, _ := rl.CheckLimit(ctx, "1.2.3.4", "eth", limit, window); !allowed {
		t.Error("same ip, different subdomain: allowed=false, want true (budgets are per-service)")
	}
	if allowed, _, _, _ := rl.CheckLimit(ctx, "5.6.7.8", "solana", limit, window); !allowed {
		t.Error("different ip, same subdomain: allowed=false, want true (budgets are per-IP)")
	}
}

// TestRateLimiterDisabledAllowsEverything covers the nil-Redis path, which the
// request handler relies on when rate limiting is turned off.
func TestRateLimiterDisabledAllowsEverything(t *testing.T) {
	ctx := context.Background()
	var rl *RateLimiter

	for i := 0; i < 3; i++ {
		allowed, remaining, _, err := rl.CheckLimit(ctx, "1.2.3.4", "solana", 1, time.Minute)
		if err != nil || !allowed {
			t.Fatalf("nil limiter: allowed=%v err=%v, want allowed=true", allowed, err)
		}
		if remaining != 1 {
			t.Errorf("nil limiter: remaining=%d, want 1 (full budget)", remaining)
		}
	}
}

// TestRateLimiterUnreachableRedisFailsFast pins the 2026-10-02 incident: Redis
// was black-holed (its node went dark, so connections were never
// answered), each check blocked on go-redis timeouts and retries, and taiji's
// "fail open" cost ~30s per request. A check must give up within
// redisCheckTimeout, and after redisFailuresToSkip consecutive failures later
// checks must skip Redis entirely.
func TestRateLimiterUnreachableRedisFailsFast(t *testing.T) {
	// A listener that accepts connections and never replies stands in for a
	// Redis whose node has gone dark.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()

	client := newRedisClient(ln.Addr().String(), "", 0)
	t.Cleanup(func() { _ = client.Close() })
	rl := &RateLimiter{redis: client}
	ctx := context.Background()

	// The first redisFailuresToSkip checks each try Redis and give up within
	// the bound. Fewer failures must not switch rate limiting off.
	for i := 1; i <= redisFailuresToSkip; i++ {
		start := time.Now()
		_, _, _, err := rl.CheckLimit(ctx, "1.2.3.4", "eth", 10, time.Minute)
		if err == nil || errors.Is(err, errRedisUnavailable) {
			t.Fatalf("check %d: err=%v, want a Redis timeout", i, err)
		}
		if took := time.Since(start); took > 4*redisCheckTimeout {
			t.Fatalf("check %d took %s, want under %s", i, took, 4*redisCheckTimeout)
		}
	}

	start := time.Now()
	_, _, _, err = rl.CheckLimit(ctx, "1.2.3.4", "eth", 10, time.Minute)
	if !errors.Is(err, errRedisUnavailable) {
		t.Fatalf("check after %d failures: err=%v, want errRedisUnavailable", redisFailuresToSkip, err)
	}
	if took := time.Since(start); took > 10*time.Millisecond {
		t.Fatalf("check after %d failures took %s, want Redis skipped", redisFailuresToSkip, took)
	}
}

// TestRateLimiterWeightedBatch pins CheckLimitN: a request charges its whole
// weight, is rejected when the weight does not fit, and a rejected batch costs
// nothing.
func TestRateLimiterWeightedBatch(t *testing.T) {
	rl := newTestRateLimiter(t)
	ctx := context.Background()
	const limit = 10
	window := time.Minute

	allowed, remaining, _, err := rl.CheckLimitN(ctx, "1.2.3.4", "eth", limit, window, 7)
	if err != nil || !allowed || remaining != 3 {
		t.Fatalf("batch of 7: allowed=%v remaining=%d err=%v, want true 3 nil", allowed, remaining, err)
	}
	// 4 more do not fit in the 3 left: rejected, and no budget consumed.
	if allowed, _, _, _ := rl.CheckLimitN(ctx, "1.2.3.4", "eth", limit, window, 4); allowed {
		t.Fatal("batch of 4 with 3 left was allowed")
	}
	if card := rl.redis.ZCard(ctx, "ratelimit:eth:1.2.3.4").Val(); card != 7 {
		t.Fatalf("window holds %d entries after a rejected batch, want 7", card)
	}
	// A single request still fits.
	if allowed, remaining, _, _ := rl.CheckLimit(ctx, "1.2.3.4", "eth", limit, window); !allowed || remaining != 2 {
		t.Fatalf("single request: allowed=%v remaining=%d, want true 2", allowed, remaining)
	}
	// A batch larger than the limit itself never fits.
	if allowed, _, _, _ := rl.CheckLimitN(ctx, "5.6.7.8", "eth", limit, window, limit+1); allowed {
		t.Fatal("batch larger than the limit was allowed")
	}
}

// TestBatchWeight counts top-level array items and leaves the body intact.
func TestBatchWeight(t *testing.T) {
	cases := []struct {
		body string
		want int
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}`, 1},
		{`[{"id":1},{"id":2},{"id":3}]`, 3},
		{` [ {"id":1, "params":["a",[1,2]]} , {"id":2} ] `, 2},
		{`[]`, 1},
		{`not json`, 1},
		{`[{"id":1},{"id":`, 1}, // truncated: counts what parsed
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(c.body))
		if got := batchWeight(r); got != c.want {
			t.Errorf("batchWeight(%q) = %d, want %d", c.body, got, c.want)
		}
		rest, _ := io.ReadAll(r.Body)
		if string(rest) != c.body {
			t.Errorf("body changed: got %q, want %q", rest, c.body)
		}
	}
	// Bodies past the peek limit stay intact too.
	big := "[" + strings.Repeat(`{"id":1},`, maxBatchPeekBytes/9+10) + `{"id":2}]`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(big))
	if got := batchWeight(r); got < 1 {
		t.Fatalf("big batch weight %d", got)
	}
	if rest, _ := io.ReadAll(r.Body); string(rest) != big {
		t.Fatal("big body changed")
	}
}
