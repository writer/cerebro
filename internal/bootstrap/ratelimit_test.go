package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
)

func TestRateLimiterAllowsRequestsUnderLimit(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		BurstSize:         10,
		ExemptPaths:       []string{"/health"},
	}
	rl := newRateLimiter(cfg, config.RequestOriginConfig{})

	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First 10 requests (burst) should succeed immediately
	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/test", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimiterExemptsHealthPaths(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		BurstSize:         1,
		ExemptPaths:       []string{"/health", "/healthz"},
	}
	rl := newRateLimiter(cfg, config.RequestOriginConfig{})

	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make many requests to exempt path - all should succeed
	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/health", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("exempt request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimiterChargesReadinessWhenNotExempt(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		BurstSize:         1,
		ExemptPaths:       []string{"/healthz", "/livez", "/metrics", "/.well-known/"},
	}
	rl := newRateLimiter(cfg, config.RequestOriginConfig{})

	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/health", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("readiness request %d status = %d, want %d", i+1, rec.Code, want)
		}
	}

	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/healthz", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("liveness request %d status = %d, want 200", i+1, rec.Code)
		}
	}
}

func TestRateLimiterExemptsWellKnownPaths(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		BurstSize:         1,
		ExemptPaths:       []string{"/.well-known/"},
	}
	rl := newRateLimiter(cfg, config.RequestOriginConfig{})

	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Well-known endpoints should be exempt
	for i := 0; i < 20; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("well-known request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimiterDisabledPassesThrough(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:           false,
		RequestsPerSecond: 1,
		BurstSize:         1,
	}
	rl := newRateLimiter(cfg, config.RequestOriginConfig{})

	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Many requests should succeed when disabled
	for i := 0; i < 100; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/test", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("disabled request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimiterPerClientIsolation(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		BurstSize:         5,
		ExemptPaths:       []string{},
	}
	rl := newRateLimiter(cfg, config.RequestOriginConfig{})

	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust burst from one IP
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		handler.ServeHTTP(rec, req)
	}

	// Same IP should be rate limited now
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	handler.ServeHTTP(rec, req)

	// Different IP should still have full burst available
	for i := 0; i < 5; i++ {
		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest("GET", "/api/test", nil)
		req2.RemoteAddr = "192.168.1.2:1234"
		handler.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusOK {
			t.Fatalf("different IP request %d: expected 200, got %d", i+1, rec2.Code)
		}
	}
}

func TestRateLimiterUsesConfiguredRequestOriginTrust(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		BurstSize:         1,
		ExemptPaths:       []string{},
	}
	originCfg := config.RequestOriginConfig{
		TrustedProxyCIDRs: []string{"192.0.2.0/24"},
	}
	rl := newRateLimiter(cfg, originCfg)

	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest("GET", "/api/test", nil)
	req1.RemoteAddr = "10.0.1.20:443"
	req1.Header.Set("X-Forwarded-For", "198.51.100.1")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rec1.Code)
	}

	req2 := httptest.NewRequest("GET", "/api/test", nil)
	req2.RemoteAddr = "10.0.1.20:443"
	req2.Header.Set("X-Forwarded-For", "198.51.100.2")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed forwarded-for request status = %d, want 429", rec2.Code)
	}
}

func TestRateLimiterCleanupRemovesStaleLimiters(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		BurstSize:         10,
		ExemptPaths:       []string{},
	}
	// Use constructor with custom cleanup interval to avoid data race
	rl := newRateLimiterWithInterval(cfg, config.RequestOriginConfig{}, 100*time.Millisecond)

	// Make a request to create a limiter
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	// Verify limiter exists
	rl.mu.RLock()
	_, exists := rl.limiters["192.168.1.1"]
	rl.mu.RUnlock()
	if !exists {
		t.Fatal("expected limiter to exist after request")
	}

	// Manually set old access time and trigger cleanup
	rl.mu.Lock()
	rl.lastAccess["192.168.1.1"] = time.Now().Add(-15 * time.Minute)
	rl.mu.Unlock()

	rl.cleanupStaleLimiters()

	// Verify limiter was cleaned up
	rl.mu.RLock()
	_, exists = rl.limiters["192.168.1.1"]
	rl.mu.RUnlock()
	if exists {
		t.Fatal("expected stale limiter to be cleaned up")
	}
}
