package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerWindow: 5,
		Window:            time.Minute,
	})
	t.Cleanup(rl.Close)

	key := "test-key"

	// First 5 requests should be allowed
	for i := 0; i < 5; i++ {
		allowed, remaining, _ := rl.Allow(key)
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
		if remaining != 4-i {
			t.Errorf("expected remaining %d, got %d", 4-i, remaining)
		}
	}

	// 6th request should be denied
	allowed, remaining, _ := rl.Allow(key)
	if allowed {
		t.Error("6th request should be denied")
	}
	if remaining != 0 {
		t.Errorf("expected remaining 0, got %d", remaining)
	}
}

func TestRateLimiterWindowReset(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerWindow: 2,
		Window:            50 * time.Millisecond,
	})
	t.Cleanup(rl.Close)

	key := "test-key"

	// Use up all tokens
	rl.Allow(key)
	rl.Allow(key)

	allowed, _, _ := rl.Allow(key)
	if allowed {
		t.Error("should be rate limited")
	}

	// Wait for window to reset
	time.Sleep(60 * time.Millisecond)

	allowed, remaining, _ := rl.Allow(key)
	if !allowed {
		t.Error("should be allowed after window reset")
	}
	if remaining != 1 {
		t.Errorf("expected remaining 1, got %d", remaining)
	}
}

func TestRateLimiterDifferentKeys(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerWindow: 1,
		Window:            time.Minute,
	})
	t.Cleanup(rl.Close)

	// First key
	allowed1, _, _ := rl.Allow("key1")
	if !allowed1 {
		t.Error("key1 first request should be allowed")
	}

	allowed1Again, _, _ := rl.Allow("key1")
	if allowed1Again {
		t.Error("key1 second request should be denied")
	}

	// Second key should have its own bucket
	allowed2, _, _ := rl.Allow("key2")
	if !allowed2 {
		t.Error("key2 first request should be allowed")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerWindow: 2,
		Window:            time.Minute,
		Enabled:           true,
	})
	t.Cleanup(rl.Close)
	middleware := RateLimitMiddlewareWithLimiter(RateLimitConfig{
		RequestsPerWindow: 2,
		Window:            time.Minute,
		Enabled:           true,
	}, rl)

	wrapped := middleware(handler)

	// First 2 requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}

		// Check headers
		if w.Header().Get("X-RateLimit-Limit") != "2" {
			t.Error("missing X-RateLimit-Limit header")
		}
	}

	// 3rd request should be rate limited
	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
}

func TestRateLimitMiddlewareDisabled(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := RateLimitMiddleware(RateLimitConfig{
		RequestsPerWindow: 1,
		Window:            time.Minute,
		Enabled:           false, // Disabled
	})

	wrapped := middleware(handler)

	// All requests should succeed when disabled
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200 when disabled, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimitMiddlewareSkipsHealthEndpoints(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerWindow: 1,
		Window:            time.Minute,
		Enabled:           true,
	})
	t.Cleanup(rl.Close)
	middleware := RateLimitMiddlewareWithLimiter(RateLimitConfig{
		RequestsPerWindow: 1,
		Window:            time.Minute,
		Enabled:           true,
	}, rl)

	wrapped := middleware(handler)

	// Health endpoint should always work
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("/health request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// Same for /ready
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/ready", nil)
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("/ready request %d: expected 200, got %d", i+1, w.Code)
		}
	}
}

func TestGetClientKey(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		addr     string
		expected string
	}{
		{
			name:     "remote address host:port",
			headers:  map[string]string{"X-API-Key": "my-api-key"},
			addr:     "192.168.1.1:1234",
			expected: "ip:192.168.1.1",
		},
		{
			name:     "remote address plain ip",
			headers:  map[string]string{"Authorization": "Bearer token123"},
			addr:     "10.0.0.7",
			expected: "ip:10.0.0.7",
		},
		{
			name:     "fallback x-forwarded-for",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4"},
			addr:     "invalid",
			expected: "ip:1.2.3.4",
		},
		{
			name:     "X-Real-IP header",
			headers:  map[string]string{"X-Real-IP": "5.6.7.8"},
			addr:     "invalid",
			expected: "ip:5.6.7.8",
		},
		{
			name:     "RemoteAddr fallback",
			headers:  map[string]string{},
			addr:     "192.168.1.1:1234",
			expected: "ip:192.168.1.1",
		},
		{
			name:     "remote addr takes precedence",
			headers:  map[string]string{"X-API-Key": "key", "X-Forwarded-For": "1.2.3.4"},
			addr:     "203.0.113.9:8443",
			expected: "ip:203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if tt.addr != "" {
				req.RemoteAddr = tt.addr
			}

			got := getClientKey(req)
			if got != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, got)
			}
		})
	}
}

func TestRateLimiterEnforcesBucketCap(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerWindow: 2,
		Window:            time.Minute,
		MaxBuckets:        3,
	})
	t.Cleanup(rl.Close)

	for i := 0; i < 10; i++ {
		key := "ip:198.51.100." + strconv.Itoa(i)
		_, _, _ = rl.Allow(key)
	}

	rl.mu.RLock()
	defer rl.mu.RUnlock()
	if len(rl.buckets) > 3 {
		t.Fatalf("expected bucket count to be capped at 3, got %d", len(rl.buckets))
	}
	if _, ok := rl.buckets[overflowRateLimitBucketKey]; !ok {
		t.Fatalf("expected overflow bucket %q to exist", overflowRateLimitBucketKey)
	}
}

func TestParsePagination(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		defaultLimit  int
		maxLimit      int
		expectedLimit int
		expectedOff   int
	}{
		{
			name:          "defaults",
			query:         "",
			defaultLimit:  20,
			maxLimit:      100,
			expectedLimit: 20,
			expectedOff:   0,
		},
		{
			name:          "custom limit",
			query:         "limit=50",
			defaultLimit:  20,
			maxLimit:      100,
			expectedLimit: 50,
			expectedOff:   0,
		},
		{
			name:          "limit exceeds max",
			query:         "limit=200",
			defaultLimit:  20,
			maxLimit:      100,
			expectedLimit: 100,
			expectedOff:   0,
		},
		{
			name:          "with offset",
			query:         "limit=10&offset=30",
			defaultLimit:  20,
			maxLimit:      100,
			expectedLimit: 10,
			expectedOff:   30,
		},
		{
			name:          "invalid values ignored",
			query:         "limit=abc&offset=-5",
			defaultLimit:  20,
			maxLimit:      100,
			expectedLimit: 20,
			expectedOff:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/?"+tt.query, nil)
			p := ParsePagination(req, tt.defaultLimit, tt.maxLimit)

			if p.Limit != tt.expectedLimit {
				t.Errorf("expected limit %d, got %d", tt.expectedLimit, p.Limit)
			}
			if p.Offset != tt.expectedOff {
				t.Errorf("expected offset %d, got %d", tt.expectedOff, p.Offset)
			}
		})
	}
}

func TestBuildPaginationResponse(t *testing.T) {
	params := PaginationParams{Limit: 10, Offset: 20}

	// More results available
	resp := BuildPaginationResponse(100, params, 10)
	if !resp.HasMore {
		t.Error("expected HasMore=true when more results available")
	}

	// Last page
	params.Offset = 90
	resp = BuildPaginationResponse(100, params, 10)
	if resp.HasMore {
		t.Error("expected HasMore=false on last page")
	}
}
