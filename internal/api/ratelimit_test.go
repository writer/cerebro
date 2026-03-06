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
	retryAfter := w.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("missing Retry-After header")
	} else if parsed, err := strconv.Atoi(retryAfter); err != nil || parsed < 1 {
		t.Errorf("expected Retry-After >= 1, got %q", retryAfter)
	}
}

func TestRateLimitMiddleware_RetryAfterMinimumOneSecond(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerWindow: 1,
		Window:            50 * time.Millisecond,
		Enabled:           true,
	})
	t.Cleanup(rl.Close)
	middleware := RateLimitMiddlewareWithLimiter(RateLimitConfig{
		RequestsPerWindow: 1,
		Window:            50 * time.Millisecond,
		Enabled:           true,
	}, rl)

	wrapped := middleware(handler)

	req1 := httptest.NewRequest("GET", "/api/v1/test", nil)
	req1.RemoteAddr = "192.168.1.1:1234"
	w1 := httptest.NewRecorder()
	wrapped.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w1.Code)
	}

	req2 := httptest.NewRequest("GET", "/api/v1/test", nil)
	req2.RemoteAddr = "192.168.1.1:1234"
	w2 := httptest.NewRecorder()
	wrapped.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: expected 429, got %d", w2.Code)
	}

	retryAfter := w2.Header().Get("Retry-After")
	parsed, err := strconv.Atoi(retryAfter)
	if err != nil {
		t.Fatalf("expected numeric Retry-After header, got %q", retryAfter)
	}
	if parsed < 1 {
		t.Fatalf("expected Retry-After >= 1, got %d", parsed)
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

func TestRateLimitMiddlewareSkipsPublicEndpoints(t *testing.T) {
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

	publicPaths := []string{"/health", "/ready", "/metrics", "/docs", "/openapi.yaml"}
	for _, path := range publicPaths {
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()

			wrapped.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("%s request %d: expected 200, got %d", path, i+1, w.Code)
			}
			if got := w.Header().Get("X-RateLimit-Limit"); got != "" {
				t.Errorf("%s request %d: expected no rate limit headers for bypassed endpoint, got X-RateLimit-Limit=%q", path, i+1, got)
			}
		}
	}

	// Public endpoint traffic should not consume API route quota.
	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first protected route request: expected 200, got %d", w.Code)
	}

	req2 := httptest.NewRequest("GET", "/api/v1/test", nil)
	req2.RemoteAddr = "192.168.1.1:1234"
	w2 := httptest.NewRecorder()
	wrapped.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second protected route request: expected 429, got %d", w2.Code)
	}
}

func TestRateLimitMiddleware_UsesRemoteIPWithoutPort(t *testing.T) {
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

	// Requests from the same client IP but different source ports must share
	// one bucket so opening new connections cannot bypass limits.
	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.RemoteAddr = "192.168.1.1:10001"
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w.Code)
	}

	req2 := httptest.NewRequest("GET", "/api/v1/test", nil)
	req2.RemoteAddr = "192.168.1.1:10002"
	w2 := httptest.NewRecorder()
	wrapped.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request from same IP with different port: expected 429, got %d", w2.Code)
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
			name:     "X-API-Key header",
			headers:  map[string]string{"X-API-Key": "my-api-key"},
			expected: "apikey:my-api-key",
		},
		{
			name:     "Authorization header",
			headers:  map[string]string{"Authorization": "Bearer token123"},
			expected: "apikey:token123",
		},
		{
			name:     "Authorization header with extra spaces",
			headers:  map[string]string{"Authorization": "   Bearer   token123   "},
			expected: "apikey:token123",
		},
		{
			name:     "X-Forwarded-For header",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4"},
			expected: "ip:1.2.3.4",
		},
		{
			name:     "X-Forwarded-For uses first IP",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8"},
			expected: "ip:1.2.3.4",
		},
		{
			name:     "X-Real-IP header",
			headers:  map[string]string{"X-Real-IP": "5.6.7.8"},
			expected: "ip:5.6.7.8",
		},
		{
			name:     "RemoteAddr fallback",
			headers:  map[string]string{},
			addr:     "192.168.1.1:1234",
			expected: "ip:192.168.1.1",
		},
		{
			name:     "RemoteAddr fallback keeps host when no port",
			headers:  map[string]string{},
			addr:     "192.168.1.1",
			expected: "ip:192.168.1.1",
		},
		{
			name:     "RemoteAddr fallback supports IPv6 host:port",
			headers:  map[string]string{},
			addr:     "[2001:db8::1]:1234",
			expected: "ip:2001:db8::1",
		},
		{
			name:     "X-API-Key takes precedence",
			headers:  map[string]string{"X-API-Key": "key", "X-Forwarded-For": "1.2.3.4"},
			expected: "apikey:key",
		},
		{
			name:     "matching Authorization and X-API-Key canonicalize to one key",
			headers:  map[string]string{"Authorization": "Bearer key", "X-API-Key": "key"},
			expected: "apikey:key",
		},
		{
			name:     "malformed Authorization falls back to IP key",
			headers:  map[string]string{"Authorization": "Token token123", "X-Forwarded-For": "1.2.3.4"},
			expected: "ip:1.2.3.4",
		},
		{
			name:     "conflicting API credentials fall back to IP key",
			headers:  map[string]string{"Authorization": "Bearer token123", "X-API-Key": "other"},
			addr:     "192.168.1.1:1234",
			expected: "ip:192.168.1.1",
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
