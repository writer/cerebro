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

func TestGetClientKey_NoTrustedProxies(t *testing.T) {
	// Without trusted proxies configured, forwarded headers are ignored.
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
			name:     "matching Authorization and X-API-Key canonicalize to one key",
			headers:  map[string]string{"Authorization": "Bearer key", "X-API-Key": "key"},
			expected: "apikey:key",
		},
		{
			name:     "malformed Authorization falls back to IP key",
			headers:  map[string]string{"Authorization": "Token token123", "X-Forwarded-For": "1.2.3.4"},
			addr:     "203.0.113.9:8443",
			expected: "ip:203.0.113.9",
		},
		{
			name:     "conflicting API credentials fall back to IP key",
			headers:  map[string]string{"Authorization": "Bearer token123", "X-API-Key": "other"},
			addr:     "192.168.1.1:1234",
			expected: "ip:192.168.1.1",
		},
		{
			name:     "RemoteAddr used even when XFF present",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4"},
			addr:     "203.0.113.9:8443",
			expected: "ip:203.0.113.9",
		},
		{
			name:     "RemoteAddr plain ip",
			headers:  map[string]string{},
			addr:     "10.0.0.7",
			expected: "ip:10.0.0.7",
		},
		{
			name:     "RemoteAddr host:port",
			headers:  map[string]string{},
			addr:     "192.168.1.1:1234",
			expected: "ip:192.168.1.1",
		},
		{
			name:     "RemoteAddr IPv6 host:port",
			headers:  map[string]string{},
			addr:     "[2001:db8::1]:1234",
			expected: "ip:2001:db8::1",
		},
		{
			name:     "invalid RemoteAddr returns unknown",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4"},
			addr:     "invalid",
			expected: "ip:unknown",
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
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestGetClientKey_TrustedProxy(t *testing.T) {
	trusted := parseTrustedProxyCIDRs([]string{"10.0.0.0/8", "172.16.0.0/12"})

	tests := []struct {
		name     string
		headers  map[string]string
		addr     string
		expected string
	}{
		{
			name:     "trusted proxy honours XFF",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4"},
			addr:     "10.0.0.1:9090",
			expected: "ip:1.2.3.4",
		},
		{
			name:     "trusted proxy multi-hop XFF uses leftmost",
			headers:  map[string]string{"X-Forwarded-For": "5.6.7.8, 10.0.0.2"},
			addr:     "10.0.0.1:9090",
			expected: "ip:5.6.7.8",
		},
		{
			name:     "trusted proxy honours X-Real-IP when no XFF",
			headers:  map[string]string{"X-Real-IP": "9.8.7.6"},
			addr:     "172.16.0.5:8080",
			expected: "ip:9.8.7.6",
		},
		{
			name:     "trusted proxy falls back to RemoteAddr when no forwarded headers",
			headers:  map[string]string{},
			addr:     "10.0.0.1:9090",
			expected: "ip:10.0.0.1",
		},
		{
			name:     "untrusted remote ignores XFF",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4"},
			addr:     "203.0.113.50:4321",
			expected: "ip:203.0.113.50",
		},
		{
			name:     "trusted proxy with malformed XFF falls to RemoteAddr",
			headers:  map[string]string{"X-Forwarded-For": "not-an-ip"},
			addr:     "10.0.0.1:9090",
			expected: "ip:10.0.0.1",
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

			got := getClientKeyTrusted(req, trusted)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestParseTrustedProxyCIDRs(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect int
	}{
		{"nil input", nil, 0},
		{"empty strings", []string{"", " "}, 0},
		{"valid CIDR", []string{"10.0.0.0/8"}, 1},
		{"bare IP becomes /32", []string{"192.168.1.1"}, 1},
		{"mixed valid and invalid", []string{"10.0.0.0/8", "garbage", "172.16.0.0/12"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets := parseTrustedProxyCIDRs(tt.input)
			if len(nets) != tt.expect {
				t.Errorf("expected %d nets, got %d", tt.expect, len(nets))
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
