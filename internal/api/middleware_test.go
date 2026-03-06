package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/auth"
)

func TestExtractAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*http.Request)
		expected string
	}{
		{
			name: "Bearer token",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer test-key-123")
			},
			expected: "test-key-123",
		},
		{
			name: "X-API-Key header",
			setup: func(r *http.Request) {
				r.Header.Set("X-API-Key", "header-key-456")
			},
			expected: "header-key-456",
		},
		{
			name:     "No key",
			setup:    func(r *http.Request) {},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/v1/test", nil)
			tt.setup(r)

			key := extractAPIKey(r)
			if key != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, key)
			}
		})
	}
}

func TestAPIKeyAuth(t *testing.T) {
	cfg := AuthConfig{
		Enabled: true,
		APIKeys: map[string]string{
			"valid-key": "user-1",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := GetUserID(r.Context())
		w.Write([]byte(userID))
	})

	middleware := APIKeyAuth(cfg)(handler)

	tests := []struct {
		name       string
		path       string
		apiKey     string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "Valid key",
			path:       "/api/v1/test",
			apiKey:     "valid-key",
			wantStatus: http.StatusOK,
			wantBody:   "user-1",
		},
		{
			name:       "Invalid key",
			path:       "/api/v1/test",
			apiKey:     "invalid-key",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Missing key",
			path:       "/api/v1/test",
			apiKey:     "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Health endpoint - no auth required",
			path:       "/health",
			apiKey:     "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "Ready endpoint - no auth required",
			path:       "/ready",
			apiKey:     "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "Metrics endpoint - no auth required",
			path:       "/metrics",
			apiKey:     "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "Docs endpoint - no auth required",
			path:       "/docs",
			apiKey:     "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "OpenAPI endpoint - no auth required",
			path:       "/openapi.yaml",
			apiKey:     "",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.path, nil)
			if tt.apiKey != "" {
				r.Header.Set("Authorization", "Bearer "+tt.apiKey)
			}

			w := httptest.NewRecorder()
			middleware.ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, w.Code)
			}

			if tt.wantBody != "" && w.Body.String() != tt.wantBody {
				t.Errorf("expected body '%s', got '%s'", tt.wantBody, w.Body.String())
			}
		})
	}
}

func TestAPIKeyAuthDisabled(t *testing.T) {
	cfg := AuthConfig{
		Enabled: false,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := APIKeyAuth(cfg)(handler)

	r := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()
	middleware.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 when auth disabled, got %d", w.Code)
	}
}

func TestAPIKeyAuth_FallsBackToXAPIKeyWhenAuthorizationIsMalformed(t *testing.T) {
	cfg := AuthConfig{
		Enabled: true,
		APIKeys: map[string]string{
			"valid-key": "user-1",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(GetUserID(r.Context())))
	})

	middleware := APIKeyAuth(cfg)(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("Authorization", "Token malformed")
	req.Header.Set("X-API-Key", "valid-key")

	w := httptest.NewRecorder()
	middleware.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if got := w.Body.String(); got != "user-1" {
		t.Fatalf("expected user-1 from X-API-Key fallback, got %q", got)
	}
}

func TestRBACMiddleware_PassesThroughWithoutAuthenticatedUser(t *testing.T) {
	rbac := auth.NewRBAC()
	m := RBACMiddleware(rbac)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/sessions", nil)
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected pass-through without user context, got %d", w.Code)
	}
}

func TestRoutePermissionCoverage(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		expectedRB string
	}{
		{name: "agents read", method: http.MethodGet, path: "/api/v1/agents/", expectedRB: "agents:read"},
		{name: "agents write", method: http.MethodPost, path: "/api/v1/agents/sessions", expectedRB: "agents:write"},
		{name: "tickets read", method: http.MethodGet, path: "/api/v1/tickets/", expectedRB: "tickets:read"},
		{name: "tickets write", method: http.MethodPost, path: "/api/v1/tickets/", expectedRB: "tickets:write"},
		{name: "runtime read", method: http.MethodGet, path: "/api/v1/runtime/detections", expectedRB: "runtime:read"},
		{name: "runtime write", method: http.MethodPost, path: "/api/v1/runtime/events", expectedRB: "runtime:write"},
		{name: "graph read", method: http.MethodGet, path: "/api/v1/graph/stats", expectedRB: "graph:read"},
		{name: "graph write", method: http.MethodPost, path: "/api/v1/graph/rebuild", expectedRB: "graph:write"},
		{name: "incident route uses findings", method: http.MethodGet, path: "/api/v1/incidents/playbooks", expectedRB: "findings:read"},
		{name: "providers require admin", method: http.MethodGet, path: "/api/v1/providers/aws", expectedRB: "admin:users"},
		{name: "compliance export", method: http.MethodGet, path: "/api/v1/compliance/frameworks/pci/export", expectedRB: "compliance:export"},
		{name: "unknown api read is locked down", method: http.MethodGet, path: "/api/v1/unknown", expectedRB: "findings:read"},
		{name: "unknown api write is admin", method: http.MethodPost, path: "/api/v1/unknown", expectedRB: "admin:users"},
		{name: "non api route", method: http.MethodGet, path: "/health", expectedRB: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := routePermission(tt.method, tt.path)
			if got != tt.expectedRB {
				t.Fatalf("routePermission(%s, %s) = %q, want %q", tt.method, tt.path, got, tt.expectedRB)
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := SecurityHeaders()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected X-Content-Type-Options nosniff, got %q", got)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("expected X-Frame-Options DENY, got %q", got)
	}
	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("expected Referrer-Policy no-referrer, got %q", got)
	}
	if got := w.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatal("expected Strict-Transport-Security header")
	}
}

func TestCORSPreflight(t *testing.T) {
	h := CORS([]string{"https://app.example.com"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("allowed origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/test", nil)
		req.Header.Set("Origin", "https://app.example.com")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", w.Code)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
			t.Fatalf("expected allowed origin header, got %q", got)
		}
	})

	t.Run("blocked origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/test", nil)
		req.Header.Set("Origin", "https://blocked.example.com")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
}
