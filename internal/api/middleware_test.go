package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
			name: "Bearer token (case-insensitive scheme)",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "bearer test-key-123")
			},
			expected: "test-key-123",
		},
		{
			name: "Bearer token (extra whitespace)",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "  Bearer   spaced-key  ")
			},
			expected: "spaced-key",
		},
		{
			name: "X-API-Key header",
			setup: func(r *http.Request) {
				r.Header.Set("X-API-Key", "header-key-456")
			},
			expected: "header-key-456",
		},
		{
			name: "Malformed Authorization does not fall back",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Token malformed")
				r.Header.Set("X-API-Key", "header-key-456")
			},
			expected: "",
		},
		{
			name: "Conflicting headers rejected",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer auth-key")
				r.Header.Set("X-API-Key", "header-key-456")
			},
			expected: "",
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

			key, err := extractAPIKeyStrict(r)
			if err != nil {
				key = ""
			}
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
		if _, err := w.Write([]byte(userID)); err != nil {
			t.Fatalf("write response: %v", err)
		}
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

func TestAPIKeyAuth_DynamicAPIKeyProvider(t *testing.T) {
	currentKeys := map[string]string{
		"old-key": "user-old",
	}

	cfg := AuthConfig{
		Enabled: true,
		APIKeyProvider: func() map[string]string {
			cloned := make(map[string]string, len(currentKeys))
			for key, value := range currentKeys {
				cloned[key] = value
			}
			return cloned
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(GetUserID(r.Context())))
	})
	middleware := APIKeyAuth(cfg)(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer old-key")
	w := httptest.NewRecorder()
	middleware.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "user-old" {
		t.Fatalf("expected old key to authenticate before rotation, status=%d body=%q", w.Code, w.Body.String())
	}

	currentKeys = map[string]string{
		"new-key": "user-new",
	}

	reqOld := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	reqOld.Header.Set("Authorization", "Bearer old-key")
	wOld := httptest.NewRecorder()
	middleware.ServeHTTP(wOld, reqOld)
	if wOld.Code != http.StatusUnauthorized {
		t.Fatalf("expected rotated-out key to fail auth, got status=%d", wOld.Code)
	}

	reqNew := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	reqNew.Header.Set("Authorization", "Bearer new-key")
	wNew := httptest.NewRecorder()
	middleware.ServeHTTP(wNew, reqNew)
	if wNew.Code != http.StatusOK || wNew.Body.String() != "user-new" {
		t.Fatalf("expected new key to authenticate after rotation, status=%d body=%q", wNew.Code, wNew.Body.String())
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

func TestAPIKeyAuth_RejectsMalformedAuthorizationEvenWithXAPIKey(t *testing.T) {
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
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if body := w.Body.String(); body == "" || !strings.Contains(body, "invalid_authorization_header") {
		t.Fatalf("expected invalid_authorization_header body, got %q", body)
	}
}

func TestAPIKeyAuth_RejectsConflictingCredentials(t *testing.T) {
	cfg := AuthConfig{
		Enabled: true,
		APIKeys: map[string]string{
			"valid-key": "user-1",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := APIKeyAuth(cfg)(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer valid-key")
	req.Header.Set("X-API-Key", "different-key")

	w := httptest.NewRecorder()
	middleware.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if body := w.Body.String(); body == "" || !strings.Contains(body, "conflicting_api_credentials") {
		t.Fatalf("expected conflicting_api_credentials body, got %q", body)
	}
}

func TestAPIKeyAuth_AllowsMatchingCredentialsFromBothHeaders(t *testing.T) {
	cfg := AuthConfig{
		Enabled: true,
		APIKeys: map[string]string{
			"valid-key": "user-1",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(GetUserID(r.Context())))
	})

	middleware := APIKeyAuth(cfg)(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer valid-key")
	req.Header.Set("X-API-Key", "valid-key")

	w := httptest.NewRecorder()
	middleware.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if got := w.Body.String(); got != "user-1" {
		t.Fatalf("expected user-1, got %q", got)
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

func TestRBACMiddleware_SetsTenantInContext(t *testing.T) {
	rbac := auth.NewRBAC()
	if err := rbac.CreateUser(&auth.User{
		ID:       "tenant-user-1",
		Email:    "tenant@example.com",
		TenantID: "tenant-acme",
		RoleIDs:  []string{"viewer"},
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	m := RBACMiddleware(rbac)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(GetTenantID(r.Context())))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextKeyUserID, "tenant-user-1"))
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "tenant-acme" {
		t.Fatalf("expected tenant-acme in context, got %q", got)
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
		{name: "tickets read", method: http.MethodGet, path: "/api/v1/tickets/", expectedRB: "security.tickets.read"},
		{name: "tickets write", method: http.MethodPost, path: "/api/v1/tickets/", expectedRB: "security.tickets.manage"},
		{name: "runtime read", method: http.MethodGet, path: "/api/v1/runtime/detections", expectedRB: "security.runtime.read"},
		{name: "runtime write", method: http.MethodPost, path: "/api/v1/runtime/events", expectedRB: "security.runtime.write"},
		{name: "graph read", method: http.MethodGet, path: "/api/v1/graph/stats", expectedRB: "platform.graph.read"},
		{name: "graph write", method: http.MethodPost, path: "/api/v1/graph/rebuild", expectedRB: "platform.graph.write"},
		{name: "agent sdk tools list", method: http.MethodGet, path: "/api/v1/agent-sdk/tools", expectedRB: "sdk.schema.read"},
		{name: "agent sdk context", method: http.MethodGet, path: "/api/v1/agent-sdk/context/service:payments", expectedRB: "sdk.context.read"},
		{name: "agent sdk check", method: http.MethodPost, path: "/api/v1/agent-sdk/check", expectedRB: "sdk.enforcement.run"},
		{name: "agent sdk claim", method: http.MethodPost, path: "/api/v1/agent-sdk/claims", expectedRB: "sdk.worldmodel.write"},
		{name: "mcp invoke", method: http.MethodPost, path: "/api/v1/mcp", expectedRB: "sdk.invoke"},
		{name: "platform intelligence", method: http.MethodGet, path: "/api/v1/platform/intelligence/leverage", expectedRB: "platform.intelligence.read"},
		{name: "platform intelligence run", method: http.MethodPost, path: "/api/v1/platform/intelligence/reports/quality/runs", expectedRB: "platform.intelligence.run"},
		{name: "platform graph diff materialize", method: http.MethodPost, path: "/api/v1/platform/graph/diffs", expectedRB: "platform.graph.write"},
		{name: "platform workload scan targets", method: http.MethodGet, path: "/api/v1/platform/workload-scan/targets", expectedRB: "platform.graph.read"},
		{name: "cross tenant read", method: http.MethodGet, path: "/api/v1/graph/cross-tenant/patterns", expectedRB: "platform.cross_tenant.read"},
		{name: "cross tenant write", method: http.MethodPost, path: "/api/v1/graph/cross-tenant/patterns/ingest", expectedRB: "platform.cross_tenant.write"},
		{name: "platform knowledge read", method: http.MethodGet, path: "/api/v1/platform/knowledge/claims", expectedRB: "platform.knowledge.read"},
		{name: "platform knowledge write", method: http.MethodPost, path: "/api/v1/platform/knowledge/claims", expectedRB: "platform.knowledge.write"},
		{name: "org expertise read", method: http.MethodGet, path: "/api/v1/org/expertise/queries", expectedRB: "org.expertise.read"},
		{name: "org reorg simulate", method: http.MethodPost, path: "/api/v1/org/reorg-simulations", expectedRB: "org.reorg.simulate"},
		{name: "incident route uses security scope", method: http.MethodGet, path: "/api/v1/incidents/playbooks", expectedRB: "security.incidents.read"},
		{name: "audit routes require admin", method: http.MethodGet, path: "/api/v1/audit", expectedRB: "admin.audit.read"},
		{name: "providers require admin", method: http.MethodGet, path: "/api/v1/providers/aws", expectedRB: "admin.providers.manage"},
		{name: "compliance export", method: http.MethodGet, path: "/api/v1/compliance/frameworks/pci/export", expectedRB: "security.compliance.export"},
		{name: "unknown api read is locked down", method: http.MethodGet, path: "/api/v1/unknown", expectedRB: "security.findings.read"},
		{name: "unknown api write is admin", method: http.MethodPost, path: "/api/v1/unknown", expectedRB: "admin.operations.manage"},
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

func TestRoutePermission_WorkloadScanTargetsRequiresGraphRead(t *testing.T) {
	required := routePermission(http.MethodGet, "/api/v1/platform/workload-scan/targets")
	if required != "platform.graph.read" {
		t.Fatalf("expected platform.graph.read, got %q", required)
	}
	if credentialAllowsPermission([]string{"security.findings.read"}, required) {
		t.Fatalf("security.findings.read should not satisfy %q", required)
	}
	if !credentialAllowsPermission([]string{"platform.graph.read"}, required) {
		t.Fatalf("platform.graph.read should satisfy %q", required)
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
