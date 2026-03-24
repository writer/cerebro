package api

import (
	"net/http"
	"testing"
)

func TestPublicEndpoints_RemainAccessibleWhenAPIAuthEnabled(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{
		"smoke-key": "smoke-user",
	}

	s := NewServer(a)

	publicPaths := []string{"/health", "/ready", "/metrics", "/docs", "/openapi.yaml", "/api/v1/trust-center", "/api/v1/trust-center/evidence"}
	for _, path := range publicPaths {
		w := do(t, s, http.MethodGet, path, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for public endpoint %s, got %d", path, w.Code)
		}
	}

	protected := do(t, s, http.MethodGet, "/api/v1/policies/", nil)
	if protected.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for protected endpoint, got %d", protected.Code)
	}
}
