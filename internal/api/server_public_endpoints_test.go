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

	publicPaths := []string{"/health", "/ready", "/docs", "/openapi.yaml"}
	for _, path := range publicPaths {
		w := do(t, s, http.MethodGet, path, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for public endpoint %s, got %d", path, w.Code)
		}
	}

	metrics := do(t, s, http.MethodGet, "/metrics", nil)
	if metrics.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for /metrics when auth is enabled, got %d", metrics.Code)
	}

	protected := do(t, s, http.MethodGet, "/api/v1/policies/", nil)
	if protected.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for protected endpoint, got %d", protected.Code)
	}
}
