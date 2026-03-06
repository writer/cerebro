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

	cases := []struct {
		path       string
		wantStatus int
	}{
		{path: "/health", wantStatus: http.StatusOK},
		{path: "/ready", wantStatus: http.StatusOK},
		{path: "/metrics", wantStatus: http.StatusOK},
		{path: "/docs", wantStatus: http.StatusOK},
		// openapi.yaml is served from a relative file path in tests and may 404,
		// but auth middleware must not block it.
		{path: "/openapi.yaml", wantStatus: 0},
	}

	for _, tc := range cases {
		w := do(t, s, http.MethodGet, tc.path, nil)
		if tc.wantStatus != 0 && w.Code != tc.wantStatus {
			t.Fatalf("expected %d for public endpoint %s, got %d", tc.wantStatus, tc.path, w.Code)
		}
		if w.Code == http.StatusUnauthorized {
			t.Fatalf("expected auth bypass for public endpoint %s, got 401", tc.path)
		}
	}

	protected := do(t, s, http.MethodGet, "/api/v1/policies/", nil)
	if protected.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for protected endpoint, got %d", protected.Code)
	}
}
