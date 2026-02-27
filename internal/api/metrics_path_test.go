package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestMetricPath_UsesChiRoutePattern(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/f-123", nil)
	rctx := chi.NewRouteContext()
	rctx.RoutePatterns = append(rctx.RoutePatterns, "/api/v1/findings/{id}")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	if got := metricPath(req); got != "/api/v1/findings/{id}" {
		t.Fatalf("expected chi route pattern, got %q", got)
	}
}

func TestMetricPath_FallsBackToNormalizedURLPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/p-123", nil)

	if got := metricPath(req); got != "/api/v1/policies/{id}" {
		t.Fatalf("expected normalized path, got %q", got)
	}
}
