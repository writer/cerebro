package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestMetricsEndpoint_ReturnsPrometheusPayload(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/metrics", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /metrics, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "cerebro_") {
		t.Fatalf("expected prometheus payload to include cerebro metrics, got: %s", w.Body.String())
	}
}

func TestOpenAPIEndpoint_ReturnsEmbeddedSpec(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/openapi.yaml", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /openapi.yaml, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "application/yaml") {
		t.Fatalf("expected application/yaml content type, got %q", got)
	}
	if !strings.Contains(w.Body.String(), "openapi: 3.0.3") {
		t.Fatalf("expected OpenAPI header in spec body, got: %s", w.Body.String())
	}
}
