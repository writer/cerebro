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
