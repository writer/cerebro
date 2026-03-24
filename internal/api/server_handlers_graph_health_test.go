package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
)

func TestGraphHealthEndpointReturnsRuntimeSnapshot(t *testing.T) {
	now := time.Date(2026, time.March, 20, 18, 0, 0, 0, time.UTC)
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		graphRuntime: stubGraphRuntime{
			healthSnapshot: app.GraphHealthSnapshot{
				EvaluatedAt:    now,
				NodeCount:      12,
				EdgeCount:      34,
				SnapshotCount:  5,
				LastMutationAt: now.Add(-5 * time.Minute),
				WriterLease: app.GraphWriterLeaseStatus{
					Enabled:       true,
					Role:          app.GraphWriterRoleWriter,
					LeaseHolderID: "writer-1",
				},
				TierDistribution: app.GraphTierDistribution{
					Hot:  1,
					Warm: 2,
					Cold: 5,
				},
				MemoryUsageEstimateBytes: 22272,
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	w := do(t, s, http.MethodGet, "/api/v1/graph/health", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if got := int(body["node_count"].(float64)); got != 12 {
		t.Fatalf("node_count = %d, want 12", got)
	}
	if got := int(body["edge_count"].(float64)); got != 34 {
		t.Fatalf("edge_count = %d, want 34", got)
	}
	if got := int(body["snapshot_count"].(float64)); got != 5 {
		t.Fatalf("snapshot_count = %d, want 5", got)
	}
	writerLease, ok := body["writer_lease"].(map[string]any)
	if !ok {
		t.Fatalf("expected writer_lease object, got %#v", body["writer_lease"])
	}
	if writerLease["lease_holder_id"] != "writer-1" {
		t.Fatalf("lease_holder_id = %#v, want writer-1", writerLease["lease_holder_id"])
	}
	tierDistribution, ok := body["tier_distribution"].(map[string]any)
	if !ok {
		t.Fatalf("expected tier_distribution object, got %#v", body["tier_distribution"])
	}
	if got := int(tierDistribution["warm"].(float64)); got != 2 {
		t.Fatalf("tier_distribution.warm = %d, want 2", got)
	}
	if got := int(body["memory_usage_estimate_bytes"].(float64)); got != 22272 {
		t.Fatalf("memory_usage_estimate_bytes = %d, want 22272", got)
	}
}

func TestGraphHealthEndpointNilServerReturnsServiceUnavailable(t *testing.T) {
	var s *Server

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/graph/health", nil)

	s.graphHealth(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}
	body := decodeJSON(t, w)
	if got := body["error"]; got != "graph platform not initialized" {
		t.Fatalf("error = %#v, want %q", got, "graph platform not initialized")
	}
	if got := body["code"]; got != "service_unavailable" {
		t.Fatalf("code = %#v, want %q", got, "service_unavailable")
	}
}
