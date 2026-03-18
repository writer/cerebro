package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
)

func TestComplianceFrameworkHandlersUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreComplianceTestGraph(false))

	report := do(t, s, http.MethodGet, "/api/v1/compliance/frameworks/cis-aws-1.5/report", nil)
	if report.Code != http.StatusOK {
		t.Fatalf("expected report 200, got %d: %s", report.Code, report.Body.String())
	}
	reportBody := decodeJSON(t, report)
	reportControl := requireComplianceControl(t, reportBody["report"], "2.1.1")
	if got := reportControl["status"]; got != "failing" {
		t.Fatalf("expected failing control from store-backed report, got %#v", reportControl)
	}
	if got := reportControl["evaluation_source"]; got != "graph" {
		t.Fatalf("expected graph evaluation source from store-backed report, got %#v", reportControl)
	}

	status := do(t, s, http.MethodGet, "/api/v1/compliance/frameworks/cis-aws-1.5/status", nil)
	if status.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", status.Code, status.Body.String())
	}
	statusBody := decodeJSON(t, status)
	statusControl := requireComplianceControl(t, statusBody, "2.1.1")
	if got := statusControl["status"]; got != "failing" {
		t.Fatalf("expected failing control from store-backed status, got %#v", statusControl)
	}
}

func TestComplianceFrameworkHandlersPreferLiveGraphOverSnapshotWhenAvailable(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		graphRuntime: stubGraphRuntime{
			graph: buildGraphStoreComplianceTestGraph(true),
			store: buildGraphStoreComplianceTestGraph(false),
		},
	})
	t.Cleanup(func() { s.Close() })

	status := do(t, s, http.MethodGet, "/api/v1/compliance/frameworks/cis-aws-1.5/status", nil)
	if status.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", status.Code, status.Body.String())
	}
	body := decodeJSON(t, status)
	control := requireComplianceControl(t, body, "2.1.1")
	if got := control["status"]; got != "passing" {
		t.Fatalf("expected live graph to win over failing snapshot, got %#v", control)
	}
}

func buildGraphStoreComplianceTestGraph(encrypted bool) *graph.Graph {
	now := time.Date(2026, time.March, 18, 18, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:        "arn:aws:s3:::graph-store-compliance-bucket",
		Kind:      graph.NodeKindBucket,
		Name:      "graph-store-compliance-bucket",
		Provider:  "aws",
		Account:   "123456789012",
		CreatedAt: now,
		Properties: map[string]any{
			"encrypted":           encrypted,
			"public":              !encrypted,
			"block_public_acls":   encrypted,
			"block_public_policy": encrypted,
			"logging_enabled":     encrypted,
			"observed_at":         now,
			"valid_from":          now,
			"recorded_at":         now,
			"transaction_from":    now,
		},
	})
	return g
}

func requireComplianceControl(t *testing.T, payload any, controlID string) map[string]any {
	t.Helper()

	body, ok := payload.(map[string]any)
	if !ok {
		t.Fatalf("expected map payload, got %T", payload)
	}

	rawControls, ok := body["controls"].([]any)
	if !ok {
		t.Fatalf("expected controls list, got %#v", body)
	}
	for _, raw := range rawControls {
		control, ok := raw.(map[string]any)
		if ok && control["control_id"] == controlID {
			return control
		}
	}
	t.Fatalf("expected control %s in payload %#v", controlID, body)
	return nil
}
