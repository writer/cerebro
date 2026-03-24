package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func TestTrustCenterSnapshotIncludesFrameworksSubprocessorsAndEvidence(t *testing.T) {
	s := newTestServer(t)
	now := time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC)
	s.app.SecurityGraph.AddNode(&graph.Node{
		ID:        "arn:aws:s3:::trust-center-bucket",
		Kind:      graph.NodeKindBucket,
		Name:      "trust-center-bucket",
		Provider:  "aws",
		Account:   "123456789012",
		CreatedAt: now,
		Properties: map[string]any{
			"encrypted":           false,
			"public":              true,
			"block_public_acls":   false,
			"block_public_policy": false,
			"logging_enabled":     false,
			"observed_at":         now,
			"valid_from":          now,
			"recorded_at":         now,
			"transaction_from":    now,
		},
	})
	s.app.SecurityGraph.AddNode(&graph.Node{
		ID:   "vendor:slack",
		Kind: graph.NodeKindVendor,
		Name: "Slack",
		Risk: graph.RiskHigh,
		Properties: map[string]any{
			"vendor_risk_score":         86,
			"vendor_category":           "saas_integration",
			"verification_status":       "verified",
			"permission_level":          "admin",
			"source_providers":          []string{"okta", "azure"},
			"accessible_resource_kinds": []string{"bucket", "secret"},
		},
	})

	resp := do(t, s, http.MethodGet, "/api/v1/trust-center", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for trust center snapshot, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	if got, ok := body["generated_at"].(string); !ok || got == "" {
		t.Fatalf("expected generated_at in trust center snapshot, got %#v", body["generated_at"])
	}
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary payload, got %#v", body["summary"])
	}
	if got, ok := summary["framework_count"].(float64); !ok || got == 0 {
		t.Fatalf("expected non-zero framework count, got %#v", summary["framework_count"])
	}
	subprocessors, ok := body["subprocessors"].([]any)
	if !ok || len(subprocessors) == 0 {
		t.Fatalf("expected subprocessors payload, got %#v", body["subprocessors"])
	}
	firstSubprocessor, ok := subprocessors[0].(map[string]any)
	if !ok || firstSubprocessor["vendor_id"] != "vendor:slack" {
		t.Fatalf("expected slack vendor in subprocessors, got %#v", subprocessors)
	}
	evidenceCatalog, ok := body["evidence_catalog"].([]any)
	if !ok || len(evidenceCatalog) == 0 {
		t.Fatalf("expected evidence catalog, got %#v", body["evidence_catalog"])
	}
	practices, ok := body["security_practices"].([]any)
	if !ok || len(practices) == 0 {
		t.Fatalf("expected security practices, got %#v", body["security_practices"])
	}
}

func TestTrustCenterEvidenceCatalogEndpoint(t *testing.T) {
	s := newTestServer(t)

	resp := do(t, s, http.MethodGet, "/api/v1/trust-center/evidence", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for trust center evidence catalog, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	if got, ok := body["count"].(float64); !ok || got == 0 {
		t.Fatalf("expected non-zero evidence count, got %#v", body["count"])
	}
	documents, ok := body["documents"].([]any)
	if !ok || len(documents) == 0 {
		t.Fatalf("expected evidence documents payload, got %#v", body["documents"])
	}
}
