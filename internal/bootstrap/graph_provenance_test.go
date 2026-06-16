package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/graphprovenance"
	"github.com/writer/cerebro/internal/ports"
)

func TestHandleGetGraphProvenance(t *testing.T) {
	graphStore := &stubGraphStore{cypherRows: [][]ports.CypherRow{{
		{Values: map[string]any{
			"urn":             "urn:cerebro:writer:asset:alpha",
			"tenant_id":       "writer",
			"entity_type":     "asset",
			"label":           "alpha",
			"source_id":       "okta",
			"runtime_id":      "runtime-1",
			"attributes_json": `{"event_id":"evt-1","observed_at":"2026-06-15T12:00:00Z","projection_class":"durable_state","projection_reason":"projected_current_state"}`,
		}},
	}}}
	app := New(graphReasoningAuthConfig(), Dependencies{GraphStore: graphStore}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/provenance?urn=urn:cerebro:writer:asset:alpha", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET graph provenance: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var response graphprovenance.Response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.ProjectionClass != "durable_state" || response.ProjectionReason != "projected_current_state" {
		t.Fatalf("projection metadata = class:%q reason:%q", response.ProjectionClass, response.ProjectionReason)
	}
	if response.Provenance.Surface != "graph-provenance" || response.Provenance.CitationStatus != "valid" {
		t.Fatalf("provenance = %#v", response.Provenance)
	}
	if len(response.Provenance.FreshnessSignals) != 1 {
		t.Fatalf("freshness signals = %#v", response.Provenance.FreshnessSignals)
	}
	if got := graphStore.cypherRequests[0].Params["tenant_id"]; got != "writer" {
		t.Fatalf("tenant param = %v, want writer", got)
	}
}

func TestHandleGetGraphProvenanceRejectsOtherTenantURN(t *testing.T) {
	app := New(graphReasoningAuthConfig(), Dependencies{GraphStore: &stubGraphStore{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/provenance?urn=urn:cerebro:other:asset:alpha", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET graph provenance: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}
