package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/ports"
)

func TestHandleAgentPlatformGraphReason(t *testing.T) {
	graphStore := &stubGraphStore{
		cypherRows: [][]ports.CypherRow{{
			{Values: map[string]any{
				"entity_urn":  "urn:cerebro:writer:asset:alpha",
				"entity_type": "asset",
				"label":       "alpha",
			}},
		}},
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:asset:alpha", EntityType: "asset", Label: "alpha"},
		},
	}
	llm := &graphagent.StubLLMClient{
		DraftResponse: &graphagent.DraftResponse{
			Rationale: "Reasoning over scoped graph rows.",
			Cypher: `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS entity_urn, e.entity_type AS entity_type, e.label AS label
LIMIT 25`,
		},
		Summary: "Review `urn:cerebro:writer:asset:alpha` first.",
	}
	app := New(graphReasoningAuthConfig(), Dependencies{GraphStore: graphStore, GraphAgentLLM: llm}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp := postAgentGraphReason(t, server, `{"question":"Which scoped asset should I review?","scope_urn":"urn:cerebro:writer:asset:alpha"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("content-type = %q, want application/json", got)
	}
	var response graphagent.ReasonResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("decode graph reason response: %v", err)
	}
	if response.TraceID == "" || response.QueryPlan == nil || response.Cypher == nil {
		t.Fatalf("response missing trace/query/cypher: %#v", response)
	}
	if response.TenantID != "writer" {
		t.Fatalf("tenant_id = %q, want authenticated tenant writer", response.TenantID)
	}
	if len(response.Rows) != 1 || response.Rows[0]["entity_urn"] != "urn:cerebro:writer:asset:alpha" {
		t.Fatalf("rows = %#v", response.Rows)
	}
	if response.Provenance.Surface != "graph-reasoning" || response.Provenance.CitationStatus != "valid" {
		t.Fatalf("provenance = %#v, want valid graph reasoning provenance", response.Provenance)
	}
	if response.Preflight == nil || !response.Preflight.Enabled {
		t.Fatalf("preflight = %#v, want enabled graph reasoning preflight", response.Preflight)
	}
	if response.Preflight.TenantID != "writer" || len(response.Provenance.PolicyChecks) == 0 {
		t.Fatalf("preflight/provenance = preflight:%#v provenance:%#v", response.Preflight, response.Provenance)
	}
}

func TestHandleAgentPlatformGraphReasonRejectsTenantOverride(t *testing.T) {
	app := New(graphReasoningAuthConfig(), Dependencies{
		GraphStore:    &stubGraphStore{},
		GraphAgentLLM: graphagent.NewStubLLMClient(),
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp := postAgentGraphReason(t, server, `{"tenant_id":"other","question":"hello"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestHandleAgentPlatformGraphReasonMissingTenantWithoutAuthIsBadRequest(t *testing.T) {
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
	}, Dependencies{
		GraphStore:    &stubGraphStore{},
		GraphAgentLLM: graphagent.NewStubLLMClient(),
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Post(
		server.URL+"/api/v1/agent-platform/graph/reason",
		"application/json",
		strings.NewReader(`{"question":"hello"}`),
	)
	if err != nil {
		t.Fatalf("POST graph reason error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestHandleAgentPlatformGraphReasonRequiresLLM(t *testing.T) {
	app := New(graphReasoningAuthConfig(), Dependencies{GraphStore: &stubGraphStore{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp := postAgentGraphReason(t, server, `{"question":"hello"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestClearLongRunningWriteDeadline(t *testing.T) {
	recorder := &writeDeadlineRecorder{header: http.Header{}}
	clearLongRunningWriteDeadline(recorder)
	if !recorder.deadlineSet {
		t.Fatal("write deadline was not cleared")
	}
	if !recorder.deadline.IsZero() {
		t.Fatalf("deadline = %v, want zero time", recorder.deadline)
	}
}

type writeDeadlineRecorder struct {
	header      http.Header
	deadline    time.Time
	deadlineSet bool
}

func (r *writeDeadlineRecorder) Header() http.Header {
	return r.header
}

func (r *writeDeadlineRecorder) Write(data []byte) (int, error) {
	return len(data), nil
}

func (r *writeDeadlineRecorder) WriteHeader(int) {}

func (r *writeDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	r.deadline = deadline
	r.deadlineSet = true
	return nil
}

func graphReasoningAuthConfig() config.Config {
	return config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "test-key",
				Principal: "tester",
				TenantID:  "writer",
			}},
		},
	}
}

func postAgentGraphReason(t *testing.T, server *httptest.Server, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/agent-platform/graph/reason", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST graph reason error = %v", err)
	}
	return resp
}
