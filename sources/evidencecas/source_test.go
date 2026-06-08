package evidencecas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceSpec(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "evidence_cas" {
		t.Fatalf("Spec().Id = %q, want evidence_cas", source.Spec().Id)
	}
}

func TestReadObjectRefs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/b/cases/refs" {
			t.Fatalf("request path = %q, want /v1/b/cases/refs", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer cache-token" {
			t.Fatalf("Authorization = %q, want Bearer cache-token", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"objects": []map[string]any{
				{
					"ref_type":         "evidencecas.manifest.v2",
					"uri":              "evidencecas://cases/123/evidence/triage.tar",
					"key":              "123/evidence/triage.tar",
					"digest":           "sha256abc",
					"size":             42,
					"content_type":     "application/x-tar",
					"manifest_version": 2,
					"merkle_root":      "root",
					"commit_id":        "commit",
					"blocks_count":     3,
					"updated_at":       "2026-06-06T00:00:00Z",
					"metadata": map[string]any{
						"case_id":              "123",
						"evidence_id":          "evidence-456",
						"filename":             "triage.tar",
						"resource_entity_type": "case",
						"resource_type":        "case",
						"resource_urn":         "urn:cerebro:writer:case:123",
						"source_system":        "iris",
					},
				},
			},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "cache-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "evidence_cas.object" {
		t.Fatalf("Kind = %q, want evidence_cas.object", event.Kind)
	}
	if event.SchemaRef != "evidence_cas/object/v1" {
		t.Fatalf("SchemaRef = %q, want evidence_cas/object/v1", event.SchemaRef)
	}
	if event.Attributes["evidence_id"] != "evidence-456" {
		t.Fatalf("evidence_id = %q, want evidence-456", event.Attributes["evidence_id"])
	}
	if event.Attributes["evidence_cas_uri"] != "evidencecas://cases/123/evidence/triage.tar" {
		t.Fatalf("evidence_cas_uri = %q", event.Attributes["evidence_cas_uri"])
	}
	if event.Attributes["evidence_type"] != "evidence_cas.artifact" {
		t.Fatalf("evidence_type = %q, want evidence_cas.artifact", event.Attributes["evidence_type"])
	}
	if event.Attributes["resource_entity_type"] != "case" {
		t.Fatalf("resource_entity_type = %q, want case", event.Attributes["resource_entity_type"])
	}
	if event.Attributes["resource_name"] != "triage.tar" {
		t.Fatalf("resource_name = %q, want triage.tar", event.Attributes["resource_name"])
	}
	if event.Attributes["source_system"] != "iris" {
		t.Fatalf("source_system = %q, want iris", event.Attributes["source_system"])
	}
}

func TestReadObjectRefsWithBucketAndFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/b/trusted-endpoint/refs" {
			t.Fatalf("request path = %q, want /v1/b/trusted-endpoint/refs", r.URL.Path)
		}
		if got := r.URL.Query().Get("prefix"); got != "agents/" {
			t.Fatalf("prefix query = %q, want agents/", got)
		}
		if got := r.URL.Query().Get("tag"); got != "endpoint" {
			t.Fatalf("tag query = %q, want endpoint", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"objects": []map[string]any{{
			"ref_type":         "evidencecas.manifest.v2",
			"uri":              "evidencecas://trusted-endpoint/agents/agent-1.json",
			"digest":           "sha256agent",
			"size":             42,
			"content_type":     "application/json",
			"manifest_version": 2,
			"blocks_count":     1,
			"updated_at":       "2026-06-06T00:00:00Z",
			"metadata": map[string]any{
				"evidence_id":  "agent-1",
				"resource_urn": "urn:cerebro:writer:endpoint:agent-1",
			},
		}}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "cache-token",
		"bucket":    "trusted-endpoint",
		"prefix":    "agents/",
		"tag":       "endpoint",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if pull.Events[0].Attributes["evidence_id"] != "agent-1" {
		t.Fatalf("evidence_id = %q, want agent-1", pull.Events[0].Attributes["evidence_id"])
	}
}

func TestCheckValidatesControlRoutes(t *testing.T) {
	paths := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths[r.URL.Path]++
		switch r.URL.Path {
		case "/readyz":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case "/v1/contract":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"service":                "evidence-cas",
				"route_contract_version": 1,
			})
		case "/v1/b/cases/refs":
			_ = json.NewEncoder(w).Encode(map[string]any{"objects": []map[string]any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "cache-token",
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	for _, path := range []string{"/readyz", "/v1/contract", "/v1/b/cases/refs"} {
		if paths[path] != 1 {
			t.Fatalf("%s request count = %d, want 1", path, paths[path])
		}
	}
}

func TestRejectsUnsafeBucket(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  "http://127.0.0.1",
		"token":     "cache-token",
		"bucket":    "../cases",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want invalid bucket error")
	}
}
