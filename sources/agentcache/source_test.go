package agentcache

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
	if source.Spec().Id != "agentcache" {
		t.Fatalf("Spec().Id = %q, want agentcache", source.Spec().Id)
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
					"ref_type":         "agentcache.manifest.v2",
					"uri":              "agentcache://cases/123/evidence/triage.tar",
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
						"case_id":      "123",
						"evidence_id":  "evidence-456",
						"resource_urn": "urn:cerebro:writer:case:123",
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
	if event.Kind != "agentcache.object" {
		t.Fatalf("Kind = %q, want agentcache.object", event.Kind)
	}
	if event.SchemaRef != "agentcache/object/v1" {
		t.Fatalf("SchemaRef = %q, want agentcache/object/v1", event.SchemaRef)
	}
	if event.Attributes["evidence_id"] != "evidence-456" {
		t.Fatalf("evidence_id = %q, want evidence-456", event.Attributes["evidence_id"])
	}
	if event.Attributes["agentcache_uri"] != "agentcache://cases/123/evidence/triage.tar" {
		t.Fatalf("agentcache_uri = %q", event.Attributes["agentcache_uri"])
	}
	if event.Attributes["evidence_type"] != "agentcache.artifact" {
		t.Fatalf("evidence_type = %q, want agentcache.artifact", event.Attributes["evidence_type"])
	}
}
