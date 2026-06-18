package evidencecas

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func TestReadObjectRefsPreservesCanonicalCorrelationAndLegacyMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"objects": []map[string]any{
				{
					"ref_type":         "evidencecas.manifest.v2",
					"uri":              "evidencecas://cases/case-123/evidence/evidence-456",
					"digest":           "sha256canonical",
					"manifest_version": 2,
					"merkle_root":      "merkle-root",
					"commit_id":        "commit-123",
					"updated_at":       "2026-06-06T00:05:00Z",
					"metadata": map[string]any{
						"tenant_id":                   "tenant-123",
						"source_system":               "iris",
						"source_runtime_id":           "iris-evidencecas-runtime",
						"source_event_id":             "iris-event-123",
						"case_id":                     "case-123",
						"evidence_id":                 "evidence-456",
						"resource_urn":                "urn:cerebro:tenant-123:case:case-123",
						"resource_link_status":        "missing",
						"case_link_status":            "missing",
						"unresolved_resource_context": "true",
						"unresolved_case_context":     "true",
						"request_id":                  "request-123",
						"trace_id":                    "trace-123",
						"traceparent":                 "00-00000000000000000000000000000123-0000000000000123-01",
						"occurred_at":                 "2026-06-06T00:00:00Z",
						"observed_at":                 "2026-06-06T00:03:00Z",
						"legacy_case_key":             "legacy-case-123",
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
		"tenant_id": "tenant-123",
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
	for key, want := range map[string]string{
		"tenant_id":                   "tenant-123",
		"source_system":               "iris",
		"source_runtime_id":           "iris-evidencecas-runtime",
		"source_event_id":             "iris-event-123",
		"case_id":                     "case-123",
		"evidence_id":                 "evidence-456",
		"resource_urn":                "urn:cerebro:tenant-123:case:case-123",
		"evidence_cas_uri":            "evidencecas://cases/case-123/evidence/evidence-456",
		"evidence_cas_digest":         "sha256canonical",
		"evidence_cas_merkle_root":    "merkle-root",
		"evidence_cas_commit_id":      "commit-123",
		"evidence_cas_ref_type":       "evidencecas.manifest.v2",
		"resource_link_status":        "missing",
		"case_link_status":            "missing",
		"unresolved_resource_context": "true",
		"unresolved_case_context":     "true",
		"request_id":                  "request-123",
		"trace_id":                    "trace-123",
		"traceparent":                 "00-00000000000000000000000000000123-0000000000000123-01",
		"occurred_at":                 "2026-06-06T00:00:00Z",
		"observed_at":                 "2026-06-06T00:03:00Z",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
	if got := event.GetOccurredAt().AsTime().UTC().Format("2006-01-02T15:04:05Z"); got != "2026-06-06T00:00:00Z" {
		t.Fatalf("OccurredAt = %q, want source occurred_at", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		t.Fatalf("payload JSON invalid: %v", err)
	}
	metadata, ok := payload["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("payload metadata = %#v, want object", payload["metadata"])
	}
	if got := metadata["legacy_case_key"]; got != "legacy-case-123" {
		t.Fatalf("legacy metadata = %#v, want preserved legacy_case_key", got)
	}
}

func TestReadObjectRefsEmitsCanonicalCaseURNCorrelation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"objects": []map[string]any{
				{
					"ref_type":         "evidencecas.manifest.v2",
					"uri":              "evidencecas://cases/case-789/evidence/evidence-789",
					"digest":           "sha256case",
					"manifest_version": 2,
					"updated_at":       "2026-06-06T00:00:00Z",
					"metadata": map[string]any{
						"tenant_id":        "tenant-789",
						"source_system":    "iris",
						"source_event_id":  "iris-event-789",
						"evidence_id":      "evidence-789",
						"case_id":          "case-789",
						"case_urn":         "urn:cerebro:tenant-789:case:case-789",
						"case_link_status": "linked",
						"resource_urn":     "urn:cerebro:tenant-789:case:case-789",
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
		"tenant_id": "tenant-789",
		"base_url":  server.URL,
		"token":     "cache-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["case_urn"]; got != "urn:cerebro:tenant-789:case:case-789" {
		t.Fatalf("case_urn = %q, want urn:cerebro:tenant-789:case:case-789", got)
	}
}

func TestSourceCatalogRequiresSourceSystem(t *testing.T) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		t.Fatalf("read catalog.yaml error = %v", err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog(specBytes)
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:         "evidence-cas-missing-source-system",
		TenantId:   "tenant-123",
		SourceId:   "evidence_cas",
		Kind:       "evidence_cas.object",
		SchemaRef:  "evidence_cas/object/v1",
		OccurredAt: timestamppb.Now(),
		Payload:    []byte(`{"uri":"evidencecas://cases/case-123/evidence/evidence-456","digest":"sha256canonical","manifest_version":2}`),
		Attributes: map[string]string{
			"tenant_id":             "tenant-123",
			"source_event_id":       "iris-event-123",
			"evidence_id":           "evidence-456",
			"evidence_type":         "evidence_cas.artifact",
			"resource_urn":          "urn:cerebro:tenant-123:case:case-123",
			"evidence_cas_uri":      "evidencecas://cases/case-123/evidence/evidence-456",
			"evidence_cas_digest":   "sha256canonical",
			"evidence_cas_ref_type": "evidencecas.manifest.v2",
		},
	}
	err = sourcecdk.ValidateEventEnvelopeWithContracts(event, catalog.EventContracts)
	if !errors.Is(err, sourcecdk.ErrInvalidEventEnvelope) {
		t.Fatalf("ValidateEventEnvelopeWithContracts() error = %v, want ErrInvalidEventEnvelope", err)
	}
	if got, want := err.Error(), `missing required attribute "source_system"`; !strings.Contains(got, want) {
		t.Fatalf("validation error = %q, want %q", got, want)
	}
	event.Attributes["source_system"] = "iris"
	if err := sourcecdk.ValidateEventEnvelopeWithContracts(event, catalog.EventContracts); err != nil {
		t.Fatalf("valid EvidenceCAS event failed contract validation: %v", err)
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
