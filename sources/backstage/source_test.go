package backstage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceSpec(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "backstage" {
		t.Fatalf("Spec().Id = %q, want backstage", source.Spec().Id)
	}
	if source.Spec().Name != "Backstage" {
		t.Fatalf("Spec().Name = %q, want Backstage", source.Spec().Name)
	}
}

func TestReadComponentFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/catalog/entities/by-query" {
			t.Fatalf("request path = %q, want /api/catalog/entities/by-query", r.URL.Path)
		}
		if got := r.URL.Query().Get("filter"); got != "kind=component" {
			t.Fatalf("filter query = %q, want kind=component", got)
		}
		if got := r.URL.Query().Get("limit"); got != "100" {
			t.Fatalf("limit query = %q, want 100", got)
		}
		if got := r.URL.Query().Get("per_page"); got != "" {
			t.Fatalf("per_page query = %q, want empty", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer backstage-token" {
			t.Fatalf("Authorization = %q, want Bearer backstage-token", got)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"kind": "Component",
				"metadata": map[string]any{
					"uid":         "component-1",
					"name":        "cerebro",
					"namespace":   "default",
					"description": "Security intelligence graph",
					"annotations": map[string]any{
						"cerebro.io/criticality":         "high",
						"cerebro.io/data-classification": "restricted",
					},
				},
				"spec": map[string]any{
					"type":      "service",
					"lifecycle": "production",
					"owner":     "group:platform/security",
					"system":    "security",
				},
				"repository": "WriterInternal/cerebro",
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
		"token":     "backstage-token",
		"family":    "component",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "backstage.component" {
		t.Fatalf("Kind = %q, want backstage.component", event.Kind)
	}
	if event.Attributes["name"] != "cerebro" || event.Attributes["owner"] != "group:platform/security" {
		t.Fatalf("attrs = %#v, want Backstage component attributes", event.Attributes)
	}
	if event.Attributes["repository"] != "WriterInternal/cerebro" {
		t.Fatalf("repository = %q, want WriterInternal/cerebro", event.Attributes["repository"])
	}
	if event.Attributes["criticality"] != "high" || event.Attributes["data_class"] != "restricted" {
		t.Fatalf("annotation attrs = %#v, want Backstage annotation attributes", event.Attributes)
	}
}

func TestReadComponentFamilyEmitsOwnershipContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"kind": "Component",
				"metadata": map[string]any{
					"uid":       "component-9",
					"name":      "payments",
					"namespace": "default",
					"annotations": map[string]any{
						"cerebro.io/criticality": "tier0",
					},
				},
				"spec": map[string]any{
					"type":      "service",
					"lifecycle": "production",
					"owner":     "group:platform/payments",
					"system":    "commerce",
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
		"token":     "backstage-token",
		"family":    "component",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	for _, required := range []string{"name", "kind"} {
		if strings.TrimSpace(event.Attributes[required]) == "" {
			t.Fatalf("required attribute %q missing, attrs = %#v", required, event.Attributes)
		}
	}
	if event.Attributes["owner"] != "group:platform/payments" {
		t.Fatalf("owner = %q, want group:platform/payments", event.Attributes["owner"])
	}
	if event.Attributes["criticality"] != "tier0" {
		t.Fatalf("criticality = %q, want tier0", event.Attributes["criticality"])
	}
	if event.Attributes["system"] != "commerce" {
		t.Fatalf("system = %q, want commerce", event.Attributes["system"])
	}
}

func TestReadComponentFamilyRejectsRecordWithoutIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"kind": "Component",
				"spec": map[string]any{"type": "service"},
			},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "backstage-token",
		"family":    "component",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want rejection of component record without stable identity")
	}
}

func TestReadComponentFamilyUsesStableRecordTimestamp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{
					"kind":       "Component",
					"updated_at": "2026-05-01T12:00:00Z",
					"metadata": map[string]any{
						"uid":        "component-1",
						"name":       "cerebro",
						"etag":       "etag-value",
						"generation": 7,
					},
				},
			},
			"pageInfo": map[string]any{"nextCursor": "page-2"},
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
		"token":     "backstage-token",
		"family":    "component",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	want := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	if got := pull.Events[0].OccurredAt.AsTime(); !got.Equal(want) {
		t.Fatalf("OccurredAt = %s, want %s", got, want)
	}
	if pull.NextCursor.GetOpaque() != "page-2" {
		t.Fatalf("NextCursor = %q, want page-2", pull.NextCursor.GetOpaque())
	}
}
