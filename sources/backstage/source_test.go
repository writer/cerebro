package backstage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		if r.URL.Path != "/api/catalog/entities" {
			t.Fatalf("request path = %q, want /api/catalog/entities", r.URL.Path)
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
}

func TestReadComponentFamilyUsesStableRecordTimestamp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
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
}
