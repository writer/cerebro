package securitytoolingmap

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
	if source.Spec().Id != "security_tooling_map" {
		t.Fatalf("Spec().Id = %q, want security_tooling_map", source.Spec().Id)
	}
	if source.Spec().Name != "Security Tooling Map" {
		t.Fatalf("Spec().Name = %q, want Security Tooling Map", source.Spec().Name)
	}
}

func TestReadToolFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tools" {
			t.Fatalf("request path = %q, want /tools", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer map-token" {
			t.Fatalf("Authorization = %q, want Bearer map-token", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tools": []map[string]any{
				{
					"id":              "agent-gateway",
					"name":            "agent-gateway",
					"org":             "WriterInternal",
					"repo":            "agent-gateway",
					"status":          "beta",
					"lifecycle_owner": "Security",
					"categories":      []string{"ai_security", "dlp"},
					"depends_on":      []string{"security"},
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
		"token":     "map-token",
		"family":    "tool",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "security_tooling_map.tool" {
		t.Fatalf("Kind = %q, want security_tooling_map.tool", event.Kind)
	}
	if event.Attributes["tool_id"] != "agent-gateway" || event.Attributes["repo"] != "agent-gateway" {
		t.Fatalf("attrs = %#v, want tool inventory attributes", event.Attributes)
	}
	if event.Attributes["categories"] != "ai_security,dlp" {
		t.Fatalf("categories = %q, want ai_security,dlp", event.Attributes["categories"])
	}
}

func TestReadControlMappingFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control-mappings" {
			t.Fatalf("request path = %q, want /control-mappings", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"control_mappings": []map[string]any{
				{
					"id":           "agent-gateway-soc2-cc6",
					"tool_id":      "agent-gateway",
					"control_id":   "SOC2-CC6",
					"control_name": "Logical access",
					"framework":    "SOC2",
					"coverage":     "partial",
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
		"token":     "map-token",
		"family":    "control_mapping",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if pull.Events[0].Kind != "security_tooling_map.control_mapping" {
		t.Fatalf("Kind = %q, want security_tooling_map.control_mapping", pull.Events[0].Kind)
	}
	if pull.Events[0].Attributes["control_id"] != "SOC2-CC6" {
		t.Fatalf("control_id = %q, want SOC2-CC6", pull.Events[0].Attributes["control_id"])
	}
}

func TestReadControlMappingFamilyKeepsIDLessRowsDistinct(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control-mappings" {
			t.Fatalf("request path = %q, want /control-mappings", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"control_mappings": []map[string]any{
				{
					"tool_id":    "agent-gateway",
					"control_id": "SOC2-CC6",
					"framework":  "SOC2",
				},
				{
					"tool_id":    "agent-gateway",
					"control_id": "SOC2-CC7",
					"framework":  "SOC2",
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
		"token":     "map-token",
		"family":    "control_mapping",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want both id-less control mappings", len(pull.Events))
	}
	if pull.Events[0].Id == pull.Events[1].Id {
		t.Fatalf("event IDs are equal %q, want stable per-record IDs", pull.Events[0].Id)
	}
	if pull.Events[0].Attributes["external_id"] == pull.Events[1].Attributes["external_id"] {
		t.Fatalf("external IDs are equal %q, want stable per-record identities", pull.Events[0].Attributes["external_id"])
	}
}
