package alteryx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndReadFamilies(t *testing.T) {
	tests := []struct {
		family string
		path   string
		kind   string
		body   any
	}{
		{family: familyUsers, path: "/webapi/v3/users", kind: "alteryx.users", body: []map[string]any{{"id": "user-1", "email": "user@example.com", "firstName": "User", "lastName": "One", "isActive": true}}},
		{family: familyUserGroups, path: "/webapi/v3/usergroups", kind: "alteryx.usergroups", body: []map[string]any{{"id": "group-1", "name": "Curators", "role": "Curator"}}},
		{family: familyWorkflows, path: "/webapi/v3/workflows", kind: "alteryx.workflows", body: []map[string]any{{"id": "workflow-1", "name": "Daily Evidence", "ownerId": "user-1", "executionMode": "Safe"}}},
		{family: familyCollections, path: "/webapi/v3/collections", kind: "alteryx.collections", body: []map[string]any{{"id": "collection-1", "name": "Security", "ownerId": "user-1"}}},
		{family: familyAuditEvents, path: "/webapi/admin/v1/auditlog", kind: "alteryx.audit_events", body: []map[string]any{{"id": "audit-1", "entity": "User", "entityId": "user-1", "userId": "admin-1", "timestamp": "2026-06-01T00:00:00Z", "event": "Update"}}},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			var sawHealth bool
			healthPath := "/webapi" + defaultHealthPath
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
				}
				if r.URL.Path == healthPath {
					sawHealth = true
					_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "health-user"}})
					return
				}
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
				}
				if tt.family == familyAuditEvents && r.URL.Query().Get("entity") != "User" {
					t.Fatalf("audit entity query = %q", r.URL.RawQuery)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.body)
			}))
			defer server.Close()

			cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": tt.family, "token": "test-token"})
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if !sawHealth {
				t.Fatal("health endpoint was not called")
			}
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("kind = %q, want %q", event.Kind, tt.kind)
			}
			if strings.TrimSpace(event.Id) == "" {
				t.Fatalf("event id is empty: %#v", event)
			}
		})
	}
}

func TestRuntimeConfigPreservesExistingWebAPISuffix(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": "https://server.example/webapi/", "family": familyUsers, "token": "test-token"})
	runtimeCfg, err := source.runtimeConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("runtimeConfig() error = %v", err)
	}
	if got, want := sourcecdk.ConfigValue(runtimeCfg, "base_url"), "https://server.example/webapi"; got != want {
		t.Fatalf("base_url = %q, want %q", got, want)
	}
}
