package apache

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	responses := map[string]any{
		"/eventLogs": map[string]any{"event_logs": []map[string]any{{
			"event_log_id": 123,
			"when":         "2026-06-01T00:00:00Z",
			"dag_id":       "example_dag",
			"task_id":      "load_task",
			"run_id":       "manual__2026-06-01T00:00:00Z",
			"map_index":    -1,
			"try_number":   1,
			"event":        "trigger",
			"owner":        "alice",
			"extra":        "manual trigger",
		}}},
		"/roles": map[string]any{"roles": []map[string]any{{
			"name":    "Admin",
			"actions": []map[string]any{{"action": map[string]any{"name": "can_read"}, "resource": map[string]any{"name": "DAGs"}}},
		}}},
		"/users": map[string]any{"users": []map[string]any{{
			"email":      "alice@example.com",
			"first_name": "Alice",
			"last_name":  "Admin",
			"username":   "alice",
			"active":     true,
			"roles":      []map[string]string{{"name": "Admin"}},
		}}},
		"/permissions": map[string]any{"actions": []map[string]any{{
			"name": "can_read",
		}}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
		if r.Header.Get("Authorization") != wantAuth {
			t.Fatalf("Authorization = %q, want %q", r.Header.Get("Authorization"), wantAuth)
		}
		response, ok := responses[r.URL.Path]
		if !ok {
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tests := []struct {
		family              string
		kind                string
		requiredAttributes  []string
		requiredPayloadKeys []string
	}{
		{family: familyEventlog, kind: "apache.eventlog", requiredAttributes: []string{"source_event_id", "event_type", "actor_id", "observed_at"}, requiredPayloadKeys: []string{"event_log_id", "when", "event", "owner"}},
		{family: familyRole, kind: "apache.role", requiredAttributes: []string{"source_event_id", "group_id"}, requiredPayloadKeys: []string{"name", "actions"}},
		{family: familyUser, kind: "apache.user", requiredAttributes: []string{"source_event_id", "user_id", "email"}, requiredPayloadKeys: []string{"username", "email"}},
		{family: familyPermission, kind: "apache.permission", requiredAttributes: []string{"source_event_id", "resource_type", "resource_id"}, requiredPayloadKeys: []string{"name"}},
	}
	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": tt.family, "username": "alice", "password": "secret"}
			cfg := sourcecdk.NewConfig(cfgValues)
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
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
			if event.TenantId != "tenant" {
				t.Fatalf("tenant_id = %q, want tenant", event.TenantId)
			}
			assertRequiredAttributes(t, event.Attributes, tt.requiredAttributes)
			var payload map[string]any
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			assertRequiredPayloadFields(t, payload, tt.requiredPayloadKeys)
			if tt.family == familyEventlog {
				for _, generatedKey := range []string{"event_id", "event_type", "actor_id"} {
					if _, ok := payload[generatedKey]; ok {
						t.Fatalf("eventlog payload contains generated key %q: %#v", generatedKey, payload)
					}
				}
				if event.Attributes["source_event_id"] != "123" {
					t.Fatalf("source_event_id = %q, want real event_log_id", event.Attributes["source_event_id"])
				}
				if event.Attributes["event_type"] != "trigger" {
					t.Fatalf("event_type = %q, want real event field", event.Attributes["event_type"])
				}
				if event.Attributes["actor_id"] != "alice" {
					t.Fatalf("actor_id = %q, want real owner field", event.Attributes["actor_id"])
				}
			}
		})
	}
}

func TestFixtureRequiredAttributes(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	catalogBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog(catalogBytes)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	for _, contract := range catalog.EventContracts {
		family, ok := strings.CutPrefix(contract.Kind, "apache.")
		if !ok {
			t.Fatalf("unexpected contract kind %q", contract.Kind)
		}
		t.Run(family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "family": family}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			assertRequiredAttributes(t, event.Attributes, contract.RequiredAttributes)
			var payload map[string]any
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			assertRequiredPayloadFields(t, payload, contract.RequiredPayloadFields)
			if family == familyEventlog {
				for _, field := range []string{"event_log_id", "when", "event", "owner"} {
					if _, ok := payload[field]; !ok {
						t.Fatalf("eventlog fixture payload missing real Airflow field %q: %#v", field, payload)
					}
				}
			}
		})
	}
}

func assertRequiredAttributes(t *testing.T, attributes map[string]string, required []string) {
	t.Helper()
	for _, key := range required {
		if strings.TrimSpace(attributes[key]) == "" {
			t.Fatalf("missing required attribute %q in %#v", key, attributes)
		}
	}
}

func assertRequiredPayloadFields(t *testing.T, payload map[string]any, required []string) {
	t.Helper()
	for _, key := range required {
		if !payloadHasPath(payload, key) {
			t.Fatalf("missing required payload field %q in %#v", key, payload)
		}
	}
}

func payloadHasPath(payload any, selector string) bool {
	parts := strings.Split(selector, ".")
	current := payload
	for _, part := range parts {
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = object[part]
		if !ok {
			return false
		}
	}
	if values, ok := current.([]any); ok {
		return len(values) > 0
	}
	if value, ok := current.(string); ok {
		return strings.TrimSpace(value) != ""
	}
	return current != nil
}
