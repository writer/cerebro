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
			"event_id":   "event-1",
			"dag_id":     "example_dag",
			"event":      "trigger",
			"owner":      "alice",
			"when":       "2026-06-01T00:00:00Z",
			"extra":      "manual trigger",
			"try_number": 1,
		}}},
		"/roles": map[string]any{"roles": []map[string]any{{
			"name": "Admin",
		}}},
		"/users": map[string]any{"users": []map[string]any{{
			"email":      "alice@example.com",
			"first_name": "Alice",
			"last_name":  "Admin",
			"username":   "alice",
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
		family string
		kind   string
	}{
		{family: familyEventlog, kind: "apache.eventlog"},
		{family: familyRole, kind: "apache.role"},
		{family: familyUser, kind: "apache.user"},
		{family: familyPermission, kind: "apache.permission"},
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
		})
	}
}
