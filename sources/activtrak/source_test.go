package activtrak

import (
	"context"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "test-token" {
			t.Fatalf("x-api-key = %q", r.Header.Get("x-api-key"))
		}
		if r.URL.RequestURI() == "/scim/v1/ping" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Pong"))
			return
		}
		if r.URL.Path != "/scim/v1/users" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/scim+json" {
			t.Fatalf("Content-Type = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{{"id": "user-1", "userName": "jdoe@example.test", "displayName": "John Doe", "emails": []map[string]any{{"primary": true, "value": "jdoe@example.test"}}, "active": true}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token"}
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
	if event.Kind != "activtrak.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if got := event.Attributes["email"]; got != "jdoe@example.test" {
		t.Fatalf("email attribute = %q", got)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestSourceReadFamiliesUseDocumentedPaths(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	responses := map[string]map[string]any{
		"/scim/v1/users": {
			"resources": []map[string]any{{"id": "user-1", "userName": "jdoe@example.test", "displayName": "John Doe", "active": true}},
		},
		"/scim/v1/groups": {
			"resources": []map[string]any{{"id": "group-1", "displayName": "Engineering"}},
		},
		"/admin/v1/clients": {
			"clients": []map[string]any{{"id": 10, "domain": "example", "name": "jdoe", "alias": "John Doe"}},
		},
		"/admin/v1/consumers": {
			"consumers": []map[string]any{{"id": 20, "firstName": "Jane", "lastName": "Doe", "username": "jane", "email": "jane@example.test", "ssoEnabled": true}},
		},
		"/reports/v2/activitylog": {
			"activity": []map[string]any{{"logId": 30, "time_utc": "2026-06-01T00:00:00Z", "user": "jdoe", "computerId": 40, "description": "Code Editor", "duration": 120}},
			"cursor":   "cursor-2",
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "test-token" {
			t.Fatalf("x-api-key = %q", r.Header.Get("x-api-key"))
		}
		payload, ok := responses[r.URL.Path]
		if !ok {
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer server.Close()

	for family, wantKind := range map[string]string{
		"activity_log": "activtrak.activity_log",
		"clients":      "activtrak.clients",
		"consumers":    "activtrak.consumers",
		"groups":       "activtrak.groups",
		"users":        "activtrak.users",
	} {
		t.Run(family, func(t *testing.T) {
			cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": family, "token": "test-token"})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != wantKind {
				t.Fatalf("kind = %q, want %q", got, wantKind)
			}
		})
	}
}
