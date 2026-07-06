package airtable

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
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() == "/v0/meta/whoami" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/v0/meta/bases" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"bases": []map[string]string{{"id": "appLkNDICXNqxSDhG", "name": "Project Tracker", "permissionLevel": "edit"}}})
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
	if event.Kind != "airtable.bases" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestSourceReadEnterpriseFamilies(t *testing.T) {
	tests := []struct {
		name      string
		family    string
		wantPath  string
		wantQuery string
		response  map[string]any
		wantKind  string
	}{
		{
			name:      "users",
			family:    familyUsers,
			wantPath:  "/v0/meta/enterpriseAccounts/entUBq2RGdihxl3vU/users",
			wantQuery: "id%5B%5D=usrL2PNC5o3H4lBEi",
			response: map[string]any{"users": []map[string]any{{
				"id": "usrL2PNC5o3H4lBEi", "email": "foo@bar.com", "name": "Foo Bar", "state": "provisioned", "isServiceAccount": false, "lastActivityTime": "2022-02-01T21:25:05.663Z",
			}}},
			wantKind: "airtable.users",
		},
		{
			name:      "audit events",
			family:    familyAuditEvents,
			wantPath:  "/v0/meta/enterpriseAccounts/entUBq2RGdihxl3vU/auditLogEvents",
			wantQuery: "pageSize=100",
			response: map[string]any{"events": []map[string]any{{
				"id": "01FYFFDE39BDDBC0HWK51R6GPF", "timestamp": "2022-02-01T21:25:05.663Z", "action": "createBase", "modelId": "appLkNDICXNqxSDhG", "modelType": "base",
				"actor":   map[string]any{"type": "user", "user": map[string]any{"id": "usrL2PNC5o3H4lBEi", "email": "foo@bar.com", "name": "Foo Bar"}},
				"context": map[string]any{"enterpriseAccountId": "entUBq2RGdihxl3vU", "baseId": "appLkNDICXNqxSDhG", "workspaceId": "wspmhESAta6clCCwF", "actionId": "actxr1mLqZz1T35FA"},
			}}},
			wantKind: "airtable.audit_events",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
				}
				if r.URL.Path != tt.wantPath {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.wantPath)
				}
				if r.URL.RawQuery != tt.wantQuery {
					t.Fatalf("query = %q, want %q", r.URL.RawQuery, tt.wantQuery)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()
			cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": tt.family, "token": "test-token", "enterprise_account_id": "entUBq2RGdihxl3vU", "user_id": "usrL2PNC5o3H4lBEi", "per_page": "100"}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(cfgValues), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if pull.Events[0].Kind != tt.wantKind {
				t.Fatalf("kind = %q, want %q", pull.Events[0].Kind, tt.wantKind)
			}
		})
	}
}
