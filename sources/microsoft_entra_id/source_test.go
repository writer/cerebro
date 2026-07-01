package microsoft_entra_id

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
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenRequests++
			if r.Method != http.MethodPost {
				t.Fatalf("token method = %s", r.Method)
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error = %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "client_credentials" {
				t.Fatalf("grant_type = %q", got)
			}
			if got := r.Form.Get("client_id"); got != "client-id" {
				t.Fatalf("client_id = %q", got)
			}
			if got := r.Form.Get("client_secret"); got != "client-secret" {
				t.Fatalf("client_secret = %q", got)
			}
			if got := r.Form.Get("scope"); got != "https://graph.microsoft.com/.default" {
				t.Fatalf("scope = %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 600})
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() == "/v1.0/organization" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/v1.0/users" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("$top"); got == "" {
			t.Fatalf("$top query is empty")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"id": "user-1", "displayName": "Record One", "mail": "record@example.test", "userPrincipalName": "record@example.test", "accountEnabled": true, "createdDateTime": "2026-06-01T00:00:00Z"}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token_url": server.URL + "/oauth/token", "client_id": "client-id", "client_secret": "client-secret"}
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
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d, want 1 cached token", tokenRequests)
	}
	if event.Kind != "microsoft_entra_id.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if got := event.Attributes["resource_urn"]; got != "urn:cerebro:tenant:runtime_users:user-1" {
		t.Fatalf("resource_urn = %q", got)
	}
	if got := event.Attributes["account_enabled"]; got != "true" {
		t.Fatalf("account_enabled = %q", got)
	}
	if got := event.Attributes["status"]; got != "" {
		t.Fatalf("status = %q, want empty when only accountEnabled is present", got)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestSourceReadAuditEventsDoesNotInventResourceURN(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 600})
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/v1.0/auditLogs/directoryAudits" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{
			"id":                  "audit-1",
			"activityDateTime":    "2026-06-01T00:00:00Z",
			"activityDisplayName": "Add group",
			"initiatedBy": map[string]any{"user": map[string]any{
				"id":                "admin-1",
				"displayName":       "Admin One",
				"userPrincipalName": "admin@example.test",
			}},
			"targetResources": []map[string]any{{
				"id":          "group-1",
				"displayName": "Security Group",
				"type":        "Group",
			}},
		}}})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyAuditEvents, "token_url": server.URL + "/oauth/token", "client_id": "client-id", "client_secret": "client-secret"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["resource_type"]; got != "Group" {
		t.Fatalf("resource_type = %q, want Group", got)
	}
	assertNoResourceURN(t, pull.Events[0].Attributes)
}

func TestNewFixtureReplaysMicrosoftEntraIDFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyUsers, familyGroups, familyAuditEvents} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
	for _, tt := range []struct {
		family          string
		kind            string
		wantResourceURN string
	}{
		{family: familyUsers, kind: "microsoft_entra_id.users", wantResourceURN: "urn:cerebro:tenant:runtime_users:user-1"},
		{family: familyGroups, kind: "microsoft_entra_id.groups", wantResourceURN: "urn:cerebro:tenant:runtime_groups:group-1"},
		{family: familyAuditEvents, kind: "microsoft_entra_id.audit_events"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), familyConfigs[tt.family], nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("event kind = %q, want %q", got, tt.kind)
			}
			if tt.wantResourceURN == "" {
				assertNoResourceURN(t, pull.Events[0].Attributes)
				return
			}
			if got := pull.Events[0].Attributes["resource_urn"]; got != tt.wantResourceURN {
				t.Fatalf("resource_urn = %q, want %q", got, tt.wantResourceURN)
			}
		})
	}
}

func assertNoResourceURN(t *testing.T, attributes map[string]string) {
	t.Helper()
	if got := attributes["resource_urn"]; got != "" {
		t.Fatalf("resource_urn = %q, want empty because audit event target kind is not statically known", got)
	}
}
