package auth0

import (
	"context"
	"encoding/json"
	"errors"
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
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 600})
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/users" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"user_id":        "auth0|user-1",
			"name":           "User One",
			"email":          "user@example.test",
			"email_verified": true,
			"blocked":        false,
			"created_at":     "2026-05-01T00:00:00Z",
			"updated_at":     "2026-06-01T00:00:00Z",
		}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token_url": server.URL + "/oauth/token", "client_id": "client-id", "client_secret": "client-secret", "domain": "tenant.auth0.com"}
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
	if event.Kind != "auth0.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if got := event.Attributes["external_id"]; got != "auth0|user-1" {
		t.Fatalf("external_id = %q, want raw Auth0 user ID", got)
	}
	if got := event.Attributes["resource_id"]; got != "auth0|user-1" {
		t.Fatalf("resource_id = %q, want raw Auth0 user ID", got)
	}
	if got := event.Attributes["resource_type"]; got != "identity_user" {
		t.Fatalf("resource_type = %q, want identity_user", got)
	}
	if got := event.Attributes["resource_urn"]; got != "urn:cerebro:tenant:runtime_users:auth0%7Cuser-1" {
		t.Fatalf("resource_urn = %q, want encoded Auth0 user URN", got)
	}
}

func TestReadMapsAuth0RawFamiliesToRuntimeAttributes(t *testing.T) {
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
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/roles":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":          "role-1",
				"name":        "Security Administrators",
				"description": "Manage identity security settings",
			}})
		case "/logs":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"log_id":      "log-1",
				"type":        "s",
				"description": "Success Login",
				"date":        "2026-06-01T00:00:00Z",
				"user_id":     "auth0|user-1",
				"user_name":   "user@example.test",
				"client_id":   "client-1",
				"client_name": "Workforce Portal",
			}})
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	for _, tt := range []struct {
		name       string
		family     string
		wantAttrs  map[string]string
		wantSchema string
	}{
		{
			name:   "roles",
			family: familyRoles,
			wantAttrs: map[string]string{
				"external_id":   "role-1",
				"group_id":      "role-1",
				"resource_id":   "role-1",
				"resource_type": "role",
				"resource_urn":  "urn:cerebro:tenant:runtime_roles:role-1",
			},
			wantSchema: "auth0/roles/v1",
		},
		{
			name:   "audit_events",
			family: familyAuditEvents,
			wantAttrs: map[string]string{
				"external_id":     "log-1",
				"actor_id":        "auth0|user-1",
				"actor_email":     "user@example.test",
				"event_type":      "s",
				"resource_id":     "client-1",
				"resource_name":   "Workforce Portal",
				"resource_type":   "application",
				"resource_urn":    "urn:cerebro:tenant:runtime_applications:client-1",
				"source_event_id": "log-1",
			},
			wantSchema: "auth0/audit_events/v1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
				"tenant_id":     "tenant",
				"base_url":      server.URL,
				"family":        tt.family,
				"token_url":     server.URL + "/oauth/token",
				"client_id":     "client-id",
				"client_secret": "client-secret",
				"domain":        "tenant.auth0.com",
			}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].SchemaRef; got != tt.wantSchema {
				t.Fatalf("schema_ref = %q, want %q", got, tt.wantSchema)
			}
			for key, want := range tt.wantAttrs {
				if got := pull.Events[0].Attributes[key]; got != want {
					t.Fatalf("attribute %s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestReadWithCheckpointUsesIncrementalWatermark(t *testing.T) {
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
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/users" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"id": "record-1", "resource_urn": "urn:cerebro:tenant:runtime_asset:record-1", "resource_type": "asset", "resource_id": "record-1", "name": "Record One", "updated_at": "2026-06-01T00:00:00Z"}}})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token_url": server.URL + "/oauth/token", "client_id": "client-id", "client_secret": "client-secret", "domain": "tenant.auth0.com"})
	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() first error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("first events = %d, want 1", len(first.Events))
	}
	if first.Checkpoint == nil || !sourcecdk.ResumableCursorOpaque(first.Checkpoint.GetCursorOpaque()) {
		t.Fatalf("first checkpoint is not resumable: %#v", first.Checkpoint)
	}

	second, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, first.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() second error = %v", err)
	}
	if len(second.Events) != 0 {
		t.Fatalf("second events = %d, want 0", len(second.Events))
	}
	if second.ShortCircuitReason != sourcecdk.PullShortCircuitReasonWatermarkReached {
		t.Fatalf("second short circuit = %q, want %q", second.ShortCircuitReason, sourcecdk.PullShortCircuitReasonWatermarkReached)
	}
}

func TestNewFixtureReplaysAuth0Families(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyUsers, familyRoles, familyAuditEvents} {
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
		{family: familyUsers, kind: "auth0.users", wantResourceURN: "urn:cerebro:tenant:runtime_users:auth0%7Cuser-1"},
		{family: familyRoles, kind: "auth0.roles", wantResourceURN: "urn:cerebro:tenant:runtime_roles:role-1"},
		{family: familyAuditEvents, kind: "auth0.audit_events", wantResourceURN: "urn:cerebro:tenant:runtime_applications:client-1"},
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
			if got := pull.Events[0].Attributes["resource_urn"]; got != tt.wantResourceURN {
				t.Fatalf("resource_urn = %q, want %q", got, tt.wantResourceURN)
			}
		})
	}
}

func TestSourceRejectsNonAuth0Domain(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "tenant",
		"domain":        "attacker.example",
		"client_id":     "client-id",
		"client_secret": "client-secret",
	}))
	if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("Check() err = %v, want ErrInvalidConfig", err)
	}
}
