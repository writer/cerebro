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
	"github.com/writer/cerebro/sources/internal/auth0api"
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
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": auth0api.DefaultFamily, "token_url": server.URL + "/oauth/token", "client_id": "client-id", "client_secret": "client-secret", "domain": "tenant.auth0.com"}
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
			family: auth0api.FamilyRoles,
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
			family: auth0api.FamilyAuditEvents,
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

func TestReadMapsAuth0ManagementAPIFamiliesToRuntimeAttributes(t *testing.T) {
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
		switch r.URL.EscapedPath() {
		case "/organizations":
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{"id": "org-1", "name": "writer", "display_name": "Writer"}}})
		case "/organizations/org-1/members":
			if got := r.URL.Query().Get("fields"); got != "roles" {
				t.Fatalf("organization member fields = %q, want roles", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"members": []map[string]any{{"user_id": "auth0|user-1", "email": "user@example.test", "name": "User One", "roles": []string{"role-1"}}}})
		case "/clients":
			_ = json.NewEncoder(w).Encode(map[string]any{"clients": []map[string]any{{"client_id": "client-1", "name": "Workforce Portal", "app_type": "regular_web", "callbacks": []string{"https://app.example.test/callback"}, "grant_types": []string{"authorization_code"}}}})
		case "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{"connections": []map[string]any{{"id": "conn-1", "name": "google-oauth2", "strategy": "google-oauth2", "enabled_clients": []string{"client-1"}}}})
		case "/resource-servers":
			_ = json.NewEncoder(w).Encode(map[string]any{"resource_servers": []map[string]any{{"id": "api-1", "identifier": "https://api.example.test", "name": "Example API", "scopes": []map[string]string{{"value": "read:reports", "description": "Read reports"}}}}})
		case "/client-grants":
			_ = json.NewEncoder(w).Encode(map[string]any{"client_grants": []map[string]any{{"id": "grant-1", "client_id": "client-1", "audience": "https://api.example.test", "scope": []string{"read:reports"}}}})
		case "/grants":
			_ = json.NewEncoder(w).Encode(map[string]any{"grants": []map[string]any{{"id": "user-grant-1", "user_id": "auth0|user-1", "client_id": "client-1", "audience": "https://api.example.test", "scope": []string{"read:reports"}}}})
		case "/users/auth0%7Cuser-1/roles":
			_ = json.NewEncoder(w).Encode(map[string]any{"roles": []map[string]any{{"id": "role-1", "name": "Security Administrators"}}})
		case "/users/auth0%7Cuser-1/authentication-methods":
			_ = json.NewEncoder(w).Encode(map[string]any{"authenticators": []map[string]any{{"id": "auth-method-1", "type": "webauthn-roaming", "confirmed": true}}})
		case "/guardian/factors":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"name": "sms", "enabled": true, "trial_expired": false}})
		default:
			t.Fatalf("path = %q", r.URL.EscapedPath())
		}
	}))
	defer server.Close()

	for _, tt := range []struct {
		family     string
		config     map[string]string
		wantKind   string
		wantSchema string
		wantAttrs  map[string]string
	}{
		{
			family:     auth0api.FamilyOrganizations,
			wantKind:   "auth0.organizations",
			wantSchema: "auth0/organizations/v1",
			wantAttrs:  map[string]string{"organization_id": "org-1", "resource_urn": "urn:cerebro:tenant:runtime_organizations:org-1"},
		},
		{
			family:     auth0api.FamilyOrganizationMembers,
			config:     map[string]string{"organization_ids": "org-1", "organization_member_fields": "roles"},
			wantKind:   "auth0.organization_members",
			wantSchema: "auth0/organization_members/v1",
			wantAttrs:  map[string]string{"member_user_id": "auth0|user-1", "organization_id": "org-1", "role": "role-1"},
		},
		{
			family:     auth0api.FamilyClients,
			wantKind:   "auth0.clients",
			wantSchema: "auth0/clients/v1",
			wantAttrs:  map[string]string{"app_id": "client-1", "client_id": "client-1", "resource_type": "application"},
		},
		{
			family:     auth0api.FamilyConnections,
			wantKind:   "auth0.connections",
			wantSchema: "auth0/connections/v1",
			wantAttrs:  map[string]string{"connection_id": "conn-1", "enabled_clients": "client-1", "strategy": "google-oauth2"},
		},
		{
			family:     auth0api.FamilyResourceServers,
			wantKind:   "auth0.resource_servers",
			wantSchema: "auth0/resource_servers/v1",
			wantAttrs:  map[string]string{"api_id": "api-1", "api_identifier": "https://api.example.test", "resource_type": "api"},
		},
		{
			family:     auth0api.FamilyClientGrants,
			wantKind:   "auth0.client_grants",
			wantSchema: "auth0/client_grants/v1",
			wantAttrs:  map[string]string{"client_grant_id": "grant-1", "client_id": "client-1", "scope": "read:reports"},
		},
		{
			family:     auth0api.FamilyGrants,
			wantKind:   "auth0.grants",
			wantSchema: "auth0/grants/v1",
			wantAttrs:  map[string]string{"grant_id": "user-grant-1", "subject_id": "auth0|user-1", "scope": "read:reports"},
		},
		{
			family:     auth0api.FamilyUserRoles,
			config:     map[string]string{"user_ids": "auth0|user-1"},
			wantKind:   "auth0.user_roles",
			wantSchema: "auth0/user_roles/v1",
			wantAttrs:  map[string]string{"group_id": "role-1", "member_user_id": "auth0|user-1"},
		},
		{
			family:     auth0api.FamilyUserAuthenticationMethods,
			config:     map[string]string{"user_ids": "auth0|user-1"},
			wantKind:   "auth0.user_authentication_methods",
			wantSchema: "auth0/user_authentication_methods/v1",
			wantAttrs:  map[string]string{"credential_id": "auth-method-1", "user_id": "auth0|user-1"},
		},
		{
			family:     auth0api.FamilyGuardianFactors,
			wantKind:   "auth0.guardian_factors",
			wantSchema: "auth0/guardian_factors/v1",
			wantAttrs:  map[string]string{"credential_id": "sms", "enabled": "true"},
		},
	} {
		t.Run(tt.family, func(t *testing.T) {
			cfgValues := map[string]string{
				"tenant_id":     "tenant",
				"base_url":      server.URL,
				"family":        tt.family,
				"token_url":     server.URL + "/oauth/token",
				"client_id":     "client-id",
				"client_secret": "client-secret",
				"domain":        "tenant.auth0.com",
			}
			for key, value := range tt.config {
				cfgValues[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(cfgValues), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.wantKind {
				t.Fatalf("kind = %q, want %q", event.Kind, tt.wantKind)
			}
			if event.SchemaRef != tt.wantSchema {
				t.Fatalf("schema_ref = %q, want %q", event.SchemaRef, tt.wantSchema)
			}
			for key, want := range tt.wantAttrs {
				if got := event.Attributes[key]; got != want {
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

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": auth0api.DefaultFamily, "token_url": server.URL + "/oauth/token", "client_id": "client-id", "client_secret": "client-secret", "domain": "tenant.auth0.com"})
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
	for _, family := range auth0api.FamilyNames() {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":           family,
			"organization_id":  "org-1",
			"organization_ids": "org-1",
			"tenant_id":        "tenant",
			"user_id":          "auth0|user-1",
			"user_ids":         "auth0|user-1",
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
		{family: auth0api.FamilyUsers, kind: "auth0.users", wantResourceURN: "urn:cerebro:tenant:runtime_users:auth0%7Cuser-1"},
		{family: auth0api.FamilyRoles, kind: "auth0.roles", wantResourceURN: "urn:cerebro:tenant:runtime_roles:role-1"},
		{family: auth0api.FamilyAuditEvents, kind: "auth0.audit_events", wantResourceURN: "urn:cerebro:tenant:runtime_applications:client-1"},
		{family: auth0api.FamilyOrganizations, kind: "auth0.organizations", wantResourceURN: "urn:cerebro:tenant:runtime_organizations:org-1"},
		{family: auth0api.FamilyOrganizationMembers, kind: "auth0.organization_members", wantResourceURN: "urn:cerebro:tenant:runtime_organization_members:auth0%7Cuser-1"},
		{family: auth0api.FamilyClients, kind: "auth0.clients", wantResourceURN: "urn:cerebro:tenant:runtime_applications:client-1"},
		{family: auth0api.FamilyConnections, kind: "auth0.connections", wantResourceURN: "urn:cerebro:tenant:runtime_connections:conn-1"},
		{family: auth0api.FamilyResourceServers, kind: "auth0.resource_servers", wantResourceURN: "urn:cerebro:tenant:runtime_resource_servers:api-1"},
		{family: auth0api.FamilyClientGrants, kind: "auth0.client_grants", wantResourceURN: "urn:cerebro:tenant:runtime_client_grants:grant-1"},
		{family: auth0api.FamilyGrants, kind: "auth0.grants", wantResourceURN: "urn:cerebro:tenant:runtime_grants:user-grant-1"},
		{family: auth0api.FamilyUserRoles, kind: "auth0.user_roles", wantResourceURN: "urn:cerebro:tenant:runtime_user_roles:role-1"},
		{family: auth0api.FamilyUserAuthenticationMethods, kind: "auth0.user_authentication_methods", wantResourceURN: "urn:cerebro:tenant:runtime_authentication_methods:auth-method-1"},
		{family: auth0api.FamilyGuardianFactors, kind: "auth0.guardian_factors", wantResourceURN: "urn:cerebro:tenant:runtime_guardian_factors:sms"},
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
