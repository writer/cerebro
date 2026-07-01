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
			"last_login":     "2026-06-15T00:00:00Z",
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
	if got := event.Attributes["last_login_at"]; got != "2026-06-15T00:00:00Z" {
		t.Fatalf("last_login_at = %q, want Auth0 last_login timestamp", got)
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
			assertAuth0Query(t, r, "include_totals", "true")
			assertAuth0Query(t, r, "page", "0")
			assertAuth0Query(t, r, "per_page", "50")
			_ = json.NewEncoder(w).Encode(map[string]any{"start": 0, "limit": 50, "total": 1, "roles": []map[string]any{{
				"id":          "role-1",
				"name":        "Security Administrators",
				"description": "Manage identity security settings",
			}}})
		case "/logs":
			assertAuth0Query(t, r, "take", "50")
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
		case "/clients":
			assertAuth0Query(t, r, "include_totals", "true")
			assertAuth0Query(t, r, "page", "0")
			assertAuth0Query(t, r, "per_page", "50")
			_ = json.NewEncoder(w).Encode(map[string]any{"start": 0, "limit": 50, "total": 1, "clients": []map[string]any{{
				"client_id":      "client-1",
				"name":           "Workforce Portal",
				"app_type":       "regular_web",
				"grant_types":    []string{"authorization_code", "refresh_token"},
				"is_first_party": true,
			}}})
		case "/connections":
			assertAuth0Query(t, r, "take", "50")
			_ = json.NewEncoder(w).Encode(map[string]any{"connections": []map[string]any{{
				"id":              "conn-1",
				"name":            "Username-Password-Authentication",
				"strategy":        "auth0",
				"enabled_clients": []string{"client-1"},
			}}})
		case "/organizations":
			assertAuth0Query(t, r, "take", "50")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id":           "org_1",
				"name":         "acme",
				"display_name": "Acme",
			}}})
		case "/organizations/org_1/members":
			assertAuth0Query(t, r, "take", "50")
			_ = json.NewEncoder(w).Encode(map[string]any{"members": []map[string]any{{
				"user_id": "user-1",
				"email":   "user@example.test",
				"name":    "User One",
			}}})
		case "/roles/role-1/users":
			assertAuth0Query(t, r, "take", "50")
			_ = json.NewEncoder(w).Encode(map[string]any{"users": []map[string]any{{
				"user_id": "user-1",
				"email":   "user@example.test",
				"name":    "User One",
			}}})
		case "/organizations/org_1/members/user-1/roles":
			assertAuth0Query(t, r, "include_totals", "true")
			assertAuth0Query(t, r, "page", "0")
			assertAuth0Query(t, r, "per_page", "50")
			_ = json.NewEncoder(w).Encode(map[string]any{"start": 0, "limit": 50, "total": 1, "roles": []map[string]any{{
				"id":          "role-1",
				"name":        "Member Administrator",
				"description": "Manage organization members",
			}}})
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	for _, tt := range []struct {
		name       string
		family     string
		config     map[string]string
		wantAttrs  map[string]string
		wantSchema string
	}{
		{
			name:   "roles",
			family: familyRoles,
			wantAttrs: map[string]string{
				"external_id":   "role-1",
				"group_id":      "role-1",
				"record_class":  "identity_group",
				"role_id":       "role-1",
				"role_name":     "Security Administrators",
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
		{
			name:   "clients",
			family: familyClients,
			wantAttrs: map[string]string{
				"app_id":        "client-1",
				"app_name":      "Workforce Portal",
				"app_type":      "regular_web",
				"client_id":     "client-1",
				"resource_id":   "client-1",
				"resource_type": "application",
				"resource_urn":  "urn:cerebro:tenant:runtime_applications:client-1",
			},
			wantSchema: "auth0/clients/v1",
		},
		{
			name:   "connections",
			family: familyConnections,
			wantAttrs: map[string]string{
				"connection_id":   "conn-1",
				"connection_name": "Username-Password-Authentication",
				"enabled_clients": "client-1",
				"resource_id":     "conn-1",
				"resource_type":   "connection",
				"resource_urn":    "urn:cerebro:tenant:auth0_connections:conn-1",
				"strategy":        "auth0",
			},
			wantSchema: "auth0/connections/v1",
		},
		{
			name:   "organizations",
			family: familyOrganizations,
			wantAttrs: map[string]string{
				"display_name":      "Acme",
				"organization_id":   "org_1",
				"organization_name": "acme",
				"resource_id":       "org_1",
				"resource_type":     "organization",
				"resource_urn":      "urn:cerebro:tenant:auth0_organizations:org_1",
			},
			wantSchema: "auth0/organizations/v1",
		},
		{
			name:   "organization_members",
			family: familyOrganizationMembers,
			config: map[string]string{"organization_ids": "org_1"},
			wantAttrs: map[string]string{
				"member_type":     "user",
				"organization_id": "org_1",
				"resource_id":     "user-1",
				"resource_type":   "organization_member",
				"resource_urn":    "urn:cerebro:tenant:auth0_users:user-1",
				"subject_id":      "user-1",
				"subject_type":    "user",
				"user_id":         "user-1",
			},
			wantSchema: "auth0/organization_members/v1",
		},
		{
			name:   "role_users",
			family: familyRoleUsers,
			config: map[string]string{"role_ids": "role-1"},
			wantAttrs: map[string]string{
				"resource_id":   "user-1",
				"resource_type": "role_assignment",
				"resource_urn":  "urn:cerebro:tenant:auth0_users:user-1",
				"role_id":       "role-1",
				"subject_id":    "user-1",
				"subject_type":  "user",
				"user_id":       "user-1",
			},
			wantSchema: "auth0/role_users/v1",
		},
		{
			name:   "organization_member_roles",
			family: familyOrganizationMemberRoles,
			config: map[string]string{"organization_ids": "org_1", "user_ids": "user-1"},
			wantAttrs: map[string]string{
				"organization_id": "org_1",
				"resource_id":     "role-1",
				"resource_type":   "organization_role_assignment",
				"resource_urn":    "urn:cerebro:tenant:runtime_roles:role-1",
				"role_id":         "role-1",
				"role_name":       "Member Administrator",
				"subject_id":      "user-1",
				"subject_type":    "user",
				"user_id":         "user-1",
			},
			wantSchema: "auth0/organization_member_roles/v1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := map[string]string{
				"tenant_id":     "tenant",
				"base_url":      server.URL,
				"family":        tt.family,
				"token_url":     server.URL + "/oauth/token",
				"client_id":     "client-id",
				"client_secret": "client-secret",
				"domain":        "tenant.auth0.com",
				"per_page":      "50",
			}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
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

func TestReadOrganizationMemberRolesFansOutOrganizationsAndUsers(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 600})
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		roleID := ""
		switch r.URL.Path {
		case "/organizations/org_1/members/user-1/roles":
			roleID = "role-1"
		case "/organizations/org_2/members/user-1/roles":
			roleID = "role-2"
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"start": 0, "limit": 50, "total": 1, "roles": []map[string]any{{
			"id":   roleID,
			"name": "Member Administrator",
		}}})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":        "tenant",
		"base_url":         server.URL,
		"family":           familyOrganizationMemberRoles,
		"token_url":        server.URL + "/oauth/token",
		"client_id":        "client-id",
		"client_secret":    "client-secret",
		"domain":           "tenant.auth0.com",
		"organization_ids": "org_1,org_2",
		"user_ids":         "user-1",
		"per_page":         "50",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 || first.Events[0].Attributes["organization_id"] != "org_1" || first.Events[0].Attributes["role_id"] != "role-1" {
		t.Fatalf("first event attributes = %#v", first.Events)
	}
	if first.NextCursor == nil {
		t.Fatal("first NextCursor is nil, want next organization scope")
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 || second.Events[0].Attributes["organization_id"] != "org_2" || second.Events[0].Attributes["role_id"] != "role-2" {
		t.Fatalf("second event attributes = %#v", second.Events)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(paths) != 2 || paths[0] != "/organizations/org_1/members/user-1/roles" || paths[1] != "/organizations/org_2/members/user-1/roles" {
		t.Fatalf("paths = %#v", paths)
	}
}

func assertAuth0Query(t *testing.T, r *http.Request, key string, want string) {
	t.Helper()
	if got := r.URL.Query().Get(key); got != want {
		t.Fatalf("%s query = %q, want %q for %s", key, got, want, r.URL.Path)
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
	for _, family := range familyNames() {
		config := map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		}
		switch family {
		case familyOrganizationMembers:
			config["organization_ids"] = "org_1"
		case familyRoleUsers:
			config["role_ids"] = "role-1"
		case familyOrganizationMemberRoles:
			config["organization_ids"] = "org_1"
			config["user_ids"] = "user-1"
		}
		familyConfigs[family] = sourcecdk.NewConfig(config)
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
		{family: familyClients, kind: "auth0.clients", wantResourceURN: "urn:cerebro:tenant:runtime_applications:client-1"},
		{family: familyConnections, kind: "auth0.connections", wantResourceURN: "urn:cerebro:tenant:auth0_connections:conn-1"},
		{family: familyOrganizations, kind: "auth0.organizations", wantResourceURN: "urn:cerebro:tenant:auth0_organizations:org_1"},
		{family: familyOrganizationMembers, kind: "auth0.organization_members", wantResourceURN: "urn:cerebro:tenant:auth0_users:user-1"},
		{family: familyRoleUsers, kind: "auth0.role_users", wantResourceURN: "urn:cerebro:tenant:auth0_users:user-1"},
		{family: familyOrganizationMemberRoles, kind: "auth0.organization_member_roles", wantResourceURN: "urn:cerebro:tenant:runtime_roles:role-1"},
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
