package anthropic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"gopkg.in/yaml.v3"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "anthropic" {
		t.Fatalf("Spec().Id = %q, want anthropic", got)
	}
}

func TestCatalogDeclaresVerifiedAnthropicProviderAPI(t *testing.T) {
	payload, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	var catalog struct {
		RuntimeFamilies []string `yaml:"runtime_families"`
		ProviderAPI     struct {
			Status        string   `yaml:"status"`
			Basis         string   `yaml:"basis"`
			Transport     string   `yaml:"transport"`
			Auth          string   `yaml:"auth"`
			AuthMechanics string   `yaml:"auth_mechanics"`
			BaseURL       string   `yaml:"base_url"`
			SpecURL       string   `yaml:"spec_url"`
			SpecKind      string   `yaml:"spec_kind"`
			References    []string `yaml:"references"`
			AuthEvidence  []string `yaml:"auth_evidence"`
			ScopeEvidence []string `yaml:"scope_evidence"`
			Families      []struct {
				ID     string `yaml:"id"`
				Method string `yaml:"method"`
				Path   string `yaml:"path"`
			} `yaml:"families"`
		} `yaml:"provider_api"`
	}
	if err := yaml.Unmarshal(payload, &catalog); err != nil {
		t.Fatalf("unmarshal catalog: %v", err)
	}
	wantFamilies := []string{
		"analytics_cost",
		"api_key",
		"compliance_activity",
		"compliance_group",
		"compliance_group_member",
		"compliance_organization",
		"compliance_organization_setting",
		"compliance_organization_user",
		"compliance_project",
		"compliance_project_collaborator",
		"compliance_role",
		"compliance_role_permission",
		"cost_report",
		"external_key",
		"federation_issuer",
		"federation_rule",
		"invite",
		"organization",
		"rate_limit",
		"service_account",
		"spend_limit",
		"spend_limit_increase_request",
		"usage_report_claude_code",
		"usage_report_message",
		"user",
		"workspace",
		"workspace_member",
		"workspace_rate_limit",
	}
	assertStringSet(t, catalog.RuntimeFamilies, wantFamilies)
	if catalog.ProviderAPI.Status != "verified" || catalog.ProviderAPI.Basis != "declared" || catalog.ProviderAPI.Transport != "rest" || catalog.ProviderAPI.Auth != "api_key_or_bearer_token" || catalog.ProviderAPI.BaseURL != "https://api.anthropic.com" {
		t.Fatalf("provider_api = %#v, want verified declared REST API", catalog.ProviderAPI)
	}
	if catalog.ProviderAPI.AuthMechanics != "x_api_key_admin_key_or_org_admin_bearer_with_anthropic_version_header" {
		t.Fatalf("auth_mechanics = %q", catalog.ProviderAPI.AuthMechanics)
	}
	if catalog.ProviderAPI.SpecURL != "https://platform.claude.com/docs/en/api/admin.md" || catalog.ProviderAPI.SpecKind != "api_reference_markdown" {
		t.Fatalf("provider_api spec = %q/%q, want provider Markdown reference", catalog.ProviderAPI.SpecURL, catalog.ProviderAPI.SpecKind)
	}
	for _, ref := range []string{
		"https://platform.claude.com/docs/en/manage-claude/admin-api.md",
		"https://platform.claude.com/docs/en/manage-claude/wif-admin-api.md",
		"https://platform.claude.com/docs/en/manage-claude/compliance-api.md",
		"https://platform.claude.com/docs/en/api/admin/analytics/cost/list.md",
		"https://platform.claude.com/docs/en/api/compliance/apps/projects/collaborators/list.md",
	} {
		if !hasString(catalog.ProviderAPI.References, ref) {
			t.Fatalf("provider references = %v, want %s", catalog.ProviderAPI.References, ref)
		}
	}
	if len(catalog.ProviderAPI.AuthEvidence) == 0 || len(catalog.ProviderAPI.ScopeEvidence) == 0 {
		t.Fatalf("provider evidence incomplete: auth=%v scopes=%v", catalog.ProviderAPI.AuthEvidence, catalog.ProviderAPI.ScopeEvidence)
	}
	wantPaths := map[string]string{
		"analytics_cost":                  "/v1/organizations/analytics/cost_report",
		"api_key":                         "/v1/organizations/api_keys",
		"compliance_activity":             "/v1/compliance/activities",
		"compliance_group":                "/v1/compliance/groups",
		"compliance_group_member":         "/v1/compliance/groups/{group_id}/members",
		"compliance_organization":         "/v1/compliance/organizations",
		"compliance_organization_setting": "/v1/compliance/organizations/{organization_id}/settings",
		"compliance_organization_user":    "/v1/compliance/organizations/{org_uuid}/users",
		"compliance_project":              "/v1/compliance/apps/projects",
		"compliance_project_collaborator": "/v1/compliance/apps/projects/{project_id}/collaborators",
		"compliance_role":                 "/v1/compliance/organizations/{org_uuid}/roles",
		"compliance_role_permission":      "/v1/compliance/organizations/{org_uuid}/roles/{role_id}/permissions",
		"cost_report":                     "/v1/organizations/cost_report",
		"external_key":                    "/v1/organizations/external_keys",
		"federation_issuer":               "/v1/organizations/federation_issuers",
		"federation_rule":                 "/v1/organizations/federation_rules",
		"invite":                          "/v1/organizations/invites",
		"organization":                    "/v1/organizations/me",
		"rate_limit":                      "/v1/organizations/rate_limits",
		"service_account":                 "/v1/organizations/service_accounts",
		"spend_limit":                     "/v1/organizations/spend_limits/effective",
		"spend_limit_increase_request":    "/v1/organizations/spend_limit_increase_requests",
		"usage_report_claude_code":        "/v1/organizations/usage_report/claude_code",
		"usage_report_message":            "/v1/organizations/usage_report/messages",
		"user":                            "/v1/organizations/users",
		"workspace":                       "/v1/organizations/workspaces",
		"workspace_member":                "/v1/organizations/workspaces/{workspace_id}/members",
		"workspace_rate_limit":            "/v1/organizations/workspaces/{workspace_id}/rate_limits",
	}
	gotPaths := map[string]string{}
	for _, family := range catalog.ProviderAPI.Families {
		if family.Method != http.MethodGet {
			t.Fatalf("provider family %s method = %q, want GET", family.ID, family.Method)
		}
		gotPaths[family.ID] = family.Path
	}
	for family, want := range wantPaths {
		if got := gotPaths[family]; got != want {
			t.Fatalf("provider path for %s = %q, want %q", family, got, want)
		}
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}

	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range anthropicFamilies() {
		familyConfigs[family.Name] = sourcecdk.NewConfig(map[string]string{
			"family":    family.Name,
			"tenant_id": "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func TestReadAnalyticsCostUsesDocumentedCostReportPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/organizations/analytics/cost_report" {
			t.Fatalf("request path = %q, want /organizations/analytics/cost_report", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Fatalf("anthropic-version = %q, want 2023-06-01", got)
		}
		if got := r.Header.Get("x-api-key"); got != "fixture-admin-key" {
			t.Fatalf("x-api-key = %q, want fixture-admin-key", got)
		}
		if got := r.URL.Query().Get("starting_at"); got != "2026-06-01T00:00:00Z" {
			t.Fatalf("starting_at = %q, want 2026-06-01T00:00:00Z", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":          "analytics_cost_2026_06_01",
				"starting_at": "2026-06-01T00:00:00Z",
				"ending_at":   "2026-06-02T00:00:00Z",
				"model":       "claude-sonnet-4-20250514",
				"cost_usd":    12.48,
			}},
			"has_more": false,
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":     "fixture-admin-key",
		"base_url":    server.URL,
		"family":      "analytics_cost",
		"starting_at": "2026-06-01T00:00:00Z",
		"tenant_id":   "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "anthropic.analytics_cost" {
		t.Fatalf("Kind = %q, want anthropic.analytics_cost", event.Kind)
	}
	if got := event.Attributes["cost_usd"]; got != "12.48" {
		t.Fatalf("cost_usd = %q, want 12.48", got)
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":{"message":"temporarily unavailable"}}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":   "fixture-key",
		"base_url":  server.URL,
		"family":    "user",
		"tenant_id": "writer",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "anthropic API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func TestReadInventoryFamiliesEmitContractKinds(t *testing.T) {
	cases := []struct {
		family       string
		path         string
		record       map[string]any
		wantKind     string
		wantAttrKey  string
		wantAttrVal  string
		extraConfig  map[string]string
		extraAsserts func(t *testing.T, attrs map[string]string)
	}{
		{
			family:      "user",
			path:        "/organizations/users",
			record:      map[string]any{"id": "user_1", "email": "alice@example.com", "role": "admin", "status": "active"},
			wantKind:    "anthropic.user",
			wantAttrKey: "user_id",
			wantAttrVal: "user_1",
			extraAsserts: func(t *testing.T, attrs map[string]string) {
				if got := attrs["role"]; got != "admin" {
					t.Fatalf("role = %q, want admin", got)
				}
			},
		},
		{
			family:      "workspace",
			path:        "/organizations/workspaces",
			record:      map[string]any{"id": "ws_1", "name": "Research", "created_at": "2026-01-02T03:04:05Z"},
			wantKind:    "anthropic.workspace",
			wantAttrKey: "workspace_id",
			wantAttrVal: "ws_1",
		},
		{
			family:      "api_key",
			path:        "/organizations/api_keys",
			record:      map[string]any{"id": "apikey_1", "name": "prod-key", "status": "active", "created_by": map[string]any{"id": "user_1"}},
			wantKind:    "anthropic.api_key",
			wantAttrKey: "api_key_id",
			wantAttrVal: "apikey_1",
			extraAsserts: func(t *testing.T, attrs map[string]string) {
				if got := attrs["owner_user_id"]; got != "user_1" {
					t.Fatalf("owner_user_id = %q, want user_1", got)
				}
				if got := attrs["status"]; got != "active" {
					t.Fatalf("status = %q, want active", got)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.EscapedPath(); got != tc.path {
					t.Fatalf("request path = %q, want %q", got, tc.path)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data":     []map[string]any{tc.record},
					"has_more": false,
				})
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			cfg := map[string]string{ // #nosec G101 -- test-only placeholder key.
				"api_key":   "fixture-key",
				"base_url":  server.URL,
				"family":    tc.family,
				"tenant_id": "writer",
			}
			for key, value := range tc.extraConfig {
				cfg[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(cfg), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tc.wantKind {
				t.Fatalf("Kind = %q, want %q", event.Kind, tc.wantKind)
			}
			if event.TenantId != "writer" {
				t.Fatalf("TenantId = %q, want writer", event.TenantId)
			}
			if got := event.Attributes[tc.wantAttrKey]; got != tc.wantAttrVal {
				t.Fatalf("%s = %q, want %q", tc.wantAttrKey, got, tc.wantAttrVal)
			}
			if tc.extraAsserts != nil {
				tc.extraAsserts(t, event.Attributes)
			}
		})
	}
}

func TestReadRejectsMalformedInventoryRecords(t *testing.T) {
	families := map[string]string{
		"user":      "/organizations/users",
		"workspace": "/organizations/workspaces",
		"api_key":   "/organizations/api_keys",
	}
	for family, path := range families {
		t.Run(family, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.EscapedPath(); got != path {
					t.Fatalf("request path = %q, want %q", got, path)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data":     []map[string]any{{"name": "missing-identifier"}},
					"has_more": false,
				})
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
				"api_key":   "fixture-key",
				"base_url":  server.URL,
				"family":    family,
				"tenant_id": "writer",
			}), nil)
			if err == nil {
				t.Fatalf("Read() error = nil, want malformed-record rejection for %s", family)
			}
		})
	}
}

func TestReadComplianceActivityMapsResourceAndActorDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/compliance/activities" {
			t.Fatalf("request path = %q, want /compliance/activities", got)
		}
		if got := r.URL.Query().Get("activity_types[]"); got != "claude_chat_created" {
			t.Fatalf("activity_types[] = %q, want claude_chat_created", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":                "activity_123",
				"created_at":        "2026-04-10T08:09:10Z",
				"organization_id":   "org_123",
				"organization_uuid": "org-uuid-1",
				"actor": map[string]any{
					"type":          "user_actor",
					"email_address": "alice@example.com",
					"user_id":       "user_123",
					"ip_address":    "192.0.2.34",
					"user_agent":    "Mozilla/5.0",
				},
				"type":              "claude_chat_created",
				"claude_chat_id":    "claude_chat_123",
				"claude_project_id": "claude_proj_123",
				"filename":          "brief.pdf",
			}, {
				"id":         "activity_456",
				"created_at": "2026-04-10T08:10:10Z",
				"actor": map[string]any{
					"type":             "admin_api_key_actor",
					"admin_api_key_id": "admin_key_123",
				},
				"type": "compliance_api_accessed",
			}},
			"has_more": false,
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"activity_types": "claude_chat_created",
		"api_key":        "fixture-compliance-key",
		"base_url":       server.URL,
		"family":         "compliance_activity",
		"tenant_id":      "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(pull.Events))
	}
	chatEvent := pull.Events[0]
	if got := chatEvent.Attributes["activity_type"]; got != "claude_chat_created" {
		t.Fatalf("activity_type = %q, want claude_chat_created", got)
	}
	if got := chatEvent.Attributes["actor_ip_address"]; got != "192.0.2.34" {
		t.Fatalf("actor_ip_address = %q, want 192.0.2.34", got)
	}
	if got := chatEvent.Attributes["claude_chat_id"]; got != "claude_chat_123" {
		t.Fatalf("claude_chat_id = %q, want claude_chat_123", got)
	}
	if got := chatEvent.Attributes["project_id"]; got != "claude_proj_123" {
		t.Fatalf("project_id = %q, want claude_proj_123", got)
	}
	adminKeyEvent := pull.Events[1]
	if got := adminKeyEvent.Attributes["actor_admin_api_key_id"]; got != "admin_key_123" {
		t.Fatalf("actor_admin_api_key_id = %q, want admin_key_123", got)
	}
}

func TestReadWorkspaceMemberUsesAdminAPIKeyHeadersAndCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/organizations/workspaces/wrkspc_123/members" {
			t.Fatalf("request path = %q, want /organizations/workspaces/wrkspc_123/members", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Fatalf("anthropic-version = %q, want 2023-06-01", got)
		}
		if got := r.Header.Get("x-api-key"); got != "admin-key" {
			t.Fatalf("x-api-key = %q, want admin-key", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want empty", got)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		switch r.URL.Query().Get("after_id") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":             "user_1",
					"email":          "alice@example.com",
					"workspace_role": "workspace_developer",
				}},
				"has_more": true,
				"last_id":  "user_1",
			})
		case "user_1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":             "user_2",
					"email":          "bob@example.com",
					"workspace_role": "workspace_admin",
				}},
				"has_more": false,
				"last_id":  "user_2",
			})
		default:
			t.Fatalf("after_id = %q, want empty or user_1", r.URL.Query().Get("after_id"))
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"api_key":      "admin-key",
		"base_url":     server.URL,
		"family":       "workspace_member",
		"per_page":     "2",
		"tenant_id":    "writer",
		"workspace_id": "wrkspc_123",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "user_1" {
		t.Fatalf("first NextCursor = %q, want user_1", first.NextCursor.GetOpaque())
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	event := first.Events[0]
	if event.Kind != "anthropic.workspace_member" {
		t.Fatalf("Kind = %q, want anthropic.workspace_member", event.Kind)
	}
	if got := event.Attributes["workspace_id"]; got != "wrkspc_123" {
		t.Fatalf("workspace_id = %q, want wrkspc_123", got)
	}
	if got := event.Attributes["workspace_role"]; got != "workspace_developer" {
		t.Fatalf("workspace_role = %q, want workspace_developer", got)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
}

func TestReadServiceAccountCanUseBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/organizations/service_accounts" {
			t.Fatalf("request path = %q, want /organizations/service_accounts", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer oauth-value" {
			t.Fatalf("Authorization = %q, want Bearer oauth-value", got)
		}
		if got := r.Header.Get("x-api-key"); got != "" {
			t.Fatalf("x-api-key = %q, want empty", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Fatalf("anthropic-version = %q, want 2023-06-01", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":          "svac_1",
				"name":        "CI",
				"description": "Automation",
			}},
			"has_more": false,
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test placeholder auth config only.
		"auth_model": "bearer_token",
		"base_url":   server.URL,
		"family":     "service_account",
		"tenant_id":  "writer",
		"token":      "oauth-value",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "anthropic.service_account" {
		t.Fatalf("Kind = %q, want anthropic.service_account", event.Kind)
	}
	if got := event.Attributes["service_account_id"]; got != "svac_1" {
		t.Fatalf("service_account_id = %q, want svac_1", got)
	}
}

func TestReadComplianceOrganizationUsersUsesComplianceKeyAndPageCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/compliance/organizations/org-uuid-1/users" {
			t.Fatalf("request path = %q, want /compliance/organizations/org-uuid-1/users", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Fatalf("anthropic-version = %q, want 2023-06-01", got)
		}
		if got := r.Header.Get("x-api-key"); got != "fixture-compliance-key" {
			t.Fatalf("x-api-key = %q, want fixture-compliance-key", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want empty", got)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		switch r.URL.Query().Get("page") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":                "user_1",
					"full_name":         "Alice Example",
					"email":             "alice@example.com",
					"organization_role": "admin",
					"created_at":        "2025-06-01T10:00:00Z",
				}},
				"has_more":  true,
				"next_page": "page-2",
			})
		case "page-2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":                "user_2",
					"full_name":         "Bob Example",
					"email":             "bob@example.com",
					"organization_role": "user",
					"created_at":        "2025-06-02T10:00:00Z",
				}},
				"has_more":  false,
				"next_page": nil,
			})
		default:
			t.Fatalf("page = %q, want empty or page-2", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":           "fixture-compliance-key",
		"base_url":          server.URL,
		"family":            "compliance_organization_user",
		"organization_uuid": "org-uuid-1",
		"per_page":          "2",
		"tenant_id":         "writer",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "page-2" {
		t.Fatalf("first NextCursor = %q, want page-2", first.NextCursor.GetOpaque())
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	event := first.Events[0]
	if event.Kind != "anthropic.compliance_organization_user" {
		t.Fatalf("Kind = %q, want anthropic.compliance_organization_user", event.Kind)
	}
	if got := event.Attributes["organization_uuid"]; got != "org-uuid-1" {
		t.Fatalf("organization_uuid = %q, want org-uuid-1", got)
	}
	if got := event.Attributes["user_id"]; got != "user_1" {
		t.Fatalf("user_id = %q, want user_1", got)
	}
	if got := event.Attributes["role"]; got != "admin" {
		t.Fatalf("role = %q, want admin", got)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
}

func TestReadComplianceRolePermissionsUsesRolePathAndPageCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/compliance/organizations/org-uuid-1/roles/rbac_role_123/permissions" {
			t.Fatalf("request path = %q, want /compliance/organizations/org-uuid-1/roles/rbac_role_123/permissions", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Fatalf("anthropic-version = %q, want 2023-06-01", got)
		}
		if got := r.Header.Get("x-api-key"); got != "fixture-compliance-key" {
			t.Fatalf("x-api-key = %q, want fixture-compliance-key", got)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		switch r.URL.Query().Get("page") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":            "perm_read_chats",
					"name":          "Read chats",
					"description":   "Read retained chat content.",
					"action":        "read",
					"resource_type": "chat",
				}},
				"has_more":  true,
				"next_page": "page-2",
			})
		case "page-2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":            "perm_delete_files",
					"name":          "Delete files",
					"action":        "delete",
					"resource_type": "file",
				}},
				"has_more": false,
			})
		default:
			t.Fatalf("page = %q, want empty or page-2", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":           "fixture-compliance-key",
		"base_url":          server.URL,
		"family":            "compliance_role_permission",
		"organization_uuid": "org-uuid-1",
		"per_page":          "2",
		"role_id":           "rbac_role_123",
		"tenant_id":         "writer",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "page-2" {
		t.Fatalf("first NextCursor = %q, want page-2", first.NextCursor.GetOpaque())
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	event := first.Events[0]
	if event.Kind != "anthropic.compliance_role_permission" {
		t.Fatalf("Kind = %q, want anthropic.compliance_role_permission", event.Kind)
	}
	if got := event.Attributes["organization_uuid"]; got != "org-uuid-1" {
		t.Fatalf("organization_uuid = %q, want org-uuid-1", got)
	}
	if got := event.Attributes["role_id"]; got != "rbac_role_123" {
		t.Fatalf("role_id = %q, want rbac_role_123", got)
	}
	if got := event.Attributes["permission_id"]; got != "perm_read_chats" {
		t.Fatalf("permission_id = %q, want perm_read_chats", got)
	}
	if got := event.Attributes["resource_type"]; got != "chat" {
		t.Fatalf("resource_type = %q, want chat", got)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
}

func TestReadComplianceProjectsUsesComplianceKeyAndPageCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/compliance/apps/projects" {
			t.Fatalf("request path = %q, want /compliance/apps/projects", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Fatalf("anthropic-version = %q, want 2023-06-01", got)
		}
		if got := r.Header.Get("x-api-key"); got != "fixture-compliance-key" {
			t.Fatalf("x-api-key = %q, want fixture-compliance-key", got)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		switch r.URL.Query().Get("page") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":          "claude_proj_123",
					"name":        "Legal review",
					"description": "Matter review workspace",
					"organization": map[string]any{
						"uuid": "org-uuid-1",
					},
					"created_at": "2026-01-02T03:04:05Z",
				}},
				"has_more":  true,
				"next_page": "page-2",
			})
		case "page-2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":     "claude_proj_456",
					"name":   "Engineering docs",
					"status": "archived",
				}},
				"has_more": false,
			})
		default:
			t.Fatalf("page = %q, want empty or page-2", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":   "fixture-compliance-key",
		"base_url":  server.URL,
		"family":    "compliance_project",
		"per_page":  "2",
		"tenant_id": "writer",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "page-2" {
		t.Fatalf("first NextCursor = %q, want page-2", first.NextCursor.GetOpaque())
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	event := first.Events[0]
	if event.Kind != "anthropic.compliance_project" {
		t.Fatalf("Kind = %q, want anthropic.compliance_project", event.Kind)
	}
	if got := event.Attributes["project_id"]; got != "claude_proj_123" {
		t.Fatalf("project_id = %q, want claude_proj_123", got)
	}
	if got := event.Attributes["organization_uuid"]; got != "org-uuid-1" {
		t.Fatalf("organization_uuid = %q, want org-uuid-1", got)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
}

func TestReadComplianceProjectCollaboratorsUsesProjectPathAndPageCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/compliance/apps/projects/claude_proj_123/collaborators" {
			t.Fatalf("request path = %q, want /compliance/apps/projects/claude_proj_123/collaborators", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Fatalf("anthropic-version = %q, want 2023-06-01", got)
		}
		if got := r.Header.Get("x-api-key"); got != "fixture-compliance-key" {
			t.Fatalf("x-api-key = %q, want fixture-compliance-key", got)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		switch r.URL.Query().Get("page") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id": "assignment_1",
					"principal": map[string]any{
						"type":  "user",
						"id":    "user_123",
						"email": "alice@example.com",
						"name":  "Alice Example",
					},
					"role": map[string]any{
						"id":   "project_admin",
						"name": "Project admin",
					},
					"created_at": "2026-01-02T03:04:05Z",
				}},
				"has_more":  true,
				"next_page": "page-2",
			})
		case "page-2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id": "assignment_2",
					"principal": map[string]any{
						"type": "group",
						"id":   "rbac_group_123",
						"name": "Legal",
					},
					"role": map[string]any{
						"id": "project_viewer",
					},
				}},
				"has_more": false,
			})
		default:
			t.Fatalf("page = %q, want empty or page-2", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":    "fixture-compliance-key",
		"base_url":   server.URL,
		"family":     "compliance_project_collaborator",
		"per_page":   "2",
		"project_id": "claude_proj_123",
		"tenant_id":  "writer",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "page-2" {
		t.Fatalf("first NextCursor = %q, want page-2", first.NextCursor.GetOpaque())
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	event := first.Events[0]
	if event.Kind != "anthropic.compliance_project_collaborator" {
		t.Fatalf("Kind = %q, want anthropic.compliance_project_collaborator", event.Kind)
	}
	if got := event.Attributes["project_id"]; got != "claude_proj_123" {
		t.Fatalf("project_id = %q, want claude_proj_123", got)
	}
	if got := event.Attributes["principal_type"]; got != "user" {
		t.Fatalf("principal_type = %q, want user", got)
	}
	if got := event.Attributes["principal_id"]; got != "user_123" {
		t.Fatalf("principal_id = %q, want user_123", got)
	}
	if got := event.Attributes["role_id"]; got != "project_admin" {
		t.Fatalf("role_id = %q, want project_admin", got)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	secondEvent := second.Events[0]
	if got := secondEvent.Attributes["role_id"]; got != "project_viewer" {
		t.Fatalf("second role_id = %q, want project_viewer", got)
	}
	if got := secondEvent.Attributes["role"]; got != "project_viewer" {
		t.Fatalf("second role = %q, want project_viewer", got)
	}
	if got := secondEvent.Attributes["role_name"]; got != "project_viewer" {
		t.Fatalf("second role_name = %q, want project_viewer", got)
	}
}

func TestReadComplianceOrganizationSettingsUsesSettingsListKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/compliance/organizations/org-uuid-1/settings" {
			t.Fatalf("request path = %q, want /compliance/organizations/org-uuid-1/settings", got)
		}
		if got := r.URL.Query().Get("limit"); got != "" {
			t.Fatalf("limit = %q, want empty", got)
		}
		if got := r.Header.Get("x-api-key"); got != "fixture-compliance-key" {
			t.Fatalf("x-api-key = %q, want fixture-compliance-key", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":            "effective_organization_settings",
			"organization_id": "org-uuid-1",
			"settings": []map[string]any{
				{
					"name":  "content_redaction_enabled",
					"type":  "boolean",
					"value": true,
				},
				{
					"name":  "ip_allowlist_ip_ranges",
					"type":  "string_list",
					"value": []string{"10.0.0.0/8", "203.0.113.0/24"},
				},
			},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":           "fixture-compliance-key",
		"base_url":          server.URL,
		"family":            "compliance_organization_setting",
		"organization_uuid": "org-uuid-1",
		"per_page":          "2",
		"tenant_id":         "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "anthropic.compliance_organization_setting" {
		t.Fatalf("Kind = %q, want anthropic.compliance_organization_setting", event.Kind)
	}
	if got := event.Attributes["organization_uuid"]; got != "org-uuid-1" {
		t.Fatalf("organization_uuid = %q, want org-uuid-1", got)
	}
	if got := event.Attributes["setting_name"]; got != "content_redaction_enabled" {
		t.Fatalf("setting_name = %q, want content_redaction_enabled", got)
	}
	if got := event.Attributes["setting_value"]; got != "true" {
		t.Fatalf("setting_value = %q, want true", got)
	}
}

func assertStringSet(t *testing.T, got []string, want []string) {
	t.Helper()
	gotCopy := append([]string(nil), got...)
	wantCopy := append([]string(nil), want...)
	sort.Strings(gotCopy)
	sort.Strings(wantCopy)
	if strings.Join(gotCopy, "\n") != strings.Join(wantCopy, "\n") {
		t.Fatalf("set = %v, want %v", gotCopy, wantCopy)
	}
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
