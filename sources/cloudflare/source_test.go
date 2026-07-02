package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "cloudflare" {
		t.Fatalf("Spec().Id = %q, want cloudflare", got)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}

	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range cloudflareFamilies() {
		familyConfigs[family.Name] = sourcecdk.NewConfig(map[string]string{
			"account_id": "account-1",
			"family":     family.Name,
			"tenant_id":  "tenant",
			"zone_id":    "zone-1",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"errors":[{"message":"service unavailable"}]}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    "account",
		"tenant_id": "writer",
		"token":     "token-1",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "cloudflare API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func TestReadMemberUsesAccountPathParamAndResultList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/accounts/account-1/members" {
			t.Fatalf("request path = %q, want /accounts/account-1/members", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"id":     "member-1",
				"status": "accepted",
				"user": map[string]any{
					"email": "alice@example.com",
				},
			}},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id": "account-1",
		"base_url":   server.URL,
		"family":     "member",
		"tenant_id":  "writer",
		"token":      "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "cloudflare.member" {
		t.Fatalf("Kind = %q, want cloudflare.member", event.Kind)
	}
	if got := event.Attributes["member_id"]; got != "member-1" {
		t.Fatalf("member_id = %q, want member-1", got)
	}
	if got := event.Attributes["account_id"]; got != "account-1" {
		t.Fatalf("account_id = %q, want account-1", got)
	}
	if got := event.Attributes["email"]; got != "alice@example.com" {
		t.Fatalf("email = %q, want alice@example.com", got)
	}
}

func TestReadCloudflareCoreInventoryKinds(t *testing.T) {
	for _, tt := range []struct {
		name    string
		family  string
		kind    string
		path    string
		detail  string
		config  map[string]string
		payload map[string]any
		want    map[string]string
	}{
		{
			name:    "account",
			family:  "account",
			kind:    "cloudflare.account",
			path:    "/accounts",
			payload: map[string]any{"id": "acct-1", "name": "Writer", "type": "enterprise"},
			want:    map[string]string{"account_id": "acct-1", "name": "Writer", "type": "enterprise"},
		},
		{
			name:    "role",
			family:  "role",
			kind:    "cloudflare.role",
			path:    "/accounts/acct-1/roles",
			detail:  "/accounts/acct-1/roles/role-1",
			config:  map[string]string{"account_id": "acct-1"},
			payload: map[string]any{"id": "role-1", "name": "Administrator"},
			want:    map[string]string{"role_id": "role-1", "account_id": "acct-1", "name": "Administrator"},
		},
		{
			name:    "zone",
			family:  "zone",
			kind:    "cloudflare.zone",
			path:    "/zones",
			payload: map[string]any{"id": "zone-1", "name": "example.com", "status": "active", "type": "full", "paused": false, "account": map[string]any{"id": "acct-1"}},
			want:    map[string]string{"zone_id": "zone-1", "account_id": "acct-1", "name": "example.com", "status": "active", "paused": "false"},
		},
		{
			name:    "dns_record",
			family:  "dns_record",
			kind:    "cloudflare.dns_record",
			path:    "/zones/zone-1/dns_records",
			config:  map[string]string{"zone_id": "zone-1"},
			payload: map[string]any{"id": "dns-1", "name": "www.example.com", "type": "A", "content": "203.0.113.10", "proxied": true},
			want:    map[string]string{"record_id": "dns-1", "zone_id": "zone-1", "name": "www.example.com", "type": "A", "content": "203.0.113.10", "proxied": "true"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch got := r.URL.EscapedPath(); got {
				case tt.path:
					_ = json.NewEncoder(w).Encode(map[string]any{"result": []map[string]any{tt.payload}})
				case tt.detail:
					_ = json.NewEncoder(w).Encode(map[string]any{"result": tt.payload})
				default:
					t.Fatalf("request path = %q, want %s", got, tt.path)
				}
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			config := map[string]string{"base_url": server.URL, "family": tt.family, "tenant_id": "writer", "token": "token-1"}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %q", event.Kind, tt.kind)
			}
			for key, value := range tt.want {
				if got := event.Attributes[key]; got != value {
					t.Fatalf("attribute %q = %q, want %q", key, got, value)
				}
			}
		})
	}
}

func TestReadCloudflareCoverageAttributes(t *testing.T) {
	for _, tt := range []struct {
		name     string
		family   string
		path     string
		detail   string
		config   map[string]string
		payload  map[string]any
		enriched map[string]any
		attr     string
		contains string
	}{
		{
			name:    "role permission groups",
			family:  "role",
			path:    "/accounts/account-1/roles",
			detail:  "/accounts/account-1/roles/role-1",
			config:  map[string]string{"account_id": "account-1"},
			payload: map[string]any{"id": "role-1", "name": "Security Reviewer", "permissions": []map[string]any{{"id": "analytics:read"}}},
			enriched: map[string]any{
				"id":                "role-1",
				"name":              "Security Reviewer",
				"permission_groups": []map[string]any{{"id": "pg-logs", "name": "Logs Read"}},
			},
			attr: "permission_groups", contains: "Logs Read",
		},
		{
			name:    "account ruleset rules",
			family:  "account_ruleset",
			path:    "/accounts/account-1/rulesets",
			detail:  "/accounts/account-1/rulesets/ruleset-1",
			config:  map[string]string{"account_id": "account-1"},
			payload: map[string]any{"id": "ruleset-1", "name": "Account WAF"},
			enriched: map[string]any{
				"id":    "ruleset-1",
				"name":  "Account WAF",
				"rules": []map[string]any{{"id": "rule-1", "version": "3", "action": "block"}},
			},
			attr: "rules", contains: `"version":"3"`,
		},
		{
			name:    "zone ruleset rules",
			family:  "zone_ruleset",
			path:    "/zones/zone-1/rulesets",
			detail:  "/zones/zone-1/rulesets/ruleset-2",
			config:  map[string]string{"zone_id": "zone-1"},
			payload: map[string]any{"id": "ruleset-2", "name": "Zone WAF"},
			enriched: map[string]any{
				"id":    "ruleset-2",
				"name":  "Zone WAF",
				"rules": []map[string]any{{"id": "rule-2", "version": "7", "action": "challenge"}},
			},
			attr: "rules", contains: `"version":"7"`,
		},
		{
			name:    "access application policies",
			family:  "access_application",
			path:    "/accounts/account-1/access/apps",
			config:  map[string]string{"account_id": "account-1"},
			payload: map[string]any{"id": "app-1", "name": "Admin", "policies": []map[string]any{{"id": "policy-1", "decision": "allow"}}, "allowed_idps": []string{"okta"}, "auto_redirect_to_identity": true},
			attr:    "policies", contains: "policy-1",
		},
		{
			name:    "zone access application policies",
			family:  "zone_access_application",
			path:    "/zones/zone-1/access/apps",
			config:  map[string]string{"zone_id": "zone-1"},
			payload: map[string]any{"id": "zone-app-1", "name": "Zone Admin", "domain": "admin.example.com", "policies": []map[string]any{{"id": "zone-policy-1", "decision": "allow"}}, "allowed_idps": []string{"okta"}},
			attr:    "policies", contains: "zone-policy-1",
		},
		{
			name:    "access group rules",
			family:  "access_group",
			path:    "/accounts/account-1/access/groups",
			config:  map[string]string{"account_id": "account-1"},
			payload: map[string]any{"id": "group-1", "name": "Employees", "include": []map[string]any{{"email_domain": map[string]any{"domain": "writer.com"}}}, "require": []map[string]any{{"group": map[string]any{"id": "okta-group-1"}}}},
			attr:    "include", contains: "writer.com",
		},
		{
			name:    "zone access group rules",
			family:  "zone_access_group",
			path:    "/zones/zone-1/access/groups",
			config:  map[string]string{"zone_id": "zone-1"},
			payload: map[string]any{"id": "zone-group-1", "name": "Zone Employees", "include": []map[string]any{{"email_domain": map[string]any{"domain": "example.com"}}}, "require": []map[string]any{{"group": map[string]any{"id": "idp-group-1"}}}},
			attr:    "include", contains: "example.com",
		},
		{
			name:    "gateway rule settings",
			family:  "gateway_rule",
			path:    "/accounts/account-1/gateway/rules",
			config:  map[string]string{"account_id": "account-1"},
			payload: map[string]any{"id": "gateway-rule-1", "name": "Block Malware", "filters": []string{"dns"}, "rule_settings": map[string]any{"block_page_enabled": true}},
			attr:    "rule_settings", contains: "block_page_enabled",
		},
		{
			name:    "worker script bindings",
			family:  "worker_script",
			path:    "/accounts/account-1/workers/scripts",
			config:  map[string]string{"account_id": "account-1"},
			payload: map[string]any{"id": "worker-1", "bindings": []map[string]any{{"name": "CACHE", "type": "kv_namespace", "namespace_id": "kv-1"}}, "placement": map[string]any{"mode": "smart"}},
			attr:    "bindings", contains: "kv_namespace",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch got := r.URL.EscapedPath(); got {
				case tt.path:
					_ = json.NewEncoder(w).Encode(map[string]any{"result": []map[string]any{tt.payload}})
				case tt.detail:
					_ = json.NewEncoder(w).Encode(map[string]any{"result": tt.enriched})
				default:
					t.Fatalf("request path = %q, want %s", got, tt.path)
				}
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			config := map[string]string{"base_url": server.URL, "family": tt.family, "tenant_id": "writer", "token": "token-1"}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Attributes[tt.attr]; !strings.Contains(got, tt.contains) {
				t.Fatalf("%s = %q, want to contain %q", tt.attr, got, tt.contains)
			}
			if tt.family == "worker_script" {
				if got := pull.Events[0].Attributes["resource_name"]; got != "worker-1" {
					t.Fatalf("resource_name = %q, want worker-1", got)
				}
			}
		})
	}
}

func TestAuditLogDoesNotSynthesizeResourceURNFromAuditedResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/accounts/account-1/audit_logs" {
			t.Fatalf("request path = %q, want /accounts/account-1/audit_logs", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"id":   "audit-1",
				"when": "2026-06-01T00:00:00Z",
				"action": map[string]any{
					"type": "zone.settings.update",
				},
				"resource": map[string]any{
					"id":   "zone-1",
					"type": "zone",
				},
				"account": map[string]any{
					"id": "account-1",
				},
			}},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"account_id": "account-1",
		"base_url":   server.URL,
		"family":     "audit_log",
		"tenant_id":  "writer",
		"token":      "token-1",
	})
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 1 || urns[0].String() != "urn:cerebro:writer:cloudflare_audit_log:audit-1" {
		t.Fatalf("Discover() URNs = %v, want audit log record URN", urns)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if got := attrs["audit_id"]; got != "audit-1" {
		t.Fatalf("audit_id = %q, want audit-1", got)
	}
	if got := attrs["resource_id"]; got != "zone-1" {
		t.Fatalf("resource_id = %q, want audited resource id zone-1", got)
	}
	if got := attrs["resource_urn"]; got != "" {
		t.Fatalf("resource_urn = %q, want empty because audit_log resource_id is the audited resource", got)
	}
}

func TestReadRulesetDetailFailureKeepsListRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch got := r.URL.EscapedPath(); got {
		case "/accounts/account-1/rulesets":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": []map[string]any{
					{"id": "ruleset-1", "name": "Stale WAF"},
					{"id": "ruleset-2", "name": "Live WAF"},
				},
				"result_info": map[string]any{"page": 1, "total_pages": 2},
			})
		case "/accounts/account-1/rulesets/ruleset-1":
			http.Error(w, "temporary detail error", http.StatusBadGateway)
		case "/accounts/account-1/rulesets/ruleset-2":
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"id": "ruleset-2", "name": "Live WAF", "rules": []map[string]any{{"id": "rule-2", "action": "block"}}}})
		default:
			t.Fatalf("unexpected request path %q", got)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id": "account-1",
		"base_url":   server.URL,
		"family":     "account_ruleset",
		"tenant_id":  "writer",
		"token":      "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(pull.Events))
	}
	if pull.NextCursor.GetOpaque() != "2" {
		t.Fatalf("NextCursor = %q, want 2", pull.NextCursor.GetOpaque())
	}
	if got := pull.Events[0].Attributes["name"]; got != "Stale WAF" {
		t.Fatalf("first ruleset name = %q, want Stale WAF", got)
	}
	if got := pull.Events[1].Attributes["rules"]; !strings.Contains(got, "rule-2") {
		t.Fatalf("second ruleset rules = %q, want rule-2", got)
	}
}
