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

func TestReadCloudflareCoverageAttributes(t *testing.T) {
	for _, tt := range []struct {
		name     string
		family   string
		path     string
		config   map[string]string
		payload  map[string]any
		attr     string
		contains string
	}{
		{
			name:    "role permission groups",
			family:  "role",
			path:    "/accounts/account-1/roles",
			config:  map[string]string{"account_id": "account-1"},
			payload: map[string]any{"id": "role-1", "name": "Security Reviewer", "permission_groups": []map[string]any{{"id": "pg-logs", "name": "Logs Read"}}, "permissions": []map[string]any{{"id": "analytics:read"}}},
			attr:    "permission_groups", contains: "Logs Read",
		},
		{
			name:    "account ruleset rules",
			family:  "account_ruleset",
			path:    "/accounts/account-1/rulesets",
			config:  map[string]string{"account_id": "account-1"},
			payload: map[string]any{"id": "ruleset-1", "name": "Account WAF", "rules": []map[string]any{{"id": "rule-1", "version": "3", "action": "block"}}},
			attr:    "rules", contains: `"version":"3"`,
		},
		{
			name:    "zone ruleset rules",
			family:  "zone_ruleset",
			path:    "/zones/zone-1/rulesets",
			config:  map[string]string{"zone_id": "zone-1"},
			payload: map[string]any{"id": "ruleset-2", "name": "Zone WAF", "rules": []map[string]any{{"id": "rule-2", "version": "7", "action": "challenge"}}},
			attr:    "rules", contains: `"version":"7"`,
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
			name:    "access group rules",
			family:  "access_group",
			path:    "/accounts/account-1/access/groups",
			config:  map[string]string{"account_id": "account-1"},
			payload: map[string]any{"id": "group-1", "name": "Employees", "include": []map[string]any{{"email_domain": map[string]any{"domain": "writer.com"}}}, "require": []map[string]any{{"group": map[string]any{"id": "okta-group-1"}}}},
			attr:    "include", contains: "writer.com",
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
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("request path = %q, want %s", got, tt.path)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"result": []map[string]any{tt.payload}})
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
		})
	}
}
