package github

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	gogithub "github.com/google/go-github/v66/github"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	findingrules "github.com/writer/cerebro/internal/findings"
)

func TestAuditAttributesForwardGitHubAuditRuleRequiredAttributes(t *testing.T) {
	events := []*cerebrov1.EventEnvelope{
		auditEventForTest(t, "repo.add_member", map[string]any{
			"hook_id":             99,
			"number":              12,
			"permission":          "admin",
			"previous_visibility": "private",
			"repo":                "writer/cerebro",
			"ruleset_id":          42,
			"visibility":          "public",
		}, func(entry *gogithub.AuditEntry) {
			entry.User = gogithub.String("octocat")
		}),
		auditEventForTest(t, "integration_installation.create", map[string]any{
			"installation": map[string]any{"app_id": 4242},
		}, nil),
		auditEventForTest(t, "personal_access_token.access_granted", map[string]any{
			"operation_type": "create",
			"token_id":       555,
			"user":           "octocat",
		}, func(entry *gogithub.AuditEntry) {
			userID := int64(12345)
			entry.UserID = &userID
		}),
		auditEventForTest(t, "repo.register_self_hosted_runner", map[string]any{
			"repo":              "writer/cerebro",
			"runner_ephemeral":  false,
			"runner_id":         777,
			"runner_registered": true,
		}, nil),
		auditEventForTest(t, "secret_scanning_alert.create", map[string]any{
			"number": 12,
			"repo":   "writer/cerebro",
			"secret_scanning_alert": map[string]any{
				"state": "open",
			},
		}, nil),
	}

	requiredAttrs := map[string]bool{}
	for _, rule := range findingrules.Builtin().ForRuntime(githubAuditRuntimeForRuleTest()) {
		metadataRule, ok := rule.(findingrules.MetadataRule)
		if !ok {
			continue
		}
		definition := metadataRule.RuleMetadata()
		if definition.SourceID != "github" || !containsString(definition.EventKinds, "github.audit") {
			continue
		}
		for _, required := range definition.RequiredAttributes {
			if strings.TrimSpace(required) != "" {
				requiredAttrs[required] = true
			}
		}
	}

	missing := []string{}
	for required := range requiredAttrs {
		if !anyAuditEventHasAttribute(events, required) {
			missing = append(missing, required)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Fatalf("source github auditAttributes did not forward published required attrs %v", missing)
	}
}

func TestAuditAttributes_ForwardsRunnerID(t *testing.T) {
	event := auditEventForTest(t, "repo.register_self_hosted_runner", map[string]any{
		"repo":              "writer/cerebro",
		"resource_type":     "repo",
		"runner_ephemeral":  false,
		"runner_id":         777,
		"runner_name":       "prod-runner-1",
		"runner_registered": true,
	}, nil)
	if got := event.Attributes["runner_id"]; got != "777" {
		t.Fatalf("runner_id = %q, want 777; attributes=%v", got, event.Attributes)
	}
	if got := event.Attributes["runner_scope"]; got != "repo:writer/cerebro" {
		t.Fatalf("runner_scope = %q, want repo:writer/cerebro; attributes=%v", got, event.Attributes)
	}

}

func TestAuditAttributes_PreservesNormalizedRunnerScope(t *testing.T) {
	event := auditEventForTest(t, "repo.register_self_hosted_runner", map[string]any{
		"repo":         "writer/cerebro",
		"runner_id":    777,
		"runner_scope": "repository",
	}, nil)

	if got := event.Attributes["runner_scope"]; got != "repo:writer/cerebro" {
		t.Fatalf("runner_scope = %q, want normalized repo scope; attributes=%v", got, event.Attributes)
	}
}

func TestAuditAttributes_ForwardsPostureBooleans(t *testing.T) {
	postureAttrs := map[string]any{
		"advanced_security_enabled":               true,
		"allowed_cidrs_compliant":                 true,
		"auth_control_weakened":                   false,
		"code_security_enabled":                   true,
		"dependabot_alerts_enabled":               false,
		"dependabot_enabled":                      true,
		"dependabot_security_updates_enabled":     true,
		"github_advanced_security_enabled":        true,
		"ip_allow_list_disabled":                  false,
		"ip_allow_list_enabled":                   false,
		"ip_allow_list_entries_compliant":         true,
		"mfa_required":                            true,
		"non_allowlisted_cidr_count":              1,
		"non_allowlisted_cidrs":                   []any{"203.0.113.0/24"},
		"oauth_app_restrictions_enabled":          true,
		"oauth_app_restrictions_enforced":         true,
		"private_forking_enabled":                 true,
		"private_repository_forking_enabled":      true,
		"repository_secret_scanning_enabled":      true,
		"repository_vulnerability_alerts_enabled": true,
		"saml_enabled":                            true,
		"saml_enforced":                           true,
		"saml_provider_settings_weakened":         false,
		"saml_required":                           true,
		"saml_sso_enabled":                        true,
		"secret_scanning_enabled":                 true,
		"secret_scanning_push_protection_enabled": true,
		"two_factor_enforced":                     true,
		"two_factor_required":                     true,
		"two_factor_requirement_enabled":          false,
		"vulnerability_alerts_enabled":            true,
	}
	attributes := auditEventForTest(t, "org.posture_update", postureAttrs, nil).Attributes
	for key := range postureAttrs {
		if strings.TrimSpace(attributes[key]) == "" {
			t.Fatalf("%s was not forwarded; attributes=%v", key, attributes)
		}
	}

	for _, tc := range []struct {
		name   string
		ruleID string
		action string
		raw    map[string]any
	}{
		{
			name:   "code security dependabot disabled",
			ruleID: "github-code-security-controls-disabled",
			action: "dependabot_alerts.disable",
			raw: map[string]any{
				"dependabot_alerts_enabled": false,
				"org":                       "writer",
				"repo":                      "writer/cerebro",
				"resource_id":               "writer/cerebro",
				"resource_type":             "repository",
			},
		},
		{
			name:   "org auth two factor disabled",
			ruleID: "github-org-auth-control-modified",
			action: "org.disable_two_factor_requirement",
			raw: map[string]any{
				"org":                            "writer",
				"resource_id":                    "writer",
				"resource_type":                  "org",
				"two_factor_requirement_enabled": false,
			},
		},
		{
			name:   "ip allow list disabled",
			ruleID: "github-org-ip-allow-list-modified",
			action: "ip_allow_list.disable",
			raw: map[string]any{
				"ip_allow_list_enabled": false,
				"org":                   "writer",
				"resource_id":           "writer",
				"resource_type":         "ip_allow_list",
			},
		},
		{
			name:   "private repository forking enabled",
			ruleID: "github-private-repository-forking-enabled",
			action: "private_repository_forking.enable",
			raw: map[string]any{
				"org":                                "writer",
				"private_repository_forking_enabled": true,
				"resource_id":                        "writer",
				"resource_type":                      "org",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := auditEventForTest(t, tc.action, tc.raw, nil)
			for key := range tc.raw {
				if _, exists := postureAttrs[key]; !exists {
					continue
				}
				if strings.TrimSpace(event.Attributes[key]) == "" {
					t.Fatalf("%s was not forwarded on source-backed rule event; attributes=%v", key, event.Attributes)
				}
			}
			records, err := mustGitHubFindingRule(t, tc.ruleID).Evaluate(context.Background(), githubAuditRuntimeForRuleTest(), event)
			if err != nil {
				t.Fatalf("Evaluate(%s) error = %v", tc.ruleID, err)
			}
			if len(records) != 1 {
				t.Fatalf("Evaluate(%s) returned %d findings, want 1; attrs=%v", tc.ruleID, len(records), event.Attributes)
			}
		})
	}
}

func TestAuditAttributes_ForwardsWebhookAllowlistKeys(t *testing.T) {
	webhookAttrs := map[string]any{
		"allowlisted_destination":             true,
		"destination_allowlisted":             true,
		"hook_destination_allowlisted":        true,
		"hook_url_allowlisted":                true,
		"url_allowlisted":                     true,
		"webhook_destination_allowlisted":     true,
		"webhook_url_allowlisted":             true,
		"destination_non_allowlisted":         false,
		"hook_destination_non_allowlisted":    false,
		"hook_url_non_allowlisted":            false,
		"non_allowlisted_destination":         false,
		"url_non_allowlisted":                 false,
		"webhook_destination_non_allowlisted": false,
		"webhook_url_non_allowlisted":         false,
		"hook_id":                             99,
		"repo":                                "writer/cerebro",
	}
	attributes := auditEventForTest(t, "hook.config_changed", webhookAttrs, nil).Attributes
	for key := range webhookAttrs {
		if key == "hook_id" || key == "repo" {
			continue
		}
		if strings.TrimSpace(attributes[key]) == "" {
			t.Fatalf("%s was not forwarded; attributes=%v", key, attributes)
		}
	}

	rule := mustGitHubFindingRule(t, "github-webhook-modified")
	counterRule, ok := rule.(findingrules.CounterEventRule)
	if !ok {
		t.Fatal("github-webhook-modified does not implement CounterEventRule")
	}
	openEvent := auditEventForTest(t, "hook.config_changed", map[string]any{
		"destination_allowlisted": false,
		"hook_id":                 99,
		"repo":                    "writer/cerebro",
	}, nil)
	records, err := rule.Evaluate(context.Background(), githubAuditRuntimeForRuleTest(), openEvent)
	if err != nil {
		t.Fatalf("Evaluate(source-backed webhook open event) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(source-backed webhook open event) returned %d findings, want 1; attrs=%v", len(records), openEvent.Attributes)
	}
	openAnchor := counterRule.OpenAnchor(records[0].Attributes)
	closeEvent := auditEventForTest(t, "hook.config_changed", map[string]any{
		"destination_allowlisted": true,
		"hook_id":                 99,
		"repo":                    "writer/cerebro",
	}, nil)
	closeAnchor, closes := counterRule.CloseOnEvent(closeEvent)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(source-backed webhook allowlisted event) = (%q, %v), want (%q, true); attrs=%v", closeAnchor, closes, openAnchor, closeEvent.Attributes)
	}
}

func TestAuditAttributesSurfaceM3DurableStateFields(t *testing.T) {
	t.Run("integration installation prefers app id", func(t *testing.T) {
		attributes := auditEventAttributesForTest(t, "integration_installation.create", map[string]any{
			"installation": map[string]any{
				"app_id": 4242,
				"id":     1111,
			},
		})

		if got := attributes["github_app_id"]; got != "4242" {
			t.Fatalf("github_app_id = %q, want app_id 4242", got)
		}
	})

	t.Run("integration installation falls back to installation id", func(t *testing.T) {
		attributes := auditEventAttributesForTest(t, "integration_installation.create", map[string]any{
			"installation": map[string]any{
				"id": 1111,
			},
		})

		if got := attributes["github_app_id"]; got != "1111" {
			t.Fatalf("github_app_id = %q, want installation id fallback 1111", got)
		}
	})

	t.Run("secret scanning alert forwards resolution state and comment", func(t *testing.T) {
		attributes := auditEventAttributesForTest(t, "secret_scanning_alert.resolve", map[string]any{
			"secret_scanning_alert": map[string]any{
				"resolution":         "revoked",
				"resolution_comment": "rotated exposed token",
				"state":              "resolved",
			},
		})

		for key, want := range map[string]string{
			"secret_scanning_alert.resolution":         "revoked",
			"secret_scanning_alert.resolution_comment": "rotated exposed token",
			"secret_scanning_alert.state":              "resolved",
		} {
			if got := attributes[key]; got != want {
				t.Fatalf("%s = %q, want %q", key, got, want)
			}
		}
	})
}

func TestSecretScanningAuditEventFeedsFindingRule(t *testing.T) {
	rule, ok := findingrules.Builtin().Get("github-secret-scanning-alert-created")
	if !ok {
		t.Fatal("github-secret-scanning-alert-created rule is not registered")
	}
	counterRule, ok := rule.(findingrules.CounterEventRule)
	if !ok {
		t.Fatal("github-secret-scanning-alert-created rule does not implement CounterEventRule")
	}
	runtime := &cerebrov1.SourceRuntime{
		Id:       "example-github-secret-scanning-audit",
		SourceId: "github",
		TenantId: "writer",
		Config:   map[string]string{"family": "audit"},
	}

	openEvent := secretScanningAuditEventForRuleTest(t, "secret_scanning_alert.create", "open")
	if got := strings.TrimSpace(openEvent.Attributes["state"]); got != "" {
		t.Fatalf("source adapter emitted flat state = %q, want empty", got)
	}
	if got := openEvent.Attributes["secret_scanning_alert.state"]; got != "open" {
		t.Fatalf("source adapter emitted secret_scanning_alert.state = %q, want open", got)
	}
	records, err := rule.Evaluate(context.Background(), runtime, openEvent)
	if err != nil {
		t.Fatalf("Evaluate(source adapter open event) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(source adapter open event) returned %d findings, want 1", len(records))
	}
	openAnchor := counterRule.OpenAnchor(records[0].Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty, want repo/number anchor", records[0].Attributes)
	}

	for _, tc := range []struct {
		name   string
		action string
		state  string
	}{
		{name: "resolved", action: "secret_scanning_alert.resolve", state: "resolved"},
		{name: "revoked", action: "secret_scanning_alert.revoke", state: "revoked"},
		{name: "false_positive", action: "secret_scanning_alert.false_positive", state: "false_positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closeEvent := secretScanningAuditEventForRuleTest(t, tc.action, tc.state)
			records, err := rule.Evaluate(context.Background(), runtime, closeEvent)
			if err != nil {
				t.Fatalf("Evaluate(source adapter close event) error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("Evaluate(source adapter close event) returned %d findings, want 0", len(records))
			}
			closeAnchor, closes := counterRule.CloseOnEvent(closeEvent)
			if !closes || closeAnchor != openAnchor {
				t.Fatalf("CloseOnEvent(source adapter %s) = (%q, %v), want (%q, true)", tc.name, closeAnchor, closes, openAnchor)
			}
		})
	}
}

func auditEventAttributesForTest(t *testing.T, action string, additionalFields map[string]any) map[string]string {
	t.Helper()
	return auditEventForTest(t, action, additionalFields, nil).Attributes
}

func auditEventForTest(t *testing.T, action string, additionalFields map[string]any, mutate func(*gogithub.AuditEntry)) *cerebrov1.EventEnvelope {
	t.Helper()
	entry := &gogithub.AuditEntry{
		Action:           gogithub.String(action),
		DocumentID:       gogithub.String("audit-doc-" + strings.ReplaceAll(action, ".", "-")),
		Timestamp:        &gogithub.Timestamp{Time: time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)},
		AdditionalFields: additionalFields,
	}
	if mutate != nil {
		mutate(entry)
	}
	event, err := auditEvent(settings{owner: "writer"}, entry, auditActorResolution{})
	if err != nil {
		t.Fatalf("auditEvent() error = %v", err)
	}
	if event.Kind != "github.audit" {
		t.Fatalf("event.Kind = %q, want github.audit", event.Kind)
	}
	return event
}

func secretScanningAuditEventForRuleTest(t *testing.T, action string, state string) *cerebrov1.EventEnvelope {
	t.Helper()

	event, err := auditEvent(settings{owner: "writer"}, &gogithub.AuditEntry{
		Action:     gogithub.String(action),
		DocumentID: gogithub.String("audit-doc-" + action + "-" + state),
		Timestamp:  &gogithub.Timestamp{Time: time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)},
		AdditionalFields: map[string]any{
			"number":      12,
			"repo":        "writer/cerebro",
			"secret_type": "github_personal_access_token",
			"secret_scanning_alert": map[string]any{
				"state": state,
			},
		},
	}, auditActorResolution{})
	if err != nil {
		t.Fatalf("auditEvent() error = %v", err)
	}
	if event.Kind != "github.audit" {
		t.Fatalf("event.Kind = %q, want github.audit", event.Kind)
	}
	return event
}

func githubAuditRuntimeForRuleTest() *cerebrov1.SourceRuntime {
	return &cerebrov1.SourceRuntime{
		Id:       "example-github-audit",
		SourceId: "github",
		TenantId: "writer",
		Config:   map[string]string{"family": "audit"},
	}
}

func mustGitHubFindingRule(t *testing.T, id string) findingrules.Rule {
	t.Helper()
	rule, ok := findingrules.Builtin().Get(id)
	if !ok {
		t.Fatalf("%s rule is not registered", id)
	}
	return rule
}

func anyAuditEventHasAttribute(events []*cerebrov1.EventEnvelope, key string) bool {
	for _, event := range events {
		if strings.TrimSpace(event.GetAttributes()[key]) != "" {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
