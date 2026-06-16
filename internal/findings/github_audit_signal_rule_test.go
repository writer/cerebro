package findings

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func isRetiredGitHubAuditRule(rule Rule) bool {
	metadataRule, ok := rule.(MetadataRule)
	return ok && metadataRule.RuleMetadata().Lifecycle.Kind == LifecycleRetired
}

func assertGitHubAuditRuleRetired(t *testing.T, rule Rule) {
	t.Helper()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleRetired {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleRetired)
	}
	if definition.Lifecycle.Anchor != AnchorNone {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorNone)
	}
	if definition.Maturity != RuleMaturityRetired {
		t.Fatalf("Maturity = %q, want %q", definition.Maturity, RuleMaturityRetired)
	}
	retirementRule, ok := rule.(openFindingRetirementRule)
	if !ok || !retirementRule.RetiresOpenFindings() {
		t.Fatalf("RetiresOpenFindings(%q) = false, want true", rule.Spec().GetId())
	}
	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}}
	event := githubAuditEvent("retired-"+rule.Spec().GetId(), map[string]string{"action": "retired.rule.fixture"})
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(%q) error = %v", rule.Spec().GetId(), err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(%q) returned %d findings, want none", rule.Spec().GetId(), len(records))
	}
}

func TestGitHubRetiredAuditChangeRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule Rule
	}{
		{name: "repository collaborator", rule: newGitHubRepositoryCollaboratorAddedRule()},
		{name: "organization owner", rule: newGitHubOrganizationOwnerAddedRule()},
		{name: "org auth control", rule: newGitHubOrgAuthControlModifiedRule()},
		{name: "org IP allow list", rule: newGitHubOrgIPAllowListModifiedRule()},
		{name: "repository ruleset", rule: newGitHubRepositoryRulesetModifiedRule()},
		{name: "webhook", rule: newGitHubWebhookModifiedRule()},
		{name: "app integration", rule: newGitHubAppIntegrationInstalledRule()},
		{name: "personal access token", rule: newGitHubPersonalAccessTokenCreatedRule()},
		{name: "private repository forking", rule: newGitHubPrivateRepositoryForkingEnabledRule()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertGitHubAuditRuleRetired(t, tc.rule)
		})
	}

	t.Run("secret scanning audit anchor", func(t *testing.T) {
		rule := newGitHubSecretScanningAlertCreatedRule()
		metadataRule, ok := rule.(MetadataRule)
		if !ok {
			t.Fatal("rule does not expose RuleMetadata")
		}
		definition := metadataRule.RuleMetadata()
		for _, field := range []string{"repo", "number"} {
			if !slices.Contains(definition.RequiredAttributes, field) {
				t.Fatalf("RequiredAttributes = %v, want durable anchor field %q", definition.RequiredAttributes, field)
			}
		}
		if !slices.Contains(definition.RequiredAttributes, "secret_scanning_alert.state") {
			t.Fatalf("RequiredAttributes = %v, want canonical source-emitted state attribute", definition.RequiredAttributes)
		}
		if slices.Contains(definition.RequiredAttributes, "state") {
			t.Fatalf("RequiredAttributes = %v, must not require flat state attribute", definition.RequiredAttributes)
		}
		runtime := &cerebrov1.SourceRuntime{Id: "github-secret-scanning-runtime", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}}
		base := map[string]string{
			"action":                      "secret_scanning_alert.create",
			"number":                      "12",
			"repo":                        "writer/cerebro",
			"secret_scanning_alert.state": "open",
		}
		records, err := rule.Evaluate(context.Background(), runtime, githubAuditEvent("github-secret-alert-anchor-valid", cloneGitHubTestAttrs(base)))
		if err != nil || len(records) != 1 {
			t.Fatalf("Evaluate(valid secret-scanning anchor attrs) = (%v, %v), want one finding", records, err)
		}
		for _, missing := range []string{"repo", "number"} {
			attrs := cloneGitHubTestAttrs(base)
			delete(attrs, missing)
			records, err := rule.Evaluate(context.Background(), runtime, githubAuditEvent("github-secret-alert-anchor-missing-"+missing, attrs))
			if err != nil {
				t.Fatalf("Evaluate(secret scanning missing %s) error = %v", missing, err)
			}
			if len(records) != 0 {
				t.Fatalf("Evaluate(secret scanning missing %s) returned %d findings, want 0", missing, len(records))
			}
		}
		flatOnly := cloneGitHubTestAttrs(base)
		delete(flatOnly, "secret_scanning_alert.state")
		flatOnly["state"] = "open"
		records, err = rule.Evaluate(context.Background(), runtime, githubAuditEvent("github-secret-alert-flat-state-only", flatOnly))
		if err != nil {
			t.Fatalf("Evaluate(secret scanning flat state only) error = %v", err)
		}
		if len(records) != 0 {
			t.Fatalf("Evaluate(secret scanning flat state only) returned %d findings, want 0", len(records))
		}
	})
}

func TestGitHubSecretScanningAlertCreated(t *testing.T) {
	rule := newGitHubSecretScanningAlertCreatedRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorSourceState {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorSourceState)
	}
	if !cloudStringSlicesEqual(definition.EventKinds, []string{"github.audit"}) {
		t.Fatalf("EventKinds = %v, want github.audit events", definition.EventKinds)
	}
	wantFields := []string{"repo", "number"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	if !slices.Contains(definition.RequiredAttributes, "secret_scanning_alert.state") {
		t.Fatalf("RequiredAttributes = %v, want secret_scanning_alert.state", definition.RequiredAttributes)
	}
	if slices.Contains(definition.RequiredAttributes, "state") {
		t.Fatalf("RequiredAttributes = %v, must not include flat state", definition.RequiredAttributes)
	}
	for _, field := range definition.FingerprintFields {
		if field == "action" || field == "event_id" {
			t.Fatalf("FingerprintFields still contains %q: %v", field, definition.FingerprintFields)
		}
	}
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("github-secret-scanning-alert-created does not implement CounterEventRule")
	}

	runtime := &cerebrov1.SourceRuntime{Id: "example-github-secret-scanning", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}}
	first := githubAuditEvent("github-secret-alert-writer-cerebro-12", map[string]string{
		"action":                      "secret_scanning_alert.create",
		"audit_event_id":              "github-audit-secret-alert-created",
		"html_url":                    "https://github.com/writer/cerebro/security/secret-scanning/12",
		"number":                      "12",
		"repo":                        "writer/cerebro",
		"secret_type":                 "github_personal_access_token",
		"secret_scanning_alert.state": "open",
	})
	second := githubAuditEvent("github-secret-alert-writer-cerebro-12-second", map[string]string{
		"action":                      "secret_scanning_alert.reopen",
		"audit_event_id":              "github-audit-secret-alert-created-2",
		"number":                      "12",
		"repo":                        "writer/cerebro",
		"secret_type":                 "github_personal_access_token",
		"secret_scanning_alert.state": "open",
	})
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first open alert) = (%v, %v), want one finding", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second open alert) = (%v, %v), want one finding", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across source-state replays of same (repo, number): %q vs %q", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	for _, eventID := range []string{first.GetId(), second.GetId()} {
		if strings.Contains(firstFinding.Fingerprint, eventID) {
			t.Fatalf("fingerprint %q contains source event id %q", firstFinding.Fingerprint, eventID)
		}
	}
	if !slices.Contains(firstFinding.EventIDs, "github-audit-secret-alert-created") {
		t.Fatalf("EventIDs = %v, want audit_event_id preserved as finding evidence", firstFinding.EventIDs)
	}
	if got := firstFinding.Attributes["state"]; got != "open" {
		t.Fatalf("Attributes[state] = %q, want open", got)
	}
	if got := firstFinding.Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:github_secret_scanning_alert:writer/cerebro:12" {
		t.Fatalf("primary_resource_urn = %q, want secret scanning alert source-state anchor", got)
	}
	if !slices.Contains(firstFinding.ResourceURNs, "urn:cerebro:writer:github_code_repository:writer/cerebro") {
		t.Fatalf("ResourceURNs = %v, want repo context retained", firstFinding.ResourceURNs)
	}
	openAnchor := counterRule.OpenAnchor(firstFinding.Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty, want repo/number anchor", firstFinding.Attributes)
	}
	closeAnchor, closes := counterRule.CloseOnEvent(githubAuditEvent("github-secret-alert-close-anchor", map[string]string{
		"action":                      "secret_scanning_alert.resolve",
		"number":                      "12",
		"repo":                        "writer/cerebro",
		"secret_scanning_alert.state": "resolved",
	}))
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(resolve) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}
	closeAnchor, closes = counterRule.CloseOnEvent(githubAuditEvent("github-secret-alert-close-flat-state-only", map[string]string{
		"action": "secret_scanning_alert.resolve",
		"number": "12",
		"repo":   "writer/cerebro",
		"state":  "resolved",
	}))
	if closes || closeAnchor != "" {
		t.Fatalf("CloseOnEvent(flat state only) = (%q, %v), want no close", closeAnchor, closes)
	}

	for _, tc := range []struct {
		action string
		state  string
	}{
		{action: "secret_scanning_alert.resolve", state: "resolved"},
		{action: "secret_scanning_alert.revoke", state: "revoked"},
		{action: "secret_scanning_alert.false_positive", state: "false_positive"},
	} {
		event := githubAuditEvent("github-secret-alert-"+strings.TrimPrefix(tc.action, "secret_scanning_alert."), map[string]string{
			"action":                      tc.action,
			"number":                      "12",
			"repo":                        "writer/cerebro",
			"secret_scanning_alert.state": tc.state,
		})
		records, err = rule.Evaluate(context.Background(), runtime, event)
		if err != nil {
			t.Fatalf("Evaluate(%s) error = %v", tc.action, err)
		}
		if len(records) != 0 {
			t.Fatalf("Evaluate(%s) returned %d findings, want 0 once alert is not open", tc.action, len(records))
		}
	}

	sourceStateEvent := githubSecretScanningAlertEvent("github-secret-scanning-source-state-open", map[string]string{
		"number": "12",
		"repo":   "writer/cerebro",
		"state":  "open",
	})
	records, err = rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "example-github-source-state", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "secret_scanning_alert"}}, sourceStateEvent)
	if err != nil {
		t.Fatalf("Evaluate(source-state event) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(source-state event) returned %d findings, want 0 because sources/github only emits github.audit for secret scanning audit data", len(records))
	}
}

func TestGitHubSecretScanningAlertCreatedTrajectory(t *testing.T) {
	rule := newGitHubSecretScanningAlertCreatedRule()
	if _, ok := rule.(CounterEventRule); !ok {
		t.Fatal("github-secret-scanning-alert-created does not implement CounterEventRule")
	}
	for _, tc := range []struct {
		name        string
		closeAction string
		state       string
		resolution  string
	}{
		{name: "resolve", closeAction: "secret_scanning_alert.resolve", state: "resolved", resolution: "resolved"},
		{name: "revoke", closeAction: "secret_scanning_alert.revoke", state: "revoked", resolution: "revoked"},
		{name: "false_positive", closeAction: "secret_scanning_alert.false_positive", state: "false_positive", resolution: "false_positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertGitHubRuleTrajectory(t, rule, []Event{
				newGitHubAuditSignalEvent("github-secret-scanning-trajectory-open-"+tc.name, map[string]string{
					"action":                      "secret_scanning_alert.create",
					"audit_event_id":              "github-audit-secret-scanning-trajectory-open-" + tc.name,
					"html_url":                    "https://github.com/writer/cerebro/security/secret-scanning/12",
					"number":                      "12",
					"repo":                        "writer/cerebro",
					"secret_type":                 "github_personal_access_token",
					"secret_scanning_alert.state": "open",
				}),
				newGitHubAuditSignalEvent("github-secret-scanning-trajectory-close-"+tc.name, map[string]string{
					"action":                           tc.closeAction,
					"number":                           "12",
					"repo":                             "writer/cerebro",
					"secret_scanning_alert.resolution": tc.resolution,
					"secret_scanning_alert.state":      tc.state,
				}),
			}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
		})
	}
}

func TestGitHubSelfHostedRunnerChange(t *testing.T) {
	rule := newGitHubSelfHostedRunnerChangeRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleRetired {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleRetired)
	}
	retirementRule, ok := rule.(openFindingRetirementRule)
	if !ok || !retirementRule.RetiresOpenFindings() {
		t.Fatal("github-self-hosted-runner-change does not retire open findings")
	}

	runtime := &cerebrov1.SourceRuntime{Id: "example-github-audit", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}}
	event := githubAuditEvent("github-runner-register", map[string]string{
		"action":            "repo.register_self_hosted_runner",
		"repo":              "writer/cerebro",
		"resource_id":       "writer/cerebro",
		"resource_type":     "repo",
		"runner_ephemeral":  "false",
		"runner_id":         "777",
		"runner_name":       "prod-runner-1",
		"runner_registered": "true",
	})
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(retired runner rule) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(retired runner rule) returned %d findings, want 0", len(records))
	}
}

func TestGitHubOrgAuthControlModified(t *testing.T) {
	rule := newGitHubOrgAuthControlModifiedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"org"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "action" || field == "event_id" {
			t.Fatalf("FingerprintFields still contains %q: %v", field, definition.FingerprintFields)
		}
	}

	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	first := githubAuditEvent("github-auth-two-factor-disabled", map[string]string{
		"action":                         "org.disable_two_factor_requirement",
		"org":                            "writer",
		"resource_id":                    "writer",
		"resource_type":                  "org",
		"two_factor_requirement_enabled": "false",
	})
	second := githubAuditEvent("github-auth-oauth-disabled", map[string]string{
		"action":                         "org.disable_oauth_app_restrictions",
		"org":                            "writer",
		"resource_id":                    "writer",
		"resource_type":                  "org",
		"oauth_app_restrictions_enabled": "false",
	})
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one finding", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one finding", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across weakened auth controls on same org: %q vs %q", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	if got := firstFinding.Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:github_org:writer" {
		t.Fatalf("primary_resource_urn = %q, want github org anchor", got)
	}
	if got := firstFinding.Severity; got != "CRITICAL" {
		t.Fatalf("Severity = %q, want CRITICAL", got)
	}

	restored := githubAuditEvent("github-auth-restored", map[string]string{
		"action":                         "org.disable_two_factor_requirement",
		"org":                            "writer",
		"resource_id":                    "writer",
		"resource_type":                  "org",
		"oauth_app_restrictions_enabled": "true",
		"saml_enabled":                   "true",
		"two_factor_requirement_enabled": "true",
	})
	records, err = rule.Evaluate(context.Background(), runtime, restored)
	if err != nil {
		t.Fatalf("Evaluate(restored) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(restored) returned %d findings, want 0 once org auth controls are re-strengthened", len(records))
	}
}

func TestGitHubOrgAuthControlModifiedTrajectory_Restore(t *testing.T) {
	rule := newGitHubOrgAuthControlModifiedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	assertGitHubRuleTrajectory(t, rule, []Event{
		newGitHubAuditSignalEvent("github-auth-trajectory-weakened", map[string]string{
			"action":                         "oauth_app_policy.disabled",
			"oauth_app_restrictions_enabled": "false",
			"org":                            "writer",
			"resource_id":                    "writer",
			"resource_type":                  "org",
		}),
		newGitHubAuditSignalEvent("github-auth-trajectory-restored", map[string]string{
			"action":                         "oauth_app_policy.enabled",
			"oauth_app_restrictions_enabled": "true",
			"org":                            "writer",
			"resource_id":                    "writer",
			"resource_type":                  "org",
			"saml_enabled":                   "true",
			"two_factor_requirement_enabled": "true",
		}),
	}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestGitHubOrgAuthControlModifiedTrajectory_PartialRestoreKeepsFindingOpen(t *testing.T) {
	rule := newGitHubOrgAuthControlModifiedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	assertGitHubRuleTrajectory(t, rule, []Event{
		newGitHubAuditSignalEvent("github-auth-partial-oauth-weakened", map[string]string{
			"action":                         "oauth_app_policy.disabled",
			"oauth_app_restrictions_enabled": "false",
			"org":                            "writer",
			"resource_id":                    "writer",
			"resource_type":                  "org",
		}),
		newGitHubAuditSignalEvent("github-auth-partial-2fa-weakened", map[string]string{
			"action":                         "org.disable_two_factor_requirement",
			"org":                            "writer",
			"resource_id":                    "writer",
			"resource_type":                  "org",
			"two_factor_requirement_enabled": "false",
		}),
		newGitHubAuditSignalEvent("github-auth-partial-oauth-restored", map[string]string{
			"action":                         "oauth_app_policy.enabled",
			"oauth_app_restrictions_enabled": "true",
			"org":                            "writer",
			"resource_id":                    "writer",
			"resource_type":                  "org",
		}),
	}, cerebrov1.FindingStatus_FINDING_STATUS_OPEN)
}

func TestGitHubRepositoryRulesetModifiedRequiresWeakeningSignal(t *testing.T) {
	rule := newGitHubRepositoryRulesetModifiedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	event := githubAuditEvent("github-ruleset-active", map[string]string{
		"action":      "repository_ruleset.update",
		"enforcement": "active",
		"repo":        "writer/cerebro",
		"ruleset_id":  "42",
	})
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(active update) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(active update records) = %d, want 0", len(records))
	}

	event = githubAuditEvent("github-ruleset-check-removed", map[string]string{
		"action":                        "repository_ruleset.update",
		"enforcement":                   "active",
		"required_status_check_removed": "true",
		"repo":                          "writer/cerebro",
		"ruleset_id":                    "42",
	})
	records, err = rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(required status check removed) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(required status check removed records) = %d, want 1", len(records))
	}

	event = githubAuditEvent("github-ruleset-disabled", map[string]string{
		"action":      "repository_ruleset.update",
		"enforcement": "disabled",
		"repo":        "writer/cerebro",
		"ruleset_id":  "42",
	})
	records, err = rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(disabled update) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(disabled update records) = %d, want 1", len(records))
	}
}

func TestGitHubOrgIpAllowListModified(t *testing.T) {
	rule := newGitHubOrgIPAllowListModifiedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"org"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "action" || field == "event_id" {
			t.Fatalf("FingerprintFields still contains %q: %v", field, definition.FingerprintFields)
		}
	}

	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	first := githubAuditEvent("github-ip-disabled", map[string]string{
		"action":                "ip_allow_list.disable",
		"ip_allow_list_enabled": "false",
		"org":                   "writer",
		"resource_id":           "writer",
		"resource_type":         "ip_allow_list",
	})
	second := githubAuditEvent("github-ip-non-allowlisted-cidr", map[string]string{
		"action":                "ip_allow_list_entry.create",
		"ip_allow_list_enabled": "true",
		"non_allowlisted_cidrs": "203.0.113.0/24",
		"org":                   "writer",
		"resource_id":           "writer",
		"resource_type":         "ip_allow_list",
	})
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one finding", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one finding", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across allow-list posture events on same org: %q vs %q", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	if got := firstFinding.Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:github_org:writer" {
		t.Fatalf("primary_resource_urn = %q, want github org anchor", got)
	}
	if got := firstFinding.Severity; got != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH", got)
	}

	restored := githubAuditEvent("github-ip-compliant", map[string]string{
		"action":                "ip_allow_list.disable",
		"ip_allow_list_enabled": "true",
		"org":                   "writer",
		"resource_id":           "writer",
		"resource_type":         "ip_allow_list",
	})
	records, err = rule.Evaluate(context.Background(), runtime, restored)
	if err != nil {
		t.Fatalf("Evaluate(restored) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(restored) returned %d findings, want 0 once allow-list is compliant", len(records))
	}
}

func TestGitHubOrgIpAllowListModifiedTrajectory_Restore(t *testing.T) {
	rule := newGitHubOrgIPAllowListModifiedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	assertGitHubRuleTrajectory(t, rule, []Event{
		newGitHubAuditSignalEvent("github-ip-trajectory-disabled", map[string]string{
			"action":                "ip_allow_list.disable",
			"ip_allow_list_enabled": "false",
			"org":                   "writer",
			"resource_id":           "writer",
			"resource_type":         "ip_allow_list",
		}),
		newGitHubAuditSignalEvent("github-ip-trajectory-restored", map[string]string{
			"action":                          "ip_allow_list.enabled",
			"allowed_cidrs_compliant":         "true",
			"ip_allow_list_enabled":           "true",
			"ip_allow_list_entries_compliant": "true",
			"non_allowlisted_cidr_count":      "0",
			"org":                             "writer",
			"resource_id":                     "writer",
			"resource_type":                   "ip_allow_list",
		}),
	}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestGitHubOrgIpAllowListModifiedTrajectory_PartialRestoreKeepsFindingOpen(t *testing.T) {
	rule := newGitHubOrgIPAllowListModifiedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	assertGitHubRuleTrajectory(t, rule, []Event{
		newGitHubAuditSignalEvent("github-ip-partial-disabled", map[string]string{
			"action":                "ip_allow_list.disable",
			"ip_allow_list_enabled": "false",
			"org":                   "writer",
			"resource_id":           "writer",
			"resource_type":         "ip_allow_list",
		}),
		newGitHubAuditSignalEvent("github-ip-partial-cidr-open", map[string]string{
			"action":                "ip_allow_list_entry.create",
			"ip_allow_list_enabled": "true",
			"non_allowlisted_cidrs": "203.0.113.0/24",
			"org":                   "writer",
			"resource_id":           "writer",
			"resource_type":         "ip_allow_list",
		}),
		newGitHubAuditSignalEvent("github-ip-partial-enabled", map[string]string{
			"action":                "ip_allow_list.enabled",
			"ip_allow_list_enabled": "true",
			"org":                   "writer",
			"resource_id":           "writer",
			"resource_type":         "ip_allow_list",
		}),
	}, cerebrov1.FindingStatus_FINDING_STATUS_OPEN)
}

func TestGitHubCodeSecurityControlsDisabled(t *testing.T) {
	rule := newGitHubCodeSecurityControlsDisabledRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"repo", "org"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "action" || field == "resource_id" || field == "event_id" {
			t.Fatalf("FingerprintFields still contains %q: %v", field, definition.FingerprintFields)
		}
	}

	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "example"}
	first := githubAuditEvent("github-dependabot-disabled", map[string]string{
		"action":                    "dependabot_alerts.disable",
		"dependabot_alerts_enabled": "false",
		"org":                       "example",
		"repo":                      "example/cerebro",
		"resource_id":               "example/cerebro",
		"resource_type":             "repository",
	})
	second := githubAuditEvent("github-secret-scanning-disabled", map[string]string{
		"action":                  "repository_secret_scanning.disable",
		"org":                     "example",
		"repo":                    "example/cerebro",
		"resource_id":             "example/cerebro",
		"resource_type":           "repository",
		"secret_scanning_enabled": "false",
	})
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one finding", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one finding", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across disabled controls on same repo: %q vs %q", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	if got := firstFinding.RuleID; got != githubCodeSecurityControlsDisabledRuleID {
		t.Fatalf("RuleID = %q, want %q", got, githubCodeSecurityControlsDisabledRuleID)
	}
	if got := firstFinding.Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:github_code_repository:example/cerebro" {
		t.Fatalf("primary_resource_urn = %q, want github repo anchor", got)
	}

	restored := githubAuditEvent("github-code-security-enabled", map[string]string{
		"action":                              "dependabot_alerts.disable",
		"advanced_security_enabled":           "true",
		"dependabot_alerts_enabled":           "true",
		"dependabot_security_updates_enabled": "true",
		"org":                                 "example",
		"repo":                                "example/cerebro",
		"resource_id":                         "example/cerebro",
		"resource_type":                       "repository",
		"secret_scanning_enabled":             "true",
		"vulnerability_alerts_enabled":        "true",
	})
	records, err = rule.Evaluate(context.Background(), runtime, restored)
	if err != nil {
		t.Fatalf("Evaluate(restored) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(restored) returned %d findings, want 0 once all code security controls are enabled", len(records))
	}

	orgDisabled := githubAuditEvent("github-org-code-security-disabled", map[string]string{
		"action":                    "org.advanced_security_disabled_on_all_repos",
		"advanced_security_enabled": "false",
		"org":                       "example",
		"resource_id":               "example",
		"resource_type":             "org",
		"scope":                     "organization",
	})
	records, err = rule.Evaluate(context.Background(), runtime, orgDisabled)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(orgDisabled) = (%v, %v), want one org-anchored finding", records, err)
	}
	orgFinding := records[0]
	if got := orgFinding.Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:github_org:example" {
		t.Fatalf("org primary_resource_urn = %q, want github org anchor", got)
	}
	if orgFinding.Fingerprint == firstFinding.Fingerprint {
		t.Fatalf("org-scope fingerprint = repo-scope fingerprint %q, want distinct anchors", orgFinding.Fingerprint)
	}
}

func TestGitHubCodeSecurityControlsDisabledTrajectory_DisableEnable(t *testing.T) {
	rule := newGitHubCodeSecurityControlsDisabledRule()
	if _, ok := rule.(CounterEventRule); !ok {
		t.Fatal("github-code-security-controls-disabled does not implement CounterEventRule")
	}
	assertGitHubRuleTrajectory(t, rule, []Event{
		newGitHubAuditSignalEvent("github-code-security-trajectory-disabled", map[string]string{
			"action": "repository_vulnerability_alerts.disable",
			"org":    "writer",
			"repo":   "writer/cerebro",
			"repository_vulnerability_alerts_enabled": "false",
			"resource_id":   "writer/cerebro",
			"resource_type": "repository",
		}),
		newGitHubAuditSignalEvent("github-code-security-trajectory-restored", map[string]string{
			"action":                              "repository_vulnerability_alerts.enable",
			"advanced_security_enabled":           "true",
			"dependabot_alerts_enabled":           "true",
			"dependabot_security_updates_enabled": "true",
			"org":                                 "writer",
			"repo":                                "writer/cerebro",
			"repository_secret_scanning_enabled":  "true",
			"repository_vulnerability_alerts_enabled": "true",
			"resource_id":   "writer/cerebro",
			"resource_type": "repository",
			"secret_scanning_push_protection_enabled": "true",
		}),
	}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestGitHubCodeSecurityControlsDisabledTrajectory_OrgScopeDisableEnable(t *testing.T) {
	rule := newGitHubCodeSecurityControlsDisabledRule()
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("github-code-security-controls-disabled does not implement CounterEventRule")
	}
	restored := newGitHubAuditSignalEvent("github-org-code-security-trajectory-restored", map[string]string{
		"action":                                  "org.advanced_security_enabled_on_all_repos",
		"advanced_security_enabled":               "true",
		"code_security_enabled":                   "true",
		"dependabot_alerts_enabled":               "true",
		"dependabot_security_updates_enabled":     "true",
		"org":                                     "writer",
		"repository_secret_scanning_enabled":      "true",
		"repository_vulnerability_alerts_enabled": "true",
		"resource_id":                             "writer",
		"resource_type":                           "org",
		"scope":                                   "organization",
		"secret_scanning_push_protection_enabled": "true",
	})
	if anchor, closes := counterRule.CloseOnEvent(restored); !closes || anchor != "org=writer" {
		t.Fatalf("CloseOnEvent(org restored) = (%q, %v), want (org=writer, true)", anchor, closes)
	}
	assertGitHubRuleTrajectory(t, rule, []Event{
		newGitHubAuditSignalEvent("github-org-code-security-trajectory-disabled", map[string]string{
			"action":                    "org.advanced_security_disabled_on_all_repos",
			"advanced_security_enabled": "false",
			"org":                       "writer",
			"resource_id":               "writer",
			"resource_type":             "org",
			"scope":                     "organization",
		}),
		restored,
	}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestGitHubCodeSecurityControlsDisabledScopeRequiredAttributes(t *testing.T) {
	rule := newGitHubCodeSecurityControlsDisabledRule()
	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	for _, tc := range []struct {
		name  string
		attrs map[string]string
	}{
		{
			name: "repo scope requires repo",
			attrs: map[string]string{
				"action": "repository_vulnerability_alerts.disable",
				"org":    "writer",
				"repository_vulnerability_alerts_enabled": "false",
				"resource_id":   "writer/cerebro",
				"resource_type": "repository",
				"scope":         "repository",
			},
		},
		{
			name: "repo shaped resource id requires repo",
			attrs: map[string]string{
				"action": "repository_vulnerability_alerts.disable",
				"org":    "writer",
				"repository_vulnerability_alerts_enabled": "false",
				"resource_id":   "writer/cerebro",
				"resource_type": "repository",
			},
		},
		{
			name: "org scope requires org",
			attrs: map[string]string{
				"action":                    "org.advanced_security_disabled_on_all_repos",
				"advanced_security_enabled": "false",
				"resource_id":               "writer",
				"resource_type":             "org",
				"scope":                     "organization",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, err := rule.Evaluate(context.Background(), runtime, githubAuditEvent("github-code-security-"+strings.ReplaceAll(tc.name, " ", "-"), cloneGitHubTestAttrs(tc.attrs)))
			if err != nil {
				t.Fatalf("Evaluate(%s) error = %v", tc.name, err)
			}
			if len(records) != 0 {
				t.Fatalf("Evaluate(%s) returned %d findings, want 0 when the scope anchor attribute is missing", tc.name, len(records))
			}
		})
	}
}

func TestGitHubCodeSecurityControlsDisabledTrajectory_PartialRestoreKeepsFindingOpen(t *testing.T) {
	rule := newGitHubCodeSecurityControlsDisabledRule()
	if _, ok := rule.(CounterEventRule); !ok {
		t.Fatal("github-code-security-controls-disabled does not implement CounterEventRule")
	}
	assertGitHubRuleTrajectory(t, rule, []Event{
		newGitHubAuditSignalEvent("github-code-security-partial-dependabot-disabled", map[string]string{
			"action":                    "dependabot_alerts.disable",
			"dependabot_alerts_enabled": "false",
			"org":                       "writer",
			"repo":                      "writer/cerebro",
			"resource_id":               "writer/cerebro",
			"resource_type":             "repository",
		}),
		newGitHubAuditSignalEvent("github-code-security-partial-secret-scanning-disabled", map[string]string{
			"action":                             "repository_secret_scanning.disable",
			"org":                                "writer",
			"repo":                               "writer/cerebro",
			"repository_secret_scanning_enabled": "false",
			"resource_id":                        "writer/cerebro",
			"resource_type":                      "repository",
		}),
		newGitHubAuditSignalEvent("github-code-security-partial-dependabot-enabled", map[string]string{
			"action":                    "dependabot_alerts.enable",
			"dependabot_alerts_enabled": "true",
			"org":                       "writer",
			"repo":                      "writer/cerebro",
			"resource_id":               "writer/cerebro",
			"resource_type":             "repository",
		}),
	}, cerebrov1.FindingStatus_FINDING_STATUS_OPEN)
}

func TestGitHubCodeSecurityControlsDisabledTrajectory_ClosesPerRepoAnchor(t *testing.T) {
	rule := newGitHubCodeSecurityControlsDisabledRule()
	if _, ok := rule.(CounterEventRule); !ok {
		t.Fatal("github-code-security-controls-disabled does not implement CounterEventRule")
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeID := "example-github-audit"
	events := []Event{
		newGitHubAuditSignalEvent("github-code-security-api-disabled", map[string]string{
			"action":                            "dependabot_alerts.disable",
			"dependabot_alerts_enabled":         "false",
			"org":                               "writer",
			"repo":                              "writer/api",
			"resource_id":                       "writer/api",
			"resource_type":                     "repository",
			ports.EventAttributeSourceRuntimeID: runtimeID,
		}),
		newGitHubAuditSignalEvent("github-code-security-web-disabled", map[string]string{
			"action":                            "repository_secret_scanning.disable",
			"org":                               "writer",
			"repo":                              "writer/web",
			"resource_id":                       "writer/web",
			"resource_type":                     "repository",
			"secret_scanning_enabled":           "false",
			ports.EventAttributeSourceRuntimeID: runtimeID,
		}),
		newGitHubAuditSignalEvent("github-code-security-api-enabled", map[string]string{
			"action":                            "dependabot_alerts.enable",
			"dependabot_alerts_enabled":         "true",
			"org":                               "writer",
			"repo":                              "writer/api",
			"resource_id":                       "writer/api",
			"resource_type":                     "repository",
			ports.EventAttributeSourceRuntimeID: runtimeID,
		}),
	}
	store := &stubFindingStore{}
	appendLog := &recordingAppendLog{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {Id: runtimeID, SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}},
		}},
		&stubReplayer{events: events},
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(&stubGraphStore{}).WithAppendLog(appendLog)

	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{githubCodeSecurityControlsDisabledRuleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
	}
	if result == nil || len(result.Evaluations) != 1 {
		t.Fatalf("evaluations = %v, want one evaluation", result)
	}
	if got := len(result.Evaluations[0].Findings); got != 2 {
		t.Fatalf("len(emitted findings) = %d, want 2 opening findings", got)
	}
	findings := githubTrajectoryPersistedFindings(store, githubCodeSecurityControlsDisabledRuleID, runtimeID)
	if got := len(findings); got != 2 {
		t.Fatalf("persisted findings = %d, want 2", got)
	}
	byRepo := map[string]*ports.FindingRecord{}
	for _, finding := range findings {
		byRepo[strings.TrimSpace(finding.Attributes["repo"])] = finding
	}
	if got := byRepo["writer/api"]; got == nil || got.Status != findingStatusResolved {
		t.Fatalf("writer/api status = %#v, want resolved", got)
	}
	if got := byRepo["writer/web"]; got == nil || got.Status != findingStatusOpen {
		t.Fatalf("writer/web status = %#v, want open", got)
	}
	if !containsTrimmed(byRepo["writer/api"].EventIDs, "github-code-security-api-enabled") {
		t.Fatalf("writer/api EventIDs = %#v, want close-event evidence", byRepo["writer/api"].EventIDs)
	}
	if containsTrimmed(byRepo["writer/web"].EventIDs, "github-code-security-api-enabled") {
		t.Fatalf("writer/web EventIDs = %#v, want no evidence from writer/api close event", byRepo["writer/web"].EventIDs)
	}
}

func TestGitHubCriticalResourceDeletedRetired(t *testing.T) {
	rule := newGitHubCriticalResourceDeletedRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleRetired {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleRetired)
	}
	if definition.Lifecycle.Anchor != AnchorNone {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorNone)
	}
	if definition.Maturity != "retired" {
		t.Fatalf("Maturity = %q, want retired", definition.Maturity)
	}
	retirementRule, ok := rule.(openFindingRetirementRule)
	if !ok || !retirementRule.RetiresOpenFindings() {
		t.Fatalf("RetiresOpenFindings() = false, want true so stale findings under %q are resolved", githubCriticalResourceDeletedRuleID)
	}

	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	for _, action := range []string{"repo.destroy", "environment.delete"} {
		event := githubAuditEvent("github-"+action, map[string]string{
			"action": action,
			"repo":   "writer/cerebro",
		})
		records, err := rule.Evaluate(context.Background(), runtime, event)
		if err != nil {
			t.Fatalf("Evaluate(%s) error = %v", action, err)
		}
		if len(records) != 0 {
			t.Fatalf("len(%s records) = %d, want 0 for retired rule", action, len(records))
		}
	}
}

func TestGitHubRepositoryCollaboratorAdded(t *testing.T) {
	rule := newGitHubRepositoryCollaboratorAddedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"repo", "user"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "action" {
			t.Fatalf("FingerprintFields still contains action: %v", definition.FingerprintFields)
		}
	}

	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	first := githubAuditEvent("github-collab-first", map[string]string{
		"action": "repo.add_member",
		"repo":   "writer/cerebro",
		"user":   "external-vendor",
	})
	second := githubAuditEvent("github-collab-second", map[string]string{
		"action": "repo.add_member",
		"repo":   "writer/cerebro",
		"user":   "external-vendor",
	})
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one record", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one record", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across replays: %q vs %q (should be anchored to (repo, user))", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	for _, eventID := range []string{first.GetId(), second.GetId()} {
		if strings.Contains(firstFinding.Fingerprint, eventID) {
			t.Fatalf("fingerprint %q contains event id %q", firstFinding.Fingerprint, eventID)
		}
	}

	removal := githubAuditEvent("github-collab-removed", map[string]string{
		"action": "repo.remove_member",
		"repo":   "writer/cerebro",
		"user":   "external-vendor",
	})
	records, err = rule.Evaluate(context.Background(), runtime, removal)
	if err != nil {
		t.Fatalf("Evaluate(remove) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(remove) returned %d findings, want 0 once collaborator removed", len(records))
	}
}

func TestGitHubRepositoryCollaboratorAddedTrajectory(t *testing.T) {
	rule := newGitHubRepositoryCollaboratorAddedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	assertGitHubRuleTrajectory(t, rule, []Event{
		newGitHubAuditSignalEvent("github-collab-trajectory-first", map[string]string{
			"action":        "repo.add_member",
			"repo":          "writer/cerebro",
			"resource_type": "repo",
			"user":          "external-vendor",
		}),
		newGitHubAuditSignalEvent("github-collab-trajectory-removed", map[string]string{
			"action":        "member.removed",
			"repo":          "writer/cerebro",
			"resource_type": "repo",
			"user":          "external-vendor",
		}),
	}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestGitHubAuditLifecycle_CloseOnRemoveCounterEvent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rule   Rule
		events []Event
	}{
		{
			name: "repository collaborator removed",
			rule: newGitHubRepositoryCollaboratorAddedRule(),
			events: []Event{
				newGitHubAuditSignalEvent("github-lifecycle-collab-open", map[string]string{
					"action":        "repo.add_member",
					"repo":          "writer/cerebro",
					"resource_type": "repo",
					"user":          "external-vendor",
				}),
				newGitHubAuditSignalEvent("github-lifecycle-collab-remove", map[string]string{
					"action":        "repo.remove_member",
					"repo":          "writer/cerebro",
					"resource_type": "repo",
					"user":          "external-vendor",
				}),
			},
		},
		{
			name: "organization owner removed",
			rule: newGitHubOrganizationOwnerAddedRule(),
			events: []Event{
				newGitHubAuditSignalEvent("github-lifecycle-owner-open", map[string]string{
					"action":     "org.add_member",
					"org":        "writer",
					"permission": "owner",
					"user":       "new-owner",
				}),
				newGitHubAuditSignalEvent("github-lifecycle-owner-remove", map[string]string{
					"action": "org.remove_member",
					"org":    "writer",
					"user":   "new-owner",
				}),
			},
		},
		{
			name: "app integration deleted",
			rule: newGitHubAppIntegrationInstalledRule(),
			events: []Event{
				newGitHubAuditSignalEvent("github-lifecycle-app-open", map[string]string{
					"action":        "integration_installation.create",
					"github_app_id": "123456",
					"name":          "ci-deployer",
					"org":           "writer",
					"repo":          "writer/cerebro",
				}),
				newGitHubAuditSignalEvent("github-lifecycle-app-delete", map[string]string{
					"action":        "integration_installation.delete",
					"github_app_id": "123456",
					"name":          "ci-deployer",
					"org":           "writer",
				}),
			},
		},
		{
			name: "personal access token revoked",
			rule: newGitHubPersonalAccessTokenCreatedRule(),
			events: []Event{
				newGitHubAuditSignalEvent("github-lifecycle-pat-open", map[string]string{
					"action":         "personal_access_token.access_granted",
					"operation_type": "create",
					"resource_id":    "octocat",
					"resource_type":  "personal_access_token",
					"token_id":       "555",
					"user":           "octocat",
					"user_id":        "12345",
				}),
				newGitHubAuditSignalEvent("github-lifecycle-pat-revoke", map[string]string{
					"action":        "personal_access_token.access_revoked",
					"resource_id":   "octocat",
					"resource_type": "personal_access_token",
					"token_id":      "555",
					"user":          "octocat",
					"user_id":       "12345",
				}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertGitHubAuditMirrorReplayClosed(t, tc.rule, tc.events)
		})
	}
}

func TestGitHubOrganizationOwnerAdded(t *testing.T) {
	rule := newGitHubOrganizationOwnerAddedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"org", "user"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "action" {
			t.Fatalf("FingerprintFields still contains action: %v", definition.FingerprintFields)
		}
	}

	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	first := githubAuditEvent("github-owner-first", map[string]string{
		"action":     "org.add_member",
		"org":        "writer",
		"permission": "admin",
		"user":       "new-owner",
	})
	second := githubAuditEvent("github-owner-second", map[string]string{
		"action":     "org.add_member",
		"org":        "writer",
		"permission": "admin",
		"user":       "new-owner",
	})
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one record", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one record", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across replays: %q vs %q (should be anchored to (org, user))", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	for _, eventID := range []string{first.GetId(), second.GetId()} {
		if strings.Contains(firstFinding.Fingerprint, eventID) {
			t.Fatalf("fingerprint %q contains event id %q", firstFinding.Fingerprint, eventID)
		}
	}

	demotion := githubAuditEvent("github-owner-demoted", map[string]string{
		"action":     "org.add_member",
		"org":        "writer",
		"permission": "member",
		"user":       "new-owner",
	})
	records, err = rule.Evaluate(context.Background(), runtime, demotion)
	if err != nil {
		t.Fatalf("Evaluate(demoted) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(demoted) returned %d findings, want 0 once owner privilege revoked", len(records))
	}
}

func TestGitHubOrganizationOwnerAddedTrajectory(t *testing.T) {
	rule := newGitHubOrganizationOwnerAddedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	t.Run("owner role demoted", func(t *testing.T) {
		assertGitHubRuleTrajectory(t, rule, []Event{
			newGitHubAuditSignalEvent("github-owner-trajectory-first", map[string]string{
				"action":     "org.add_member",
				"org":        "writer",
				"permission": "admin",
				"user":       "new-owner",
			}),
			newGitHubAuditSignalEvent("github-owner-trajectory-demoted", map[string]string{
				"action":     "org.add_member",
				"org":        "writer",
				"permission": "member",
				"user":       "new-owner",
			}),
		}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	})
	t.Run("member removed", func(t *testing.T) {
		assertGitHubRuleTrajectory(t, rule, []Event{
			newGitHubAuditSignalEvent("github-owner-trajectory-second", map[string]string{
				"action":     "org.add_member",
				"org":        "writer",
				"permission": "owner",
				"user":       "new-owner",
			}),
			newGitHubAuditSignalEvent("github-owner-trajectory-removed", map[string]string{
				"action": "member.removed",
				"org":    "writer",
				"user":   "new-owner",
			}),
		}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	})
}

func TestGitHubRepositoryRulesetModified(t *testing.T) {
	rule := newGitHubRepositoryRulesetModifiedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"repo", "ruleset_id"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "action" {
			t.Fatalf("FingerprintFields still contains action: %v", definition.FingerprintFields)
		}
	}

	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	first := githubAuditEvent("github-ruleset-first", map[string]string{
		"action":                        "repository_ruleset.update",
		"enforcement":                   "active",
		"repo":                          "writer/cerebro",
		"required_status_check_removed": "true",
		"ruleset_id":                    "42",
	})
	second := githubAuditEvent("github-ruleset-second", map[string]string{
		"action":      "repository_ruleset.destroy",
		"enforcement": "disabled",
		"repo":        "writer/cerebro",
		"ruleset_id":  "42",
	})
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one record", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one record", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across update vs destroy on same anchor: %q vs %q (should be anchored to (repo, ruleset_id))", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	for _, eventID := range []string{first.GetId(), second.GetId()} {
		if strings.Contains(firstFinding.Fingerprint, eventID) {
			t.Fatalf("fingerprint %q contains event id %q", firstFinding.Fingerprint, eventID)
		}
	}

	restored := githubAuditEvent("github-ruleset-restored", map[string]string{
		"action":      "repository_ruleset.update",
		"enforcement": "active",
		"repo":        "writer/cerebro",
		"ruleset_id":  "42",
	})
	records, err = rule.Evaluate(context.Background(), runtime, restored)
	if err != nil {
		t.Fatalf("Evaluate(restored) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(restored) returned %d findings, want 0 once ruleset re-enforced", len(records))
	}
}

func TestGitHubRepositoryRulesetModifiedTrajectory(t *testing.T) {
	rule := newGitHubRepositoryRulesetModifiedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	t.Run("restore enforcement", func(t *testing.T) {
		assertGitHubRuleTrajectory(t, rule, []Event{
			newGitHubAuditSignalEvent("github-ruleset-trajectory-weakened", map[string]string{
				"action":                        "repository_ruleset.update",
				"repo":                          "writer/cerebro",
				"required_status_check_removed": "true",
				"ruleset_id":                    "42",
			}),
			newGitHubAuditSignalEvent("github-ruleset-trajectory-restored", map[string]string{
				"action":      "repository_ruleset.update",
				"enforcement": "active",
				"repo":        "writer/cerebro",
				"ruleset_id":  "42",
			}),
		}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	})
	t.Run("destroyed", func(t *testing.T) {
		assertGitHubRuleTrajectory(t, rule, []Event{
			newGitHubAuditSignalEvent("github-ruleset-trajectory-weakened-before-destroy", map[string]string{
				"action":      "repository_ruleset.update",
				"enforcement": "disabled",
				"repo":        "writer/cerebro",
				"ruleset_id":  "42",
			}),
			newGitHubAuditSignalEvent("github-ruleset-trajectory-destroyed", map[string]string{
				"action":      "repository_ruleset.destroy",
				"enforcement": "disabled",
				"repo":        "writer/cerebro",
				"ruleset_id":  "42",
			}),
		}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	})
}

func TestGitHubWebhookModified(t *testing.T) {
	rule := newGitHubWebhookModifiedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"repo", "hook_id"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "action" {
			t.Fatalf("FingerprintFields still contains action: %v", definition.FingerprintFields)
		}
	}

	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	first := githubAuditEvent("github-hook-create", map[string]string{
		"action":  "hook.create",
		"hook_id": "99",
		"repo":    "writer/cerebro",
	})
	second := githubAuditEvent("github-hook-config-changed", map[string]string{
		"action":  "hook.config_changed",
		"hook_id": "99",
		"repo":    "writer/cerebro",
	})
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(create) = (%v, %v), want one record", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(config_changed) = (%v, %v), want one record", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across create vs config_changed on same anchor: %q vs %q (should be anchored to (repo, hook_id))", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	for _, eventID := range []string{first.GetId(), second.GetId()} {
		if strings.Contains(firstFinding.Fingerprint, eventID) {
			t.Fatalf("fingerprint %q contains event id %q", firstFinding.Fingerprint, eventID)
		}
	}

	destroy := githubAuditEvent("github-hook-destroy", map[string]string{
		"action":  "hook.destroy",
		"hook_id": "99",
		"repo":    "writer/cerebro",
	})
	records, err = rule.Evaluate(context.Background(), runtime, destroy)
	if err != nil {
		t.Fatalf("Evaluate(destroy) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(destroy) returned %d findings, want 0 once webhook deleted", len(records))
	}
}

func TestGitHubWebhookModifiedTrajectory(t *testing.T) {
	rule := newGitHubWebhookModifiedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	t.Run("destroyed", func(t *testing.T) {
		assertGitHubRuleTrajectory(t, rule, []Event{
			newGitHubAuditSignalEvent("github-hook-trajectory-create", map[string]string{
				"action":                  "hook.create",
				"destination_allowlisted": "false",
				"hook_id":                 "99",
				"repo":                    "writer/cerebro",
			}),
			newGitHubAuditSignalEvent("github-hook-trajectory-destroy", map[string]string{
				"action":  "hook.destroy",
				"hook_id": "99",
				"repo":    "writer/cerebro",
			}),
		}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	})
	t.Run("destination restored", func(t *testing.T) {
		assertGitHubRuleTrajectory(t, rule, []Event{
			newGitHubAuditSignalEvent("github-hook-trajectory-non-allowlisted", map[string]string{
				"action":                  "hook.config_changed",
				"destination_allowlisted": "false",
				"hook_id":                 "99",
				"repo":                    "writer/cerebro",
			}),
			newGitHubAuditSignalEvent("github-hook-trajectory-allowlisted", map[string]string{
				"action":                  "hook.config_changed",
				"destination_allowlisted": "true",
				"hook_id":                 "99",
				"repo":                    "writer/cerebro",
			}),
		}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	})
}

func TestGitHubAppIntegrationInstalled(t *testing.T) {
	rule := newGitHubAppIntegrationInstalledRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"org", "github_app_id"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "action" || field == "event_id" {
			t.Fatalf("FingerprintFields still contains %q (audit verb / per-event id): %v", field, definition.FingerprintFields)
		}
	}

	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	first := githubAuditEvent("github-app-install-first", map[string]string{
		"action":        "integration_installation.create",
		"github_app_id": "123456",
		"name":          "ci-deployer",
		"org":           "writer",
		"repo":          "writer/cerebro",
	})
	second := githubAuditEvent("github-app-install-second", map[string]string{
		"action":        "integration_installation.create",
		"github_app_id": "123456",
		"name":          "ci-deployer",
		"org":           "writer",
		"repo":          "writer/other",
	})
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one record", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one record", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across replays of the same (org, github_app_id) install: %q vs %q (should be anchored to (org, github_app_id))", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	for _, eventID := range []string{first.GetId(), second.GetId()} {
		if strings.Contains(firstFinding.Fingerprint, eventID) {
			t.Fatalf("fingerprint %q contains event id %q", firstFinding.Fingerprint, eventID)
		}
	}

	uninstall := githubAuditEvent("github-app-uninstall", map[string]string{
		"action":        "integration_installation.delete",
		"github_app_id": "123456",
		"name":          "ci-deployer",
		"org":           "writer",
	})
	records, err = rule.Evaluate(context.Background(), runtime, uninstall)
	if err != nil {
		t.Fatalf("Evaluate(uninstall) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(uninstall) returned %d findings, want 0 once app uninstalled", len(records))
	}
}

func TestGitHubAppIntegrationInstalled_InstallUninstall(t *testing.T) {
	rule := newGitHubAppIntegrationInstalledRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	for _, closeAction := range []string{"integration_installation.delete", "integration_installation.suspend", "integration_installation.destroy"} {
		t.Run(closeAction, func(t *testing.T) {
			assertGitHubRuleTrajectory(t, rule, []Event{
				newGitHubAuditSignalEvent("github-app-install-trajectory-"+strings.TrimPrefix(closeAction, "integration_installation."), map[string]string{
					"action":        "integration_installation.create",
					"github_app_id": "123456",
					"name":          "ci-deployer",
					"org":           "writer",
					"repo":          "writer/cerebro",
				}),
				newGitHubAuditSignalEvent("github-app-close-trajectory-"+strings.TrimPrefix(closeAction, "integration_installation."), map[string]string{
					"action":        closeAction,
					"github_app_id": "123456",
					"name":          "ci-deployer",
					"org":           "writer",
				}),
			}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
		})
	}
}

func TestGitHubAppIntegrationCloseAnchor_HandlesDestroy(t *testing.T) {
	rule := newGitHubAppIntegrationInstalledRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("github-app-integration-installed does not implement CounterEventRule")
	}
	open := newGitHubAuditSignalEvent("github-app-destroy-open", map[string]string{
		"action":        "integration_installation.create",
		"github_app_id": "123456",
		"name":          "ci-deployer",
		"org":           "writer",
		"repo":          "writer/cerebro",
	})
	close := newGitHubAuditSignalEvent("github-app-destroy-close", map[string]string{
		"action":        "integration_installation.destroy",
		"github_app_id": "123456",
		"name":          "ci-deployer",
		"org":           "writer",
	})
	records, err := rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "example-github-audit", SourceId: "github", TenantId: "writer", Config: map[string]string{"family": "audit"}}, open)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(open) = (%v, %v), want one finding", records, err)
	}
	openAnchor := counterRule.OpenAnchor(records[0].Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty, want org/github_app_id anchor", records[0].Attributes)
	}
	closeAnchor, closes := counterRule.CloseOnEvent(close)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(destroy) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}
	assertGitHubAuditMirrorReplayClosed(t, rule, []Event{open, close})
}

func TestGitHubAppIntegrationInstalled_DistinctAppIdsByName(t *testing.T) {
	rule := newGitHubAppIntegrationInstalledRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	first := githubAuditEvent("github-app-install-same-name-first", map[string]string{
		"action":        "integration_installation.create",
		"github_app_id": "123456",
		"name":          "ci-deployer",
		"org":           "writer",
	})
	second := githubAuditEvent("github-app-install-same-name-second", map[string]string{
		"action":        "integration_installation.create",
		"github_app_id": "654321",
		"name":          "ci-deployer",
		"org":           "writer",
	})

	firstRecords, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(firstRecords) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one record", firstRecords, err)
	}
	secondRecords, err := rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(secondRecords) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one record", secondRecords, err)
	}
	if firstRecords[0].Fingerprint == secondRecords[0].Fingerprint {
		t.Fatalf("same-name app installs collapsed to fingerprint %q; want distinct fingerprints by github_app_id", firstRecords[0].Fingerprint)
	}
	if got := strings.TrimSpace(firstRecords[0].Attributes["github_app_id"]); got != "123456" {
		t.Fatalf("first github_app_id attribute = %q, want 123456", got)
	}
	if got := strings.TrimSpace(secondRecords[0].Attributes["github_app_id"]); got != "654321" {
		t.Fatalf("second github_app_id attribute = %q, want 654321", got)
	}
}

func TestGitHubPersonalAccessTokenCreated(t *testing.T) {
	rule := newGitHubPersonalAccessTokenCreatedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"user_id", "token_id"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "action" || field == "event_id" {
			t.Fatalf("FingerprintFields still contains %q (audit verb / per-event id): %v", field, definition.FingerprintFields)
		}
	}

	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	first := githubAuditEvent("github-pat-first", map[string]string{
		"action":         "personal_access_token.access_granted",
		"operation_type": "create",
		"token_id":       "555",
		"user":           "octocat",
		"user_id":        "12345",
	})
	second := githubAuditEvent("github-pat-second", map[string]string{
		"action":         "personal_access_token.access_granted",
		"operation_type": "create",
		"token_id":       "555",
		"user":           "octocat",
		"user_id":        "12345",
	})
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one record", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one record", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across replays of the same (user_id, token_id): %q vs %q (should be anchored to (user_id, token_id))", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	for _, eventID := range []string{first.GetId(), second.GetId()} {
		if strings.Contains(firstFinding.Fingerprint, eventID) {
			t.Fatalf("fingerprint %q contains event id %q", firstFinding.Fingerprint, eventID)
		}
	}

	revoke := githubAuditEvent("github-pat-revoke", map[string]string{
		"action":         "personal_access_token.access_granted",
		"operation_type": "remove",
		"token_id":       "555",
		"user":           "octocat",
		"user_id":        "12345",
	})
	records, err = rule.Evaluate(context.Background(), runtime, revoke)
	if err != nil {
		t.Fatalf("Evaluate(revoke) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(revoke) returned %d findings, want 0 once PAT revoked", len(records))
	}
}

func TestGitHubPersonalAccessTokenCreatedTrajectory_CreateRevoke(t *testing.T) {
	rule := newGitHubPersonalAccessTokenCreatedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	assertGitHubRuleTrajectory(t, rule, []Event{
		newGitHubAuditSignalEvent("github-pat-trajectory-create", map[string]string{
			"action":         "personal_access_token.access_granted",
			"operation_type": "create",
			"resource_id":    "octocat",
			"resource_type":  "personal_access_token",
			"token_id":       "555",
			"user":           "octocat",
			"user_id":        "12345",
		}),
		newGitHubAuditSignalEvent("github-pat-trajectory-revoke", map[string]string{
			"action":        "personal_access_token.access_revoked",
			"resource_id":   "octocat",
			"resource_type": "personal_access_token",
			"token_id":      "555",
			"user":          "octocat",
			"user_id":       "12345",
		}),
	}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestGitHubPersonalAccessTokenCreatedTrajectory_CreateExpired(t *testing.T) {
	rule := newGitHubPersonalAccessTokenCreatedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	assertGitHubRuleTrajectory(t, rule, []Event{
		newGitHubAuditSignalEvent("github-pat-trajectory-create-before-expiry", map[string]string{
			"action":         "personal_access_token.access_granted",
			"operation_type": "create",
			"resource_id":    "octocat",
			"resource_type":  "personal_access_token",
			"token_id":       "555",
			"user":           "octocat",
			"user_id":        "12345",
		}),
		newGitHubAuditSignalEvent("github-pat-trajectory-expired", map[string]string{
			"action":         "personal_access_token.access_granted",
			"operation_type": "expired",
			"resource_id":    "octocat",
			"resource_type":  "personal_access_token",
			"token_id":       "555",
			"user":           "octocat",
			"user_id":        "12345",
		}),
	}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestGitHubPersonalAccessTokenCreatedTrajectory_NewestEventWins(t *testing.T) {
	rule := newGitHubPersonalAccessTokenCreatedRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	observedAt := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	openEvent := func(id string, at time.Time) Event {
		return withGitHubAuditSignalObservedAt(newGitHubAuditSignalEvent(id, map[string]string{
			"action":         "personal_access_token.access_granted",
			"operation_type": "create",
			"resource_id":    "octocat",
			"resource_type":  "personal_access_token",
			"token_id":       "555",
			"user":           "octocat",
			"user_id":        "12345",
		}), at)
	}
	closeEvent := func(id string, at time.Time) Event {
		return withGitHubAuditSignalObservedAt(newGitHubAuditSignalEvent(id, map[string]string{
			"action":        "personal_access_token.access_revoked",
			"resource_id":   "octocat",
			"resource_type": "personal_access_token",
			"token_id":      "555",
			"user":          "octocat",
			"user_id":       "12345",
		}), at)
	}

	t.Run("open then close closes", func(t *testing.T) {
		assertGitHubRuleTrajectory(t, rule, []Event{
			openEvent("github-pat-newest-wins-open", observedAt),
			closeEvent("github-pat-newest-wins-close", observedAt.Add(time.Minute)),
		}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	})

	t.Run("older close before newer open leaves finding open", func(t *testing.T) {
		assertGitHubRuleTrajectory(t, rule, []Event{
			closeEvent("github-pat-newest-wins-older-close", observedAt),
			openEvent("github-pat-newest-wins-newer-open", observedAt.Add(time.Minute)),
		}, cerebrov1.FindingStatus_FINDING_STATUS_OPEN)
	})

	t.Run("older close replayed after newer open still leaves finding open", func(t *testing.T) {
		assertGitHubRuleTrajectory(t, rule, []Event{
			openEvent("github-pat-newest-wins-newer-open-first", observedAt.Add(time.Minute)),
			closeEvent("github-pat-newest-wins-older-close-last", observedAt),
		}, cerebrov1.FindingStatus_FINDING_STATUS_OPEN)
	})
}

func TestGitHubAuditMirrors_ReplayClosesAddedThenRemoved(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rule   Rule
		events []Event
	}{
		{
			name: "collaborator add remove",
			rule: newGitHubRepositoryCollaboratorAddedRule(),
			events: []Event{
				newGitHubAuditSignalEvent("github-replay-collab-open-first", map[string]string{
					"action":        "repo.add_member",
					"repo":          "writer/cerebro",
					"resource_type": "repo",
					"user":          "external-vendor",
				}),
				newGitHubAuditSignalEvent("github-replay-collab-open-again", map[string]string{
					"action":        "repo.add_member",
					"repo":          "writer/cerebro",
					"resource_type": "repo",
					"user":          "external-vendor",
				}),
				newGitHubAuditSignalEvent("github-replay-collab-remove", map[string]string{
					"action":        "member.removed",
					"repo":          "writer/cerebro",
					"resource_type": "repo",
					"user":          "external-vendor",
				}),
			},
		},
		{
			name: "owner add remove",
			rule: newGitHubOrganizationOwnerAddedRule(),
			events: []Event{
				newGitHubAuditSignalEvent("github-replay-owner-open-first", map[string]string{
					"action":     "org.add_member",
					"org":        "writer",
					"permission": "admin",
					"user":       "new-owner",
				}),
				newGitHubAuditSignalEvent("github-replay-owner-open-again", map[string]string{
					"action":     "org.add_member",
					"org":        "writer",
					"permission": "owner",
					"user":       "new-owner",
				}),
				newGitHubAuditSignalEvent("github-replay-owner-remove", map[string]string{
					"action": "organization.remove_member",
					"org":    "writer",
					"user":   "new-owner",
				}),
			},
		},
		{
			name: "app create destroy",
			rule: newGitHubAppIntegrationInstalledRule(),
			events: []Event{
				newGitHubAuditSignalEvent("github-replay-app-open-first", map[string]string{
					"action":        "integration_installation.create",
					"github_app_id": "123456",
					"name":          "ci-deployer",
					"org":           "writer",
					"repo":          "writer/cerebro",
				}),
				newGitHubAuditSignalEvent("github-replay-app-open-again", map[string]string{
					"action":        "integration_installation.create",
					"github_app_id": "123456",
					"name":          "ci-deployer",
					"org":           "writer",
					"repo":          "writer/other",
				}),
				newGitHubAuditSignalEvent("github-replay-app-destroy", map[string]string{
					"action":        "integration_installation.destroy",
					"github_app_id": "123456",
					"name":          "ci-deployer",
					"org":           "writer",
				}),
			},
		},
		{
			name: "pat grant revoke",
			rule: newGitHubPersonalAccessTokenCreatedRule(),
			events: []Event{
				newGitHubAuditSignalEvent("github-replay-pat-open-first", map[string]string{
					"action":         "personal_access_token.access_granted",
					"operation_type": "create",
					"resource_id":    "octocat",
					"resource_type":  "personal_access_token",
					"token_id":       "555",
					"user":           "octocat",
					"user_id":        "12345",
				}),
				newGitHubAuditSignalEvent("github-replay-pat-open-again", map[string]string{
					"action":         "personal_access_token.access_granted",
					"operation_type": "create",
					"resource_id":    "octocat",
					"resource_type":  "personal_access_token",
					"token_id":       "555",
					"user":           "octocat",
					"user_id":        "12345",
				}),
				newGitHubAuditSignalEvent("github-replay-pat-revoke", map[string]string{
					"action":        "personal_access_token.access_revoked",
					"resource_id":   "octocat",
					"resource_type": "personal_access_token",
					"token_id":      "555",
					"user":          "octocat",
					"user_id":       "12345",
				}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertGitHubAuditMirrorReplayClosed(t, tc.rule, tc.events)
		})
	}
}

func TestGitHubPrivateRepositoryForkingEnabled(t *testing.T) {
	rule := newGitHubPrivateRepositoryForkingEnabledRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"org", "repo"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "action" || field == "event_id" {
			t.Fatalf("FingerprintFields still contains %q: %v", field, definition.FingerprintFields)
		}
	}

	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	orgFirst := githubAuditEvent("github-org-forking-enabled-first", map[string]string{
		"action":                             "private_repository_forking.enable",
		"org":                                "writer",
		"private_repository_forking_enabled": "true",
		"resource_id":                        "writer",
		"resource_type":                      "org",
	})
	orgSecond := githubAuditEvent("github-org-forking-enabled-second", map[string]string{
		"action":                             "private_repository_forking.clear",
		"org":                                "writer",
		"private_repository_forking_enabled": "true",
		"resource_id":                        "writer",
		"resource_type":                      "org",
	})
	records, err := rule.Evaluate(context.Background(), runtime, orgFirst)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(orgFirst) = (%v, %v), want one finding", records, err)
	}
	orgFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, orgSecond)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(orgSecond) = (%v, %v), want one finding", records, err)
	}
	if orgFinding.Fingerprint != records[0].Fingerprint {
		t.Fatalf("org-scope fingerprints differ across setting events: %q vs %q", orgFinding.Fingerprint, records[0].Fingerprint)
	}
	if got := orgFinding.Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:github_org:writer" {
		t.Fatalf("org primary_resource_urn = %q, want github org anchor", got)
	}

	repoFirst := githubAuditEvent("github-repo-forking-enabled-first", map[string]string{
		"action":                             "private_repository_forking.enable",
		"org":                                "writer",
		"private_repository_forking_enabled": "true",
		"repo":                               "writer/private-repo",
		"resource_id":                        "writer/private-repo",
		"resource_type":                      "repo",
	})
	repoSecond := githubAuditEvent("github-repo-forking-enabled-second", map[string]string{
		"action":                             "private_repository_forking.clear",
		"org":                                "writer",
		"private_repository_forking_enabled": "true",
		"repo":                               "writer/private-repo",
		"resource_id":                        "writer/private-repo",
		"resource_type":                      "repo",
	})
	records, err = rule.Evaluate(context.Background(), runtime, repoFirst)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(repoFirst) = (%v, %v), want one finding", records, err)
	}
	repoFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, repoSecond)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(repoSecond) = (%v, %v), want one finding", records, err)
	}
	if repoFinding.Fingerprint != records[0].Fingerprint {
		t.Fatalf("repo-scope fingerprints differ across setting events: %q vs %q", repoFinding.Fingerprint, records[0].Fingerprint)
	}
	if repoFinding.Fingerprint == orgFinding.Fingerprint {
		t.Fatalf("repo-scope fingerprint = org-scope fingerprint %q, want per-scope anchors", repoFinding.Fingerprint)
	}
	if got := repoFinding.Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:github_code_repository:writer/private-repo" {
		t.Fatalf("repo primary_resource_urn = %q, want github repo anchor", got)
	}

	repoResourceOnly := githubAuditEvent("github-repo-forking-resource-id-only", map[string]string{
		"action":                             "private_repository_forking.enable",
		"org":                                "writer",
		"private_repository_forking_enabled": "true",
		"resource_id":                        "writer/resource-only-repo",
		"resource_type":                      "repository",
	})
	records, err = rule.Evaluate(context.Background(), runtime, repoResourceOnly)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(repoResourceOnly) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:github_code_repository:writer/resource-only-repo" {
		t.Fatalf("resource-id repo primary_resource_urn = %q, want github repo anchor", got)
	}
	if got := records[0].Attributes["posture_scope"]; got != "repo" {
		t.Fatalf("posture_scope = %q, want repo", got)
	}

	disabled := githubAuditEvent("github-forking-disabled", map[string]string{
		"action":                             "private_repository_forking.enable",
		"org":                                "writer",
		"private_repository_forking_enabled": "false",
		"resource_id":                        "writer",
		"resource_type":                      "org",
	})
	records, err = rule.Evaluate(context.Background(), runtime, disabled)
	if err != nil {
		t.Fatalf("Evaluate(disabled) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(disabled) returned %d findings, want 0 once private repository forking is disabled", len(records))
	}
}

func TestGitHubPrivateRepositoryForkingEnabledTrajectory_Disable(t *testing.T) {
	rule := newGitHubPrivateRepositoryForkingEnabledRule()
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	t.Run("org scope", func(t *testing.T) {
		assertGitHubRuleTrajectory(t, rule, []Event{
			newGitHubAuditSignalEvent("github-org-forking-trajectory-enabled", map[string]string{
				"action":                             "private_repository_forking.enable",
				"org":                                "writer",
				"private_repository_forking_enabled": "true",
				"resource_id":                        "writer",
				"resource_type":                      "org",
			}),
			newGitHubAuditSignalEvent("github-org-forking-trajectory-disabled", map[string]string{
				"action":                             "repository.private_repository_forking_disabled",
				"org":                                "writer",
				"private_repository_forking_enabled": "false",
				"resource_id":                        "writer",
				"resource_type":                      "org",
			}),
		}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	})
	t.Run("repo scope", func(t *testing.T) {
		assertGitHubRuleTrajectory(t, rule, []Event{
			newGitHubAuditSignalEvent("github-repo-forking-trajectory-enabled", map[string]string{
				"action":                             "private_repository_forking.enable",
				"org":                                "writer",
				"private_repository_forking_enabled": "true",
				"repo":                               "writer/private-repo",
				"resource_id":                        "writer/private-repo",
				"resource_type":                      "repo",
			}),
			newGitHubAuditSignalEvent("github-repo-forking-trajectory-disabled", map[string]string{
				"action":                             "repository.private_repository_forking_disabled",
				"org":                                "writer",
				"private_repository_forking_enabled": "false",
				"repo":                               "writer/private-repo",
				"resource_id":                        "writer/private-repo",
				"resource_type":                      "repo",
			}),
		}, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	})
}

func githubSecretScanningAlertEvent(id string, attributes map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "github",
		Kind:       "github.secret_scanning_alert",
		Attributes: attributes,
	}
}

func withGitHubAuditSignalObservedAt(event *cerebrov1.EventEnvelope, observedAt time.Time) *cerebrov1.EventEnvelope {
	if event == nil {
		return nil
	}
	event.OccurredAt = timestamppb.New(observedAt.UTC())
	return event
}

func githubAuditEvent(id string, attributes map[string]string) *cerebrov1.EventEnvelope {
	if attributes["actor"] == "" {
		attributes["actor"] = "admin"
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "github",
		Kind:       "github.audit",
		Attributes: attributes,
	}
}

func cloneGitHubTestAttrs(attrs map[string]string) map[string]string {
	cloned := make(map[string]string, len(attrs))
	for key, value := range attrs {
		cloned[key] = value
	}
	return cloned
}

func assertGitHubAuditMirrorReplayClosed(t *testing.T, rule Rule, events []Event) {
	t.Helper()
	if rule == nil {
		t.Fatal("rule is required")
	}
	spec := rule.Spec()
	if spec == nil || strings.TrimSpace(spec.GetId()) == "" {
		t.Fatal("rule must expose a non-empty RuleSpec.Id")
	}
	if len(events) == 0 {
		t.Fatal("events are required")
	}
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	ruleID := strings.TrimSpace(spec.GetId())
	runtimeID := githubTrajectoryRuntimeID(events)
	tenantID := githubTrajectoryTenantID(events)
	family := githubTrajectoryFamily(events)
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry(%q) error = %v", ruleID, err)
	}
	store := &stubFindingStore{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {Id: runtimeID, SourceId: "github", TenantId: tenantID, Config: map[string]string{"family": family}},
		}},
		&stubReplayer{events: events},
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(&stubGraphStore{}).WithAppendLog(&recordingAppendLog{})

	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(%q) error = %v", ruleID, err)
	}
	if result == nil || len(result.Evaluations) != 1 || result.Evaluations[0] == nil {
		t.Fatalf("EvaluateSourceRuntimeRules(%q) result = %#v, want one evaluation", ruleID, result)
	}
	evaluation := result.Evaluations[0]
	if len(evaluation.Findings) == 0 {
		t.Fatalf("rule %q emitted no opening finding before the counter-event", ruleID)
	}
	for _, finding := range evaluation.Findings {
		if finding == nil {
			continue
		}
		if got := strings.TrimSpace(finding.Status); got == findingStatusOpen {
			t.Fatalf("evaluation finding %q status = %q, want resolved snapshot after replay close", finding.ID, got)
		}
	}
	persisted := githubTrajectoryPersistedFindings(store, ruleID, runtimeID)
	if got := len(persisted); got != 1 {
		t.Fatalf("persisted findings for rule %q = %d, want one closed row", ruleID, got)
	}
	if got := strings.TrimSpace(persisted[0].Status); got != findingStatusResolved {
		t.Fatalf("persisted finding status = %q, want %q", got, findingStatusResolved)
	}
	openRows, err := store.ListFindings(context.Background(), ports.ListFindingsRequest{
		TenantID: tenantID,
		RuleID:   ruleID,
		Status:   findingStatusOpen,
	})
	if err != nil {
		t.Fatalf("ListFindings(open) error = %v", err)
	}
	if got := len(openRows); got != 0 {
		t.Fatalf("open rows after replay for rule %q = %d, want 0: %#v", ruleID, got, openRows)
	}
}
