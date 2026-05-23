package findings

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestGitHubOrgAuthControlModifiedIgnoresHardening(t *testing.T) {
	rule := newGitHubOrgAuthControlModifiedRule()
	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	event := githubAuditEvent("github-auth-enable", map[string]string{
		"action": "org.enable_two_factor_requirement",
		"org":    "writer",
	})
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(enable) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(enable records) = %d, want 0", len(records))
	}

	event = githubAuditEvent("github-auth-disable", map[string]string{
		"action": "org.disable_two_factor_requirement",
		"org":    "writer",
	})
	records, err = rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(disable) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(disable records) = %d, want 1", len(records))
	}
	if got := records[0].Severity; got != "CRITICAL" {
		t.Fatalf("Severity = %q, want CRITICAL", got)
	}
}

func TestGitHubRepositoryRulesetModifiedRequiresWeakeningSignal(t *testing.T) {
	rule := newGitHubRepositoryRulesetModifiedRule()
	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	event := githubAuditEvent("github-ruleset-active", map[string]string{
		"action":      "repository_ruleset.update",
		"enforcement": "active",
		"repo":        "writer/cerebro",
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
	})
	records, err = rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(disabled update) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(disabled update records) = %d, want 1", len(records))
	}
}

func TestGitHubIPAllowListModifiedIgnoresEnableOnly(t *testing.T) {
	rule := newGitHubOrgIPAllowListModifiedRule()
	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	event := githubAuditEvent("github-ip-enable", map[string]string{
		"action": "ip_allow_list.enable",
		"org":    "writer",
	})
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(enable) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(enable records) = %d, want 0", len(records))
	}

	event = githubAuditEvent("github-ip-disable", map[string]string{
		"action": "ip_allow_list.disable",
		"org":    "writer",
	})
	records, err = rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(disable) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(disable records) = %d, want 1", len(records))
	}
	if got := records[0].Severity; got != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH", got)
	}
}

func TestGitHubCodeSecurityControlsDisabledIncludesSecretScanning(t *testing.T) {
	rule := newGitHubCodeSecurityControlsDisabledRule()
	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "example"}
	event := githubAuditEvent("github-secret-scanning-disable", map[string]string{
		"action":      "repository_secret_scanning.disable",
		"repo":        "example/cerebro",
		"resource_id": "example/cerebro",
	})
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(secret scanning disable) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(secret scanning disable records) = %d, want 1", len(records))
	}
	if got := records[0].RuleID; got != githubCodeSecurityControlsDisabledRuleID {
		t.Fatalf("RuleID = %q, want %q", got, githubCodeSecurityControlsDisabledRuleID)
	}
}

func TestGitHubCriticalResourceDeletedSuppressesLowValueDeletes(t *testing.T) {
	rule := newGitHubCriticalResourceDeletedRule()
	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	for _, action := range []string{"codespaces.delete", "project.delete"} {
		event := githubAuditEvent("github-"+action, map[string]string{
			"action": action,
			"repo":   "writer/cerebro",
		})
		records, err := rule.Evaluate(context.Background(), runtime, event)
		if err != nil {
			t.Fatalf("Evaluate(%s) error = %v", action, err)
		}
		if len(records) != 0 {
			t.Fatalf("len(%s records) = %d, want 0", action, len(records))
		}
	}

	event := githubAuditEvent("github-repo-destroy", map[string]string{
		"action": "repo.destroy",
		"repo":   "writer/cerebro",
	})
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(repo.destroy) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(repo.destroy records) = %d, want 1", len(records))
	}
	if got := records[0].Severity; got != "HIGH" {
		t.Fatalf("repo.destroy Severity = %q, want HIGH", got)
	}

	event = githubAuditEvent("github-environment-delete", map[string]string{
		"action": "environment.delete",
		"repo":   "writer/cerebro",
	})
	records, err = rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(environment.delete) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(environment.delete records) = %d, want 1", len(records))
	}
	if got := records[0].Severity; got != "MEDIUM" {
		t.Fatalf("environment.delete Severity = %q, want MEDIUM", got)
	}
}

func TestGitHubRepositoryCollaboratorAdded(t *testing.T) {
	rule := newGitHubRepositoryCollaboratorAddedRule()
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

func TestGitHubOrganizationOwnerAdded(t *testing.T) {
	rule := newGitHubOrganizationOwnerAddedRule()
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

func TestGitHubRepositoryRulesetModified(t *testing.T) {
	rule := newGitHubRepositoryRulesetModifiedRule()
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

func TestGitHubWebhookModified(t *testing.T) {
	rule := newGitHubWebhookModifiedRule()
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

func TestGitHubAppIntegrationInstalled(t *testing.T) {
	rule := newGitHubAppIntegrationInstalledRule()
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
	wantFields := []string{"org", "name"}
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
		"action": "integration_installation.create",
		"name":   "ci-deployer",
		"org":    "writer",
		"repo":   "writer/cerebro",
	})
	second := githubAuditEvent("github-app-install-second", map[string]string{
		"action": "integration_installation.create",
		"name":   "ci-deployer",
		"org":    "writer",
		"repo":   "writer/other",
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
		t.Fatalf("fingerprints differ across replays of the same (org, name) install: %q vs %q (should be anchored to (org, name))", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	for _, eventID := range []string{first.GetId(), second.GetId()} {
		if strings.Contains(firstFinding.Fingerprint, eventID) {
			t.Fatalf("fingerprint %q contains event id %q", firstFinding.Fingerprint, eventID)
		}
	}

	uninstall := githubAuditEvent("github-app-uninstall", map[string]string{
		"action": "integration_installation.destroy",
		"name":   "ci-deployer",
		"org":    "writer",
	})
	records, err = rule.Evaluate(context.Background(), runtime, uninstall)
	if err != nil {
		t.Fatalf("Evaluate(uninstall) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(uninstall) returned %d findings, want 0 once app uninstalled", len(records))
	}
}

func TestGitHubPersonalAccessTokenCreated(t *testing.T) {
	rule := newGitHubPersonalAccessTokenCreatedRule()
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
