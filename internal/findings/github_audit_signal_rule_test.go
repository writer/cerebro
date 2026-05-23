package findings

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestGitHubOrgAuthControlModified(t *testing.T) {
	rule := newGitHubOrgAuthControlModifiedRule()
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

func TestGitHubOrgIpAllowListModified(t *testing.T) {
	rule := newGitHubOrgIPAllowListModifiedRule()
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
	wantFields := []string{"repo"}
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
	if got := firstFinding.Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:github_repo:example/cerebro" {
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

func TestGitHubPrivateRepositoryForkingEnabled(t *testing.T) {
	rule := newGitHubPrivateRepositoryForkingEnabledRule()
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
	if got := repoFinding.Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:github_repo:writer/private-repo" {
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
	if got := records[0].Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:github_repo:writer/resource-only-repo" {
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
