package findings

import (
	"context"
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
