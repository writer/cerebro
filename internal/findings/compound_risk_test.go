package findings

import (
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestAnalyzeCompoundRisksGroupsFindingsByActorResourceAndRepository(t *testing.T) {
	report := AnalyzeCompoundRisks([]*ports.FindingRecord{
		compoundRiskFinding("finding-1", "github-branch-protection-disabled", "HIGH", "alice", "writer/app", "urn:cerebro:writer:github_repo:writer/app", "protected_branch.destroy"),
		compoundRiskFinding("finding-2", "github-secret-scanning-alert-created", "MEDIUM", "alice", "writer/app", "urn:cerebro:writer:github_repo:writer/app", "secret_scanning_alert.create"),
		compoundRiskFinding("finding-3", "github-repository-collaborator-added", "MEDIUM", "bob", "writer/app", "urn:cerebro:writer:github_repo:writer/app", "repo.add_member"),
		compoundRiskFinding("finding-4", "github-app-integration-installed", "MEDIUM", "alice", "", "urn:cerebro:writer:github_resource:integration_installation:writer", "integration_installation.create"),
	}, CompoundRiskOptions{Limit: 10, SampleLimit: 2})

	if got := len(report.Actors); got != 1 {
		t.Fatalf("len(Actors) = %d, want 1", got)
	}
	actor := report.Actors[0]
	if got := actor.Key; got != "alice" {
		t.Fatalf("Actors[0].Key = %q, want alice", got)
	}
	if got := actor.Score; got != 13 {
		t.Fatalf("Actors[0].Score = %d, want 13", got)
	}
	if got := actor.FindingCount; got != 3 {
		t.Fatalf("Actors[0].FindingCount = %d, want 3", got)
	}
	if got := actor.RuleIDs; len(got) != 3 || got[0] != "github-app-integration-installed" || got[1] != "github-branch-protection-disabled" || got[2] != "github-secret-scanning-alert-created" {
		t.Fatalf("Actors[0].RuleIDs = %#v, want sorted three-rule set", got)
	}
	if got := len(actor.SampleSummaries); got != 2 {
		t.Fatalf("len(Actors[0].SampleSummaries) = %d, want 2", got)
	}

	if got := len(report.Repositories); got != 1 {
		t.Fatalf("len(Repositories) = %d, want 1", got)
	}
	repository := report.Repositories[0]
	if got := repository.Key; got != "writer/app" {
		t.Fatalf("Repositories[0].Key = %q, want writer/app", got)
	}
	if got := repository.FindingCount; got != 3 {
		t.Fatalf("Repositories[0].FindingCount = %d, want 3", got)
	}

	if got := len(report.Resources); got != 1 {
		t.Fatalf("len(Resources) = %d, want 1", got)
	}
	resource := report.Resources[0]
	if got := resource.Key; got != "urn:cerebro:writer:github_repo:writer/app" {
		t.Fatalf("Resources[0].Key = %q, want repo resource urn", got)
	}
	if got := resource.Actions[0].Value; got != "protected_branch.destroy" {
		t.Fatalf("Resources[0].Actions[0].Value = %q, want protected branch action", got)
	}
}

func TestAnalyzeCompoundRisksDeduplicatesFindingsAndAppliesLimit(t *testing.T) {
	high := compoundRiskFinding("finding-1", "github-secret-scanning-disabled", "HIGH", "alice", "writer/app", "urn:cerebro:writer:github_repo:writer/app", "repository_secret_scanning.disable")
	report := AnalyzeCompoundRisks([]*ports.FindingRecord{
		high,
		high,
		compoundRiskFinding("finding-2", "github-secret-scanning-disabled", "HIGH", "alice", "writer/app", "urn:cerebro:writer:github_repo:writer/app", "repository_secret_scanning.disable"),
		compoundRiskFinding("finding-3", "github-repository-collaborator-added", "MEDIUM", "bob", "writer/lib", "urn:cerebro:writer:github_repo:writer/lib", "repo.add_member"),
		compoundRiskFinding("finding-4", "github-secret-scanning-alert-created", "LOW", "bob", "writer/lib", "urn:cerebro:writer:github_repo:writer/lib", "secret_scanning_alert.create"),
	}, CompoundRiskOptions{Limit: 1})

	if got := len(report.Actors); got != 1 {
		t.Fatalf("len(Actors) = %d, want 1", got)
	}
	if got := report.Actors[0].Key; got != "alice" {
		t.Fatalf("Actors[0].Key = %q, want highest scoring alice group", got)
	}
	if got := report.Actors[0].FindingCount; got != 2 {
		t.Fatalf("Actors[0].FindingCount = %d, want deduped count 2", got)
	}
}

func compoundRiskFinding(id string, ruleID string, severity string, actor string, repo string, resourceURN string, action string) *ports.FindingRecord {
	return &ports.FindingRecord{
		ID:           id,
		Fingerprint:  id,
		TenantID:     "writer",
		RuntimeID:    "writer-github-audit",
		RuleID:       ruleID,
		Severity:     severity,
		Status:       findingStatusOpen,
		Summary:      actor + " " + action + " " + repo,
		ResourceURNs: []string{resourceURN},
		Attributes: map[string]string{
			"action":               action,
			"actor":                actor,
			"primary_resource_urn": resourceURN,
			"repo":                 repo,
		},
	}
}
