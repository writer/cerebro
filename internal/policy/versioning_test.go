package policy

import (
	"context"
	"strings"
	"testing"
)

func TestPolicyVersionLifecycleAndRollback(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{
		ID:          "policy-versioned",
		Name:        "Original",
		Description: "original description",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"resource.public == true"},
		Severity:    "high",
	})

	current, ok := engine.GetPolicy("policy-versioned")
	if !ok {
		t.Fatal("expected policy to exist")
	}
	if current.Version != 1 {
		t.Fatalf("expected version 1, got %d", current.Version)
	}
	if current.LastModified.IsZero() {
		t.Fatal("expected last_modified to be populated")
	}

	if ok := engine.UpdatePolicy("policy-versioned", &Policy{
		Name:        "Updated",
		Description: "updated description",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"resource.public == false"},
		Severity:    "critical",
	}); !ok {
		t.Fatal("expected update to succeed")
	}

	updated, ok := engine.GetPolicy("policy-versioned")
	if !ok {
		t.Fatal("expected updated policy to exist")
	}
	if updated.Version != 2 {
		t.Fatalf("expected version 2, got %d", updated.Version)
	}

	history := engine.ListPolicyVersions("policy-versioned")
	if len(history) != 2 {
		t.Fatalf("expected 2 history entries after update, got %d", len(history))
	}
	if history[0].Version != 1 || history[1].Version != 2 {
		t.Fatalf("unexpected versions in history: %+v", history)
	}
	if history[0].EffectiveTo == nil {
		t.Fatal("expected first version to be closed after update")
	}

	rolledBack, err := engine.RollbackPolicy("policy-versioned", 1)
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if rolledBack.Version != 3 {
		t.Fatalf("expected rollback to create version 3, got %d", rolledBack.Version)
	}
	if rolledBack.PinnedVersion != 1 {
		t.Fatalf("expected pinned version 1, got %d", rolledBack.PinnedVersion)
	}
	if rolledBack.Name != "Original" {
		t.Fatalf("expected rollback content from version 1, got %q", rolledBack.Name)
	}
}

func TestRollbackPolicyRecompilesCELConditions(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{
		ID:              "policy-cel-rollback",
		Name:            "Original CEL",
		Description:     "match public buckets",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		ConditionFormat: ConditionFormatCEL,
		Conditions:      []string{"resource.public == true"},
		Severity:        "high",
	})

	if ok := engine.UpdatePolicy("policy-cel-rollback", &Policy{
		Name:            "Updated CEL",
		Description:     "match private buckets",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		ConditionFormat: ConditionFormatCEL,
		Conditions:      []string{"resource.public == false"},
		Severity:        "high",
	}); !ok {
		t.Fatal("expected update to succeed")
	}

	if _, err := engine.RollbackPolicy("policy-cel-rollback", 1); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	findings, err := engine.EvaluateAsset(context.Background(), map[string]interface{}{
		"_cq_id":    "bucket-1",
		"_cq_table": "aws_s3_buckets",
		"type":      "aws::s3::bucket",
		"public":    true,
	})
	if err != nil {
		t.Fatalf("EvaluateAsset failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding after rollback for public=true asset, got %d", len(findings))
	}
}

func TestDiffPolicies_TracksChangedFields(t *testing.T) {
	before := &Policy{
		ID:          "policy-diff",
		Name:        "Before",
		Description: "desc",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"resource.public == true"},
		Severity:    "high",
	}
	after := &Policy{
		ID:          "policy-diff",
		Name:        "After",
		Description: "desc",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"resource.public == false"},
		Severity:    "critical",
	}

	diff := DiffPolicies(before, after)
	if !diff.Changed {
		t.Fatal("expected diff to report changes")
	}
	if len(diff.FieldDiffs) == 0 {
		t.Fatal("expected field-level diffs")
	}

	changed := make(map[string]bool, len(diff.FieldDiffs))
	for _, field := range diff.FieldDiffs {
		changed[field.Field] = true
	}
	if !changed["name"] {
		t.Fatal("expected name to be marked changed")
	}
	if !changed["conditions"] {
		t.Fatal("expected conditions to be marked changed")
	}
	if !changed["severity"] {
		t.Fatal("expected severity to be marked changed")
	}
}

func TestDryRunPolicyChange_ComputesImpactDelta(t *testing.T) {
	engine := NewEngine()

	current := &Policy{
		ID:          "policy-dry-run",
		Name:        "Current",
		Description: "current",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"resource.public == true"},
		Severity:    "high",
	}
	candidate := &Policy{
		ID:          "policy-dry-run",
		Name:        "Candidate",
		Description: "candidate",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"resource.public == false"},
		Severity:    "high",
	}

	assets := []map[string]interface{}{
		{"_cq_id": "bucket-a", "_cq_table": "aws_s3_buckets", "public": true},
		{"_cq_id": "bucket-b", "_cq_table": "aws_s3_buckets", "public": false},
	}

	impact, err := engine.DryRunPolicyChange(context.Background(), current, candidate, assets)
	if err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}

	if impact.BeforeMatches != 1 {
		t.Fatalf("expected 1 match before, got %d", impact.BeforeMatches)
	}
	if impact.AfterMatches != 1 {
		t.Fatalf("expected 1 match after, got %d", impact.AfterMatches)
	}
	if len(impact.AddedFindingIDs) != 1 {
		t.Fatalf("expected 1 added finding, got %d", len(impact.AddedFindingIDs))
	}
	if len(impact.RemovedFindingIDs) != 1 {
		t.Fatalf("expected 1 removed finding, got %d", len(impact.RemovedFindingIDs))
	}
}

func TestGetPolicyVersionAndDiffPolicyVersions(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{
		ID:              "policy-history",
		Name:            "Original",
		Description:     "version one",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		Conditions:      []string{"resource.public == true"},
		ConditionFormat: "cel",
		Severity:        "high",
		Frameworks: []FrameworkMapping{
			{Name: " CIS ", Controls: []string{" 1.1 ", "1.2"}},
		},
		MitreAttack: []MitreMapping{
			{Tactic: " Initial Access ", Technique: " T1190 "},
		},
	})

	if ok := engine.UpdatePolicy("policy-history", &Policy{
		Name:            "Updated",
		Description:     "version two",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		Conditions:      []string{"resource.public == false"},
		ConditionFormat: "cel",
		Severity:        "critical",
		Frameworks: []FrameworkMapping{
			{Name: "NIST", Controls: []string{"AC-1"}},
		},
		MitreAttack: []MitreMapping{
			{Tactic: "Execution", Technique: "T1059"},
		},
	}); !ok {
		t.Fatal("expected update to succeed")
	}

	versionOne, ok := engine.GetPolicyVersion("policy-history", 1)
	if !ok {
		t.Fatal("expected version 1 to exist")
	}
	if versionOne.Content == nil || versionOne.Content.Name != "Original" {
		t.Fatalf("unexpected version 1 content: %#v", versionOne.Content)
	}

	versionOne.Content.Name = "Mutated copy"
	versionOneAgain, ok := engine.GetPolicyVersion("policy-history", 1)
	if !ok {
		t.Fatal("expected version 1 lookup to still succeed")
	}
	if versionOneAgain.Content == nil || versionOneAgain.Content.Name != "Original" {
		t.Fatalf("stored history should not be mutated through copies, got %#v", versionOneAgain.Content)
	}

	diff, err := engine.DiffPolicyVersions("policy-history", 1, 2)
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	if diff.PolicyID != "policy-history" || diff.FromVersion != 1 || diff.ToVersion != 2 {
		t.Fatalf("unexpected diff metadata: %#v", diff)
	}

	changed := make(map[string]bool, len(diff.FieldDiffs))
	for _, field := range diff.FieldDiffs {
		changed[field.Field] = true
	}
	for _, field := range []string{"name", "conditions", "severity", "frameworks", "mitre_attack"} {
		if !changed[field] {
			t.Fatalf("expected %q to be marked as changed, got %#v", field, diff.FieldDiffs)
		}
	}
}

func TestDiffPolicyVersionsMissingVersionAndNormalizedStructuredFields(t *testing.T) {
	engine := NewEngine()
	engine.AddPolicy(&Policy{
		ID:              "policy-normalized",
		Name:            "Normalized",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		Conditions:      []string{"resource.public == true"},
		ConditionFormat: "cel",
	})

	if _, err := engine.DiffPolicyVersions("policy-normalized", 1, 9); err == nil || !strings.Contains(err.Error(), "policy version not found") {
		t.Fatalf("expected missing version error, got %v", err)
	}

	before := &Policy{
		ID:              "  normalized-id  ",
		Name:            "Policy",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		Conditions:      []string{"resource.public == true"},
		ConditionFormat: " cel ",
		Frameworks: []FrameworkMapping{
			{Name: " CIS Controls ", Controls: []string{" 1.1 ", "1.2 "}},
		},
		MitreAttack: []MitreMapping{
			{Tactic: " Initial Access ", Technique: " T1190 "},
		},
	}
	after := &Policy{
		ID:              "normalized-id",
		Name:            "Policy",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		Conditions:      []string{"resource.public == true"},
		ConditionFormat: "cel",
		Frameworks: []FrameworkMapping{
			{Name: "CIS Controls", Controls: []string{"1.1", "1.2"}},
		},
		MitreAttack: []MitreMapping{
			{Tactic: "Initial Access", Technique: "T1190"},
		},
	}

	diff := DiffPolicies(before, after)
	if diff.PolicyID != "normalized-id" {
		t.Fatalf("expected normalized policy id, got %#v", diff.PolicyID)
	}
	if diff.Changed {
		t.Fatalf("expected whitespace-only structured changes to normalize away, got %#v", diff.FieldDiffs)
	}
}

func TestVersioningHelpers_HandleNilAndFallbackCases(t *testing.T) {
	if got := clonePolicy(nil); got != nil {
		t.Fatalf("expected nil clone for nil policy, got %#v", got)
	}

	before := &Policy{ID: "  before-only  ", Name: "before"}
	if got := firstNonEmptyPolicyID(before, nil); got != "before-only" {
		t.Fatalf("expected before policy id fallback, got %q", got)
	}
	if got := firstNonEmptyPolicyID(nil, nil); got != "" {
		t.Fatalf("expected empty id for nil inputs, got %q", got)
	}

	if got := policyFieldValue(nil, func(p *Policy) interface{} { return p.Name }); got != nil {
		t.Fatalf("expected nil policyFieldValue for nil policy, got %#v", got)
	}
}
