package policy

import (
	"context"
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
		Conditions:  []string{"public == true"},
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
		Conditions:  []string{"public == false"},
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

func TestDiffPolicies_TracksChangedFields(t *testing.T) {
	before := &Policy{
		ID:          "policy-diff",
		Name:        "Before",
		Description: "desc",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"public == true"},
		Severity:    "high",
	}
	after := &Policy{
		ID:          "policy-diff",
		Name:        "After",
		Description: "desc",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"public == false"},
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
		Conditions:  []string{"public == true"},
		Severity:    "high",
	}
	candidate := &Policy{
		ID:          "policy-dry-run",
		Name:        "Candidate",
		Description: "candidate",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"public == false"},
		Severity:    "high",
	}

	assets := []map[string]interface{}{
		{"_cq_id": "bucket-a", "_cq_table": "aws_s3_buckets", "public": "true"},
		{"_cq_id": "bucket-b", "_cq_table": "aws_s3_buckets", "public": "false"},
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
