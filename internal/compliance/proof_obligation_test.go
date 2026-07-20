package compliance

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateEvidenceReuse(t *testing.T) {
	base := testProofObligation()
	t.Run("exact", func(t *testing.T) {
		decision, err := EvaluateEvidenceReuse(base, base)
		if err != nil {
			t.Fatal(err)
		}
		if decision.State != ReuseExact || len(decision.FailedPredicates) != 0 || decision.DecisionDigest == "" {
			t.Fatalf("decision = %#v", decision)
		}
	})
	t.Run("period subset is partial", func(t *testing.T) {
		target := base
		target.PeriodStart = target.PeriodStart.Add(24 * time.Hour)
		decision, err := EvaluateEvidenceReuse(base, target)
		if err != nil {
			t.Fatal(err)
		}
		if decision.State != ReusePartial || len(decision.FailedPredicates) != 0 {
			t.Fatalf("decision = %#v", decision)
		}
	})
	t.Run("population mismatch is incompatible", func(t *testing.T) {
		target := base
		target.PopulationDigest = "sha256:" + strings.Repeat("b", 64)
		decision, err := EvaluateEvidenceReuse(base, target)
		if err != nil {
			t.Fatal(err)
		}
		if decision.State != ReuseIncompatible || !hasReusePredicate(decision.FailedPredicates, PredicatePopulation) {
			t.Fatalf("decision = %#v", decision)
		}
	})
	t.Run("stronger reviewer requirement is incompatible", func(t *testing.T) {
		target := base
		target.ReviewerRequired = true
		decision, err := EvaluateEvidenceReuse(base, target)
		if err != nil {
			t.Fatal(err)
		}
		if decision.State != ReuseIncompatible || !hasReusePredicate(decision.FailedPredicates, PredicateReview) {
			t.Fatalf("decision = %#v", decision)
		}
	})
}

func TestProofObligationDigestIsDeterministic(t *testing.T) {
	left := testProofObligation()
	left.SubjectKinds = []string{"repository", "identity", "repository"}
	right := testProofObligation()
	right.SubjectKinds = []string{"identity", "repository"}
	a, err := NormalizeProofObligation(left)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NormalizeProofObligation(right)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest {
		t.Fatalf("digests differ: %s != %s", a.Digest, b.Digest)
	}
}

func testProofObligation() ProofObligation {
	return ProofObligation{
		TenantID: "tenant", RequirementID: "requirement", ControlID: "control", FrameworkID: "framework", FrameworkVersion: "v1",
		ImplementationRevision: "implementation-v1", ScopeRevision: "scope-v1", SubjectKinds: []string{"identity", "repository"},
		PopulationDigest: "sha256:" + strings.Repeat("a", 64), PeriodStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), PeriodEnd: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		Method: ProofMethodAutomated, Strength: AssuranceTested, Frequency: "continuous",
	}
}

func hasReusePredicate(values []ReusePredicate, wanted ReusePredicate) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
