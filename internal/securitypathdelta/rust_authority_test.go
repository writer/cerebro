package securitypathdelta

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestRustComparisonAuthorityPreservesTheExistingResultContract(t *testing.T) {
	t.Parallel()
	beforeAt := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	before := mustSnapshot(t, snapshotInput("before", beforeAt, true,
		testPath("removed", "principal-a", "permission-a", "runs_as", "before", beforeAt),
	))
	after := mustSnapshot(t, snapshotInput("after", beforeAt.Add(5*time.Minute), true,
		testPath("new-a", "principal-b", "permission-b", "can_assume", "after-a", beforeAt.Add(5*time.Minute)),
		testPath("new-b", "principal-b", "permission-b", "can_assume", "after-b", beforeAt.Add(5*time.Minute)),
	))
	legacy, err := Compare(&before, after)
	if err != nil {
		t.Fatal(err)
	}
	authoritative, receipt, err := CompareRustAuthority(context.Background(), &before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(authoritative, legacy) {
		t.Fatalf("Rust authority changed the compatibility record\nRust: %#v\nlegacy: %#v", authoritative, legacy)
	}
	if receipt.Operation != "compare" || receipt.SchemaVersion != securityPathDecisionInputV1 ||
		receipt.InputDigest == "" || receipt.DecisionDigest == "" ||
		!reflect.DeepEqual(receipt.SourceSnapshotDigests, []string{before.Digest, after.Digest}) {
		t.Fatalf("Rust authority receipt = %#v", receipt)
	}
}

func TestRustVerificationAuthorityPreservesTheExistingResultContract(t *testing.T) {
	t.Parallel()
	referenceAt := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	reference := mustSnapshot(t, snapshotInput("reference", referenceAt, true,
		testPath("resource-a", "principal-a", "permission-a", "can_assume", "reference", referenceAt),
	))
	after := mustSnapshot(t, snapshotInput("after", referenceAt.Add(5*time.Minute), true))
	requested := []string{reference.Paths[0].ID}
	legacy, err := VerifyObservedAbsent(reference, after, requested)
	if err != nil {
		t.Fatal(err)
	}
	authoritative, receipt, err := VerifyObservedAbsentRustAuthority(
		context.Background(),
		reference,
		after,
		requested,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(authoritative, legacy) {
		t.Fatalf("Rust authority changed the compatibility record\nRust: %#v\nlegacy: %#v", authoritative, legacy)
	}
	if receipt.Operation != "verify_observed_absent" || receipt.InputDigest == "" ||
		receipt.DecisionDigest == "" ||
		!reflect.DeepEqual(receipt.SourceSnapshotDigests, []string{reference.Digest, after.Digest}) {
		t.Fatalf("Rust authority receipt = %#v", receipt)
	}
}

func TestRustAuthorityRejectsUnboundOutputReferences(t *testing.T) {
	t.Parallel()
	observedAt := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	after := mustSnapshot(t, snapshotInput("after", observedAt, true))
	_, err := hydrateRustComparison(nil, after, rustComparisonDecision{
		State:                string(DeltaStateInitial),
		NewlyObservedPathIDs: []string{"path:not-in-snapshot"},
	})
	if err == nil {
		t.Fatal("unknown Rust path reference hydrated successfully")
	}

	_, err = hydrateCandidateCuts([]CandidateEdgeCut{{
		Rank: 1,
		Edge: ProofEdge{ID: "edge:not-in-paths"},
	}}, nil)
	if err == nil {
		t.Fatal("unbound Rust candidate edge hydrated successfully")
	}
}

func TestRustAuthorityHasNoGoFallbackWhenEvaluationIsCanceled(t *testing.T) {
	t.Parallel()
	observedAt := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	after := mustSnapshot(t, snapshotInput("after", observedAt, true))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	delta, receipt, err := CompareRustAuthority(ctx, nil, after)
	if err == nil {
		t.Fatal("canceled Rust evaluation unexpectedly succeeded")
	}
	if delta.ID != "" || receipt.InputDigest != "" {
		t.Fatalf("failed Rust evaluation returned authority output: delta=%#v receipt=%#v", delta, receipt)
	}
}
