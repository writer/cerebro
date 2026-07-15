package compliancetruth

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/trustclaims"
)

func TestConflictingCurrentTruthBlocksQualifiedAndShareableStatus(t *testing.T) {
	now := truthTime()
	claimA := validClaim(t, "claim-a", "receipt-a", "enabled", trustclaims.ClaimStatusShareable, trustclaims.CitationCurrent, now)
	claimB := validClaim(t, "claim-b", "receipt-b", "disabled", trustclaims.ClaimStatusShareable, trustclaims.CitationCurrent, now)
	revisionA := mustRevision(t, revisionInput("revision-a", "enabled", claimA, now))
	revisionB := mustRevision(t, revisionInput("revision-b", "disabled", claimB, now.Add(time.Minute)))

	evaluation, err := Evaluate(Ledger{Revisions: []TruthRevision{revisionA, revisionB}, Claims: []trustclaims.ClaimReceipt{claimA, claimB}}, EvaluationQuery{
		TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: now.Add(time.Hour), EffectiveAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.State != EvaluationConflicted || evaluation.Qualified || evaluation.Shareable {
		t.Fatalf("evaluation = %#v, want explicit blocking conflict", evaluation)
	}
	if len(evaluation.Conflicts) != 1 || evaluation.Conflicts[0].Kind != ConflictValueDisagreement || !evaluation.Conflicts[0].Resolvable {
		t.Fatalf("conflicts = %#v", evaluation.Conflicts)
	}
	if !reflect.DeepEqual(evaluation.Conflicts[0].InputDigests, []string{min(revisionA.Digest, revisionB.Digest), max(revisionA.Digest, revisionB.Digest)}) {
		t.Fatalf("conflict inputs = %#v, want exact sorted revision digests", evaluation.Conflicts[0].InputDigests)
	}
}

func TestAsKnownAtAndEffectiveAtPreserveLateCorrectionHistory(t *testing.T) {
	now := truthTime()
	oldClaim := validClaim(t, "claim-old", "receipt-old", "enabled", trustclaims.ClaimStatusShareable, trustclaims.CitationCurrent, now)
	newClaim := validClaim(t, "claim-new", "receipt-new", "disabled", trustclaims.ClaimStatusShareable, trustclaims.CitationCurrent, now)
	validTo := now.Add(90 * 24 * time.Hour)
	oldInput := revisionInput("revision-old", "enabled", oldClaim, now)
	oldInput.ValidTime = Interval{From: now.Add(-24 * time.Hour), To: &validTo}
	oldRevision := mustRevision(t, oldInput)
	oldSnapshot := oldRevision

	correctionInput := revisionInput("revision-correction", "disabled", newClaim, now.Add(30*24*time.Hour))
	correctionInput.ValidTime = Interval{From: now.Add(-24 * time.Hour), To: &validTo}
	corrected, supersession, err := CorrectRevision(oldRevision, correctionInput)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(oldRevision, oldSnapshot) {
		t.Fatal("CorrectRevision mutated the prior revision")
	}
	if corrected.PreviousDigest != oldRevision.Digest || supersession.PriorDigest != oldRevision.Digest || supersession.SuccessorDigest != corrected.Digest {
		t.Fatalf("correction lineage missing: corrected=%#v supersession=%#v", corrected, supersession)
	}
	ledger := Ledger{Revisions: []TruthRevision{oldRevision, corrected}, Supersessions: []SupersessionReceipt{supersession}, Claims: []trustclaims.ClaimReceipt{oldClaim, newClaim}}

	before, err := Evaluate(ledger, EvaluationQuery{TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: now.Add(10 * 24 * time.Hour), EffectiveAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if before.State != EvaluationQualified || before.Value != "enabled" || !reflect.DeepEqual(before.RevisionDigests, []string{oldRevision.Digest}) {
		t.Fatalf("before correction = %#v", before)
	}
	after, err := Evaluate(ledger, EvaluationQuery{TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: now.Add(31 * 24 * time.Hour), EffectiveAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if after.State != EvaluationQualified || after.Value != "disabled" || !reflect.DeepEqual(after.RevisionDigests, []string{corrected.Digest}) {
		t.Fatalf("after correction = %#v", after)
	}
	outside, err := Evaluate(ledger, EvaluationQuery{TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: now.Add(31 * 24 * time.Hour), EffectiveAt: validTo})
	if err != nil {
		t.Fatal(err)
	}
	if outside.State != EvaluationUnknown || outside.Qualified || outside.Shareable {
		t.Fatalf("outside valid interval = %#v", outside)
	}
}

func TestEvaluationRejectsSupersessionThatChangesAssertionIdentity(t *testing.T) {
	now := truthTime()
	claim := validClaim(t, "claim-a", "receipt-a", "enabled", trustclaims.ClaimStatusShareable, trustclaims.CitationCurrent, now)
	prior := mustRevision(t, revisionInput("revision-a", "enabled", claim, now))
	successor, supersession, err := CorrectRevision(prior, revisionInput("revision-b", "disabled", claim, now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	successor.Predicate = "password_rotation_required"
	successor.Digest = mustDigest(t, revisionWithoutDigest(successor))
	supersession.SuccessorDigest = successor.Digest
	supersession.Digest = mustDigest(t, supersessionWithoutDigest(supersession))

	_, err = Evaluate(Ledger{Revisions: []TruthRevision{prior, successor}, Supersessions: []SupersessionReceipt{supersession}, Claims: []trustclaims.ClaimReceipt{claim}}, EvaluationQuery{
		TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: now.Add(2 * time.Hour), EffectiveAt: now,
	})
	if !errors.Is(err, ErrInvalidTruthRecord) {
		t.Fatalf("Evaluate() error = %v, want ErrInvalidTruthRecord", err)
	}
}

func TestConflictResolutionBindsReviewerExactInputsAndDecisionTime(t *testing.T) {
	now := truthTime()
	claimA := validClaim(t, "claim-a", "receipt-a", "enabled", trustclaims.ClaimStatusAuditorReady, trustclaims.CitationCurrent, now)
	claimB := validClaim(t, "claim-b", "receipt-b", "disabled", trustclaims.ClaimStatusAuditorReady, trustclaims.CitationCurrent, now)
	revisionA := mustRevision(t, revisionInput("revision-a", "enabled", claimA, now))
	revisionB := mustRevision(t, revisionInput("revision-b", "disabled", claimB, now.Add(time.Minute)))
	ledger := Ledger{Revisions: []TruthRevision{revisionA, revisionB}, Claims: []trustclaims.ClaimReceipt{claimA, claimB}}
	conflicted, err := Evaluate(ledger, EvaluationQuery{TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: now.Add(time.Hour), EffectiveAt: now})
	if err != nil {
		t.Fatal(err)
	}
	conflict := conflicted.Conflicts[0]
	approvedAt := now.Add(2 * time.Hour)
	resolution, err := ResolveConflict(ResolutionInput{
		TenantID: "tenant-a", AssertionID: "assertion-access", ConflictID: conflict.ID,
		InputDigests: conflict.InputDigests, Decision: ResolutionAcceptRevision, SelectedRevisionDigest: revisionA.Digest,
		Reviewer:   trustclaims.ReviewerApproval{ReviewerID: "reviewer-a", Decision: trustclaims.ApprovalApproved, Reason: "The current configuration record is authoritative.", ApprovedAt: approvedAt},
		RecordedAt: approvedAt.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	ledger.Resolutions = []ConflictResolutionReceipt{resolution}

	beforeResolution, err := Evaluate(ledger, EvaluationQuery{TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: approvedAt, EffectiveAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if beforeResolution.State != EvaluationConflicted {
		t.Fatalf("resolution applied before recorded time: %#v", beforeResolution)
	}
	afterResolution, err := Evaluate(ledger, EvaluationQuery{TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: approvedAt.Add(2 * time.Minute), EffectiveAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if afterResolution.State != EvaluationQualified || afterResolution.Value != "enabled" || len(afterResolution.ResolvedConflicts) != 1 || afterResolution.ResolvedConflicts[0].ResolutionDigest != resolution.Digest {
		t.Fatalf("resolved evaluation = %#v", afterResolution)
	}
	if _, err := ResolveConflict(ResolutionInput{TenantID: "tenant-a", AssertionID: "assertion-access", ConflictID: conflict.ID, InputDigests: conflict.InputDigests, Decision: ResolutionAcceptRevision, SelectedRevisionDigest: revisionA.Digest, RecordedAt: approvedAt}); !errors.Is(err, ErrInvalidTruthRecord) {
		t.Fatalf("unapproved resolution error = %v, want ErrInvalidTruthRecord", err)
	}
}

func TestConflictResolutionDiscardsClaimConflictsFromRejectedRevision(t *testing.T) {
	now := truthTime()
	claimA := validClaim(t, "claim-a", "receipt-a", "enabled", trustclaims.ClaimStatusShareable, trustclaims.CitationCurrent, now)
	claimB := validClaim(t, "claim-b", "receipt-b", "disabled", trustclaims.ClaimStatusWithdrawn, trustclaims.CitationCurrent, now)
	revisionA := mustRevision(t, revisionInput("revision-a", "enabled", claimA, now))
	revisionB := mustRevision(t, revisionInput("revision-b", "disabled", claimB, now.Add(2*time.Minute)))
	conflict := conflictingValues([]TruthRevision{revisionA, revisionB})
	if conflict == nil {
		t.Fatal("conflictingValues() = nil")
	}
	approvedAt := now.Add(3 * time.Minute)
	resolution, err := ResolveConflict(ResolutionInput{
		TenantID: "tenant-a", AssertionID: "assertion-access", ConflictID: conflict.ID,
		InputDigests: conflict.InputDigests, Decision: ResolutionAcceptRevision, SelectedRevisionDigest: revisionA.Digest,
		Reviewer:   trustclaims.ReviewerApproval{ReviewerID: "reviewer-a", Decision: trustclaims.ApprovalApproved, ApprovedAt: approvedAt},
		RecordedAt: approvedAt.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	evaluation, err := Evaluate(Ledger{
		Revisions: []TruthRevision{revisionA, revisionB},
		Claims:    []trustclaims.ClaimReceipt{claimA, claimB},
		Resolutions: []ConflictResolutionReceipt{
			resolution,
		},
	}, EvaluationQuery{TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: approvedAt.Add(2 * time.Minute), EffectiveAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.State != EvaluationQualified || evaluation.Value != "enabled" || len(evaluation.Conflicts) != 0 || !reflect.DeepEqual(evaluation.RevisionDigests, []string{revisionA.Digest}) {
		t.Fatalf("resolved evaluation = %#v, want only the selected valid revision", evaluation)
	}
}

func TestConflictedOrWithdrawnClaimRemainsExplicitAndUnresolvable(t *testing.T) {
	now := truthTime()
	tests := []struct {
		name          string
		status        string
		citationState string
		wantKind      string
	}{
		{name: "conflicting citation", status: trustclaims.ClaimStatusDraft, citationState: trustclaims.CitationConflicted, wantKind: ConflictCitationState},
		{name: "withdrawn claim", status: trustclaims.ClaimStatusWithdrawn, citationState: trustclaims.CitationCurrent, wantKind: ConflictClaimState},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claim := validClaim(t, "claim-a", "receipt-a", "enabled", test.status, test.citationState, now)
			revision := mustRevision(t, revisionInput("revision-a", "enabled", claim, now))
			evaluation, err := Evaluate(Ledger{Revisions: []TruthRevision{revision}, Claims: []trustclaims.ClaimReceipt{claim}}, EvaluationQuery{TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: now.Add(time.Hour), EffectiveAt: now})
			if err != nil {
				t.Fatal(err)
			}
			if evaluation.State != EvaluationConflicted || evaluation.Qualified || evaluation.Shareable {
				t.Fatalf("evaluation = %#v", evaluation)
			}
			found := false
			for _, conflict := range evaluation.Conflicts {
				if conflict.Kind == test.wantKind {
					found = true
					if conflict.Resolvable {
						t.Fatalf("source integrity conflict must not be overridable: %#v", conflict)
					}
				}
			}
			if !found {
				t.Fatalf("conflicts = %#v, want kind %s", evaluation.Conflicts, test.wantKind)
			}
		})
	}
}

func TestLaterWithdrawalInvalidatesAPreviouslyBoundShareableReceipt(t *testing.T) {
	now := truthTime()
	claim := validClaim(t, "claim-a", "receipt-a", "enabled", trustclaims.ClaimStatusShareable, trustclaims.CitationCurrent, now)
	revision := mustRevision(t, revisionInput("revision-a", "enabled", claim, now))
	withdrawal, err := trustclaims.ApplyEvidenceChange(claim, trustclaims.EvidenceChange{
		TenantID: "tenant-a", CitationID: claim.Citations[0].ID, State: trustclaims.CitationRevoked,
		Reason: "The source retracted the evidence.", ObservedAt: now.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := Evaluate(Ledger{
		Revisions: []TruthRevision{revision}, Claims: []trustclaims.ClaimReceipt{claim, withdrawal.Receipt},
	}, EvaluationQuery{TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: now.Add(time.Hour), EffectiveAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.State != EvaluationConflicted || len(evaluation.Conflicts) == 0 {
		t.Fatalf("evaluation = %#v, want later withdrawal to block the older binding", evaluation)
	}
}

func TestEvaluationIsTenantScoped(t *testing.T) {
	now := truthTime()
	claim := validClaim(t, "claim-a", "receipt-a", "enabled", trustclaims.ClaimStatusShareable, trustclaims.CitationCurrent, now)
	revision := mustRevision(t, revisionInput("revision-a", "enabled", claim, now))
	if _, err := Evaluate(Ledger{Revisions: []TruthRevision{revision}, Claims: []trustclaims.ClaimReceipt{claim}}, EvaluationQuery{TenantID: "tenant-b", AssertionID: "assertion-access", AsKnownAt: now.Add(time.Hour), EffectiveAt: now}); !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("Evaluate() error = %v, want ErrTenantMismatch", err)
	}

	otherClaimInput := validClaimInput("claim-b", "receipt-b", "enabled", trustclaims.ClaimStatusShareable, trustclaims.CitationCurrent, now)
	otherClaimInput.TenantID = "tenant-b"
	otherClaim := mustClaim(t, otherClaimInput)
	revisionWithOtherClaim := mustRevision(t, revisionInput("revision-b", "enabled", otherClaim, now))
	revisionWithOtherClaim.TenantID = "tenant-a"
	revisionWithOtherClaim.Digest = mustDigest(t, revisionWithoutDigest(revisionWithOtherClaim))
	if _, err := Evaluate(Ledger{Revisions: []TruthRevision{revisionWithOtherClaim}, Claims: []trustclaims.ClaimReceipt{otherClaim}}, EvaluationQuery{TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: now.Add(time.Hour), EffectiveAt: now}); !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("Evaluate(cross-tenant claim) error = %v, want ErrTenantMismatch", err)
	}
}

func TestDeterministicTruthReceiptsAndEvaluation(t *testing.T) {
	now := truthTime()
	claimA := validClaim(t, "claim-a", "receipt-a", "enabled", trustclaims.ClaimStatusShareable, trustclaims.CitationCurrent, now)
	claimB := validClaim(t, "claim-b", "receipt-b", "enabled", trustclaims.ClaimStatusShareable, trustclaims.CitationCurrent, now)
	input := revisionInput("revision-a", "enabled", claimA, now)
	input.ClaimBindings = append(input.ClaimBindings, ClaimBinding{ReceiptID: claimB.ReceiptID, ReceiptDigest: claimB.Digest, Position: PositionSupports})
	reversed := input
	reversed.ClaimBindings = []ClaimBinding{input.ClaimBindings[1], input.ClaimBindings[0]}
	revisionA := mustRevision(t, input)
	revisionB := mustRevision(t, reversed)
	if revisionA.Digest != revisionB.Digest {
		t.Fatalf("revision digests differ: %s != %s", revisionA.Digest, revisionB.Digest)
	}
	query := EvaluationQuery{TenantID: "tenant-a", AssertionID: "assertion-access", AsKnownAt: now.Add(time.Hour), EffectiveAt: now}
	first, err := Evaluate(Ledger{Revisions: []TruthRevision{revisionA}, Claims: []trustclaims.ClaimReceipt{claimA, claimB}}, query)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Evaluate(Ledger{Revisions: []TruthRevision{revisionA}, Claims: []trustclaims.ClaimReceipt{claimB, claimA}}, query)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || first.State != EvaluationQualified || !first.Shareable {
		t.Fatalf("deterministic evaluations differ: %#v %#v", first, second)
	}
}

func validClaim(t *testing.T, claimID, receiptID, value, status, citationState string, now time.Time) trustclaims.ClaimReceipt {
	t.Helper()
	if status == trustclaims.ClaimStatusWithdrawn {
		input := validClaimInput(claimID, receiptID, value, trustclaims.ClaimStatusShareable, trustclaims.CitationCurrent, now)
		base := mustClaim(t, input)
		transition, err := trustclaims.ApplyEvidenceChange(base, trustclaims.EvidenceChange{TenantID: input.TenantID, CitationID: input.Citations[0].ID, State: trustclaims.CitationStale, Reason: "Evidence was invalidated.", ObservedAt: now.Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		return transition.Receipt
	}
	return mustClaim(t, validClaimInput(claimID, receiptID, value, status, citationState, now))
}

func validClaimInput(claimID, receiptID, value, status, citationState string, now time.Time) trustclaims.ReceiptInput {
	expires := now.Add(365 * 24 * time.Hour)
	disclosure := trustclaims.DisclosureCustomer
	if status == trustclaims.ClaimStatusAuditorReady {
		disclosure = trustclaims.DisclosureAuditor
	}
	requestedStatus := status
	if status == trustclaims.ClaimStatusWithdrawn {
		requestedStatus = trustclaims.ClaimStatusDraft
	}
	return trustclaims.ReceiptInput{
		TenantID: "tenant-a", ReceiptID: receiptID, ClaimID: claimID, Version: 1,
		Statement: "The access control is " + value + ".", Origin: trustclaims.ClaimOriginAuthored,
		RequestedStatus: requestedStatus, DisclosureClass: disclosure,
		Citations: []trustclaims.Citation{{ID: "citation-" + receiptID, EvidenceID: "evidence-" + receiptID, SourceID: "source-a", SourceEventIDs: []string{"event-" + receiptID}, ResourceRefs: []trustclaims.ResourceRef{{URN: "urn:resource:access", Revision: "12"}}, State: citationState, Trusted: true, ObservedAt: now.Add(-time.Minute), ExpiresAt: &expires}},
		Controls:  []trustclaims.VersionedRef{{ID: "control-access", Version: "3"}}, Policies: []trustclaims.VersionedRef{{ID: "policy-access", Version: "7"}},
		ResourceRefs: []trustclaims.ResourceRef{{URN: "urn:resource:access", Revision: "12", Type: "access_control"}},
		Approval:     &trustclaims.ReviewerApproval{ReviewerID: "reviewer-a", Decision: trustclaims.ApprovalApproved, ApprovedAt: now},
		FreshUntil:   &expires, ExpiresAt: &expires, IssuedAt: now,
	}
}

func mustClaim(t *testing.T, input trustclaims.ReceiptInput) trustclaims.ClaimReceipt {
	t.Helper()
	receipt, err := trustclaims.IssueReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func revisionInput(revisionID, value string, claim trustclaims.ClaimReceipt, recordedAt time.Time) RevisionInput {
	return RevisionInput{
		TenantID: "tenant-a", AssertionID: "assertion-access", RevisionID: revisionID, Version: 1,
		Subject:   trustclaims.ResourceRef{URN: "urn:resource:access", Revision: "12", Type: "access_control"},
		Predicate: "second_factor_required", Value: value,
		ValidTime: Interval{From: truthTime().Add(-24 * time.Hour)}, RecordedAt: recordedAt,
		ClaimBindings: []ClaimBinding{{ReceiptID: claim.ReceiptID, ReceiptDigest: claim.Digest, Position: PositionSupports}},
	}
}

func mustRevision(t *testing.T, input RevisionInput) TruthRevision {
	t.Helper()
	revision, err := IssueRevision(input)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func mustDigest(t *testing.T, value any) string {
	t.Helper()
	digest, err := digestValue(value)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func truthTime() time.Time { return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC) }
func min(a, b string) string {
	if a < b {
		return a
	}
	return b
}
func max(a, b string) string {
	if a > b {
		return a
	}
	return b
}
