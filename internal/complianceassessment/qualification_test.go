package complianceassessment

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/observability"
)

func TestQualifyDecisionRequiresEveryAssuranceGate(t *testing.T) {
	input := validQualificationInput()
	decision := QualifyDecision(context.Background(), input)
	if !decision.Qualified {
		t.Fatalf("Qualified = false, reasons = %v", decision.Reasons)
	}
	if decision.ManifestHash == "" || decision.ResultHash == "" || decision.DecisionDigest == "" {
		t.Fatalf("decision is not pinned: %#v", decision)
	}
	if err := decision.AuthorizeProductionUse(); err != nil {
		t.Fatalf("AuthorizeProductionUse() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*QualificationInput)
		reason QualificationReason
	}{
		{
			name: "incomplete population",
			mutate: func(input *QualificationInput) {
				input.Manifest.Receipts[0].Completeness = CollectionPartial
			},
			reason: QualificationPopulationIncomplete,
		},
		{
			name: "scope unpinned",
			mutate: func(input *QualificationInput) {
				input.Manifest.ScopeRevisionID = ""
			},
			reason: QualificationScopeUnpinned,
		},
		{
			name: "missing source proof",
			mutate: func(input *QualificationInput) {
				input.SourceProofs = nil
			},
			reason: QualificationSourceProofMissing,
		},
		{
			name: "unhealthy source",
			mutate: func(input *QualificationInput) {
				input.SourceProofs[0].State = SourceFailed
			},
			reason: QualificationSourceUnhealthy,
		},
		{
			name: "stale source",
			mutate: func(input *QualificationInput) {
				input.SourceProofs[0].FreshUntil = input.AsOf.Add(-time.Millisecond)
			},
			reason: QualificationSourceStale,
		},
		{
			name: "stale evidence",
			mutate: func(input *QualificationInput) {
				input.EvidenceProofs[0].ValidUntil = input.AsOf.Add(-time.Millisecond)
			},
			reason: QualificationEvidenceNotCurrent,
		},
		{
			name: "limitations not declared",
			mutate: func(input *QualificationInput) {
				input.Limitations = nil
			},
			reason: QualificationLimitationsUndeclared,
		},
		{
			name: "blocking limitation",
			mutate: func(input *QualificationInput) {
				input.Limitations = []Limitation{{Code: "scope_gap", Detail: "A required population is unavailable.", Blocking: true}}
			},
			reason: QualificationBlockingLimitation,
		},
		{
			name: "reviews not declared",
			mutate: func(input *QualificationInput) {
				input.RequiredReviews = nil
			},
			reason: QualificationReviewsUndeclared,
		},
		{
			name: "required review pending",
			mutate: func(input *QualificationInput) {
				input.RequiredReviews[0].Status = ReviewPending
			},
			reason: QualificationReviewIncomplete,
		},
		{
			name: "expired exception",
			mutate: func(input *QualificationInput) {
				input.Exceptions = []ExceptionProof{{ExceptionID: "exception-1", Active: true, ValidUntil: input.AsOf.Add(-time.Millisecond)}}
			},
			reason: QualificationExceptionExpired,
		},
		{
			name: "failed verification",
			mutate: func(input *QualificationInput) {
				input.Verification = VerificationProof{Required: true, State: VerificationFailed, VerifiedAt: input.AsOf.Add(-time.Hour), ValidUntil: input.AsOf.Add(time.Hour)}
			},
			reason: QualificationVerificationFailed,
		},
		{
			name: "verification state omitted",
			mutate: func(input *QualificationInput) {
				input.Verification = VerificationProof{}
			},
			reason: QualificationVerificationFailed,
		},
		{
			name: "failed optional verification",
			mutate: func(input *QualificationInput) {
				input.Verification = VerificationProof{Required: false, State: VerificationFailed, VerifiedAt: input.AsOf.Add(-time.Hour)}
			},
			reason: QualificationVerificationFailed,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := cloneQualificationInput(input)
			testCase.mutate(&candidate)
			decision := QualifyDecision(context.Background(), candidate)
			if decision.Qualified {
				t.Fatalf("Qualified = true, want false: %#v", decision)
			}
			if !containsQualificationReason(decision.Reasons, testCase.reason) {
				t.Fatalf("reasons = %v, want %q", decision.Reasons, testCase.reason)
			}
			if err := decision.AuthorizeProductionUse(); !errors.Is(err, ErrDecisionNotQualified) {
				t.Fatalf("AuthorizeProductionUse() error = %v", err)
			}
		})
	}
}

func TestQualifiedDecisionIsDeterministicAcrossProofOrder(t *testing.T) {
	input := validQualificationInput()
	input.SourceProofs = append(input.SourceProofs, SourceProof{
		RuntimeID: "unused-runtime", State: SourceSupported, ObservedAt: input.AsOf.Add(-time.Minute), FreshUntil: input.AsOf.Add(time.Hour),
	})
	first := QualifyDecision(context.Background(), input)
	input.SourceProofs[0], input.SourceProofs[1] = input.SourceProofs[1], input.SourceProofs[0]
	second := QualifyDecision(context.Background(), input)
	if first.DecisionDigest != second.DecisionDigest {
		t.Fatalf("decision digest changed with proof order: %s != %s", first.DecisionDigest, second.DecisionDigest)
	}
}

func TestQualifiedDecisionDuplicateSourceProofFailsClosedAcrossOrder(t *testing.T) {
	input := validQualificationInput()
	input.SourceProofs = append(input.SourceProofs, SourceProof{
		RuntimeID: "runtime-1", State: SourceFailed,
		ObservedAt: input.AsOf.Add(-time.Minute), FreshUntil: input.AsOf.Add(time.Hour),
	})

	first := QualifyDecision(context.Background(), input)
	if first.Qualified || !containsQualificationReason(first.Reasons, QualificationSourceUnhealthy) {
		t.Fatalf("decision with failed duplicate source proof = %#v", first)
	}
	slices.Reverse(input.SourceProofs)
	second := QualifyDecision(context.Background(), input)
	assertQualificationDecisionStable(t, first, second)
}

func TestQualifiedDecisionDuplicateEvidenceProofFailsClosedAcrossOrder(t *testing.T) {
	input := validQualificationInput()
	input.EvidenceProofs = append(input.EvidenceProofs, EvidenceProof{
		EvidenceID: "evidence-1", State: EvidenceConflicting,
		CollectedAt: input.AsOf.Add(-time.Minute), ValidUntil: input.AsOf.Add(time.Hour),
	})

	first := QualifyDecision(context.Background(), input)
	if first.Qualified || !containsQualificationReason(first.Reasons, QualificationEvidenceConflicting) || !containsQualificationReason(first.Reasons, QualificationEvidenceNotCurrent) {
		t.Fatalf("decision with conflicting duplicate evidence proof = %#v", first)
	}
	slices.Reverse(input.EvidenceProofs)
	second := QualifyDecision(context.Background(), input)
	assertQualificationDecisionStable(t, first, second)
}

func TestQualifiedDecisionIsDeterministicAcrossDuplicatePrimaryKeys(t *testing.T) {
	input := validQualificationInput()
	input.SourceProofs = append(input.SourceProofs, SourceProof{
		RuntimeID: "runtime-1", State: SourceFailed,
		ObservedAt: input.AsOf.Add(-2 * time.Hour), FreshUntil: input.AsOf.Add(-time.Hour),
	})
	input.EvidenceProofs = append(input.EvidenceProofs, EvidenceProof{
		EvidenceID: "evidence-1", State: EvidenceConflicting,
		CollectedAt: input.AsOf.Add(-2 * time.Hour), ValidUntil: input.AsOf.Add(-time.Hour),
	})
	input.Exceptions = []ExceptionProof{
		{ExceptionID: "exception-1", Active: false, ValidUntil: input.AsOf.Add(time.Hour)},
		{ExceptionID: "exception-1", Active: true, ValidUntil: input.AsOf.Add(-time.Hour)},
	}
	input.Limitations = []Limitation{
		{Code: "scope_gap", Detail: "A required population is unavailable."},
		{Code: "scope_gap", Detail: "A required population is unavailable.", Blocking: true},
	}
	input.RequiredReviews = []ReviewRequirement{
		{Kind: "control_owner", Status: ReviewApproved, CompletedAt: input.AsOf.Add(-2 * time.Hour)},
		{Kind: "control_owner", Required: true, Status: ReviewPending, CompletedAt: input.AsOf.Add(-time.Hour), ValidUntil: input.AsOf.Add(time.Hour)},
	}

	first := QualifyDecision(context.Background(), input)
	slices.Reverse(input.SourceProofs)
	slices.Reverse(input.EvidenceProofs)
	slices.Reverse(input.Exceptions)
	slices.Reverse(input.Limitations)
	slices.Reverse(input.RequiredReviews)
	second := QualifyDecision(context.Background(), input)
	assertQualificationDecisionStable(t, first, second)
}

func assertQualificationDecisionStable(t *testing.T, first, second QualifiedDecision) {
	t.Helper()
	if first.ProofDigest != second.ProofDigest {
		t.Fatalf("proof digest changed with proof order: %s != %s", first.ProofDigest, second.ProofDigest)
	}
	if first.DecisionDigest != second.DecisionDigest {
		t.Fatalf("decision digest changed with proof order: %s != %s", first.DecisionDigest, second.DecisionDigest)
	}
	if strings.Join(qualificationReasonStrings(first.Reasons), ",") != strings.Join(qualificationReasonStrings(second.Reasons), ",") {
		t.Fatalf("reasons changed with proof order: %v != %v", first.Reasons, second.Reasons)
	}
}

func qualificationReasonStrings(values []QualificationReason) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = string(values[index])
	}
	return result
}

func TestAssuranceCanariesAreDetectedAndCannotAuthorizeProductionUse(t *testing.T) {
	input := validQualificationInput()
	tests := []struct {
		scenario AssuranceCanaryScenario
		reason   QualificationReason
	}{
		{CanaryIncompletePagination, QualificationPopulationIncomplete},
		{CanaryStaleEvidence, QualificationEvidenceNotCurrent},
		{CanaryUnhealthySource, QualificationSourceUnhealthy},
		{CanaryConflictingEvidence, QualificationEvidenceConflicting},
		{CanaryExpiredException, QualificationExceptionExpired},
		{CanaryFailedVerification, QualificationVerificationFailed},
	}
	for _, testCase := range tests {
		t.Run(string(testCase.scenario), func(t *testing.T) {
			result, err := RunAssuranceCanary(context.Background(), testCase.scenario, input)
			if err != nil {
				t.Fatalf("RunAssuranceCanary() error = %v", err)
			}
			if !result.Detected || result.ProductionEligible() {
				t.Fatalf("canary result = %#v", result)
			}
			if !containsQualificationReason(result.Reasons, testCase.reason) {
				t.Fatalf("reasons = %v, want %q", result.Reasons, testCase.reason)
			}
			if containsQualificationReason(result.Reasons, QualificationLimitationsUndeclared) {
				t.Fatalf("declared empty limitations were lost while cloning: %v", result.Reasons)
			}
			if !errors.Is(result.AuthorizeAuditPacket(), ErrCanaryProductionUse) || !errors.Is(result.AuthorizeAction(), ErrCanaryProductionUse) {
				t.Fatal("canary authorized a production packet or action")
			}
		})
	}
}

func TestAssuranceMetricsExposeCoverageAndCanaryEscapeCounters(t *testing.T) {
	old := observability.Default
	observability.Default = observability.NewRegistry()
	t.Cleanup(func() { observability.Default = old })

	qualified := validQualificationInput()
	QualifyDecision(context.Background(), qualified)
	unqualified := cloneQualificationInput(qualified)
	unqualified.SourceProofs[0].State = SourceFailed
	QualifyDecision(context.Background(), unqualified)
	if _, err := RunAssuranceCanary(context.Background(), CanaryUnhealthySource, qualified); err != nil {
		t.Fatal(err)
	}
	rendered := observability.Default.Render()
	for _, metric := range []string{
		`cerebro_assurance_decisions_total{status="qualified"} 1`,
		`cerebro_assurance_decisions_total{status="unqualified"} 1`,
		`cerebro_assurance_qualified_coverage_total{measure="applicable"} 2`,
		`cerebro_assurance_qualified_coverage_total{measure="qualified"} 1`,
		`cerebro_assurance_canary_runs_total{scenario="unhealthy_source",status="detected"} 1`,
	} {
		if !strings.Contains(rendered, metric) {
			t.Fatalf("metrics missing %q:\n%s", metric, rendered)
		}
	}
}

func validQualificationInput() QualificationInput {
	asOf := time.Date(2026, 7, 14, 16, 0, 0, 0, time.UTC)
	manifest := validManifest()
	manifest.PeriodEnd = asOf.Add(-time.Hour)
	manifest.CollectionCutoff = asOf.Add(-time.Hour)
	manifest.PeriodStart = asOf.Add(-24 * time.Hour)
	for index := range manifest.Receipts {
		manifest.Receipts[index].Cutoff = manifest.CollectionCutoff
		manifest.Receipts[index].Watermark = asOf.Add(-time.Hour)
	}
	result := validObjectiveResult()
	result.EvaluatedAt = asOf.Add(-30 * time.Minute)
	result.EvidenceIDs = []string{"evidence-1"}
	result.SourceRuntimeIDs = []string{"runtime-1"}
	return QualificationInput{
		Manifest: manifest,
		Result:   result,
		AsOf:     asOf,
		SourceProofs: []SourceProof{{
			RuntimeID: "runtime-1", State: SourceSupported, ObservedAt: asOf.Add(-time.Hour), FreshUntil: asOf.Add(time.Hour),
		}},
		EvidenceProofs: []EvidenceProof{{
			EvidenceID: "evidence-1", State: EvidenceSufficient, CollectedAt: asOf.Add(-time.Hour), ValidUntil: asOf.Add(time.Hour),
		}},
		Limitations: []Limitation{},
		RequiredReviews: []ReviewRequirement{{
			Kind: "control_owner", Required: true, Status: ReviewApproved, CompletedAt: asOf.Add(-time.Hour), ValidUntil: asOf.Add(24 * time.Hour),
		}},
		Verification: VerificationProof{Required: false, State: VerificationNotRequired},
	}
}

func containsQualificationReason(values []QualificationReason, expected QualificationReason) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
