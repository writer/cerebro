package complianceassessment

import (
	"context"
	"fmt"
	"time"

	"github.com/writer/cerebro/internal/observability"
)

type AssuranceCanaryScenario string

const (
	CanaryIncompletePagination AssuranceCanaryScenario = "incomplete_pagination"
	CanaryStaleEvidence        AssuranceCanaryScenario = "stale_evidence"
	CanaryUnhealthySource      AssuranceCanaryScenario = "unhealthy_source"
	CanaryConflictingEvidence  AssuranceCanaryScenario = "conflicting_evidence"
	CanaryExpiredException     AssuranceCanaryScenario = "expired_exception"
	CanaryFailedVerification   AssuranceCanaryScenario = "failed_verification"
)

type AssuranceCanaryResult struct {
	Scenario    AssuranceCanaryScenario `json:"scenario"`
	Detected    bool                    `json:"detected"`
	Reasons     []QualificationReason   `json:"reasons"`
	ProbeDigest string                  `json:"probe_digest"`
}

func (AssuranceCanaryResult) ProductionEligible() bool { return false }

func (AssuranceCanaryResult) AuthorizeAuditPacket() error { return ErrCanaryProductionUse }

func (AssuranceCanaryResult) AuthorizeAction() error { return ErrCanaryProductionUse }

// RunAssuranceCanary injects one known failure into an otherwise production-
// shaped decision. The return type cannot be converted to a QualifiedDecision,
// and its packet/action authorization methods always fail closed.
func RunAssuranceCanary(ctx context.Context, scenario AssuranceCanaryScenario, base QualificationInput) (AssuranceCanaryResult, error) {
	input := cloneQualificationInput(base)
	switch scenario {
	case CanaryIncompletePagination:
		if len(input.Manifest.Receipts) == 0 {
			return AssuranceCanaryResult{}, fmt.Errorf("%s canary requires a collection receipt", scenario)
		}
		input.Manifest.Receipts[0].Completeness = CollectionPartial
	case CanaryStaleEvidence:
		if len(input.EvidenceProofs) == 0 {
			return AssuranceCanaryResult{}, fmt.Errorf("%s canary requires evidence proof", scenario)
		}
		input.EvidenceProofs[0].ValidUntil = input.AsOf.Add(-time.Millisecond)
	case CanaryUnhealthySource:
		if len(input.SourceProofs) == 0 {
			return AssuranceCanaryResult{}, fmt.Errorf("%s canary requires source proof", scenario)
		}
		input.SourceProofs[0].State = SourceFailed
	case CanaryConflictingEvidence:
		input.Result.AutomatedOutcome = OutcomeIndeterminate
		input.Result.EvidenceState = EvidenceConflicting
		input.Result.Assurance = AssuranceNone
		input.Result.ReasonCodes = []ReasonCode{ReasonEvidenceConflicting}
		input.Result.NextActions = []NextAction{ActionReview}
	case CanaryExpiredException:
		input.Exceptions = append(input.Exceptions, ExceptionProof{
			ExceptionID: "assurance-canary-expired-exception",
			Active:      true,
			ValidUntil:  input.AsOf.Add(-time.Millisecond),
		})
	case CanaryFailedVerification:
		input.Verification = VerificationProof{
			Required:   true,
			State:      VerificationFailed,
			VerifiedAt: input.AsOf.Add(-time.Minute),
			ValidUntil: input.AsOf.Add(time.Hour),
		}
	default:
		return AssuranceCanaryResult{}, fmt.Errorf("unknown assurance canary scenario %q", scenario)
	}

	decision := evaluateQualification(input)
	result := AssuranceCanaryResult{
		Scenario: scenario,
		Detected: !decision.Qualified,
		Reasons:  append([]QualificationReason(nil), decision.Reasons...),
	}
	digestInput := struct {
		Scenario       AssuranceCanaryScenario `json:"scenario"`
		Detected       bool                    `json:"detected"`
		DecisionDigest string                  `json:"decision_digest"`
	}{scenario, result.Detected, decision.DecisionDigest}
	data, err := canonicalBytes(digestInput)
	if err != nil {
		return AssuranceCanaryResult{}, err
	}
	result.ProbeDigest = digestBytes(data)
	status := "escaped"
	if result.Detected {
		status = "detected"
	}
	observability.Default.Inc("cerebro_assurance_canary_runs_total", map[string]string{
		"scenario": string(scenario),
		"status":   status,
	})
	return result, nil
}

func cloneQualificationInput(input QualificationInput) QualificationInput {
	clone := input
	clone.Manifest = NormalizeManifest(input.Manifest)
	clone.Result = NormalizeResult(input.Result)
	clone.SourceProofs = append([]SourceProof(nil), input.SourceProofs...)
	clone.EvidenceProofs = append([]EvidenceProof(nil), input.EvidenceProofs...)
	clone.Limitations = append([]Limitation(nil), input.Limitations...)
	clone.RequiredReviews = append([]ReviewRequirement(nil), input.RequiredReviews...)
	clone.Exceptions = append([]ExceptionProof(nil), input.Exceptions...)
	return clone
}
