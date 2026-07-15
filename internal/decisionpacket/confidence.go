package decisionpacket

import "github.com/writer/cerebro/internal/agentplatform"

func DeriveDecision(inputs DecisionInputs) Decision {
	if inputs.Applicable != nil && !*inputs.Applicable {
		return Decision{State: DecisionNotApplicable, Reasons: []string{"explicitly_not_applicable"}}
	}

	state := DecisionInsufficientEvidence
	reasons := []string{}
	switch inputs.ClaimVerdict {
	case agentplatform.ClaimVerdictSupported:
		state = DecisionSupported
	case agentplatform.ClaimVerdictWeaklySupported:
		state = DecisionSupportedWithGaps
		reasons = append(reasons, "weak_claim_support")
	case agentplatform.ClaimVerdictContradicted:
		state = DecisionBlocked
		reasons = append(reasons, "claim_contradicted")
	default:
		reasons = append(reasons, "claim_evidence_insufficient")
	}

	if inputs.PrimaryConflict {
		state = DecisionBlocked
		reasons = append(reasons, "primary_claim_contradiction")
	}
	if state == DecisionSupported && (inputs.RequiredGap || inputs.RequiredStale || inputs.OutcomeTruncated) {
		state = DecisionSupportedWithGaps
	}
	if inputs.RequiredGap {
		reasons = append(reasons, "required_coverage_gap")
	}
	if inputs.RequiredStale {
		reasons = append(reasons, "required_evidence_stale")
	}
	if inputs.OutcomeTruncated {
		reasons = append(reasons, "decision_inputs_truncated")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "claim_supported")
	}
	return Decision{State: state, Reasons: uniqueSortedStrings(reasons)}
}

func DeriveConfidence(inputs ConfidenceInputs) Confidence {
	if inputs.SupportingEvidence == 0 {
		return Confidence{Level: ConfidenceUnknown, Basis: []string{"no_supporting_evidence"}}
	}

	level := ConfidenceHigh
	basis := []string{}
	if !inputs.GuardrailsPassed {
		level = ConfidenceLow
		basis = append(basis, "guardrails_not_passed")
	}
	if inputs.RequiredGap {
		level = ConfidenceLow
		basis = append(basis, "required_coverage_gap")
	}
	if inputs.RequiredStale {
		level = ConfidenceLow
		basis = append(basis, "required_evidence_stale")
	}
	if inputs.RequiredUnverified {
		level = ConfidenceLow
		basis = append(basis, "required_source_unverified")
	}
	if inputs.OutcomeTruncated {
		level = ConfidenceLow
		basis = append(basis, "decision_inputs_truncated")
	}
	if inputs.UnresolvedConflict {
		level = lowerConfidence(level, ConfidenceMedium)
		basis = append(basis, "unresolved_contradiction")
	}
	if inputs.OptionalGapMatters {
		level = lowerConfidence(level, ConfidenceMedium)
		basis = append(basis, "material_optional_coverage_gap")
	}
	if len(basis) == 0 {
		basis = append(basis, "fresh_complete_nonconflicting_evidence")
	}
	return Confidence{Level: level, Basis: uniqueSortedStrings(basis)}
}

func lowerConfidence(current, cap string) string {
	rank := map[string]int{ConfidenceUnknown: 0, ConfidenceLow: 1, ConfidenceMedium: 2, ConfidenceHigh: 3}
	if rank[current] > rank[cap] {
		return cap
	}
	return current
}
