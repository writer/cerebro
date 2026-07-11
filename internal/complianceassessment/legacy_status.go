package complianceassessment

const (
	LegacyStatusNotApplicable   = "not_applicable"
	LegacyStatusException       = "exception"
	LegacyStatusFailing         = "failing"
	LegacyStatusMissingEvidence = "missing_evidence"
	LegacyStatusStaleEvidence   = "stale_evidence"
	LegacyStatusManualReview    = "manual_review"
	LegacyStatusPassing         = "passing"
)

// LegacyStatus preserves the existing caller precedence while the canonical
// result retains independent automation, evidence, and disposition axes.
func LegacyStatus(result ObjectiveResult) string {
	if result.ScopeState == ScopeNotApplicable {
		return LegacyStatusNotApplicable
	}
	if result.DispositionState == DispositionAcceptedException || result.DispositionState == DispositionAcceptedRisk {
		return LegacyStatusException
	}
	if result.AutomatedOutcome == OutcomeNotSatisfied {
		return LegacyStatusFailing
	}
	switch result.EvidenceState {
	case EvidenceMissing, EvidenceIncomplete:
		return LegacyStatusMissingEvidence
	case EvidenceStale:
		return LegacyStatusStaleEvidence
	case EvidenceManualReview, EvidenceConflicting, EvidenceUntrusted:
		return LegacyStatusManualReview
	case EvidenceSufficient:
		if result.AutomatedOutcome == OutcomeSatisfied {
			return LegacyStatusPassing
		}
	}
	return LegacyStatusManualReview
}
