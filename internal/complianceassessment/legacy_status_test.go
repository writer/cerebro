package complianceassessment

import "testing"

func TestLegacyStatusPreservesExistingPrecedence(t *testing.T) {
	result := validObjectiveResult()
	result.ScopeState = ScopeNotApplicable
	result.DispositionState = DispositionAcceptedException
	result.AutomatedOutcome = OutcomeNotSatisfied
	result.EvidenceState = EvidenceMissing
	if got := LegacyStatus(result); got != LegacyStatusNotApplicable {
		t.Fatalf("not applicable precedence = %q", got)
	}
	result.ScopeState = ScopeInScope
	if got := LegacyStatus(result); got != LegacyStatusException {
		t.Fatalf("exception precedence = %q", got)
	}
	result.DispositionState = DispositionNone
	if got := LegacyStatus(result); got != LegacyStatusFailing {
		t.Fatalf("failing precedence = %q", got)
	}
	result.AutomatedOutcome = OutcomeIndeterminate
	if got := LegacyStatus(result); got != LegacyStatusMissingEvidence {
		t.Fatalf("missing evidence precedence = %q", got)
	}
}
