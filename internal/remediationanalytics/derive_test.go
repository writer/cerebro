package remediationanalytics

import (
	"testing"
	"time"
)

func TestDeriveOutcomeProviderSuccessWithoutVerificationIsCensored(t *testing.T) {
	input := validOutcomeInput()
	input.ProviderSucceeded = true
	input.Verification = nil

	record, err := DeriveOutcome(input)
	if err != nil {
		t.Fatalf("DeriveOutcome() error = %v", err)
	}
	if record.VerificationState != VerificationStateCensored || record.CensoredReason != CensoredMissingVerification {
		t.Fatalf("verification = %q/%q, want censored/missing_verification", record.VerificationState, record.CensoredReason)
	}
	if record.VerifiedResolution {
		t.Fatal("provider success counted as verified resolution")
	}
}

func TestDeriveOutcomeRequiresFreshCompleteExactEvaluation(t *testing.T) {
	tests := []struct {
		name           string
		mutate         func(*OutcomeInput)
		wantState      string
		wantCensor     string
		wantResolution bool
	}{
		{name: "verified closed", wantState: VerificationStateVerifiedClosed, wantResolution: true},
		{name: "still matching", mutate: func(input *OutcomeInput) { input.Verification.Result = VerificationResultStillMatches }, wantState: VerificationStateStillMatching},
		{name: "stale", mutate: func(input *OutcomeInput) { input.Verification.Fresh = false }, wantState: VerificationStateCensored, wantCensor: CensoredStaleEvidence},
		{name: "incomplete", mutate: func(input *OutcomeInput) { input.Verification.Complete = false }, wantState: VerificationStateCensored, wantCensor: CensoredIncompleteEvidence},
		{name: "truncated", mutate: func(input *OutcomeInput) { input.Verification.Truncated = true }, wantState: VerificationStateCensored, wantCensor: CensoredTruncatedEvidence},
		{name: "source unhealthy", mutate: func(input *OutcomeInput) { input.SourceHealth = SourceHealthUnhealthy }, wantState: VerificationStateCensored, wantCensor: CensoredSourceUnhealthy},
		{name: "source health unknown", mutate: func(input *OutcomeInput) { input.SourceHealth = "" }, wantState: VerificationStateCensored, wantCensor: CensoredSourceHealthUnknown},
		{name: "verification failed", mutate: func(input *OutcomeInput) { input.Verification.Result = VerificationResultFailed }, wantState: VerificationStateCensored, wantCensor: CensoredVerificationFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validOutcomeInput()
			if test.mutate != nil {
				test.mutate(&input)
			}
			record, err := DeriveOutcome(input)
			if err != nil {
				t.Fatalf("DeriveOutcome() error = %v", err)
			}
			if record.VerificationState != test.wantState || record.CensoredReason != test.wantCensor {
				t.Fatalf("verification = %q/%q, want %q/%q", record.VerificationState, record.CensoredReason, test.wantState, test.wantCensor)
			}
			if record.VerifiedResolution != test.wantResolution {
				t.Fatalf("VerifiedResolution = %t, want %t", record.VerifiedResolution, test.wantResolution)
			}
		})
	}
}

func TestDeriveOutcomeIsDeterministicAndVersionScoped(t *testing.T) {
	input := validOutcomeInput()
	first, err := DeriveOutcome(input)
	if err != nil {
		t.Fatalf("DeriveOutcome(first) error = %v", err)
	}
	second, err := DeriveOutcome(input)
	if err != nil {
		t.Fatalf("DeriveOutcome(second) error = %v", err)
	}
	if first.ID != second.ID || first.Digest != second.Digest || first.EpisodeID != second.EpisodeID {
		t.Fatalf("deterministic record changed: first=%+v second=%+v", first, second)
	}
	input.RuleVersion = "rule-v3"
	versioned, err := DeriveOutcome(input)
	if err != nil {
		t.Fatalf("DeriveOutcome(versioned) error = %v", err)
	}
	if versioned.ID == first.ID {
		t.Fatal("rule version change did not produce a distinct observation")
	}
	if versioned.EpisodeID != first.EpisodeID {
		t.Fatal("rule version change split the open-to-close episode")
	}
}

func TestDeriveEpisodeDurabilityAndRecurrence(t *testing.T) {
	base := validEpisodeInput()
	tests := []struct {
		name      string
		mutate    func(*EpisodeInput)
		wantState string
		wantRecur time.Duration
	}{
		{name: "verified close", mutate: func(input *EpisodeInput) { input.AsOf = input.Closure.ResolvedAt }, wantState: DurabilityVerifiedClosed},
		{name: "observing", wantState: DurabilityObserving},
		{name: "thirty days", mutate: func(input *EpisodeInput) { input.AsOf = input.Closure.ResolvedAt.Add(30 * 24 * time.Hour) }, wantState: Durability30Days},
		{name: "ninety days", mutate: func(input *EpisodeInput) { input.AsOf = input.Closure.ResolvedAt.Add(90 * 24 * time.Hour) }, wantState: Durability90Days},
		{name: "source unhealthy", mutate: func(input *EpisodeInput) { input.SourceHealth = SourceHealthUnhealthy }, wantState: DurabilityIndeterminateSourceHealth},
		{name: "recurred", mutate: func(input *EpisodeInput) {
			input.ReopenedAt = input.Closure.ResolvedAt.Add(12 * time.Hour)
			input.AsOf = input.ReopenedAt
		}, wantState: DurabilityRecurred, wantRecur: 12 * time.Hour},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			closure := *base.Closure
			input.Closure = &closure
			if test.mutate != nil {
				test.mutate(&input)
			}
			record, err := DeriveEpisode(input)
			if err != nil {
				t.Fatalf("DeriveEpisode() error = %v", err)
			}
			if record.DurabilityState != test.wantState {
				t.Fatalf("DurabilityState = %q, want %q", record.DurabilityState, test.wantState)
			}
			if record.TimeToRecurrence != test.wantRecur {
				t.Fatalf("TimeToRecurrence = %s, want %s", record.TimeToRecurrence, test.wantRecur)
			}
		})
	}
}

func TestDeriveEpisodeKeepsManualClosureSeparate(t *testing.T) {
	input := validEpisodeInput()
	input.Closure = &ClosureObservation{ResolutionType: ResolutionTypeManual, ResolvedAt: input.Closure.ResolvedAt}
	record, err := DeriveEpisode(input)
	if err != nil {
		t.Fatalf("DeriveEpisode() error = %v", err)
	}
	if record.DurabilityState != DurabilityManualClosedUnverified {
		t.Fatalf("DurabilityState = %q, want manual_closed_unverified", record.DurabilityState)
	}
	if record.VerificationID != "" || record.OutcomeID != "" {
		t.Fatalf("manual closure carries verified refs: %+v", record)
	}
}

func TestDeriveEpisodeRejectsVerifiedClosureWithoutVerification(t *testing.T) {
	input := validEpisodeInput()
	input.Closure.VerificationID = ""
	if _, err := DeriveEpisode(input); err == nil {
		t.Fatal("DeriveEpisode() error = nil, want missing verification error")
	}
}

func validOutcomeInput() OutcomeInput {
	openedAt := time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)
	actionAt := openedAt.Add(2 * time.Hour)
	verifiedAt := actionAt.Add(15 * time.Minute)
	return OutcomeInput{
		TenantID: "tenant-a", FindingID: "finding-1", FindingFingerprint: "fingerprint-1",
		FindingRevision: "finding-v4", RuleID: "rule-1", RuleVersion: "rule-v2",
		DecisionID: "decision-1", ProposalID: "proposal-1", ActionID: "action-1",
		ActionType: "identity.okta.suspend_user", ActionVersion: "action-v1",
		ExecutionID: "execution-1", ProviderCapabilityVersion: "okta-v3",
		SourceRuntimeID: "runtime-1", SourceHealth: SourceHealthHealthy,
		ProviderSucceeded: true, ActionCompletedAt: actionAt, ObservedAt: verifiedAt,
		EpisodeOpenedAt: openedAt,
		Verification:    &VerificationObservation{ID: "verification-1", EvaluationRunID: "evaluation-1", Result: VerificationResultNoMatch, Fresh: true, Complete: true, ObservedAt: verifiedAt},
	}
}

func validEpisodeInput() EpisodeInput {
	openedAt := time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)
	resolvedAt := openedAt.Add(24 * time.Hour)
	return EpisodeInput{
		TenantID: "tenant-a", FindingID: "finding-1", FindingFingerprint: "fingerprint-1",
		FindingRevision: "finding-v4", RuleID: "rule-1", RuleVersion: "rule-v2",
		SourceRuntimeID: "runtime-1", SourceHealth: SourceHealthHealthy, OpenedAt: openedAt,
		Closure: &ClosureObservation{ResolutionType: ResolutionTypeVerified, OutcomeID: "outcome-1", VerificationID: "verification-1", ResolvedAt: resolvedAt},
		AsOf:    resolvedAt.Add(24 * time.Hour),
	}
}
