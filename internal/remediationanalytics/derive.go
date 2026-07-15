package remediationanalytics

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const (
	SourceHealthHealthy   = "healthy"
	SourceHealthUnhealthy = "unhealthy"
	SourceHealthUnknown   = "unknown"

	VerificationStateVerifiedClosed = "verified_closed"
	VerificationStateStillMatching  = "still_matching"
	VerificationStateCensored       = "censored"

	VerificationResultNoMatch      = "no_match"
	VerificationResultStillMatches = "still_matches"
	VerificationResultFailed       = "failed"
	VerificationResultUnavailable  = "unavailable"

	CensoredMissingVerification = "missing_verification"
	CensoredSourceUnhealthy     = "source_unhealthy"
	CensoredSourceHealthUnknown = "source_health_unknown"
	CensoredVerificationFailed  = "verification_failed"
	CensoredVerificationMissing = "verification_unavailable"
	CensoredStaleEvidence       = "stale_evidence"
	CensoredIncompleteEvidence  = "incomplete_evidence"
	CensoredTruncatedEvidence   = "truncated_evidence"

	ResolutionTypeVerified = "verified"
	ResolutionTypeManual   = "manual"

	DurabilityOpen                      = "open"
	DurabilityVerifiedClosed            = "verified_closed"
	DurabilityObserving                 = "durability_observing"
	Durability30Days                    = "durable_30d"
	Durability90Days                    = "durable_90d"
	DurabilityRecurred                  = "recurred"
	DurabilityManualClosedUnverified    = "manual_closed_unverified"
	DurabilityIndeterminateSourceHealth = "indeterminate_source_unhealthy"
)

var ErrInvalidObservation = errors.New("invalid remediation observation")

type VerificationObservation struct {
	ID              string
	EvaluationRunID string
	Result          string
	Fresh           bool
	Complete        bool
	Truncated       bool
	ObservedAt      time.Time
}

type OutcomeInput struct {
	TenantID                  string
	FindingID                 string
	FindingFingerprint        string
	FindingRevision           string
	RuleID                    string
	RuleVersion               string
	DecisionID                string
	ProposalID                string
	ActionID                  string
	ActionType                string
	ActionVersion             string
	ExecutionID               string
	ProviderCapabilityVersion string
	SourceRuntimeID           string
	SourceHealth              string
	ProviderSucceeded         bool
	ActionCompletedAt         time.Time
	ObservedAt                time.Time
	EpisodeOpenedAt           time.Time
	Verification              *VerificationObservation
}

type ClosureObservation struct {
	ResolutionType string
	OutcomeID      string
	VerificationID string
	ResolvedAt     time.Time
}

type EpisodeInput struct {
	TenantID           string
	FindingID          string
	FindingFingerprint string
	FindingRevision    string
	RuleID             string
	RuleVersion        string
	SourceRuntimeID    string
	SourceHealth       string
	OpenedAt           time.Time
	Closure            *ClosureObservation
	ReopenedAt         time.Time
	AsOf               time.Time
}

// DeriveOutcome normalizes one realized-result observation. Provider success
// is retained as execution context but never establishes verification.
func DeriveOutcome(input OutcomeInput) (*ports.RemediationOutcomeRecord, error) {
	normalizeOutcomeInput(&input)
	if input.TenantID == "" || input.FindingID == "" || input.FindingFingerprint == "" || input.FindingRevision == "" ||
		input.RuleID == "" || input.RuleVersion == "" || input.ActionID == "" || input.ActionType == "" ||
		input.ActionVersion == "" || input.ExecutionID == "" || input.ProviderCapabilityVersion == "" ||
		input.SourceRuntimeID == "" || input.ObservedAt.IsZero() || input.EpisodeOpenedAt.IsZero() {
		return nil, fmt.Errorf("%w: tenant, finding, rule, action, execution, provider capability, source runtime, episode open time, and observation revisions are required", ErrInvalidObservation)
	}
	if input.ObservedAt.Before(input.EpisodeOpenedAt) {
		return nil, fmt.Errorf("%w: observed_at precedes episode opened_at", ErrInvalidObservation)
	}
	episodeID := episodeID(input.TenantID, input.FindingFingerprint, input.EpisodeOpenedAt)
	state, censored, verifiedAt, evaluationRunID, verificationID, err := classifyVerification(input)
	if err != nil {
		return nil, err
	}
	parts := []string{
		input.TenantID, episodeID, input.FindingID, input.FindingFingerprint, input.FindingRevision,
		input.RuleID, input.RuleVersion, input.DecisionID, input.ProposalID, input.ActionID, input.ActionType,
		input.ActionVersion, input.ExecutionID, input.ProviderCapabilityVersion, verificationID, evaluationRunID,
		state, censored, input.SourceHealth, input.SourceRuntimeID, fmt.Sprintf("%t", input.ProviderSucceeded),
		timeKey(input.ActionCompletedAt), timeKey(verifiedAt), timeKey(input.ObservedAt),
	}
	digest := digest(parts...)
	record := &ports.RemediationOutcomeRecord{
		ID: outcomeID(input.TenantID, digest),
		RemediationOutcomeBinding: ports.RemediationOutcomeBinding{
			TenantID: input.TenantID, EpisodeID: episodeID, FindingID: input.FindingID,
			FindingFingerprint: input.FindingFingerprint, FindingRevision: input.FindingRevision,
			RuleID: input.RuleID, RuleVersion: input.RuleVersion, DecisionID: input.DecisionID,
			ProposalID: input.ProposalID, ActionID: input.ActionID, ActionType: input.ActionType,
			ActionVersion: input.ActionVersion, ExecutionID: input.ExecutionID,
			ProviderCapabilityVersion: input.ProviderCapabilityVersion, VerificationID: verificationID,
			EvaluationRunID: evaluationRunID, SourceRuntimeID: input.SourceRuntimeID,
		},
		VerificationState:  state,
		CensoredReason:     censored,
		SourceHealth:       input.SourceHealth,
		ProviderSucceeded:  input.ProviderSucceeded,
		VerifiedResolution: state == VerificationStateVerifiedClosed,
		RemediationOutcomeTiming: ports.RemediationOutcomeTiming{
			ActionCompletedAt: input.ActionCompletedAt, VerifiedAt: verifiedAt, ObservedAt: input.ObservedAt,
		},
		Digest: digest,
	}
	if !verifiedAt.IsZero() && !input.ActionCompletedAt.IsZero() {
		if verifiedAt.Before(input.ActionCompletedAt) {
			return nil, fmt.Errorf("%w: verification precedes action completion", ErrInvalidObservation)
		}
		record.VerificationLatency = verifiedAt.Sub(input.ActionCompletedAt)
	}
	return record, nil
}

// DeriveEpisode computes the latest state for one finding open-to-close
// interval. Source-health gaps prevent durability credit.
func DeriveEpisode(input EpisodeInput) (*ports.ResolutionEpisodeRecord, error) {
	normalizeEpisodeInput(&input)
	if input.TenantID == "" || input.FindingID == "" || input.FindingFingerprint == "" || input.FindingRevision == "" ||
		input.RuleID == "" || input.RuleVersion == "" || input.SourceRuntimeID == "" || input.OpenedAt.IsZero() || input.AsOf.IsZero() {
		return nil, fmt.Errorf("%w: tenant, finding, rule, source runtime, opened_at, as_of, and revisions are required", ErrInvalidObservation)
	}
	if input.AsOf.Before(input.OpenedAt) {
		return nil, fmt.Errorf("%w: as_of precedes opened_at", ErrInvalidObservation)
	}
	record := &ports.ResolutionEpisodeRecord{
		EpisodeID:          episodeID(input.TenantID, input.FindingFingerprint, input.OpenedAt),
		TenantID:           input.TenantID,
		FindingID:          input.FindingID,
		FindingFingerprint: input.FindingFingerprint,
		FindingRevision:    input.FindingRevision,
		RuleID:             input.RuleID,
		RuleVersion:        input.RuleVersion,
		SourceHealth:       input.SourceHealth,
		SourceRuntimeID:    input.SourceRuntimeID,
		DurabilityState:    DurabilityOpen,
		OpenedAt:           input.OpenedAt,
		AsOf:               input.AsOf,
	}
	if input.Closure != nil {
		normalizeClosure(input.Closure)
		if input.Closure.ResolvedAt.IsZero() || input.Closure.ResolvedAt.Before(input.OpenedAt) || input.AsOf.Before(input.Closure.ResolvedAt) {
			return nil, fmt.Errorf("%w: resolution timestamps are not ordered", ErrInvalidObservation)
		}
		switch input.Closure.ResolutionType {
		case ResolutionTypeVerified:
			if input.Closure.OutcomeID == "" || input.Closure.VerificationID == "" {
				return nil, fmt.Errorf("%w: verified resolution requires outcome and verification ids", ErrInvalidObservation)
			}
		case ResolutionTypeManual:
			if input.Closure.VerificationID != "" {
				return nil, fmt.Errorf("%w: manual resolution cannot carry a verification id", ErrInvalidObservation)
			}
		default:
			return nil, fmt.Errorf("%w: unsupported resolution type %q", ErrInvalidObservation, input.Closure.ResolutionType)
		}
		record.ResolutionType = input.Closure.ResolutionType
		record.OutcomeID = input.Closure.OutcomeID
		record.VerificationID = input.Closure.VerificationID
		record.ResolvedAt = input.Closure.ResolvedAt
		record.TimeToResolution = input.Closure.ResolvedAt.Sub(input.OpenedAt)
		record.DurabilityState = durabilityState(input)
	}
	if !input.ReopenedAt.IsZero() {
		if input.Closure == nil || input.ReopenedAt.Before(input.Closure.ResolvedAt) || input.AsOf.Before(input.ReopenedAt) {
			return nil, fmt.Errorf("%w: recurrence requires an earlier resolution and ordered timestamps", ErrInvalidObservation)
		}
		record.ReopenedAt = input.ReopenedAt
		record.TimeToRecurrence = input.ReopenedAt.Sub(input.Closure.ResolvedAt)
		record.DurabilityState = DurabilityRecurred
	}
	record.RevisionDigest = digest(
		record.EpisodeID, record.FindingRevision, record.RuleVersion, record.ResolutionType,
		record.OutcomeID, record.VerificationID, record.SourceHealth, record.SourceRuntimeID,
		record.DurabilityState, timeKey(record.OpenedAt), timeKey(record.ResolvedAt),
		timeKey(record.ReopenedAt), timeKey(record.AsOf),
	)
	return record, nil
}

func classifyVerification(input OutcomeInput) (state, censored string, verifiedAt time.Time, evaluationRunID, verificationID string, err error) {
	verification := input.Verification
	if verification == nil {
		if input.SourceHealth != SourceHealthHealthy {
			return VerificationStateCensored, sourceHealthCensor(input.SourceHealth), time.Time{}, "", "", nil
		}
		return VerificationStateCensored, CensoredMissingVerification, time.Time{}, "", "", nil
	}
	verification.ID = strings.TrimSpace(verification.ID)
	verification.EvaluationRunID = strings.TrimSpace(verification.EvaluationRunID)
	verification.Result = strings.TrimSpace(verification.Result)
	if verification.ID == "" || verification.EvaluationRunID == "" || verification.ObservedAt.IsZero() {
		return "", "", time.Time{}, "", "", fmt.Errorf("%w: verification id, evaluation run id, and observed_at are required", ErrInvalidObservation)
	}
	if input.ObservedAt.Before(verification.ObservedAt) {
		return "", "", time.Time{}, "", "", fmt.Errorf("%w: observed_at precedes verification", ErrInvalidObservation)
	}
	if input.SourceHealth != SourceHealthHealthy {
		return VerificationStateCensored, sourceHealthCensor(input.SourceHealth), time.Time{}, verification.EvaluationRunID, verification.ID, nil
	}
	if verification.Truncated {
		return VerificationStateCensored, CensoredTruncatedEvidence, time.Time{}, verification.EvaluationRunID, verification.ID, nil
	}
	if !verification.Fresh {
		return VerificationStateCensored, CensoredStaleEvidence, time.Time{}, verification.EvaluationRunID, verification.ID, nil
	}
	if !verification.Complete {
		return VerificationStateCensored, CensoredIncompleteEvidence, time.Time{}, verification.EvaluationRunID, verification.ID, nil
	}
	switch verification.Result {
	case VerificationResultNoMatch:
		return VerificationStateVerifiedClosed, "", verification.ObservedAt.UTC(), verification.EvaluationRunID, verification.ID, nil
	case VerificationResultStillMatches:
		return VerificationStateStillMatching, "", verification.ObservedAt.UTC(), verification.EvaluationRunID, verification.ID, nil
	case VerificationResultFailed:
		return VerificationStateCensored, CensoredVerificationFailed, time.Time{}, verification.EvaluationRunID, verification.ID, nil
	case VerificationResultUnavailable:
		return VerificationStateCensored, CensoredVerificationMissing, time.Time{}, verification.EvaluationRunID, verification.ID, nil
	default:
		return "", "", time.Time{}, "", "", fmt.Errorf("%w: unsupported verification result %q", ErrInvalidObservation, verification.Result)
	}
}

func durabilityState(input EpisodeInput) string {
	if input.Closure.ResolutionType == ResolutionTypeManual {
		return DurabilityManualClosedUnverified
	}
	if input.SourceHealth != SourceHealthHealthy {
		return DurabilityIndeterminateSourceHealth
	}
	age := input.AsOf.Sub(input.Closure.ResolvedAt)
	switch {
	case age >= 90*24*time.Hour:
		return Durability90Days
	case age >= 30*24*time.Hour:
		return Durability30Days
	case age > 0:
		return DurabilityObserving
	default:
		return DurabilityVerifiedClosed
	}
}

func normalizeOutcomeInput(input *OutcomeInput) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.FindingID = strings.TrimSpace(input.FindingID)
	input.FindingFingerprint = strings.TrimSpace(input.FindingFingerprint)
	input.FindingRevision = strings.TrimSpace(input.FindingRevision)
	input.RuleID = strings.TrimSpace(input.RuleID)
	input.RuleVersion = strings.TrimSpace(input.RuleVersion)
	input.DecisionID = strings.TrimSpace(input.DecisionID)
	input.ProposalID = strings.TrimSpace(input.ProposalID)
	input.ActionID = strings.TrimSpace(input.ActionID)
	input.ActionType = strings.TrimSpace(input.ActionType)
	input.ActionVersion = strings.TrimSpace(input.ActionVersion)
	input.ExecutionID = strings.TrimSpace(input.ExecutionID)
	input.ProviderCapabilityVersion = strings.TrimSpace(input.ProviderCapabilityVersion)
	input.SourceRuntimeID = strings.TrimSpace(input.SourceRuntimeID)
	input.SourceHealth = normalizeSourceHealth(input.SourceHealth)
	input.ActionCompletedAt = input.ActionCompletedAt.UTC()
	input.ObservedAt = input.ObservedAt.UTC()
	input.EpisodeOpenedAt = input.EpisodeOpenedAt.UTC()
}

func normalizeEpisodeInput(input *EpisodeInput) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.FindingID = strings.TrimSpace(input.FindingID)
	input.FindingFingerprint = strings.TrimSpace(input.FindingFingerprint)
	input.FindingRevision = strings.TrimSpace(input.FindingRevision)
	input.RuleID = strings.TrimSpace(input.RuleID)
	input.RuleVersion = strings.TrimSpace(input.RuleVersion)
	input.SourceRuntimeID = strings.TrimSpace(input.SourceRuntimeID)
	input.SourceHealth = normalizeSourceHealth(input.SourceHealth)
	input.OpenedAt = input.OpenedAt.UTC()
	input.ReopenedAt = input.ReopenedAt.UTC()
	input.AsOf = input.AsOf.UTC()
}

func normalizeClosure(closure *ClosureObservation) {
	closure.ResolutionType = strings.TrimSpace(closure.ResolutionType)
	closure.OutcomeID = strings.TrimSpace(closure.OutcomeID)
	closure.VerificationID = strings.TrimSpace(closure.VerificationID)
	closure.ResolvedAt = closure.ResolvedAt.UTC()
}

func normalizeSourceHealth(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SourceHealthHealthy:
		return SourceHealthHealthy
	case SourceHealthUnhealthy:
		return SourceHealthUnhealthy
	default:
		return SourceHealthUnknown
	}
}

func sourceHealthCensor(value string) string {
	if value == SourceHealthUnhealthy {
		return CensoredSourceUnhealthy
	}
	return CensoredSourceHealthUnknown
}

func episodeID(tenantID, fingerprint string, openedAt time.Time) string {
	return fmt.Sprintf("urn:cerebro:%s:resolution_episode:%s", urnSegment(tenantID), digest(tenantID, fingerprint, timeKey(openedAt)))
}

func outcomeID(tenantID, recordDigest string) string {
	return fmt.Sprintf("urn:cerebro:%s:remediation_outcome:%s", urnSegment(tenantID), recordDigest)
}

func urnSegment(value string) string {
	return strings.ReplaceAll(url.PathEscape(strings.TrimSpace(value)), ":", "%3A")
}

func digest(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func timeKey(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
