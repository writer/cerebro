// Package remediationanalytics derives deterministic remediation outcome records
// from canonical prediction, verification, finding, and source-health facts.
package remediationanalytics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

var ErrInvalidRecord = errors.New("invalid remediation analytics record")

type FindingRevision struct {
	FindingID   string `json:"finding_id"`
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	Revision    uint64 `json:"revision"`
}

type PredictionReceipt struct {
	TenantID                 string            `json:"tenant_id"`
	ReportRunID              string            `json:"report_run_id"`
	CandidateID              string            `json:"candidate_id"`
	PlanModelVersion         string            `json:"plan_model_version"`
	ActionType               string            `json:"action_type"`
	TargetType               string            `json:"target_type"`
	FindingRevisions         []FindingRevision `json:"finding_revisions"`
	PredictedRiskDelta       float64           `json:"predicted_risk_delta"`
	PredictedAttackPathDelta float64           `json:"predicted_attack_path_delta"`
	PredictedEffort          time.Duration     `json:"predicted_effort"`
	PredictedCostMicros      int64             `json:"predicted_cost_micros"`
	PredictedCollateralRisk  float64           `json:"predicted_collateral_risk"`
	RollbackPlanDigest       string            `json:"rollback_plan_digest"`
	CreatedAt                time.Time         `json:"created_at"`
	Digest                   string            `json:"digest"`
}

type PredictionInput struct {
	TenantID                 string
	ReportRunID              string
	CandidateID              string
	PlanModelVersion         string
	ActionType               string
	TargetType               string
	FindingRevisions         []FindingRevision
	PredictedRiskDelta       float64
	PredictedAttackPathDelta float64
	PredictedEffort          time.Duration
	PredictedCostMicros      int64
	PredictedCollateralRisk  float64
	RollbackPlanDigest       string
	CreatedAt                time.Time
}

func NewPredictionReceipt(input PredictionInput) (PredictionReceipt, error) {
	if missing(input.TenantID, input.ReportRunID, input.CandidateID, input.PlanModelVersion, input.ActionType, input.TargetType) {
		return PredictionReceipt{}, fmt.Errorf("%w: prediction identity is required", ErrInvalidRecord)
	}
	if input.CreatedAt.IsZero() || invalidNumber(input.PredictedRiskDelta) || invalidNumber(input.PredictedAttackPathDelta) ||
		input.PredictedEffort <= 0 || input.PredictedCostMicros < 0 || invalidProbability(input.PredictedCollateralRisk) || !validDigest(input.RollbackPlanDigest) {
		return PredictionReceipt{}, fmt.Errorf("%w: prediction time, operational baseline, rollback plan, and finite deltas are required", ErrInvalidRecord)
	}
	findings, err := normalizeFindingRevisions(input.FindingRevisions)
	if err != nil {
		return PredictionReceipt{}, err
	}
	receipt := PredictionReceipt{
		TenantID:                 strings.TrimSpace(input.TenantID),
		ReportRunID:              strings.TrimSpace(input.ReportRunID),
		CandidateID:              strings.TrimSpace(input.CandidateID),
		PlanModelVersion:         strings.TrimSpace(input.PlanModelVersion),
		ActionType:               strings.TrimSpace(input.ActionType),
		TargetType:               strings.TrimSpace(input.TargetType),
		FindingRevisions:         findings,
		PredictedRiskDelta:       input.PredictedRiskDelta,
		PredictedAttackPathDelta: input.PredictedAttackPathDelta,
		PredictedEffort:          input.PredictedEffort,
		PredictedCostMicros:      input.PredictedCostMicros,
		PredictedCollateralRisk:  input.PredictedCollateralRisk,
		RollbackPlanDigest:       strings.TrimSpace(input.RollbackPlanDigest),
		CreatedAt:                canonicalTime(input.CreatedAt),
	}
	receipt.Digest, err = digest(receipt)
	return receipt, err
}

func validatePredictionReceipt(receipt PredictionReceipt) error {
	rebuilt, err := NewPredictionReceipt(PredictionInput{
		TenantID:                 receipt.TenantID,
		ReportRunID:              receipt.ReportRunID,
		CandidateID:              receipt.CandidateID,
		PlanModelVersion:         receipt.PlanModelVersion,
		ActionType:               receipt.ActionType,
		TargetType:               receipt.TargetType,
		FindingRevisions:         receipt.FindingRevisions,
		PredictedRiskDelta:       receipt.PredictedRiskDelta,
		PredictedAttackPathDelta: receipt.PredictedAttackPathDelta,
		PredictedEffort:          receipt.PredictedEffort,
		PredictedCostMicros:      receipt.PredictedCostMicros,
		PredictedCollateralRisk:  receipt.PredictedCollateralRisk,
		RollbackPlanDigest:       receipt.RollbackPlanDigest,
		CreatedAt:                receipt.CreatedAt,
	})
	if err != nil {
		return err
	}
	if rebuilt.Digest != receipt.Digest {
		return fmt.Errorf("%w: prediction receipt does not match its digest", ErrInvalidRecord)
	}
	return nil
}

type SourceHealth string

const (
	SourceHealthy   SourceHealth = "healthy"
	SourceUnhealthy SourceHealth = "unhealthy"
	SourceUnknown   SourceHealth = "unknown"
)

type RealizedResult struct {
	RealizedIdentity
	RealizedVerification
	RealizedBenefit
	RealizedOperations
	Digest string `json:"digest"`
}

type RealizedIdentity struct {
	TenantID         string `json:"tenant_id"`
	PredictionDigest string `json:"prediction_digest"`
	PlanModelVersion string `json:"plan_model_version"`
	ActionType       string `json:"action_type"`
	TargetType       string `json:"target_type"`
	ExecutionID      string `json:"execution_id"`
}

type RealizedVerification struct {
	VerificationID             string        `json:"verification_id,omitempty"`
	ExecutorPrincipalID        string        `json:"executor_principal_id"`
	VerifierPrincipalID        string        `json:"verifier_principal_id,omitempty"`
	VerificationEvidenceDigest string        `json:"verification_evidence_digest,omitempty"`
	SourceHealth               SourceHealth  `json:"source_health"`
	CensoredReason             string        `json:"censored_reason,omitempty"`
	VerificationLatency        time.Duration `json:"verification_latency"`
	ObservedAt                 time.Time     `json:"observed_at"`
}

type RealizedBenefit struct {
	VerifiedClosedFindingIDs []string `json:"verified_closed_finding_ids,omitempty"`
	StillMatchingFindingIDs  []string `json:"still_matching_finding_ids,omitempty"`
	RealizedRiskDelta        *float64 `json:"realized_risk_delta,omitempty"`
	RealizedAttackPathDelta  *float64 `json:"realized_attack_path_delta,omitempty"`
	RiskPredictionError      *float64 `json:"risk_prediction_error,omitempty"`
}

type RealizedOperations struct {
	ActualEffort              time.Duration `json:"actual_effort"`
	EffortPredictionError     time.Duration `json:"effort_prediction_error"`
	ActualCostMicros          int64         `json:"actual_cost_micros"`
	CostPredictionErrorMicros int64         `json:"cost_prediction_error_micros"`
	CollateralFindingIDs      []string      `json:"collateral_finding_ids,omitempty"`
	PredictedCollateralRisk   float64       `json:"predicted_collateral_risk"`
	CollateralOccurred        bool          `json:"collateral_occurred"`
	CollateralPredictionError float64       `json:"collateral_prediction_error"`
	RollbackPlanDigest        string        `json:"rollback_plan_digest"`
	RolledBack                bool          `json:"rolled_back"`
	RollbackCompletedAt       time.Time     `json:"rollback_completed_at,omitempty"`
	RollbackLatency           time.Duration `json:"rollback_latency,omitempty"`
}

type RealizedInput struct {
	Prediction                 PredictionReceipt
	VerificationID             string
	ExecutionID                string
	ExecutorPrincipalID        string
	VerifierPrincipalID        string
	VerificationEvidenceDigest string
	VerifiedClosedFindingIDs   []string
	StillMatchingFindingIDs    []string
	SourceHealth               SourceHealth
	CensoredReason             string
	RealizedRiskDelta          *float64
	RealizedAttackPathDelta    *float64
	ActualEffort               time.Duration
	ActualCostMicros           int64
	CollateralFindingIDs       []string
	RolledBack                 bool
	RollbackCompletedAt        time.Time
	ObservedAt                 time.Time
}

func NewRealizedResult(input RealizedInput) (RealizedResult, error) {
	if err := validatePredictionReceipt(input.Prediction); err != nil {
		return RealizedResult{}, err
	}
	if input.ObservedAt.IsZero() || input.ObservedAt.Before(input.Prediction.CreatedAt) ||
		missing(input.ExecutionID, input.ExecutorPrincipalID) || input.ActualEffort <= 0 || input.ActualCostMicros < 0 {
		return RealizedResult{}, fmt.Errorf("%w: execution identity, effort, cost, and bounded observation time are required", ErrInvalidRecord)
	}
	if input.SourceHealth != SourceHealthy && input.SourceHealth != SourceUnhealthy && input.SourceHealth != SourceUnknown {
		return RealizedResult{}, fmt.Errorf("%w: source health is required", ErrInvalidRecord)
	}
	closed := normalizedStrings(input.VerifiedClosedFindingIDs)
	matching := normalizedStrings(input.StillMatchingFindingIDs)
	if overlaps(closed, matching) {
		return RealizedResult{}, fmt.Errorf("%w: a finding cannot be closed and still matching", ErrInvalidRecord)
	}
	allowed := findingIDSet(input.Prediction.FindingRevisions)
	if !subset(closed, allowed) || !subset(matching, allowed) {
		return RealizedResult{}, fmt.Errorf("%w: realized findings must be bound to the prediction", ErrInvalidRecord)
	}
	censored := strings.TrimSpace(input.CensoredReason)
	verified := strings.TrimSpace(input.VerificationID)
	executor := strings.TrimSpace(input.ExecutorPrincipalID)
	verifier := strings.TrimSpace(input.VerifierPrincipalID)
	verificationDigest := strings.TrimSpace(input.VerificationEvidenceDigest)
	if input.SourceHealth != SourceHealthy || verified == "" {
		if censored == "" {
			return RealizedResult{}, fmt.Errorf("%w: unavailable verification must include a censored reason", ErrInvalidRecord)
		}
		if input.RealizedRiskDelta != nil || input.RealizedAttackPathDelta != nil || len(closed) != 0 || len(matching) != 0 {
			return RealizedResult{}, fmt.Errorf("%w: censored results cannot claim realized benefit", ErrInvalidRecord)
		}
	} else if censored != "" || verifier == "" || executor == verifier || !validDigest(verificationDigest) {
		return RealizedResult{}, fmt.Errorf("%w: credited results require independent verification evidence", ErrInvalidRecord)
	}
	if invalidOptionalNumber(input.RealizedRiskDelta) || invalidOptionalNumber(input.RealizedAttackPathDelta) {
		return RealizedResult{}, fmt.Errorf("%w: realized deltas must be finite", ErrInvalidRecord)
	}
	collateralFindings := normalizedStrings(input.CollateralFindingIDs)
	for _, findingID := range collateralFindings {
		if _, predicted := allowed[findingID]; predicted {
			return RealizedResult{}, fmt.Errorf("%w: collateral findings must be distinct from predicted findings", ErrInvalidRecord)
		}
	}
	rollbackCompletedAt := canonicalTime(input.RollbackCompletedAt)
	if input.RolledBack && (rollbackCompletedAt.IsZero() || rollbackCompletedAt.Before(input.Prediction.CreatedAt) || rollbackCompletedAt.After(input.ObservedAt)) {
		return RealizedResult{}, fmt.Errorf("%w: rollback completion must be bounded by prediction and observation", ErrInvalidRecord)
	}
	if !input.RolledBack && !rollbackCompletedAt.IsZero() {
		return RealizedResult{}, fmt.Errorf("%w: rollback completion requires a rollback", ErrInvalidRecord)
	}
	result := RealizedResult{
		RealizedIdentity:     RealizedIdentity{TenantID: input.Prediction.TenantID, PredictionDigest: input.Prediction.Digest, PlanModelVersion: input.Prediction.PlanModelVersion, ActionType: input.Prediction.ActionType, TargetType: input.Prediction.TargetType, ExecutionID: strings.TrimSpace(input.ExecutionID)},
		RealizedVerification: RealizedVerification{VerificationID: verified, ExecutorPrincipalID: executor, VerifierPrincipalID: verifier, VerificationEvidenceDigest: verificationDigest, SourceHealth: input.SourceHealth, CensoredReason: censored, VerificationLatency: canonicalTime(input.ObservedAt).Sub(input.Prediction.CreatedAt), ObservedAt: canonicalTime(input.ObservedAt)},
		RealizedBenefit:      RealizedBenefit{VerifiedClosedFindingIDs: closed, StillMatchingFindingIDs: matching, RealizedRiskDelta: cloneFloat(input.RealizedRiskDelta), RealizedAttackPathDelta: cloneFloat(input.RealizedAttackPathDelta)},
		RealizedOperations:   RealizedOperations{ActualEffort: input.ActualEffort, EffortPredictionError: input.ActualEffort - input.Prediction.PredictedEffort, ActualCostMicros: input.ActualCostMicros, CostPredictionErrorMicros: input.ActualCostMicros - input.Prediction.PredictedCostMicros, CollateralFindingIDs: collateralFindings, PredictedCollateralRisk: input.Prediction.PredictedCollateralRisk, CollateralOccurred: len(collateralFindings) > 0, RollbackPlanDigest: input.Prediction.RollbackPlanDigest, RolledBack: input.RolledBack, RollbackCompletedAt: rollbackCompletedAt},
	}
	actualCollateral := 0.0
	if result.CollateralOccurred {
		actualCollateral = 1
	}
	result.CollateralPredictionError = actualCollateral - input.Prediction.PredictedCollateralRisk
	if input.RolledBack {
		result.RollbackLatency = rollbackCompletedAt.Sub(input.Prediction.CreatedAt)
	}
	if result.RealizedRiskDelta != nil {
		errorValue := *result.RealizedRiskDelta - input.Prediction.PredictedRiskDelta
		result.RiskPredictionError = &errorValue
	}
	var err error
	result.Digest, err = digest(result)
	return result, err
}

type ObservationKind string

const (
	ObservationOpened          ObservationKind = "opened"
	ObservationVerifiedClosed  ObservationKind = "verified_closed"
	ObservationRecurred        ObservationKind = "recurred"
	ObservationSourceUnhealthy ObservationKind = "source_unhealthy"
	ObservationSourceRestored  ObservationKind = "source_restored"
)

type LifecycleObservation struct {
	TenantID       string          `json:"tenant_id"`
	FindingID      string          `json:"finding_id"`
	Fingerprint    string          `json:"fingerprint"`
	RuleID         string          `json:"rule_id"`
	Kind           ObservationKind `json:"kind"`
	VerificationID string          `json:"verification_id,omitempty"`
	ObservedAt     time.Time       `json:"observed_at"`
}

type DurabilityState string

const (
	DurabilityOpen                         DurabilityState = "open"
	DurabilityVerifiedClosed               DurabilityState = "verified_closed"
	DurabilityObserving                    DurabilityState = "durability_observing"
	Durability30Days                       DurabilityState = "durable_30d"
	Durability90Days                       DurabilityState = "durable_90d"
	DurabilityRecurred                     DurabilityState = "recurred"
	DurabilityIndeterminateSourceUnhealthy DurabilityState = "indeterminate_source_unhealthy"
)

type ResolutionEpisode struct {
	EpisodeID        string          `json:"episode_id"`
	TenantID         string          `json:"tenant_id"`
	FindingID        string          `json:"finding_id"`
	Fingerprint      string          `json:"fingerprint"`
	RuleID           string          `json:"rule_id"`
	OpenedAt         time.Time       `json:"opened_at"`
	VerificationID   string          `json:"verification_id,omitempty"`
	ResolvedAt       time.Time       `json:"resolved_at,omitempty"`
	ReopenedAt       time.Time       `json:"reopened_at,omitempty"`
	TimeToResolution time.Duration   `json:"time_to_resolution,omitempty"`
	TimeToRecurrence time.Duration   `json:"time_to_recurrence,omitempty"`
	Durability       DurabilityState `json:"durability_state"`
}

func DeriveResolutionEpisodes(observations []LifecycleObservation, asOf time.Time) ([]ResolutionEpisode, error) {
	asOf = canonicalTime(asOf)
	if asOf.IsZero() {
		return nil, fmt.Errorf("%w: as-of time is required", ErrInvalidRecord)
	}
	items := append([]LifecycleObservation(nil), observations...)
	for i := range items {
		if missing(items[i].TenantID, items[i].FindingID, items[i].Fingerprint, items[i].RuleID) || items[i].ObservedAt.IsZero() || items[i].ObservedAt.After(asOf) || !validObservationKind(items[i].Kind) {
			return nil, fmt.Errorf("%w: invalid lifecycle observation", ErrInvalidRecord)
		}
		items[i].TenantID = strings.TrimSpace(items[i].TenantID)
		items[i].FindingID = strings.TrimSpace(items[i].FindingID)
		items[i].Fingerprint = strings.TrimSpace(items[i].Fingerprint)
		items[i].RuleID = strings.TrimSpace(items[i].RuleID)
		items[i].VerificationID = strings.TrimSpace(items[i].VerificationID)
		items[i].ObservedAt = canonicalTime(items[i].ObservedAt)
		if items[i].Kind == ObservationVerifiedClosed && items[i].VerificationID == "" {
			return nil, fmt.Errorf("%w: verified closure requires verification identity", ErrInvalidRecord)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].ObservedAt.Equal(items[j].ObservedAt) {
			return items[i].ObservedAt.Before(items[j].ObservedAt)
		}
		if lifecycleKey(items[i]) != lifecycleKey(items[j]) {
			return lifecycleKey(items[i]) < lifecycleKey(items[j])
		}
		return observationRank(items[i].Kind) < observationRank(items[j].Kind)
	})
	var episodes []ResolutionEpisode
	active := map[string]int{}
	for _, item := range items {
		key := lifecycleKey(item)
		index, ok := active[key]
		switch item.Kind {
		case ObservationOpened:
			if ok && episodes[index].ResolvedAt.IsZero() {
				continue
			}
			episodes = append(episodes, newEpisode(item))
			active[key] = len(episodes) - 1
		case ObservationVerifiedClosed:
			if !ok || !episodes[index].ResolvedAt.IsZero() {
				return nil, fmt.Errorf("%w: closure without an open episode", ErrInvalidRecord)
			}
			episodes[index].ResolvedAt = item.ObservedAt
			episodes[index].VerificationID = item.VerificationID
			episodes[index].TimeToResolution = item.ObservedAt.Sub(episodes[index].OpenedAt)
			episodes[index].Durability = DurabilityVerifiedClosed
		case ObservationRecurred:
			if !ok || episodes[index].ResolvedAt.IsZero() {
				return nil, fmt.Errorf("%w: recurrence without verified closure", ErrInvalidRecord)
			}
			episodes[index].ReopenedAt = item.ObservedAt
			episodes[index].TimeToRecurrence = item.ObservedAt.Sub(episodes[index].ResolvedAt)
			episodes[index].Durability = DurabilityRecurred
			episodes = append(episodes, newEpisode(item))
			active[key] = len(episodes) - 1
		case ObservationSourceUnhealthy:
			if ok && !episodes[index].ResolvedAt.IsZero() && episodes[index].ReopenedAt.IsZero() {
				episodes[index].Durability = DurabilityIndeterminateSourceUnhealthy
			}
		case ObservationSourceRestored:
			if ok && episodes[index].Durability == DurabilityIndeterminateSourceUnhealthy {
				episodes[index].Durability = durabilityAt(episodes[index], asOf)
			}
		}
	}
	for i := range episodes {
		if episodes[i].Durability != DurabilityRecurred && episodes[i].Durability != DurabilityIndeterminateSourceUnhealthy {
			episodes[i].Durability = durabilityAt(episodes[i], asOf)
		}
	}
	return episodes, nil
}

type Benchmark struct {
	TenantID                    string        `json:"tenant_id"`
	PlanModelVersion            string        `json:"plan_model_version"`
	ActionType                  string        `json:"action_type"`
	TargetType                  string        `json:"target_type"`
	SampleSize                  int           `json:"sample_size"`
	MinimumSampleMet            bool          `json:"minimum_sample_met"`
	VerifiedResolutionRate      float64       `json:"verified_resolution_rate"`
	VerificationFailureRate     float64       `json:"verification_failure_rate"`
	MedianVerificationLatency   time.Duration `json:"median_verification_latency"`
	MeanAbsoluteRiskError       float64       `json:"mean_absolute_risk_error"`
	MeanAbsoluteEffortError     time.Duration `json:"mean_absolute_effort_error"`
	MeanAbsoluteCostErrorMicros int64         `json:"mean_absolute_cost_error_micros"`
	MeanAbsoluteCollateralError float64       `json:"mean_absolute_collateral_error"`
	CollateralRate              float64       `json:"collateral_rate"`
	RollbackRate                float64       `json:"rollback_rate"`
}

func BuildBenchmarks(results []RealizedResult, minimumSample int) []Benchmark {
	if minimumSample < 1 {
		minimumSample = 1
	}
	buckets := map[string][]RealizedResult{}
	for _, result := range results {
		if result.CensoredReason != "" {
			continue
		}
		key := strings.Join([]string{result.TenantID, result.PlanModelVersion, result.ActionType, result.TargetType}, "\x00")
		buckets[key] = append(buckets[key], result)
	}
	keys := make([]string, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]Benchmark, 0, len(keys))
	for _, key := range keys {
		values := buckets[key]
		latencies := make([]time.Duration, 0, len(values))
		closed, failed, collateral, rolledBack := 0, 0, 0, 0
		absoluteError, errorCount, absoluteCollateralError := 0.0, 0, 0.0
		absoluteEffortError := newNonNegativeMean(len(values))
		absoluteCostError := newNonNegativeMean(len(values))
		for _, value := range values {
			latencies = append(latencies, value.VerificationLatency)
			if len(value.VerifiedClosedFindingIDs) > 0 {
				closed++
			}
			if len(value.StillMatchingFindingIDs) > 0 {
				failed++
			}
			if len(value.CollateralFindingIDs) > 0 {
				collateral++
			}
			if value.RolledBack {
				rolledBack++
			}
			absoluteEffortError.add(int64(absDuration(value.EffortPredictionError)))
			absoluteCostError.add(absInt64(value.CostPredictionErrorMicros))
			absoluteCollateralError += math.Abs(value.CollateralPredictionError)
			if value.RiskPredictionError != nil {
				absoluteError += math.Abs(*value.RiskPredictionError)
				errorCount++
			}
		}
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		parts := strings.Split(key, "\x00")
		benchmark := Benchmark{TenantID: parts[0], PlanModelVersion: parts[1], ActionType: parts[2], TargetType: parts[3], SampleSize: len(values), MinimumSampleMet: len(values) >= minimumSample, VerifiedResolutionRate: float64(closed) / float64(len(values)), VerificationFailureRate: float64(failed) / float64(len(values)), MedianVerificationLatency: latencies[(len(latencies)-1)/2], MeanAbsoluteEffortError: time.Duration(absoluteEffortError.value()), MeanAbsoluteCostErrorMicros: absoluteCostError.value(), MeanAbsoluteCollateralError: absoluteCollateralError / float64(len(values)), CollateralRate: float64(collateral) / float64(len(values)), RollbackRate: float64(rolledBack) / float64(len(values))}
		if errorCount > 0 {
			benchmark.MeanAbsoluteRiskError = absoluteError / float64(errorCount)
		}
		out = append(out, benchmark)
	}
	return out
}

func newEpisode(item LifecycleObservation) ResolutionEpisode {
	opened := item.ObservedAt
	payload := strings.Join([]string{item.TenantID, item.FindingID, item.Fingerprint, opened.Format(time.RFC3339Nano)}, "\x00")
	sum := sha256.Sum256([]byte(payload))
	return ResolutionEpisode{EpisodeID: "episode-" + hex.EncodeToString(sum[:12]), TenantID: item.TenantID, FindingID: item.FindingID, Fingerprint: item.Fingerprint, RuleID: item.RuleID, OpenedAt: opened, Durability: DurabilityOpen}
}

func durabilityAt(episode ResolutionEpisode, asOf time.Time) DurabilityState {
	if episode.ResolvedAt.IsZero() {
		return DurabilityOpen
	}
	age := asOf.Sub(episode.ResolvedAt)
	if age >= 90*24*time.Hour {
		return Durability90Days
	}
	if age >= 30*24*time.Hour {
		return Durability30Days
	}
	if age > 0 {
		return DurabilityObserving
	}
	return DurabilityVerifiedClosed
}

func normalizeFindingRevisions(values []FindingRevision) ([]FindingRevision, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: at least one finding revision is required", ErrInvalidRecord)
	}
	result := append([]FindingRevision(nil), values...)
	for i := range result {
		if missing(result[i].FindingID, result[i].Fingerprint, result[i].RuleID) || result[i].Revision == 0 {
			return nil, fmt.Errorf("%w: complete finding revisions are required", ErrInvalidRecord)
		}
		result[i].FindingID = strings.TrimSpace(result[i].FindingID)
		result[i].Fingerprint = strings.TrimSpace(result[i].Fingerprint)
		result[i].RuleID = strings.TrimSpace(result[i].RuleID)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].FindingID != result[j].FindingID {
			return result[i].FindingID < result[j].FindingID
		}
		if result[i].Fingerprint != result[j].Fingerprint {
			return result[i].Fingerprint < result[j].Fingerprint
		}
		return result[i].Revision < result[j].Revision
	})
	for i := 1; i < len(result); i++ {
		if result[i-1].FindingID == result[i].FindingID {
			return nil, fmt.Errorf("%w: duplicate finding revision", ErrInvalidRecord)
		}
	}
	return result, nil
}

func digest(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func canonicalTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Round(0)
}
func invalidNumber(value float64) bool          { return math.IsNaN(value) || math.IsInf(value, 0) }
func invalidProbability(value float64) bool     { return invalidNumber(value) || value < 0 || value > 1 }
func invalidOptionalNumber(value *float64) bool { return value != nil && invalidNumber(*value) }
func cloneFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
func missing(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}
func normalizedStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
func findingIDSet(values []FindingRevision) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value.FindingID] = struct{}{}
	}
	return result
}
func subset(values []string, allowed map[string]struct{}) bool {
	for _, value := range values {
		if _, ok := allowed[value]; !ok {
			return false
		}
	}
	return true
}
func overlaps(left, right []string) bool {
	set := map[string]struct{}{}
	for _, v := range left {
		set[v] = struct{}{}
	}
	for _, v := range right {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}
func validDigest(value string) bool {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}
func absInt64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

type nonNegativeMean struct {
	divisor   int64
	quotient  int64
	remainder int64
}

func newNonNegativeMean(sampleSize int) nonNegativeMean {
	return nonNegativeMean{divisor: int64(sampleSize)}
}

func (mean *nonNegativeMean) add(value int64) {
	mean.quotient += value / mean.divisor
	remainder := value % mean.divisor
	space := mean.divisor - mean.remainder
	if remainder >= space {
		mean.quotient++
		mean.remainder = remainder - space
		return
	}
	mean.remainder += remainder
}

func (mean nonNegativeMean) value() int64 {
	return mean.quotient
}
func lifecycleKey(value LifecycleObservation) string {
	return strings.Join([]string{value.TenantID, value.FindingID, value.Fingerprint}, "\x00")
}
func validObservationKind(value ObservationKind) bool {
	switch value {
	case ObservationOpened, ObservationVerifiedClosed, ObservationRecurred, ObservationSourceUnhealthy, ObservationSourceRestored:
		return true
	}
	return false
}
func observationRank(value ObservationKind) int {
	switch value {
	case ObservationOpened:
		return 0
	case ObservationVerifiedClosed:
		return 1
	case ObservationSourceUnhealthy:
		return 2
	case ObservationSourceRestored:
		return 3
	case ObservationRecurred:
		return 4
	}
	return 99
}
