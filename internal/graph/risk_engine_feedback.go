package graph

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	defaultOutcomeFeedbackWindow = 90 * 24 * time.Hour
	defaultOutcomeLeadWindow     = 45 * 24 * time.Hour
)

// OutcomeEvent captures a realized business outcome tied to an entity.
type OutcomeEvent struct {
	ID         string         `json:"id"`
	EntityID   string         `json:"entity_id"`
	Outcome    string         `json:"outcome"`
	OccurredAt time.Time      `json:"occurred_at"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// RuleObservation records one risk signal emitted by analysis.
type RuleObservation struct {
	RuleID       string    `json:"rule_id"`
	RuleType     string    `json:"rule_type"`
	SignalFamily string    `json:"signal_family"`
	Severity     Severity  `json:"severity"`
	Score        float64   `json:"score"`
	EntityIDs    []string  `json:"entity_ids,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
}

// FactorObservation records one entity factor score emitted by analysis.
type FactorObservation struct {
	EntityID   string    `json:"entity_id"`
	Signal     string    `json:"signal"`
	Score      float64   `json:"score"`
	ObservedAt time.Time `json:"observed_at"`
}

// RuleEffectiveness describes historical predictive quality of a rule.
type RuleEffectiveness struct {
	RuleID           string    `json:"rule_id"`
	RuleType         string    `json:"rule_type"`
	SignalFamily     string    `json:"signal_family"`
	Severity         Severity  `json:"severity"`
	Detections       int       `json:"detections"`
	TruePositives    int       `json:"true_positives"`
	FalsePositives   int       `json:"false_positives"`
	RelevantOutcomes int       `json:"relevant_outcomes"`
	Precision        float64   `json:"precision"`
	Recall           float64   `json:"recall"`
	AvgLeadTimeDays  float64   `json:"avg_lead_time_days"`
	LastSeenAt       time.Time `json:"last_seen_at,omitempty"`
}

// SeverityAdjustmentSuggestion proposes severity changes based on outcomes.
type SeverityAdjustmentSuggestion struct {
	RuleID            string   `json:"rule_id"`
	CurrentSeverity   Severity `json:"current_severity"`
	SuggestedSeverity Severity `json:"suggested_severity"`
	Confidence        float64  `json:"confidence"`
	Reason            string   `json:"reason"`
}

// RuleRetirementSuggestion flags noisy low-value rules.
type RuleRetirementSuggestion struct {
	RuleID            string  `json:"rule_id"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
	Detections        int     `json:"detections"`
	Reason            string  `json:"reason"`
}

// SignalWeightRecommendation proposes risk-profile weight changes by signal family.
type SignalWeightRecommendation struct {
	Signal          string  `json:"signal"`
	CurrentWeight   float64 `json:"current_weight"`
	SuggestedWeight float64 `json:"suggested_weight"`
	Delta           float64 `json:"delta"`
	Direction       string  `json:"direction"`
	OutcomeHitRate  float64 `json:"outcome_hit_rate"`
	Observations    int     `json:"observations"`
	Confidence      float64 `json:"confidence"`
	Rationale       string  `json:"rationale"`
}

// CalibrationBucket summarizes observed outcomes for a predicted-probability range.
type CalibrationBucket struct {
	LowerBound   float64 `json:"lower_bound"`
	UpperBound   float64 `json:"upper_bound"`
	Samples      int     `json:"samples"`
	OutcomeRate  float64 `json:"outcome_rate"`
	AvgPredicted float64 `json:"avg_predicted"`
	Gap          float64 `json:"gap"`
}

// OutcomeBacktest summarizes aggregate quality for observed risk predictions.
type OutcomeBacktest struct {
	Samples       int     `json:"samples"`
	BrierScore    float64 `json:"brier_score"`
	PrecisionAt50 float64 `json:"precision_at_50"`
	RecallAt50    float64 `json:"recall_at_50"`
}

// SignalDrift captures directional quality drift between baseline and recent windows.
type SignalDrift struct {
	Signal          string  `json:"signal"`
	RecentHitRate   float64 `json:"recent_hit_rate"`
	BaselineHitRate float64 `json:"baseline_hit_rate"`
	Delta           float64 `json:"delta"`
	Status          string  `json:"status"`
	RecentSamples   int     `json:"recent_samples"`
	BaselineSamples int     `json:"baseline_samples"`
}

// OutcomeFeedbackReport summarizes rule effectiveness and tuning recommendations.
type OutcomeFeedbackReport struct {
	GeneratedAt             time.Time                      `json:"generated_at"`
	ObservationWindowDays   int                            `json:"observation_window_days"`
	OutcomeCount            int                            `json:"outcome_count"`
	RuleSignalCount         int                            `json:"rule_signal_count"`
	Profile                 string                         `json:"profile"`
	Backtest                OutcomeBacktest                `json:"backtest"`
	Calibration             []CalibrationBucket            `json:"calibration,omitempty"`
	SignalDrift             []SignalDrift                  `json:"signal_drift,omitempty"`
	RulePromotions          []RulePromotionEvent           `json:"rule_promotions,omitempty"`
	RuleEffectiveness       []RuleEffectiveness            `json:"rule_effectiveness,omitempty"`
	SeverityAdjustments     []SeverityAdjustmentSuggestion `json:"severity_adjustments,omitempty"`
	RetirementSuggestions   []RuleRetirementSuggestion     `json:"retirement_suggestions,omitempty"`
	SignalWeightAdjustments []SignalWeightRecommendation   `json:"signal_weight_adjustments,omitempty"`
}

func normalizeOutcomeType(raw string) string {
	outcome := strings.TrimSpace(strings.ToLower(raw))
	outcome = strings.ReplaceAll(outcome, "-", "_")
	return outcome
}

// RecordOutcome stores a realized outcome event for later feedback analysis.
func (r *RiskEngine) RecordOutcome(event OutcomeEvent) (OutcomeEvent, error) {
	if r == nil {
		return OutcomeEvent{}, fmt.Errorf("risk engine is nil")
	}

	entityID := strings.TrimSpace(event.EntityID)
	if entityID == "" {
		return OutcomeEvent{}, fmt.Errorf("entity_id is required")
	}
	if r.graph != nil {
		if _, ok := r.graph.GetNode(entityID); !ok {
			return OutcomeEvent{}, fmt.Errorf("entity %q not found", entityID)
		}
	}

	outcome := normalizeOutcomeType(event.Outcome)
	if outcome == "" {
		return OutcomeEvent{}, fmt.Errorf("outcome is required")
	}

	occurredAt := event.OccurredAt.UTC()
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	normalized := OutcomeEvent{
		ID:         strings.TrimSpace(event.ID),
		EntityID:   entityID,
		Outcome:    outcome,
		OccurredAt: occurredAt,
		Metadata:   event.Metadata,
	}
	if normalized.ID == "" {
		normalized.ID = fmt.Sprintf("%s:%s:%d", normalized.EntityID, normalized.Outcome, normalized.OccurredAt.UnixNano())
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.outcomeEvents = append(r.outcomeEvents, normalized)
	sort.Slice(r.outcomeEvents, func(i, j int) bool {
		if r.outcomeEvents[i].OccurredAt.Equal(r.outcomeEvents[j].OccurredAt) {
			return r.outcomeEvents[i].ID < r.outcomeEvents[j].ID
		}
		return r.outcomeEvents[i].OccurredAt.Before(r.outcomeEvents[j].OccurredAt)
	})
	r.trimSignalsLocked()

	return normalized, nil
}

// OutcomeEvents returns outcome events, optionally filtered by entity and outcome type.
func (r *RiskEngine) OutcomeEvents(entityID, outcome string) []OutcomeEvent {
	if r == nil {
		return nil
	}

	entityID = strings.TrimSpace(entityID)
	outcome = normalizeOutcomeType(outcome)

	r.mu.RLock()
	defer r.mu.RUnlock()

	filtered := make([]OutcomeEvent, 0, len(r.outcomeEvents))
	for _, event := range r.outcomeEvents {
		if entityID != "" && event.EntityID != entityID {
			continue
		}
		if outcome != "" && event.Outcome != outcome {
			continue
		}
		filtered = append(filtered, event)
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].OccurredAt.Equal(filtered[j].OccurredAt) {
			return filtered[i].ID > filtered[j].ID
		}
		return filtered[i].OccurredAt.After(filtered[j].OccurredAt)
	})
	return filtered
}

// OutcomeFeedback evaluates rule/factor performance against realized outcomes.
func (r *RiskEngine) OutcomeFeedback(window time.Duration, profileName string) OutcomeFeedbackReport {
	if window <= 0 {
		window = defaultOutcomeFeedbackWindow
	}
	now := time.Now().UTC()
	cutoff := now.Add(-window)

	r.mu.RLock()
	outcomes := make([]OutcomeEvent, 0, len(r.outcomeEvents))
	for _, event := range r.outcomeEvents {
		if event.OccurredAt.Before(cutoff) {
			continue
		}
		outcomes = append(outcomes, event)
	}
	ruleSignals := make([]RuleObservation, 0, len(r.ruleSignals))
	for _, signal := range r.ruleSignals {
		if signal.ObservedAt.Before(cutoff) {
			continue
		}
		ruleSignals = append(ruleSignals, signal)
	}
	factorSignals := make([]FactorObservation, 0, len(r.factorSignals))
	for _, signal := range r.factorSignals {
		if signal.ObservedAt.Before(cutoff) {
			continue
		}
		factorSignals = append(factorSignals, signal)
	}
	rulePromotions := append([]RulePromotionEvent(nil), r.rulePromotions...)
	profile := r.riskProfile
	r.mu.RUnlock()

	trimmedProfileName := strings.TrimSpace(strings.ToLower(profileName))
	if trimmedProfileName != "" {
		resolved := DefaultRiskProfile(trimmedProfileName)
		if resolved.Name != "default" || trimmedProfileName == "default" {
			profile = resolved
		}
	}

	ruleEffectiveness := evaluateRuleEffectiveness(ruleSignals, outcomes, defaultOutcomeLeadWindow)
	severityAdjustments := buildSeverityAdjustments(ruleEffectiveness)
	retirementSuggestions := buildRetirementSuggestions(ruleEffectiveness)
	signalAdjustments := buildSignalWeightRecommendations(factorSignals, outcomes, profile, defaultOutcomeLeadWindow)
	backtest, calibration := buildOutcomeCalibration(ruleSignals, outcomes, defaultOutcomeLeadWindow)
	drift := detectSignalDrift(factorSignals, outcomes, defaultOutcomeLeadWindow, cutoff, now)

	return OutcomeFeedbackReport{
		GeneratedAt:             now,
		ObservationWindowDays:   int(window.Hours() / 24),
		OutcomeCount:            len(outcomes),
		RuleSignalCount:         len(ruleSignals),
		Profile:                 profile.Name,
		Backtest:                backtest,
		Calibration:             calibration,
		SignalDrift:             drift,
		RulePromotions:          rulePromotions,
		RuleEffectiveness:       ruleEffectiveness,
		SeverityAdjustments:     severityAdjustments,
		RetirementSuggestions:   retirementSuggestions,
		SignalWeightAdjustments: signalAdjustments,
	}
}

func (r *RiskEngine) recordSignalsLocked(report *SecurityReport, observedAt time.Time) {
	if report == nil {
		return
	}

	for _, risk := range report.TopRisks {
		if risk == nil || strings.TrimSpace(risk.ID) == "" {
			continue
		}
		entityIDs := uniqueTrimmedStrings(risk.AffectedAssets)
		if len(entityIDs) == 0 && strings.HasPrefix(risk.ID, "entity-risk:") {
			parts := strings.Split(risk.ID, ":")
			if len(parts) >= 3 {
				entityIDs = append(entityIDs, strings.TrimSpace(parts[1]))
			}
		}

		r.ruleSignals = append(r.ruleSignals, RuleObservation{
			RuleID:       risk.ID,
			RuleType:     strings.TrimSpace(risk.Type),
			SignalFamily: inferSignalFamily(risk),
			Severity:     risk.Severity,
			Score:        clampScore(risk.Score),
			EntityIDs:    entityIDs,
			ObservedAt:   observedAt,
		})
	}

	for entityID, entityRisk := range report.EntityRisks {
		if strings.TrimSpace(entityID) == "" {
			continue
		}
		for _, factor := range entityRisk.Factors {
			if factor.Score <= 0 {
				continue
			}
			signal := normalizeSignalFamily(factor.Source)
			if signal == "" {
				continue
			}
			r.factorSignals = append(r.factorSignals, FactorObservation{
				EntityID:   entityID,
				Signal:     signal,
				Score:      clampScore(factor.Score),
				ObservedAt: observedAt,
			})
		}
	}

	r.trimSignalsLocked()
}

func (r *RiskEngine) trimSignalsLocked() {
	if r.signalLimit <= 0 {
		return
	}

	if len(r.ruleSignals) > r.signalLimit {
		r.ruleSignals = append([]RuleObservation(nil), r.ruleSignals[len(r.ruleSignals)-r.signalLimit:]...)
	}
	if len(r.factorSignals) > r.signalLimit {
		r.factorSignals = append([]FactorObservation(nil), r.factorSignals[len(r.factorSignals)-r.signalLimit:]...)
	}
	if len(r.outcomeEvents) > r.signalLimit {
		r.outcomeEvents = append([]OutcomeEvent(nil), r.outcomeEvents[len(r.outcomeEvents)-r.signalLimit:]...)
	}
	if len(r.rulePromotions) > r.signalLimit {
		r.rulePromotions = append([]RulePromotionEvent(nil), r.rulePromotions[len(r.rulePromotions)-r.signalLimit:]...)
	}
}

func evaluateRuleEffectiveness(observations []RuleObservation, outcomes []OutcomeEvent, leadWindow time.Duration) []RuleEffectiveness {
	if leadWindow <= 0 {
		leadWindow = defaultOutcomeLeadWindow
	}
	if len(observations) == 0 {
		return nil
	}

	observedByRule := make(map[string][]RuleObservation)
	for _, observation := range observations {
		if strings.TrimSpace(observation.RuleID) == "" {
			continue
		}
		observedByRule[observation.RuleID] = append(observedByRule[observation.RuleID], observation)
	}
	if len(observedByRule) == 0 {
		return nil
	}

	outcomesByEntity := indexOutcomesByEntity(outcomes)
	result := make([]RuleEffectiveness, 0, len(observedByRule))
	for ruleID, ruleObservations := range observedByRule {
		sort.Slice(ruleObservations, func(i, j int) bool {
			if ruleObservations[i].ObservedAt.Equal(ruleObservations[j].ObservedAt) {
				return ruleObservations[i].RuleID < ruleObservations[j].RuleID
			}
			return ruleObservations[i].ObservedAt.Before(ruleObservations[j].ObservedAt)
		})

		effectiveness := RuleEffectiveness{
			RuleID:       ruleID,
			RuleType:     strings.TrimSpace(ruleObservations[0].RuleType),
			SignalFamily: normalizeSignalFamily(ruleObservations[0].SignalFamily),
			Severity:     ruleObservations[0].Severity,
		}

		relevantEntities := make(map[string]struct{})
		leadDaysTotal := 0.0
		leadSamples := 0

		for _, observation := range ruleObservations {
			effectiveness.Detections++
			if effectiveness.LastSeenAt.IsZero() || observation.ObservedAt.After(effectiveness.LastSeenAt) {
				effectiveness.LastSeenAt = observation.ObservedAt
			}

			for _, entityID := range observation.EntityIDs {
				if trimmed := strings.TrimSpace(entityID); trimmed != "" {
					relevantEntities[trimmed] = struct{}{}
				}
			}

			matchedOutcome, matched := matchOutcomeForObservation(observation, outcomesByEntity, leadWindow)
			if matched {
				effectiveness.TruePositives++
				leadDaysTotal += matchedOutcome.OccurredAt.Sub(observation.ObservedAt).Hours() / 24
				leadSamples++
			} else {
				effectiveness.FalsePositives++
			}
		}

		if effectiveness.Detections > 0 {
			effectiveness.Precision = float64(effectiveness.TruePositives) / float64(effectiveness.Detections)
		}
		if leadSamples > 0 {
			effectiveness.AvgLeadTimeDays = leadDaysTotal / float64(leadSamples)
		}

		relevantOutcomes := 0
		predictedOutcomes := 0
		for entityID := range relevantEntities {
			entityOutcomes := outcomesByEntity[entityID]
			for _, outcome := range entityOutcomes {
				relevantOutcomes++
				if rulePredictedOutcome(ruleObservations, outcome, leadWindow) {
					predictedOutcomes++
				}
			}
		}
		effectiveness.RelevantOutcomes = relevantOutcomes
		if relevantOutcomes > 0 {
			effectiveness.Recall = float64(predictedOutcomes) / float64(relevantOutcomes)
		}
		if effectiveness.Severity == "" {
			effectiveness.Severity = SeverityMedium
		}

		result = append(result, effectiveness)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Detections == result[j].Detections {
			if result[i].Precision == result[j].Precision {
				return result[i].RuleID < result[j].RuleID
			}
			return result[i].Precision > result[j].Precision
		}
		return result[i].Detections > result[j].Detections
	})

	return result
}

func buildSeverityAdjustments(effectiveness []RuleEffectiveness) []SeverityAdjustmentSuggestion {
	if len(effectiveness) == 0 {
		return nil
	}

	suggestions := make([]SeverityAdjustmentSuggestion, 0)
	for _, metric := range effectiveness {
		if metric.Detections < 3 {
			continue
		}

		current := metric.Severity
		if current == "" {
			current = SeverityMedium
		}
		suggested := current
		confidence := 0.0
		reason := ""

		switch {
		case metric.Precision >= 0.75 && metric.Recall >= 0.35:
			suggested = increaseSeverity(current)
			confidence = clampUnitInterval(0.35 + metric.Precision*0.35 + metric.Recall*0.2 + math.Min(0.1, float64(metric.Detections)/40))
			reason = fmt.Sprintf("High predictive quality (precision %.2f, recall %.2f) suggests stronger severity", metric.Precision, metric.Recall)
		case metric.Precision <= 0.25 && metric.Detections >= 4:
			suggested = decreaseSeverity(current)
			confidence = clampUnitInterval(0.35 + (1-metric.Precision)*0.35 + math.Min(0.25, float64(metric.Detections)/25))
			reason = fmt.Sprintf("Frequent false positives (precision %.2f across %d detections)", metric.Precision, metric.Detections)
		}
		if suggested == current {
			continue
		}

		suggestions = append(suggestions, SeverityAdjustmentSuggestion{
			RuleID:            metric.RuleID,
			CurrentSeverity:   current,
			SuggestedSeverity: suggested,
			Confidence:        confidence,
			Reason:            reason,
		})
	}

	sort.Slice(suggestions, func(i, j int) bool {
		if suggestions[i].Confidence == suggestions[j].Confidence {
			return suggestions[i].RuleID < suggestions[j].RuleID
		}
		return suggestions[i].Confidence > suggestions[j].Confidence
	})
	return suggestions
}

func buildRetirementSuggestions(effectiveness []RuleEffectiveness) []RuleRetirementSuggestion {
	if len(effectiveness) == 0 {
		return nil
	}

	suggestions := make([]RuleRetirementSuggestion, 0)
	for _, metric := range effectiveness {
		if metric.Detections < 6 {
			continue
		}
		if metric.Precision >= 0.15 {
			continue
		}
		if metric.Recall >= 0.20 && metric.RelevantOutcomes > 0 {
			continue
		}
		falsePositiveRate := 1.0
		if metric.Detections > 0 {
			falsePositiveRate = float64(metric.FalsePositives) / float64(metric.Detections)
		}
		suggestions = append(suggestions, RuleRetirementSuggestion{
			RuleID:            metric.RuleID,
			FalsePositiveRate: falsePositiveRate,
			Detections:        metric.Detections,
			Reason:            "High false-positive rate with weak outcome correlation",
		})
	}

	sort.Slice(suggestions, func(i, j int) bool {
		if suggestions[i].FalsePositiveRate == suggestions[j].FalsePositiveRate {
			return suggestions[i].RuleID < suggestions[j].RuleID
		}
		return suggestions[i].FalsePositiveRate > suggestions[j].FalsePositiveRate
	})
	return suggestions
}

func buildSignalWeightRecommendations(factors []FactorObservation, outcomes []OutcomeEvent, profile RiskProfile, leadWindow time.Duration) []SignalWeightRecommendation {
	if leadWindow <= 0 {
		leadWindow = defaultOutcomeLeadWindow
	}
	if len(factors) == 0 {
		return nil
	}

	type aggregate struct {
		observations int
		outcomeHits  int
	}
	aggregates := make(map[string]*aggregate)
	outcomesByEntity := indexOutcomesByEntity(outcomes)
	for _, factor := range factors {
		signal := normalizeSignalFamily(factor.Signal)
		if signal == "" {
			continue
		}
		entry := aggregates[signal]
		if entry == nil {
			entry = &aggregate{}
			aggregates[signal] = entry
		}
		entry.observations++
		if hasOutcomeInWindow(factor.EntityID, factor.ObservedAt, outcomesByEntity, leadWindow) {
			entry.outcomeHits++
		}
	}

	recommendations := make([]SignalWeightRecommendation, 0)
	for signal, aggregate := range aggregates {
		if aggregate.observations < 3 {
			continue
		}
		hitRate := float64(aggregate.outcomeHits) / float64(aggregate.observations)
		currentWeight := profile.Weight(signal)
		if currentWeight <= 0 {
			currentWeight = 1
		}

		suggestedWeight := currentWeight
		direction := "stable"
		rationale := ""
		switch {
		case hitRate >= 0.60:
			suggestedWeight = math.Min(3.0, currentWeight+0.20+(hitRate-0.60)*0.80)
			direction = "increase"
			rationale = fmt.Sprintf("Signal predicts outcomes frequently (hit rate %.2f)", hitRate)
		case hitRate <= 0.20:
			suggestedWeight = math.Max(0.30, currentWeight-(0.15+(0.20-hitRate)*0.75))
			direction = "decrease"
			rationale = fmt.Sprintf("Signal rarely maps to outcomes (hit rate %.2f)", hitRate)
		}
		delta := suggestedWeight - currentWeight
		if math.Abs(delta) < 0.05 {
			continue
		}

		confidence := clampUnitInterval(0.30 + math.Abs(hitRate-0.50)*0.9 + math.Min(0.25, float64(aggregate.observations)/24))
		recommendations = append(recommendations, SignalWeightRecommendation{
			Signal:          signal,
			CurrentWeight:   currentWeight,
			SuggestedWeight: suggestedWeight,
			Delta:           delta,
			Direction:       direction,
			OutcomeHitRate:  hitRate,
			Observations:    aggregate.observations,
			Confidence:      confidence,
			Rationale:       rationale,
		})
	}

	sort.Slice(recommendations, func(i, j int) bool {
		if recommendations[i].Confidence == recommendations[j].Confidence {
			return recommendations[i].Signal < recommendations[j].Signal
		}
		return recommendations[i].Confidence > recommendations[j].Confidence
	})
	return recommendations
}

func matchOutcomeForObservation(observation RuleObservation, outcomesByEntity map[string][]OutcomeEvent, leadWindow time.Duration) (OutcomeEvent, bool) {
	match := OutcomeEvent{}
	found := false
	for _, entityID := range observation.EntityIDs {
		entityID = strings.TrimSpace(entityID)
		if entityID == "" {
			continue
		}
		for _, outcome := range outcomesByEntity[entityID] {
			if outcome.OccurredAt.Before(observation.ObservedAt) {
				continue
			}
			if outcome.OccurredAt.Sub(observation.ObservedAt) > leadWindow {
				break
			}
			if !found || outcome.OccurredAt.Before(match.OccurredAt) {
				match = outcome
				found = true
			}
		}
	}
	return match, found
}

func rulePredictedOutcome(observations []RuleObservation, outcome OutcomeEvent, leadWindow time.Duration) bool {
	for _, observation := range observations {
		if observation.ObservedAt.After(outcome.OccurredAt) {
			continue
		}
		if outcome.OccurredAt.Sub(observation.ObservedAt) > leadWindow {
			continue
		}
		for _, entityID := range observation.EntityIDs {
			if strings.TrimSpace(entityID) == outcome.EntityID {
				return true
			}
		}
	}
	return false
}

func hasOutcomeInWindow(entityID string, start time.Time, outcomesByEntity map[string][]OutcomeEvent, window time.Duration) bool {
	entityID = strings.TrimSpace(entityID)
	if entityID == "" {
		return false
	}
	for _, outcome := range outcomesByEntity[entityID] {
		if outcome.OccurredAt.Before(start) {
			continue
		}
		if outcome.OccurredAt.Sub(start) > window {
			return false
		}
		return true
	}
	return false
}

func indexOutcomesByEntity(outcomes []OutcomeEvent) map[string][]OutcomeEvent {
	index := make(map[string][]OutcomeEvent)
	for _, outcome := range outcomes {
		entityID := strings.TrimSpace(outcome.EntityID)
		if entityID == "" {
			continue
		}
		index[entityID] = append(index[entityID], outcome)
	}
	for entityID := range index {
		sort.Slice(index[entityID], func(i, j int) bool {
			if index[entityID][i].OccurredAt.Equal(index[entityID][j].OccurredAt) {
				return index[entityID][i].ID < index[entityID][j].ID
			}
			return index[entityID][i].OccurredAt.Before(index[entityID][j].OccurredAt)
		})
	}
	return index
}

func buildOutcomeCalibration(observations []RuleObservation, outcomes []OutcomeEvent, leadWindow time.Duration) (OutcomeBacktest, []CalibrationBucket) {
	if leadWindow <= 0 {
		leadWindow = defaultOutcomeLeadWindow
	}
	if len(observations) == 0 {
		return OutcomeBacktest{}, nil
	}
	outcomesByEntity := indexOutcomesByEntity(outcomes)

	type predictionSample struct {
		predicted float64
		actual    float64
	}
	samples := make([]predictionSample, 0, len(observations))
	for _, observation := range observations {
		if len(observation.EntityIDs) == 0 {
			continue
		}
		predicted := clampUnitInterval(observation.Score / 100.0)
		actual := 0.0
		if _, ok := matchOutcomeForObservation(observation, outcomesByEntity, leadWindow); ok {
			actual = 1.0
		}
		samples = append(samples, predictionSample{
			predicted: predicted,
			actual:    actual,
		})
	}
	if len(samples) == 0 {
		return OutcomeBacktest{}, nil
	}

	type bucketAccumulator struct {
		samples      int
		predictedSum float64
		actualSum    float64
	}

	const bucketCount = 5
	accumulators := make([]bucketAccumulator, bucketCount)
	brierSum := 0.0
	predictedPositives := 0
	actualPositives := 0
	truePositives := 0
	for _, sample := range samples {
		idx := int(sample.predicted * bucketCount)
		if idx >= bucketCount {
			idx = bucketCount - 1
		}
		accumulators[idx].samples++
		accumulators[idx].predictedSum += sample.predicted
		accumulators[idx].actualSum += sample.actual

		err := sample.predicted - sample.actual
		brierSum += err * err
		if sample.predicted >= 0.5 {
			predictedPositives++
			if sample.actual >= 0.5 {
				truePositives++
			}
		}
		if sample.actual >= 0.5 {
			actualPositives++
		}
	}

	buckets := make([]CalibrationBucket, 0, bucketCount)
	for idx := 0; idx < bucketCount; idx++ {
		lower := float64(idx) / bucketCount
		upper := float64(idx+1) / bucketCount
		aggregate := accumulators[idx]
		if aggregate.samples == 0 {
			continue
		}
		avgPredicted := aggregate.predictedSum / float64(aggregate.samples)
		outcomeRate := aggregate.actualSum / float64(aggregate.samples)
		buckets = append(buckets, CalibrationBucket{
			LowerBound:   lower,
			UpperBound:   upper,
			Samples:      aggregate.samples,
			OutcomeRate:  outcomeRate,
			AvgPredicted: avgPredicted,
			Gap:          outcomeRate - avgPredicted,
		})
	}

	backtest := OutcomeBacktest{
		Samples:    len(samples),
		BrierScore: brierSum / float64(len(samples)),
	}
	if predictedPositives > 0 {
		backtest.PrecisionAt50 = float64(truePositives) / float64(predictedPositives)
	}
	if actualPositives > 0 {
		backtest.RecallAt50 = float64(truePositives) / float64(actualPositives)
	}
	return backtest, buckets
}

func detectSignalDrift(
	factors []FactorObservation,
	outcomes []OutcomeEvent,
	leadWindow time.Duration,
	windowStart time.Time,
	windowEnd time.Time,
) []SignalDrift {
	if leadWindow <= 0 {
		leadWindow = defaultOutcomeLeadWindow
	}
	if len(factors) == 0 || !windowEnd.After(windowStart) {
		return nil
	}
	outcomesByEntity := indexOutcomesByEntity(outcomes)
	midpoint := windowStart.Add(windowEnd.Sub(windowStart) / 2)

	type aggregate struct {
		recentSamples   int
		recentHits      int
		baselineSamples int
		baselineHits    int
	}
	bySignal := make(map[string]*aggregate)
	for _, factor := range factors {
		signal := normalizeSignalFamily(factor.Signal)
		if signal == "" {
			continue
		}
		entry := bySignal[signal]
		if entry == nil {
			entry = &aggregate{}
			bySignal[signal] = entry
		}

		hit := hasOutcomeInWindow(factor.EntityID, factor.ObservedAt, outcomesByEntity, leadWindow)
		if factor.ObservedAt.Before(midpoint) {
			entry.baselineSamples++
			if hit {
				entry.baselineHits++
			}
			continue
		}
		entry.recentSamples++
		if hit {
			entry.recentHits++
		}
	}

	drift := make([]SignalDrift, 0, len(bySignal))
	for signal, aggregate := range bySignal {
		if aggregate.baselineSamples < 3 || aggregate.recentSamples < 3 {
			continue
		}
		baselineRate := float64(aggregate.baselineHits) / float64(aggregate.baselineSamples)
		recentRate := float64(aggregate.recentHits) / float64(aggregate.recentSamples)
		delta := recentRate - baselineRate
		status := "stable"
		switch {
		case delta <= -0.20:
			status = "degrading"
		case delta >= 0.20:
			status = "improving"
		}
		drift = append(drift, SignalDrift{
			Signal:          signal,
			RecentHitRate:   recentRate,
			BaselineHitRate: baselineRate,
			Delta:           delta,
			Status:          status,
			RecentSamples:   aggregate.recentSamples,
			BaselineSamples: aggregate.baselineSamples,
		})
	}

	sort.Slice(drift, func(i, j int) bool {
		iAbs := math.Abs(drift[i].Delta)
		jAbs := math.Abs(drift[j].Delta)
		if iAbs == jAbs {
			return drift[i].Signal < drift[j].Signal
		}
		return iAbs > jAbs
	})
	return drift
}

func inferSignalFamily(risk *RankedRisk) string {
	if risk == nil {
		return "security"
	}
	id := strings.TrimSpace(strings.ToLower(risk.ID))
	if strings.HasPrefix(id, "entity-risk:") {
		parts := strings.Split(id, ":")
		if len(parts) >= 3 {
			if signal := normalizeSignalFamily(parts[len(parts)-1]); signal != "" {
				return signal
			}
		}
	}

	switch strings.TrimSpace(strings.ToLower(risk.Type)) {
	case "revenue_risk":
		return "stripe"
	case "sla_breach":
		return "support"
	case "pipeline_risk":
		return "crm"
	case "churn_signal":
		return "topology"
	case "operational_risk":
		return "security"
	default:
		return "security"
	}
}

func normalizeSignalFamily(raw string) string {
	signal := strings.TrimSpace(strings.ToLower(raw))
	switch signal {
	case "billing", "revenue", "payments":
		return "stripe"
	case "tickets", "support":
		return "support"
	case "sales", "pipeline":
		return "crm"
	case "customer", "customer_health", "churn":
		return "topology"
	case "code", "deploy":
		return "github"
	case "operations":
		return "security"
	}
	return signal
}

func uniqueTrimmedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		unique = append(unique, trimmed)
	}
	sort.Strings(unique)
	return unique
}

func increaseSeverity(current Severity) Severity {
	switch current {
	case SeverityLow:
		return SeverityMedium
	case SeverityMedium:
		return SeverityHigh
	case SeverityHigh:
		return SeverityCritical
	default:
		return current
	}
}

func decreaseSeverity(current Severity) Severity {
	switch current {
	case SeverityCritical:
		return SeverityHigh
	case SeverityHigh:
		return SeverityMedium
	case SeverityMedium:
		return SeverityLow
	default:
		return current
	}
}
