package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

type crossTenantPatternAggregate struct {
	Fingerprint string
	Outcome     string
	Signals     []string
	Occurrences int
	LastUpdated time.Time
	tenantSet   map[string]struct{}
}

// AnonymizedPatternSample is the privacy-safe telemetry contract for cross-tenant learning.
type AnonymizedPatternSample struct {
	TenantHash  string    `json:"tenant_hash"`
	Fingerprint string    `json:"fingerprint"`
	Outcome     string    `json:"outcome"`
	Signals     []string  `json:"signals,omitempty"`
	ObservedAt  time.Time `json:"observed_at"`
	Support     int       `json:"support"`
}

// PatternIngestSummary tracks cross-tenant pattern ingest results.
type PatternIngestSummary struct {
	Received int `json:"received"`
	Added    int `json:"added"`
	Updated  int `json:"updated"`
	Skipped  int `json:"skipped"`
}

// CrossTenantPattern is an aggregated anonymized signature/outcome pair.
type CrossTenantPattern struct {
	Fingerprint        string    `json:"fingerprint"`
	Outcome            string    `json:"outcome"`
	Signals            []string  `json:"signals,omitempty"`
	TenantCount        int       `json:"tenant_count"`
	Occurrences        int       `json:"occurrences"`
	OutcomeProbability float64   `json:"outcome_probability"`
	SuggestedAction    string    `json:"suggested_action"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// CrossTenantPatternMatch is a recommendation produced for a current-tenant entity.
type CrossTenantPatternMatch struct {
	EntityID           string   `json:"entity_id"`
	EntityKind         NodeKind `json:"entity_kind"`
	EntityScore        float64  `json:"entity_score"`
	Fingerprint        string   `json:"fingerprint"`
	Outcome            string   `json:"outcome"`
	OutcomeProbability float64  `json:"outcome_probability"`
	MatchedTenants     int      `json:"matched_tenants"`
	Occurrences        int      `json:"occurrences"`
	SuggestedAction    string   `json:"suggested_action"`
}

// BuildAnonymizedPatternSamples creates privacy-safe telemetry samples for cross-tenant sharing.
func (r *RiskEngine) BuildAnonymizedPatternSamples(tenantID string, window time.Duration) ([]AnonymizedPatternSample, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	if window <= 0 {
		window = 90 * 24 * time.Hour
	}

	report := r.GetCachedReport(30 * time.Minute)
	if report == nil {
		report = r.Analyze()
	}
	if report == nil {
		return nil, nil
	}

	cutoff := time.Now().UTC().Add(-window)
	outcomes := r.OutcomeEvents("", "")
	outcomesByEntity := make(map[string][]OutcomeEvent)
	for _, outcome := range outcomes {
		if outcome.OccurredAt.Before(cutoff) {
			continue
		}
		outcomesByEntity[outcome.EntityID] = append(outcomesByEntity[outcome.EntityID], outcome)
	}

	tenantHash := hashTenantID(tenantID)
	combined := make(map[string]AnonymizedPatternSample)
	for entityID, risk := range report.EntityRisks {
		entityOutcomes := outcomesByEntity[entityID]
		if len(entityOutcomes) == 0 {
			continue
		}
		signals := strongSignalFamilies(risk.Factors)
		if len(signals) == 0 {
			continue
		}
		fingerprint := anonymizedFingerprint(risk.EntityKind, risk.Score, signals, len(risk.Factors))
		for _, outcome := range entityOutcomes {
			key := fingerprint + "|" + outcome.Outcome
			existing, ok := combined[key]
			if !ok {
				existing = AnonymizedPatternSample{
					TenantHash:  tenantHash,
					Fingerprint: fingerprint,
					Outcome:     outcome.Outcome,
					Signals:     append([]string(nil), signals...),
					ObservedAt:  outcome.OccurredAt,
					Support:     0,
				}
			}
			existing.Support++
			if outcome.OccurredAt.After(existing.ObservedAt) {
				existing.ObservedAt = outcome.OccurredAt
			}
			combined[key] = existing
		}
	}

	samples := make([]AnonymizedPatternSample, 0, len(combined))
	for _, sample := range combined {
		samples = append(samples, sample)
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Fingerprint == samples[j].Fingerprint {
			return samples[i].Outcome < samples[j].Outcome
		}
		return samples[i].Fingerprint < samples[j].Fingerprint
	})
	return samples, nil
}

// IngestAnonymizedPatternSamples ingests privacy-safe signatures from many tenants.
func (r *RiskEngine) IngestAnonymizedPatternSamples(samples []AnonymizedPatternSample) PatternIngestSummary {
	summary := PatternIngestSummary{Received: len(samples)}
	if len(samples) == 0 {
		return summary
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, sample := range samples {
		tenantHash := strings.TrimSpace(sample.TenantHash)
		fingerprint := strings.TrimSpace(sample.Fingerprint)
		outcome := normalizeOutcomeType(sample.Outcome)
		if tenantHash == "" || fingerprint == "" || outcome == "" {
			summary.Skipped++
			continue
		}

		support := sample.Support
		if support <= 0 {
			support = 1
		}

		key := fingerprint + "|" + outcome
		aggregate, exists := r.patternLibrary[key]
		if !exists {
			aggregate = &crossTenantPatternAggregate{
				Fingerprint: fingerprint,
				Outcome:     outcome,
				Signals:     uniqueTrimmedStrings(sample.Signals),
				tenantSet:   map[string]struct{}{tenantHash: {}},
			}
			r.patternLibrary[key] = aggregate
			summary.Added++
		} else {
			summary.Updated++
			aggregate.Signals = uniqueTrimmedStrings(append(aggregate.Signals, sample.Signals...))
			if aggregate.tenantSet == nil {
				aggregate.tenantSet = make(map[string]struct{})
			}
			aggregate.tenantSet[tenantHash] = struct{}{}
		}

		aggregate.Occurrences += support
		observedAt := sample.ObservedAt.UTC()
		if observedAt.IsZero() {
			observedAt = time.Now().UTC()
		}
		if aggregate.LastUpdated.IsZero() || observedAt.After(aggregate.LastUpdated) {
			aggregate.LastUpdated = observedAt
		}
	}

	return summary
}

// CrossTenantPatterns returns anonymized pattern aggregates for recommendation matching.
func (r *RiskEngine) CrossTenantPatterns(minTenants int) []CrossTenantPattern {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cfg := r.crossTenantPrivacyConfigLocked()
	if minTenants < cfg.MinTenantCount {
		minTenants = cfg.MinTenantCount
	}

	if len(r.patternLibrary) == 0 {
		return nil
	}

	totalByFingerprint := make(map[string]int)
	for _, aggregate := range r.patternLibrary {
		totalByFingerprint[aggregate.Fingerprint] += aggregate.Occurrences
	}

	patterns := make([]CrossTenantPattern, 0, len(r.patternLibrary))
	for _, aggregate := range r.patternLibrary {
		tenantCount := len(aggregate.tenantSet)
		if tenantCount < minTenants {
			continue
		}
		if aggregate.Occurrences < cfg.MinPatternSupport {
			continue
		}
		total := totalByFingerprint[aggregate.Fingerprint]
		probability := 0.0
		if total > 0 {
			probability = float64(aggregate.Occurrences) / float64(total)
		}
		patterns = append(patterns, CrossTenantPattern{
			Fingerprint:        aggregate.Fingerprint,
			Outcome:            aggregate.Outcome,
			Signals:            append([]string(nil), aggregate.Signals...),
			TenantCount:        tenantCount,
			Occurrences:        aggregate.Occurrences,
			OutcomeProbability: roundProbability(probability),
			SuggestedAction:    suggestedActionForOutcome(aggregate.Outcome),
			UpdatedAt:          aggregate.LastUpdated,
		})
	}

	sort.Slice(patterns, func(i, j int) bool {
		if patterns[i].TenantCount == patterns[j].TenantCount {
			if patterns[i].OutcomeProbability == patterns[j].OutcomeProbability {
				return patterns[i].Fingerprint < patterns[j].Fingerprint
			}
			return patterns[i].OutcomeProbability > patterns[j].OutcomeProbability
		}
		return patterns[i].TenantCount > patterns[j].TenantCount
	})
	return patterns
}

// MatchCrossTenantPatterns compares current-tenant entity fingerprints to cross-tenant library patterns.
func (r *RiskEngine) MatchCrossTenantPatterns(minProbability float64, limit int) []CrossTenantPatternMatch {
	if minProbability <= 0 {
		minProbability = 0.60
	}
	if limit <= 0 {
		limit = 25
	}

	report := r.GetCachedReport(30 * time.Minute)
	if report == nil {
		report = r.Analyze()
	}
	if report == nil {
		return nil
	}

	patterns := r.CrossTenantPatterns(2)
	if len(patterns) == 0 {
		return nil
	}
	byFingerprint := make(map[string][]CrossTenantPattern)
	for _, pattern := range patterns {
		byFingerprint[pattern.Fingerprint] = append(byFingerprint[pattern.Fingerprint], pattern)
	}

	matches := make([]CrossTenantPatternMatch, 0)
	for entityID, risk := range report.EntityRisks {
		signals := strongSignalFamilies(risk.Factors)
		if len(signals) == 0 {
			continue
		}
		fingerprint := anonymizedFingerprint(risk.EntityKind, risk.Score, signals, len(risk.Factors))
		candidates := byFingerprint[fingerprint]
		for _, candidate := range candidates {
			if candidate.OutcomeProbability < minProbability {
				continue
			}
			matches = append(matches, CrossTenantPatternMatch{
				EntityID:           entityID,
				EntityKind:         risk.EntityKind,
				EntityScore:        risk.Score,
				Fingerprint:        fingerprint,
				Outcome:            candidate.Outcome,
				OutcomeProbability: candidate.OutcomeProbability,
				MatchedTenants:     candidate.TenantCount,
				Occurrences:        candidate.Occurrences,
				SuggestedAction:    candidate.SuggestedAction,
			})
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].OutcomeProbability == matches[j].OutcomeProbability {
			if matches[i].MatchedTenants == matches[j].MatchedTenants {
				return matches[i].EntityID < matches[j].EntityID
			}
			return matches[i].MatchedTenants > matches[j].MatchedTenants
		}
		return matches[i].OutcomeProbability > matches[j].OutcomeProbability
	})

	if len(matches) > limit {
		matches = matches[:limit]
	}
	return matches
}

func hashTenantID(tenantID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(strings.ToLower(tenantID))))
	return hex.EncodeToString(sum[:8])
}

func strongSignalFamilies(factors []EntityRiskFactor) []string {
	signals := make([]string, 0)
	for _, factor := range factors {
		if factor.Score < 35 {
			continue
		}
		signal := normalizeSignalFamily(factor.Source)
		if signal == "" {
			continue
		}
		signals = append(signals, signal)
	}
	if len(signals) == 0 {
		for _, factor := range factors {
			signal := normalizeSignalFamily(factor.Source)
			if signal == "" {
				continue
			}
			signals = append(signals, signal)
			if len(signals) >= 2 {
				break
			}
		}
	}
	return uniqueTrimmedStrings(signals)
}

func anonymizedFingerprint(kind NodeKind, score float64, signals []string, factorCount int) string {
	if len(signals) == 0 {
		signals = []string{"unknown"}
	}
	riskBucket := "low"
	switch {
	case score >= 80:
		riskBucket = "critical"
	case score >= 60:
		riskBucket = "high"
	case score >= 40:
		riskBucket = "medium"
	}

	factorBucket := "1"
	switch {
	case factorCount >= 4:
		factorBucket = "4+"
	case factorCount == 3:
		factorBucket = "3"
	case factorCount == 2:
		factorBucket = "2"
	}
	return fmt.Sprintf(
		"kind=%s|risk=%s|signals=%s|factors=%s",
		kind,
		riskBucket,
		strings.Join(signals, ","),
		factorBucket,
	)
}

func suggestedActionForOutcome(outcome string) string {
	switch normalizeOutcomeType(outcome) {
	case "churn":
		return "Trigger customer rescue plan and executive sponsor review within 24h."
	case "closed_lost":
		return "Escalate deal recovery workflow with legal, product, and account team alignment."
	case "sla_breach":
		return "Initiate SLA breach response runbook and increase incident command staffing."
	case "incident":
		return "Run incident containment playbook and enforce immediate postmortem ownership."
	case "payment_default":
		return "Start collections + commercial risk intervention with finance and account owner."
	default:
		return "Open a cross-functional mitigation plan and monitor risk trajectory daily."
	}
}

func roundProbability(value float64) float64 {
	return math.Round(value*1000) / 1000
}
