package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const riskEngineSnapshotVersion = 1

// CrossTenantPrivacyConfig controls minimum privacy thresholds for pattern sharing.
type CrossTenantPrivacyConfig struct {
	MinTenantCount    int `json:"min_tenant_count"`
	MinPatternSupport int `json:"min_pattern_support"`
}

// RulePromotionEvent tracks approval-time promotion outcomes.
type RulePromotionEvent struct {
	CandidateID string    `json:"candidate_id"`
	RuleType    string    `json:"rule_type"`
	Status      string    `json:"status"`
	Details     string    `json:"details,omitempty"`
	AppliedAt   time.Time `json:"applied_at"`
}

// RiskEngineSnapshot stores durable state needed to rehydrate feedback/discovery engines.
type RiskEngineSnapshot struct {
	Version         int                              `json:"version"`
	SavedAt         time.Time                        `json:"saved_at"`
	RiskProfile     string                           `json:"risk_profile"`
	CrossTenantCfg  CrossTenantPrivacyConfig         `json:"cross_tenant_privacy"`
	OutcomeEvents   []OutcomeEvent                   `json:"outcome_events,omitempty"`
	RuleSignals     []RuleObservation                `json:"rule_signals,omitempty"`
	FactorSignals   []FactorObservation              `json:"factor_signals,omitempty"`
	DiscoveredRules []DiscoveredRuleCandidate        `json:"discovered_rules,omitempty"`
	PatternLibrary  []CrossTenantPatternSnapshotItem `json:"pattern_library,omitempty"`
	RulePromotions  []RulePromotionEvent             `json:"rule_promotions,omitempty"`
}

// CrossTenantPatternSnapshotItem is the durable form of one aggregate pattern.
type CrossTenantPatternSnapshotItem struct {
	Fingerprint  string    `json:"fingerprint"`
	Outcome      string    `json:"outcome"`
	Signals      []string  `json:"signals,omitempty"`
	Occurrences  int       `json:"occurrences"`
	LastUpdated  time.Time `json:"last_updated"`
	TenantHashes []string  `json:"tenant_hashes,omitempty"`
}

func defaultCrossTenantPrivacyConfig() CrossTenantPrivacyConfig {
	return CrossTenantPrivacyConfig{
		MinTenantCount:    2,
		MinPatternSupport: 2,
	}
}

func normalizeCrossTenantPrivacyConfig(cfg CrossTenantPrivacyConfig) CrossTenantPrivacyConfig {
	if cfg.MinTenantCount <= 0 {
		cfg.MinTenantCount = defaultCrossTenantPrivacyConfig().MinTenantCount
	}
	if cfg.MinPatternSupport <= 0 {
		cfg.MinPatternSupport = defaultCrossTenantPrivacyConfig().MinPatternSupport
	}
	return cfg
}

// SetCrossTenantPrivacyConfig sets minimum thresholds used for cross-tenant pattern outputs.
func (r *RiskEngine) SetCrossTenantPrivacyConfig(cfg CrossTenantPrivacyConfig) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.crossTenantCfg = normalizeCrossTenantPrivacyConfig(cfg)
}

func (r *RiskEngine) crossTenantPrivacyConfigLocked() CrossTenantPrivacyConfig {
	return normalizeCrossTenantPrivacyConfig(r.crossTenantCfg)
}

// Snapshot exports durable risk-engine state for persistence.
func (r *RiskEngine) Snapshot() RiskEngineSnapshot {
	if r == nil {
		return RiskEngineSnapshot{
			Version: riskEngineSnapshotVersion,
			SavedAt: time.Now().UTC(),
		}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	discovered := make([]DiscoveredRuleCandidate, 0, len(r.discoveredRules))
	for _, candidate := range r.discoveredRules {
		discovered = append(discovered, candidate)
	}
	sort.Slice(discovered, func(i, j int) bool {
		if discovered[i].ProposedAt.Equal(discovered[j].ProposedAt) {
			return discovered[i].ID < discovered[j].ID
		}
		return discovered[i].ProposedAt.Before(discovered[j].ProposedAt)
	})

	patterns := make([]CrossTenantPatternSnapshotItem, 0, len(r.patternLibrary))
	for _, aggregate := range r.patternLibrary {
		if aggregate == nil || strings.TrimSpace(aggregate.Fingerprint) == "" || strings.TrimSpace(aggregate.Outcome) == "" {
			continue
		}
		tenants := make([]string, 0, len(aggregate.tenantSet))
		for tenantHash := range aggregate.tenantSet {
			tenantHash = strings.TrimSpace(tenantHash)
			if tenantHash == "" {
				continue
			}
			tenants = append(tenants, tenantHash)
		}
		sort.Strings(tenants)
		patterns = append(patterns, CrossTenantPatternSnapshotItem{
			Fingerprint:  aggregate.Fingerprint,
			Outcome:      aggregate.Outcome,
			Signals:      append([]string(nil), aggregate.Signals...),
			Occurrences:  aggregate.Occurrences,
			LastUpdated:  aggregate.LastUpdated,
			TenantHashes: tenants,
		})
	}
	sort.Slice(patterns, func(i, j int) bool {
		if patterns[i].Fingerprint == patterns[j].Fingerprint {
			return patterns[i].Outcome < patterns[j].Outcome
		}
		return patterns[i].Fingerprint < patterns[j].Fingerprint
	})

	return RiskEngineSnapshot{
		Version:         riskEngineSnapshotVersion,
		SavedAt:         time.Now().UTC(),
		RiskProfile:     r.riskProfile.Name,
		CrossTenantCfg:  r.crossTenantPrivacyConfigLocked(),
		OutcomeEvents:   append([]OutcomeEvent(nil), r.outcomeEvents...),
		RuleSignals:     append([]RuleObservation(nil), r.ruleSignals...),
		FactorSignals:   append([]FactorObservation(nil), r.factorSignals...),
		DiscoveredRules: discovered,
		PatternLibrary:  patterns,
		RulePromotions:  append([]RulePromotionEvent(nil), r.rulePromotions...),
	}
}

// RestoreSnapshot rehydrates risk-engine feedback/discovery state from a prior snapshot.
func (r *RiskEngine) RestoreSnapshot(snapshot RiskEngineSnapshot) error {
	if r == nil {
		return fmt.Errorf("risk engine is nil")
	}
	if snapshot.Version == 0 {
		return fmt.Errorf("snapshot version is required")
	}
	if snapshot.Version != riskEngineSnapshotVersion {
		return fmt.Errorf("unsupported snapshot version %d", snapshot.Version)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if profileName := strings.TrimSpace(snapshot.RiskProfile); profileName != "" {
		profile := DefaultRiskProfile(profileName)
		if profile.Name == "default" && strings.ToLower(profileName) != "default" {
			return fmt.Errorf("snapshot has unknown risk profile %q", profileName)
		}
		r.riskProfile = profile
	}

	r.crossTenantCfg = normalizeCrossTenantPrivacyConfig(snapshot.CrossTenantCfg)
	r.outcomeEvents = append([]OutcomeEvent(nil), snapshot.OutcomeEvents...)
	r.ruleSignals = append([]RuleObservation(nil), snapshot.RuleSignals...)
	r.factorSignals = append([]FactorObservation(nil), snapshot.FactorSignals...)

	r.discoveredRules = make(map[string]DiscoveredRuleCandidate, len(snapshot.DiscoveredRules))
	for _, candidate := range snapshot.DiscoveredRules {
		candidate.ID = strings.TrimSpace(candidate.ID)
		if candidate.ID == "" {
			continue
		}
		if candidate.Status == "" {
			candidate.Status = RuleCandidateStatusPendingApproval
		}
		r.discoveredRules[candidate.ID] = candidate
	}

	r.patternLibrary = make(map[string]*crossTenantPatternAggregate, len(snapshot.PatternLibrary))
	for _, item := range snapshot.PatternLibrary {
		fingerprint := strings.TrimSpace(item.Fingerprint)
		outcome := normalizeOutcomeType(item.Outcome)
		if fingerprint == "" || outcome == "" {
			continue
		}
		key := fingerprint + "|" + outcome
		tenantSet := make(map[string]struct{}, len(item.TenantHashes))
		for _, tenantHash := range item.TenantHashes {
			tenantHash = strings.TrimSpace(tenantHash)
			if tenantHash == "" {
				continue
			}
			tenantSet[tenantHash] = struct{}{}
		}
		r.patternLibrary[key] = &crossTenantPatternAggregate{
			Fingerprint: fingerprint,
			Outcome:     outcome,
			Signals:     uniqueTrimmedStrings(item.Signals),
			Occurrences: item.Occurrences,
			LastUpdated: item.LastUpdated.UTC(),
			tenantSet:   tenantSet,
		}
	}

	r.rulePromotions = append([]RulePromotionEvent(nil), snapshot.RulePromotions...)
	r.trimSignalsLocked()
	return nil
}
