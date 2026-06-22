package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const riskScoringConfiguredModelPrefix = FindingRiskModelVersion + "+config:"

// DefaultRiskScoringConfig returns the built-in scoring config for a tenant.
func DefaultRiskScoringConfig(tenantID string) ports.RiskScoringConfig {
	return ports.RiskScoringConfig{
		TenantID: strings.TrimSpace(tenantID),
		Thresholds: ports.RiskScoringLevelThresholds{
			Critical: 85,
			High:     70,
			Medium:   40,
		},
		Signals: ports.RiskScoringSignalThresholds{
			EPSSHigh:                    0.7,
			EPSSElevated:                0.2,
			CVSSCritical:                9,
			CVSSHigh:                    7,
			PrivateNetworkLikelihoodCap: 35,
		},
		RelationWeights: map[string]int{
			"can_admin":          10,
			"can_assume":         8,
			"can_impersonate":    8,
			"can_perform":        8,
			"can_reach":          7,
			"acted_on":           5,
			"has_evidence":       5,
			"supports":           5,
			"assigned_to":        4,
			"member_of":          4,
			"runs_as":            4,
			"has_finding":        3,
			"has_identifier":     1,
			"has_classification": 1,
			"tagged_as":          1,
			"default":            2,
		},
		FactorWeights: map[string]ports.RiskScoringFactorWeight{
			"active":                      {Likelihood: 5},
			"active_threat":               {Likelihood: 25},
			"critical_asset":              {Impact: 35},
			"cvss_critical":               {Likelihood: 10, Impact: 10},
			"cvss_high":                   {Likelihood: 5, Impact: 5},
			"external_exposure":           {Likelihood: 35},
			"exploit_available":           {Likelihood: 20},
			"exploit_maturity":            {Likelihood: 15},
			"graph_evidence":              {Confidence: 5},
			"known_exploited":             {Likelihood: 35},
			"limited_evidence":            {Confidence: -15},
			"overdue":                     {Impact: 5},
			"private_network_context":     {LikelihoodCap: 35},
			"privilege_or_control_plane":  {Impact: 20},
			"privileged_actor":            {Likelihood: 10, Impact: 15},
			"production_environment":      {Impact: 15},
			"recent_24h":                  {Likelihood: 5},
			"recent_7d":                   {Likelihood: 2},
			"regulated_or_sensitive_data": {Impact: 20},
			"risky_action":                {Likelihood: 12},
			"sensitive_data":              {Impact: 25},
			"crown_jewel":                 {Impact: 35},
			"epss_high":                   {Likelihood: 25},
			"epss_elevated":               {Likelihood: 12},
		},
	}
}

// NormalizeCompleteRiskScoringConfig normalizes a fully materialized config while
// preserving explicit zero-valued signal thresholds.
func NormalizeCompleteRiskScoringConfig(input ports.RiskScoringConfig) (ports.RiskScoringConfig, error) {
	normalized := DefaultRiskScoringConfig(input.TenantID)
	if input.Thresholds != (ports.RiskScoringLevelThresholds{}) {
		normalized.Thresholds = input.Thresholds
	}
	if input.Signals != (ports.RiskScoringSignalThresholds{}) {
		normalized.Signals = input.Signals
	}
	for key, weight := range input.RelationWeights {
		name := normalizeRiskScoringKey(key)
		if name == "" {
			return ports.RiskScoringConfig{}, fmt.Errorf("relation weight key is required")
		}
		normalized.RelationWeights[name] = weight
	}
	for key, weight := range input.FactorWeights {
		name := normalizeRiskScoringKey(key)
		if name == "" {
			return ports.RiskScoringConfig{}, fmt.Errorf("factor weight key is required")
		}
		normalized.FactorWeights[name] = weight
	}
	syncPrivateNetworkCap(&normalized)
	normalized.CreatedAt = input.CreatedAt
	normalized.UpdatedAt = input.UpdatedAt
	if err := ValidateRiskScoringConfig(normalized); err != nil {
		return ports.RiskScoringConfig{}, err
	}
	return normalized, nil
}

// ValidateRiskScoringConfig validates a normalized config.
func ValidateRiskScoringConfig(config ports.RiskScoringConfig) error {
	thresholds := config.Thresholds
	if thresholds.Critical <= thresholds.High || thresholds.High <= thresholds.Medium || thresholds.Medium <= 0 || thresholds.Critical > 100 {
		return fmt.Errorf("risk level thresholds must satisfy 100 >= critical > high > medium > 0")
	}
	signals := config.Signals
	if signals.EPSSHigh < 0 || signals.EPSSHigh > 1 || signals.EPSSElevated < 0 || signals.EPSSElevated > 1 || signals.EPSSHigh < signals.EPSSElevated {
		return fmt.Errorf("EPSS thresholds must satisfy 1 >= high >= elevated >= 0")
	}
	if signals.CVSSCritical < 0 || signals.CVSSCritical > 10 || signals.CVSSHigh < 0 || signals.CVSSHigh > 10 || signals.CVSSCritical <= signals.CVSSHigh {
		return fmt.Errorf("CVSS thresholds must satisfy 10 >= critical > high >= 0")
	}
	if signals.PrivateNetworkLikelihoodCap < 0 || signals.PrivateNetworkLikelihoodCap > 100 {
		return fmt.Errorf("private network likelihood cap must be between 0 and 100")
	}
	if len(config.RelationWeights) > 64 {
		return fmt.Errorf("relation weights must contain at most 64 entries")
	}
	for key, weight := range config.RelationWeights {
		if normalizeRiskScoringKey(key) == "" {
			return fmt.Errorf("relation weight key is required")
		}
		if weight < 0 || weight > 100 {
			return fmt.Errorf("relation weight %q must be between 0 and 100", key)
		}
	}
	if len(config.FactorWeights) > 128 {
		return fmt.Errorf("factor weights must contain at most 128 entries")
	}
	for key, weight := range config.FactorWeights {
		if normalizeRiskScoringKey(key) == "" {
			return fmt.Errorf("factor weight key is required")
		}
		if weight.Likelihood < -100 || weight.Likelihood > 100 || weight.Impact < -100 || weight.Impact > 100 || weight.Confidence < -100 || weight.Confidence > 100 {
			return fmt.Errorf("factor weight %q dimensions must be between -100 and 100", key)
		}
		if weight.LikelihoodCap < 0 || weight.LikelihoodCap > 100 {
			return fmt.Errorf("factor weight %q likelihood cap must be between 0 and 100", key)
		}
	}
	return nil
}

func normalizeRiskScoringKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func syncPrivateNetworkCap(config *ports.RiskScoringConfig) {
	if config == nil {
		return
	}
	if config.FactorWeights == nil {
		config.FactorWeights = map[string]ports.RiskScoringFactorWeight{}
	}
	weight := config.FactorWeights["private_network_context"]
	weight.LikelihoodCap = config.Signals.PrivateNetworkLikelihoodCap
	config.FactorWeights["private_network_context"] = weight
}

func riskScoringSettingsFromConfig(config *ports.RiskScoringConfig) riskScoringSettings {
	if config == nil {
		defaultConfig := DefaultRiskScoringConfig("")
		return riskScoringSettings{config: defaultConfig, modelVersion: defaultFindingRiskModelVersion}
	}
	normalized, err := NormalizeCompleteRiskScoringConfig(*config)
	if err != nil {
		defaultConfig := DefaultRiskScoringConfig("")
		return riskScoringSettings{config: defaultConfig, modelVersion: defaultFindingRiskModelVersion}
	}
	return riskScoringSettings{config: normalized, modelVersion: riskScoringConfigModelVersion(normalized), configured: true}
}

type riskScoringSettings struct {
	config       ports.RiskScoringConfig
	modelVersion string
	configured   bool
}

func (s riskScoringSettings) level(score int) string {
	score = clampScore(score)
	switch {
	case score >= s.config.Thresholds.Critical:
		return "critical"
	case score >= s.config.Thresholds.High:
		return "high"
	case score >= s.config.Thresholds.Medium:
		return "medium"
	case score > 0:
		return "low"
	default:
		return ""
	}
}

func (s riskScoringSettings) severity(score int) string {
	switch s.level(score) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		return ""
	}
}

func (s riskScoringSettings) factorWeight(key string, fallback ports.RiskScoringFactorWeight) ports.RiskScoringFactorWeight {
	if s.configured {
		if weight, ok := s.config.FactorWeights[normalizeRiskScoringKey(key)]; ok {
			return weight
		}
	}
	return fallback
}

func applyRiskScoringFactor(settings riskScoringSettings, key string, reason string, fallback ports.RiskScoringFactorWeight, likelihood *int, impact *int, confidence *int, reasons *[]string) {
	weight := settings.factorWeight(key, fallback)
	*likelihood += weight.Likelihood
	*impact += weight.Impact
	*confidence += weight.Confidence
	if weight.LikelihoodCap > 0 || normalizeRiskScoringKey(key) == "private_network_context" {
		*likelihood = min(*likelihood, weight.LikelihoodCap)
	}
	if strings.TrimSpace(reason) != "" {
		*reasons = append(*reasons, reason)
	}
}

func riskScoringRelationWeight(settings riskScoringSettings, relation string) int {
	if weight, ok := settings.config.RelationWeights[normalizeRiskScoringKey(relation)]; ok {
		return weight
	}
	if weight, ok := settings.config.RelationWeights["default"]; ok {
		return weight
	}
	return 2
}

func riskScoringConfigModelVersion(config ports.RiskScoringConfig) string {
	return RiskScoringConfigModelVersion(config)
}

// RiskScoringConfigModelVersion returns the risk model version for a normalized config.
func RiskScoringConfigModelVersion(config ports.RiskScoringConfig) string {
	body, err := json.Marshal(struct {
		Thresholds      ports.RiskScoringLevelThresholds         `json:"thresholds"`
		Signals         ports.RiskScoringSignalThresholds        `json:"signals"`
		RelationWeights map[string]int                           `json:"relation_weights"`
		FactorWeights   map[string]ports.RiskScoringFactorWeight `json:"factor_weights"`
	}{
		Thresholds:      config.Thresholds,
		Signals:         config.Signals,
		RelationWeights: config.RelationWeights,
		FactorWeights:   config.FactorWeights,
	})
	if err != nil {
		return defaultFindingRiskModelVersion
	}
	sum := sha256.Sum256(body)
	return riskScoringConfiguredModelPrefix + hex.EncodeToString(sum[:])[:12]
}
