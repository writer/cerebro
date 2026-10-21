// Package assetrisk scores assets and attack paths as chains of compromise
// probabilities. Each step's probability rises with vulnerability intelligence
// (EPSS, CISA KEV, CVSS) and exposure, falls with countermeasures, and the
// chain is weighted by how much the target asset is worth.
package assetrisk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// ModelVersion identifies the built-in scoring semantics.
const ModelVersion = "asset-risk-v1"

// ErrInvalidModel marks a model that fails validation.
var ErrInvalidModel = errors.New("invalid asset risk model")

// Relation directions relative to the attacker's movement.
const (
	DirectionOutgoing = "outgoing"
	DirectionIncoming = "incoming"
	DirectionBoth     = "both"
)

const (
	maxClassifications   = 64
	maxKindValues        = 128
	maxAttributeKeys     = 16
	maxCountermeasures   = 32
	maxRelations         = 64
	maxVulnRelations     = 8
	maxVulnsPerAssetCap  = 200
	maxTraversalDepth    = 6
	maxTraversalPaths    = 200
	maxTraversalExpands  = 1000
	maxModelKeyLength    = 128
	maxCountermeasureVal = 32
)

// DefaultModel returns the built-in model for a tenant.
func DefaultModel(tenantID string) ports.AssetRiskModel {
	return ports.AssetRiskModel{
		TenantID: strings.TrimSpace(tenantID),
		AssetValue: ports.AssetRiskValueModel{
			Default:                  0.2,
			CrownJewel:               1,
			ProductionBoost:          0.15,
			ClassificationAttributes: []string{"data_classification", "classification", "data_sensitivity", "sensitivity"},
			Classifications: map[string]float64{
				"restricted":   1,
				"secret":       1,
				"confidential": 0.85,
				"pii":          0.85,
				"phi":          0.9,
				"pci":          0.9,
				"sensitive":    0.8,
				"internal":     0.4,
				"public":       0.05,
			},
			KindValues: map[string]float64{
				"secret":        0.9,
				"database":      0.8,
				"cluster":       0.7,
				"repository":    0.6,
				"bucket":        0.6,
				"application":   0.6,
				"role":          0.5,
				"host":          0.5,
				"instance":      0.5,
				"device":        0.4,
				"identity":      0.4,
				"user":          0.4,
				"person":        0.3,
				"group":         0.3,
				"entitlement":   0.4,
				"capability":    0.5,
				"vulnerability": 0,
			},
		},
		Vulnerability: ports.AssetRiskVulnerabilityModel{
			Relations:               []string{"affected_by"},
			Base:                    0.05,
			NoKnownVulnerability:    0.02,
			EPSSWeight:              1,
			KnownExploited:          0.85,
			RansomwareUse:           0.95,
			CVSSCritical:            9,
			CVSSHigh:                7,
			CVSSCriticalProbability: 0.3,
			CVSSHighProbability:     0.15,
			MaxPerAsset:             50,
		},
		Exposure: ports.AssetRiskExposureModel{
			EntryProbability:   0.2,
			Internet:           1,
			Internal:           0.4,
			InternetAttributes: []string{"internet_exposed", "publicly_accessible", "public", "public_ip", "external_exposure"},
		},
		Countermeasures: []ports.AssetRiskCountermeasure{
			{Key: "mfa", Label: "MFA enforced", Attributes: []string{"mfa_enabled", "mfa_enforced", "mfa_active"}, AppliesTo: []string{"identity", "user", "person", "account"}, Reduction: 0.6},
			{Key: "edr", Label: "EDR agent active", Attributes: []string{"edr_active", "edr_installed", "agent_active"}, AppliesTo: []string{"device", "host", "instance", "endpoint"}, Reduction: 0.5},
			{Key: "network_segmentation", Label: "Network segmented", Attributes: []string{"network_segmented", "private_network"}, Reduction: 0.4},
			{Key: "waf", Label: "WAF in front", Attributes: []string{"waf_enabled", "waf_protected"}, Reduction: 0.3},
			{Key: "encryption", Label: "Encrypted at rest", Attributes: []string{"encrypted", "encryption_enabled", "disk_encrypted"}, Reduction: 0.2},
		},
		Relations: map[string]ports.AssetRiskRelation{
			"same_actor":          {Probability: 0.95, Direction: DirectionBoth},
			"represents_identity": {Probability: 0.95, Direction: DirectionBoth},
			"owned_by":            {Probability: 0.7, Direction: DirectionBoth},
			"member_of":           {Probability: 1, Direction: DirectionOutgoing},
			"assigned_to":         {Probability: 0.9, Direction: DirectionOutgoing},
			"grants_entitlement":  {Probability: 0.9, Direction: DirectionOutgoing},
			"confers_capability":  {Probability: 0.9, Direction: DirectionOutgoing},
			"can_admin":           {Probability: 0.9, Direction: DirectionOutgoing},
			"can_assume":          {Probability: 0.8, Direction: DirectionOutgoing},
			"can_impersonate":     {Probability: 0.8, Direction: DirectionOutgoing},
			"runs_as":             {Probability: 0.8, Direction: DirectionOutgoing},
			"has_access":          {Probability: 0.7, Direction: DirectionOutgoing},
			"can_perform":         {Probability: 0.6, Direction: DirectionOutgoing},
			"can_reach":           {Probability: 0.5, Direction: DirectionOutgoing, RequiresExploit: true},
		},
		Traversal: ports.AssetRiskTraversal{
			MaxDepth:       4,
			MaxPaths:       50,
			MaxExpansions:  150,
			MinProbability: 0.01,
		},
		Thresholds: ports.RiskScoringLevelThresholds{Critical: 40, High: 20, Medium: 8},
	}
}

// DecodeModel reads a model document. Sections absent from the document keep
// their defaults; a section that is present replaces the default section, so
// clients can remove map entries and countermeasures.
func DecodeModel(tenantID string, data []byte) (ports.AssetRiskModel, error) {
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(data, &sections); err != nil {
		return ports.AssetRiskModel{}, fmt.Errorf("%w: %w", ErrInvalidModel, err)
	}
	model := DefaultModel(tenantID)
	decode := func(key string, target any) error {
		raw, ok := sections[key]
		if !ok || string(raw) == "null" {
			return nil
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrInvalidModel, key, err)
		}
		return nil
	}
	defaults := model.AssetValue
	model.AssetValue.Classifications = nil
	model.AssetValue.KindValues = nil
	if err := decode("asset_value", &model.AssetValue); err != nil {
		return ports.AssetRiskModel{}, err
	}
	if model.AssetValue.Classifications == nil {
		model.AssetValue.Classifications = defaults.Classifications
	}
	if model.AssetValue.KindValues == nil {
		model.AssetValue.KindValues = defaults.KindValues
	}
	if err := decode("vulnerability", &model.Vulnerability); err != nil {
		return ports.AssetRiskModel{}, err
	}
	if err := decode("exposure", &model.Exposure); err != nil {
		return ports.AssetRiskModel{}, err
	}
	if raw, ok := sections["countermeasures"]; ok && string(raw) != "null" {
		model.Countermeasures = nil
		if err := decode("countermeasures", &model.Countermeasures); err != nil {
			return ports.AssetRiskModel{}, err
		}
		if model.Countermeasures == nil {
			model.Countermeasures = []ports.AssetRiskCountermeasure{}
		}
	}
	if raw, ok := sections["relations"]; ok && string(raw) != "null" {
		model.Relations = nil
		if err := decode("relations", &model.Relations); err != nil {
			return ports.AssetRiskModel{}, err
		}
	}
	if err := decode("traversal", &model.Traversal); err != nil {
		return ports.AssetRiskModel{}, err
	}
	if err := decode("thresholds", &model.Thresholds); err != nil {
		return ports.AssetRiskModel{}, err
	}
	return NormalizeModel(model)
}

// NormalizeModel canonicalizes keys, fills missing maps with defaults, and
// validates the result.
func NormalizeModel(input ports.AssetRiskModel) (ports.AssetRiskModel, error) {
	defaults := DefaultModel(input.TenantID)
	model := input
	model.TenantID = strings.TrimSpace(input.TenantID)
	model.AssetValue.ClassificationAttributes = normalizeKeyList(input.AssetValue.ClassificationAttributes)
	var err error
	if model.AssetValue.Classifications, err = normalizeFloatMap(input.AssetValue.Classifications, defaults.AssetValue.Classifications, "classification"); err != nil {
		return ports.AssetRiskModel{}, err
	}
	if model.AssetValue.KindValues, err = normalizeFloatMap(input.AssetValue.KindValues, defaults.AssetValue.KindValues, "asset kind"); err != nil {
		return ports.AssetRiskModel{}, err
	}
	model.Vulnerability.Relations = normalizeKeyList(input.Vulnerability.Relations)
	model.Exposure.InternetAttributes = normalizeKeyList(input.Exposure.InternetAttributes)
	if input.Countermeasures == nil {
		model.Countermeasures = defaults.Countermeasures
	} else {
		model.Countermeasures = make([]ports.AssetRiskCountermeasure, 0, len(input.Countermeasures))
		for _, countermeasure := range input.Countermeasures {
			countermeasure.Key = normalizeKey(countermeasure.Key)
			countermeasure.Label = strings.TrimSpace(countermeasure.Label)
			if countermeasure.Label == "" {
				countermeasure.Label = countermeasure.Key
			}
			countermeasure.Attributes = normalizeKeyList(countermeasure.Attributes)
			countermeasure.AppliesTo = normalizeKeyList(countermeasure.AppliesTo)
			countermeasure.Values = normalizeKeyList(countermeasure.Values)
			model.Countermeasures = append(model.Countermeasures, countermeasure)
		}
	}
	if input.Relations == nil {
		model.Relations = defaults.Relations
	} else {
		model.Relations = make(map[string]ports.AssetRiskRelation, len(input.Relations))
		for key, relation := range input.Relations {
			name := normalizeKey(key)
			if name == "" {
				return ports.AssetRiskModel{}, fmt.Errorf("%w: relation name is required", ErrInvalidModel)
			}
			relation.Direction = strings.ToLower(strings.TrimSpace(relation.Direction))
			if relation.Direction == "" {
				relation.Direction = DirectionOutgoing
			}
			model.Relations[name] = relation
		}
	}
	if err := ValidateModel(model); err != nil {
		return ports.AssetRiskModel{}, err
	}
	return model, nil
}

// ValidateModel checks every bound on a normalized model.
func ValidateModel(model ports.AssetRiskModel) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidModel, fmt.Sprintf(format, args...))
	}
	fractions := []struct {
		name  string
		value float64
	}{
		{"asset_value.default", model.AssetValue.Default},
		{"asset_value.crown_jewel", model.AssetValue.CrownJewel},
		{"asset_value.production_boost", model.AssetValue.ProductionBoost},
		{"vulnerability.base", model.Vulnerability.Base},
		{"vulnerability.no_known_vulnerability", model.Vulnerability.NoKnownVulnerability},
		{"vulnerability.epss_weight", model.Vulnerability.EPSSWeight},
		{"vulnerability.known_exploited", model.Vulnerability.KnownExploited},
		{"vulnerability.ransomware_use", model.Vulnerability.RansomwareUse},
		{"vulnerability.cvss_critical_probability", model.Vulnerability.CVSSCriticalProbability},
		{"vulnerability.cvss_high_probability", model.Vulnerability.CVSSHighProbability},
		{"exposure.entry_probability", model.Exposure.EntryProbability},
		{"exposure.internet", model.Exposure.Internet},
		{"exposure.internal", model.Exposure.Internal},
		{"traversal.min_probability", model.Traversal.MinProbability},
	}
	for _, fraction := range fractions {
		if !isFraction(fraction.value) {
			return invalid("%s must be between 0 and 1", fraction.name)
		}
	}
	if model.Traversal.MinProbability >= 1 {
		return invalid("traversal.min_probability must be below 1")
	}
	if len(model.AssetValue.ClassificationAttributes) > maxAttributeKeys {
		return invalid("asset_value.classification_attributes must contain at most %d keys", maxAttributeKeys)
	}
	if len(model.AssetValue.Classifications) > maxClassifications {
		return invalid("asset_value.classifications must contain at most %d entries", maxClassifications)
	}
	if len(model.AssetValue.KindValues) > maxKindValues {
		return invalid("asset_value.kind_values must contain at most %d entries", maxKindValues)
	}
	for key, value := range model.AssetValue.Classifications {
		if !isFraction(value) {
			return invalid("classification %q value must be between 0 and 1", key)
		}
	}
	for key, value := range model.AssetValue.KindValues {
		if !isFraction(value) {
			return invalid("asset kind %q value must be between 0 and 1", key)
		}
	}
	vuln := model.Vulnerability
	if len(vuln.Relations) == 0 || len(vuln.Relations) > maxVulnRelations {
		return invalid("vulnerability.relations must contain between 1 and %d relations", maxVulnRelations)
	}
	if vuln.CVSSCritical < 0 || vuln.CVSSCritical > 10 || vuln.CVSSHigh < 0 || vuln.CVSSHigh > 10 || vuln.CVSSCritical <= vuln.CVSSHigh {
		return invalid("CVSS thresholds must satisfy 10 >= critical > high >= 0")
	}
	if vuln.MaxPerAsset < 1 || vuln.MaxPerAsset > maxVulnsPerAssetCap {
		return invalid("vulnerability.max_per_asset must be between 1 and %d", maxVulnsPerAssetCap)
	}
	if len(model.Exposure.InternetAttributes) > maxAttributeKeys {
		return invalid("exposure.internet_attributes must contain at most %d keys", maxAttributeKeys)
	}
	if len(model.Countermeasures) > maxCountermeasures {
		return invalid("countermeasures must contain at most %d entries", maxCountermeasures)
	}
	seen := make(map[string]struct{}, len(model.Countermeasures))
	for _, countermeasure := range model.Countermeasures {
		if countermeasure.Key == "" {
			return invalid("countermeasure key is required")
		}
		if _, ok := seen[countermeasure.Key]; ok {
			return invalid("countermeasure %q is defined more than once", countermeasure.Key)
		}
		seen[countermeasure.Key] = struct{}{}
		if len(countermeasure.Attributes) == 0 || len(countermeasure.Attributes) > maxAttributeKeys {
			return invalid("countermeasure %q must name between 1 and %d attributes", countermeasure.Key, maxAttributeKeys)
		}
		if len(countermeasure.Values) > maxCountermeasureVal || len(countermeasure.AppliesTo) > maxAttributeKeys {
			return invalid("countermeasure %q has too many values or entity kinds", countermeasure.Key)
		}
		if !isFraction(countermeasure.Reduction) {
			return invalid("countermeasure %q reduction must be between 0 and 1", countermeasure.Key)
		}
	}
	if len(model.Relations) == 0 || len(model.Relations) > maxRelations {
		return invalid("relations must contain between 1 and %d entries", maxRelations)
	}
	for key, relation := range model.Relations {
		if !isFraction(relation.Probability) {
			return invalid("relation %q probability must be between 0 and 1", key)
		}
		switch relation.Direction {
		case DirectionOutgoing, DirectionIncoming, DirectionBoth:
		default:
			return invalid("relation %q direction must be outgoing, incoming, or both", key)
		}
		if slices.Contains(vuln.Relations, key) {
			return invalid("relation %q cannot be both an attack step and a vulnerability relation", key)
		}
	}
	traversal := model.Traversal
	if traversal.MaxDepth < 1 || traversal.MaxDepth > maxTraversalDepth {
		return invalid("traversal.max_depth must be between 1 and %d", maxTraversalDepth)
	}
	if traversal.MaxPaths < 1 || traversal.MaxPaths > maxTraversalPaths {
		return invalid("traversal.max_paths must be between 1 and %d", maxTraversalPaths)
	}
	if traversal.MaxExpansions < 1 || traversal.MaxExpansions > maxTraversalExpands {
		return invalid("traversal.max_expansions must be between 1 and %d", maxTraversalExpands)
	}
	thresholds := model.Thresholds
	if thresholds.Critical <= thresholds.High || thresholds.High <= thresholds.Medium || thresholds.Medium <= 0 || thresholds.Critical > 100 {
		return invalid("risk level thresholds must satisfy 100 >= critical > high > medium > 0")
	}
	return nil
}

// Version returns the built-in version, or a content-addressed version for a
// saved model so scores can be traced to the model that produced them.
func Version(model ports.AssetRiskModel, persisted bool) string {
	if !persisted {
		return ModelVersion
	}
	hashed := model
	hashed.TenantID = ""
	hashed.CreatedAt = time.Time{}
	hashed.UpdatedAt = time.Time{}
	payload, err := json.Marshal(hashed)
	if err != nil {
		return ModelVersion
	}
	sum := sha256.Sum256(payload)
	return ModelVersion + "+config:" + hex.EncodeToString(sum[:])[:12]
}

func isFraction(value float64) bool {
	return value >= 0 && value <= 1
}

func normalizeKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) > maxModelKeyLength {
		value = value[:maxModelKeyLength]
	}
	return value
}

func normalizeKeyList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := normalizeKey(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func normalizeFloatMap(values map[string]float64, defaults map[string]float64, label string) (map[string]float64, error) {
	if values == nil {
		return maps.Clone(defaults), nil
	}
	out := make(map[string]float64, len(values))
	for key, value := range values {
		name := normalizeKey(key)
		if name == "" {
			return nil, fmt.Errorf("%w: %s name is required", ErrInvalidModel, label)
		}
		out[name] = value
	}
	return out, nil
}
