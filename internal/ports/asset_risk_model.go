package ports

import (
	"context"
	"errors"
	"time"
)

// ErrAssetRiskModelNotFound indicates that a tenant has no saved asset risk model.
var ErrAssetRiskModelNotFound = errors.New("asset risk model not found")

// AssetRiskModel is a tenant-scoped model for scoring assets and attack paths
// as chains of compromise probabilities weighted by what the target is worth.
// Probabilities, values, and reductions are fractions between 0 and 1.
type AssetRiskModel struct {
	TenantID        string                       `json:"tenant_id"`
	AssetValue      AssetRiskValueModel          `json:"asset_value"`
	Vulnerability   AssetRiskVulnerabilityModel  `json:"vulnerability"`
	Exposure        AssetRiskExposureModel       `json:"exposure"`
	Countermeasures []AssetRiskCountermeasure    `json:"countermeasures"`
	Relations       map[string]AssetRiskRelation `json:"relations"`
	Traversal       AssetRiskTraversal           `json:"traversal"`
	Thresholds      RiskScoringLevelThresholds   `json:"thresholds"`
	CreatedAt       time.Time                    `json:"created_at,omitempty"`
	UpdatedAt       time.Time                    `json:"updated_at,omitempty"`
}

// AssetRiskValueModel decides how much an asset is worth to an attacker.
type AssetRiskValueModel struct {
	Default                  float64            `json:"default"`
	CrownJewel               float64            `json:"crown_jewel"`
	ProductionBoost          float64            `json:"production_boost"`
	ClassificationAttributes []string           `json:"classification_attributes"`
	Classifications          map[string]float64 `json:"classifications"`
	KindValues               map[string]float64 `json:"kind_values"`
}

// AssetRiskVulnerabilityModel turns vulnerability intelligence into the
// probability that one vulnerability lets an attacker compromise its asset.
type AssetRiskVulnerabilityModel struct {
	Relations               []string `json:"relations"`
	Base                    float64  `json:"base"`
	NoKnownVulnerability    float64  `json:"no_known_vulnerability"`
	EPSSWeight              float64  `json:"epss_weight"`
	KnownExploited          float64  `json:"known_exploited"`
	RansomwareUse           float64  `json:"ransomware_use"`
	CVSSCritical            float64  `json:"cvss_critical"`
	CVSSHigh                float64  `json:"cvss_high"`
	CVSSCriticalProbability float64  `json:"cvss_critical_probability"`
	CVSSHighProbability     float64  `json:"cvss_high_probability"`
	MaxPerAsset             int      `json:"max_per_asset"`
}

// AssetRiskExposureModel controls how reachable a starting point is.
type AssetRiskExposureModel struct {
	EntryProbability   float64  `json:"entry_probability"`
	Internet           float64  `json:"internet"`
	Internal           float64  `json:"internal"`
	InternetAttributes []string `json:"internet_attributes"`
}

// AssetRiskCountermeasure lowers the probability of compromising an entity
// whose attributes show the control is in place.
type AssetRiskCountermeasure struct {
	Key        string   `json:"key"`
	Label      string   `json:"label"`
	Attributes []string `json:"attributes"`
	Values     []string `json:"values,omitempty"`
	AppliesTo  []string `json:"applies_to,omitempty"`
	Reduction  float64  `json:"reduction"`
}

// AssetRiskRelation controls one graph relation as an attack step.
// Direction is outgoing, incoming, or both, relative to the attacker's movement.
type AssetRiskRelation struct {
	Probability     float64 `json:"probability"`
	Direction       string  `json:"direction"`
	RequiresExploit bool    `json:"requires_exploit,omitempty"`
}

// AssetRiskTraversal bounds attack path exploration.
type AssetRiskTraversal struct {
	MaxDepth       int     `json:"max_depth"`
	MaxPaths       int     `json:"max_paths"`
	MaxExpansions  int     `json:"max_expansions"`
	MinProbability float64 `json:"min_probability"`
}

// AssetRiskModelStore persists tenant-scoped asset risk models. State stores
// implement it as an optional capability discovered via type assertion.
type AssetRiskModelStore interface {
	PutAssetRiskModel(context.Context, *AssetRiskModel) error
	GetAssetRiskModel(context.Context, string) (*AssetRiskModel, error)
	DeleteAssetRiskModel(context.Context, string) error
}
