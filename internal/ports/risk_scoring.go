package ports

import (
	"context"
	"errors"
	"time"
)

// ErrRiskScoringConfigNotFound indicates that a tenant has no persisted risk scoring override.
var ErrRiskScoringConfigNotFound = errors.New("risk scoring config not found")

// RiskScoringLevelThresholds controls score-to-level boundaries.
type RiskScoringLevelThresholds struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
}

// RiskScoringSignalThresholds controls numeric signal thresholds used by risk scoring.
type RiskScoringSignalThresholds struct {
	EPSSHigh                    float64 `json:"epss_high"`
	EPSSElevated                float64 `json:"epss_elevated"`
	CVSSCritical                float64 `json:"cvss_critical"`
	CVSSHigh                    float64 `json:"cvss_high"`
	PrivateNetworkLikelihoodCap int     `json:"private_network_likelihood_cap"`
}

// RiskScoringFactorWeight controls how a named risk signal adjusts the score dimensions.
type RiskScoringFactorWeight struct {
	Likelihood    int `json:"likelihood,omitempty"`
	Impact        int `json:"impact,omitempty"`
	Confidence    int `json:"confidence,omitempty"`
	LikelihoodCap int `json:"likelihood_cap,omitempty"`
}

// RiskScoringConfig is a tenant-scoped override for the default finding risk model.
type RiskScoringConfig struct {
	TenantID        string                             `json:"tenant_id"`
	Thresholds      RiskScoringLevelThresholds         `json:"thresholds"`
	Signals         RiskScoringSignalThresholds        `json:"signals"`
	RelationWeights map[string]int                     `json:"relation_weights"`
	FactorWeights   map[string]RiskScoringFactorWeight `json:"factor_weights"`
	CreatedAt       time.Time                          `json:"created_at,omitempty"`
	UpdatedAt       time.Time                          `json:"updated_at,omitempty"`
}

// RiskScoringConfigStore persists tenant-scoped risk scoring overrides.
type RiskScoringConfigStore interface {
	PutRiskScoringConfig(context.Context, *RiskScoringConfig) error
	GetRiskScoringConfig(context.Context, string) (*RiskScoringConfig, error)
	DeleteRiskScoringConfig(context.Context, string) error
}
