package risk

import graph "github.com/writer/cerebro/internal/graph"

type (
	Severity                   = graph.Severity
	RiskFactor                 = graph.RiskFactor
	RiskFactorType             = graph.RiskFactorType
	RemediationStep            = graph.RemediationStep
	AttackPath                 = graph.AttackPath
	AttackStep                 = graph.AttackStep
	ToxicCombination           = graph.ToxicCombination
	ToxicCombinationRule       = graph.ToxicCombinationRule
	ToxicCombinationEngine     = graph.ToxicCombinationEngine
	AttackPathSimulator        = graph.AttackPathSimulator
	SimulationResult           = graph.SimulationResult
	ScoredAttackPath           = graph.ScoredAttackPath
	Chokepoint                 = graph.Chokepoint
	FixSimulation              = graph.FixSimulation
	BlastRadiusResult          = graph.BlastRadiusResult
	ReachableNode              = graph.ReachableNode
	RiskSummary                = graph.RiskSummary
	ReverseAccessResult        = graph.ReverseAccessResult
	AccessorNode               = graph.AccessorNode
	CascadingBlastRadiusResult = graph.CascadingBlastRadiusResult
	CompromisedNode            = graph.CompromisedNode
	SensitiveDataNode          = graph.SensitiveDataNode
	AccountBoundaryCross       = graph.AccountBoundaryCross
	RiskEngine                 = graph.RiskEngine
	SecurityReport             = graph.SecurityReport
	RankedRisk                 = graph.RankedRisk
	RemediationPlan            = graph.RemediationPlan
	RemediationAction          = graph.RemediationAction
	TrendAnalysis              = graph.TrendAnalysis
	ComplianceGap              = graph.ComplianceGap
	RiskProfile                = graph.RiskProfile
	EntityRisk                 = graph.EntityRisk
	EntityRiskFactor           = graph.EntityRiskFactor
	RiskScoreChangedEvent      = graph.RiskScoreChangedEvent
	OutcomeEvent               = graph.OutcomeEvent
	RuleObservation            = graph.RuleObservation
	FactorObservation          = graph.FactorObservation
	CrossTenantPrivacyConfig   = graph.CrossTenantPrivacyConfig
	RulePromotionEvent         = graph.RulePromotionEvent
	RiskEngineSnapshot         = graph.RiskEngineSnapshot
	AnonymizedPatternSample    = graph.AnonymizedPatternSample
	PatternIngestSummary       = graph.PatternIngestSummary
	CrossTenantPattern         = graph.CrossTenantPattern
	CrossTenantPatternMatch    = graph.CrossTenantPatternMatch
	DiscoveredRuleCandidate    = graph.DiscoveredRuleCandidate
)

const (
	SeverityCritical = graph.SeverityCritical
	SeverityHigh     = graph.SeverityHigh
	SeverityMedium   = graph.SeverityMedium
	SeverityLow      = graph.SeverityLow
)

var (
	NewRiskEngine             = graph.NewRiskEngine
	NewToxicCombinationEngine = graph.NewToxicCombinationEngine
	NewAttackPathSimulator    = graph.NewAttackPathSimulator
	BlastRadius               = graph.BlastRadius
	CascadingBlastRadius      = graph.CascadingBlastRadius
	ReverseAccess             = graph.ReverseAccess
)
