package riskplan

import (
	"time"

	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

const (
	// ModelVersion identifies the planner contract and scoring model.
	ModelVersion = "risk-action-plan-v2"

	// DefaultCandidateLimit is the report and MCP default for ranked actions.
	DefaultCandidateLimit = 10

	// MaxCandidateLimit caps action-plan output for agent-facing surfaces.
	MaxCandidateLimit = 25

	// MaxSimulationSeedLimit caps simulation work before final ranking.
	MaxSimulationSeedLimit = 50

	ActionTypeAssignOwner          = "assign_owner"
	ActionTypeRefreshEvidence      = "refresh_evidence"
	SimulationStatusSimulated      = "simulated"
	SimulationStatusUnsupported    = "unsupported"
	SimulationStatusNoExpectedRisk = "no_expected_reduction"
)

// Options controls deterministic risk action planning over already-scoped findings.
type Options struct {
	TenantID           string
	RuntimeIDs         []string
	CandidateLimit     int
	SeedLimit          int
	GraphNeighborhoods map[string]*ports.EntityNeighborhood
	Now                time.Time
	PreviousCandidates []Candidate
	IncludeUnscored    bool
	Generators         []CandidateGenerator
	RiskScoringConfig  *ports.RiskScoringConfig
}

// Plan is the typed risk-action-plan contract shared by reports and MCP tools.
type Plan struct {
	TenantID                string      `json:"tenant_id"`
	RuntimeIDs              []string    `json:"runtime_ids,omitempty"`
	GeneratedAt             string      `json:"generated_at,omitempty"`
	ModelVersion            string      `json:"model_version"`
	TotalFindings           int         `json:"total_findings"`
	CandidateSeedCount      int         `json:"candidate_seed_count"`
	TotalCandidates         int         `json:"total_candidates"`
	SimulatedCandidateCount int         `json:"simulated_candidate_count"`
	UnscoredCandidateCount  int         `json:"unscored_candidate_count"`
	ActionCandidates        []Candidate `json:"action_candidates"`
	Diff                    *PlanDiff   `json:"plan_diff,omitempty"`
}

// CandidateGenerator is a pluggable source of candidate remediation seeds.
type CandidateGenerator interface {
	ID() string
	Generate(CandidateGeneratorInput) []CandidateSeed
}

// CandidateGeneratorInput is the per-finding context passed to generators.
type CandidateGeneratorInput struct {
	TenantID    string
	Finding     *ports.FindingRecord
	RiskContext findinganalysis.FindingRiskContext
	Now         time.Time
}

// CandidateSeed is the minimal typed proposal produced by a generator.
type CandidateSeed struct {
	ID                  string
	Title               string
	ActionType          string
	ScenarioType        string
	TargetURN           string
	SimulationSupported bool
	Reasons             []string
}

// Candidate is one ranked next-best action. Embedded contracts keep the JSON
// shape flat while keeping the Go type cohesive.
type Candidate struct {
	CandidateIdentity
	CandidateScoring
	CandidateReferences
	CandidateExecution
	RiskDelta findinganalysis.RiskDeltaSimulationReport `json:"risk_delta"`
}

// CandidateIdentity identifies the action target and simulation mode.
type CandidateIdentity struct {
	ID               string `json:"id"`
	Title            string `json:"title"`
	ActionType       string `json:"action_type"`
	ScenarioType     string `json:"scenario_type,omitempty"`
	TargetURN        string `json:"target_urn"`
	Owner            string `json:"owner,omitempty"`
	RiskLevel        string `json:"risk_level,omitempty"`
	SimulationStatus string `json:"simulation_status"`
}

// CandidateScoring contains all ranking and expected-reduction fields.
type CandidateScoring struct {
	PriorityScore                    int               `json:"priority_score"`
	ScoreBreakdown                   ScoreBreakdown    `json:"score_breakdown"`
	ConfidenceScore                  int               `json:"confidence_score,omitempty"`
	ExpectedRiskScoreReduction       int               `json:"expected_risk_score_reduction"`
	ExpectedAttackPathScoreReduction int               `json:"expected_attack_path_score_reduction"`
	ExpectedAttackPathCountReduction int               `json:"expected_attack_path_count_reduction"`
	ExpectedReduction                ExpectedReduction `json:"expected_reduction"`
	BeforeRiskScore                  int               `json:"before_risk_score"`
	AfterRiskScore                   int               `json:"after_risk_score"`
}

// CandidateReferences links a candidate to the findings and evidence that produced it.
type CandidateReferences struct {
	FindingIDs   []string            `json:"finding_ids,omitempty"`
	RuleIDs      []string            `json:"rule_ids,omitempty"`
	RuntimeIDs   []string            `json:"runtime_ids,omitempty"`
	ResourceURNs []string            `json:"resource_urns,omitempty"`
	ControlRefs  []string            `json:"control_refs,omitempty"`
	RiskFactors  []RiskFactorSummary `json:"risk_factors,omitempty"`
	Reasons      []string            `json:"reasons,omitempty"`
}

// CandidateExecution describes operational readiness and learned outcomes.
type CandidateExecution struct {
	Effort          Effort             `json:"effort"`
	Ownership       Ownership          `json:"ownership"`
	Evidence        EvidenceConfidence `json:"evidence"`
	OutcomeLearning OutcomeLearning    `json:"outcome_learning"`
}

// ExpectedReduction groups all expected impact fields for newer consumers.
type ExpectedReduction struct {
	RiskScore       int `json:"risk_score"`
	AttackPathScore int `json:"attack_path_score"`
	AttackPathCount int `json:"attack_path_count"`
}

// ScoreBreakdown makes priority scoring auditable.
type ScoreBreakdown struct {
	RiskReductionPoints            int `json:"risk_reduction_points"`
	AttackPathScoreReductionPoints int `json:"attack_path_score_reduction_points"`
	AttackPathCountReductionPoints int `json:"attack_path_count_reduction_points"`
	RiskContextPoints              int `json:"risk_context_points"`
	FindingCoveragePoints          int `json:"finding_coverage_points"`
	ConfidencePoints               int `json:"confidence_points"`
	OutcomePriorPoints             int `json:"outcome_prior_points"`
	EffortCostPoints               int `json:"effort_cost_points"`
	OwnershipPenaltyPoints         int `json:"ownership_penalty_points"`
	SimulationPenaltyPoints        int `json:"simulation_penalty_points"`
	Total                          int `json:"total"`
}

// Effort estimates the operational cost and reversibility of a candidate.
type Effort struct {
	Level             string `json:"level"`
	Estimate          string `json:"estimate"`
	CostPoints        int    `json:"cost_points"`
	ApprovalRequired  bool   `json:"approval_required"`
	ApprovalReason    string `json:"approval_reason,omitempty"`
	Reversible        bool   `json:"reversible"`
	PrimaryConstraint string `json:"primary_constraint,omitempty"`
}

// Ownership captures likely ownership and whether routing is blocked.
type Ownership struct {
	Owner      string   `json:"owner,omitempty"`
	Source     string   `json:"source,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
	Missing    bool     `json:"missing"`
}

// EvidenceConfidence summarizes data quality behind a candidate.
type EvidenceConfidence struct {
	ConfidenceScore int    `json:"confidence_score"`
	Status          string `json:"status"`
	Freshness       string `json:"freshness,omitempty"`
	LastObservedAt  string `json:"last_observed_at,omitempty"`
	EvidenceRefs    int    `json:"evidence_refs"`
}

// OutcomeLearning records prior action/outcome signals connected to the target.
type OutcomeLearning struct {
	Status               string `json:"status"`
	PriorActionCount     int    `json:"prior_action_count"`
	PositiveOutcomeCount int    `json:"positive_outcome_count"`
	NegativeOutcomeCount int    `json:"negative_outcome_count"`
	PriorityAdjustment   int    `json:"priority_adjustment"`
}

// RiskFactorSummary is the aggregate risk-factor explanation for a candidate.
type RiskFactorSummary struct {
	FactorID             string   `json:"factor_id"`
	Category             string   `json:"category,omitempty"`
	SeverityContribution string   `json:"severity_contribution,omitempty"`
	Count                int      `json:"count"`
	WeightTotal          int      `json:"weight_total"`
	EvidenceRefs         []string `json:"evidence_refs,omitempty"`
}

// PlanDiff describes how a candidate set changed relative to a previous run.
type PlanDiff struct {
	Added          []CandidateDiff `json:"added,omitempty"`
	Removed        []CandidateDiff `json:"removed,omitempty"`
	Changed        []CandidateDiff `json:"changed,omitempty"`
	UnchangedCount int             `json:"unchanged_count"`
}

// CandidateDiff is one added, removed, or materially changed candidate.
type CandidateDiff struct {
	ID                                       string `json:"id"`
	Title                                    string `json:"title,omitempty"`
	ChangeType                               string `json:"change_type"`
	PreviousPriorityScore                    int    `json:"previous_priority_score,omitempty"`
	CurrentPriorityScore                     int    `json:"current_priority_score,omitempty"`
	PriorityScoreDelta                       int    `json:"priority_score_delta,omitempty"`
	PreviousExpectedRiskScoreReduction       int    `json:"previous_expected_risk_score_reduction,omitempty"`
	CurrentExpectedRiskScoreReduction        int    `json:"current_expected_risk_score_reduction,omitempty"`
	ExpectedRiskScoreReductionDelta          int    `json:"expected_risk_score_reduction_delta,omitempty"`
	PreviousExpectedAttackPathCountReduction int    `json:"previous_expected_attack_path_count_reduction,omitempty"`
	CurrentExpectedAttackPathCountReduction  int    `json:"current_expected_attack_path_count_reduction,omitempty"`
}
