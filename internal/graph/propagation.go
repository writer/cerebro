package graph

import (
	"fmt"
	"sort"
)

// ChangeProposal describes a proposed graph mutation and why it is being made.
type ChangeProposal struct {
	ID     string     `json:"id"`
	Source string     `json:"source"`
	Delta  GraphDelta `json:"delta"`
	Reason string     `json:"reason"`
}

// PropagationDecision is the outcome of propagation evaluation.
type PropagationDecision string

const (
	DecisionSafe          PropagationDecision = "safe"
	DecisionNeedsApproval PropagationDecision = "needs_approval"
	DecisionBlocked       PropagationDecision = "blocked"
)

// SLAImpact summarizes customer-facing service/SLA risk.
type SLAImpact struct {
	Service     string `json:"service"`
	RiskLevel   string `json:"risk_level"`
	Description string `json:"description"`
}

// PropagationResult summarizes projected downstream impact for a proposal.
type PropagationResult struct {
	Proposal   *ChangeProposal        `json:"proposal"`
	Simulation *GraphSimulationResult `json:"simulation"`
	Decision   PropagationDecision    `json:"decision"`

	BlockReasons    []string `json:"block_reasons,omitempty"`
	ApprovalReasons []string `json:"approval_reasons,omitempty"`

	AffectedCustomers []*Node     `json:"affected_customers,omitempty"`
	AffectedARR       float64     `json:"affected_arr"`
	SLARisk           []SLAImpact `json:"sla_risk,omitempty"`

	ToxicCombosResolved   int     `json:"toxic_combos_resolved"`
	ToxicCombosIntroduced int     `json:"toxic_combos_introduced"`
	AttackPathsBlocked    int     `json:"attack_paths_blocked"`
	AttackPathsCreated    int     `json:"attack_paths_created"`
	RiskScoreDelta        float64 `json:"risk_score_delta"`

	FrameworksAffected []string `json:"frameworks_affected,omitempty"`
	ControlsImpacted   []string `json:"controls_impacted,omitempty"`
}

// PropagationEngine evaluates proposed graph changes before they are applied.
type PropagationEngine struct {
	graph                *Graph
	approvalARRThreshold float64
}

type PropagationOption func(*PropagationEngine)

// WithApprovalARRThreshold customizes ARR threshold for manual approvals.
func WithApprovalARRThreshold(threshold float64) PropagationOption {
	return func(engine *PropagationEngine) {
		if threshold > 0 {
			engine.approvalARRThreshold = threshold
		}
	}
}

// NewPropagationEngine creates a new propagation engine.
func NewPropagationEngine(g *Graph, options ...PropagationOption) *PropagationEngine {
	engine := &PropagationEngine{
		graph:                g,
		approvalARRThreshold: 1_000_000,
	}
	for _, option := range options {
		if option != nil {
			option(engine)
		}
	}
	return engine
}

// Evaluate simulates a proposal and returns downstream impact + decision.
func (e *PropagationEngine) Evaluate(proposal *ChangeProposal) (*PropagationResult, error) {
	if e == nil || e.graph == nil {
		return nil, fmt.Errorf("propagation engine requires graph")
	}
	if proposal == nil {
		return nil, fmt.Errorf("proposal is required")
	}

	simulation, err := e.graph.Simulate(proposal.Delta)
	if err != nil {
		return nil, err
	}

	result := &PropagationResult{
		Proposal:              proposal,
		Simulation:            simulation,
		AffectedCustomers:     simulation.After.AffectedCustomers,
		AffectedARR:           simulation.After.AffectedARR,
		ToxicCombosResolved:   len(simulation.Delta.ToxicCombosRemoved),
		ToxicCombosIntroduced: len(simulation.Delta.ToxicCombosAdded),
		AttackPathsBlocked:    len(simulation.Delta.AttackPathsBlocked),
		AttackPathsCreated:    len(simulation.Delta.AttackPathsCreated),
		RiskScoreDelta:        simulation.Delta.RiskScoreDelta,
		FrameworksAffected:    collectAffectedFrameworks(simulation.Delta),
		ControlsImpacted:      collectImpactedControls(simulation.Delta),
		SLARisk:               buildSLAImpact(simulation),
		BlockReasons:          []string{},
		ApprovalReasons:       []string{},
	}
	e.deriveDecision(result)
	return result, nil
}

func (e *PropagationEngine) deriveDecision(result *PropagationResult) {
	if result == nil || result.Simulation == nil {
		return
	}

	for _, combo := range result.Simulation.Delta.ToxicCombosAdded {
		if combo == nil {
			continue
		}
		if combo.Severity == SeverityCritical {
			result.Decision = DecisionBlocked
			result.BlockReasons = append(result.BlockReasons,
				fmt.Sprintf("Introduces critical toxic combination: %s", combo.Name))
		}
	}

	if result.Decision != DecisionBlocked && result.AffectedARR > e.approvalARRThreshold {
		result.Decision = DecisionNeedsApproval
		result.ApprovalReasons = append(result.ApprovalReasons,
			fmt.Sprintf("Affects customers with ARR %.0f above threshold %.0f", result.AffectedARR, e.approvalARRThreshold))
	}

	if result.Decision != DecisionBlocked &&
		result.RiskScoreDelta < 0 &&
		result.ToxicCombosIntroduced == 0 &&
		result.AttackPathsCreated == 0 {
		result.Decision = DecisionSafe
	}

	if result.Decision == "" {
		if result.RiskScoreDelta > 0 || result.ToxicCombosIntroduced > 0 || result.AttackPathsCreated > 0 {
			result.Decision = DecisionNeedsApproval
			if result.RiskScoreDelta > 0 {
				result.ApprovalReasons = append(result.ApprovalReasons,
					fmt.Sprintf("Increases risk score by %.2f", result.RiskScoreDelta))
			}
		} else {
			result.Decision = DecisionSafe
		}
	}

	sort.Strings(result.BlockReasons)
	sort.Strings(result.ApprovalReasons)
}

func collectImpactedControls(diff GraphSimulationDiff) []string {
	controls := map[string]struct{}{}
	for _, combo := range diff.ToxicCombosAdded {
		if combo == nil {
			continue
		}
		if combo.ID != "" {
			controls[combo.ID] = struct{}{}
		}
		for _, tag := range combo.Tags {
			if tag == "" {
				continue
			}
			controls[tag] = struct{}{}
		}
	}
	for _, combo := range diff.ToxicCombosRemoved {
		if combo == nil {
			continue
		}
		if combo.ID != "" {
			controls[combo.ID] = struct{}{}
		}
	}

	list := make([]string, 0, len(controls))
	for control := range controls {
		list = append(list, control)
	}
	sort.Strings(list)
	return list
}

func collectAffectedFrameworks(diff GraphSimulationDiff) []string {
	frameworks := map[string]struct{}{}
	if len(diff.ToxicCombosAdded) > 0 || len(diff.ToxicCombosRemoved) > 0 {
		frameworks["SOC2"] = struct{}{}
		frameworks["ISO27001"] = struct{}{}
	}
	if len(diff.AttackPathsCreated) > 0 || len(diff.AttackPathsBlocked) > 0 {
		frameworks["NIST-CSF"] = struct{}{}
	}

	list := make([]string, 0, len(frameworks))
	for framework := range frameworks {
		list = append(list, framework)
	}
	sort.Strings(list)
	return list
}

func buildSLAImpact(simulation *GraphSimulationResult) []SLAImpact {
	if simulation == nil || len(simulation.After.AffectedCustomers) == 0 {
		return nil
	}

	riskLevel := "medium"
	if simulation.Delta.RiskScoreDelta > 0 {
		riskLevel = "high"
	}
	return []SLAImpact{{
		Service:     "customer-impact",
		RiskLevel:   riskLevel,
		Description: fmt.Sprintf("%d customers potentially impacted", len(simulation.After.AffectedCustomers)),
	}}
}
