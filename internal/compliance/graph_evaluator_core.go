package compliance

import (
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	entities "github.com/writer/cerebro/internal/graph/entities"
)

type graphComplianceEvaluator struct {
	graph                *graph.Graph
	validAt              time.Time
	recordedAt           time.Time
	generatedAt          time.Time
	openFindingsByPolicy map[string]int
	entityCache          map[string][]entities.EntityRecord
}

type policyEvaluation struct {
	PolicyID      string
	Supported     bool
	Source        string
	Status        string
	Applicable    int
	Passing       int
	Failing       int
	Evidence      []ControlEvidence
	FailEntityIDs map[string]struct{}
	PassEntityIDs map[string]struct{}
}

func (e *graphComplianceEvaluator) evaluateControl(ctrl Control) ControlStatus {
	policyResults := make([]policyEvaluation, 0, len(ctrl.PolicyIDs))
	hasGraph := false
	hasFallback := false

	for _, policyID := range ctrl.PolicyIDs {
		result := e.evaluatePolicy(policyID)
		if !result.Supported {
			result = e.fallbackPolicy(policyID)
		}
		if result.Source == ControlEvaluationSourceGraph {
			hasGraph = true
		}
		if result.Source == ControlEvaluationSourceFindingsFallback {
			hasFallback = true
		}
		policyResults = append(policyResults, result)
	}

	status := ControlStatus{
		ControlID:     ctrl.ID,
		Title:         ctrl.Title,
		Description:   ctrl.Description,
		Severity:      ctrl.Severity,
		Status:        ControlStateUnknown,
		LastEvaluated: e.generatedAt.Format(time.RFC3339),
		PolicyIDs:     append([]string(nil), ctrl.PolicyIDs...),
	}

	failIDs := make(map[string]struct{})
	passIDs := make(map[string]struct{})
	notApplicablePolicies := 0
	evidence := make([]ControlEvidence, 0)
	anyFail := false
	anyPass := false
	anyPartial := false

	for _, result := range policyResults {
		for id := range result.FailEntityIDs {
			failIDs[id] = struct{}{}
		}
		for id := range result.PassEntityIDs {
			passIDs[id] = struct{}{}
		}
		evidence = append(evidence, result.Evidence...)
		switch result.Status {
		case ControlStateFailing:
			anyFail = true
		case ControlStatePassing:
			anyPass = true
		case ControlStatePartial, ControlStateUnknown:
			anyPartial = true
		case ControlStateNotApplicable:
			notApplicablePolicies++
		}
	}

	if anyFail {
		status.Status = ControlStateFailing
	} else if anyPartial {
		status.Status = ControlStatePartial
	} else if anyPass {
		status.Status = ControlStatePassing
	} else if len(policyResults) > 0 && notApplicablePolicies == len(policyResults) {
		status.Status = ControlStateNotApplicable
	}

	// Asset counts are only meaningful when the evaluator identified concrete
	// graph entities. Findings-fallback controls derive control state from
	// finding presence alone and intentionally do not invent evaluated-asset
	// counts that the graph cannot substantiate.
	status.FailCount = len(failIDs)
	status.PassCount = len(passIDs)
	status.TotalAssets = len(unionStringSets(failIDs, passIDs))
	if hasGraph && hasFallback {
		status.EvaluationSource = ControlEvaluationSourceHybrid
	} else if hasGraph {
		status.EvaluationSource = ControlEvaluationSourceGraph
	} else {
		status.EvaluationSource = ControlEvaluationSourceFindingsFallback
	}
	status.Evidence = limitControlEvidence(evidence)
	return status
}

func (e *graphComplianceEvaluator) evaluatePolicy(policyID string) policyEvaluation {
	policyID = strings.TrimSpace(policyID)
	evaluator, ok := lookupPolicyEvaluator(policyID)
	if !ok {
		return policyEvaluation{PolicyID: policyID}
	}
	return evaluator.evaluate(e, policyID)
}

func (e *graphComplianceEvaluator) fallbackPolicy(policyID string) policyEvaluation {
	count := e.openFindingsByPolicy[strings.TrimSpace(policyID)]
	result := policyEvaluation{
		PolicyID:      policyID,
		Supported:     true,
		Source:        ControlEvaluationSourceFindingsFallback,
		FailEntityIDs: make(map[string]struct{}),
		PassEntityIDs: make(map[string]struct{}),
	}
	if count > 0 {
		result.Status = ControlStateFailing
		result.Failing = count
		result.Evidence = []ControlEvidence{{
			PolicyID: policyID,
			Status:   ControlStateFailing,
			Reason:   fmt.Sprintf("%d open findings mapped to policy %s", count, policyID),
		}}
		return result
	}
	result.Status = ControlStatePassing
	result.Evidence = []ControlEvidence{{
		PolicyID: policyID,
		Status:   ControlStatePassing,
		Reason:   fmt.Sprintf("No open findings mapped to policy %s", policyID),
	}}
	return result
}
