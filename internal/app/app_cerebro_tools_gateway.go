package app

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/policy"
)

type toolGraphEvaluateChangeRequest struct {
	ID                   string               `json:"id"`
	Source               string               `json:"source"`
	Reason               string               `json:"reason"`
	Nodes                []graph.NodeMutation `json:"nodes"`
	Edges                []graph.EdgeMutation `json:"edges"`
	Mutations            []map[string]any     `json:"mutations"`
	ApprovalARRThreshold *float64             `json:"approval_arr_threshold,omitempty"`
}

func (a *App) toolCerebroEvaluatePolicy(ctx context.Context, args json.RawMessage) (string, error) {
	if a == nil || a.Policy == nil {
		return "", fmt.Errorf("policy engine not initialized")
	}

	var req struct {
		policy.EvalRequest
		ProposedChange *toolGraphEvaluateChangeRequest `json:"proposed_change,omitempty"`
		TraceContext   map[string]any                  `json:"trace_context,omitempty"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	req.Action = strings.TrimSpace(req.Action)
	if req.Action == "" {
		return "", fmt.Errorf("action is required")
	}
	if len(req.Resource) == 0 {
		return "", fmt.Errorf("resource is required")
	}

	policyResp, err := a.Policy.Evaluate(ctx, &req.EvalRequest)
	if err != nil {
		return "", err
	}

	decision := strings.ToLower(strings.TrimSpace(policyResp.Decision))
	if decision == "" {
		decision = "allow"
	}
	if decision == "needs_approval" {
		decision = "require_approval"
	}

	matched := append([]string(nil), policyResp.Matched...)
	reasons := append([]string(nil), policyResp.Reasons...)

	var propagationResult *graph.PropagationResult
	if decision != "deny" && req.ProposedChange != nil {
		if a.SecurityGraph == nil {
			return "", fmt.Errorf("graph platform not initialized")
		}

		delta := graph.GraphDelta{
			Nodes: append([]graph.NodeMutation(nil), req.ProposedChange.Nodes...),
			Edges: append([]graph.EdgeMutation(nil), req.ProposedChange.Edges...),
		}
		if len(req.ProposedChange.Mutations) > 0 {
			parsed, parseErr := parseToolGraphMutations(req.ProposedChange.Mutations)
			if parseErr != nil {
				return "", parseErr
			}
			delta.Nodes = append(delta.Nodes, parsed.Nodes...)
			delta.Edges = append(delta.Edges, parsed.Edges...)
		}

		if len(delta.Nodes) > 0 || len(delta.Edges) > 0 {
			options := make([]graph.PropagationOption, 0, 1)
			if req.ProposedChange.ApprovalARRThreshold != nil {
				options = append(options, graph.WithApprovalARRThreshold(*req.ProposedChange.ApprovalARRThreshold))
			}

			engine := graph.NewPropagationEngine(a.SecurityGraph, options...)
			propagationResult, err = engine.Evaluate(&graph.ChangeProposal{
				ID:     strings.TrimSpace(req.ProposedChange.ID),
				Source: strings.TrimSpace(req.ProposedChange.Source),
				Reason: strings.TrimSpace(req.ProposedChange.Reason),
				Delta:  delta,
			})
			if err != nil {
				return "", err
			}

			switch propagationResult.Decision {
			case graph.DecisionBlocked:
				decision = "deny"
				reasons = append(reasons, propagationResult.BlockReasons...)
			case graph.DecisionNeedsApproval:
				decision = "require_approval"
				reasons = append(reasons, propagationResult.ApprovalReasons...)
			}
		}
	}

	now := time.Now().UTC()
	response := map[string]any{
		"request_id":         fmt.Sprintf("check:%d", now.UnixNano()),
		"decision":           decision,
		"requires_approval":  decision == "require_approval",
		"matched":            matched,
		"matched_policies":   matched,
		"reasons":            toolDedupeAndSortStrings(reasons),
		"remediation_steps":  toolPolicyEvaluationRemediationSteps(decision, matched, reasons, propagationResult),
		"policy_evaluation":  policyResp,
		"evaluated_at":       now,
		"trace_context_echo": cloneToolJSONMap(req.TraceContext),
	}
	if propagationResult != nil {
		response["propagation"] = propagationResult
	}

	return marshalToolResponse(response)
}

func toolPolicyEvaluationRemediationSteps(decision string, matched []string, reasons []string, propagation *graph.PropagationResult) []string {
	steps := make([]string, 0, 6)
	if decision == "deny" {
		if len(matched) > 0 {
			steps = append(steps, "Review matched policy requirements and update action context before retrying")
		}
		steps = append(steps, "Apply least-privilege scope or required controls, then re-run evaluation")
	}
	if decision == "require_approval" {
		steps = append(steps, "Submit this action for manual approval with business justification")
		steps = append(steps, "Attach impact analysis and mitigation plan to the approval request")
	}
	if propagation != nil {
		if propagation.AffectedARR > 0 {
			steps = append(steps, fmt.Sprintf("Validate customer impact (affected ARR %.0f) and stage rollout safely", propagation.AffectedARR))
		}
		if len(propagation.SLARisk) > 0 {
			steps = append(steps, "Coordinate with service owners for SLA-risked systems before execution")
		}
		if propagation.AttackPathsCreated > 0 || propagation.ToxicCombosIntroduced > 0 {
			steps = append(steps, "Adjust proposed change to avoid introducing new attack paths or toxic combinations")
		}
	}
	if len(steps) == 0 && len(reasons) > 0 {
		steps = append(steps, "Address listed evaluation reasons and re-submit for policy check")
	}
	if len(steps) == 0 {
		steps = append(steps, "No remediation required")
	}
	return toolDedupeAndSortStrings(steps)
}

func toolDedupeAndSortStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
