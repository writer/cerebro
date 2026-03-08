package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/evalops/cerebro/internal/agents"
	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/graph"
)

func (a *App) cerebroTools() []agents.Tool {
	requiresSimApproval := true
	requiresAccessReviewApproval := true
	if a != nil && a.Config != nil {
		requiresSimApproval = a.Config.CerebroSimulateNeedsApproval
		requiresAccessReviewApproval = a.Config.CerebroAccessReviewNeedsApproval
	}

	return []agents.Tool{
		{
			Name:             "simulate",
			Description:      "Run high-level scenario simulations (customer_churn, access_removal, team_change, service_disruption, vendor_exit, role_change)",
			RequiresApproval: requiresSimApproval,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"scenario": map[string]any{
						"type": "string",
						"enum": []string{"customer_churn", "access_removal", "team_change", "service_disruption", "vendor_exit", "role_change"},
					},
					"target": map[string]any{
						"type":        "string",
						"description": "Primary node identifier to simulate against",
					},
					"parameters": map[string]any{
						"type":        "object",
						"description": "Scenario-specific parameters (for example to_team, from_team, new_role)",
					},
					"requester": map[string]any{"type": "string"},
					"context":   map[string]any{"type": "string"},
				},
				"required": []string{"scenario", "target"},
			},
			Handler: a.toolCerebroScenarioSimulate,
		},
		{
			Name:             "cerebro.simulate",
			Description:      "Run a hypothetical graph simulation for proposed node/edge mutations",
			RequiresApproval: requiresSimApproval,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"nodes": map[string]any{
						"type":        "array",
						"description": "Node mutations in graph.GraphDelta format",
					},
					"edges": map[string]any{
						"type":        "array",
						"description": "Edge mutations in graph.GraphDelta format",
					},
					"mutations": map[string]any{
						"type":        "array",
						"description": "Optional shorthand mutations (add_node/remove_node/modify_node/add_edge/remove_edge)",
					},
				},
			},
			Handler: a.toolCerebroSimulate,
		},
		{
			Name:        "cerebro.blast_radius",
			Description: "Compute blast radius and reachable resources for a principal",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"principal_id": map[string]any{"type": "string"},
					"max_depth":    map[string]any{"type": "integer", "default": 3},
				},
				"required": []string{"principal_id"},
			},
			Handler: a.toolCerebroBlastRadius,
		},
		{
			Name:        "cerebro.risk_score",
			Description: "Return composite risk scoring details for an entity",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"entity_id":       map[string]any{"type": "string"},
					"include_overall": map[string]any{"type": "boolean", "default": false},
				},
				"required": []string{"entity_id"},
			},
			Handler: a.toolCerebroRiskScore,
		},
		{
			Name:        "cerebro.graph_query",
			Description: "Run graph queries for neighbors or shortest paths",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"mode":      map[string]any{"type": "string", "enum": []string{"neighbors", "paths"}, "default": "neighbors"},
					"node_id":   map[string]any{"type": "string"},
					"target_id": map[string]any{"type": "string"},
					"direction": map[string]any{"type": "string", "enum": []string{"out", "in", "both"}, "default": "both"},
					"limit":     map[string]any{"type": "integer", "default": 25},
					"k":         map[string]any{"type": "integer", "default": 3},
					"max_depth": map[string]any{"type": "integer", "default": 6},
				},
				"required": []string{"node_id"},
			},
			Handler: a.toolCerebroGraphQuery,
		},
		{
			Name:        "cerebro.findings",
			Description: "List and search findings with filtering",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"severity":    map[string]any{"type": "string"},
					"status":      map[string]any{"type": "string"},
					"policy_id":   map[string]any{"type": "string"},
					"signal_type": map[string]any{"type": "string"},
					"domain":      map[string]any{"type": "string"},
					"query":       map[string]any{"type": "string"},
					"limit":       map[string]any{"type": "integer", "default": 50},
					"offset":      map[string]any{"type": "integer", "default": 0},
				},
			},
			Handler: a.toolCerebroFindings,
		},
		{
			Name:             "cerebro.access_review",
			Description:      "Generate an access review scoped to one identity",
			RequiresApproval: requiresAccessReviewApproval,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"identity_id": map[string]any{"type": "string"},
					"name":        map[string]any{"type": "string"},
					"description": map[string]any{"type": "string"},
					"created_by":  map[string]any{"type": "string"},
				},
				"required": []string{"identity_id"},
			},
			Handler: a.toolCerebroAccessReview,
		},
	}
}

type cerebroGraphQueryRequest struct {
	Mode      string `json:"mode"`
	NodeID    string `json:"node_id"`
	TargetID  string `json:"target_id"`
	Direction string `json:"direction"`
	Limit     int    `json:"limit"`
	K         int    `json:"k"`
	MaxDepth  int    `json:"max_depth"`
}

func (a *App) toolCerebroSimulate(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		Nodes     []graph.NodeMutation `json:"nodes"`
		Edges     []graph.EdgeMutation `json:"edges"`
		Mutations []map[string]any     `json:"mutations"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	delta := graph.GraphDelta{
		Nodes: append([]graph.NodeMutation(nil), req.Nodes...),
		Edges: append([]graph.EdgeMutation(nil), req.Edges...),
	}
	if len(req.Mutations) > 0 {
		parsed, err := parseToolGraphMutations(req.Mutations)
		if err != nil {
			return "", err
		}
		delta.Nodes = append(delta.Nodes, parsed.Nodes...)
		delta.Edges = append(delta.Edges, parsed.Edges...)
	}
	if len(delta.Nodes) == 0 && len(delta.Edges) == 0 {
		return "", fmt.Errorf("at least one mutation is required")
	}

	result, err := g.Simulate(delta)
	if err != nil {
		return "", err
	}
	return marshalToolResponse(result)
}

func (a *App) toolCerebroScenarioSimulate(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		Scenario   string         `json:"scenario"`
		Target     string         `json:"target"`
		Parameters map[string]any `json:"parameters"`
		Requester  string         `json:"requester"`
		Context    string         `json:"context"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	req.Scenario = strings.ToLower(strings.TrimSpace(req.Scenario))
	req.Target = strings.TrimSpace(req.Target)
	if req.Scenario == "" {
		return "", fmt.Errorf("scenario is required")
	}
	if req.Target == "" {
		return "", fmt.Errorf("target is required")
	}
	if _, ok := g.GetNode(req.Target); !ok {
		return "", fmt.Errorf("target not found: %s", req.Target)
	}

	delta, err := buildScenarioSimulationDelta(g, req.Scenario, req.Target, req.Parameters)
	if err != nil {
		return "", err
	}

	result, err := g.Simulate(delta)
	if err != nil {
		return "", err
	}

	response := map[string]any{
		"scenario": req.Scenario,
		"target":   req.Target,
		"before": map[string]any{
			"risk_score":         result.Before.RiskScore,
			"affected_entities":  simulationAffectedEntityCount(result.Before),
			"affected_customers": len(result.Before.AffectedCustomers),
		},
		"after": map[string]any{
			"risk_score":         result.After.RiskScore,
			"affected_entities":  simulationAffectedEntityCount(result.After),
			"affected_customers": len(result.After.AffectedCustomers),
		},
		"delta": map[string]any{
			"risk_delta":               result.Delta.RiskScoreDelta,
			"new_findings":             simulationNewFindings(result),
			"affected_teams":           simulationAffectedTeams(result, req.Scenario, req.Parameters),
			"estimated_revenue_impact": simulationRevenueImpact(result),
			"attack_paths_created":     len(result.Delta.AttackPathsCreated),
			"attack_paths_blocked":     len(result.Delta.AttackPathsBlocked),
			"toxic_combos_added":       len(result.Delta.ToxicCombosAdded),
			"toxic_combos_removed":     len(result.Delta.ToxicCombosRemoved),
		},
		"recommendation": simulationRecommendation(result),
	}
	if strings.TrimSpace(req.Requester) != "" {
		response["requester"] = strings.TrimSpace(req.Requester)
	}
	if strings.TrimSpace(req.Context) != "" {
		response["context"] = strings.TrimSpace(req.Context)
	}
	if len(req.Parameters) > 0 {
		response["parameters"] = req.Parameters
	}

	return marshalToolResponse(response)
}

func buildScenarioSimulationDelta(g *graph.Graph, scenario string, target string, parameters map[string]any) (graph.GraphDelta, error) {
	switch scenario {
	case "customer_churn", "access_removal", "service_disruption", "vendor_exit":
		return graph.GraphDelta{
			Nodes: []graph.NodeMutation{
				{Action: "remove", ID: target},
			},
		}, nil
	case "team_change":
		toTeam := strings.TrimSpace(stringValue(parameters["to_team"]))
		if toTeam == "" {
			return graph.GraphDelta{}, fmt.Errorf("team_change requires parameters.to_team")
		}
		if _, ok := g.GetNode(toTeam); !ok {
			return graph.GraphDelta{}, fmt.Errorf("to_team not found: %s", toTeam)
		}

		fromTeam := strings.TrimSpace(stringValue(parameters["from_team"]))
		edges := make([]graph.EdgeMutation, 0)
		for _, edge := range g.GetOutEdges(target) {
			if edge == nil || edge.Kind != graph.EdgeKindMemberOf {
				continue
			}
			if fromTeam != "" && edge.Target != fromTeam {
				continue
			}
			edges = append(edges, graph.EdgeMutation{
				Action: "remove",
				Source: target,
				Target: edge.Target,
				Kind:   graph.EdgeKindMemberOf,
			})
		}
		edges = append(edges, graph.EdgeMutation{
			Action: "add",
			Edge: &graph.Edge{
				ID:     fmt.Sprintf("simulate:%s:member_of:%s", target, toTeam),
				Source: target,
				Target: toTeam,
				Kind:   graph.EdgeKindMemberOf,
				Effect: graph.EdgeEffectAllow,
				Risk:   graph.RiskNone,
			},
		})
		return graph.GraphDelta{Edges: edges}, nil
	case "role_change":
		newRole := strings.TrimSpace(stringValue(parameters["new_role"]))
		if newRole == "" {
			return graph.GraphDelta{}, fmt.Errorf("role_change requires parameters.new_role")
		}
		return graph.GraphDelta{
			Nodes: []graph.NodeMutation{
				{
					Action: "modify",
					ID:     target,
					Properties: map[string]any{
						"role": newRole,
					},
				},
			},
		}, nil
	default:
		return graph.GraphDelta{}, fmt.Errorf("unsupported scenario %q", scenario)
	}
}

func simulationAffectedEntityCount(snapshot graph.GraphSimulationSnapshot) int {
	seen := make(map[string]struct{})
	for _, customer := range snapshot.AffectedCustomers {
		if customer == nil || strings.TrimSpace(customer.ID) == "" {
			continue
		}
		seen[customer.ID] = struct{}{}
	}
	for _, path := range snapshot.AttackPaths {
		if path == nil {
			continue
		}
		if path.EntryPoint != nil && strings.TrimSpace(path.EntryPoint.ID) != "" {
			seen[path.EntryPoint.ID] = struct{}{}
		}
		if path.Target != nil && strings.TrimSpace(path.Target.ID) != "" {
			seen[path.Target.ID] = struct{}{}
		}
	}
	return len(seen)
}

func simulationNewFindings(result *graph.GraphSimulationResult) []string {
	if result == nil {
		return nil
	}
	findingsSet := make(map[string]struct{})
	for _, combo := range result.Delta.ToxicCombosAdded {
		if combo == nil {
			continue
		}
		name := strings.TrimSpace(combo.Name)
		if name == "" {
			name = strings.TrimSpace(combo.ID)
		}
		if name == "" {
			continue
		}
		findingsSet[name] = struct{}{}
	}
	out := make([]string, 0, len(findingsSet))
	for finding := range findingsSet {
		out = append(out, finding)
	}
	sort.Strings(out)
	return out
}

func simulationAffectedTeams(result *graph.GraphSimulationResult, scenario string, parameters map[string]any) []string {
	teams := make(map[string]struct{})
	if result != nil {
		for _, customer := range result.After.AffectedCustomers {
			if customer == nil {
				continue
			}
			for _, key := range []string{"team", "department", "owner_team", "team_id"} {
				value := strings.TrimSpace(stringValue(customer.Properties[key]))
				if value == "" {
					continue
				}
				teams[value] = struct{}{}
			}
		}
	}
	if scenario == "team_change" {
		if fromTeam := strings.TrimSpace(stringValue(parameters["from_team"])); fromTeam != "" {
			teams[fromTeam] = struct{}{}
		}
		if toTeam := strings.TrimSpace(stringValue(parameters["to_team"])); toTeam != "" {
			teams[toTeam] = struct{}{}
		}
	}
	out := make([]string, 0, len(teams))
	for team := range teams {
		out = append(out, team)
	}
	sort.Strings(out)
	return out
}

func simulationRevenueImpact(result *graph.GraphSimulationResult) float64 {
	if result == nil {
		return 0
	}
	delta := result.After.AffectedARR - result.Before.AffectedARR
	if delta < 0 {
		return 0
	}
	return delta
}

func simulationRecommendation(result *graph.GraphSimulationResult) string {
	if result == nil {
		return "unknown"
	}
	if result.Delta.RiskScoreDelta >= 0.25 || len(result.Delta.ToxicCombosAdded) > 0 {
		return "needs_approval"
	}
	if result.Delta.RiskScoreDelta >= 0.10 || len(result.Delta.AttackPathsCreated) > 0 {
		return "review_recommended"
	}
	return "safe_to_proceed"
}

func (a *App) toolCerebroBlastRadius(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		PrincipalID string `json:"principal_id"`
		MaxDepth    int    `json:"max_depth"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	req.PrincipalID = strings.TrimSpace(req.PrincipalID)
	if req.PrincipalID == "" {
		return "", fmt.Errorf("principal_id is required")
	}
	req.MaxDepth = clampInt(req.MaxDepth, 3, 1, 10)

	result := graph.BlastRadius(g, req.PrincipalID, req.MaxDepth)
	return marshalToolResponse(result)
}

func (a *App) toolCerebroRiskScore(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		EntityID       string `json:"entity_id"`
		IncludeOverall bool   `json:"include_overall"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	req.EntityID = strings.TrimSpace(req.EntityID)
	if req.EntityID == "" {
		return "", fmt.Errorf("entity_id is required")
	}

	engine := graph.NewRiskEngine(g)
	risk := engine.ScoreEntity(req.EntityID)
	if risk == nil {
		return "", fmt.Errorf("entity not found: %s", req.EntityID)
	}

	response := map[string]any{"entity_risk": risk}
	if req.IncludeOverall {
		report := engine.Analyze()
		response["overall_risk_score"] = report.RiskScore
		response["overall_risk_level"] = report.RiskLevel
	}
	return marshalToolResponse(response)
}

func (a *App) toolCerebroGraphQuery(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req cerebroGraphQueryRequest
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	req.Mode = strings.ToLower(strings.TrimSpace(req.Mode))
	if req.Mode == "" {
		req.Mode = "neighbors"
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	req.TargetID = strings.TrimSpace(req.TargetID)
	if req.NodeID == "" {
		return "", fmt.Errorf("node_id is required")
	}
	if _, ok := g.GetNode(req.NodeID); !ok {
		return "", fmt.Errorf("node not found: %s", req.NodeID)
	}

	switch req.Mode {
	case "neighbors":
		return a.runNeighborsQuery(g, req)
	case "paths", "path":
		return a.runPathsQuery(g, req)
	default:
		return "", fmt.Errorf("unsupported mode: %s", req.Mode)
	}
}

func (a *App) runNeighborsQuery(g *graph.Graph, req cerebroGraphQueryRequest) (string, error) {
	direction := strings.ToLower(strings.TrimSpace(req.Direction))
	if direction == "" {
		direction = "both"
	}
	if direction != "out" && direction != "in" && direction != "both" {
		return "", fmt.Errorf("direction must be one of out, in, both")
	}
	limit := clampInt(req.Limit, 25, 1, 200)

	type neighborResult struct {
		Direction string      `json:"direction"`
		Edge      *graph.Edge `json:"edge"`
		Node      *graph.Node `json:"node,omitempty"`
	}

	results := make([]neighborResult, 0)
	if direction == "out" || direction == "both" {
		for _, edge := range g.GetOutEdges(req.NodeID) {
			targetNode, _ := g.GetNode(edge.Target)
			results = append(results, neighborResult{
				Direction: "out",
				Edge:      edge,
				Node:      targetNode,
			})
		}
	}
	if direction == "in" || direction == "both" {
		for _, edge := range g.GetInEdges(req.NodeID) {
			sourceNode, _ := g.GetNode(edge.Source)
			results = append(results, neighborResult{
				Direction: "in",
				Edge:      edge,
				Node:      sourceNode,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Direction == results[j].Direction {
			if results[i].Edge.Source == results[j].Edge.Source {
				if results[i].Edge.Target == results[j].Edge.Target {
					return string(results[i].Edge.Kind) < string(results[j].Edge.Kind)
				}
				return results[i].Edge.Target < results[j].Edge.Target
			}
			return results[i].Edge.Source < results[j].Edge.Source
		}
		return results[i].Direction < results[j].Direction
	})

	total := len(results)
	if len(results) > limit {
		results = results[:limit]
	}

	return marshalToolResponse(map[string]any{
		"mode":      "neighbors",
		"node_id":   req.NodeID,
		"direction": direction,
		"total":     total,
		"count":     len(results),
		"limit":     limit,
		"truncated": total > len(results),
		"neighbors": results,
	})
}

func (a *App) runPathsQuery(g *graph.Graph, req cerebroGraphQueryRequest) (string, error) {
	if req.TargetID == "" {
		return "", fmt.Errorf("target_id is required for paths mode")
	}
	if _, ok := g.GetNode(req.TargetID); !ok {
		return "", fmt.Errorf("target node not found: %s", req.TargetID)
	}

	k := clampInt(req.K, 3, 1, 10)
	maxDepth := clampInt(req.MaxDepth, 6, 1, 12)

	simulator := graph.NewAttackPathSimulator(g)
	paths := simulator.KShortestPaths(req.NodeID, req.TargetID, k, maxDepth)

	return marshalToolResponse(map[string]any{
		"mode":      "paths",
		"source_id": req.NodeID,
		"target_id": req.TargetID,
		"k":         k,
		"max_depth": maxDepth,
		"count":     len(paths),
		"paths":     paths,
	})
}

func (a *App) toolCerebroFindings(_ context.Context, args json.RawMessage) (string, error) {
	if a == nil || a.Findings == nil {
		return "", fmt.Errorf("findings store not initialized")
	}

	var req struct {
		Severity   string `json:"severity"`
		Status     string `json:"status"`
		PolicyID   string `json:"policy_id"`
		SignalType string `json:"signal_type"`
		Domain     string `json:"domain"`
		Query      string `json:"query"`
		Limit      int    `json:"limit"`
		Offset     int    `json:"offset"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	limit := clampInt(req.Limit, 50, 1, 500)
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}

	baseFilter := findings.FindingFilter{
		Severity:   strings.TrimSpace(req.Severity),
		Status:     strings.TrimSpace(req.Status),
		PolicyID:   strings.TrimSpace(req.PolicyID),
		SignalType: strings.TrimSpace(req.SignalType),
		Domain:     strings.TrimSpace(req.Domain),
	}

	query := strings.ToLower(strings.TrimSpace(req.Query))
	if query == "" {
		pageFilter := baseFilter
		pageFilter.Limit = limit
		pageFilter.Offset = offset
		list := a.Findings.List(pageFilter)
		total := a.Findings.Count(baseFilter)
		return marshalToolResponse(map[string]any{
			"total":    total,
			"count":    len(list),
			"limit":    limit,
			"offset":   offset,
			"findings": list,
			"stats":    a.Findings.Stats(),
		})
	}

	all := a.Findings.List(baseFilter)
	matched := make([]*findings.Finding, 0, len(all))
	for _, finding := range all {
		if findingMatchesQuery(finding, query) {
			matched = append(matched, finding)
		}
	}
	total := len(matched)
	if offset >= total {
		return marshalToolResponse(map[string]any{
			"total":    total,
			"count":    0,
			"limit":    limit,
			"offset":   offset,
			"query":    query,
			"findings": []any{},
			"stats":    a.Findings.Stats(),
		})
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := matched[offset:end]

	return marshalToolResponse(map[string]any{
		"total":    total,
		"count":    len(page),
		"limit":    limit,
		"offset":   offset,
		"query":    query,
		"findings": page,
		"stats":    a.Findings.Stats(),
	})
}

func (a *App) toolCerebroAccessReview(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		IdentityID  string `json:"identity_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		CreatedBy   string `json:"created_by"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	req.IdentityID = strings.TrimSpace(req.IdentityID)
	if req.IdentityID == "" {
		return "", fmt.Errorf("identity_id is required")
	}
	if _, ok := g.GetNode(req.IdentityID); !ok {
		return "", fmt.Errorf("identity not found: %s", req.IdentityID)
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Identity access review: " + req.IdentityID
	}
	createdBy := strings.TrimSpace(req.CreatedBy)
	if createdBy == "" {
		createdBy = "ensemble"
	}

	review := graph.CreateAccessReview(g, name, graph.ReviewScope{
		Type:       graph.ScopeTypePrincipal,
		Principals: []string{req.IdentityID},
	}, createdBy)
	review.Description = strings.TrimSpace(req.Description)
	return marshalToolResponse(review)
}

func findingMatchesQuery(f *findings.Finding, query string) bool {
	if f == nil || query == "" {
		return false
	}
	if strings.Contains(strings.ToLower(f.ID), query) {
		return true
	}
	if strings.Contains(strings.ToLower(f.Title), query) {
		return true
	}
	if strings.Contains(strings.ToLower(f.Description), query) {
		return true
	}
	if strings.Contains(strings.ToLower(f.PolicyID), query) {
		return true
	}
	if strings.Contains(strings.ToLower(f.PolicyName), query) {
		return true
	}
	if strings.Contains(strings.ToLower(f.ResourceID), query) {
		return true
	}
	if strings.Contains(strings.ToLower(f.ResourceName), query) {
		return true
	}
	return false
}

func parseToolGraphMutations(raw []map[string]any) (graph.GraphDelta, error) {
	delta := graph.GraphDelta{}
	for idx, mutation := range raw {
		mutationType := strings.ToLower(strings.TrimSpace(stringValue(mutation["type"])))
		mutationType = strings.ReplaceAll(mutationType, "-", "_")

		switch mutationType {
		case "add_node":
			node, err := decodeToolMutationNode(mutation["node"])
			if err != nil {
				return graph.GraphDelta{}, fmt.Errorf("mutation %d: %w", idx, err)
			}
			delta.Nodes = append(delta.Nodes, graph.NodeMutation{Action: "add", Node: node})
		case "remove_node":
			nodeID := strings.TrimSpace(stringValue(mutation["id"]))
			delta.Nodes = append(delta.Nodes, graph.NodeMutation{Action: "remove", ID: nodeID})
		case "modify_node":
			nodeID := strings.TrimSpace(stringValue(mutation["id"]))
			properties, ok := mutation["properties"].(map[string]any)
			if !ok {
				return graph.GraphDelta{}, fmt.Errorf("mutation %d: modify_node requires properties object", idx)
			}
			delta.Nodes = append(delta.Nodes, graph.NodeMutation{Action: "modify", ID: nodeID, Properties: properties})
		case "add_edge":
			edge, err := decodeToolMutationEdge(mutation)
			if err != nil {
				return graph.GraphDelta{}, fmt.Errorf("mutation %d: %w", idx, err)
			}
			delta.Edges = append(delta.Edges, graph.EdgeMutation{Action: "add", Edge: edge})
		case "remove_edge":
			edge, err := decodeToolMutationEdge(mutation)
			if err != nil {
				return graph.GraphDelta{}, fmt.Errorf("mutation %d: %w", idx, err)
			}
			delta.Edges = append(delta.Edges, graph.EdgeMutation{Action: "remove", Source: edge.Source, Target: edge.Target, Kind: edge.Kind})
		default:
			return graph.GraphDelta{}, fmt.Errorf("mutation %d: unsupported type %q", idx, mutationType)
		}
	}
	return delta, nil
}

func decodeToolMutationNode(raw any) (*graph.Node, error) {
	if raw == nil {
		return nil, fmt.Errorf("add_node requires node object")
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("encode node payload: %w", err)
	}
	var node graph.Node
	if err := json.Unmarshal(encoded, &node); err != nil {
		return nil, fmt.Errorf("decode node payload: %w", err)
	}
	return &node, nil
}

func decodeToolMutationEdge(raw map[string]any) (*graph.Edge, error) {
	if nested, ok := raw["edge"]; ok && nested != nil {
		encoded, err := json.Marshal(nested)
		if err != nil {
			return nil, fmt.Errorf("encode edge payload: %w", err)
		}
		var edge graph.Edge
		if err := json.Unmarshal(encoded, &edge); err != nil {
			return nil, fmt.Errorf("decode edge payload: %w", err)
		}
		return &edge, nil
	}

	edge := &graph.Edge{
		Source: strings.TrimSpace(stringValue(raw["source"])),
		Target: strings.TrimSpace(stringValue(raw["target"])),
		Kind:   graph.EdgeKind(strings.TrimSpace(stringValue(raw["kind"]))),
	}
	if edge.Source == "" || edge.Target == "" || strings.TrimSpace(string(edge.Kind)) == "" {
		return nil, fmt.Errorf("edge mutation requires source, target, and kind")
	}
	return edge, nil
}

func decodeToolArgs(args json.RawMessage, out any) error {
	trimmed := bytes.TrimSpace(args)
	if len(trimmed) == 0 {
		return nil
	}
	if err := json.Unmarshal(trimmed, out); err != nil {
		return fmt.Errorf("invalid tool arguments: %w", err)
	}
	return nil
}

func marshalToolResponse(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode tool response: %w", err)
	}
	return string(encoded), nil
}

func (a *App) requireSecurityGraph() (*graph.Graph, error) {
	if a == nil || a.SecurityGraph == nil {
		return nil, fmt.Errorf("security graph not initialized")
	}
	return a.SecurityGraph, nil
}

func clampInt(value, defaultValue, minValue, maxValue int) int {
	if value == 0 {
		value = defaultValue
	}
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	case json.Number:
		return typed.String()
	case int:
		return strconv.Itoa(typed)
	default:
		if value == nil {
			return ""
		}
		return fmt.Sprintf("%v", value)
	}
}
