package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
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
			Name:        "insight_card",
			Description: "Build a context-rich entity insight card for Slack/Ensemble responses",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"entity": map[string]any{
						"type":        "string",
						"description": "Entity node ID (for example customer:acme-corp, person:alice@example.com)",
					},
					"sections": map[string]any{
						"type":        "array",
						"description": "Optional sections to include: risk, relationships, activity, recommendations",
						"items": map[string]any{
							"type": "string",
							"enum": []string{"risk", "relationships", "activity", "recommendations"},
						},
					},
				},
				"required": []string{"entity"},
			},
			Handler: a.toolCerebroInsightCard,
		},
		{
			Name:        "cerebro.intelligence_report",
			Description: "Build a decision-grade intelligence report with prioritized insights and evidence",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"entity_id": map[string]any{
						"type":        "string",
						"description": "Optional entity focus for entity-centric scoring and recommendations",
					},
					"window_days": map[string]any{
						"type":        "integer",
						"description": "Outcome feedback window in days (1-3650)",
						"default":     90,
					},
					"history_limit": map[string]any{
						"type":        "integer",
						"description": "Schema history entries to include (1-200)",
						"default":     20,
					},
					"include_counterfactual": map[string]any{
						"type":        "boolean",
						"description": "Include precomputed what-if simulations in returned insights",
						"default":     true,
					},
					"max_insights": map[string]any{
						"type":        "integer",
						"description": "Maximum number of prioritized insights to return (1-20)",
						"default":     8,
					},
				},
			},
			Handler: a.toolCerebroIntelligenceReport,
		},
		{
			Name:        "cerebro.graph_quality_report",
			Description: "Build graph quality KPIs and prioritized recommendations for ontology, identity, temporal, and write-back health",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"history_limit": map[string]any{
						"type":        "integer",
						"description": "Schema history entries to include (1-200)",
						"default":     20,
					},
					"since_version": map[string]any{
						"type":        "integer",
						"description": "Optional schema drift baseline version",
					},
					"stale_after_hours": map[string]any{
						"type":        "integer",
						"description": "Freshness threshold in hours (1-8760)",
						"default":     720,
					},
				},
			},
			Handler: a.toolCerebroGraphQualityReport,
		},
		{
			Name:        "cerebro.graph_leverage_report",
			Description: "Build a deep graph leverage report across identity, ingestion, temporal, closed-loop, predictive, query, and actuation readiness",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"history_limit": map[string]any{
						"type":        "integer",
						"description": "Schema history entries to include (1-200)",
						"default":     20,
					},
					"since_version": map[string]any{
						"type":        "integer",
						"description": "Optional schema drift baseline version",
					},
					"stale_after_hours": map[string]any{
						"type":        "integer",
						"description": "Freshness threshold in hours (1-8760)",
						"default":     720,
					},
					"identity_suggest_threshold": map[string]any{
						"type":        "number",
						"description": "Identity candidate suggestion threshold (0-1)",
						"default":     0.55,
					},
					"identity_queue_limit": map[string]any{
						"type":        "integer",
						"description": "Max identity review queue entries (1-200)",
						"default":     25,
					},
					"recent_window_hours": map[string]any{
						"type":        "integer",
						"description": "Recent activity window in hours (1-168)",
						"default":     24,
					},
					"decision_sla_days": map[string]any{
						"type":        "integer",
						"description": "Days before a decision without outcomes is considered stale (1-365)",
						"default":     14,
					},
				},
			},
			Handler: a.toolCerebroGraphLeverageReport,
		},
		{
			Name:        "cerebro.graph_query_templates",
			Description: "List reusable graph investigation templates for analysts and agents",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
			Handler: a.toolCerebroGraphQueryTemplates,
		},
		{
			Name:        "cerebro.graph_changelog",
			Description: "Inspect recent graph snapshot changes or one stored/derived graph diff in detail",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"diff_id": map[string]any{
						"type":        "string",
						"description": "Optional graph diff ID from changelog results. When set, returns detailed filtered diff data for either a stored artifact or a derived adjacent snapshot diff.",
					},
					"since": map[string]any{
						"type":        "string",
						"description": "Optional RFC3339 lower bound for changelog listing.",
					},
					"until": map[string]any{
						"type":        "string",
						"description": "Optional RFC3339 upper bound for changelog listing.",
					},
					"last": map[string]any{
						"type":        "string",
						"description": "Optional duration window for changelog listing, for example 24h or 7d.",
					},
					"kind": map[string]any{
						"type":        "string",
						"description": "Optional node kind filter.",
					},
					"provider": map[string]any{
						"type":        "string",
						"description": "Optional provider filter.",
					},
					"account": map[string]any{
						"type":        "string",
						"description": "Optional account filter.",
					},
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum changelog entries to return (1-200).",
						"default":     20,
					},
				},
			},
			Handler: a.toolCerebroGraphChangelog,
		},
		{
			Name:        "cerebro.entity_history",
			Description: "Reconstruct one entity at a historical time or diff one entity across two times",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"entity_id": map[string]any{
						"type":        "string",
						"description": "Stable entity identifier.",
					},
					"timestamp": map[string]any{
						"type":        "string",
						"description": "RFC3339 point-in-time selector for one reconstructed entity state.",
					},
					"from": map[string]any{
						"type":        "string",
						"description": "RFC3339 start timestamp for one entity diff window.",
					},
					"to": map[string]any{
						"type":        "string",
						"description": "RFC3339 end timestamp for one entity diff window.",
					},
					"recorded_at": map[string]any{
						"type":        "string",
						"description": "Optional RFC3339 system-time selector.",
					},
				},
				"required": []string{"entity_id"},
			},
			Handler: a.toolCerebroEntityHistory,
		},
		{
			Name:        "evaluate_policy",
			Description: "Evaluate whether a proposed action should be allowed, denied, or require approval with optional propagation analysis",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"principal": map[string]any{"type": "object"},
					"action":    map[string]any{"type": "string"},
					"resource":  map[string]any{"type": "object"},
					"context":   map[string]any{"type": "object"},
					"proposed_change": map[string]any{
						"type":        "object",
						"description": "Optional proposed graph mutations to evaluate propagation and approval impact",
					},
					"trace_context": map[string]any{
						"type":        "object",
						"description": "Optional trace metadata to carry through gateway calls",
					},
				},
				"required": []string{"action", "resource"},
			},
			Handler: a.toolCerebroEvaluatePolicy,
		},
		{
			Name:        "cerebro.record_observation",
			Description: "Write one evidence observation targeting an entity with provenance and temporal metadata",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":              map[string]any{"type": "string"},
					"entity_id":       map[string]any{"type": "string"},
					"observation":     map[string]any{"type": "string"},
					"summary":         map[string]any{"type": "string"},
					"source_system":   map[string]any{"type": "string", "default": "agent"},
					"source_event_id": map[string]any{"type": "string"},
					"observed_at":     map[string]any{"type": "string"},
					"valid_from":      map[string]any{"type": "string"},
					"valid_to":        map[string]any{"type": "string"},
					"confidence":      map[string]any{"type": "number", "default": 0.8},
					"metadata":        map[string]any{"type": "object"},
				},
				"required": []string{"entity_id", "observation"},
			},
			Handler: a.toolCerebroRecordObservation,
		},
		{
			Name:        "cerebro.write_claim",
			Description: "Write one first-class claim with provenance, bitemporal fields, and evidence/source linkage",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":                   map[string]any{"type": "string"},
					"claim_type":           map[string]any{"type": "string"},
					"subject_id":           map[string]any{"type": "string"},
					"predicate":            map[string]any{"type": "string"},
					"object_id":            map[string]any{"type": "string"},
					"object_value":         map[string]any{"type": "string"},
					"status":               map[string]any{"type": "string"},
					"summary":              map[string]any{"type": "string"},
					"evidence_ids":         map[string]any{"type": "array"},
					"supporting_claim_ids": map[string]any{"type": "array"},
					"refuting_claim_ids":   map[string]any{"type": "array"},
					"supersedes_claim_id":  map[string]any{"type": "string"},
					"source_id":            map[string]any{"type": "string"},
					"source_name":          map[string]any{"type": "string"},
					"source_type":          map[string]any{"type": "string"},
					"source_url":           map[string]any{"type": "string"},
					"trust_tier":           map[string]any{"type": "string"},
					"reliability_score":    map[string]any{"type": "number"},
					"source_system":        map[string]any{"type": "string", "default": "agent"},
					"source_event_id":      map[string]any{"type": "string"},
					"observed_at":          map[string]any{"type": "string"},
					"valid_from":           map[string]any{"type": "string"},
					"valid_to":             map[string]any{"type": "string"},
					"recorded_at":          map[string]any{"type": "string"},
					"transaction_from":     map[string]any{"type": "string"},
					"transaction_to":       map[string]any{"type": "string"},
					"confidence":           map[string]any{"type": "number", "default": 0.8},
					"metadata":             map[string]any{"type": "object"},
				},
				"required": []string{"subject_id", "predicate"},
			},
			Handler: a.toolCerebroWriteClaim,
		},
		{
			Name:        "cerebro.annotate_entity",
			Description: "Append analyst/agent annotations to one entity with provenance metadata",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"entity_id":       map[string]any{"type": "string"},
					"annotation":      map[string]any{"type": "string"},
					"tags":            map[string]any{"type": "array"},
					"source_system":   map[string]any{"type": "string", "default": "agent"},
					"source_event_id": map[string]any{"type": "string"},
					"observed_at":     map[string]any{"type": "string"},
					"valid_from":      map[string]any{"type": "string"},
					"valid_to":        map[string]any{"type": "string"},
					"confidence":      map[string]any{"type": "number", "default": 0.8},
					"metadata":        map[string]any{"type": "object"},
				},
				"required": []string{"entity_id", "annotation"},
			},
			Handler: a.toolCerebroAnnotateEntity,
		},
		{
			Name:        "cerebro.record_decision",
			Description: "Write one decision node and connect it to targets/evidence/actions",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":              map[string]any{"type": "string"},
					"decision_type":   map[string]any{"type": "string"},
					"status":          map[string]any{"type": "string", "default": "proposed"},
					"made_by":         map[string]any{"type": "string"},
					"rationale":       map[string]any{"type": "string"},
					"target_ids":      map[string]any{"type": "array"},
					"evidence_ids":    map[string]any{"type": "array"},
					"action_ids":      map[string]any{"type": "array"},
					"source_system":   map[string]any{"type": "string", "default": "agent"},
					"source_event_id": map[string]any{"type": "string"},
					"observed_at":     map[string]any{"type": "string"},
					"valid_from":      map[string]any{"type": "string"},
					"valid_to":        map[string]any{"type": "string"},
					"confidence":      map[string]any{"type": "number", "default": 0.8},
					"metadata":        map[string]any{"type": "object"},
				},
				"required": []string{"decision_type", "target_ids"},
			},
			Handler: a.toolCerebroRecordDecision,
		},
		{
			Name:        "cerebro.record_outcome",
			Description: "Write one outcome node and connect it back to decision + impacted targets",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":              map[string]any{"type": "string"},
					"decision_id":     map[string]any{"type": "string"},
					"outcome_type":    map[string]any{"type": "string"},
					"verdict":         map[string]any{"type": "string"},
					"impact_score":    map[string]any{"type": "number"},
					"target_ids":      map[string]any{"type": "array"},
					"source_system":   map[string]any{"type": "string", "default": "agent"},
					"source_event_id": map[string]any{"type": "string"},
					"observed_at":     map[string]any{"type": "string"},
					"valid_from":      map[string]any{"type": "string"},
					"valid_to":        map[string]any{"type": "string"},
					"confidence":      map[string]any{"type": "number", "default": 0.8},
					"metadata":        map[string]any{"type": "object"},
				},
				"required": []string{"decision_id", "outcome_type", "verdict"},
			},
			Handler: a.toolCerebroRecordOutcome,
		},
		{
			Name:        "cerebro.resolve_identity",
			Description: "Resolve one external alias to canonical identity nodes with confidence scoring",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"alias_id":            map[string]any{"type": "string"},
					"source_system":       map[string]any{"type": "string"},
					"source_event_id":     map[string]any{"type": "string"},
					"external_id":         map[string]any{"type": "string"},
					"alias_type":          map[string]any{"type": "string"},
					"canonical_hint":      map[string]any{"type": "string"},
					"email":               map[string]any{"type": "string"},
					"name":                map[string]any{"type": "string"},
					"observed_at":         map[string]any{"type": "string"},
					"confidence":          map[string]any{"type": "number"},
					"auto_link_threshold": map[string]any{"type": "number"},
					"suggest_threshold":   map[string]any{"type": "number"},
				},
				"required": []string{"source_system", "external_id"},
			},
			Handler: a.toolCerebroResolveIdentity,
		},
		{
			Name:        "cerebro.split_identity",
			Description: "Remove one alias->canonical identity link to reverse an incorrect merge",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"alias_node_id":     map[string]any{"type": "string"},
					"canonical_node_id": map[string]any{"type": "string"},
					"reason":            map[string]any{"type": "string"},
					"source_system":     map[string]any{"type": "string", "default": "agent"},
					"source_event_id":   map[string]any{"type": "string"},
					"observed_at":       map[string]any{"type": "string"},
				},
				"required": []string{"alias_node_id", "canonical_node_id"},
			},
			Handler: a.toolCerebroSplitIdentity,
		},
		{
			Name:        "cerebro.identity_review",
			Description: "Record a human verdict for one alias->canonical identity candidate",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"alias_node_id":     map[string]any{"type": "string"},
					"canonical_node_id": map[string]any{"type": "string"},
					"verdict":           map[string]any{"type": "string", "enum": []string{"accepted", "rejected", "uncertain"}},
					"reviewer":          map[string]any{"type": "string"},
					"reason":            map[string]any{"type": "string"},
					"source_system":     map[string]any{"type": "string", "default": "review"},
					"source_event_id":   map[string]any{"type": "string"},
					"observed_at":       map[string]any{"type": "string"},
					"confidence":        map[string]any{"type": "number", "default": 0.95},
				},
				"required": []string{"alias_node_id", "canonical_node_id", "verdict"},
			},
			Handler: a.toolCerebroIdentityReview,
		},
		{
			Name:        "cerebro.identity_calibration",
			Description: "Return identity precision/coverage metrics and optional review queue backlog",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"suggest_threshold": map[string]any{"type": "number", "default": 0.55},
					"queue_limit":       map[string]any{"type": "integer", "default": 25},
					"include_queue":     map[string]any{"type": "boolean", "default": true},
				},
			},
			Handler: a.toolCerebroIdentityCalibration,
		},
		{
			Name:        "cerebro.actuate_recommendation",
			Description: "Write one action node from a recommendation and link it to targets and optional decision context",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":                map[string]any{"type": "string"},
					"recommendation_id": map[string]any{"type": "string"},
					"insight_type":      map[string]any{"type": "string"},
					"title":             map[string]any{"type": "string"},
					"summary":           map[string]any{"type": "string"},
					"decision_id":       map[string]any{"type": "string"},
					"target_ids":        map[string]any{"type": "array"},
					"source_system":     map[string]any{"type": "string", "default": "agent"},
					"source_event_id":   map[string]any{"type": "string"},
					"observed_at":       map[string]any{"type": "string"},
					"valid_from":        map[string]any{"type": "string"},
					"valid_to":          map[string]any{"type": "string"},
					"confidence":        map[string]any{"type": "number", "default": 0.8},
					"auto_generated":    map[string]any{"type": "boolean", "default": true},
					"metadata":          map[string]any{"type": "object"},
				},
			},
			Handler: a.toolCerebroActuateRecommendation,
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
					"as_of":     map[string]any{"type": "string", "description": "Optional RFC3339 point-in-time scope"},
					"from":      map[string]any{"type": "string", "description": "Optional RFC3339 temporal window start (requires to)"},
					"to":        map[string]any{"type": "string", "description": "Optional RFC3339 temporal window end (requires from)"},
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
	AsOf      string `json:"as_of"`
	From      string `json:"from"`
	To        string `json:"to"`
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

func (a *App) toolCerebroInsightCard(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		Entity   string   `json:"entity"`
		Sections []string `json:"sections"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	req.Entity = strings.TrimSpace(req.Entity)
	if req.Entity == "" {
		return "", fmt.Errorf("entity is required")
	}

	node, ok := g.GetNode(req.Entity)
	if !ok {
		return "", fmt.Errorf("entity not found: %s", req.Entity)
	}

	sections := normalizeInsightSections(req.Sections)
	cardType := inferInsightCardType(node)

	response := map[string]any{
		"entity":    firstNonEmpty(node.Name, node.ID),
		"entity_id": node.ID,
		"card_type": cardType,
		"sections":  sections,
	}

	if sections["risk"] {
		riskScore, riskTrend, riskSignals := buildInsightRiskSection(g, node)
		response["risk_score"] = riskScore
		response["risk_trend"] = riskTrend
		response["risk_signals"] = riskSignals
		response["toxic_combinations"] = buildInsightToxicCombinations(g, node.ID)
	}

	if sections["relationships"] {
		blast := buildInsightBlastRadius(g, node)
		response["blast_radius"] = blast
		response["key_relationships"] = buildInsightRelationships(g, node)
	}

	if sections["activity"] {
		response["peer_comparison"] = buildInsightPeerComparison(g, node)
		response["activity"] = buildInsightActivity(g, node)
	}

	if sections["recommendations"] {
		response["recommendations"] = buildInsightRecommendations(g, node)
	}

	return marshalToolResponse(response)
}

func (a *App) toolCerebroIntelligenceReport(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		EntityID              string `json:"entity_id"`
		WindowDays            int    `json:"window_days"`
		HistoryLimit          int    `json:"history_limit"`
		IncludeCounterfactual *bool  `json:"include_counterfactual"`
		MaxInsights           int    `json:"max_insights"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	includeCounterfactual := true
	if req.IncludeCounterfactual != nil {
		includeCounterfactual = *req.IncludeCounterfactual
	}

	windowDays := clampInt(req.WindowDays, 90, 1, 3650)
	historyLimit := clampInt(req.HistoryLimit, 20, 1, 200)
	maxInsights := clampInt(req.MaxInsights, 8, 1, 20)

	report := graph.BuildIntelligenceReport(g, graph.NewRiskEngine(g), graph.IntelligenceReportOptions{
		EntityID:              strings.TrimSpace(req.EntityID),
		OutcomeWindow:         time.Duration(windowDays) * 24 * time.Hour,
		SchemaHistoryLimit:    historyLimit,
		MaxInsights:           maxInsights,
		IncludeCounterfactual: includeCounterfactual,
	})
	return marshalToolResponse(report)
}

func (a *App) toolCerebroGraphQualityReport(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		HistoryLimit    int   `json:"history_limit"`
		SinceVersion    int64 `json:"since_version"`
		StaleAfterHours int   `json:"stale_after_hours"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	if req.SinceVersion < 0 {
		return "", fmt.Errorf("since_version must be a positive integer")
	}

	historyLimit := clampInt(req.HistoryLimit, 20, 1, 200)
	staleAfterHours := clampInt(req.StaleAfterHours, 720, 1, 8760)

	report := graph.BuildGraphQualityReport(g, graph.GraphQualityReportOptions{
		SchemaHistoryLimit:  historyLimit,
		SchemaSinceVersion:  req.SinceVersion,
		FreshnessStaleAfter: time.Duration(staleAfterHours) * time.Hour,
	})
	return marshalToolResponse(report)
}

func (a *App) toolCerebroGraphLeverageReport(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		HistoryLimit             int     `json:"history_limit"`
		SinceVersion             int64   `json:"since_version"`
		StaleAfterHours          int     `json:"stale_after_hours"`
		IdentitySuggestThreshold float64 `json:"identity_suggest_threshold"`
		IdentityQueueLimit       int     `json:"identity_queue_limit"`
		RecentWindowHours        int     `json:"recent_window_hours"`
		DecisionSLADays          int     `json:"decision_sla_days"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	if req.SinceVersion < 0 {
		return "", fmt.Errorf("since_version must be a positive integer")
	}
	if req.IdentitySuggestThreshold < 0 || req.IdentitySuggestThreshold > 1 {
		return "", fmt.Errorf("identity_suggest_threshold must be between 0 and 1")
	}

	historyLimit := clampInt(req.HistoryLimit, 20, 1, 200)
	staleAfterHours := clampInt(req.StaleAfterHours, 720, 1, 8760)
	queueLimit := clampInt(req.IdentityQueueLimit, 25, 1, 200)
	recentWindowHours := clampInt(req.RecentWindowHours, 24, 1, 168)
	decisionSLADays := clampInt(req.DecisionSLADays, 14, 1, 365)
	suggestThreshold := req.IdentitySuggestThreshold
	if suggestThreshold == 0 {
		suggestThreshold = 0.55
	}

	report := graph.BuildGraphLeverageReport(g, graph.GraphLeverageReportOptions{
		SchemaHistoryLimit:       historyLimit,
		SchemaSinceVersion:       req.SinceVersion,
		FreshnessStaleAfter:      time.Duration(staleAfterHours) * time.Hour,
		IdentitySuggestThreshold: suggestThreshold,
		IdentityQueueLimit:       queueLimit,
		RecentWindow:             time.Duration(recentWindowHours) * time.Hour,
		DecisionStaleAfter:       time.Duration(decisionSLADays) * 24 * time.Hour,
	})
	return marshalToolResponse(report)
}

func (a *App) toolCerebroGraphQueryTemplates(_ context.Context, _ json.RawMessage) (string, error) {
	templates := graph.DefaultGraphQueryTemplates()
	return marshalToolResponse(map[string]any{
		"templates": templates,
		"count":     len(templates),
	})
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

func normalizeInsightSections(raw []string) map[string]bool {
	sections := map[string]bool{
		"risk":            false,
		"relationships":   false,
		"activity":        false,
		"recommendations": false,
	}
	if len(raw) == 0 {
		for key := range sections {
			sections[key] = true
		}
		return sections
	}
	for _, section := range raw {
		section = strings.ToLower(strings.TrimSpace(section))
		if _, ok := sections[section]; ok {
			sections[section] = true
		}
	}
	enabled := false
	for _, on := range sections {
		if on {
			enabled = true
			break
		}
	}
	if !enabled {
		for key := range sections {
			sections[key] = true
		}
	}
	return sections
}

func inferInsightCardType(node *graph.Node) string {
	if node == nil {
		return "entity"
	}
	switch node.Kind {
	case graph.NodeKindCustomer, graph.NodeKindContact, graph.NodeKindCompany, graph.NodeKindDeal, graph.NodeKindOpportunity, graph.NodeKindSubscription:
		return "customer"
	case graph.NodeKindPerson, graph.NodeKindUser:
		return "person"
	case graph.NodeKindDepartment:
		return "team"
	case graph.NodeKindApplication, graph.NodeKindFunction, graph.NodeKindDatabase, graph.NodeKindBucket, graph.NodeKindInstance, graph.NodeKindNetwork:
		return "service"
	default:
		return "entity"
	}
}

func buildInsightRiskSection(g *graph.Graph, node *graph.Node) (float64, string, []map[string]any) {
	if g == nil || node == nil {
		return 0, "stable", nil
	}
	engine := graph.NewRiskEngine(g)
	entityRisk := engine.ScoreEntity(node.ID)
	if entityRisk == nil {
		return mapNodeRiskToScore(node.Risk), "stable", nil
	}
	signals := make([]map[string]any, 0, len(entityRisk.Factors))
	for _, factor := range entityRisk.Factors {
		signals = append(signals, map[string]any{
			"family": factor.Source,
			"signal": firstNonEmpty(factor.Title, factor.Type),
			"weight": factor.Weight,
		})
	}
	if len(signals) > 5 {
		signals = signals[:5]
	}
	return normalizeRiskScore(entityRisk.Score), firstNonEmpty(entityRisk.Trend, "stable"), signals
}

func buildInsightToxicCombinations(g *graph.Graph, entityID string) []string {
	if g == nil || strings.TrimSpace(entityID) == "" {
		return nil
	}
	engine := graph.NewToxicCombinationEngine()
	combinations := engine.Analyze(g)
	matches := make([]string, 0)
	for _, combo := range combinations {
		if combo == nil {
			continue
		}
		matched := false
		for _, asset := range combo.AffectedAssets {
			if asset == entityID {
				matched = true
				break
			}
		}
		if !matched && combo.AttackPath != nil {
			if combo.AttackPath.EntryPoint != nil && combo.AttackPath.EntryPoint.ID == entityID {
				matched = true
			}
			if combo.AttackPath.Target != nil && combo.AttackPath.Target.ID == entityID {
				matched = true
			}
		}
		if !matched {
			continue
		}
		label := firstNonEmpty(combo.ID, "toxic_combo")
		name := strings.TrimSpace(combo.Name)
		if name != "" {
			label += ": " + name
		}
		matches = append(matches, label)
	}
	sort.Strings(matches)
	return matches
}

func buildInsightBlastRadius(g *graph.Graph, node *graph.Node) map[string]any {
	if g == nil || node == nil {
		return map[string]any{"direct": 0, "indirect": 0, "revenue_at_risk": 0.0}
	}
	directSet := make(map[string]struct{})
	for _, edge := range g.GetOutEdges(node.ID) {
		if edge != nil && strings.TrimSpace(edge.Target) != "" {
			directSet[edge.Target] = struct{}{}
		}
	}
	for _, edge := range g.GetInEdges(node.ID) {
		if edge != nil && strings.TrimSpace(edge.Source) != "" {
			directSet[edge.Source] = struct{}{}
		}
	}

	reachable := make(map[string]struct{})
	queue := make([]string, 0, len(directSet))
	for id := range directSet {
		queue = append(queue, id)
		reachable[id] = struct{}{}
	}
	for _, current := range append([]string(nil), queue...) {
		for _, edge := range g.GetOutEdges(current) {
			if edge == nil || edge.Target == node.ID {
				continue
			}
			if _, seen := reachable[edge.Target]; !seen {
				reachable[edge.Target] = struct{}{}
			}
		}
		for _, edge := range g.GetInEdges(current) {
			if edge == nil || edge.Source == node.ID {
				continue
			}
			if _, seen := reachable[edge.Source]; !seen {
				reachable[edge.Source] = struct{}{}
			}
		}
	}
	indirect := len(reachable) - len(directSet)
	if indirect < 0 {
		indirect = 0
	}

	revenueAtRisk := 0.0
	if node.Kind == graph.NodeKindCustomer {
		revenueAtRisk = readFloat(mapFromAny(node.Properties), "arr", "annual_revenue", "mrr")
	} else {
		for targetID := range directSet {
			target, ok := g.GetNode(targetID)
			if !ok || target == nil || target.Kind != graph.NodeKindCustomer {
				continue
			}
			revenueAtRisk += readFloat(mapFromAny(target.Properties), "arr", "annual_revenue", "mrr")
		}
	}

	return map[string]any{
		"direct":          len(directSet),
		"indirect":        indirect,
		"revenue_at_risk": revenueAtRisk,
	}
}

func buildInsightRelationships(g *graph.Graph, node *graph.Node) []map[string]any {
	if g == nil || node == nil {
		return nil
	}
	relationships := make([]map[string]any, 0)
	appendRelationship := func(edge *graph.Edge, direction string) {
		if edge == nil {
			return
		}
		otherID := edge.Target
		if direction == "in" {
			otherID = edge.Source
		}
		other, ok := g.GetNode(otherID)
		if !ok || other == nil {
			return
		}
		relationships = append(relationships, map[string]any{
			"type":      string(edge.Kind),
			"direction": direction,
			"entity_id": other.ID,
			"entity":    firstNonEmpty(other.Name, other.ID),
		})
	}
	for _, edge := range g.GetOutEdges(node.ID) {
		appendRelationship(edge, "out")
	}
	for _, edge := range g.GetInEdges(node.ID) {
		appendRelationship(edge, "in")
	}
	if len(relationships) > 8 {
		relationships = relationships[:8]
	}
	return relationships
}

func buildInsightPeerComparison(g *graph.Graph, node *graph.Node) string {
	if g == nil || node == nil {
		return "Peer comparison unavailable"
	}
	if outlier, ok := graph.GetEntityOutlierScore(g, node.ID); ok && outlier != nil {
		switch {
		case outlier.OutlierScore >= 0.90:
			return "Bottom 10% of comparable peers"
		case outlier.OutlierScore >= 0.75:
			return "Bottom 25% of comparable peers"
		case outlier.OutlierScore >= 0.50:
			return "Below peer baseline"
		default:
			return "Near peer baseline"
		}
	}
	return "No peer anomalies detected"
}

func buildInsightActivity(g *graph.Graph, node *graph.Node) map[string]any {
	if g == nil || node == nil {
		return map[string]any{"interaction_edges": 0}
	}
	interactionEdges := 0
	lastInteraction := time.Time{}
	for _, edge := range g.GetOutEdges(node.ID) {
		if edge == nil || edge.Kind != graph.EdgeKindInteractedWith {
			continue
		}
		interactionEdges++
		if ts, ok := parseTimeValue(firstPresent(mapFromAny(edge.Properties), "last_seen", "last_interaction", "last_activity")); ok && ts.After(lastInteraction) {
			lastInteraction = ts
		}
	}
	for _, edge := range g.GetInEdges(node.ID) {
		if edge == nil || edge.Kind != graph.EdgeKindInteractedWith {
			continue
		}
		interactionEdges++
		if ts, ok := parseTimeValue(firstPresent(mapFromAny(edge.Properties), "last_seen", "last_interaction", "last_activity")); ok && ts.After(lastInteraction) {
			lastInteraction = ts
		}
	}

	out := map[string]any{
		"interaction_edges": interactionEdges,
	}
	if !lastInteraction.IsZero() {
		out["last_interaction"] = lastInteraction.UTC().Format(time.RFC3339)
	}
	return out
}

func buildInsightRecommendations(g *graph.Graph, node *graph.Node) []string {
	if g == nil || node == nil {
		return []string{"Review entity context and validate current ownership"}
	}
	riskScore, _, riskSignals := buildInsightRiskSection(g, node)
	recommendations := make([]string, 0, 4)
	if riskScore >= 0.70 {
		recommendations = append(recommendations, "Schedule owner escalation and immediate risk review")
	}
	if len(riskSignals) > 0 {
		recommendations = append(recommendations, "Prioritize top risk signals and address highest-weight contributors")
	}
	blast := buildInsightBlastRadius(g, node)
	if toInt(blast["direct"])+toInt(blast["indirect"]) >= 5 {
		recommendations = append(recommendations, "Run scenario simulation before making high-impact changes")
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "No immediate high-risk indicators; continue routine monitoring")
	}
	return dedupeStrings(recommendations)
}

func normalizeRiskScore(score float64) float64 {
	if score <= 0 {
		return 0
	}
	if score > 1 {
		score = score / 100.0
	}
	if score > 1 {
		return 1
	}
	return score
}

func mapNodeRiskToScore(risk graph.RiskLevel) float64 {
	switch risk {
	case graph.RiskCritical:
		return 0.95
	case graph.RiskHigh:
		return 0.75
	case graph.RiskMedium:
		return 0.50
	case graph.RiskLow:
		return 0.25
	default:
		return 0.05
	}
}

func dedupeStrings(values []string) []string {
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
	return out
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

	queryGraph := g
	temporalScope := map[string]any{}

	asOfRaw := strings.TrimSpace(req.AsOf)
	if asOfRaw != "" {
		asOf, err := time.Parse(time.RFC3339, asOfRaw)
		if err != nil {
			return "", fmt.Errorf("as_of must be RFC3339")
		}
		temporalScope["as_of"] = asOf.UTC()
		queryGraph = g.SubgraphAt(asOf.UTC())
	}

	fromRaw := strings.TrimSpace(req.From)
	toRaw := strings.TrimSpace(req.To)
	if fromRaw != "" || toRaw != "" {
		if fromRaw == "" || toRaw == "" {
			return "", fmt.Errorf("both from and to are required when specifying a temporal window")
		}
		from, err := time.Parse(time.RFC3339, fromRaw)
		if err != nil {
			return "", fmt.Errorf("from must be RFC3339")
		}
		to, err := time.Parse(time.RFC3339, toRaw)
		if err != nil {
			return "", fmt.Errorf("to must be RFC3339")
		}
		temporalScope["from"] = from.UTC()
		temporalScope["to"] = to.UTC()
		queryGraph = g.SubgraphBetween(from.UTC(), to.UTC())
	}

	if _, ok := queryGraph.GetNode(req.NodeID); !ok {
		return "", fmt.Errorf("node not found in selected scope: %s", req.NodeID)
	}

	switch req.Mode {
	case "neighbors":
		return a.runNeighborsQuery(queryGraph, req, temporalScope)
	case "paths", "path":
		return a.runPathsQuery(queryGraph, req, temporalScope)
	default:
		return "", fmt.Errorf("unsupported mode: %s", req.Mode)
	}
}

func (a *App) runNeighborsQuery(g *graph.Graph, req cerebroGraphQueryRequest, temporalScope map[string]any) (string, error) {
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
		"temporal":  temporalScope,
		"total":     total,
		"count":     len(results),
		"limit":     limit,
		"truncated": total > len(results),
		"neighbors": results,
	})
}

func (a *App) runPathsQuery(g *graph.Graph, req cerebroGraphQueryRequest, temporalScope map[string]any) (string, error) {
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
		"temporal":  temporalScope,
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
	if a == nil {
		return nil, fmt.Errorf("security graph not initialized")
	}
	securityGraph := a.CurrentSecurityGraph()
	if securityGraph == nil {
		return nil, fmt.Errorf("security graph not initialized")
	}
	return securityGraph, nil
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

func readFloat(m map[string]any, keys ...string) float64 {
	for _, key := range keys {
		if m == nil {
			continue
		}
		value, ok := m[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return typed
		case float32:
			return float64(typed)
		case int:
			return float64(typed)
		case int8:
			return float64(typed)
		case int16:
			return float64(typed)
		case int32:
			return float64(typed)
		case int64:
			return float64(typed)
		case uint:
			return float64(typed)
		case uint8:
			return float64(typed)
		case uint16:
			return float64(typed)
		case uint32:
			return float64(typed)
		case uint64:
			return float64(typed)
		case json.Number:
			if parsed, err := typed.Float64(); err == nil {
				return parsed
			}
		case string:
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64); err == nil {
				return parsed
			}
		}
	}
	return 0
}
