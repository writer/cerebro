package mcpoperations

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/agentplatform"
)

const (
	TaskStateComplete = "complete"
	TaskStatePartial  = "partial"
	TaskStateBlocked  = "blocked"

	DependencyAvailable   = "available"
	DependencyPartial     = "partial"
	DependencyUnavailable = "unavailable"
	DependencySkipped     = "skipped"
)

type TaskDependency struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Required bool   `json:"required"`
}

type TaskResponse struct {
	Task           string           `json:"task"`
	State          string           `json:"state"`
	Contract       string           `json:"contract"`
	WouldMutate    bool             `json:"would_mutate"`
	NextState      string           `json:"next_state,omitempty"`
	Dependencies   []TaskDependency `json:"dependencies"`
	PartialReasons []string         `json:"partial_reasons,omitempty"`
	Data           json.RawMessage  `json:"data"`
	GeneratedAt    string           `json:"generated_at"`
}

type OutputSchema map[string]any

type StructuredContent map[string]any

type InputSchema map[string]any

type Properties map[string]any

type TaskToolLimits struct {
	Evidence      int
	Assets        int
	Actions       int
	Findings      int
	ResourceRoots int
	Graph         int
}

type TaskToolDefinition struct {
	Name        string
	Title       string
	Description string
	InputSchema InputSchema
}

var ErrInvalidTaskRequest = errors.New("invalid MCP task request")

func EvidencePacketRequest(args StructuredContent) (agentplatform.EvidencePacketRequest, error) {
	question, stage := stringValue(args["question"]), stringValue(args["action_stage"])
	if question == "" {
		return agentplatform.EvidencePacketRequest{}, fmt.Errorf("%w: question is required", ErrInvalidTaskRequest)
	}
	if stage != "" && stage != agentplatform.ActionStageObserve && stage != agentplatform.ActionStageExplain && stage != agentplatform.ActionStageRecommend && stage != agentplatform.ActionStageDryRun {
		return agentplatform.EvidencePacketRequest{}, fmt.Errorf("%w: action_stage must be observe, explain, recommend, or dry_run", ErrInvalidTaskRequest)
	}
	return agentplatform.EvidencePacketRequest{
		Question: question, ScopeURN: stringValue(args["scope_urn"]), Model: stringValue(args["model"]), CapabilityIDs: stringList(args["capability_ids"]),
		RequestedScopes: []string{agentplatform.ScopeCosmoSecurityRead}, AllowPreview: boolValue(args["allow_preview"]), EvidenceURNs: stringList(args["evidence_urns"]),
		Action: agentplatform.EvidencePacketAction{Stage: stage, TargetURNs: stringList(args["target_urns"])},
	}, nil
}

func TaskToolDefinitions(limits TaskToolLimits) []TaskToolDefinition {
	readScope := " Requires cerebro.cosmo.security.read."
	return []TaskToolDefinition{
		{Name: "cerebro.risk.explain", Title: "Explain Finding Risk", Description: "Return one authorized finding with evidence, affected assets, and optional graph context. Finding and evidence stores are required; graph failures return a partial task state." + readScope, InputSchema: objectSchema(map[string]any{
			"finding_id": map[string]any{"type": "string"}, "limit": limitSchema(limits.Evidence, "evidence records"), "asset_limit": limitSchema(limits.Assets, "related assets"), "skip_graph": map[string]any{"type": "boolean"}, "compact": map[string]any{"type": "boolean"},
		}, []string{"finding_id"})},
		{Name: "cerebro.evidence.packet", Title: "Build Evidence Packet", Description: "Build an authorized agent evidence packet from current coverage and verifier contracts. The tool never approves or executes an action and reports blocked or partial task states." + readScope, InputSchema: objectSchema(map[string]any{
			"question": map[string]any{"type": "string"}, "scope_urn": map[string]any{"type": "string"}, "model": map[string]any{"type": "string"}, "capability_ids": stringArraySchema(), "evidence_urns": stringArraySchema(), "action_stage": map[string]any{"type": "string", "enum": []string{agentplatform.ActionStageObserve, agentplatform.ActionStageExplain, agentplatform.ActionStageRecommend, agentplatform.ActionStageDryRun}}, "target_urns": stringArraySchema(), "allow_preview": map[string]any{"type": "boolean"},
		}, []string{"question"})},
		{Name: "cerebro.sources.health", Title: "Report Source Health", Description: "Report authorized source coverage, stale data, failed runtimes, unsupported dimensions, and blind spots. Missing runtime state returns a partial task state." + readScope, InputSchema: objectSchema(nil, nil)},
		{Name: "cerebro.action.plan", Title: "Plan Remediation Actions", Description: "Rank non-mutating remediation candidates from authorized findings. Graph context is optional and its absence returns a partial task state; execution remains a separate approval-gated operation." + readScope, InputSchema: objectSchema(map[string]any{
			"runtime_id": map[string]any{"type": "string"}, "runtime_ids": stringArraySchema(), "status": map[string]any{"type": "string", "enum": []string{"open", "resolved", "suppressed"}}, "limit": limitSchema(limits.Actions, "risk action candidates"), "finding_limit": limitSchema(limits.Findings, "risk findings to seed the plan"), "resource_limit": limitSchema(limits.ResourceRoots, "candidate target graph roots"), "graph_limit": limitSchema(limits.Graph, "graph neighbors per candidate target"), "include_unscored": map[string]any{"type": "boolean"},
		}, nil)},
	}
}

func objectSchema(properties map[string]any, required []string) InputSchema {
	if properties == nil {
		properties = map[string]any{}
	}
	schema := InputSchema{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) != 0 {
		schema["required"] = required
	}
	return schema
}

func ObjectSchema(properties Properties, required []string) OutputSchema {
	if properties == nil {
		properties = Properties{}
	}
	schema := OutputSchema{"type": "object", "properties": map[string]any(properties), "additionalProperties": false}
	if len(required) != 0 {
		schema["required"] = required
	}
	return schema
}

func ResponseSchema(properties Properties) OutputSchema {
	if properties == nil {
		properties = Properties{}
	}
	if len(properties) != 0 {
		cloned := make(Properties, len(properties)+1)
		for key, value := range properties {
			cloned[key] = value
		}
		properties = cloned
		if _, ok := properties["metadata"]; !ok {
			properties["metadata"] = map[string]any{"type": "object"}
		}
	}
	return OutputSchema{"type": "object", "properties": map[string]any(properties), "additionalProperties": len(properties) == 0}
}

func LimitSchema(max int, itemName string) OutputSchema {
	return OutputSchema{"type": "integer", "minimum": 1, "maximum": max, "description": fmt.Sprintf("Maximum %s to return. Values above %d are clamped.", itemName, max)}
}

func limitSchema(max int, itemName string) map[string]any {
	return map[string]any{"type": "integer", "minimum": 1, "maximum": max, "description": fmt.Sprintf("Maximum %s to return. Values above %d are clamped.", itemName, max)}
}

func stringArraySchema() map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func stringList(value any) []string {
	values := []string{}
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			values = append(values, stringValue(item))
		}
	case []string:
		values = append(values, typed...)
	case string:
		values = append(values, strings.Split(typed, ",")...)
	}
	return uniqueSortedStrings(values)
}

func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case json.Number:
		number, err := typed.Float64()
		return err == nil && number != 0
	case float64:
		return typed != 0
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true") || strings.TrimSpace(typed) == "1"
	default:
		return false
	}
}

func TaskOutputSchema() OutputSchema {
	return OutputSchema{
		"type": "object",
		"properties": map[string]any{
			"task":            map[string]any{"type": "string"},
			"state":           map[string]any{"type": "string", "enum": []string{TaskStateComplete, TaskStatePartial, TaskStateBlocked}},
			"contract":        map[string]any{"type": "string"},
			"would_mutate":    map[string]any{"type": "boolean", "const": false},
			"next_state":      map[string]any{"type": "string"},
			"dependencies":    map[string]any{"type": "array"},
			"partial_reasons": map[string]any{"type": "array"},
			"data":            map[string]any{"type": "object"},
			"generated_at":    map[string]any{"type": "string"},
		},
		"additionalProperties": false,
	}
}

func RiskExplanation(data StructuredContent, skipGraph bool) (TaskResponse, error) {
	reasons := partialErrors(data)
	graphState := DependencyAvailable
	if skipGraph {
		graphState = DependencySkipped
	} else if reasonsContain(reasons, "graph") {
		graphState = DependencyUnavailable
	}
	return newTaskResponse("risk.explain", "finding_investigation.v1", data, []TaskDependency{
		{Name: "finding_store", State: DependencyAvailable, Required: true},
		{Name: "finding_evidence", State: DependencyAvailable, Required: true},
		{Name: "graph_projection", State: graphState, Required: false},
	}, reasons, false, "")
}

func EvidencePacket(packet agentplatform.AgentEvidencePacket, coverage *agentplatform.AgentCoverageContext) (TaskResponse, error) {
	coverageState, reasons := coverageState(coverage)
	blocked := !packet.Preflight.Enabled || strings.EqualFold(strings.TrimSpace(packet.Confidence.Level), "blocked")
	if blocked {
		reasons = append(reasons, "The packet is blocked until its preflight or verifier requirements are satisfied.")
	}
	preflightState := DependencyAvailable
	if blocked {
		preflightState = DependencyPartial
	}
	return newTaskResponse("evidence.packet", "agent_evidence_packet.v1", packet, []TaskDependency{
		{Name: "agent_preflight", State: preflightState, Required: true},
		{Name: "source_coverage", State: coverageState, Required: false},
	}, reasons, blocked, "")
}

func SourcesHealth(coverage *agentplatform.AgentCoverageContext, runtimeAvailable bool, catalogAvailable bool) (TaskResponse, error) {
	coverageState, reasons := coverageState(coverage)
	catalogState := DependencyAvailable
	if !catalogAvailable {
		catalogState = DependencyUnavailable
		reasons = append(reasons, "Source catalog is unavailable; source coverage cannot be calculated.")
	}
	runtimeState := DependencyAvailable
	if !runtimeAvailable {
		runtimeState = DependencyUnavailable
		reasons = append(reasons, "Source runtime state is unavailable; coverage is based on registered source capabilities.")
	}
	return newTaskResponse("sources.health", "agent_source_coverage.v1", map[string]any{"coverage": coverage}, []TaskDependency{
		{Name: "source_catalog", State: catalogState, Required: true},
		{Name: "source_runtime_store", State: runtimeState, Required: false},
		{Name: "source_coverage", State: coverageState, Required: false},
	}, reasons, !catalogAvailable, "")
}

func ActionPlan(plan StructuredContent, graphIncluded bool) (TaskResponse, error) {
	reasons := partialErrors(plan)
	graphState := DependencyAvailable
	if !graphIncluded {
		graphState = DependencyUnavailable
		reasons = append(reasons, "Graph evidence is unavailable; action candidates use finding evidence only.")
	}
	return newTaskResponse("action.plan", "risk_action_plan.v1", plan, []TaskDependency{
		{Name: "finding_store", State: DependencyAvailable, Required: true},
		{Name: "graph_projection", State: graphState, Required: false},
	}, reasons, false, "proposal")
}

func newTaskResponse(task string, contract string, data any, dependencies []TaskDependency, reasons []string, blocked bool, nextState string) (TaskResponse, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return TaskResponse{}, err
	}
	reasons = uniqueSortedStrings(reasons)
	state := TaskStateComplete
	if blocked {
		state = TaskStateBlocked
	} else if len(reasons) != 0 || dependenciesPartial(dependencies) {
		state = TaskStatePartial
	}
	return TaskResponse{Task: task, State: state, Contract: contract, WouldMutate: false, NextState: nextState, Dependencies: dependencies, PartialReasons: reasons, Data: payload, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}

func coverageState(coverage *agentplatform.AgentCoverageContext) (string, []string) {
	if coverage == nil || coverage.TotalDimensions == 0 {
		return DependencyUnavailable, []string{"No source coverage dimensions are available."}
	}
	if coverage.BlindSpotCount+coverage.UnconfiguredCount+coverage.StaleCount+coverage.FailedCount+coverage.UnsupportedCount+coverage.PartialCount > 0 {
		return DependencyPartial, []string{"Source coverage contains blind spots, stale data, failed runtimes, unsupported dimensions, or partial collection."}
	}
	return DependencyAvailable, nil
}

func partialErrors(value any) []string {
	var typed map[string]any
	switch current := value.(type) {
	case map[string]any:
		typed = current
	case StructuredContent:
		typed = map[string]any(current)
	default:
		return nil
	}
	metadata, ok := typed["metadata"].(map[string]any)
	if !ok {
		return nil
	}
	switch errors := metadata["partial_errors"].(type) {
	case []string:
		return append([]string(nil), errors...)
	case []any:
		values := make([]string, 0, len(errors))
		for _, item := range errors {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				values = append(values, strings.TrimSpace(text))
			}
		}
		return values
	default:
		return nil
	}
}

func reasonsContain(reasons []string, term string) bool {
	for _, reason := range reasons {
		if strings.Contains(strings.ToLower(reason), strings.ToLower(term)) {
			return true
		}
	}
	return false
}

func dependenciesPartial(dependencies []TaskDependency) bool {
	for _, dependency := range dependencies {
		if dependency.State == DependencyPartial || dependency.State == DependencyUnavailable {
			return true
		}
	}
	return false
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}
