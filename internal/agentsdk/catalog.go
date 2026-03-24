package agentsdk

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/textutil"
)

const (
	ContractAPIVersion = "cerebro.agent-sdk.contracts/v1alpha1"
	ContractKind       = "AgentSDKCatalog"
	ProtocolVersion    = "2025-06-18"

	ExecutionKindDirectTool = "direct_tool"
	ExecutionKindReportRun  = "report_run"
)

type ToolDefinition struct {
	ID                 string         `json:"id"`
	Version            string         `json:"version"`
	ToolName           string         `json:"tool_name"`
	SDKMethod          string         `json:"sdk_method,omitempty"`
	Title              string         `json:"title,omitempty"`
	Description        string         `json:"description"`
	Category           string         `json:"category,omitempty"`
	HTTPMethod         string         `json:"http_method,omitempty"`
	HTTPPath           string         `json:"http_path,omitempty"`
	RequiredPermission string         `json:"required_permission,omitempty"`
	InputSchema        map[string]any `json:"input_schema,omitempty"`
	ExampleInput       map[string]any `json:"example_input,omitempty"`
	RequiresApproval   bool           `json:"requires_approval,omitempty"`
	ExecutionKind      string         `json:"execution_kind,omitempty"`
	SupportsAsync      bool           `json:"supports_async,omitempty"`
	SupportsProgress   bool           `json:"supports_progress,omitempty"`
	StatusResource     string         `json:"status_resource,omitempty"`
}

type ResourceDefinition struct {
	URI                string `json:"uri"`
	Version            string `json:"version"`
	Name               string `json:"name"`
	Description        string `json:"description,omitempty"`
	MimeType           string `json:"mime_type,omitempty"`
	RequiredPermission string `json:"required_permission,omitempty"`
}

type MethodDefinition struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description,omitempty"`
}

type Catalog struct {
	APIVersion      string               `json:"api_version"`
	Kind            string               `json:"kind"`
	GeneratedAt     time.Time            `json:"generated_at,omitempty"`
	ProtocolVersion string               `json:"protocol_version"`
	Tools           []ToolDefinition     `json:"tools"`
	Resources       []ResourceDefinition `json:"resources"`
	Methods         []MethodDefinition   `json:"methods"`
}

type toolContractOverride struct {
	ID                 string
	Version            string
	SDKMethod          string
	Title              string
	Category           string
	HTTPMethod         string
	HTTPPath           string
	RequiredPermission string
	InputSchema        map[string]any
	ExecutionKind      string
	SupportsAsync      bool
	SupportsProgress   bool
	StatusResource     string
}

func ZeroGeneratedAt() time.Time {
	return time.Time{}
}

func BuildCatalog(tools []agents.Tool, generatedAt time.Time) Catalog {
	catalog := Catalog{
		APIVersion:      ContractAPIVersion,
		Kind:            ContractKind,
		ProtocolVersion: ProtocolVersion,
		Tools:           BuildToolCatalog(tools),
		Resources:       Resources(),
		Methods:         Methods(),
	}
	if !generatedAt.IsZero() {
		catalog.GeneratedAt = generatedAt.UTC()
	}
	return catalog
}

func BuildToolCatalog(tools []agents.Tool) []ToolDefinition {
	bindings := make([]ToolDefinition, 0, len(tools))
	for _, tool := range tools {
		bindings = append(bindings, DefinitionForTool(tool))
	}
	sort.SliceStable(bindings, func(i, j int) bool {
		return bindings[i].ID < bindings[j].ID
	})
	return bindings
}

func DefinitionForTool(tool agents.Tool) ToolDefinition {
	override, ok := lookupToolContractOverride(tool.Name)
	if !ok {
		override = defaultToolContractOverride(tool.Name)
	}
	inputSchema := cloneJSONMap(tool.Parameters)
	if len(override.InputSchema) > 0 {
		inputSchema = cloneJSONMap(override.InputSchema)
	}
	if override.Version == "" {
		override.Version = "1.0.0"
	}
	definition := ToolDefinition{
		ID:                 textutil.FirstNonEmptyTrimmed(strings.TrimSpace(override.ID), sanitizeToolID(tool.Name)),
		Version:            override.Version,
		ToolName:           strings.TrimSpace(tool.Name),
		SDKMethod:          strings.TrimSpace(override.SDKMethod),
		Title:              textutil.FirstNonEmptyTrimmed(override.Title, humanizeToolName(tool.Name)),
		Description:        strings.TrimSpace(tool.Description),
		Category:           strings.TrimSpace(override.Category),
		HTTPMethod:         strings.TrimSpace(override.HTTPMethod),
		HTTPPath:           strings.TrimSpace(override.HTTPPath),
		RequiredPermission: strings.TrimSpace(override.RequiredPermission),
		InputSchema:        inputSchema,
		ExampleInput:       ExampleInput(inputSchema),
		RequiresApproval:   tool.RequiresApproval,
		ExecutionKind:      textutil.FirstNonEmptyTrimmed(override.ExecutionKind, ExecutionKindDirectTool),
		SupportsAsync:      override.SupportsAsync,
		SupportsProgress:   override.SupportsProgress,
		StatusResource:     strings.TrimSpace(override.StatusResource),
	}
	if definition.ID == "" {
		definition.ID = sanitizeToolID(tool.Name)
	}
	if definition.SDKMethod == "" {
		definition.SDKMethod = strings.TrimPrefix(definition.ID, "cerebro_")
	}
	if definition.Category == "" {
		definition.Category = "query"
	}
	if definition.RequiredPermission == "" {
		definition.RequiredPermission = InferPermission(tool.Name)
	}
	return definition
}

func Resources() []ResourceDefinition {
	resources := []ResourceDefinition{
		{
			URI:                "cerebro://agent-sdk/catalog",
			Version:            "1.0.0",
			Name:               "Agent SDK Contract Catalog",
			Description:        "Generated Agent SDK contract catalog with tools, resources, and MCP method metadata",
			MimeType:           "application/json",
			RequiredPermission: "sdk.schema.read",
		},
		{
			URI:                "cerebro://schema/node-kinds",
			Version:            "1.0.0",
			Name:               "Node Kinds",
			Description:        "Registered graph node kind schema definitions",
			MimeType:           "application/json",
			RequiredPermission: "sdk.schema.read",
		},
		{
			URI:                "cerebro://schema/edge-kinds",
			Version:            "1.0.0",
			Name:               "Edge Kinds",
			Description:        "Registered graph edge kind schema definitions",
			MimeType:           "application/json",
			RequiredPermission: "sdk.schema.read",
		},
		{
			URI:                "cerebro://tools/catalog",
			Version:            "1.0.0",
			Name:               "Agent Tool Catalog",
			Description:        "Discovered Agent SDK tool catalog with JSON Schema parameters",
			MimeType:           "application/json",
			RequiredPermission: "sdk.schema.read",
		},
		{
			URI:                "cerebro://reports/catalog",
			Version:            "1.0.0",
			Name:               "Platform Report Catalog",
			Description:        "Built-in platform intelligence report definitions exposed for agent discovery",
			MimeType:           "application/json",
			RequiredPermission: "sdk.schema.read",
		},
	}
	sort.SliceStable(resources, func(i, j int) bool {
		return resources[i].URI < resources[j].URI
	})
	return resources
}

func Methods() []MethodDefinition {
	methods := []MethodDefinition{
		{Name: "initialize", Kind: "request", Description: "Initialize one MCP session over Streamable HTTP"},
		{Name: "tools/list", Kind: "request", Description: "List visible Agent SDK tools"},
		{Name: "tools/call", Kind: "request", Description: "Invoke one Agent SDK tool by public ID"},
		{Name: "resources/list", Kind: "request", Description: "List readable Agent SDK resources"},
		{Name: "resources/read", Kind: "request", Description: "Read one Agent SDK resource payload"},
		{Name: "notifications/progress", Kind: "notification", Description: "Server-initiated progress notifications for long-running report executions"},
		{Name: "notifications/report_section", Kind: "notification", Description: "Server-initiated section payload notifications for durable report executions"},
	}
	return methods
}

func ReportToolInputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"report_id": map[string]any{
				"type":        "string",
				"description": "Built-in platform report definition ID",
				"default":     "insights",
			},
			"execution_mode": map[string]any{
				"type":        "string",
				"enum":        []string{"sync", "async"},
				"description": "Whether to execute inline or queue a durable report run",
				"default":     "sync",
			},
			"materialize_result": map[string]any{
				"type":        "boolean",
				"description": "Whether to persist the materialized report snapshot payload",
				"default":     true,
			},
			"parameters": map[string]any{
				"type":        "array",
				"description": "Typed report parameter bindings",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name":            map[string]any{"type": "string"},
						"string_value":    map[string]any{"type": "string"},
						"integer_value":   map[string]any{"type": "integer"},
						"number_value":    map[string]any{"type": "number"},
						"boolean_value":   map[string]any{"type": "boolean"},
						"timestamp_value": map[string]any{"type": "string", "format": "date-time"},
					},
					"required": []string{"name"},
				},
			},
			"retry_policy": map[string]any{
				"type":        "object",
				"description": "Retry and backoff configuration for durable async report runs",
				"properties": map[string]any{
					"max_attempts":    map[string]any{"type": "integer", "default": 3},
					"base_backoff_ms": map[string]any{"type": "integer", "default": 5000},
					"max_backoff_ms":  map[string]any{"type": "integer", "default": 60000},
				},
			},
		},
	}
}

func ExampleInput(schema map[string]any) map[string]any {
	properties, ok := schema["properties"].(map[string]any)
	if !ok || len(properties) == 0 {
		return nil
	}
	example := make(map[string]any)
	for key, raw := range properties {
		property, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if def, ok := property["default"]; ok {
			example[key] = cloneJSONValue(def)
			continue
		}
		switch strings.TrimSpace(stringValue(property["type"])) {
		case "string":
			if values, ok := stringSlice(property["enum"]); ok && len(values) > 0 {
				example[key] = values[0]
			} else if strings.EqualFold(stringValue(property["format"]), "date-time") {
				example[key] = "2026-03-09T00:00:00Z"
			} else {
				example[key] = sampleStringForKey(key)
			}
		case "integer":
			example[key] = 1
		case "number":
			example[key] = 0.5
		case "boolean":
			example[key] = true
		case "array":
			items, _ := property["items"].(map[string]any)
			switch strings.TrimSpace(stringValue(items["type"])) {
			case "string":
				example[key] = []any{sampleStringForKey(key)}
			case "object":
				itemExample := ExampleInput(items)
				if len(itemExample) > 0 {
					example[key] = []any{itemExample}
				} else {
					example[key] = []any{}
				}
			default:
				example[key] = []any{}
			}
		case "object":
			child := ExampleInput(property)
			if len(child) == 0 {
				child = map[string]any{"example": true}
			}
			example[key] = child
		}
	}
	if len(example) == 0 {
		return nil
	}
	return example
}

func InferPermission(name string) string {
	switch strings.TrimSpace(name) {
	case "evaluate_policy", "simulate", "cerebro.simulate", "cerebro.access_review":
		return "sdk.enforcement.run"
	case "cerebro.record_observation", "cerebro.write_claim", "cerebro.record_decision", "cerebro.record_outcome", "cerebro.annotate_entity", "cerebro.resolve_identity", "cerebro.split_identity", "cerebro.identity_review", "cerebro.actuate_recommendation":
		return "sdk.worldmodel.write"
	default:
		return "sdk.context.read"
	}
}

func lookupToolContractOverride(name string) (toolContractOverride, bool) {
	overrides := map[string]toolContractOverride{
		"insight_card": {
			ID:                 "cerebro_context",
			Version:            "1.0.0",
			SDKMethod:          "context",
			Title:              "Entity Context Card",
			Category:           "query",
			HTTPMethod:         "GET",
			HTTPPath:           "/api/v1/agent-sdk/context/{entity_id}",
			RequiredPermission: "sdk.context.read",
		},
		"cerebro.intelligence_report": {
			ID:                 "cerebro_report",
			Version:            "2.0.0",
			SDKMethod:          "report",
			Title:              "Platform Intelligence Report Run",
			Category:           "intelligence",
			HTTPMethod:         "POST",
			HTTPPath:           "/api/v1/agent-sdk/report",
			RequiredPermission: "sdk.context.read",
			InputSchema:        ReportToolInputSchema(),
			ExecutionKind:      ExecutionKindReportRun,
			SupportsAsync:      true,
			SupportsProgress:   true,
			StatusResource:     "platform.report_run",
		},
		"cerebro.graph_quality_report": {
			ID:                 "cerebro_quality",
			Version:            "1.0.0",
			SDKMethod:          "quality",
			Title:              "Graph Quality Report",
			Category:           "query",
			HTTPMethod:         "GET",
			HTTPPath:           "/api/v1/agent-sdk/quality",
			RequiredPermission: "sdk.context.read",
		},
		"cerebro.graph_leverage_report": {
			ID:                 "cerebro_leverage",
			Version:            "1.0.0",
			SDKMethod:          "leverage",
			Title:              "Graph Leverage Report",
			Category:           "query",
			HTTPMethod:         "GET",
			HTTPPath:           "/api/v1/agent-sdk/leverage",
			RequiredPermission: "sdk.context.read",
		},
		"cerebro.graph_query_templates": {
			ID:                 "cerebro_templates",
			Version:            "1.0.0",
			SDKMethod:          "templates",
			Title:              "Graph Query Templates",
			Category:           "query",
			HTTPMethod:         "GET",
			HTTPPath:           "/api/v1/agent-sdk/templates",
			RequiredPermission: "sdk.context.read",
		},
		"cerebro.execution_status": {
			ID:                 "cerebro_execution_status",
			Version:            "2.0.0",
			SDKMethod:          "execution_status",
			Title:              "Execution Status",
			Category:           "query",
			RequiredPermission: "sdk.context.read",
		},
		"cerebro.nl_query": {
			ID:                 "cerebro_nlq",
			Version:            "1.0.0",
			SDKMethod:          "nlq",
			Title:              "Natural Language Security Query",
			Category:           "query",
			RequiredPermission: "sdk.context.read",
		},
		"cerebro.correlate_events": {
			ID:                 "cerebro_correlate_events",
			Version:            "2.0.0",
			SDKMethod:          "correlate_events",
			Title:              "Correlate Events",
			Category:           "query",
			RequiredPermission: "sdk.context.read",
		},
		"evaluate_policy": {
			ID:                 "cerebro_check",
			Version:            "1.0.0",
			SDKMethod:          "check",
			Title:              "Pre-Action Policy Check",
			Category:           "enforcement",
			HTTPMethod:         "POST",
			HTTPPath:           "/api/v1/agent-sdk/check",
			RequiredPermission: "sdk.enforcement.run",
		},
		"simulate": {
			ID:                 "cerebro_simulate",
			Version:            "2.0.0",
			SDKMethod:          "simulate",
			Title:              "Scenario Simulation",
			Category:           "enforcement",
			HTTPMethod:         "POST",
			HTTPPath:           "/api/v1/agent-sdk/simulate",
			RequiredPermission: "sdk.enforcement.run",
		},
		"cerebro.simulate": {
			ID:                 "cerebro_graph_simulate",
			Version:            "1.0.0",
			SDKMethod:          "graph_simulate",
			Title:              "Graph Mutation Simulation",
			Category:           "enforcement",
			RequiredPermission: "sdk.enforcement.run",
		},
		"cerebro.record_observation": {
			ID:                 "cerebro_observe",
			Version:            "1.0.0",
			SDKMethod:          "observe",
			Title:              "Record Observation",
			Category:           "writeback",
			HTTPMethod:         "POST",
			HTTPPath:           "/api/v1/agent-sdk/observations",
			RequiredPermission: "sdk.worldmodel.write",
		},
		"cerebro.write_claim": {
			ID:                 "cerebro_claim",
			Version:            "1.0.0",
			SDKMethod:          "claim",
			Title:              "Write World Model Claim",
			Category:           "writeback",
			HTTPMethod:         "POST",
			HTTPPath:           "/api/v1/agent-sdk/claims",
			RequiredPermission: "sdk.worldmodel.write",
		},
		"cerebro.record_decision": {
			ID:                 "cerebro_decide",
			Version:            "1.0.0",
			SDKMethod:          "decide",
			Title:              "Record Decision",
			Category:           "writeback",
			HTTPMethod:         "POST",
			HTTPPath:           "/api/v1/agent-sdk/decisions",
			RequiredPermission: "sdk.worldmodel.write",
		},
		"cerebro.record_outcome": {
			ID:                 "cerebro_outcome",
			Version:            "1.0.0",
			SDKMethod:          "outcome",
			Title:              "Record Outcome",
			Category:           "writeback",
			HTTPMethod:         "POST",
			HTTPPath:           "/api/v1/agent-sdk/outcomes",
			RequiredPermission: "sdk.worldmodel.write",
		},
		"cerebro.annotate_entity": {
			ID:                 "cerebro_annotate",
			Version:            "1.0.0",
			SDKMethod:          "annotate",
			Title:              "Annotate Entity",
			Category:           "writeback",
			HTTPMethod:         "POST",
			HTTPPath:           "/api/v1/agent-sdk/annotations",
			RequiredPermission: "sdk.worldmodel.write",
		},
		"cerebro.resolve_identity": {
			ID:                 "cerebro_resolve_identity",
			Version:            "1.0.0",
			SDKMethod:          "resolve_identity",
			Title:              "Resolve Identity",
			Category:           "writeback",
			HTTPMethod:         "POST",
			HTTPPath:           "/api/v1/agent-sdk/identity/resolve",
			RequiredPermission: "sdk.worldmodel.write",
		},
	}
	override, ok := overrides[strings.TrimSpace(name)]
	return override, ok
}

func defaultToolContractOverride(name string) toolContractOverride {
	sanitized := sanitizeToolID(name)
	return toolContractOverride{
		Version:            "1.0.0",
		SDKMethod:          strings.TrimPrefix(sanitized, "cerebro_"),
		Title:              humanizeToolName(sanitized),
		Category:           "query",
		RequiredPermission: InferPermission(name),
	}
}

func sanitizeToolID(name string) string {
	normalized := strings.TrimSpace(strings.ToLower(name))
	if normalized == "" {
		return "cerebro_tool"
	}
	replacer := strings.NewReplacer(".", "_", "-", "_", ":", "_", "/", "_")
	normalized = replacer.Replace(normalized)
	if !strings.HasPrefix(normalized, "cerebro_") {
		normalized = "cerebro_" + normalized
	}
	return normalized
}

func humanizeToolName(id string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(id), "cerebro_")
	if trimmed == "" {
		return "Cerebro Tool"
	}
	parts := strings.Split(trimmed, "_")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func cloneJSONMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	payload, err := json.Marshal(values)
	if err != nil {
		cloned := make(map[string]any, len(values))
		for key, value := range values {
			cloned[key] = cloneJSONValue(value)
		}
		return cloned
	}
	var cloned map[string]any
	if err := json.Unmarshal(payload, &cloned); err != nil {
		fallback := make(map[string]any, len(values))
		for key, value := range values {
			fallback[key] = cloneJSONValue(value)
		}
		return fallback
	}
	return cloned
}

func cloneJSONValue(value any) any {
	payload, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var cloned any
	if err := json.Unmarshal(payload, &cloned); err != nil {
		return value
	}
	return cloned
}

func stringValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func stringSlice(value any) ([]string, bool) {
	raw, ok := value.([]string)
	if ok {
		return raw, true
	}
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, text)
	}
	return out, true
}

func sampleStringForKey(key string) string {
	switch strings.TrimSpace(key) {
	case "entity", "entity_id", "subject_id", "target", "principal_id":
		return "service:payments"
	case "action":
		return "refund.create"
	case "report_id":
		return "insights"
	case "decision_id":
		return "decision:example"
	case "predicate":
		return "healthy"
	case "verdict":
		return "confirmed"
	case "outcome_type":
		return "impact_review"
	case "decision_type":
		return "prioritization"
	case "annotation":
		return "Escalate for review"
	case "observation":
		return "manual_review_signal"
	default:
		return key
	}
}
