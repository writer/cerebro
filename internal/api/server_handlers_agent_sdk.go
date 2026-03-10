package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/evalops/cerebro/internal/agents"
	"github.com/evalops/cerebro/internal/graph"
)

const agentSDKMCPProtocolVersion = "2025-06-18"

type agentSDKToolBinding struct {
	ID                 string         `json:"id"`
	ToolName           string         `json:"tool_name"`
	SDKMethod          string         `json:"sdk_method,omitempty"`
	Title              string         `json:"title,omitempty"`
	Description        string         `json:"description"`
	Category           string         `json:"category,omitempty"`
	HTTPMethod         string         `json:"http_method,omitempty"`
	HTTPPath           string         `json:"http_path,omitempty"`
	RequiredPermission string         `json:"required_permission,omitempty"`
	InputSchema        map[string]any `json:"input_schema,omitempty"`
	RequiresApproval   bool           `json:"requires_approval,omitempty"`
	tool               agents.Tool
}

type agentSDKResourceDefinition struct {
	URI                string `json:"uri"`
	Name               string `json:"name"`
	Description        string `json:"description,omitempty"`
	MimeType           string `json:"mime_type,omitempty"`
	RequiredPermission string `json:"required_permission,omitempty"`
}

type agentSDKMCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type agentSDKMCPResponse struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      any               `json:"id,omitempty"`
	Result  any               `json:"result,omitempty"`
	Error   *agentSDKMCPError `json:"error,omitempty"`
}

type agentSDKMCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type agentSDKMCPToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type agentSDKMCPResourceReadParams struct {
	URI string `json:"uri"`
}

type agentSDKToolMetadata struct {
	ID                 string         `json:"id"`
	ToolName           string         `json:"tool_name"`
	SDKMethod          string         `json:"sdk_method,omitempty"`
	Title              string         `json:"title,omitempty"`
	Description        string         `json:"description"`
	Category           string         `json:"category,omitempty"`
	HTTPMethod         string         `json:"http_method,omitempty"`
	HTTPPath           string         `json:"http_path,omitempty"`
	RequiredPermission string         `json:"required_permission,omitempty"`
	InputSchema        map[string]any `json:"input_schema,omitempty"`
	RequiresApproval   bool           `json:"requires_approval,omitempty"`
}

type agentSDKPermissionError struct {
	Permission string
}

func (e *agentSDKPermissionError) Error() string {
	if e == nil || strings.TrimSpace(e.Permission) == "" {
		return "insufficient permissions"
	}
	return "insufficient permissions: requires " + e.Permission
}

func (s *Server) listAgentSDKTools(w http.ResponseWriter, r *http.Request) {
	visible := make([]agentSDKToolMetadata, 0)
	for _, binding := range s.agentSDKToolCatalog() {
		if !s.agentSDKHasPermission(r.Context(), binding.RequiredPermission) {
			continue
		}
		visible = append(visible, binding.metadata())
	}
	s.json(w, http.StatusOK, visible)
}

func (s *Server) agentSDKCallTool(w http.ResponseWriter, r *http.Request) {
	toolID := strings.TrimSpace(chi.URLParam(r, "tool_id"))
	args, err := readJSONBodyRaw(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	binding, result, raw, err := s.invokeAgentSDKTool(r.Context(), toolID, args)
	if err != nil {
		s.handleAgentSDKToolError(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]any{
		"tool_id":     binding.ID,
		"tool_name":   binding.ToolName,
		"sdk_method":  binding.SDKMethod,
		"result":      result,
		"raw_result":  raw,
		"invoked_at":  time.Now().UTC(),
		"approval":    binding.RequiresApproval,
		"http_method": binding.HTTPMethod,
		"http_path":   binding.HTTPPath,
	})
}

func (s *Server) agentSDKContext(w http.ResponseWriter, r *http.Request) {
	entityID := strings.TrimSpace(chi.URLParam(r, "entity_id"))
	if entityID == "" {
		s.error(w, http.StatusBadRequest, "entity_id is required")
		return
	}

	sections := agentSDKContextSectionsFromRequest(r)
	args, err := json.Marshal(map[string]any{
		"entity":   entityID,
		"sections": sections,
	})
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, result, _, invokeErr := s.invokeAgentSDKTool(r.Context(), "cerebro_context", args)
	if invokeErr != nil {
		s.handleAgentSDKToolError(w, invokeErr)
		return
	}
	s.json(w, http.StatusOK, result)
}

func (s *Server) agentSDKReport(w http.ResponseWriter, r *http.Request) {
	s.agentSDKToolHTTPProxy(w, r, "cerebro_report", http.StatusOK)
}

func (s *Server) agentSDKQuality(w http.ResponseWriter, r *http.Request) {
	s.graphIntelligenceQuality(w, r)
}

func (s *Server) agentSDKLeverage(w http.ResponseWriter, r *http.Request) {
	s.graphIntelligenceLeverage(w, r)
}

func (s *Server) agentSDKTemplates(w http.ResponseWriter, r *http.Request) {
	s.platformGraphTemplates(w, r)
}

func (s *Server) agentSDKCheck(w http.ResponseWriter, r *http.Request) {
	s.evaluatePolicy(w, r)
}

func (s *Server) agentSDKSimulate(w http.ResponseWriter, r *http.Request) {
	s.agentSDKToolHTTPProxy(w, r, "cerebro_simulate", http.StatusOK)
}

func (s *Server) agentSDKObservation(w http.ResponseWriter, r *http.Request) {
	s.graphWriteObservation(w, r)
}

func (s *Server) agentSDKClaim(w http.ResponseWriter, r *http.Request) {
	s.platformWriteClaim(w, r)
}

func (s *Server) agentSDKDecision(w http.ResponseWriter, r *http.Request) {
	s.platformWriteDecision(w, r)
}

func (s *Server) agentSDKOutcome(w http.ResponseWriter, r *http.Request) {
	s.graphWriteOutcome(w, r)
}

func (s *Server) agentSDKAnnotation(w http.ResponseWriter, r *http.Request) {
	s.graphAnnotateEntity(w, r)
}

func (s *Server) agentSDKResolveIdentity(w http.ResponseWriter, r *http.Request) {
	s.graphResolveIdentity(w, r)
}

func (s *Server) listAgentSDKNodeSchema(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, graph.RegisteredNodeKinds())
}

func (s *Server) listAgentSDKEdgeSchema(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, graph.RegisteredEdgeKinds())
}

func (s *Server) agentSDKMCPStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.error(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if sessionID == "" {
		sessionID = uuid.NewString()
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Mcp-Session-Id", sessionID)
	w.WriteHeader(http.StatusOK)

	payload, _ := json.Marshal(map[string]any{
		"session_id":       sessionID,
		"protocol_version": agentSDKMCPProtocolVersion,
		"status":           "ready",
		"emitted_at":       time.Now().UTC(),
	})
	_, _ = fmt.Fprintf(w, "event: ready\ndata: %s\n\n", payload)
	flusher.Flush()
}

func (s *Server) agentSDKMCP(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if sessionID == "" {
		sessionID = uuid.NewString()
	}
	w.Header().Set("Mcp-Session-Id", sessionID)

	var req agentSDKMCPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeAgentSDKMCPResponse(w, agentSDKMCPResponse{
			JSONRPC: "2.0",
			Error:   &agentSDKMCPError{Code: -32700, Message: "invalid JSON-RPC request"},
		})
		return
	}
	if strings.TrimSpace(req.JSONRPC) == "" {
		req.JSONRPC = "2.0"
	}
	if req.JSONRPC != "2.0" {
		s.writeAgentSDKMCPResponse(w, agentSDKMCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &agentSDKMCPError{Code: -32600, Message: "jsonrpc must be 2.0"},
		})
		return
	}

	result, mcpErr := s.dispatchAgentSDKMCP(r, req)
	resp := agentSDKMCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
		Error:   mcpErr,
	}
	s.writeAgentSDKMCPResponse(w, resp)
}

func (s *Server) agentSDKToolHTTPProxy(w http.ResponseWriter, r *http.Request, toolID string, status int) {
	args, err := readJSONBodyRaw(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	_, result, _, invokeErr := s.invokeAgentSDKTool(r.Context(), toolID, args)
	if invokeErr != nil {
		s.handleAgentSDKToolError(w, invokeErr)
		return
	}
	s.json(w, status, result)
}

func (s *Server) invokeAgentSDKTool(ctx context.Context, toolID string, args json.RawMessage) (agentSDKToolBinding, any, string, error) {
	binding, ok := s.lookupAgentSDKTool(toolID)
	if !ok {
		return agentSDKToolBinding{}, nil, "", fmt.Errorf("tool not found: %s", toolID)
	}
	if err := s.authorizeAgentSDKTool(ctx, binding.RequiredPermission); err != nil {
		return binding, nil, "", err
	}
	if err := binding.tool.ValidateExecution(false); err != nil {
		return binding, nil, "", err
	}

	result, err := binding.tool.Handler(ctx, normalizeAgentSDKRawArgs(args))
	if err != nil {
		return binding, nil, "", err
	}
	return binding, decodeAgentSDKToolResult(result), result, nil
}

func (s *Server) authorizeAgentSDKTool(ctx context.Context, permission string) error {
	if strings.TrimSpace(permission) == "" {
		return nil
	}
	if !s.agentSDKHasPermission(ctx, permission) {
		return &agentSDKPermissionError{Permission: permission}
	}
	return nil
}

func (s *Server) agentSDKHasPermission(ctx context.Context, permission string) bool {
	if strings.TrimSpace(permission) == "" {
		return true
	}
	if s == nil || s.app == nil || s.app.RBAC == nil || s.app.Config == nil || !s.app.Config.APIAuthEnabled {
		return true
	}
	userID := GetUserID(ctx)
	if strings.TrimSpace(userID) == "" {
		return true
	}
	return s.app.RBAC.HasPermission(ctx, userID, permission)
}

func (s *Server) lookupAgentSDKTool(toolID string) (agentSDKToolBinding, bool) {
	normalized := strings.TrimSpace(toolID)
	if normalized == "" {
		return agentSDKToolBinding{}, false
	}
	for _, binding := range s.agentSDKToolCatalog() {
		if binding.ID == normalized || binding.ToolName == normalized {
			return binding, true
		}
	}
	return agentSDKToolBinding{}, false
}

func (s *Server) agentSDKToolCatalog() []agentSDKToolBinding {
	tools := s.app.AgentSDKTools()
	bindings := make([]agentSDKToolBinding, 0, len(tools))
	for _, tool := range tools {
		alias := agentSDKAliasForTool(tool.Name)
		bindings = append(bindings, agentSDKToolBinding{
			ID:                 alias.ID,
			ToolName:           tool.Name,
			SDKMethod:          alias.SDKMethod,
			Title:              firstNonEmpty(alias.Title, humanizeAgentSDKToolName(alias.ID)),
			Description:        strings.TrimSpace(tool.Description),
			Category:           alias.Category,
			HTTPMethod:         alias.HTTPMethod,
			HTTPPath:           alias.HTTPPath,
			RequiredPermission: alias.RequiredPermission,
			InputSchema:        cloneJSONMap(tool.Parameters),
			RequiresApproval:   tool.RequiresApproval,
			tool:               tool,
		})
	}
	sort.SliceStable(bindings, func(i, j int) bool {
		return bindings[i].ID < bindings[j].ID
	})
	return bindings
}

func (b agentSDKToolBinding) metadata() agentSDKToolMetadata {
	return agentSDKToolMetadata{
		ID:                 b.ID,
		ToolName:           b.ToolName,
		SDKMethod:          b.SDKMethod,
		Title:              b.Title,
		Description:        b.Description,
		Category:           b.Category,
		HTTPMethod:         b.HTTPMethod,
		HTTPPath:           b.HTTPPath,
		RequiredPermission: b.RequiredPermission,
		InputSchema:        b.InputSchema,
		RequiresApproval:   b.RequiresApproval,
	}
}

func agentSDKAliasForTool(name string) agentSDKToolBinding {
	if alias, ok := agentSDKAliasMap()[strings.TrimSpace(name)]; ok {
		return alias
	}
	return agentSDKToolBinding{
		ID:                 sanitizeAgentSDKToolID(name),
		SDKMethod:          strings.TrimPrefix(sanitizeAgentSDKToolID(name), "cerebro_"),
		Title:              humanizeAgentSDKToolName(sanitizeAgentSDKToolID(name)),
		Category:           "query",
		RequiredPermission: inferAgentSDKPermission(name),
	}
}

func agentSDKAliasMap() map[string]agentSDKToolBinding {
	return map[string]agentSDKToolBinding{
		"insight_card": {
			ID:                 "cerebro_context",
			SDKMethod:          "context",
			Title:              "Entity Context Card",
			Category:           "query",
			HTTPMethod:         http.MethodGet,
			HTTPPath:           "/api/v1/agent-sdk/context/{entity_id}",
			RequiredPermission: "sdk.context.read",
		},
		"cerebro.intelligence_report": {
			ID:                 "cerebro_report",
			SDKMethod:          "report",
			Title:              "Intelligence Report",
			Category:           "query",
			HTTPMethod:         http.MethodPost,
			HTTPPath:           "/api/v1/agent-sdk/report",
			RequiredPermission: "sdk.context.read",
		},
		"cerebro.graph_quality_report": {
			ID:                 "cerebro_quality",
			SDKMethod:          "quality",
			Title:              "Graph Quality Report",
			Category:           "query",
			HTTPMethod:         http.MethodGet,
			HTTPPath:           "/api/v1/agent-sdk/quality",
			RequiredPermission: "sdk.context.read",
		},
		"cerebro.graph_leverage_report": {
			ID:                 "cerebro_leverage",
			SDKMethod:          "leverage",
			Title:              "Graph Leverage Report",
			Category:           "query",
			HTTPMethod:         http.MethodGet,
			HTTPPath:           "/api/v1/agent-sdk/leverage",
			RequiredPermission: "sdk.context.read",
		},
		"cerebro.graph_query_templates": {
			ID:                 "cerebro_templates",
			SDKMethod:          "templates",
			Title:              "Graph Query Templates",
			Category:           "query",
			HTTPMethod:         http.MethodGet,
			HTTPPath:           "/api/v1/agent-sdk/templates",
			RequiredPermission: "sdk.context.read",
		},
		"evaluate_policy": {
			ID:                 "cerebro_check",
			SDKMethod:          "check",
			Title:              "Pre-Action Policy Check",
			Category:           "enforcement",
			HTTPMethod:         http.MethodPost,
			HTTPPath:           "/api/v1/agent-sdk/check",
			RequiredPermission: "sdk.enforcement.run",
		},
		"simulate": {
			ID:                 "cerebro_simulate",
			SDKMethod:          "simulate",
			Title:              "Scenario Simulation",
			Category:           "enforcement",
			HTTPMethod:         http.MethodPost,
			HTTPPath:           "/api/v1/agent-sdk/simulate",
			RequiredPermission: "sdk.enforcement.run",
		},
		"cerebro.record_observation": {
			ID:                 "cerebro_observe",
			SDKMethod:          "observe",
			Title:              "Record Observation",
			Category:           "writeback",
			HTTPMethod:         http.MethodPost,
			HTTPPath:           "/api/v1/agent-sdk/observations",
			RequiredPermission: "sdk.worldmodel.write",
		},
		"cerebro.write_claim": {
			ID:                 "cerebro_claim",
			SDKMethod:          "claim",
			Title:              "Write World Model Claim",
			Category:           "writeback",
			HTTPMethod:         http.MethodPost,
			HTTPPath:           "/api/v1/agent-sdk/claims",
			RequiredPermission: "sdk.worldmodel.write",
		},
		"cerebro.record_decision": {
			ID:                 "cerebro_decide",
			SDKMethod:          "decide",
			Title:              "Record Decision",
			Category:           "writeback",
			HTTPMethod:         http.MethodPost,
			HTTPPath:           "/api/v1/agent-sdk/decisions",
			RequiredPermission: "sdk.worldmodel.write",
		},
		"cerebro.record_outcome": {
			ID:                 "cerebro_outcome",
			SDKMethod:          "outcome",
			Title:              "Record Outcome",
			Category:           "writeback",
			HTTPMethod:         http.MethodPost,
			HTTPPath:           "/api/v1/agent-sdk/outcomes",
			RequiredPermission: "sdk.worldmodel.write",
		},
		"cerebro.annotate_entity": {
			ID:                 "cerebro_annotate",
			SDKMethod:          "annotate",
			Title:              "Annotate Entity",
			Category:           "writeback",
			HTTPMethod:         http.MethodPost,
			HTTPPath:           "/api/v1/agent-sdk/annotations",
			RequiredPermission: "sdk.worldmodel.write",
		},
		"cerebro.resolve_identity": {
			ID:                 "cerebro_resolve_identity",
			SDKMethod:          "resolve_identity",
			Title:              "Resolve Identity",
			Category:           "writeback",
			HTTPMethod:         http.MethodPost,
			HTTPPath:           "/api/v1/agent-sdk/identity/resolve",
			RequiredPermission: "sdk.worldmodel.write",
		},
	}
}

func agentSDKResources() []agentSDKResourceDefinition {
	return []agentSDKResourceDefinition{
		{
			URI:                "cerebro://schema/node-kinds",
			Name:               "Node Kinds",
			Description:        "Registered graph node kind schema definitions",
			MimeType:           "application/json",
			RequiredPermission: "sdk.schema.read",
		},
		{
			URI:                "cerebro://schema/edge-kinds",
			Name:               "Edge Kinds",
			Description:        "Registered graph edge kind schema definitions",
			MimeType:           "application/json",
			RequiredPermission: "sdk.schema.read",
		},
		{
			URI:                "cerebro://tools/catalog",
			Name:               "Agent Tool Catalog",
			Description:        "Discovered Agent SDK tool catalog with JSON Schema parameters",
			MimeType:           "application/json",
			RequiredPermission: "sdk.schema.read",
		},
	}
}

func (s *Server) dispatchAgentSDKMCP(r *http.Request, req agentSDKMCPRequest) (any, *agentSDKMCPError) {
	switch strings.TrimSpace(req.Method) {
	case "initialize":
		return map[string]any{
			"protocolVersion": agentSDKMCPProtocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": false},
				"resources": map[string]any{
					"subscribe":   false,
					"listChanged": false,
				},
			},
			"serverInfo": map[string]any{
				"name":    "cerebro",
				"version": "2.0.0",
			},
		}, nil
	case "tools/list":
		tools := make([]map[string]any, 0)
		for _, binding := range s.agentSDKToolCatalog() {
			if !s.agentSDKHasPermission(r.Context(), binding.RequiredPermission) {
				continue
			}
			tools = append(tools, map[string]any{
				"name":        binding.ID,
				"title":       binding.Title,
				"description": binding.Description,
				"inputSchema": binding.InputSchema,
			})
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var params agentSDKMCPToolCallParams
		if err := decodeOptionalJSON(req.Params, &params); err != nil {
			return nil, &agentSDKMCPError{Code: -32602, Message: "invalid tools/call params"}
		}
		binding, result, raw, err := s.invokeAgentSDKTool(r.Context(), params.Name, params.Arguments)
		if err != nil {
			return nil, agentSDKMCPErrorFromInvoke(err)
		}
		return map[string]any{
			"tool": binding.ID,
			"content": []map[string]any{
				{"type": "text", "text": raw},
			},
			"structuredContent": result,
		}, nil
	case "resources/list":
		resources := make([]map[string]any, 0)
		for _, resource := range agentSDKResources() {
			if !s.agentSDKHasPermission(r.Context(), resource.RequiredPermission) {
				continue
			}
			resources = append(resources, map[string]any{
				"uri":         resource.URI,
				"name":        resource.Name,
				"description": resource.Description,
				"mimeType":    resource.MimeType,
			})
		}
		return map[string]any{"resources": resources}, nil
	case "resources/read":
		var params agentSDKMCPResourceReadParams
		if err := decodeOptionalJSON(req.Params, &params); err != nil {
			return nil, &agentSDKMCPError{Code: -32602, Message: "invalid resources/read params"}
		}
		resource, payload, err := s.readAgentSDKResource(r, strings.TrimSpace(params.URI))
		if err != nil {
			return nil, agentSDKMCPErrorFromInvoke(err)
		}
		return map[string]any{
			"contents": []map[string]any{
				{
					"uri":      resource.URI,
					"mimeType": resource.MimeType,
					"text":     payload,
				},
			},
		}, nil
	default:
		return nil, &agentSDKMCPError{Code: -32601, Message: "method not found"}
	}
}

func (s *Server) readAgentSDKResource(r *http.Request, uri string) (agentSDKResourceDefinition, string, error) {
	for _, resource := range agentSDKResources() {
		if resource.URI != uri {
			continue
		}
		if err := s.authorizeAgentSDKTool(r.Context(), resource.RequiredPermission); err != nil {
			return agentSDKResourceDefinition{}, "", err
		}

		var payload any
		switch resource.URI {
		case "cerebro://schema/node-kinds":
			payload = graph.RegisteredNodeKinds()
		case "cerebro://schema/edge-kinds":
			payload = graph.RegisteredEdgeKinds()
		case "cerebro://tools/catalog":
			visible := make([]agentSDKToolMetadata, 0)
			for _, binding := range s.agentSDKToolCatalog() {
				if !s.agentSDKHasPermission(r.Context(), binding.RequiredPermission) {
					continue
				}
				visible = append(visible, binding.metadata())
			}
			payload = visible
		default:
			return agentSDKResourceDefinition{}, "", fmt.Errorf("resource not found: %s", uri)
		}
		encoded, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return agentSDKResourceDefinition{}, "", err
		}
		return resource, string(encoded), nil
	}
	return agentSDKResourceDefinition{}, "", fmt.Errorf("resource not found: %s", uri)
}

func (s *Server) writeAgentSDKMCPResponse(w http.ResponseWriter, resp agentSDKMCPResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleAgentSDKToolError(w http.ResponseWriter, err error) {
	if err == nil {
		s.error(w, http.StatusInternalServerError, "internal server error")
		return
	}

	var permErr *agentSDKPermissionError
	if errors.As(err, &permErr) {
		writeJSONError(w, http.StatusForbidden, "forbidden", permErr.Error())
		return
	}

	var toolErr *agents.ToolError
	if errors.As(err, &toolErr) {
		status := http.StatusBadRequest
		if toolErr.Code == "approval_required" {
			status = http.StatusConflict
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(toolErr.AsMap())
		return
	}

	status := http.StatusBadRequest
	if strings.Contains(strings.ToLower(err.Error()), "not found") {
		status = http.StatusNotFound
	}
	s.error(w, status, err.Error())
}

func agentSDKMCPErrorFromInvoke(err error) *agentSDKMCPError {
	if err == nil {
		return nil
	}
	var permErr *agentSDKPermissionError
	if errors.As(err, &permErr) {
		return &agentSDKMCPError{Code: -32001, Message: permErr.Error()}
	}
	var toolErr *agents.ToolError
	if errors.As(err, &toolErr) {
		code := -32000
		if toolErr.Code == "approval_required" {
			code = -32002
		}
		return &agentSDKMCPError{Code: code, Message: toolErr.Message}
	}
	if strings.Contains(strings.ToLower(err.Error()), "not found") {
		return &agentSDKMCPError{Code: -32004, Message: err.Error()}
	}
	return &agentSDKMCPError{Code: -32000, Message: err.Error()}
}

func readJSONBodyRaw(r *http.Request) (json.RawMessage, error) {
	if r == nil || r.Body == nil {
		return json.RawMessage("{}"), nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	body = bytesTrimSpace(body)
	if len(body) == 0 {
		return json.RawMessage("{}"), nil
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("invalid request body")
	}
	return json.RawMessage(body), nil
}

func decodeOptionalJSON(raw json.RawMessage, out any) error {
	trimmed := bytesTrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	return json.Unmarshal(trimmed, out)
}

func normalizeAgentSDKRawArgs(args json.RawMessage) json.RawMessage {
	trimmed := bytesTrimSpace(args)
	if len(trimmed) == 0 {
		return json.RawMessage("{}")
	}
	return json.RawMessage(trimmed)
}

func decodeAgentSDKToolResult(raw string) any {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return map[string]any{}
	}
	if json.Valid([]byte(trimmed)) {
		var decoded any
		if err := json.Unmarshal([]byte(trimmed), &decoded); err == nil {
			return decoded
		}
	}
	return raw
}

func sanitizeAgentSDKToolID(name string) string {
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

func humanizeAgentSDKToolName(id string) string {
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

func inferAgentSDKPermission(name string) string {
	switch strings.TrimSpace(name) {
	case "evaluate_policy", "simulate", "cerebro.simulate", "cerebro.access_review":
		return "sdk.enforcement.run"
	case "cerebro.record_observation", "cerebro.write_claim", "cerebro.record_decision", "cerebro.record_outcome", "cerebro.annotate_entity", "cerebro.resolve_identity", "cerebro.split_identity", "cerebro.identity_review", "cerebro.actuate_recommendation":
		return "sdk.worldmodel.write"
	default:
		return "sdk.context.read"
	}
}

func agentSDKContextSectionsFromRequest(r *http.Request) []string {
	sections := parseCSVQueryValues(r.URL.Query()["sections"])
	if len(sections) > 0 {
		return sections
	}
	sections = []string{"risk", "relationships", "activity", "recommendations"}
	if value := strings.TrimSpace(r.URL.Query().Get("include_relationships")); value != "" {
		if enabled, err := strconv.ParseBool(value); err == nil && !enabled {
			sections = removeString(sections, "relationships")
		}
	}
	if value := strings.TrimSpace(r.URL.Query().Get("include_activity")); value != "" {
		if enabled, err := strconv.ParseBool(value); err == nil && !enabled {
			sections = removeString(sections, "activity")
		}
	}
	return sections
}

func parseCSVQueryValues(values []string) []string {
	out := make([]string, 0)
	seen := make(map[string]struct{})
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}

func removeString(values []string, target string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == target {
			continue
		}
		out = append(out, value)
	}
	return out
}

func bytesTrimSpace(value []byte) []byte {
	return []byte(strings.TrimSpace(string(value)))
}
