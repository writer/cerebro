package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/agentsdk"
	"github.com/writer/cerebro/internal/graph"
	reports "github.com/writer/cerebro/internal/graph/reports"
)

const agentSDKMCPProtocolVersion = agentsdk.ProtocolVersion

type agentSDKToolBinding struct {
	agentsdk.ToolDefinition
	tool agents.Tool
}

type agentSDKResourceDefinition = agentsdk.ResourceDefinition

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
	Method  string            `json:"method,omitempty"`
	Params  any               `json:"params,omitempty"`
}

type agentSDKMCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type agentSDKMCPToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Meta      map[string]any  `json:"_meta,omitempty"`
}

type agentSDKMCPResourceReadParams struct {
	URI string `json:"uri"`
}

type agentSDKReportRequest struct {
	ReportID          string                         `json:"report_id,omitempty"`
	ExecutionMode     string                         `json:"execution_mode,omitempty"`
	MaterializeResult *bool                          `json:"materialize_result,omitempty"`
	Parameters        []reports.ReportParameterValue `json:"parameters,omitempty"`
	RetryPolicy       *reports.ReportRetryPolicy     `json:"retry_policy,omitempty"`
}

type agentSDKPermissionError struct {
	Permission string
}

const (
	contextKeyAgentSDKInvocationSurface contextKey = "agent_sdk_invocation_surface"
	contextKeyAgentSDKMCPSessionID      contextKey = "agent_sdk_mcp_session_id"
	contextKeyAgentSDKProgressToken     contextKey = "agent_sdk_progress_token"
)

func (e *agentSDKPermissionError) Error() string {
	if e == nil || strings.TrimSpace(e.Permission) == "" {
		return "insufficient permissions"
	}
	return "insufficient permissions: requires " + e.Permission
}

func (s *Server) listAgentSDKTools(w http.ResponseWriter, r *http.Request) {
	visible := make([]agentsdk.ToolDefinition, 0)
	for _, binding := range s.agentSDKToolCatalog() {
		if !s.agentSDKHasPermission(r.Context(), binding.RequiredPermission) {
			continue
		}
		visible = append(visible, binding.ToolDefinition)
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

	ctx := agentSDKContextWithInvocation(r.Context(), "agent_sdk.http.tools.call")
	binding, result, raw, err := s.invokeAgentSDKTool(ctx, toolID, args)
	if err != nil {
		s.handleAgentSDKToolError(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]any{
		"tool_id":           binding.ID,
		"tool_name":         binding.ToolName,
		"sdk_method":        binding.SDKMethod,
		"result":            result,
		"raw_result":        raw,
		"invoked_at":        time.Now().UTC(),
		"approval":          binding.RequiresApproval,
		"http_method":       binding.HTTPMethod,
		"http_path":         binding.HTTPPath,
		"execution_kind":    binding.ExecutionKind,
		"supports_async":    binding.SupportsAsync,
		"supports_progress": binding.SupportsProgress,
		"status_resource":   binding.StatusResource,
		"api_credential_id": GetAPICredentialID(ctx),
		"api_client_id":     GetAPIClientID(ctx),
		"traceparent":       GetTraceparent(ctx),
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
	ctx := agentSDKContextWithInvocation(r.Context(), "agent_sdk.http.context")
	_, result, _, invokeErr := s.invokeAgentSDKTool(ctx, "cerebro_context", args)
	if invokeErr != nil {
		s.handleAgentSDKToolError(w, invokeErr)
		return
	}
	s.json(w, http.StatusOK, result)
}

func (s *Server) agentSDKReport(w http.ResponseWriter, r *http.Request) {
	var req agentSDKReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ctx := agentSDKContextWithInvocation(r.Context(), "agent_sdk.http.report")
	run, status, err := s.executeAgentSDKReportRequest(ctx, req)
	if err != nil {
		if run != nil {
			w.Header().Set("Location", run.StatusURL)
			s.json(w, status, run)
			return
		}
		s.error(w, status, err.Error())
		return
	}
	if run == nil {
		s.error(w, http.StatusInternalServerError, "report run not created")
		return
	}
	w.Header().Set("Location", run.StatusURL)
	s.json(w, status, run)
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
	s.platformWriteObservation(w, s.enrichAgentSDKWriteRequest(r, "cerebro_observe"))
}

func (s *Server) agentSDKClaim(w http.ResponseWriter, r *http.Request) {
	s.platformWriteClaim(w, s.enrichAgentSDKWriteRequest(r, "cerebro_claim"))
}

func (s *Server) agentSDKDecision(w http.ResponseWriter, r *http.Request) {
	s.platformWriteDecision(w, s.enrichAgentSDKWriteRequest(r, "cerebro_decide"))
}

func (s *Server) agentSDKOutcome(w http.ResponseWriter, r *http.Request) {
	s.graphWriteOutcome(w, s.enrichAgentSDKWriteRequest(r, "cerebro_outcome"))
}

func (s *Server) agentSDKAnnotation(w http.ResponseWriter, r *http.Request) {
	s.graphAnnotateEntity(w, s.enrichAgentSDKWriteRequest(r, "cerebro_annotate"))
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

	notifyCh, cancel := s.registerAgentSDKMCPSession(sessionID)
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Mcp-Session-Id", sessionID)
	w.Header().Set("MCP-Protocol-Version", agentSDKMCPProtocolVersion)
	w.WriteHeader(http.StatusOK)

	payload, _ := json.Marshal(map[string]any{
		"session_id":       sessionID,
		"protocol_version": agentSDKMCPProtocolVersion,
		"status":           "ready",
		"emitted_at":       time.Now().UTC(),
	})
	_, _ = fmt.Fprintf(w, "event: ready\ndata: %s\n\n", payload)
	flusher.Flush()

	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case message := <-notifyCh:
			encoded, err := json.Marshal(message)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", encoded)
			flusher.Flush()
		case <-keepAlive.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) agentSDKMCP(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if sessionID == "" {
		sessionID = uuid.NewString()
	}
	w.Header().Set("Mcp-Session-Id", sessionID)
	w.Header().Set("MCP-Protocol-Version", agentSDKMCPProtocolVersion)

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

	ctx := agentSDKContextWithSession(r.Context(), sessionID)
	result, mcpErr := s.dispatchAgentSDKMCP(r.WithContext(ctx), req)
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

	ctx := agentSDKContextWithInvocation(r.Context(), "agent_sdk.http.typed")
	_, result, _, invokeErr := s.invokeAgentSDKTool(ctx, toolID, args)
	if invokeErr != nil {
		s.handleAgentSDKToolError(w, invokeErr)
		return
	}
	s.json(w, status, result)
}

func (s *Server) executeAgentSDKReportRequest(ctx context.Context, req agentSDKReportRequest) (*reports.ReportRun, int, error) {
	reportID := strings.TrimSpace(req.ReportID)
	if reportID == "" {
		reportID = "insights"
	}
	return s.startPlatformReportRun(ctx, reportID, platformReportRunRequest{
		ExecutionMode:     req.ExecutionMode,
		MaterializeResult: req.MaterializeResult,
		Parameters:        reports.CloneReportParameterValues(req.Parameters),
		RetryPolicy:       req.RetryPolicy,
	}, strings.TrimSpace(GetUserID(ctx)), agentSDKInvocationSurface(ctx))
}

func (s *Server) invokeAgentSDKTool(ctx context.Context, toolID string, args json.RawMessage) (agentSDKToolBinding, any, string, error) {
	binding, ok := s.lookupAgentSDKTool(toolID)
	if !ok {
		return agentSDKToolBinding{}, nil, "", fmt.Errorf("tool not found: %s", toolID)
	}
	if err := s.authorizeAgentSDKTool(ctx, binding.RequiredPermission); err != nil {
		return binding, nil, "", err
	}
	if binding.ExecutionKind == agentsdk.ExecutionKindReportRun {
		run, _, err := s.executeAgentSDKReportRequest(ctx, agentSDKReportRequestFromArgs(args))
		if err != nil {
			return binding, nil, "", err
		}
		raw, marshalErr := marshalAgentSDKResult(run)
		if marshalErr != nil {
			return binding, nil, "", marshalErr
		}
		return binding, run, raw, nil
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
	if !credentialAllowsPermission(GetAPICredentialScopes(ctx), permission) {
		return false
	}
	if s == nil || s.app == nil || s.app.Config == nil || !s.app.Config.APIAuthEnabled {
		return true
	}
	if s.app.RBAC == nil {
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
	definitions := agentsdk.BuildToolCatalog(tools)
	toolsByName := make(map[string]agents.Tool, len(tools))
	for _, tool := range tools {
		toolsByName[strings.TrimSpace(tool.Name)] = tool
	}
	bindings := make([]agentSDKToolBinding, 0, len(definitions))
	for _, definition := range definitions {
		binding := agentSDKToolBinding{ToolDefinition: definition}
		if tool, ok := toolsByName[strings.TrimSpace(definition.ToolName)]; ok {
			binding.tool = tool
		}
		bindings = append(bindings, binding)
	}
	return bindings
}

func (s *Server) visibleAgentSDKCatalog(ctx context.Context) agentsdk.Catalog {
	catalog := agentsdk.BuildCatalog(s.app.AgentSDKTools(), time.Now().UTC())
	visibleTools := make([]agentsdk.ToolDefinition, 0, len(catalog.Tools))
	for _, tool := range catalog.Tools {
		if !s.agentSDKHasPermission(ctx, tool.RequiredPermission) {
			continue
		}
		visibleTools = append(visibleTools, tool)
	}
	catalog.Tools = visibleTools
	visibleResources := make([]agentsdk.ResourceDefinition, 0, len(catalog.Resources))
	for _, resource := range catalog.Resources {
		if !s.agentSDKHasPermission(ctx, resource.RequiredPermission) {
			continue
		}
		visibleResources = append(visibleResources, resource)
	}
	catalog.Resources = visibleResources
	return catalog
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
				"name":             binding.ID,
				"title":            binding.Title,
				"description":      binding.Description,
				"inputSchema":      binding.InputSchema,
				"supportsAsync":    binding.SupportsAsync,
				"supportsProgress": binding.SupportsProgress,
				"statusResource":   binding.StatusResource,
			})
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var params agentSDKMCPToolCallParams
		if err := decodeOptionalJSON(req.Params, &params); err != nil {
			return nil, &agentSDKMCPError{Code: -32602, Message: "invalid tools/call params"}
		}
		ctx := agentSDKContextWithProgress(r.Context(), strings.TrimSpace(agentSDKMCPSessionID(r.Context())), params.ProgressToken(), "mcp.tools.call")
		binding, result, raw, err := s.invokeAgentSDKTool(ctx, params.Name, params.Arguments)
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
		for _, resource := range agentsdk.Resources() {
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
			"contents": []map[string]any{{
				"uri":      resource.URI,
				"mimeType": resource.MimeType,
				"text":     payload,
			}},
		}, nil
	default:
		return nil, &agentSDKMCPError{Code: -32601, Message: "method not found"}
	}
}

func (params agentSDKMCPToolCallParams) ProgressToken() string {
	if len(params.Meta) == 0 {
		return ""
	}
	for _, key := range []string{"progressToken", "progress_token"} {
		if value, ok := params.Meta[key]; ok {
			switch typed := value.(type) {
			case string:
				return strings.TrimSpace(typed)
			case float64:
				return strconv.FormatInt(int64(typed), 10)
			case int64:
				return strconv.FormatInt(typed, 10)
			case int:
				return strconv.Itoa(typed)
			}
		}
	}
	return ""
}

func (s *Server) readAgentSDKResource(r *http.Request, uri string) (agentSDKResourceDefinition, string, error) {
	for _, resource := range agentsdk.Resources() {
		if resource.URI != uri {
			continue
		}
		if err := s.authorizeAgentSDKTool(r.Context(), resource.RequiredPermission); err != nil {
			return agentSDKResourceDefinition{}, "", err
		}

		var payload any
		switch resource.URI {
		case "cerebro://agent-sdk/catalog":
			payload = s.visibleAgentSDKCatalog(r.Context())
		case "cerebro://schema/node-kinds":
			payload = graph.RegisteredNodeKinds()
		case "cerebro://schema/edge-kinds":
			payload = graph.RegisteredEdgeKinds()
		case "cerebro://tools/catalog":
			payload = s.visibleAgentSDKCatalog(r.Context()).Tools
		case "cerebro://reports/catalog":
			payload = reports.ReportCatalogSnapshot(time.Now().UTC())
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
	w.Header().Set("MCP-Protocol-Version", agentSDKMCPProtocolVersion)
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

func agentSDKReportRequestFromArgs(args json.RawMessage) agentSDKReportRequest {
	request := agentSDKReportRequest{}
	_ = decodeOptionalJSON(normalizeAgentSDKRawArgs(args), &request)
	return request
}

func marshalAgentSDKResult(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(payload), nil
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

func agentSDKContextWithInvocation(ctx context.Context, surface string) context.Context {
	return context.WithValue(ctx, contextKeyAgentSDKInvocationSurface, strings.TrimSpace(surface))
}

func agentSDKContextWithSession(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, contextKeyAgentSDKMCPSessionID, strings.TrimSpace(sessionID))
}

func agentSDKContextWithProgress(ctx context.Context, sessionID, progressToken, surface string) context.Context {
	ctx = agentSDKContextWithInvocation(ctx, surface)
	ctx = agentSDKContextWithSession(ctx, sessionID)
	if strings.TrimSpace(progressToken) != "" {
		ctx = context.WithValue(ctx, contextKeyAgentSDKProgressToken, strings.TrimSpace(progressToken))
	}
	return ctx
}

func agentSDKInvocationSurface(ctx context.Context) string {
	if value, ok := ctx.Value(contextKeyAgentSDKInvocationSurface).(string); ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return "agent_sdk.request"
}

func agentSDKMCPSessionID(ctx context.Context) string {
	if value, ok := ctx.Value(contextKeyAgentSDKMCPSessionID).(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func agentSDKProgressToken(ctx context.Context) string {
	if value, ok := ctx.Value(contextKeyAgentSDKProgressToken).(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}
