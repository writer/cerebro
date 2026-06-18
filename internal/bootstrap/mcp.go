package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/agentplatform"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/findingapi"
	findingdomain "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/riskplan"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/telemetry"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	mcpProtocolVersion          = "2025-11-25"
	mcpEndpointPath             = "/api/v1/mcp"
	defaultMCPListLimit         = 25
	maxMCPListLimit             = 100
	defaultMCPAssetLimit        = 10
	maxMCPAssetLimit            = 50
	defaultMCPEvidenceLimit     = 25
	maxMCPEvidenceLimit         = 100
	defaultMCPNeighborhoodLimit = 10
	maxMCPNeighborhoodLimit     = 50
	defaultMCPGraphLimit        = 25
	maxMCPGraphLimit            = 100
	defaultMCPImpactLimit       = 100
	maxMCPImpactLimit           = 250
	defaultMCPRiskLimit         = 100
	maxMCPRiskLimit             = 500
	defaultMCPRiskActionRoots   = 3
	maxMCPRiskActionRoots       = 10
	defaultMCPRiskActionGraph   = 3
	maxMCPRiskActionGraph       = 10
	defaultMCPRecentRiskRows    = 10
	mcpResourceMIMEJSON         = "application/json"
)

const mcpMaxConcurrentGraphFetches = 4

const (
	mcpGraphEvidenceIncluded     = "included"
	mcpGraphEvidenceUnconfigured = "unconfigured"
)

type mcpJSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpJSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpGraphStoreNeighborhoodResult struct {
	urn          string
	neighborhood *ports.EntityNeighborhood
	err          error
}

func fetchMCPGraphStoreNeighborhoods(ctx context.Context, graphStore ports.GraphQueryStore, roots []string, limit int) []mcpGraphStoreNeighborhoodResult {
	if graphStore == nil || len(roots) == 0 {
		return nil
	}
	results := make([]mcpGraphStoreNeighborhoodResult, len(roots))
	sem := make(chan struct{}, mcpMaxConcurrentGraphFetches)
	var wg sync.WaitGroup
	for index, rootURN := range roots {
		index, rootURN := index, rootURN
		results[index].urn = rootURN
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[index].err = ctx.Err()
				return
			}
			neighborhood, err := graphStore.GetEntityNeighborhood(ctx, rootURN, limit)
			results[index].neighborhood = neighborhood
			results[index].err = err
		}()
	}
	wg.Wait()
	return results
}

type mcpInvestigationResourceResult struct {
	asset            *mcpAssetSearchResult
	assetErr         error
	neighborhood     any
	graphErr         error
	graphEncodingErr bool
}

func (app *App) fetchMCPInvestigationResources(ctx context.Context, r *http.Request, resourceURNs []string, includeGraph bool) []mcpInvestigationResourceResult {
	if app == nil || r == nil || len(resourceURNs) == 0 {
		return nil
	}
	results := make([]mcpInvestigationResourceResult, len(resourceURNs))
	sem := make(chan struct{}, mcpMaxConcurrentGraphFetches)
	var wg sync.WaitGroup
	graphService := app.graphQueryService()
	for index, resourceURN := range resourceURNs {
		index, resourceURN := index, resourceURN
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[index].assetErr = ctx.Err()
				return
			}

			found, err := app.mcpAssetSearchResults(r.Clone(ctx), map[string]any{"urn": resourceURN, "limit": 1})
			if err == nil && len(found) > 0 {
				asset := found[0]
				results[index].asset = &asset
			} else if err != nil {
				results[index].assetErr = err
			}
			if !includeGraph || graphService == nil {
				return
			}
			neighborhood, err := graphService.GetEntityNeighborhood(ctx, graphquery.NeighborhoodRequest{
				RootURN: resourceURN,
				Limit:   uint32(defaultMCPGraphLimit),
			})
			if err != nil {
				results[index].graphErr = err
				return
			}
			if neighborhood == nil {
				return
			}
			value, err := protoJSONValue(graphNeighborhoodResponse(neighborhood))
			if err != nil {
				results[index].graphEncodingErr = true
				return
			}
			results[index].neighborhood = mcpAddResponseMetadata(value, mcpResponseMetadata(defaultMCPGraphLimit, mcpNeighborhoodResultCount(neighborhood), nil))
		}()
	}
	wg.Wait()
	return results
}

type mcpTool struct {
	Name         string         `json:"name"`
	Title        string         `json:"title,omitempty"`
	Description  string         `json:"description"`
	InputSchema  map[string]any `json:"inputSchema"`
	OutputSchema map[string]any `json:"outputSchema,omitempty"`
	Annotations  map[string]any `json:"annotations,omitempty"`
}

type mcpToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type mcpToolResult struct {
	Content           []mcpContent `json:"content"`
	StructuredContent any          `json:"structuredContent,omitempty"`
	IsError           bool         `json:"isError,omitempty"`
}

type mcpContent struct {
	Type     string               `json:"type"`
	Text     string               `json:"text,omitempty"`
	Resource *mcpEmbeddedResource `json:"resource,omitempty"`
}

type mcpEmbeddedResource struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

type mcpResource struct {
	URI         string         `json:"uri"`
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	MimeType    string         `json:"mimeType,omitempty"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

type mcpResourceTemplate struct {
	URITemplate string         `json:"uriTemplate"`
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	MimeType    string         `json:"mimeType,omitempty"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

type mcpReadResourceParams struct {
	URI string `json:"uri"`
}

type mcpReadResourceResult struct {
	Contents []mcpEmbeddedResource `json:"contents"`
}

type mcpPrompt struct {
	Name        string              `json:"name"`
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	Arguments   []mcpPromptArgument `json:"arguments,omitempty"`
}

type mcpPromptArgument struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type mcpPromptGetParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type mcpPromptMessage struct {
	Role    string     `json:"role"`
	Content mcpContent `json:"content"`
}

type mcpAssetSearchResult struct {
	URN        string            `json:"urn"`
	TenantID   string            `json:"tenant_id"`
	RuntimeID  string            `json:"runtime_id,omitempty"`
	SourceID   string            `json:"source_id,omitempty"`
	EntityType string            `json:"entity_type"`
	Label      string            `json:"label"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type mcpRiskSummary struct {
	TenantID             string               `json:"tenant_id,omitempty"`
	RuntimeID            string               `json:"runtime_id,omitempty"`
	TotalFindings        int                  `json:"total_findings"`
	ReturnedFindings     int                  `json:"returned_findings"`
	OpenFindings         int                  `json:"open_findings"`
	CriticalOpenFindings int                  `json:"critical_open_findings"`
	HighOpenFindings     int                  `json:"high_open_findings"`
	MaxRiskScore         int                  `json:"max_risk_score"`
	AverageRiskScore     float64              `json:"average_risk_score"`
	BySeverity           map[string]int       `json:"by_severity"`
	ByStatus             map[string]int       `json:"by_status"`
	TopRiskReasons       []mcpRiskReasonCount `json:"top_risk_reasons"`
	RecentHighRisk       []any                `json:"recent_high_risk"`
	LimitApplied         int                  `json:"limit_applied"`
	Metadata             map[string]any       `json:"metadata,omitempty"`
}

type mcpFindingSummaryStore interface {
	SummarizeFindings(context.Context, ports.ListFindingsRequest) (ports.FindingSummary, error)
}

type mcpRiskReasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type mcpTelemetryDetails struct {
	RequestKind      string
	JSONRPCIDPresent bool
	ParamsPresent    bool
	Response         *mcpJSONRPCResponse
}

func (app *App) handleMCP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		mcpTelemetryEvent(r, "", "", http.StatusMethodNotAllowed, 0, "http_method", "", time.Since(started), mcpTelemetryDetails{RequestKind: "transport_reject"})
		return
	}
	if !app.mcpValidOrigin(r) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		mcpTelemetryEvent(r, "", "", http.StatusForbidden, 0, "origin_forbidden", "", time.Since(started), mcpTelemetryDetails{RequestKind: "transport_reject"})
		return
	}
	defer func() { _ = r.Body.Close() }()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes))
	decoder.UseNumber()
	var request mcpJSONRPCRequest
	if err := decoder.Decode(&request); err != nil {
		mcpWriteJSONRPC(w, mcpJSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &mcpError{Code: -32700, Message: "parse error"},
		})
		mcpTelemetryEvent(r, "", "", http.StatusOK, -32700, "parse_error", "", time.Since(started), mcpTelemetryDetails{RequestKind: "parse_error"})
		return
	}
	if request.Method == "" && (len(request.Result) != 0 || request.Error != nil) {
		w.WriteHeader(http.StatusAccepted)
		mcpTelemetryEvent(r, "", "", http.StatusAccepted, 0, "client_message", "", time.Since(started), mcpTelemetryDetails{RequestKind: "client_message"})
		return
	}
	if len(request.ID) == 0 && strings.TrimSpace(request.Method) != "" {
		w.WriteHeader(http.StatusAccepted)
		mcpTelemetryEvent(r, request.Method, mcpToolNameFromParams(request.Method, request.Params), http.StatusAccepted, 0, "notification", "", time.Since(started), mcpTelemetryDetails{
			RequestKind:      "notification",
			ParamsPresent:    len(request.Params) != 0,
			JSONRPCIDPresent: false,
		})
		return
	}
	if request.Method != "initialize" && !mcpSupportedProtocolVersion(strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))) {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		mcpTelemetryEvent(r, request.Method, mcpToolNameFromParams(request.Method, request.Params), http.StatusBadRequest, -32600, "unsupported_protocol_version", "", time.Since(started), mcpTelemetryDetails{
			RequestKind:      "request",
			ParamsPresent:    len(request.Params) != 0,
			JSONRPCIDPresent: len(request.ID) != 0,
		})
		return
	}
	if request.Method == "tools/call" && mcpToolNameFromParams(request.Method, request.Params) == "cerebro.graph.reason" {
		clearLongRunningWriteDeadline(w)
	}
	response := app.handleMCPRequest(r, request)
	mcpWriteJSONRPC(w, response)
	mcpTelemetryEvent(r, request.Method, mcpToolNameFromParams(request.Method, request.Params), http.StatusOK, mcpResponseErrorCode(response), mcpResponseOutcome(response), mcpResponseToolErrorKind(response), time.Since(started), mcpTelemetryDetails{
		RequestKind:      "request",
		ParamsPresent:    len(request.Params) != 0,
		JSONRPCIDPresent: len(request.ID) != 0,
		Response:         &response,
	})
}

func (app *App) handleMCPStream(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		mcpTelemetryEvent(r, "", "", http.StatusMethodNotAllowed, 0, "http_method", "", time.Since(started), mcpTelemetryDetails{RequestKind: "transport_reject"})
		return
	}
	w.Header().Set("Allow", http.MethodPost)
	w.Header().Set("MCP-Protocol-Version", mcpProtocolVersion)
	w.Header().Set("X-Cerebro-MCP-Stateless", "true")
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	mcpTelemetryEvent(r, "", "", http.StatusMethodNotAllowed, 0, "stateless_get_rejected", "", time.Since(started), mcpTelemetryDetails{RequestKind: "transport_reject"})
}

func (app *App) handleMCPRequest(r *http.Request, request mcpJSONRPCRequest) mcpJSONRPCResponse {
	response := mcpJSONRPCResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
	}
	if request.JSONRPC != "2.0" || strings.TrimSpace(request.Method) == "" {
		response.Error = &mcpError{Code: -32600, Message: "invalid request"}
		return response
	}
	if err := authorizeMCPMethodScope(r.Context(), request.Method); err != nil {
		response.Error = &mcpError{Code: -32602, Message: safeMCPToolError(err)}
		return response
	}
	switch request.Method {
	case "initialize":
		response.Result = app.mcpInitializeResult(r, request.Params)
	case "ping":
		response.Result = map[string]any{}
	case "tools/list":
		result, err := mcpPaginatedResult(mcpTools(), request.Params, "tools")
		if err != nil {
			response.Error = &mcpError{Code: -32602, Message: err.Error()}
			return response
		}
		response.Result = result
	case "tools/call":
		result, err := app.mcpCallTool(r, request.Params)
		if err != nil {
			response.Error = &mcpError{Code: -32602, Message: err.Error()}
			return response
		}
		response.Result = result
	case "resources/list":
		result, err := mcpPaginatedResult(mcpResources(), request.Params, "resources")
		if err != nil {
			response.Error = &mcpError{Code: -32602, Message: err.Error()}
			return response
		}
		response.Result = result
	case "resources/templates/list":
		result, err := mcpPaginatedResult(mcpResourceTemplates(), request.Params, "resourceTemplates")
		if err != nil {
			response.Error = &mcpError{Code: -32602, Message: err.Error()}
			return response
		}
		response.Result = result
	case "resources/read":
		result, err := app.mcpReadResource(r, request.Params)
		if err != nil {
			response.Error = &mcpError{Code: -32602, Message: safeMCPToolError(err)}
			return response
		}
		response.Result = result
	case "prompts/list":
		result, err := mcpPaginatedResult(mcpPrompts(), request.Params, "prompts")
		if err != nil {
			response.Error = &mcpError{Code: -32602, Message: err.Error()}
			return response
		}
		response.Result = result
	case "prompts/get":
		result, err := app.mcpGetPrompt(r, request.Params)
		if err != nil {
			response.Error = &mcpError{Code: -32602, Message: err.Error()}
			return response
		}
		response.Result = result
	case "notifications/initialized":
		response.Result = map[string]any{}
	default:
		response.Error = &mcpError{Code: -32601, Message: "method not found"}
	}
	return response
}

func authorizeMCPMethodScope(ctx context.Context, method string) error {
	switch strings.TrimSpace(method) {
	case "initialize", "ping", "notifications/initialized":
		return nil
	case "tools/list", "tools/call", "resources/list", "resources/templates/list", "resources/read", "prompts/list", "prompts/get":
		return authorizeMCPReadScope(ctx)
	default:
		if strings.TrimSpace(method) == "" {
			return nil
		}
		return authorizeMCPReadScope(ctx)
	}
}

func authorizeMCPToolScope(ctx context.Context, _ string) error {
	return authorizeMCPReadScope(ctx)
}

func authorizeMCPResourceScope(ctx context.Context, _ string) error {
	return authorizeMCPReadScope(ctx)
}

func authorizeMCPReadScope(ctx context.Context) error {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	if !ok || !principalScopeRestricted(auth.principal) {
		return nil
	}
	return authorizePrincipalScope(auth.principal, scopeCosmoSecurityRead)
}

func (app *App) mcpInitializeResult(r *http.Request, rawParams json.RawMessage) map[string]any {
	return map[string]any{
		"protocolVersion": mcpNegotiatedProtocolVersion(r, rawParams),
		"capabilities": map[string]any{
			"tools":     map[string]any{"listChanged": false},
			"resources": map[string]any{"subscribe": false, "listChanged": false},
			"prompts":   map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":        buildinfo.ServiceName,
			"title":       "Cerebro",
			"version":     buildinfo.Version,
			"description": "Writer security graph and findings MCP server. POST requests are stateless.",
		},
	}
}

func (app *App) mcpCallTool(r *http.Request, rawParams json.RawMessage) (mcpToolResult, error) {
	var params mcpToolCallParams
	if err := decodeMCPJSON(rawParams, &params); err != nil {
		return mcpToolResult{}, fmt.Errorf("invalid tool call params")
	}
	args := map[string]any{}
	if len(params.Arguments) != 0 {
		if err := decodeMCPJSON(params.Arguments, &args); err != nil {
			return mcpToolResult{}, fmt.Errorf("invalid tool arguments")
		}
	}
	name := strings.TrimSpace(params.Name)
	if err := authorizeMCPToolScope(r.Context(), name); err != nil {
		return mcpErrorToolResult(safeMCPToolError(err)), nil
	}
	structured, err := app.mcpToolStructuredContent(r, name, args)
	if err != nil {
		return mcpErrorToolResult(safeMCPToolError(err)), nil
	}
	return mcpSuccessToolResult(structured)
}

func (app *App) mcpToolStructuredContent(r *http.Request, name string, args map[string]any) (any, error) {
	switch name {
	case "cerebro.health":
		return protoJSONValue(healthResponse(r.Context(), app.cfg, app.deps))
	case "cerebro.version":
		return protoJSONValue(&cerebrov1.GetVersionResponse{
			ServiceName: buildinfo.ServiceName,
			Version:     buildinfo.Version,
			Commit:      buildinfo.Commit,
			BuildDate:   buildinfo.BuildDate,
			ApiVersion:  buildinfo.APIVersion,
		})
	case "cerebro.source_runtimes.list":
		return app.mcpListSourceRuntimes(r, args)
	case "cerebro.connector_definitions.list":
		return app.mcpListConnectorDefinitions(r, args)
	case "cerebro.connector_definitions.validate":
		return app.mcpValidateConnectorDefinition(r, args)
	case "cerebro.findings.list":
		return app.mcpListFindings(r, args)
	case "cerebro.findings.get":
		return app.mcpGetFinding(r, args)
	case "cerebro.findings.search":
		return app.mcpSearchFindings(r, args)
	case "cerebro.runtimes.status":
		return app.mcpRuntimeStatus(r, args)
	case "cerebro.evidence.list":
		return app.mcpListEvidence(r, args)
	case "cerebro.evidence.get":
		return app.mcpGetEvidence(r, args)
	case "cerebro.assets.search":
		return app.mcpSearchAssets(r, args)
	case "cerebro.assets.get":
		return app.mcpGetAsset(r, args)
	case "cerebro.risk.summary":
		return app.mcpRiskSummary(r, args)
	case "cerebro.risk.actions.list":
		return app.mcpRiskActionsList(r, args)
	case "cerebro.risk.actions.explain":
		return app.mcpRiskActionsExplain(r, args)
	case "cerebro.graph.neighborhood":
		return app.mcpGraphNeighborhood(r, args)
	case "cerebro.graph.impact":
		return app.mcpGraphImpact(r, args)
	case "cerebro.graph.paths":
		return app.mcpGraphPaths(r, args)
	case "cerebro.agent.preflight":
		return app.mcpAgentPreflight(r, args)
	case "cerebro.graph.reason":
		return app.mcpGraphReason(r, args)
	case "cerebro.investigation.context":
		return app.mcpInvestigationContext(r, args)
	case "cerebro.findings.action.propose":
		return app.mcpProposeFindingAction(r, args)
	case "cerebro.source_runtimes.refresh.propose":
		return app.mcpProposeRuntimeRefresh(r, args)
	default:
		return nil, fmt.Errorf("%w: unknown tool %q", errInvalidHTTPRequest, name)
	}
}

func (app *App) mcpListSourceRuntimes(r *http.Request, args map[string]any) (any, error) {
	limit, err := mcpBoundedLimit(args, "limit", defaultMCPListLimit, maxMCPListLimit)
	if err != nil {
		return nil, err
	}
	filter := ports.SourceRuntimeFilter{
		RuntimeID: mcpStringArg(args, "runtime_id"),
		TenantID:  mcpStringArg(args, "tenant_id"),
		SourceID:  mcpStringArg(args, "source_id"),
		Limit:     boundedUint32(limit),
	}
	if filter.TenantID == "" {
		if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok && strings.TrimSpace(auth.principal.TenantID) != "" {
			filter.TenantID = strings.TrimSpace(auth.principal.TenantID)
		}
	}
	if filter.TenantID == "" && filter.RuntimeID != "" && requiresTenantFilter(r.Context()) {
		store := sourceRuntimeStore(app.deps.StateStore)
		if store == nil {
			return nil, sourceruntime.ErrRuntimeUnavailable
		}
		runtime, err := store.GetSourceRuntime(r.Context(), filter.RuntimeID)
		if errors.Is(err, ports.ErrSourceRuntimeNotFound) {
			return map[string]any{"runtimes": []any{}, "metadata": mcpResponseMetadata(limit, 0, nil)}, nil
		}
		if err != nil {
			return nil, err
		}
		if !tenantAllowedByContext(r.Context(), runtime.GetTenantId()) {
			return map[string]any{"runtimes": []any{}, "metadata": mcpResponseMetadata(limit, 0, nil)}, nil
		}
		filter.TenantID = strings.TrimSpace(runtime.GetTenantId())
	}
	if filter.TenantID == "" && filter.RuntimeID == "" && requiresTenantFilter(r.Context()) {
		return nil, errTenantForbidden
	}
	if err := authorizeTenantID(r.Context(), filter.TenantID); err != nil {
		return nil, err
	}
	runtimes, err := app.runtimeService().List(r.Context(), filter)
	if err != nil {
		return nil, err
	}
	values := make([]any, 0, len(runtimes))
	for _, runtime := range runtimes {
		value, err := protoJSONValue(redactSourceRuntime(runtime))
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return map[string]any{
		"runtimes": values,
		"metadata": mcpResponseMetadata(limit, len(values), nil),
	}, nil
}

func (app *App) mcpListConnectorDefinitions(r *http.Request, args map[string]any) (any, error) {
	limit, err := mcpBoundedLimit(args, "limit", defaultMCPListLimit, maxMCPListLimit)
	if err != nil {
		return nil, err
	}
	tenantID := mcpTenantArg(r, args)
	if tenantID == "" && requiresTenantFilter(r.Context()) {
		return nil, errTenantForbidden
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		return nil, err
	}
	store := connectorDefinitionStore(app.deps.StateStore)
	if store == nil {
		return nil, sourceruntime.ErrRuntimeUnavailable
	}
	records, err := store.ListConnectorDefinitions(r.Context(), ports.ConnectorDefinitionFilter{
		TenantID: tenantID,
		Stage:    mcpStringArg(args, "stage"),
		Limit:    boundedUint32(limit),
	})
	if err != nil {
		return nil, err
	}
	definitions := make([]any, 0, len(records))
	for _, record := range records {
		definition, err := connectorDefinitionFromRecord(record)
		if err != nil {
			return nil, err
		}
		if err := authorizeTenantID(r.Context(), definition.TenantID); err != nil {
			return nil, err
		}
		definitions = append(definitions, definition)
	}
	return map[string]any{
		"definitions": definitions,
		"metadata":    mcpResponseMetadata(limit, len(definitions), nil),
	}, nil
}

func (app *App) mcpValidateConnectorDefinition(r *http.Request, args map[string]any) (any, error) {
	rawDefinition, ok := args["definition"]
	if !ok {
		return nil, fmt.Errorf("%w: definition is required", errInvalidHTTPRequest)
	}
	payload, err := json.Marshal(rawDefinition)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid definition", errInvalidHTTPRequest)
	}
	definition := connectordefinitions.Definition{}
	if err := json.Unmarshal(payload, &definition); err != nil {
		return nil, fmt.Errorf("%w: invalid definition", errInvalidHTTPRequest)
	}
	tenantID := mcpTenantArg(r, map[string]any{"tenant_id": definition.TenantID})
	if tenantID == "" && requiresTenantFilter(r.Context()) {
		return nil, errTenantForbidden
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		return nil, err
	}
	definition.TenantID = tenantID
	normalized, err := connectordefinitions.Normalize(definition)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidHTTPRequest, err)
	}
	support, err := connectordefinitions.Classify(normalized, connectordefinitions.DefaultGrammar())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidHTTPRequest, err)
	}
	return map[string]any{
		"definition": normalized,
		"validation": normalized.Validation,
		"promotion":  normalized.Promotion,
		"support":    support,
		"metadata":   mcpResponseMetadata(0, 1, nil),
	}, nil
}

func (app *App) mcpListFindings(r *http.Request, args map[string]any) (any, error) {
	runtimeID := mcpStringArg(args, "runtime_id")
	if strings.TrimSpace(runtimeID) == "" {
		return nil, fmt.Errorf("%w: runtime_id is required", findingdomain.ErrInvalidRequest)
	}
	status := ""
	if rawStatus := mcpStringArg(args, "status"); rawStatus != "" {
		parsed, err := parseFindingStatus(rawStatus)
		if err != nil {
			return nil, err
		}
		status = findingStatusString(parsed)
	}
	order := ports.FindingOrder("")
	if rawOrder := mcpStringArg(args, "order"); rawOrder != "" {
		parsed, err := parseFindingOrder(rawOrder)
		if err != nil {
			return nil, err
		}
		order = findingOrder(parsed)
	}
	limit, err := mcpBoundedLimit(args, "limit", defaultMCPListLimit, maxMCPListLimit)
	if err != nil {
		return nil, err
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(app.deps.StateStore), runtimeID); err != nil {
		return nil, mcpNormalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound)
	}
	response, err := app.findingService().ListFindings(r.Context(), findingdomain.ListRequest{
		RuntimeID:   runtimeID,
		FindingID:   mcpStringArg(args, "finding_id"),
		RuleID:      mcpStringArg(args, "rule_id"),
		Severity:    mcpStringArg(args, "severity"),
		Status:      status,
		ResourceURN: mcpStringArg(args, "resource_urn"),
		EventID:     mcpStringArg(args, "event_id"),
		PolicyID:    mcpStringArg(args, "policy_id"),
		Limit:       boundedUint32(limit),
		Order:       order,
	})
	if err != nil {
		return nil, err
	}
	values, err := mcpSafeFindingValues(response.Findings)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"findings": values,
		"metadata": mcpResponseMetadata(limit, len(values), nil),
	}, nil
}

func (app *App) mcpGetFinding(r *http.Request, args map[string]any) (any, error) {
	findingID := mcpStringArg(args, "finding_id")
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding_id is required", findingdomain.ErrInvalidRequest)
	}
	if err := authorizeFindingIDTenant(r.Context(), findingStore(app.deps.StateStore), findingID); err != nil {
		return nil, mcpNormalizeIDLookupError(err, ports.ErrFindingNotFound)
	}
	finding, err := app.findingService().GetFinding(r.Context(), findingID)
	if err != nil {
		return nil, err
	}
	value, err := mcpSafeFindingValue(finding)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"finding":  value,
		"metadata": mcpResponseMetadata(0, 1, nil),
	}, nil
}

func (app *App) mcpSearchFindings(r *http.Request, args map[string]any) (any, error) {
	runtimeID := mcpStringArg(args, "runtime_id")
	tenantID := mcpTenantArg(r, args)
	limit, err := mcpBoundedLimit(args, "limit", defaultMCPListLimit, maxMCPListLimit)
	if err != nil {
		return nil, err
	}
	status := ""
	if rawStatus := mcpStringArg(args, "status"); rawStatus != "" {
		parsed, err := parseFindingStatus(rawStatus)
		if err != nil {
			return nil, err
		}
		status = findingStatusString(parsed)
	}
	if runtimeID != "" {
		if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(app.deps.StateStore), runtimeID); err != nil {
			return nil, mcpNormalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound)
		}
	}
	if tenantID == "" && runtimeID == "" && requiresTenantFilter(r.Context()) {
		return nil, errTenantForbidden
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		return nil, err
	}
	records, err := app.mcpListRiskFindings(r, ports.ListFindingsRequest{
		TenantID:    tenantID,
		RuntimeID:   runtimeID,
		RuleID:      mcpStringArg(args, "rule_id"),
		Severity:    mcpStringArg(args, "severity"),
		Status:      status,
		ResourceURN: mcpStringArg(args, "resource_urn"),
		EventID:     mcpStringArg(args, "event_id"),
		PolicyID:    mcpStringArg(args, "policy_id"),
		Limit:       boundedUint32(limit),
		Order:       ports.FindingOrderRiskScore,
	})
	if err != nil {
		return nil, err
	}
	query := strings.ToLower(mcpStringArg(args, "query"))
	if query != "" {
		filtered := records[:0]
		for _, finding := range records {
			if mcpFindingMatchesQuery(finding, query) {
				filtered = append(filtered, finding)
			}
		}
		records = filtered
	}
	values, err := mcpSafeFindingValues(records)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"findings": values,
		"metadata": mcpResponseMetadata(limit, len(values), nil),
	}, nil
}

func (app *App) mcpRuntimeStatus(r *http.Request, args map[string]any) (any, error) {
	runtimeID := mcpStringArg(args, "runtime_id")
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: runtime_id is required", sourceruntime.ErrInvalidRequest)
	}
	runtimeStore := sourceRuntimeStore(app.deps.StateStore)
	if runtimeStore == nil {
		return nil, sourceruntime.ErrRuntimeUnavailable
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), runtimeStore, runtimeID); err != nil {
		return nil, mcpNormalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound)
	}
	runtime, err := runtimeStore.GetSourceRuntime(r.Context(), runtimeID)
	if err != nil {
		return nil, err
	}
	runtimeValue, err := protoJSONValue(redactSourceRuntime(runtime))
	if err != nil {
		return nil, err
	}
	findings, err := app.mcpListRiskFindings(r, ports.ListFindingsRequest{
		TenantID:  strings.TrimSpace(runtime.GetTenantId()),
		RuntimeID: runtimeID,
		Limit:     uint32(defaultMCPRiskLimit),
		Order:     ports.FindingOrderRiskScore,
	})
	if err != nil {
		return nil, err
	}
	summary, err := app.mcpBuildRiskSummaryForRequest(r, ports.ListFindingsRequest{
		TenantID:  strings.TrimSpace(runtime.GetTenantId()),
		RuntimeID: runtimeID,
		Limit:     uint32(defaultMCPRiskLimit),
		Order:     ports.FindingOrderRiskScore,
	}, defaultMCPRiskLimit, findings)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"runtime":      runtimeValue,
		"risk_summary": summary,
		"metadata":     mcpResponseMetadata(defaultMCPRiskLimit, len(findings), nil),
	}, nil
}

func (app *App) mcpListEvidence(r *http.Request, args map[string]any) (any, error) {
	runtimeID := mcpStringArg(args, "runtime_id")
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: runtime_id is required", findingdomain.ErrInvalidRequest)
	}
	limit, err := mcpBoundedLimit(args, "limit", defaultMCPEvidenceLimit, maxMCPEvidenceLimit)
	if err != nil {
		return nil, err
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(app.deps.StateStore), runtimeID); err != nil {
		return nil, mcpNormalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound)
	}
	response, err := app.findingService().ListEvidence(r.Context(), findingdomain.ListEvidenceRequest{
		RuntimeID:    runtimeID,
		FindingID:    mcpStringArg(args, "finding_id"),
		RunID:        mcpStringArg(args, "run_id"),
		RuleID:       mcpStringArg(args, "rule_id"),
		ClaimID:      mcpStringArg(args, "claim_id"),
		EventID:      mcpStringArg(args, "event_id"),
		GraphRootURN: mcpStringArg(args, "graph_root_urn"),
		GraphPathURN: mcpStringArg(args, "graph_path_urn"),
		Limit:        boundedUint32(limit),
	})
	if err != nil {
		return nil, err
	}
	values, err := mcpSafeFindingEvidenceValues(response.Evidence)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"evidence": values,
		"metadata": mcpResponseMetadata(limit, len(values), nil),
	}, nil
}

func (app *App) mcpGetEvidence(r *http.Request, args map[string]any) (any, error) {
	evidenceID := mcpStringArg(args, "evidence_id")
	if evidenceID == "" {
		return nil, fmt.Errorf("%w: evidence_id is required", findingdomain.ErrInvalidRequest)
	}
	evidence, err := app.findingService().GetEvidence(r.Context(), evidenceID)
	if err != nil {
		return nil, err
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(app.deps.StateStore), evidence.GetRuntimeId()); err != nil {
		return nil, mcpNormalizeIDLookupError(err, ports.ErrFindingEvidenceNotFound)
	}
	value, err := mcpSafeFindingEvidenceValue(evidence)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"evidence": value,
		"metadata": mcpResponseMetadata(0, 1, nil),
	}, nil
}

func (app *App) mcpSearchAssets(r *http.Request, args map[string]any) (any, error) {
	assets, err := app.mcpAssetSearchResults(r, args)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"assets":   assets,
		"metadata": mcpResponseMetadata(mcpMetadataLimit(args, "limit", defaultMCPAssetLimit, maxMCPAssetLimit), len(assets), nil),
	}, nil
}

func (app *App) mcpGetAsset(r *http.Request, args map[string]any) (any, error) {
	urn := mcpStringArg(args, "urn")
	if urn == "" {
		return nil, fmt.Errorf("%w: urn is required", graphquery.ErrInvalidRequest)
	}
	scoped := map[string]any{"urn": urn, "limit": 1}
	assets, err := app.mcpAssetSearchResults(r, scoped)
	if err != nil {
		return nil, err
	}
	if len(assets) == 0 {
		return nil, ports.ErrGraphEntityNotFound
	}
	return map[string]any{
		"asset":    assets[0],
		"metadata": mcpResponseMetadata(0, 1, nil),
	}, nil
}

func (app *App) mcpAssetSearchResults(r *http.Request, args map[string]any) ([]mcpAssetSearchResult, error) {
	query := mcpStringArg(args, "query")
	urn := mcpStringArg(args, "urn")
	tenantID := mcpTenantArg(r, args)
	entityType := mcpStringArg(args, "entity_type")
	runtimeID := mcpStringArg(args, "runtime_id")
	limit, err := mcpBoundedLimit(args, "limit", defaultMCPAssetLimit, maxMCPAssetLimit)
	if err != nil {
		return nil, err
	}
	if urn == "" && query == "" && entityType == "" && runtimeID == "" {
		return nil, fmt.Errorf("%w: at least one of query, urn, entity_type, or runtime_id is required", graphquery.ErrInvalidRequest)
	}
	if urn != "" {
		if err := authorizeCerebroURNTenant(r.Context(), urn); err != nil {
			return nil, mcpNormalizeIDLookupError(err, ports.ErrGraphEntityNotFound)
		}
		if tenantID == "" {
			tenantID = cerebroURNTenant(urn)
		}
	}
	if runtimeID != "" {
		if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(app.deps.StateStore), runtimeID); err != nil {
			return nil, mcpNormalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound)
		}
	}
	if tenantID == "" && requiresTenantFilter(r.Context()) {
		return nil, errTenantForbidden
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		return nil, err
	}
	store := graphQueryStore(app.deps.GraphStore)
	if store == nil {
		return nil, graphquery.ErrRuntimeUnavailable
	}
	rows, err := store.ExecuteReadCypher(r.Context(), ports.CypherQueryRequest{
		Query: `MATCH (e:Entity)
WHERE ($tenant_id = '' OR e.tenant_id = $tenant_id)
  AND ($runtime_id = '' OR coalesce(e.runtime_id, '') = $runtime_id)
  AND ($urn = '' OR e.urn = $urn)
  AND ($entity_type = '' OR e.entity_type = $entity_type)
  AND ($query = '' OR toLower(coalesce(e.urn, '')) CONTAINS $query OR toLower(coalesce(e.label, '')) CONTAINS $query)
RETURN e.urn AS urn,
       coalesce(e.tenant_id, '') AS tenant_id,
       coalesce(e.runtime_id, '') AS runtime_id,
       coalesce(e.source_id, '') AS source_id,
       coalesce(e.entity_type, '') AS entity_type,
       coalesce(e.label, '') AS label,
       coalesce(e.attributes_json, '{}') AS attributes_json
ORDER BY e.entity_type, e.label, e.urn`,
		Params: map[string]any{
			"tenant_id":   tenantID,
			"runtime_id":  runtimeID,
			"urn":         urn,
			"entity_type": entityType,
			"query":       strings.ToLower(query),
		},
		RowLimit: limit,
	})
	if err != nil {
		return nil, err
	}
	assets := make([]mcpAssetSearchResult, 0, len(rows))
	for _, row := range rows {
		asset, err := mcpAssetSearchResultFromRow(row)
		if err != nil {
			return nil, err
		}
		if !tenantAllowedByContext(r.Context(), asset.TenantID) {
			continue
		}
		assets = append(assets, asset)
	}
	return assets, nil
}

func (app *App) mcpRiskSummary(r *http.Request, args map[string]any) (any, error) {
	runtimeID := mcpStringArg(args, "runtime_id")
	tenantID := mcpTenantArg(r, args)
	limit, err := mcpBoundedLimit(args, "limit", defaultMCPRiskLimit, maxMCPRiskLimit)
	if err != nil {
		return nil, err
	}
	if runtimeID != "" {
		runtimeStore := sourceRuntimeStore(app.deps.StateStore)
		if err := authorizeSourceRuntimeIDTenant(r.Context(), runtimeStore, runtimeID); err != nil {
			return nil, mcpNormalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound)
		}
		if tenantID == "" {
			runtime, err := runtimeStore.GetSourceRuntime(r.Context(), runtimeID)
			if err != nil {
				return nil, err
			}
			tenantID = strings.TrimSpace(runtime.GetTenantId())
		}
	}
	if tenantID == "" && runtimeID == "" && requiresTenantFilter(r.Context()) {
		return nil, errTenantForbidden
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		return nil, err
	}
	findings, err := app.mcpListRiskFindings(r, ports.ListFindingsRequest{
		TenantID:  tenantID,
		RuntimeID: runtimeID,
		Status:    mcpStringArg(args, "status"),
		Limit:     boundedUint32(limit),
		Order:     ports.FindingOrderRiskScore,
	})
	if err != nil {
		return nil, err
	}
	summary, err := app.mcpBuildRiskSummaryForRequest(r, ports.ListFindingsRequest{
		TenantID:  tenantID,
		RuntimeID: runtimeID,
		Status:    mcpStringArg(args, "status"),
		Limit:     boundedUint32(limit),
		Order:     ports.FindingOrderRiskScore,
	}, limit, findings)
	if err != nil {
		return nil, err
	}
	return summary, nil
}

type mcpRiskActionPlanResult struct {
	Plan                   riskplan.Plan
	Limit                  int
	FindingLimit           int
	GraphEvidenceStatus    string
	GraphNeighborhoodCount int
	PartialErrors          []string
}

func (app *App) mcpRiskActionsList(r *http.Request, args map[string]any) (any, error) {
	result, err := app.mcpBuildRiskActionPlan(r, args)
	if err != nil {
		return nil, err
	}
	planValue, err := jsonValue(result.Plan)
	if err != nil {
		return nil, err
	}
	candidatesValue, err := jsonValue(result.Plan.ActionCandidates)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"plan":                     planValue,
		"action_candidates":        candidatesValue,
		"graph_evidence_status":    result.GraphEvidenceStatus,
		"graph_neighborhood_count": result.GraphNeighborhoodCount,
		"metadata":                 mcpResponseMetadata(result.Limit, len(result.Plan.ActionCandidates), result.PartialErrors),
	}, nil
}

func (app *App) mcpRiskActionsExplain(r *http.Request, args map[string]any) (any, error) {
	candidateID := mcpStringArg(args, "candidate_id")
	if candidateID == "" {
		return nil, fmt.Errorf("%w: candidate_id is required", findingdomain.ErrInvalidRequest)
	}
	result, err := app.mcpBuildRiskActionPlan(r, args)
	if err != nil {
		return nil, err
	}
	for _, candidate := range result.Plan.ActionCandidates {
		if candidate.ID != candidateID {
			continue
		}
		candidateValue, err := jsonValue(candidate)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"candidate":                candidateValue,
			"score_breakdown":          candidate.ScoreBreakdown,
			"expected_reduction":       candidate.ExpectedReduction,
			"effort":                   candidate.Effort,
			"ownership":                candidate.Ownership,
			"evidence":                 candidate.Evidence,
			"outcome_learning":         candidate.OutcomeLearning,
			"risk_delta":               candidate.RiskDelta,
			"plan_model_version":       result.Plan.ModelVersion,
			"graph_evidence_status":    result.GraphEvidenceStatus,
			"graph_neighborhood_count": result.GraphNeighborhoodCount,
			"metadata":                 mcpResponseMetadata(result.Limit, 1, result.PartialErrors),
		}, nil
	}
	return nil, fmt.Errorf("%w: risk action candidate %q not found", ports.ErrFindingNotFound, candidateID)
}

func (app *App) mcpBuildRiskActionPlan(r *http.Request, args map[string]any) (mcpRiskActionPlanResult, error) {
	tenantID := mcpTenantArg(r, args)
	runtimeIDs := mcpRuntimeIDsArg(args)
	limit, err := mcpBoundedLimit(args, "limit", riskplan.DefaultCandidateLimit, riskplan.MaxCandidateLimit)
	if err != nil {
		return mcpRiskActionPlanResult{}, err
	}
	findingLimit, err := mcpBoundedLimit(args, "finding_limit", defaultMCPRiskLimit, maxMCPRiskLimit)
	if err != nil {
		return mcpRiskActionPlanResult{}, err
	}
	rootLimit, err := mcpBoundedLimit(args, "resource_limit", defaultMCPRiskActionRoots, maxMCPRiskActionRoots)
	if err != nil {
		return mcpRiskActionPlanResult{}, err
	}
	graphLimit, err := mcpBoundedLimit(args, "graph_limit", defaultMCPRiskActionGraph, maxMCPRiskActionGraph)
	if err != nil {
		return mcpRiskActionPlanResult{}, err
	}
	status := mcpStringArg(args, "status")
	if status != "" {
		parsed, err := parseFindingStatus(status)
		if err != nil {
			return mcpRiskActionPlanResult{}, err
		}
		status = findingStatusString(parsed)
	}
	if len(runtimeIDs) > 0 {
		runtimeStore := sourceRuntimeStore(app.deps.StateStore)
		runtimeTenantID := ""
		mixedRuntimeTenants := false
		for _, runtimeID := range runtimeIDs {
			resolvedTenantID, err := sourceRuntimeTenantID(r.Context(), runtimeStore, runtimeID, false)
			if err != nil {
				return mcpRiskActionPlanResult{}, mcpNormalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound)
			}
			if tenantID != "" || resolvedTenantID == "" {
				continue
			}
			if runtimeTenantID == "" {
				runtimeTenantID = resolvedTenantID
				continue
			}
			if runtimeTenantID != resolvedTenantID {
				mixedRuntimeTenants = true
			}
		}
		if tenantID == "" && !mixedRuntimeTenants {
			tenantID = runtimeTenantID
		}
	}
	if tenantID == "" && len(runtimeIDs) == 0 && requiresTenantFilter(r.Context()) {
		return mcpRiskActionPlanResult{}, errTenantForbidden
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		return mcpRiskActionPlanResult{}, err
	}
	store := findingStore(app.deps.StateStore)
	if store == nil {
		return mcpRiskActionPlanResult{}, findingdomain.ErrRuntimeUnavailable
	}
	listRequest := ports.ListFindingsRequest{
		TenantID: tenantID,
		Status:   status,
		Limit:    boundedUint32(findingLimit),
		Order:    ports.FindingOrderRiskScore,
	}
	if len(runtimeIDs) == 1 {
		listRequest.RuntimeID = runtimeIDs[0]
	} else if len(runtimeIDs) > 1 {
		listRequest.RuntimeIDs = runtimeIDs
	}
	findings, err := store.ListFindings(r.Context(), listRequest)
	if err != nil {
		return mcpRiskActionPlanResult{}, err
	}
	filtered := findings[:0]
	for _, finding := range findings {
		if finding == nil || !tenantAllowedByContext(r.Context(), finding.TenantID) {
			continue
		}
		filtered = append(filtered, finding)
	}
	findings = filtered

	graphEvidenceStatus := mcpGraphEvidenceUnconfigured
	graphNeighborhoods := map[string]*ports.EntityNeighborhood{}
	partialErrors := []string{}
	now := time.Now().UTC()
	if graphStore := graphQueryStore(app.deps.GraphStore); graphStore != nil {
		graphEvidenceStatus = mcpGraphEvidenceIncluded
		targetURNs := riskplan.TargetURNs(findings, riskplan.Options{
			TenantID:        tenantID,
			RuntimeIDs:      runtimeIDs,
			SeedLimit:       riskplan.MaxSimulationSeedLimit,
			Now:             now,
			IncludeUnscored: mcpBoolArg(args, "include_unscored"),
		})
		seen := map[string]struct{}{}
		roots := []string{}
		for _, targetURN := range targetURNs {
			if len(seen) >= rootLimit {
				break
			}
			targetURN = strings.TrimSpace(targetURN)
			if targetURN == "" {
				continue
			}
			if _, ok := seen[targetURN]; ok {
				continue
			}
			seen[targetURN] = struct{}{}
			roots = append(roots, targetURN)
		}
		for _, result := range fetchMCPGraphStoreNeighborhoods(r.Context(), graphStore, roots, graphLimit) {
			switch {
			case result.err == nil:
				neighborhood := result.neighborhood
				if neighborhood == nil {
					neighborhood = &ports.EntityNeighborhood{}
				}
				graphNeighborhoods[result.urn] = neighborhood
			case errors.Is(result.err, ports.ErrGraphEntityNotFound):
				continue
			default:
				partialErrors = append(partialErrors, "graph neighborhood failed for "+result.urn+": "+safeMCPToolError(result.err))
			}
		}
	}
	plan := riskplan.Analyze(findings, riskplan.Options{
		TenantID:           tenantID,
		RuntimeIDs:         runtimeIDs,
		CandidateLimit:     limit,
		SeedLimit:          riskplan.MaxSimulationSeedLimit,
		GraphNeighborhoods: graphNeighborhoods,
		Now:                now,
		IncludeUnscored:    mcpBoolArg(args, "include_unscored"),
	})
	return mcpRiskActionPlanResult{
		Plan:                   plan,
		Limit:                  limit,
		FindingLimit:           findingLimit,
		GraphEvidenceStatus:    graphEvidenceStatus,
		GraphNeighborhoodCount: len(graphNeighborhoods),
		PartialErrors:          partialErrors,
	}, nil
}

func (app *App) mcpGraphNeighborhood(r *http.Request, args map[string]any) (any, error) {
	rootURN := mcpStringArg(args, "root_urn")
	limit, err := mcpUint32Arg(args, "limit")
	if err != nil {
		return nil, err
	}
	limitApplied := mcpNormalizeLimitValue(limit, defaultMCPNeighborhoodLimit, maxMCPNeighborhoodLimit)
	if err := authorizeCerebroURNTenant(r.Context(), rootURN); err != nil {
		return nil, mcpNormalizeIDLookupError(err, ports.ErrGraphEntityNotFound)
	}
	response, err := app.graphQueryService().GetEntityNeighborhood(r.Context(), graphquery.NeighborhoodRequest{
		RootURN: rootURN,
		Limit:   boundedUint32(limitApplied),
	})
	if err != nil {
		return nil, err
	}
	value, err := protoJSONValue(graphNeighborhoodResponse(response))
	if err != nil {
		return nil, err
	}
	return mcpAddResponseMetadata(value, mcpResponseMetadata(limitApplied, mcpNeighborhoodResultCount(response), nil)), nil
}

func (app *App) mcpGraphImpact(r *http.Request, args map[string]any) (any, error) {
	kind := mcpStringArg(args, "kind")
	if kind == "" {
		kind = graphquery.ImpactKindAsset
	}
	request := graphquery.ImpactRequest{
		Kind:       kind,
		TenantID:   mcpTenantArg(r, args),
		Identifier: mcpStringArg(args, "identifier"),
		RootURN:    mcpStringArg(args, "root_urn"),
	}
	limit, err := mcpUint32Arg(args, "limit")
	if err != nil {
		return nil, err
	}
	depth, err := mcpUint32Arg(args, "depth")
	if err != nil {
		return nil, err
	}
	limitApplied := mcpNormalizeLimitValue(limit, defaultMCPImpactLimit, maxMCPImpactLimit)
	request.Limit = boundedUint32(limitApplied)
	request.Depth = depth
	if request.RootURN != "" {
		if err := authorizeCerebroURNTenant(r.Context(), request.RootURN); err != nil {
			return nil, mcpNormalizeIDLookupError(err, ports.ErrGraphEntityNotFound)
		}
		if request.TenantID == "" {
			request.TenantID = cerebroURNTenant(request.RootURN)
		}
	}
	if request.RootURN == "" && mcpImpactKindIsAsset(request.Kind) && strings.HasPrefix(strings.TrimSpace(request.Identifier), "urn:cerebro:") {
		if err := authorizeCerebroURNTenant(r.Context(), request.Identifier); err != nil {
			return nil, mcpNormalizeIDLookupError(err, ports.ErrGraphEntityNotFound)
		}
		if request.TenantID == "" {
			request.TenantID = cerebroURNTenant(request.Identifier)
		}
	}
	if request.TenantID == "" && requiresTenantFilter(r.Context()) {
		return nil, errTenantForbidden
	}
	if err := authorizeTenantID(r.Context(), request.TenantID); err != nil {
		return nil, err
	}
	result, err := app.graphQueryService().GetImpact(r.Context(), request)
	if err != nil {
		return nil, err
	}
	value, err := jsonValue(mcpSafeImpactResult(result))
	if err != nil {
		return nil, err
	}
	return mcpAddResponseMetadata(value, mcpResponseMetadata(limitApplied, mcpImpactResultCount(result), nil)), nil
}

func (app *App) mcpGraphPaths(r *http.Request, args map[string]any) (any, error) {
	tenantID := mcpTenantArg(r, args)
	if tenantID == "" && requiresTenantFilter(r.Context()) {
		return nil, errTenantForbidden
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		return nil, err
	}
	limit, err := mcpUint32Arg(args, "limit")
	if err != nil {
		return nil, err
	}
	limitApplied := mcpNormalizeLimitValue(limit, defaultMCPGraphLimit, maxMCPGraphLimit)
	result, err := app.graphQueryService().GetAttackPaths(r.Context(), graphquery.AttackPathRequest{
		TenantID:  tenantID,
		AccountID: mcpStringArg(args, "account_id"),
		Limit:     boundedUint32(limitApplied),
	})
	if err != nil {
		return nil, err
	}
	value, err := jsonValue(result)
	if err != nil {
		return nil, err
	}
	return mcpAddResponseMetadata(value, mcpResponseMetadata(limitApplied, mcpMapArrayCount(value, "paths"), nil)), nil
}

func (app *App) mcpGraphReason(r *http.Request, args map[string]any) (any, error) {
	request := graphagent.AskRequest{
		TenantID: mcpStringArg(args, "tenant_id"),
		Question: mcpStringArg(args, "question"),
		ScopeURN: mcpStringArg(args, "scope_urn"),
		Model:    mcpStringArg(args, "model"),
	}
	resolved, err := resolveAgentPlatformRequestContext(r.Context(), request.TenantID, "", nil)
	if err != nil {
		return nil, err
	}
	request.TenantID = resolved.TenantID
	if request.ScopeURN != "" {
		if err := authorizeCerebroURNTenant(r.Context(), request.ScopeURN); err != nil {
			return nil, mcpNormalizeIDLookupError(err, ports.ErrGraphEntityNotFound)
		}
	}
	preflight := agentplatform.PreflightAgentRun(agentplatform.AgentRunPreflightRequest{
		TenantID:              request.TenantID,
		ActorID:               resolved.ActorID,
		CapabilityIDs:         []string{agentplatform.DefaultAgentRunCapabilityID},
		Question:              request.Question,
		ScopeURN:              request.ScopeURN,
		Model:                 request.Model,
		RequestedScopes:       resolved.RequestedScopes,
		ScopeUnrestricted:     resolved.ScopeUnrestricted || !resolved.Authenticated,
		ProvenanceRequirement: "graph-reasoning",
	})
	if !preflight.Enabled {
		return nil, agentPreflightDeniedError(preflight)
	}
	request.PlatformContext = &preflight
	if err := graphagent.ValidateRequest(request); err != nil {
		return nil, err
	}
	service, err := app.newGraphReasoningService()
	if err != nil {
		return nil, err
	}
	response, err := service.Reason(r.Context(), request)
	if err != nil {
		return nil, err
	}
	value, err := jsonValue(response)
	if err != nil {
		return nil, err
	}
	rows := 0
	if typed, ok := value.(map[string]any); ok {
		rows = mcpMapArrayCount(typed, "rows")
		return mcpAddResponseMetadata(typed, mcpResponseMetadata(0, rows, nil)), nil
	}
	return value, nil
}

func (app *App) mcpAgentPreflight(r *http.Request, args map[string]any) (any, error) {
	request := agentplatform.AgentRunPreflightRequest{
		TenantID:              mcpStringArg(args, "tenant_id"),
		ActorID:               mcpStringArg(args, "actor_id"),
		CapabilityIDs:         mcpStringListArg(args, "capability_ids"),
		Question:              mcpStringArg(args, "question"),
		ScopeURN:              mcpStringArg(args, "scope_urn"),
		Model:                 mcpStringArg(args, "model"),
		RequestedScopes:       mcpStringListArg(args, "requested_scopes"),
		ConnectorReadiness:    mcpStringMapArg(args, "connector_readiness"),
		AllowPreview:          mcpBoolArg(args, "allow_preview"),
		SelectionReason:       mcpStringArg(args, "selection_reason"),
		ProvenanceRequirement: mcpStringArg(args, "provenance_requirement"),
	}
	resolved, err := resolveAgentPlatformRequestContext(r.Context(), request.TenantID, request.ActorID, request.RequestedScopes)
	if err != nil {
		return nil, err
	}
	request.TenantID = resolved.TenantID
	request.ActorID = resolved.ActorID
	request.RequestedScopes = resolved.RequestedScopes
	request.ScopeUnrestricted = resolved.ScopeUnrestricted
	if request.ScopeURN != "" {
		if err := authorizeCerebroURNTenant(r.Context(), request.ScopeURN); err != nil {
			return nil, mcpNormalizeIDLookupError(err, ports.ErrGraphEntityNotFound)
		}
	}
	value, err := jsonValue(agentplatform.PreflightAgentRun(request))
	if err != nil {
		return nil, err
	}
	if typed, ok := value.(map[string]any); ok {
		return mcpAddResponseMetadata(typed, mcpResponseMetadata(0, mcpMapArrayCount(typed, "capability_decisions"), nil)), nil
	}
	return value, nil
}

func (app *App) mcpInvestigationContext(r *http.Request, args map[string]any) (any, error) {
	findingID := mcpStringArg(args, "finding_id")
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding_id is required", findingdomain.ErrInvalidRequest)
	}
	if err := authorizeFindingIDTenant(r.Context(), findingStore(app.deps.StateStore), findingID); err != nil {
		return nil, mcpNormalizeIDLookupError(err, ports.ErrFindingNotFound)
	}
	finding, err := app.findingService().GetFinding(r.Context(), findingID)
	if err != nil {
		return nil, err
	}
	limit, err := mcpBoundedLimit(args, "limit", defaultMCPEvidenceLimit, maxMCPEvidenceLimit)
	if err != nil {
		return nil, err
	}
	evidence, err := app.findingService().ListEvidence(r.Context(), findingdomain.ListEvidenceRequest{
		RuntimeID: finding.RuntimeID,
		FindingID: finding.ID,
		Limit:     boundedUint32(limit),
	})
	if err != nil {
		return nil, err
	}
	findingValue, err := mcpSafeFindingValue(finding)
	if err != nil {
		return nil, err
	}
	evidenceValues, err := mcpSafeFindingEvidenceValues(evidence.Evidence)
	if err != nil {
		return nil, err
	}
	evidenceValue := map[string]any{
		"evidence": evidenceValues,
		"metadata": mcpResponseMetadata(limit, len(evidenceValues), nil),
	}
	assetLimit := 5
	if rawLimit, err := mcpUint32Arg(args, "asset_limit"); err != nil {
		return nil, err
	} else if rawLimit > uint32(maxMCPAssetLimit) {
		assetLimit = maxMCPAssetLimit
	} else if rawLimit != 0 {
		assetLimit = int(rawLimit)
	}
	assets := []mcpAssetSearchResult{}
	neighborhoods := []any{}
	partialErrors := []string{}
	includeGraph := !mcpBoolArg(args, "skip_graph")
	resourceURNs := make([]string, 0, len(finding.ResourceURNs))
	seenResourceURNs := map[string]struct{}{}
	for _, resourceURN := range finding.ResourceURNs {
		resourceURN = strings.TrimSpace(resourceURN)
		if resourceURN == "" {
			continue
		}
		if _, ok := seenResourceURNs[resourceURN]; ok {
			continue
		}
		seenResourceURNs[resourceURN] = struct{}{}
		resourceURNs = append(resourceURNs, resourceURN)
	}
	for _, result := range app.fetchMCPInvestigationResources(r.Context(), r, resourceURNs, includeGraph) {
		if len(assets) >= assetLimit {
			continue
		}
		if result.asset != nil {
			assets = append(assets, *result.asset)
		} else if result.assetErr != nil {
			partialErrors = append(partialErrors, "asset lookup failed: "+safeMCPToolError(result.assetErr))
		}
		if result.neighborhood != nil {
			neighborhoods = append(neighborhoods, result.neighborhood)
		} else if result.graphErr != nil {
			partialErrors = append(partialErrors, "graph neighborhood failed: "+safeMCPToolError(result.graphErr))
		} else if result.graphEncodingErr {
			partialErrors = append(partialErrors, "graph neighborhood encoding failed")
		}
	}
	result := map[string]any{
		"finding":        findingValue,
		"evidence":       evidenceValue,
		"assets":         assets,
		"neighborhoods":  neighborhoods,
		"limit_applied":  limit,
		"compact":        mcpBoolArg(args, "compact"),
		"staleness_note": "Context is bounded by requested limits and current graph/finding store freshness.",
		"metadata":       mcpResponseMetadata(limit, len(evidenceValues), partialErrors),
	}
	if mcpBoolArg(args, "compact") {
		result["evidence_count"] = len(evidence.Evidence)
		result["asset_count"] = len(assets)
		result["neighborhood_count"] = len(neighborhoods)
		delete(result, "evidence")
		delete(result, "neighborhoods")
	}
	return result, nil
}

func (app *App) mcpProposeFindingAction(r *http.Request, args map[string]any) (any, error) {
	if !mcpBoolArg(args, "dry_run") {
		return nil, fmt.Errorf("%w: dry_run=true is required for action proposals", errInvalidHTTPRequest)
	}
	findingID := mcpStringArg(args, "finding_id")
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding_id is required", findingdomain.ErrInvalidRequest)
	}
	if err := authorizeFindingIDTenant(r.Context(), findingStore(app.deps.StateStore), findingID); err != nil {
		return nil, mcpNormalizeIDLookupError(err, ports.ErrFindingNotFound)
	}
	finding, err := app.findingService().GetFinding(r.Context(), findingID)
	if err != nil {
		return nil, err
	}
	action := strings.TrimSpace(mcpStringArg(args, "action"))
	switch action {
	case "add_note":
		if mcpStringArg(args, "note") == "" {
			return nil, fmt.Errorf("%w: note is required for add_note", errInvalidHTTPRequest)
		}
	case "update_status":
		if _, err := parseFindingStatus(mcpStringArg(args, "status")); err != nil {
			return nil, err
		}
		if err := findingapi.ValidateOptionalStatus(mcpStringArg(args, "expected_status")); err != nil {
			return nil, err
		}
	case "create_exception":
		if mcpStringArg(args, "reason") == "" {
			return nil, fmt.Errorf("%w: reason is required for create_exception", errInvalidHTTPRequest)
		}
	case "link_ticket":
		if mcpStringArg(args, "ticket_url") == "" && mcpStringArg(args, "ticket_id") == "" {
			return nil, fmt.Errorf("%w: ticket_url or ticket_id is required for link_ticket", errInvalidHTTPRequest)
		}
	case "execute_graph_action":
	default:
		return nil, fmt.Errorf("%w: unsupported action %q", errInvalidHTTPRequest, action)
	}
	proposal := findingapi.NewMCPActionProposal(findingapi.MCPArguments(args), findingID, action)
	mcpApplyExternalLifecycleProposal(proposal, finding, action)
	if err := findingapi.ApplyMCPGraphActionProposal(proposal, finding, action, findingapi.MCPArguments(args), scopeGraphActionsWrite); err != nil {
		return nil, err
	}
	return proposal, nil
}

func mcpApplyExternalLifecycleProposal(proposal findingapi.MCPActionProposalPayload, finding *ports.FindingRecord, action string) {
	ref, ok := mcpExternalOwnedRef(finding)
	if !ok {
		return
	}
	proposal["lifecycle_owner"] = "external_owned"
	proposal["external_system"] = strings.TrimSpace(ref.System)
	proposal["external_ref_kind"] = strings.TrimSpace(ref.Kind)
	proposal["external_id"] = strings.TrimSpace(ref.ExternalID)
	proposal["external_status"] = strings.TrimSpace(ref.ExternalStatus)
	proposal["external_status_reason"] = strings.TrimSpace(ref.ExternalStatusReason)
	proposal["external_url"] = strings.TrimSpace(ref.URL)
	if strings.TrimSpace(action) == "update_status" {
		proposal["handoff_required"] = true
		proposal["recommended_action"] = "update_external_ref"
		proposal["status_source"] = "external_lifecycle:" + strings.TrimSpace(ref.System)
		proposal["proposal_note"] = "Lifecycle is owned by " + strings.TrimSpace(ref.System) + " " + strings.TrimSpace(ref.Kind) + "; update the external case or source and let Cerebro refresh the finding status."
	}
}

func mcpExternalOwnedRef(finding *ports.FindingRecord) (ports.FindingExternalRef, bool) {
	if finding == nil {
		return ports.FindingExternalRef{}, false
	}
	for _, ref := range finding.ExternalRefs {
		if strings.EqualFold(strings.TrimSpace(ref.LifecycleOwner), "external_owned") {
			return ref, true
		}
	}
	if !strings.EqualFold(strings.TrimSpace(finding.Attributes["lifecycle_owner"]), "external_owned") {
		return ports.FindingExternalRef{}, false
	}
	return ports.FindingExternalRef{
		System:               finding.Attributes["external_ref_system"],
		Kind:                 finding.Attributes["external_ref_kind"],
		ExternalID:           finding.Attributes["external_ref_id"],
		URL:                  finding.Attributes["case_url"],
		ExternalStatus:       finding.Attributes["external_ref_status"],
		ExternalStatusReason: finding.Attributes["status_reason"],
		LifecycleOwner:       "external_owned",
	}, true
}

func (app *App) mcpProposeRuntimeRefresh(r *http.Request, args map[string]any) (any, error) {
	if !mcpBoolArg(args, "dry_run") {
		return nil, fmt.Errorf("%w: dry_run=true is required for runtime refresh proposals", errInvalidHTTPRequest)
	}
	runtimeID := mcpStringArg(args, "runtime_id")
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: runtime_id is required", sourceruntime.ErrInvalidRequest)
	}
	runtimeStore := sourceRuntimeStore(app.deps.StateStore)
	if runtimeStore == nil {
		return nil, sourceruntime.ErrRuntimeUnavailable
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), runtimeStore, runtimeID); err != nil {
		return nil, mcpNormalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound)
	}
	if _, err := runtimeStore.GetSourceRuntime(r.Context(), runtimeID); err != nil {
		return nil, err
	}
	return map[string]any{
		"dry_run":           true,
		"would_mutate":      false,
		"runtime_id":        runtimeID,
		"action":            "source_runtime.refresh",
		"required_scope":    "write",
		"approval_required": true,
	}, nil
}

func mcpTools() []mcpTool {
	return []mcpTool{
		{
			Name:         "cerebro.health",
			Title:        "Cerebro Health",
			Description:  "Return Cerebro service health and dependency status.",
			InputSchema:  mcpObjectSchema(nil, nil),
			OutputSchema: mcpOutputSchema(nil),
			Annotations:  mcpReadOnlyAnnotations("Cerebro Health"),
		},
		{
			Name:         "cerebro.version",
			Title:        "Cerebro Version",
			Description:  "Return Cerebro service build and API version metadata.",
			InputSchema:  mcpObjectSchema(nil, nil),
			OutputSchema: mcpOutputSchema(nil),
			Annotations:  mcpReadOnlyAnnotations("Cerebro Version"),
		},
		{
			Name:        "cerebro.source_runtimes.list",
			Title:       "List Source Runtimes",
			Description: "List source runtimes visible to the authenticated caller. Runtime config values are redacted.",
			InputSchema: mcpObjectSchema(map[string]any{
				"runtime_id": map[string]any{"type": "string"},
				"tenant_id":  map[string]any{"type": "string"},
				"source_id":  map[string]any{"type": "string"},
				"limit":      mcpLimitSchema(maxMCPListLimit, "runtimes"),
			}, nil),
			OutputSchema: mcpOutputSchema(map[string]any{"runtimes": map[string]any{"type": "array"}}),
			Annotations:  mcpReadOnlyAnnotations("List Source Runtimes"),
		},
		{
			Name:        "cerebro.connector_definitions.list",
			Title:       "List Connector Definitions",
			Description: "List dynamic connector definitions visible to the authenticated caller.",
			InputSchema: mcpObjectSchema(map[string]any{
				"tenant_id": map[string]any{"type": "string"},
				"stage":     map[string]any{"type": "string", "enum": []string{"draft", "sandbox", "pilot", "approved", "certified"}},
				"limit":     mcpLimitSchema(maxMCPListLimit, "definitions"),
			}, nil),
			OutputSchema: mcpOutputSchema(map[string]any{"definitions": map[string]any{"type": "array"}}),
			Annotations:  mcpReadOnlyAnnotations("List Connector Definitions"),
		},
		{
			Name:        "cerebro.connector_definitions.validate",
			Title:       "Validate Connector Definition",
			Description: "Validate a proposed dynamic connector definition without persisting it or contacting a third party.",
			InputSchema: mcpObjectSchema(map[string]any{
				"definition": map[string]any{
					"type":                 "object",
					"additionalProperties": true,
				},
			}, []string{"definition"}),
			OutputSchema: mcpOutputSchema(map[string]any{
				"definition": map[string]any{"type": "object"},
				"validation": map[string]any{"type": "object"},
				"promotion":  map[string]any{"type": "object"},
				"support":    map[string]any{"type": "object"},
			}),
			Annotations: mcpReadOnlyAnnotations("Validate Connector Definition"),
		},
		{
			Name:        "cerebro.findings.list",
			Title:       "List Runtime Findings",
			Description: "List findings for one source runtime visible to the authenticated caller.",
			InputSchema: mcpObjectSchema(map[string]any{
				"runtime_id":   map[string]any{"type": "string"},
				"finding_id":   map[string]any{"type": "string"},
				"rule_id":      map[string]any{"type": "string"},
				"severity":     map[string]any{"type": "string"},
				"status":       map[string]any{"type": "string", "enum": []string{"open", "resolved", "suppressed"}},
				"resource_urn": map[string]any{"type": "string"},
				"event_id":     map[string]any{"type": "string"},
				"policy_id":    map[string]any{"type": "string"},
				"limit":        mcpLimitSchema(maxMCPListLimit, "findings"),
				"order":        map[string]any{"type": "string", "enum": []string{"last_observed", "priority", "risk_score"}},
			}, []string{"runtime_id"}),
			OutputSchema: mcpOutputSchema(map[string]any{"findings": map[string]any{"type": "array"}}),
			Annotations:  mcpReadOnlyAnnotations("List Runtime Findings"),
		},
		{
			Name:        "cerebro.findings.get",
			Title:       "Get Finding",
			Description: "Return one finding by ID if it is visible to the authenticated caller.",
			InputSchema: mcpObjectSchema(map[string]any{
				"finding_id": map[string]any{"type": "string"},
			}, []string{"finding_id"}),
			OutputSchema: mcpOutputSchema(map[string]any{"finding": map[string]any{"type": "object"}}),
			Annotations:  mcpReadOnlyAnnotations("Get Finding"),
		},
		{
			Name:        "cerebro.findings.search",
			Title:       "Search Findings",
			Description: "Search visible findings across a runtime or tenant by query, severity, status, rule, resource, event, or policy.",
			InputSchema: mcpObjectSchema(map[string]any{
				"tenant_id":    map[string]any{"type": "string"},
				"runtime_id":   map[string]any{"type": "string"},
				"query":        map[string]any{"type": "string"},
				"rule_id":      map[string]any{"type": "string"},
				"severity":     map[string]any{"type": "string"},
				"status":       map[string]any{"type": "string", "enum": []string{"open", "resolved", "suppressed"}},
				"resource_urn": map[string]any{"type": "string"},
				"event_id":     map[string]any{"type": "string"},
				"policy_id":    map[string]any{"type": "string"},
				"limit":        mcpLimitSchema(maxMCPListLimit, "findings"),
			}, nil),
			OutputSchema: mcpOutputSchema(map[string]any{"findings": map[string]any{"type": "array"}}),
			Annotations:  mcpReadOnlyAnnotations("Search Findings"),
		},
		{
			Name:        "cerebro.runtimes.status",
			Title:       "Runtime Status",
			Description: "Return a redacted runtime record and bounded finding risk summary for one source runtime.",
			InputSchema: mcpObjectSchema(map[string]any{
				"runtime_id": map[string]any{"type": "string"},
			}, []string{"runtime_id"}),
			OutputSchema: mcpOutputSchema(map[string]any{"runtime": map[string]any{"type": "object"}, "risk_summary": map[string]any{"type": "object"}}),
			Annotations:  mcpReadOnlyAnnotations("Runtime Status"),
		},
		{
			Name:        "cerebro.evidence.list",
			Title:       "List Finding Evidence",
			Description: "List durable evidence records for one source runtime, optionally scoped to finding, run, rule, claim, event, or graph URN.",
			InputSchema: mcpObjectSchema(map[string]any{
				"runtime_id":     map[string]any{"type": "string"},
				"finding_id":     map[string]any{"type": "string"},
				"run_id":         map[string]any{"type": "string"},
				"rule_id":        map[string]any{"type": "string"},
				"claim_id":       map[string]any{"type": "string"},
				"event_id":       map[string]any{"type": "string"},
				"graph_root_urn": map[string]any{"type": "string"},
				"graph_path_urn": map[string]any{"type": "string"},
				"limit":          mcpLimitSchema(maxMCPEvidenceLimit, "evidence records"),
			}, []string{"runtime_id"}),
			OutputSchema: mcpOutputSchema(map[string]any{"evidence": map[string]any{"type": "array"}}),
			Annotations:  mcpReadOnlyAnnotations("List Finding Evidence"),
		},
		{
			Name:        "cerebro.evidence.get",
			Title:       "Get Finding Evidence",
			Description: "Return one finding evidence record by ID if it is visible to the authenticated caller.",
			InputSchema: mcpObjectSchema(map[string]any{
				"evidence_id": map[string]any{"type": "string"},
			}, []string{"evidence_id"}),
			OutputSchema: mcpOutputSchema(map[string]any{"evidence": map[string]any{"type": "object"}}),
			Annotations:  mcpReadOnlyAnnotations("Get Finding Evidence"),
		},
		{
			Name:        "cerebro.assets.search",
			Title:       "Search Assets",
			Description: "Search graph assets/entities visible to the authenticated caller by query, URN, entity type, tenant, or runtime.",
			InputSchema: mcpObjectSchema(map[string]any{
				"query":       map[string]any{"type": "string"},
				"urn":         map[string]any{"type": "string"},
				"entity_type": map[string]any{"type": "string"},
				"tenant_id":   map[string]any{"type": "string"},
				"runtime_id":  map[string]any{"type": "string"},
				"limit":       mcpLimitSchema(maxMCPAssetLimit, "assets"),
			}, nil),
			OutputSchema: mcpOutputSchema(map[string]any{"assets": map[string]any{"type": "array"}}),
			Annotations:  mcpReadOnlyAnnotations("Search Assets"),
		},
		{
			Name:        "cerebro.assets.get",
			Title:       "Get Asset",
			Description: "Return one graph asset/entity by exact Cerebro URN with sensitive attributes redacted.",
			InputSchema: mcpObjectSchema(map[string]any{
				"urn": map[string]any{"type": "string"},
			}, []string{"urn"}),
			OutputSchema: mcpOutputSchema(map[string]any{"asset": map[string]any{"type": "object"}}),
			Annotations:  mcpReadOnlyAnnotations("Get Asset"),
		},
		{
			Name:        "cerebro.risk.summary",
			Title:       "Risk Summary",
			Description: "Summarize visible finding risk by severity, status, risk score, and top risk reasons.",
			InputSchema: mcpObjectSchema(map[string]any{
				"tenant_id":  map[string]any{"type": "string"},
				"runtime_id": map[string]any{"type": "string"},
				"status":     map[string]any{"type": "string", "enum": []string{"open", "resolved", "suppressed"}},
				"limit":      mcpLimitSchema(maxMCPRiskLimit, "risk findings"),
			}, nil),
			OutputSchema: mcpOutputSchema(nil),
			Annotations:  mcpReadOnlyAnnotations("Risk Summary"),
		},
		{
			Name:        "cerebro.risk.actions.list",
			Title:       "List Risk Actions",
			Description: "Rank next-best remediation and planning-blocker candidates from visible findings using bounded risk-delta simulations and graph context.",
			InputSchema: mcpObjectSchema(map[string]any{
				"tenant_id":        map[string]any{"type": "string"},
				"runtime_id":       map[string]any{"type": "string"},
				"runtime_ids":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"status":           map[string]any{"type": "string", "enum": []string{"open", "resolved", "suppressed"}},
				"limit":            mcpLimitSchema(riskplan.MaxCandidateLimit, "risk action candidates"),
				"finding_limit":    mcpLimitSchema(maxMCPRiskLimit, "risk findings to seed the plan"),
				"resource_limit":   mcpLimitSchema(maxMCPRiskActionRoots, "candidate target graph roots"),
				"graph_limit":      mcpLimitSchema(maxMCPRiskActionGraph, "graph neighbors per candidate target"),
				"include_unscored": map[string]any{"type": "boolean"},
			}, nil),
			OutputSchema: mcpOutputSchema(map[string]any{
				"plan":                     map[string]any{"type": "object"},
				"action_candidates":        map[string]any{"type": "array"},
				"graph_evidence_status":    map[string]any{"type": "string"},
				"graph_neighborhood_count": map[string]any{"type": "integer"},
			}),
			Annotations: mcpReadOnlyAnnotations("List Risk Actions"),
		},
		{
			Name:        "cerebro.risk.actions.explain",
			Title:       "Explain Risk Action",
			Description: "Explain one ranked risk action candidate by id, including score breakdown, expected reduction, effort, ownership, evidence quality, outcome learning, and risk delta.",
			InputSchema: mcpObjectSchema(map[string]any{
				"candidate_id":     map[string]any{"type": "string"},
				"tenant_id":        map[string]any{"type": "string"},
				"runtime_id":       map[string]any{"type": "string"},
				"runtime_ids":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"status":           map[string]any{"type": "string", "enum": []string{"open", "resolved", "suppressed"}},
				"limit":            mcpLimitSchema(riskplan.MaxCandidateLimit, "risk action candidates"),
				"finding_limit":    mcpLimitSchema(maxMCPRiskLimit, "risk findings to seed the plan"),
				"resource_limit":   mcpLimitSchema(maxMCPRiskActionRoots, "candidate target graph roots"),
				"graph_limit":      mcpLimitSchema(maxMCPRiskActionGraph, "graph neighbors per candidate target"),
				"include_unscored": map[string]any{"type": "boolean"},
			}, []string{"candidate_id"}),
			OutputSchema: mcpOutputSchema(map[string]any{
				"candidate":                map[string]any{"type": "object"},
				"score_breakdown":          map[string]any{"type": "object"},
				"expected_reduction":       map[string]any{"type": "object"},
				"effort":                   map[string]any{"type": "object"},
				"ownership":                map[string]any{"type": "object"},
				"evidence":                 map[string]any{"type": "object"},
				"outcome_learning":         map[string]any{"type": "object"},
				"risk_delta":               map[string]any{"type": "object"},
				"plan_model_version":       map[string]any{"type": "string"},
				"graph_evidence_status":    map[string]any{"type": "string"},
				"graph_neighborhood_count": map[string]any{"type": "integer"},
			}),
			Annotations: mcpReadOnlyAnnotations("Explain Risk Action"),
		},
		{
			Name:        "cerebro.graph.neighborhood",
			Title:       "Graph Neighborhood",
			Description: "Return a bounded graph neighborhood around a Cerebro URN visible to the authenticated caller.",
			InputSchema: mcpObjectSchema(map[string]any{
				"root_urn": map[string]any{"type": "string"},
				"limit":    mcpLimitSchema(maxMCPNeighborhoodLimit, "graph neighbors"),
			}, []string{"root_urn"}),
			OutputSchema: mcpOutputSchema(nil),
			Annotations:  mcpReadOnlyAnnotations("Graph Neighborhood"),
		},
		{
			Name:        "cerebro.graph.impact",
			Title:       "Graph Impact",
			Description: "Return bounded graph impact for an asset URN, package, or vulnerability.",
			InputSchema: mcpObjectSchema(map[string]any{
				"kind":       map[string]any{"type": "string", "enum": []string{"asset", "package", "vulnerability"}},
				"tenant_id":  map[string]any{"type": "string"},
				"identifier": map[string]any{"type": "string"},
				"root_urn":   map[string]any{"type": "string"},
				"depth":      map[string]any{"type": "integer", "minimum": 1},
				"limit":      mcpLimitSchema(maxMCPImpactLimit, "impact rows"),
			}, nil),
			OutputSchema: mcpOutputSchema(nil),
			Annotations:  mcpReadOnlyAnnotations("Graph Impact"),
		},
		{
			Name:        "cerebro.graph.paths",
			Title:       "Graph Attack Paths",
			Description: "Return bounded tenant-scoped cloud exposure/privilege attack path samples.",
			InputSchema: mcpObjectSchema(map[string]any{
				"tenant_id":  map[string]any{"type": "string"},
				"account_id": map[string]any{"type": "string"},
				"limit":      mcpLimitSchema(maxMCPGraphLimit, "attack path rows"),
			}, nil),
			OutputSchema: mcpOutputSchema(nil),
			Annotations:  mcpReadOnlyAnnotations("Graph Attack Paths"),
		},
		{
			Name:        "cerebro.agent.preflight",
			Title:       "Agent Run Preflight",
			Description: "Resolve tenant-scoped capability, graph, connector, policy, and write-back preconditions before an agent plans work.",
			InputSchema: mcpObjectSchema(map[string]any{
				"capability_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"question":       map[string]any{"type": "string"},
				"scope_urn":      map[string]any{"type": "string"},
				"model":          map[string]any{"type": "string"},
				"connector_readiness": map[string]any{
					"type":                 "object",
					"additionalProperties": map[string]any{"type": "string"},
				},
				"allow_preview":          map[string]any{"type": "boolean"},
				"selection_reason":       map[string]any{"type": "string"},
				"provenance_requirement": map[string]any{"type": "string"},
			}, nil),
			OutputSchema: mcpOutputSchema(map[string]any{
				"tenant_id":            map[string]any{"type": "string"},
				"enabled":              map[string]any{"type": "boolean"},
				"blockers":             map[string]any{"type": "array"},
				"capability_decisions": map[string]any{"type": "array"},
				"graph_context":        map[string]any{"type": "object"},
				"connector_context":    map[string]any{"type": "array"},
				"policy":               map[string]any{"type": "object"},
				"write_back":           map[string]any{"type": "object"},
				"runtime_events":       map[string]any{"type": "array"},
				"provenance":           map[string]any{"type": "array"},
			}),
			Annotations: mcpReadOnlyAnnotations("Agent Run Preflight"),
		},
		{
			Name:        "cerebro.graph.reason",
			Title:       "Graph Reasoning",
			Description: "Answer a tenant-scoped graph question with query plan, guarded Cypher, rows, graph evidence, citations, and provenance.",
			InputSchema: mcpObjectSchema(map[string]any{
				"question":  map[string]any{"type": "string"},
				"scope_urn": map[string]any{"type": "string"},
				"model":     map[string]any{"type": "string"},
			}, []string{"question"}),
			OutputSchema: mcpOutputSchema(map[string]any{
				"trace_id":            map[string]any{"type": "string"},
				"query_plan":          map[string]any{"type": "object"},
				"cypher":              map[string]any{"type": "object"},
				"rows":                map[string]any{"type": "array"},
				"graph":               map[string]any{"type": "object"},
				"answer_markdown":     map[string]any{"type": "string"},
				"citations":           map[string]any{"type": "array"},
				"citation_validation": map[string]any{"type": "object"},
				"preflight":           map[string]any{"type": "object"},
				"provenance":          map[string]any{"type": "object"},
			}),
			Annotations: mcpReadOnlyAnnotations("Graph Reasoning"),
		},
		{
			Name:        "cerebro.investigation.context",
			Title:       "Investigation Context",
			Description: "Bundle finding, evidence, assets, and graph context for one finding so an agent can investigate without many round trips.",
			InputSchema: mcpObjectSchema(map[string]any{
				"finding_id":  map[string]any{"type": "string"},
				"limit":       mcpLimitSchema(maxMCPEvidenceLimit, "evidence records"),
				"asset_limit": mcpLimitSchema(maxMCPAssetLimit, "related assets"),
				"skip_graph":  map[string]any{"type": "boolean"},
				"compact":     map[string]any{"type": "boolean"},
			}, []string{"finding_id"}),
			OutputSchema: mcpOutputSchema(nil),
			Annotations:  mcpReadOnlyAnnotations("Investigation Context"),
		},
		{
			Name:         "cerebro.findings.action.propose",
			Title:        "Propose Finding Action",
			Description:  "Validate and describe a finding workflow action without applying it. Requires dry_run=true and never mutates state.",
			InputSchema:  mcpObjectSchema(findingapi.MCPActionInputProperties(), []string{"dry_run", "finding_id", "action"}),
			OutputSchema: mcpOutputSchema(findingapi.MCPActionOutputProperties()),
			Annotations:  mcpReadOnlyAnnotations("Propose Finding Action"),
		},
		{
			Name:        "cerebro.source_runtimes.refresh.propose",
			Title:       "Propose Runtime Refresh",
			Description: "Validate and describe a source runtime refresh without applying it. Requires dry_run=true and never mutates state.",
			InputSchema: mcpObjectSchema(map[string]any{
				"dry_run":    map[string]any{"type": "boolean", "const": true},
				"runtime_id": map[string]any{"type": "string"},
			}, []string{"dry_run", "runtime_id"}),
			OutputSchema: mcpOutputSchema(map[string]any{
				"dry_run":           map[string]any{"type": "boolean", "const": true},
				"would_mutate":      map[string]any{"type": "boolean", "const": false},
				"runtime_id":        map[string]any{"type": "string"},
				"action":            map[string]any{"type": "string"},
				"required_scope":    map[string]any{"type": "string"},
				"approval_required": map[string]any{"type": "boolean"},
			}),
			Annotations: mcpReadOnlyAnnotations("Propose Runtime Refresh"),
		},
	}
}

func mcpObjectSchema(properties map[string]any, required []string) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) != 0 {
		schema["required"] = required
	}
	return schema
}

func mcpOutputSchema(properties map[string]any) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	if len(properties) != 0 {
		if _, ok := properties["metadata"]; !ok {
			properties = cloneMCPProperties(properties)
			properties["metadata"] = map[string]any{"type": "object"}
		}
	}
	return map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": len(properties) == 0,
	}
}

func mcpLimitSchema(max int, itemName string) map[string]any {
	return map[string]any{
		"type":        "integer",
		"minimum":     1,
		"maximum":     max,
		"description": fmt.Sprintf("Maximum %s to return. Values above %d are clamped.", itemName, max),
	}
}

func cloneMCPProperties(properties map[string]any) map[string]any {
	cloned := make(map[string]any, len(properties)+1)
	for key, value := range properties {
		cloned[key] = value
	}
	return cloned
}

func mcpReadOnlyAnnotations(title string) map[string]any {
	return map[string]any{
		"title":           title,
		"readOnlyHint":    true,
		"destructiveHint": false,
		"idempotentHint":  true,
		"openWorldHint":   true,
	}
}

func mcpTelemetryEvent(r *http.Request, method string, tool string, statusCode int, jsonRPCErrorCode int, outcome string, toolErrorKind string, duration time.Duration, details ...mcpTelemetryDetails) {
	if r == nil {
		return
	}
	detail := mcpTelemetryDetails{}
	if len(details) != 0 {
		detail = details[0]
	}
	method = mcpSanitizeTelemetryValue(method, 96)
	tool = mcpSanitizeTelemetryValue(tool, 128)
	outcome = mcpSanitizeTelemetryValue(outcome, 64)
	toolErrorKind = mcpSanitizeTelemetryValue(toolErrorKind, 64)
	requestKind := mcpSanitizeTelemetryValue(detail.RequestKind, 64)
	if requestKind == "" {
		requestKind = "request"
	}
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "http.method", Value: r.Method},
		telemetry.Field{Key: "http.route", Value: mcpTelemetryHTTPRoute(r)},
		telemetry.Field{Key: "http.status_code", Value: statusCode},
		telemetry.Field{Key: "mcp.request_kind", Value: requestKind},
		telemetry.Field{Key: "mcp.method", Value: method},
		telemetry.Field{Key: "mcp.outcome", Value: outcome},
		telemetry.Field{Key: "mcp.protocol_version", Value: mcpSanitizeTelemetryValue(r.Header.Get("MCP-Protocol-Version"), 32)},
		telemetry.Field{Key: "mcp.transport", Value: "stateless_http"},
		telemetry.Field{Key: "mcp.stateless", Value: true},
		telemetry.Field{Key: "mcp.accepts_json", Value: mcpHeaderAccepts(r.Header.Get("Accept"), "application/json")},
		telemetry.Field{Key: "mcp.accepts_sse", Value: mcpHeaderAccepts(r.Header.Get("Accept"), "text/event-stream")},
		telemetry.Field{Key: "mcp.session_header_present", Value: strings.TrimSpace(r.Header.Get("Mcp-Session-Id")) != ""},
		telemetry.Field{Key: "mcp.jsonrpc_id_present", Value: detail.JSONRPCIDPresent},
		telemetry.Field{Key: "mcp.params_present", Value: detail.ParamsPresent},
		telemetry.Field{Key: "duration_ms", Value: duration.Milliseconds()},
	)
	if contentType := mcpMediaType(r.Header.Get("Content-Type")); contentType != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "mcp.content_type", Value: contentType})
	}
	for _, field := range mcpResponseTelemetryFields(detail.Response) {
		attrs = attrs.WithField(field)
	}
	if requestID := accessAuditRequestID(r); requestID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "request_id", Value: requestID})
	}
	if tool != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "mcp.tool", Value: tool})
		attrs = attrs.WithField(telemetry.Field{Key: "mcp.tool_known", Value: mcpKnownTool(tool)})
		if family := mcpToolFamily(tool); family != "" {
			attrs = attrs.WithField(telemetry.Field{Key: "mcp.tool_family", Value: family})
		}
	}
	if jsonRPCErrorCode != 0 {
		attrs = attrs.WithField(telemetry.Field{Key: "mcp.jsonrpc_error_code", Value: jsonRPCErrorCode})
	}
	if outcome == "tool_error" {
		attrs = attrs.WithField(telemetry.Field{Key: "mcp.tool_error", Value: true})
	}
	if toolErrorKind != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "mcp.tool_error_kind", Value: toolErrorKind})
	}
	if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok {
		if tenantID := strings.TrimSpace(auth.principal.TenantID); tenantID != "" {
			attrs = attrs.WithField(telemetry.Field{Key: "tenant_id", Value: mcpSanitizeTelemetryValue(tenantID, 128)})
		}
		if principal := strings.TrimSpace(auth.principal.Name); principal != "" {
			attrs = attrs.WithField(telemetry.Field{Key: "principal", Value: mcpSanitizeTelemetryValue(principal, 128)})
		}
		if authMode := strings.TrimSpace(auth.principal.AuthMode); authMode != "" {
			attrs = attrs.WithField(telemetry.Field{Key: "auth_mode", Value: mcpSanitizeTelemetryValue(authMode, 64)})
		}
		if credentialID := strings.TrimSpace(auth.principal.CredentialID); credentialID != "" {
			attrs = attrs.WithField(telemetry.Field{Key: "credential_id", Value: mcpSanitizeTelemetryValue(credentialID, 128)})
		}
		if clientID := strings.TrimSpace(auth.principal.ClientID); clientID != "" {
			attrs = attrs.WithField(telemetry.Field{Key: "client_id", Value: mcpSanitizeTelemetryValue(clientID, 128)})
		}
	}
	telemetry.Event(r.Context(), "cerebro.mcp.request", attrs)
	telemetry.IncrementMain(r.Context(), "mcp.request.count", 1)
	if mcpTelemetryOutcomeFailed(outcome) {
		telemetry.IncrementMain(r.Context(), "mcp.request.error.count", 1)
	}
	mainAttrs := telemetry.Attrs(
		telemetry.Field{Key: "mcp.status_code", Value: statusCode},
		telemetry.Field{Key: "mcp.request_kind", Value: requestKind},
		telemetry.Field{Key: "mcp.method", Value: method},
		telemetry.Field{Key: "mcp.outcome", Value: outcome},
		telemetry.Field{Key: "mcp.protocol_version", Value: mcpSanitizeTelemetryValue(r.Header.Get("MCP-Protocol-Version"), 32)},
		telemetry.Field{Key: "mcp.transport", Value: "stateless_http"},
		telemetry.Field{Key: "mcp.stateless", Value: true},
		telemetry.Field{Key: "mcp.accepts_json", Value: mcpHeaderAccepts(r.Header.Get("Accept"), "application/json")},
		telemetry.Field{Key: "mcp.accepts_sse", Value: mcpHeaderAccepts(r.Header.Get("Accept"), "text/event-stream")},
		telemetry.Field{Key: "mcp.session_header_present", Value: strings.TrimSpace(r.Header.Get("Mcp-Session-Id")) != ""},
		telemetry.Field{Key: "mcp.jsonrpc_id_present", Value: detail.JSONRPCIDPresent},
		telemetry.Field{Key: "mcp.params_present", Value: detail.ParamsPresent},
		telemetry.Field{Key: "mcp.duration_ms", Value: duration.Milliseconds()},
	)
	if contentType := mcpMediaType(r.Header.Get("Content-Type")); contentType != "" {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "mcp.content_type", Value: contentType})
	}
	for _, field := range mcpResponseTelemetryFields(detail.Response) {
		mainAttrs = mainAttrs.WithField(field)
	}
	if tool != "" {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "mcp.tool", Value: tool})
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "mcp.tool_known", Value: mcpKnownTool(tool)})
		if family := mcpToolFamily(tool); family != "" {
			mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "mcp.tool_family", Value: family})
		}
	}
	if jsonRPCErrorCode != 0 {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "mcp.jsonrpc_error_code", Value: jsonRPCErrorCode})
	}
	if outcome == "tool_error" {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "mcp.tool_error", Value: true})
	}
	if toolErrorKind != "" {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "mcp.tool_error_kind", Value: toolErrorKind})
	}
	if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok {
		if tenantID := strings.TrimSpace(auth.principal.TenantID); tenantID != "" {
			mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "tenant_id", Value: mcpSanitizeTelemetryValue(tenantID, 128)})
		}
		if authMode := strings.TrimSpace(auth.principal.AuthMode); authMode != "" {
			mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "auth.mode", Value: mcpSanitizeTelemetryValue(authMode, 64)})
		}
		if tier := accessAuditCredentialTier(auth.principal); tier != "" {
			mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "auth.credential_tier", Value: tier})
		}
		mainAttrs = mainAttrs.
			WithField(telemetry.Field{Key: "auth.principal.present", Value: strings.TrimSpace(auth.principal.Name) != ""}).
			WithField(telemetry.Field{Key: "auth.client.present", Value: strings.TrimSpace(auth.principal.ClientID) != ""})
	}
	telemetry.AnnotateMain(r.Context(), mainAttrs)
}

func mcpTelemetryOutcomeFailed(outcome string) bool {
	switch strings.TrimSpace(outcome) {
	case "ok", "notification", "client_message":
		return false
	default:
		return true
	}
}

func mcpTelemetryHTTPRoute(r *http.Request) string {
	if r == nil {
		return mcpEndpointPath
	}
	method := strings.TrimSpace(r.Method)
	if method == "" {
		return mcpEndpointPath
	}
	return method + " " + mcpEndpointPath
}

func mcpHeaderAccepts(header string, mediaType string) bool {
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	for _, part := range strings.Split(header, ",") {
		if mcpMediaType(part) == mediaType || mcpMediaType(part) == "*/*" {
			return true
		}
	}
	return false
}

func mcpMediaType(header string) string {
	value := strings.ToLower(strings.TrimSpace(header))
	if value == "" {
		return ""
	}
	mediaType, _, _ := strings.Cut(value, ";")
	return mcpSanitizeTelemetryValue(strings.TrimSpace(mediaType), 96)
}

func mcpResponseTelemetryFields(response *mcpJSONRPCResponse) []telemetry.Field {
	if response == nil {
		return nil
	}
	if response.Error != nil {
		return []telemetry.Field{
			{Key: "mcp.response_shape", Value: "jsonrpc_error"},
			{Key: "mcp.response_error", Value: true},
		}
	}
	switch result := response.Result.(type) {
	case mcpToolResult:
		return []telemetry.Field{
			{Key: "mcp.response_shape", Value: "tool_result"},
			{Key: "mcp.tool_result_error", Value: result.IsError},
			{Key: "mcp.tool_result_content_count", Value: len(result.Content)},
			{Key: "mcp.structured_content_present", Value: result.StructuredContent != nil},
		}
	case map[string]any:
		fields := []telemetry.Field{{Key: "mcp.response_shape", Value: mcpMapResponseShape(result)}}
		if version := mcpAnyString(result["protocolVersion"]); version != "" {
			fields = append(fields, telemetry.Field{Key: "mcp.initialize_protocol_version", Value: mcpSanitizeTelemetryValue(version, 32)})
		}
		if key, count, found := mcpListResponseCount(result); found {
			fields = append(fields,
				telemetry.Field{Key: "mcp.list_key", Value: key},
				telemetry.Field{Key: "mcp.list_count", Value: count},
				telemetry.Field{Key: "mcp.list_has_next_cursor", Value: strings.TrimSpace(mcpAnyString(result["nextCursor"])) != ""},
			)
		}
		return fields
	default:
		return []telemetry.Field{{Key: "mcp.response_shape", Value: "other"}}
	}
}

func mcpMapResponseShape(result map[string]any) string {
	if _, ok := result["protocolVersion"]; ok {
		return "initialize"
	}
	if _, _, ok := mcpListResponseCount(result); ok {
		return "list"
	}
	if len(result) == 0 {
		return "empty_object"
	}
	return "object"
}

func mcpListResponseCount(result map[string]any) (string, int, bool) {
	for _, key := range []string{"tools", "resources", "resourceTemplates", "prompts"} {
		switch items := result[key].(type) {
		case []mcpTool:
			return key, len(items), true
		case []mcpResource:
			return key, len(items), true
		case []mcpResourceTemplate:
			return key, len(items), true
		case []mcpPrompt:
			return key, len(items), true
		case []any:
			return key, len(items), true
		}
	}
	return "", 0, false
}

func mcpResponseErrorCode(response mcpJSONRPCResponse) int {
	if response.Error == nil {
		return 0
	}
	return response.Error.Code
}

func mcpResponseOutcome(response mcpJSONRPCResponse) string {
	if response.Error != nil {
		return mcpJSONRPCErrorOutcome(response.Error)
	}
	if mcpResponseToolError(response) {
		return "tool_error"
	}
	return "ok"
}

func mcpResponseToolErrorKind(response mcpJSONRPCResponse) string {
	result, ok := response.Result.(mcpToolResult)
	if !ok || !result.IsError {
		return ""
	}
	return mcpToolErrorKindFromMessage(mcpToolResultText(result))
}

func mcpResponseToolError(response mcpJSONRPCResponse) bool {
	result, ok := response.Result.(mcpToolResult)
	return ok && result.IsError
}

func mcpToolResultText(result mcpToolResult) string {
	for _, content := range result.Content {
		if text := strings.TrimSpace(content.Text); text != "" {
			return text
		}
	}
	return ""
}

func mcpToolErrorKindFromMessage(message string) string {
	message = strings.ToLower(strings.TrimSpace(message))
	switch {
	case message == "":
		return "execution_failed"
	case strings.Contains(message, "scope forbidden"):
		return "scope_forbidden"
	case strings.Contains(message, "tenant forbidden"):
		return "tenant_forbidden"
	case strings.Contains(message, "not found"):
		return "not_found"
	case strings.Contains(message, "unavailable"):
		return "runtime_unavailable"
	case strings.Contains(message, "invalid"):
		return "invalid_request"
	case strings.Contains(message, "forbidden"):
		return "authorization_failed"
	default:
		return "execution_failed"
	}
}

func mcpJSONRPCErrorOutcome(err *mcpError) string {
	if err == nil {
		return "ok"
	}
	switch err.Code {
	case -32700:
		return "parse_error"
	case -32600:
		return "invalid_request"
	case -32601:
		return "method_not_found"
	case -32602:
		return "invalid_params"
	default:
		return "jsonrpc_error"
	}
}

func mcpToolNameFromParams(method string, rawParams json.RawMessage) string {
	if method != "tools/call" || len(rawParams) == 0 {
		return ""
	}
	var params mcpToolCallParams
	if err := decodeMCPJSON(rawParams, &params); err != nil {
		return ""
	}
	return strings.TrimSpace(params.Name)
}

func mcpKnownTool(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, tool := range mcpTools() {
		if tool.Name == name {
			return true
		}
	}
	return false
}

func mcpToolFamily(name string) string {
	name = strings.TrimPrefix(strings.TrimSpace(name), "cerebro.")
	if name == "" {
		return ""
	}
	family, _, _ := strings.Cut(name, ".")
	return mcpSanitizeTelemetryValue(family, 64)
}

func mcpSanitizeTelemetryValue(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	replacer := strings.NewReplacer("\n", " ", "\r", " ", "\t", " ")
	value = replacer.Replace(value)
	if limit > 0 && len(value) > limit {
		value = value[:limit]
	}
	return value
}

func mcpResources() []mcpResource {
	annotations := mcpReadOnlyAnnotations("Cerebro Resource")
	return []mcpResource{
		{URI: "cerebro://server/health", Name: "server_health", Title: "Server Health", Description: "Cerebro service health.", MimeType: mcpResourceMIMEJSON, Annotations: annotations},
		{URI: "cerebro://server/version", Name: "server_version", Title: "Server Version", Description: "Cerebro service version/build metadata.", MimeType: mcpResourceMIMEJSON, Annotations: annotations},
		{URI: "cerebro://risk/summary", Name: "risk_summary", Title: "Risk Summary", Description: "Tenant-scoped risk summary for the authenticated caller.", MimeType: mcpResourceMIMEJSON, Annotations: annotations},
	}
}

func mcpResourceTemplates() []mcpResourceTemplate {
	annotations := mcpReadOnlyAnnotations("Cerebro Resource Template")
	return []mcpResourceTemplate{
		{URITemplate: "cerebro://finding/{finding_id}", Name: "finding", Title: "Finding", Description: "Read one finding by ID.", MimeType: mcpResourceMIMEJSON, Annotations: annotations},
		{URITemplate: "cerebro://finding-evidence/{evidence_id}", Name: "finding_evidence", Title: "Finding Evidence", Description: "Read one finding evidence record by ID.", MimeType: mcpResourceMIMEJSON, Annotations: annotations},
		{URITemplate: "cerebro://asset/{asset_urn}", Name: "asset", Title: "Asset", Description: "Read one graph asset by URL-encoded Cerebro URN.", MimeType: mcpResourceMIMEJSON, Annotations: annotations},
		{URITemplate: "cerebro://runtime/{runtime_id}", Name: "runtime", Title: "Runtime", Description: "Read one source runtime status bundle.", MimeType: mcpResourceMIMEJSON, Annotations: annotations},
		{URITemplate: "cerebro://investigation/finding/{finding_id}", Name: "finding_investigation", Title: "Finding Investigation", Description: "Read a bounded investigation context bundle for one finding.", MimeType: mcpResourceMIMEJSON, Annotations: annotations},
	}
}

func mcpPrompts() []mcpPrompt {
	return []mcpPrompt{
		{
			Name:        "investigate_finding",
			Title:       "Investigate Finding",
			Description: "Guide an agent through finding triage using Cerebro MCP tools/resources.",
			Arguments: []mcpPromptArgument{{
				Name:        "finding_id",
				Title:       "Finding ID",
				Description: "The Cerebro finding ID to investigate.",
				Required:    true,
			}},
		},
		{
			Name:        "investigate_asset",
			Title:       "Investigate Asset",
			Description: "Guide an agent through asset context, graph impact, and related findings.",
			Arguments: []mcpPromptArgument{{
				Name:        "asset_urn",
				Title:       "Asset URN",
				Description: "The Cerebro graph asset URN to investigate.",
				Required:    true,
			}},
		},
		{
			Name:        "summarize_tenant_risk",
			Title:       "Summarize Tenant Risk",
			Description: "Guide an agent through tenant risk summarization and next-step recommendations.",
			Arguments: []mcpPromptArgument{{
				Name:        "tenant_id",
				Title:       "Tenant ID",
				Description: "Optional tenant ID; tenant-scoped API keys can omit it.",
			}},
		},
	}
}

func (app *App) mcpReadResource(r *http.Request, rawParams json.RawMessage) (mcpReadResourceResult, error) {
	var params mcpReadResourceParams
	if err := decodeMCPJSON(rawParams, &params); err != nil {
		return mcpReadResourceResult{}, fmt.Errorf("%w: invalid resource read params", errInvalidHTTPRequest)
	}
	rawURI := strings.TrimSpace(params.URI)
	parsed, err := url.Parse(rawURI)
	if err != nil || parsed.Scheme != "cerebro" || strings.TrimSpace(parsed.Host) == "" {
		return mcpReadResourceResult{}, fmt.Errorf("%w: invalid resource uri", errInvalidHTTPRequest)
	}
	if err := authorizeMCPResourceScope(r.Context(), parsed.Host); err != nil {
		return mcpReadResourceResult{}, err
	}
	pathValue, err := url.PathUnescape(strings.TrimPrefix(parsed.EscapedPath(), "/"))
	if err != nil {
		return mcpReadResourceResult{}, fmt.Errorf("%w: invalid resource path", errInvalidHTTPRequest)
	}
	args := mcpArgsFromQuery(parsed.Query())
	var value any
	switch parsed.Host {
	case "server":
		switch pathValue {
		case "health":
			value, err = protoJSONValue(healthResponse(r.Context(), app.cfg, app.deps))
		case "version":
			value, err = protoJSONValue(&cerebrov1.GetVersionResponse{
				ServiceName: buildinfo.ServiceName,
				Version:     buildinfo.Version,
				Commit:      buildinfo.Commit,
				BuildDate:   buildinfo.BuildDate,
				ApiVersion:  buildinfo.APIVersion,
			})
		default:
			err = ports.ErrGraphEntityNotFound
		}
	case "risk":
		if pathValue != "summary" {
			err = ports.ErrGraphEntityNotFound
			break
		}
		value, err = app.mcpRiskSummary(r, args)
	case "finding":
		value, err = app.mcpGetFinding(r, map[string]any{"finding_id": pathValue})
	case "finding-evidence":
		value, err = app.mcpGetEvidence(r, map[string]any{"evidence_id": pathValue})
	case "asset":
		value, err = app.mcpGetAsset(r, map[string]any{"urn": pathValue})
	case "runtime":
		value, err = app.mcpRuntimeStatus(r, map[string]any{"runtime_id": pathValue})
	case "investigation":
		parts := strings.SplitN(pathValue, "/", 2)
		if len(parts) != 2 || parts[0] != "finding" {
			err = ports.ErrGraphEntityNotFound
			break
		}
		args["finding_id"] = parts[1]
		value, err = app.mcpInvestigationContext(r, args)
	default:
		err = ports.ErrGraphEntityNotFound
	}
	if err != nil {
		return mcpReadResourceResult{}, err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return mcpReadResourceResult{}, err
	}
	return mcpReadResourceResult{Contents: []mcpEmbeddedResource{{
		URI:      rawURI,
		MimeType: mcpResourceMIMEJSON,
		Text:     string(payload),
	}}}, nil
}

func (app *App) mcpGetPrompt(_ *http.Request, rawParams json.RawMessage) (map[string]any, error) {
	var params mcpPromptGetParams
	if err := decodeMCPJSON(rawParams, &params); err != nil {
		return nil, fmt.Errorf("%w: invalid prompt params", errInvalidHTTPRequest)
	}
	args := map[string]any{}
	if len(params.Arguments) != 0 {
		if err := decodeMCPJSON(params.Arguments, &args); err != nil {
			return nil, fmt.Errorf("%w: invalid prompt arguments", errInvalidHTTPRequest)
		}
	}
	name := strings.TrimSpace(params.Name)
	var text string
	switch name {
	case "investigate_finding":
		findingID := mcpStringArg(args, "finding_id")
		if findingID == "" {
			return nil, fmt.Errorf("%w: finding_id is required", errInvalidHTTPRequest)
		}
		text = "Investigate Cerebro finding " + findingID + ". First read cerebro://investigation/finding/" + url.PathEscape(findingID) + ", then use cerebro.evidence.list, cerebro.assets.get, cerebro.graph.reason, cerebro.graph.neighborhood, cerebro.graph.impact, and cerebro.findings.action.propose with dry_run=true for recommended next steps. Never infer data from inaccessible IDs, never reveal redacted values, and treat tenant-forbidden or not-found tool results as a hard boundary."
	case "investigate_asset":
		assetURN := mcpStringArg(args, "asset_urn")
		if assetURN == "" {
			return nil, fmt.Errorf("%w: asset_urn is required", errInvalidHTTPRequest)
		}
		text = "Investigate Cerebro asset " + assetURN + ". Read cerebro://asset/" + url.PathEscape(assetURN) + ", then use cerebro.graph.reason, cerebro.graph.neighborhood, cerebro.graph.impact, cerebro.findings.search, and cerebro.risk.summary to explain blast radius and related findings. Never infer data from inaccessible IDs, never reveal redacted values, and treat tenant-forbidden or not-found tool results as a hard boundary."
	case "summarize_tenant_risk":
		tenantID := mcpStringArg(args, "tenant_id")
		if tenantID == "" {
			text = "Summarize tenant risk for the authenticated Cerebro principal using cerebro.risk.summary, cerebro.findings.search, cerebro.graph.reason, cerebro.graph.paths, and dry-run-only proposal tools for next actions. Never infer data from inaccessible IDs, never reveal redacted values, and treat tenant-forbidden or not-found tool results as a hard boundary."
		} else {
			text = "Summarize Cerebro tenant " + tenantID + " risk using cerebro.risk.summary, cerebro.findings.search, cerebro.graph.reason, cerebro.graph.paths, and dry-run-only proposal tools for next actions. Never infer data from inaccessible IDs, never reveal redacted values, and treat tenant-forbidden or not-found tool results as a hard boundary."
		}
	default:
		return nil, fmt.Errorf("%w: unknown prompt %q", errInvalidHTTPRequest, name)
	}
	return map[string]any{
		"description": "Cerebro investigation prompt",
		"messages": []mcpPromptMessage{{
			Role:    "user",
			Content: mcpContent{Type: "text", Text: text},
		}},
	}, nil
}

func mcpPaginatedResult[T any](items []T, rawParams json.RawMessage, key string) (map[string]any, error) {
	args := map[string]any{}
	if len(rawParams) != 0 {
		if err := decodeMCPJSON(rawParams, &args); err != nil {
			return nil, fmt.Errorf("%w: invalid list params", errInvalidHTTPRequest)
		}
	}
	offset, err := mcpDecodeCursor(mcpStringArg(args, "cursor"))
	if err != nil {
		return nil, err
	}
	if offset > len(items) {
		return nil, fmt.Errorf("%w: cursor is out of range", errInvalidHTTPRequest)
	}
	limit, err := mcpBoundedLimit(args, "limit", len(items), maxMCPListLimit)
	if err != nil {
		return nil, err
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	result := map[string]any{key: items[offset:end]}
	if end < len(items) {
		result["nextCursor"] = mcpEncodeCursor(end)
	}
	return result, nil
}

func mcpDecodeCursor(cursor string) (int, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 0, nil
	}
	cursor = strings.TrimPrefix(cursor, "offset:")
	parsed, err := strconv.Atoi(cursor)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%w: invalid cursor", errInvalidHTTPRequest)
	}
	return parsed, nil
}

func mcpEncodeCursor(offset int) string {
	return fmt.Sprintf("offset:%d", offset)
}

func mcpArgsFromQuery(values url.Values) map[string]any {
	args := map[string]any{}
	for key, value := range values {
		if len(value) > 0 {
			args[key] = value[0]
		}
	}
	return args
}

func mcpTenantArg(r *http.Request, args map[string]any) string {
	tenantID := mcpStringArg(args, "tenant_id")
	if tenantID != "" {
		return tenantID
	}
	if r != nil {
		if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok {
			return strings.TrimSpace(auth.principal.TenantID)
		}
	}
	return ""
}

func cerebroURNTenant(urn string) string {
	parts := strings.Split(strings.TrimSpace(urn), ":")
	if len(parts) >= 3 && parts[0] == "urn" && parts[1] == "cerebro" {
		return strings.TrimSpace(parts[2])
	}
	return ""
}

func mcpBoundedLimit(args map[string]any, key string, defaultLimit int, maxLimit int) (int, error) {
	limit, err := mcpUint32Arg(args, key)
	if err != nil {
		return 0, err
	}
	if limit == 0 {
		return defaultLimit, nil
	}
	if limit > math.MaxInt32 {
		return maxLimit, nil
	}
	value := int(limit)
	if value > maxLimit {
		return maxLimit, nil
	}
	return value, nil
}

func mcpAssetSearchResultFromRow(row ports.CypherRow) (mcpAssetSearchResult, error) {
	values := row.Values
	attributes, err := mcpStringMapFromJSON(mcpAnyString(values["attributes_json"]))
	if err != nil {
		return mcpAssetSearchResult{}, err
	}
	return mcpAssetSearchResult{
		URN:        mcpAnyString(values["urn"]),
		TenantID:   mcpAnyString(values["tenant_id"]),
		RuntimeID:  mcpAnyString(values["runtime_id"]),
		SourceID:   mcpAnyString(values["source_id"]),
		EntityType: mcpAnyString(values["entity_type"]),
		Label:      mcpAnyString(values["label"]),
		Attributes: mcpRedactSensitiveAttributes(attributes),
	}, nil
}

func (app *App) mcpListRiskFindings(r *http.Request, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	ctx := r.Context()
	store := findingStore(app.deps.StateStore)
	if store == nil {
		return nil, findingdomain.ErrRuntimeUnavailable
	}
	if strings.TrimSpace(request.Status) != "" {
		parsed, err := parseFindingStatus(request.Status)
		if err != nil {
			return nil, err
		}
		request.Status = findingStatusString(parsed)
	}
	if strings.TrimSpace(request.RuntimeID) != "" {
		return store.ListFindings(ctx, request)
	}
	runtimes, err := app.runtimeService().List(ctx, ports.SourceRuntimeFilter{
		TenantID: request.TenantID,
		Limit:    uint32(maxMCPRiskLimit),
	})
	if err != nil {
		return nil, err
	}
	findings := make([]*ports.FindingRecord, 0, request.Limit)
	for _, runtime := range runtimes {
		if runtime == nil || strings.TrimSpace(runtime.GetId()) == "" {
			continue
		}
		if !tenantAllowedByContext(ctx, runtime.GetTenantId()) {
			continue
		}
		scoped := request
		scoped.TenantID = strings.TrimSpace(runtime.GetTenantId())
		scoped.RuntimeID = strings.TrimSpace(runtime.GetId())
		if request.Limit != 0 {
			findingsCount := boundedUint32(len(findings))
			if findingsCount >= request.Limit {
				break
			}
			scoped.Limit = request.Limit - findingsCount
		}
		items, err := store.ListFindings(ctx, scoped)
		if err != nil {
			return nil, err
		}
		findings = append(findings, items...)
	}
	return findings, nil
}

func (app *App) mcpBuildRiskSummaryForRequest(r *http.Request, request ports.ListFindingsRequest, limit int, findings []*ports.FindingRecord) (mcpRiskSummary, error) {
	summaryStore, ok := findingStore(app.deps.StateStore).(mcpFindingSummaryStore)
	if !ok {
		summary := mcpBuildRiskSummary(request.TenantID, request.RuntimeID, limit, findings)
		summary.Metadata = mcpRiskSummaryMetadata(limit, len(findings), summary.TotalFindings)
		return summary, nil
	}
	request.Limit = 0
	if strings.TrimSpace(request.Status) != "" {
		parsed, err := parseFindingStatus(request.Status)
		if err != nil {
			return mcpRiskSummary{}, err
		}
		request.Status = findingStatusString(parsed)
	}
	summary := mcpRiskSummary{
		TenantID:         request.TenantID,
		RuntimeID:        request.RuntimeID,
		BySeverity:       map[string]int{},
		ByStatus:         map[string]int{},
		LimitApplied:     limit,
		RecentHighRisk:   []any{},
		ReturnedFindings: len(findings),
	}
	reasonCounts := map[string]int{}
	riskScoreTotal := 0
	merge := func(item ports.FindingSummary) {
		summary.TotalFindings += item.TotalFindings
		summary.OpenFindings += item.OpenFindings
		summary.CriticalOpenFindings += item.CriticalFindings
		summary.HighOpenFindings += item.HighFindings
		if item.MaxRiskScore > summary.MaxRiskScore {
			summary.MaxRiskScore = item.MaxRiskScore
		}
		riskScoreTotal += item.RiskScoreTotal
		for severity, count := range item.BySeverity {
			severity = strings.TrimSpace(severity)
			if severity == "" {
				severity = "unknown"
			}
			summary.BySeverity[severity] += count
		}
		for status, count := range item.ByStatus {
			status = strings.TrimSpace(status)
			if status == "" {
				status = "unknown"
			}
			summary.ByStatus[status] += count
		}
		for reason, count := range item.RiskReasonCounts {
			reason = strings.TrimSpace(reason)
			if reason != "" {
				reasonCounts[reason] += count
			}
		}
	}
	if strings.TrimSpace(request.RuntimeID) != "" {
		item, err := summaryStore.SummarizeFindings(r.Context(), request)
		if err != nil {
			return mcpRiskSummary{}, err
		}
		merge(item)
	} else {
		runtimes, err := app.runtimeService().List(r.Context(), ports.SourceRuntimeFilter{
			TenantID: request.TenantID,
			Limit:    uint32(maxMCPRiskLimit),
		})
		if err != nil {
			return mcpRiskSummary{}, err
		}
		for _, runtime := range runtimes {
			if runtime == nil || strings.TrimSpace(runtime.GetId()) == "" {
				continue
			}
			if !tenantAllowedByContext(r.Context(), runtime.GetTenantId()) {
				continue
			}
			scoped := request
			scoped.TenantID = strings.TrimSpace(runtime.GetTenantId())
			scoped.RuntimeID = strings.TrimSpace(runtime.GetId())
			item, err := summaryStore.SummarizeFindings(r.Context(), scoped)
			if err != nil {
				return mcpRiskSummary{}, err
			}
			merge(item)
		}
	}
	if summary.TotalFindings != 0 {
		summary.AverageRiskScore = float64(riskScoreTotal) / float64(summary.TotalFindings)
	}
	summary.TopRiskReasons = mcpTopRiskReasons(reasonCounts, 10)
	mcpAttachRecentHighRisk(&summary, findings)
	summary.Metadata = mcpRiskSummaryMetadata(limit, len(findings), summary.TotalFindings)
	return summary, nil
}

func mcpBuildRiskSummary(tenantID string, runtimeID string, limit int, findings []*ports.FindingRecord) mcpRiskSummary {
	summary := mcpRiskSummary{
		TenantID:       tenantID,
		RuntimeID:      runtimeID,
		BySeverity:     map[string]int{},
		ByStatus:       map[string]int{},
		LimitApplied:   limit,
		RecentHighRisk: []any{},
	}
	reasonCounts := map[string]int{}
	riskScoreTotal := 0
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		summary.TotalFindings++
		summary.ReturnedFindings++
		status := strings.ToLower(strings.TrimSpace(finding.Status))
		if status == "" {
			status = "unknown"
		}
		severity := strings.ToLower(strings.TrimSpace(finding.Severity))
		if severity == "" {
			severity = "unknown"
		}
		summary.ByStatus[status]++
		summary.BySeverity[severity]++
		if status == "open" {
			summary.OpenFindings++
			switch severity {
			case "critical":
				summary.CriticalOpenFindings++
			case "high":
				summary.HighOpenFindings++
			}
		}
		if finding.RiskScore > summary.MaxRiskScore {
			summary.MaxRiskScore = finding.RiskScore
		}
		riskScoreTotal += finding.RiskScore
		for _, reason := range finding.RiskReasons {
			reason = strings.TrimSpace(reason)
			if reason != "" {
				reasonCounts[reason]++
			}
		}
	}
	if summary.TotalFindings != 0 {
		summary.AverageRiskScore = float64(riskScoreTotal) / float64(summary.TotalFindings)
	}
	summary.TopRiskReasons = mcpTopRiskReasons(reasonCounts, 10)
	mcpAttachRecentHighRisk(&summary, findings)
	return summary
}

func mcpAttachRecentHighRisk(summary *mcpRiskSummary, findings []*ports.FindingRecord) {
	recent := make([]*ports.FindingRecord, 0, len(findings))
	for _, finding := range findings {
		if finding != nil {
			recent = append(recent, finding)
		}
	}
	sort.Slice(recent, func(i, j int) bool {
		left := recent[i]
		right := recent[j]
		switch {
		case left.RiskScore != right.RiskScore:
			return left.RiskScore > right.RiskScore
		case left.LastObservedAt.Equal(right.LastObservedAt):
			return left.ID < right.ID
		default:
			return left.LastObservedAt.After(right.LastObservedAt)
		}
	})
	if len(recent) > defaultMCPRecentRiskRows {
		recent = recent[:defaultMCPRecentRiskRows]
	}
	for _, finding := range recent {
		if value, err := mcpSafeFindingValue(finding); err == nil {
			summary.RecentHighRisk = append(summary.RecentHighRisk, value)
		}
	}
}

func mcpTopRiskReasons(counts map[string]int, limit int) []mcpRiskReasonCount {
	reasons := make([]mcpRiskReasonCount, 0, len(counts))
	for reason, count := range counts {
		reasons = append(reasons, mcpRiskReasonCount{Reason: reason, Count: count})
	}
	sort.Slice(reasons, func(i, j int) bool {
		if reasons[i].Count == reasons[j].Count {
			return reasons[i].Reason < reasons[j].Reason
		}
		return reasons[i].Count > reasons[j].Count
	})
	if len(reasons) > limit {
		reasons = reasons[:limit]
	}
	return reasons
}

func mcpStringMapFromJSON(raw string) (map[string]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	rawValues := map[string]any{}
	if err := json.Unmarshal([]byte(trimmed), &rawValues); err != nil {
		return nil, fmt.Errorf("%w: decode asset attributes", graphquery.ErrInvalidRequest)
	}
	values := make(map[string]string, len(rawValues))
	for key, value := range rawValues {
		values[key] = mcpAnyString(value)
	}
	return values, nil
}

func mcpRedactSensitiveAttributes(attributes map[string]string) map[string]string {
	return redactSensitiveAttributes(attributes)
}

func mcpSafeFindingValue(finding *ports.FindingRecord) (any, error) {
	return protoJSONValue(mcpSafeFindingMessage(finding))
}

func mcpSafeFindingValues(findings []*ports.FindingRecord) ([]any, error) {
	values := make([]any, 0, len(findings))
	for _, finding := range findings {
		value, err := mcpSafeFindingValue(finding)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func mcpSafeFindingMessage(finding *ports.FindingRecord) *cerebrov1.Finding {
	return safeFindingMessage(finding)
}

func mcpSafeFindingEvidenceValue(evidence *cerebrov1.FindingEvidence) (any, error) {
	return protoJSONValue(mcpSafeFindingEvidence(evidence))
}

func mcpSafeFindingEvidenceValues(evidence []*cerebrov1.FindingEvidence) ([]any, error) {
	values := make([]any, 0, len(evidence))
	for _, record := range evidence {
		value, err := mcpSafeFindingEvidenceValue(record)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func mcpSafeFindingEvidence(evidence *cerebrov1.FindingEvidence) *cerebrov1.FindingEvidence {
	return safeFindingEvidence(evidence)
}

func mcpImpactKindIsAsset(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "asset", "root":
		return true
	default:
		return false
	}
}

func mcpSafeImpactResult(result *graphquery.ImpactResult) *graphquery.ImpactResult {
	if result == nil {
		return nil
	}
	cloned := *result
	cloned.Assets = append([]*ports.NeighborhoodNode(nil), result.Assets...)
	cloned.Packages = append([]*ports.NeighborhoodNode(nil), result.Packages...)
	cloned.Vulnerabilities = append([]*ports.NeighborhoodNode(nil), result.Vulnerabilities...)
	cloned.Evidence = append([]*ports.NeighborhoodNode(nil), result.Evidence...)
	cloned.Relations = mcpSafeNeighborhoodRelations(result.Relations)
	return &cloned
}

func mcpSafeNeighborhoodRelations(relations []*ports.NeighborhoodRelation) []*ports.NeighborhoodRelation {
	if len(relations) == 0 {
		return relations
	}
	safeRelations := make([]*ports.NeighborhoodRelation, 0, len(relations))
	for _, relation := range relations {
		if relation == nil {
			continue
		}
		cloned := *relation
		cloned.Attributes = mcpRedactSensitiveAttributes(relation.Attributes)
		safeRelations = append(safeRelations, &cloned)
	}
	return safeRelations
}

func mcpResponseMetadata(limit int, returned int, partialErrors []string) map[string]any {
	metadata := map[string]any{
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"returned":       returned,
		"stateless":      true,
		"freshness_note": "Snapshot is generated from current Cerebro stores at request time.",
		"redaction_note": "Sensitive attribute values are redacted by key before returning MCP content.",
	}
	if limit > 0 {
		metadata["limit_applied"] = limit
		metadata["truncated"] = returned > limit
		if returned > limit {
			metadata["truncation_reason"] = "limit_reached"
		} else if returned == limit {
			metadata["more_results_possible"] = true
		}
	}
	if len(partialErrors) != 0 {
		metadata["partial_errors"] = append([]string(nil), partialErrors...)
	}
	return metadata
}

func mcpRiskSummaryMetadata(limit int, returned int, total int) map[string]any {
	metadata := mcpResponseMetadata(limit, returned, nil)
	if total > returned {
		metadata["more_results_possible"] = true
		metadata["total_matching_findings"] = total
	}
	return metadata
}

func mcpAddResponseMetadata(value any, metadata map[string]any) map[string]any {
	result, ok := value.(map[string]any)
	if !ok || result == nil {
		return map[string]any{"data": value, "metadata": metadata}
	}
	cloned := make(map[string]any, len(result)+1)
	for key, item := range result {
		cloned[key] = item
	}
	cloned["metadata"] = metadata
	return cloned
}

func mcpMetadataLimit(args map[string]any, key string, defaultLimit int, maxLimit int) int {
	limit, err := mcpBoundedLimit(args, key, defaultLimit, maxLimit)
	if err != nil {
		return defaultLimit
	}
	return limit
}

func mcpNormalizeLimitValue(limit uint32, defaultLimit int, maxLimit int) int {
	if limit == 0 {
		return defaultLimit
	}
	if limit > math.MaxInt32 {
		return maxLimit
	}
	value := int(limit)
	if value > maxLimit {
		return maxLimit
	}
	return value
}

func mcpNeighborhoodResultCount(neighborhood *ports.EntityNeighborhood) int {
	if neighborhood == nil {
		return 0
	}
	return len(neighborhood.Neighbors)
}

func mcpImpactResultCount(result *graphquery.ImpactResult) int {
	if result == nil {
		return 0
	}
	seen := map[string]struct{}{}
	add := func(node *ports.NeighborhoodNode) {
		if node == nil || strings.TrimSpace(node.URN) == "" {
			return
		}
		seen[node.URN] = struct{}{}
	}
	add(result.Root)
	for _, node := range result.Assets {
		add(node)
	}
	for _, node := range result.Packages {
		add(node)
	}
	for _, node := range result.Vulnerabilities {
		add(node)
	}
	for _, node := range result.Evidence {
		add(node)
	}
	return len(seen)
}

func mcpMapArrayCount(value any, key string) int {
	result, ok := value.(map[string]any)
	if !ok {
		return 0
	}
	items, ok := result[key].([]any)
	if !ok {
		return 0
	}
	return len(items)
}

func mcpNormalizeIDLookupError(err error, normalized error) error {
	return normalizeIDLookupError(err, normalized)
}

func mcpAnyString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func jsonValue(value any) (any, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func mcpSuccessToolResult(structured any) (mcpToolResult, error) {
	text, err := json.Marshal(structured)
	if err != nil {
		return mcpToolResult{}, err
	}
	return mcpToolResult{
		Content: []mcpContent{{
			Type: "text",
			Text: string(text),
		}},
		StructuredContent: structured,
	}, nil
}

func mcpErrorToolResult(message string) mcpToolResult {
	return mcpToolResult{
		Content: []mcpContent{{
			Type: "text",
			Text: message,
		}},
		IsError: true,
	}
}

func protoJSONValue(message proto.Message) (any, error) {
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(message)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeMCPJSON(raw json.RawMessage, value any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(value)
}

func mcpStringArg(args map[string]any, key string) string {
	value, ok := args[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func mcpRuntimeIDsArg(args map[string]any) []string {
	values := []string{}
	if runtimeID := mcpStringArg(args, "runtime_id"); runtimeID != "" {
		values = append(values, runtimeID)
	}
	raw, ok := args["runtime_ids"]
	if !ok || raw == nil {
		return normalizeMCPStringList(values)
	}
	switch typed := raw.(type) {
	case []any:
		for _, item := range typed {
			values = append(values, mcpAnyString(item))
		}
	case []string:
		values = append(values, typed...)
	case string:
		values = append(values, splitMCPStringList(typed)...)
	default:
		values = append(values, splitMCPStringList(mcpAnyString(typed))...)
	}
	return normalizeMCPStringList(values)
}

func mcpStringListArg(args map[string]any, key string) []string {
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil
	}
	switch typed := raw.(type) {
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			values = append(values, mcpAnyString(item))
		}
		return normalizeMCPStringList(values)
	case []string:
		return normalizeMCPStringList(typed)
	case string:
		return normalizeMCPStringList(splitMCPStringList(typed))
	default:
		return normalizeMCPStringList(splitMCPStringList(mcpAnyString(typed)))
	}
}

func mcpStringMapArg(args map[string]any, key string) map[string]string {
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil
	}
	out := map[string]string{}
	switch typed := raw.(type) {
	case map[string]any:
		for itemKey, itemValue := range typed {
			itemKey = strings.TrimSpace(itemKey)
			itemString := strings.TrimSpace(mcpAnyString(itemValue))
			if itemKey != "" && itemString != "" {
				out[itemKey] = itemString
			}
		}
	case map[string]string:
		for itemKey, itemValue := range typed {
			itemKey = strings.TrimSpace(itemKey)
			itemValue = strings.TrimSpace(itemValue)
			if itemKey != "" && itemValue != "" {
				out[itemKey] = itemValue
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func splitMCPStringList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	})
	values := make([]string, 0, len(parts))
	values = append(values, parts...)
	return values
}

func normalizeMCPStringList(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	sort.Strings(normalized)
	return normalized
}

func mcpBoolArg(args map[string]any, key string) bool {
	value, ok := args[key]
	if !ok || value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case json.Number:
		return typed.String() != "" && typed.String() != "0"
	case float64:
		return typed != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "1", "true", "yes", "y", "on":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func mcpUint32Arg(args map[string]any, key string) (uint32, error) {
	value, ok := args[key]
	if !ok || value == nil || value == "" {
		return 0, nil
	}
	var raw string
	switch typed := value.(type) {
	case json.Number:
		raw = typed.String()
	case float64:
		raw = fmt.Sprintf("%.0f", typed)
	case string:
		raw = strings.TrimSpace(typed)
	default:
		raw = strings.TrimSpace(fmt.Sprint(typed))
	}
	if raw == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %s must be a positive integer", errInvalidHTTPRequest, key)
	}
	if parsed == 0 || parsed > uint64(^uint32(0)) {
		return 0, fmt.Errorf("%w: %s must be between 1 and %d", errInvalidHTTPRequest, key, uint64(^uint32(0)))
	}
	return uint32(parsed), nil
}

func mcpWriteJSONRPC(w http.ResponseWriter, response mcpJSONRPCResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("MCP-Protocol-Version", mcpProtocolVersion)
	w.Header().Set("X-Cerebro-MCP-Stateless", "true")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func mcpNegotiatedProtocolVersion(r *http.Request, rawParams json.RawMessage) string {
	version := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))
	if mcpSupportedProtocolVersion(version) && version != "" {
		return mcpFirstProtocolVersion(version)
	}
	params := map[string]any{}
	if len(rawParams) != 0 && decodeMCPJSON(rawParams, &params) == nil {
		if requested := mcpStringArg(params, "protocolVersion"); mcpSupportedProtocolVersion(requested) && requested != "" {
			return mcpFirstProtocolVersion(requested)
		}
	}
	return mcpProtocolVersion
}

func mcpSupportedProtocolVersion(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return true
	}
	sawVersion := false
	values := strings.Split(version, ",")
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		sawVersion = true
		switch strings.TrimSpace(value) {
		case mcpProtocolVersion, "2025-06-18", "2025-03-26":
			continue
		default:
			return false
		}
	}
	return sawVersion
}

func mcpFirstProtocolVersion(version string) string {
	for _, value := range strings.Split(strings.TrimSpace(version), ",") {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func (app *App) mcpValidOrigin(r *http.Request) bool {
	rawOrigin := strings.TrimRight(strings.TrimSpace(r.Header.Get("Origin")), "/")
	if rawOrigin == "" {
		return true
	}
	parsed, err := url.Parse(rawOrigin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	origin := resolveRequestOrigin(r, app.cfg.Auth.RequestOrigin)
	allowed := origin.Scheme + "://" + origin.Host
	return strings.EqualFold(rawOrigin, allowed)
}

func mcpFindingMatchesQuery(finding *ports.FindingRecord, query string) bool {
	if finding == nil {
		return false
	}
	values := []string{
		finding.ID,
		finding.Fingerprint,
		finding.RuleID,
		finding.Title,
		finding.Summary,
		finding.Severity,
		finding.Status,
		finding.PolicyID,
		finding.PolicyName,
		finding.CheckID,
		finding.CheckName,
	}
	values = append(values, finding.ResourceURNs...)
	values = append(values, finding.EventIDs...)
	for _, value := range values {
		if strings.Contains(strings.ToLower(strings.TrimSpace(value)), query) {
			return true
		}
	}
	for key, value := range mcpRedactSensitiveAttributes(finding.Attributes) {
		if strings.Contains(strings.ToLower(key), query) || strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func safeMCPToolError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errScopeForbidden):
		return "scope forbidden"
	case errors.Is(err, errTenantForbidden):
		return "tenant forbidden"
	case errors.Is(err, errInvalidHTTPRequest),
		errors.Is(err, graphagent.ErrInvalidRequest),
		errors.Is(err, graphquery.ErrInvalidRequest),
		errors.Is(err, sourceruntime.ErrInvalidRequest),
		errors.Is(err, findingdomain.ErrInvalidRequest):
		return err.Error()
	case errors.Is(err, ports.ErrSourceRuntimeNotFound):
		return "source runtime not found"
	case errors.Is(err, ports.ErrFindingNotFound):
		return "finding not found"
	case errors.Is(err, ports.ErrFindingEvidenceNotFound):
		return "finding evidence not found"
	case errors.Is(err, ports.ErrGraphEntityNotFound):
		return "graph entity not found"
	case errors.Is(err, graphquery.ErrRuntimeUnavailable),
		errors.Is(err, sourceruntime.ErrRuntimeUnavailable),
		errors.Is(err, findingdomain.ErrRuntimeUnavailable):
		return "runtime unavailable"
	default:
		return "tool execution failed"
	}
}
