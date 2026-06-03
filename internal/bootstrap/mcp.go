package bootstrap

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/buildinfo"
	findingdomain "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceruntime"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	mcpProtocolVersion       = "2025-03-26"
	mcpEndpointPath          = "/api/v1/mcp"
	mcpRedactedValue         = "[redacted]"
	defaultMCPListLimit      = 25
	maxMCPListLimit          = 100
	defaultMCPAssetLimit     = 10
	maxMCPAssetLimit         = 50
	defaultMCPRiskLimit      = 100
	maxMCPRiskLimit          = 500
	defaultMCPRecentRiskRows = 10
)

type mcpJSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
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

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
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
	Type string `json:"type"`
	Text string `json:"text"`
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
}

type mcpRiskReasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

func (app *App) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	defer func() { _ = r.Body.Close() }()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes))
	decoder.UseNumber()
	var request mcpJSONRPCRequest
	if err := decoder.Decode(&request); err != nil {
		mcpWriteJSONRPC(w, r, mcpJSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &mcpError{Code: -32700, Message: "parse error"},
		})
		return
	}
	if len(request.ID) == 0 && strings.HasPrefix(request.Method, "notifications/") {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	response := app.handleMCPRequest(r, request)
	mcpWriteJSONRPC(w, r, response)
}

func (app *App) handleMCPStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	sessionID := mcpSessionID(r)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Mcp-Session-Id", sessionID)
	_, _ = fmt.Fprintf(w, "event: ready\ndata: %s\n\n", mcpEndpointPath)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
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
	switch request.Method {
	case "initialize":
		response.Result = app.mcpInitializeResult(r)
	case "ping":
		response.Result = map[string]any{}
	case "tools/list":
		response.Result = map[string]any{"tools": mcpTools()}
	case "tools/call":
		result, err := app.mcpCallTool(r, request.Params)
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

func (app *App) mcpInitializeResult(r *http.Request) map[string]any {
	return map[string]any{
		"protocolVersion": mcpNegotiatedProtocolVersion(r),
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    buildinfo.ServiceName,
			"version": buildinfo.Version,
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
	structured, err := app.mcpToolStructuredContent(r, strings.TrimSpace(params.Name), args)
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
	case "cerebro.findings.list":
		return app.mcpListFindings(r, args)
	case "cerebro.findings.get":
		return app.mcpGetFinding(r, args)
	case "cerebro.assets.search":
		return app.mcpSearchAssets(r, args)
	case "cerebro.risk.summary":
		return app.mcpRiskSummary(r, args)
	case "cerebro.graph.neighborhood":
		return app.mcpGraphNeighborhood(r, args)
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
		Limit:     uint32(limit),
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
			return map[string]any{"runtimes": []any{}}, nil
		}
		if err != nil {
			return nil, err
		}
		if !tenantAllowedByContext(r.Context(), runtime.GetTenantId()) {
			return map[string]any{"runtimes": []any{}}, nil
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
	return map[string]any{"runtimes": values}, nil
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
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(app.deps.StateStore), runtimeID, false); err != nil {
		return nil, err
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
		Limit:       uint32(limit),
		Order:       order,
	})
	if err != nil {
		return nil, err
	}
	return protoJSONValue(listFindingsResponse(response))
}

func (app *App) mcpGetFinding(r *http.Request, args map[string]any) (any, error) {
	findingID := mcpStringArg(args, "finding_id")
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding_id is required", findingdomain.ErrInvalidRequest)
	}
	if err := authorizeFindingIDTenant(r.Context(), findingStore(app.deps.StateStore), findingID); err != nil {
		return nil, err
	}
	finding, err := app.findingService().GetFinding(r.Context(), findingID)
	if err != nil {
		return nil, err
	}
	return protoJSONValue(&cerebrov1.GetFindingResponse{Finding: findingMessage(finding)})
}

func (app *App) mcpSearchAssets(r *http.Request, args map[string]any) (any, error) {
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
			return nil, err
		}
		if tenantID == "" {
			tenantID = cerebroURNTenant(urn)
		}
	}
	if runtimeID != "" {
		if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(app.deps.StateStore), runtimeID, false); err != nil {
			return nil, err
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
  AND ($query = '' OR toLower(coalesce(e.urn, '')) CONTAINS $query OR toLower(coalesce(e.label, '')) CONTAINS $query OR toLower(coalesce(e.attributes_json, '')) CONTAINS $query)
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
	return map[string]any{"assets": assets}, nil
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
		if err := authorizeSourceRuntimeIDTenant(r.Context(), runtimeStore, runtimeID, false); err != nil {
			return nil, err
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
		Limit:     uint32(limit),
		Order:     ports.FindingOrderRiskScore,
	})
	if err != nil {
		return nil, err
	}
	return mcpBuildRiskSummary(tenantID, runtimeID, limit, findings), nil
}

func (app *App) mcpGraphNeighborhood(r *http.Request, args map[string]any) (any, error) {
	rootURN := mcpStringArg(args, "root_urn")
	limit, err := mcpUint32Arg(args, "limit")
	if err != nil {
		return nil, err
	}
	if err := authorizeCerebroURNTenant(r.Context(), rootURN); err != nil {
		return nil, err
	}
	response, err := app.graphQueryService().GetEntityNeighborhood(r.Context(), graphquery.NeighborhoodRequest{
		RootURN: rootURN,
		Limit:   limit,
	})
	if err != nil {
		return nil, err
	}
	return protoJSONValue(graphNeighborhoodResponse(response))
}

func mcpTools() []mcpTool {
	return []mcpTool{
		{
			Name:        "cerebro.health",
			Description: "Return Cerebro service health and dependency status.",
			InputSchema: mcpObjectSchema(nil, nil),
		},
		{
			Name:        "cerebro.version",
			Description: "Return Cerebro service build and API version metadata.",
			InputSchema: mcpObjectSchema(nil, nil),
		},
		{
			Name:        "cerebro.source_runtimes.list",
			Description: "List source runtimes visible to the authenticated caller. Runtime config values are redacted.",
			InputSchema: mcpObjectSchema(map[string]any{
				"runtime_id": map[string]any{"type": "string"},
				"tenant_id":  map[string]any{"type": "string"},
				"source_id":  map[string]any{"type": "string"},
				"limit":      map[string]any{"type": "integer", "minimum": 1},
			}, nil),
		},
		{
			Name:        "cerebro.findings.list",
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
				"limit":        map[string]any{"type": "integer", "minimum": 1},
				"order":        map[string]any{"type": "string", "enum": []string{"last_observed", "priority", "risk_score"}},
			}, []string{"runtime_id"}),
		},
		{
			Name:        "cerebro.findings.get",
			Description: "Return one finding by ID if it is visible to the authenticated caller.",
			InputSchema: mcpObjectSchema(map[string]any{
				"finding_id": map[string]any{"type": "string"},
			}, []string{"finding_id"}),
		},
		{
			Name:        "cerebro.assets.search",
			Description: "Search graph assets/entities visible to the authenticated caller by query, URN, entity type, tenant, or runtime.",
			InputSchema: mcpObjectSchema(map[string]any{
				"query":       map[string]any{"type": "string"},
				"urn":         map[string]any{"type": "string"},
				"entity_type": map[string]any{"type": "string"},
				"tenant_id":   map[string]any{"type": "string"},
				"runtime_id":  map[string]any{"type": "string"},
				"limit":       map[string]any{"type": "integer", "minimum": 1, "maximum": maxMCPAssetLimit},
			}, nil),
		},
		{
			Name:        "cerebro.risk.summary",
			Description: "Summarize visible finding risk by severity, status, risk score, and top risk reasons.",
			InputSchema: mcpObjectSchema(map[string]any{
				"tenant_id":  map[string]any{"type": "string"},
				"runtime_id": map[string]any{"type": "string"},
				"status":     map[string]any{"type": "string", "enum": []string{"open", "resolved", "suppressed"}},
				"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": maxMCPRiskLimit},
			}, nil),
		},
		{
			Name:        "cerebro.graph.neighborhood",
			Description: "Return a bounded graph neighborhood around a Cerebro URN visible to the authenticated caller.",
			InputSchema: mcpObjectSchema(map[string]any{
				"root_urn": map[string]any{"type": "string"},
				"limit":    map[string]any{"type": "integer", "minimum": 1},
			}, []string{"root_urn"}),
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
	switch {
	case limit == 0:
		return defaultLimit, nil
	case int(limit) > maxLimit:
		return maxLimit, nil
	default:
		return int(limit), nil
	}
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
			if len(findings) >= int(request.Limit) {
				break
			}
			scoped.Limit = request.Limit - uint32(len(findings))
		}
		items, err := store.ListFindings(ctx, scoped)
		if err != nil {
			return nil, err
		}
		findings = append(findings, items...)
	}
	return findings, nil
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
		summary.RecentHighRisk = append(summary.RecentHighRisk, findingMessage(finding))
	}
	return summary
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
	values := map[string]string{}
	if err := json.Unmarshal([]byte(trimmed), &values); err != nil {
		return nil, fmt.Errorf("%w: decode asset attributes", graphquery.ErrInvalidRequest)
	}
	return values, nil
}

func mcpRedactSensitiveAttributes(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return attributes
	}
	redacted := make(map[string]string, len(attributes))
	for key, value := range attributes {
		if sensitiveSourceConfigKey(key) {
			redacted[key] = mcpRedactedValue
			continue
		}
		redacted[key] = value
	}
	return redacted
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

func mcpWriteJSONRPC(w http.ResponseWriter, r *http.Request, response mcpJSONRPCResponse) {
	sessionID := mcpSessionID(r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Mcp-Session-Id", sessionID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func mcpSessionID(r *http.Request) string {
	if r != nil {
		if sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id")); sessionID != "" {
			return sessionID
		}
	}
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "cerebro-session"
	}
	return hex.EncodeToString(bytes[:])
}

func mcpNegotiatedProtocolVersion(r *http.Request) string {
	version := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))
	if version != "" {
		return version
	}
	return mcpProtocolVersion
}

func safeMCPToolError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errTenantForbidden):
		return "tenant forbidden"
	case errors.Is(err, errInvalidHTTPRequest),
		errors.Is(err, graphquery.ErrInvalidRequest),
		errors.Is(err, sourceruntime.ErrInvalidRequest),
		errors.Is(err, findingdomain.ErrInvalidRequest):
		return err.Error()
	case errors.Is(err, ports.ErrSourceRuntimeNotFound):
		return "source runtime not found"
	case errors.Is(err, ports.ErrFindingNotFound):
		return "finding not found"
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
