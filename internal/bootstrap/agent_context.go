package bootstrap

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

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/agentplatform"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/reports"
	"github.com/writer/cerebro/internal/sourceruntime"
)

const agentContextPath = "/api/v1/agent/context"

type agentContextResponse struct {
	Version          string                `json:"version"`
	Links            map[string]string     `json:"links"`
	Auth             agentAuthDiscovery    `json:"auth"`
	Caller           agentCallerContext    `json:"caller"`
	MutationContract agentMutationContract `json:"mutation_contract"`
	Telemetry        agentTelemetryContext `json:"telemetry"`
	Workflows        []agentWorkflow       `json:"workflows"`
}

type agentAuthDiscovery struct {
	Schemes                   []string `json:"schemes"`
	ProtectedResourceMetadata string   `json:"protected_resource_metadata"`
	AuthorizationServer       string   `json:"authorization_server"`
	TokenEndpoint             string   `json:"token_endpoint"`
	RequiredDefaultScope      string   `json:"required_default_scope"`
	SupportedScopes           []string `json:"supported_scopes"`
}

type agentCallerContext struct {
	Authenticated bool     `json:"authenticated"`
	TenantID      string   `json:"tenant_id,omitempty"`
	ActorID       string   `json:"actor_id,omitempty"`
	AuthMode      string   `json:"auth_mode,omitempty"`
	ActorType     string   `json:"actor_type"`
	Scopes        []string `json:"scopes,omitempty"`
	UserAgent     string   `json:"user_agent"`
}

type agentMutationContract struct {
	DryRunField      string   `json:"dry_run_field"`
	ApprovalField    string   `json:"approval_field"`
	Idempotency      string   `json:"idempotency"`
	DefaultBehavior  string   `json:"default_behavior"`
	ExecutionRules   []string `json:"execution_rules"`
	SupportedActions []string `json:"supported_actions"`
}

type agentTelemetryContext struct {
	ActorTypeAttribute string   `json:"actor_type_attribute"`
	UserAgentAttribute string   `json:"user_agent_attribute"`
	RequestHeaders     []string `json:"request_headers"`
}

type agentWorkflow struct {
	ID             string            `json:"id"`
	Resource       string            `json:"resource"`
	StateCheck     agentNextAction   `json:"state_check"`
	NextActions    []agentNextAction `json:"next_actions"`
	SlackBotIntent string            `json:"slack_bot_intent,omitempty"`
}

type agentNextAction struct {
	ID               string `json:"id"`
	Label            string `json:"label"`
	Method           string `json:"method"`
	Path             string `json:"path"`
	RequiredScope    string `json:"required_scope"`
	Stage            string `json:"stage"`
	DryRunSupported  bool   `json:"dry_run_supported,omitempty"`
	ApprovalRequired bool   `json:"approval_required,omitempty"`
	When             string `json:"when"`
}

type agentTaskRequest struct {
	TenantID    string            `json:"tenant_id,omitempty"`
	DryRun      bool              `json:"dry_run,omitempty"`
	Approved    bool              `json:"approved,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Parameters  map[string]string `json:"parameters,omitempty"`
	Idempotency string            `json:"idempotency_key,omitempty"`
}

type agentTaskResponse struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	Status      string            `json:"status"`
	Resource    agentResourceRef  `json:"resource"`
	DryRun      bool              `json:"dry_run"`
	Approved    bool              `json:"approved"`
	Reason      string            `json:"reason,omitempty"`
	Mutation    *agentMutationRef `json:"mutation,omitempty"`
	NextActions []agentNextAction `json:"next_actions,omitempty"`
	Result      map[string]any    `json:"result,omitempty"`
}

type agentResourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Path string `json:"path"`
}

type agentMutationRef struct {
	Method           string            `json:"method"`
	Path             string            `json:"path"`
	RequiredScope    string            `json:"required_scope"`
	ApprovalRequired bool              `json:"approval_required"`
	DryRunSupported  bool              `json:"dry_run_supported"`
	Parameters       map[string]string `json:"parameters,omitempty"`
}

func (a *App) handleAgentContext(w http.ResponseWriter, r *http.Request) {
	origin := strings.TrimRight(externalOrigin(r, a.cfg.Auth.RequestOrigin), "/")
	if origin == "" {
		origin = "https://cerebro"
	}
	writeJSON(w, http.StatusOK, agentContextResponse{
		Version: agentplatform.ContractVersion,
		Links: map[string]string{
			"openapi":             origin + "/openapi.yaml",
			"agent_card":          origin + agentplatform.A2AAgentCardPath,
			"agent_platform":      origin + "/api/v1/agent-platform/contract",
			"capabilities":        origin + "/api/v1/agent-platform/capabilities",
			"event_subscriptions": origin + agentplatform.EventSubscriptionContractPath,
			"idempotency":         origin + agentplatform.IdempotencyContractPath,
		},
		Auth:             agentAuthDiscoveryForOrigin(origin),
		Caller:           agentCallerContextForRequest(r),
		MutationContract: agentMutationContractForContext(),
		Telemetry: agentTelemetryContext{
			ActorTypeAttribute: "client.actor_type",
			UserAgentAttribute: "user_agent.family",
			RequestHeaders:     []string{"User-Agent", "X-Request-Id", "X-Cerebro-Tenant", "Idempotency-Key"},
		},
		Workflows: agentWorkflows(),
	})
}

func agentAuthDiscoveryForOrigin(origin string) agentAuthDiscovery {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	if origin == "" {
		origin = "https://cerebro"
	}
	return agentAuthDiscovery{
		Schemes:                   []string{"Authorization: Bearer <token>", "X-Cerebro-API-Key: <key>"},
		ProtectedResourceMetadata: origin + oauthProtectedResourceMetadataPath,
		AuthorizationServer:       origin + oauthAuthorizationServerMetadataPath,
		TokenEndpoint:             origin + oauthTokenPath,
		RequiredDefaultScope:      scopeCosmoSecurityRead,
		SupportedScopes:           supportedOAuthScopes(),
	}
}

func agentCallerContextForRequest(r *http.Request) agentCallerContext {
	ctx := agentCallerContext{
		ActorType: agentActorTypeFromUserAgent(requestHeaderValue(r, "User-Agent")),
		UserAgent: userAgentFamilyValue(requestHeaderValue(r, "User-Agent")),
	}
	if r == nil {
		return ctx
	}
	auth, ok := r.Context().Value(authContextKey{}).(authContext)
	if !ok {
		return ctx
	}
	ctx.Authenticated = true
	ctx.TenantID = strings.TrimSpace(auth.principal.TenantID)
	ctx.ActorID = agentPlatformPrincipalActorID(auth.principal, "")
	ctx.AuthMode = strings.TrimSpace(auth.principal.AuthMode)
	ctx.Scopes = expandedPrincipalScopes(auth.principal)
	if ctx.ActorType == "unknown" || ctx.ActorType == "automation" {
		ctx.ActorType = agentActorTypeFromPrincipal(auth.principal, requestHeaderValue(r, "User-Agent"))
	}
	return ctx
}

func agentActorTypeFromPrincipal(principal authPrincipal, userAgent string) string {
	switch strings.TrimSpace(principal.AuthMode) {
	case "device_jwt":
		return "agent"
	case "api_credential", "capability_token":
		return "service"
	}
	return agentActorTypeFromUserAgent(userAgent)
}

func agentActorTypeFromUserAgent(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch {
	case normalized == "":
		return "unknown"
	case strings.Contains(normalized, "codex"),
		strings.Contains(normalized, "openai"),
		strings.Contains(normalized, "mcp"),
		strings.Contains(normalized, "langchain"),
		strings.Contains(normalized, "autogen"),
		strings.Contains(normalized, "crewai"),
		strings.Contains(normalized, "claude"),
		strings.Contains(normalized, "anthropic"):
		return "agent"
	case strings.Contains(normalized, "bot"),
		strings.Contains(normalized, "crawler"),
		strings.Contains(normalized, "spider"):
		return "agent"
	case strings.Contains(normalized, "mozilla") &&
		(strings.Contains(normalized, "chrome") || strings.Contains(normalized, "safari") || strings.Contains(normalized, "firefox") || strings.Contains(normalized, "edg/")):
		return "human"
	case strings.Contains(normalized, "curl"),
		strings.Contains(normalized, "httpie"),
		strings.Contains(normalized, "wget"),
		strings.Contains(normalized, "python-requests"),
		strings.Contains(normalized, "go-http-client"),
		strings.Contains(normalized, "node-fetch"),
		strings.Contains(normalized, "axios"),
		strings.Contains(normalized, "postman"):
		return "automation"
	default:
		return "unknown"
	}
}

func userAgentFamilyValue(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch {
	case normalized == "":
		return "none"
	case strings.Contains(normalized, "codex"):
		return "codex"
	case strings.Contains(normalized, "openai"):
		return "openai"
	case strings.Contains(normalized, "mcp"):
		return "mcp"
	case strings.Contains(normalized, "slack"):
		return "slack"
	case strings.Contains(normalized, "bot"), strings.Contains(normalized, "crawler"), strings.Contains(normalized, "spider"):
		return "bot"
	case strings.Contains(normalized, "edge"), strings.Contains(normalized, "edg/"):
		return "edge"
	case strings.Contains(normalized, "chrome"):
		return "chrome"
	case strings.Contains(normalized, "safari"):
		return "safari"
	case strings.Contains(normalized, "firefox"):
		return "firefox"
	case strings.Contains(normalized, "curl"):
		return "curl"
	case strings.Contains(normalized, "python-requests"):
		return "python-requests"
	case strings.Contains(normalized, "go-http-client"):
		return "go-http-client"
	case strings.Contains(normalized, "node-fetch"):
		return "node-fetch"
	case strings.Contains(normalized, "axios"):
		return "axios"
	case strings.Contains(normalized, "postman"):
		return "postman"
	default:
		return "other"
	}
}

func requestHeaderValue(r *http.Request, key string) string {
	if r == nil {
		return ""
	}
	return r.Header.Get(key)
}

func agentMutationContractForContext() agentMutationContract {
	return agentMutationContract{
		DryRunField:     "dry_run",
		ApprovalField:   "approved",
		Idempotency:     "Use Idempotency-Key or idempotency_key on approved writes that may be retried.",
		DefaultBehavior: "Agent task endpoints return a plan unless approved=true and dry_run is false.",
		ExecutionRules: []string{
			"Read and explain actions require the read scope only.",
			"Mutating runtime and report tasks require their dedicated write scope.",
			"Provider-backed graph actions support dry_run=true and require approved=true before execution.",
			"Finding lifecycle updates stay on typed finding endpoints and require the finding lifecycle write scope.",
		},
		SupportedActions: []string{
			"identity.okta.suspend_user",
			"identity.okta.unsuspend_user",
			"endpoint.cerebro.revoke_device",
		},
	}
}

func agentWorkflows() []agentWorkflow {
	return []agentWorkflow{
		{
			ID:         "finding_triage",
			Resource:   "finding",
			StateCheck: agentNextAction{ID: "read_finding", Label: "Read finding", Method: http.MethodGet, Path: "/findings/{findingID}", RequiredScope: scopeCosmoSecurityRead, Stage: "observe", When: "Start here before changing finding state."},
			NextActions: []agentNextAction{
				{ID: "explain_finding", Label: "Explain finding", Method: http.MethodPost, Path: "/api/v1/agent/tasks/findings/{findingID}/explain", RequiredScope: scopeCosmoSecurityRead, Stage: "explain", When: "Use when a bot needs a short packet for a channel or review thread."},
				{ID: "triage_finding", Label: "Prepare triage", Method: http.MethodPost, Path: "/api/v1/agent/tasks/findings/{findingID}/triage", RequiredScope: scopeCosmoSecurityRead, Stage: "recommend", When: "Use when the next owner, due date, note, or ticket is not decided yet."},
				{ID: "plan_graph_action", Label: "Dry-run graph action", Method: http.MethodPost, Path: "/platform/graph/actions", RequiredScope: scopeGraphActionsWrite, Stage: "dry_run", DryRunSupported: true, ApprovalRequired: true, When: "Use for provider-backed actions tied to an eligible finding."},
			},
			SlackBotIntent: "Post finding summary, owner, evidence, and proposed next step.",
		},
		{
			ID:         "control_packet",
			Resource:   "control",
			StateCheck: agentNextAction{ID: "read_controls", Label: "Read controls", Method: http.MethodGet, Path: "/grc/controls", RequiredScope: scopeCosmoSecurityRead, Stage: "observe", When: "Use before collecting evidence for control status."},
			NextActions: []agentNextAction{
				{ID: "build_control_packet", Label: "Build control packet", Method: http.MethodGet, Path: "/grc/control-packets", RequiredScope: scopeCosmoSecurityRead, Stage: "explain", When: "Use when the team needs evidence and gaps for a control."},
				{ID: "custom_control_packet", Label: "Build scoped packet", Method: http.MethodPost, Path: "/grc/control-packets", RequiredScope: scopeCosmoSecurityRead, Stage: "explain", When: "Use when the bot has a specific framework, control, or evidence scope."},
			},
			SlackBotIntent: "Post control status, missing evidence, stale evidence, and owners.",
		},
		{
			ID:         "report_run",
			Resource:   "report",
			StateCheck: agentNextAction{ID: "list_reports", Label: "List reports", Method: http.MethodGet, Path: "/reports", RequiredScope: scopeCosmoSecurityRead, Stage: "observe", When: "Use before selecting a report id."},
			NextActions: []agentNextAction{
				{ID: "plan_report_run", Label: "Plan report run", Method: http.MethodPost, Path: "/api/v1/agent/tasks/reports/{reportID}/run", RequiredScope: scopeCosmoSecurityRead, Stage: "dry_run", DryRunSupported: true, When: "Use when a bot needs to show parameters before running a report."},
				{ID: "run_report", Label: "Run report", Method: http.MethodPost, Path: "/api/v1/agent/tasks/reports/{reportID}/run", RequiredScope: scopeReportsRun, Stage: "execute", DryRunSupported: true, ApprovalRequired: true, When: "Use after a human approves the report parameters."},
			},
			SlackBotIntent: "Post report parameters, run status, and link to the report run.",
		},
		{
			ID:         "runtime_retry",
			Resource:   "source_runtime",
			StateCheck: agentNextAction{ID: "read_runtime", Label: "Read runtime", Method: http.MethodGet, Path: "/source-runtimes/{runtimeID}", RequiredScope: scopeCosmoSecurityRead, Stage: "observe", When: "Use before retrying a runtime."},
			NextActions: []agentNextAction{
				{ID: "plan_runtime_retry", Label: "Plan runtime retry", Method: http.MethodPost, Path: "/api/v1/agent/tasks/source-runtimes/{runtimeID}/retry", RequiredScope: scopeCosmoSecurityRead, Stage: "dry_run", DryRunSupported: true, When: "Use when a runtime is stale or failed and the bot needs the exact retry call."},
				{ID: "retry_runtime", Label: "Retry runtime", Method: http.MethodPost, Path: "/api/v1/agent/tasks/source-runtimes/{runtimeID}/retry", RequiredScope: scopeSourceRuntimesWrite, Stage: "execute", DryRunSupported: true, ApprovalRequired: true, When: "Use after a human approves the retry."},
			},
			SlackBotIntent: "Post runtime status, last sync, failure reason, and retry plan.",
		},
	}
}

func (a *App) handleAgentFindingExplainTask(w http.ResponseWriter, r *http.Request) {
	findingID := r.PathValue("findingID")
	if err := authorizeFindingIDTenant(r.Context(), findingStore(a.deps.StateStore), findingID); err != nil {
		writeAgentTaskError(w, normalizeIDLookupError(err, ports.ErrFindingNotFound))
		return
	}
	req, err := readAgentTaskRequest(w, r)
	if err != nil {
		writeAgentTaskError(w, err)
		return
	}
	response := baseAgentTaskResponse("finding_explain", "finding", findingID, "/findings/"+findingID, req)
	response.Status = "planned"
	response.NextActions = findingAgentNextActions(findingID)
	response.Result = map[string]any{
		"read_path":        "/findings/" + findingID,
		"evidence_request": "/api/v1/agent-platform/evidence-packets",
		"graph_reason":     "/api/v1/agent-platform/graph/reason",
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleAgentFindingTriageTask(w http.ResponseWriter, r *http.Request) {
	findingID := r.PathValue("findingID")
	if err := authorizeFindingIDTenant(r.Context(), findingStore(a.deps.StateStore), findingID); err != nil {
		writeAgentTaskError(w, normalizeIDLookupError(err, ports.ErrFindingNotFound))
		return
	}
	req, err := readAgentTaskRequest(w, r)
	if err != nil {
		writeAgentTaskError(w, err)
		return
	}
	response := baseAgentTaskResponse("finding_triage", "finding", findingID, "/findings/"+findingID, req)
	response.Status = "planned"
	response.NextActions = findingAgentNextActions(findingID)
	response.Result = map[string]any{
		"lifecycle_paths": []string{
			"/findings/" + findingID + "/assign",
			"/findings/" + findingID + "/due",
			"/findings/" + findingID + "/notes",
			"/findings/" + findingID + "/tickets",
			"/findings/" + findingID + "/resolve",
			"/findings/" + findingID + "/suppress",
		},
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleAgentFindingAuditPacketTask(w http.ResponseWriter, r *http.Request) {
	findingID := r.PathValue("findingID")
	if err := authorizeFindingIDTenant(r.Context(), findingStore(a.deps.StateStore), findingID); err != nil {
		writeAgentTaskError(w, normalizeIDLookupError(err, ports.ErrFindingNotFound))
		return
	}
	req, err := readAgentTaskRequest(w, r)
	if err != nil {
		writeAgentTaskError(w, err)
		return
	}
	response := baseAgentTaskResponse("finding_audit_packet", "finding", findingID, "/findings/"+findingID, req)
	response.Status = "planned"
	response.NextActions = []agentNextAction{
		{ID: "build_evidence_packet", Label: "Build evidence packet", Method: http.MethodPost, Path: "/api/v1/agent-platform/evidence-packets", RequiredScope: scopeCosmoSecurityRead, Stage: "explain", When: "Use scope_urn for the finding and include evidence URNs when known."},
		{ID: "read_control_packets", Label: "Read control packets", Method: http.MethodGet, Path: "/grc/control-packets", RequiredScope: scopeCosmoSecurityRead, Stage: "explain", When: "Use when the finding maps to framework controls."},
	}
	response.Result = map[string]any{
		"scope_urn": "urn:cerebro:{tenant}:finding:" + findingID,
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleAgentSourceRuntimeRetryTask(w http.ResponseWriter, r *http.Request) {
	runtimeID := r.PathValue("runtimeID")
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), runtimeID); err != nil {
		writeAgentTaskError(w, normalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound))
		return
	}
	req, err := readAgentTaskRequest(w, r)
	if err != nil {
		writeAgentTaskError(w, err)
		return
	}
	response := baseAgentTaskResponse("source_runtime_retry", "source_runtime", runtimeID, "/source-runtimes/"+runtimeID, req)
	response.Mutation = &agentMutationRef{
		Method:           http.MethodPost,
		Path:             "/source-runtimes/" + runtimeID + "/sync",
		RequiredScope:    scopeSourceRuntimesWrite,
		ApprovalRequired: true,
		DryRunSupported:  true,
		Parameters:       req.Parameters,
	}
	if req.DryRun || !req.Approved {
		response.Status = "dry_run"
		response.DryRun = true
		response.NextActions = []agentNextAction{
			{ID: "approve_runtime_retry", Label: "Approve runtime retry", Method: http.MethodPost, Path: "/api/v1/agent/tasks/source-runtimes/" + runtimeID + "/retry", RequiredScope: scopeSourceRuntimesWrite, Stage: "execute", DryRunSupported: true, ApprovalRequired: true, When: "Call with approved=true after review."},
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if err := authorizeAgentTaskExecutionScope(r.Context(), scopeSourceRuntimesWrite); err != nil {
		writeAgentTaskError(w, err)
		return
	}
	pageLimit, err := pageLimitFromTask(req)
	if err != nil {
		writeAgentTaskError(w, err)
		return
	}
	syncResp, err := a.runtimeService().SyncWithLease(r.Context(), &cerebrov1.SyncSourceRuntimeRequest{Id: runtimeID, PageLimit: pageLimit}, sourceruntime.SyncWithLeaseOptions{
		LeaseStore: sourceRuntimeLeaseStore(a.deps.StateStore),
	})
	if err != nil {
		writeAgentTaskError(w, err)
		return
	}
	response.Status = "succeeded"
	response.Result = map[string]any{
		"runtime_id":         syncResp.GetRuntime().GetId(),
		"pages_read":         syncResp.GetPagesRead(),
		"events_appended":    syncResp.GetEventsAppended(),
		"entities_projected": syncResp.GetEntitiesProjected(),
		"links_projected":    syncResp.GetLinksProjected(),
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleAgentReportRunTask(w http.ResponseWriter, r *http.Request) {
	reportID := r.PathValue("reportID")
	req, err := readAgentTaskRequest(w, r)
	if err != nil {
		writeAgentTaskError(w, err)
		return
	}
	if tenantID := strings.TrimSpace(firstNonEmpty(req.TenantID, req.Parameters["tenant_id"])); tenantID != "" {
		if err := authorizeTenantID(r.Context(), tenantID); err != nil {
			writeAgentTaskError(w, err)
			return
		}
	}
	response := baseAgentTaskResponse("report_run", "report", reportID, "/reports/"+reportID+"/runs", req)
	response.Mutation = &agentMutationRef{
		Method:           http.MethodPost,
		Path:             "/reports/" + reportID + "/runs",
		RequiredScope:    scopeReportsRun,
		ApprovalRequired: true,
		DryRunSupported:  true,
		Parameters:       req.Parameters,
	}
	if req.DryRun || !req.Approved {
		response.Status = "dry_run"
		response.DryRun = true
		response.NextActions = []agentNextAction{
			{ID: "approve_report_run", Label: "Approve report run", Method: http.MethodPost, Path: "/api/v1/agent/tasks/reports/" + reportID + "/run", RequiredScope: scopeReportsRun, Stage: "execute", DryRunSupported: true, ApprovalRequired: true, When: "Call with approved=true after checking report parameters."},
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if err := authorizeAgentTaskExecutionScope(r.Context(), scopeReportsRun); err != nil {
		writeAgentTaskError(w, err)
		return
	}
	runResp, err := a.reportService().Run(r.Context(), &cerebrov1.RunReportRequest{ReportId: reportID, Parameters: req.Parameters})
	if err != nil {
		writeAgentTaskError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), runResp.GetRun().GetParameters()["tenant_id"]); err != nil {
		writeAgentTaskError(w, err)
		return
	}
	response.Status = "succeeded"
	response.Result = map[string]any{
		"report_id":    runResp.GetRun().GetReportId(),
		"run_id":       runResp.GetRun().GetId(),
		"status":       runResp.GetRun().GetStatus(),
		"generated_at": agentTaskTimestampString(runResp.GetRun().GetGeneratedAt()),
	}
	writeJSON(w, http.StatusOK, response)
}

func baseAgentTaskResponse(kind string, resourceType string, resourceID string, path string, req agentTaskRequest) agentTaskResponse {
	return agentTaskResponse{
		ID:       "agent-task:" + kind + ":" + resourceID,
		Kind:     kind,
		Status:   "planned",
		Resource: agentResourceRef{Type: resourceType, ID: resourceID, Path: path},
		DryRun:   req.DryRun,
		Approved: req.Approved,
		Reason:   strings.TrimSpace(req.Reason),
	}
}

func findingAgentNextActions(findingID string) []agentNextAction {
	return []agentNextAction{
		{ID: "build_evidence_packet", Label: "Build evidence packet", Method: http.MethodPost, Path: "/api/v1/agent-platform/evidence-packets", RequiredScope: scopeCosmoSecurityRead, Stage: "explain", When: "Use before posting a finding summary or making a recommendation."},
		{ID: "add_note", Label: "Add finding note", Method: http.MethodPost, Path: "/findings/" + findingID + "/notes", RequiredScope: scopeFindingLifecycleWrite, Stage: "close_loop", ApprovalRequired: true, When: "Use after the team approves the note text."},
		{ID: "link_ticket", Label: "Link ticket", Method: http.MethodPost, Path: "/findings/" + findingID + "/tickets", RequiredScope: scopeFindingLifecycleWrite, Stage: "close_loop", ApprovalRequired: true, When: "Use when a remediation ticket already exists."},
		{ID: "dry_run_graph_action", Label: "Dry-run graph action", Method: http.MethodPost, Path: "/platform/graph/actions", RequiredScope: scopeGraphActionsWrite, Stage: "dry_run", DryRunSupported: true, ApprovalRequired: true, When: "Use for supported provider actions attached to the finding."},
	}
}

func readAgentTaskRequest(w http.ResponseWriter, r *http.Request) (agentTaskRequest, error) {
	request := agentTaskRequest{Parameters: map[string]string{}}
	if r == nil || r.Body == nil {
		return request, nil
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		if errors.Is(err, io.EOF) {
			return request, nil
		}
		return agentTaskRequest{}, fmt.Errorf("%w: decode agent task request: %w", errInvalidHTTPRequest, err)
	}
	if request.Parameters == nil {
		request.Parameters = map[string]string{}
	}
	return request, nil
}

func pageLimitFromTask(req agentTaskRequest) (uint32, error) {
	raw := strings.TrimSpace(req.Parameters["page_limit"])
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: page_limit must be a positive integer", errInvalidHTTPRequest)
	}
	if value == 0 {
		return 0, fmt.Errorf("%w: page_limit must be a positive integer", errInvalidHTTPRequest)
	}
	return uint32(value), nil
}

func authorizeAgentTaskExecutionScope(ctx context.Context, required string) error {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	if !ok || !principalScopeRestricted(auth.principal) {
		return nil
	}
	return authorizePrincipalScope(auth.principal, required)
}

func writeAgentTaskError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, errInvalidHTTPRequest), errors.Is(err, reports.ErrInvalidRequest), errors.Is(err, sourceruntime.ErrInvalidRequest):
		status = http.StatusBadRequest
	case errors.Is(err, errTenantForbidden), errors.Is(err, errScopeForbidden):
		status = http.StatusForbidden
	case errors.Is(err, ports.ErrFindingNotFound), errors.Is(err, ports.ErrSourceRuntimeNotFound):
		status = http.StatusNotFound
	case errors.Is(err, sourceruntime.ErrRuntimeUnavailable), errors.Is(err, reports.ErrRuntimeUnavailable), errors.Is(err, findings.ErrRuntimeUnavailable):
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"error": err.Error()})
}

func agentTaskTimestampString(ts interface{ AsTime() time.Time }) string {
	if ts == nil {
		return ""
	}
	value := ts.AsTime()
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
