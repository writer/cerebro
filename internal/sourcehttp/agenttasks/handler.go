package agenttasks

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

	"github.com/writer/cerebro/internal/agentplatform"
)

const ContextPath = "/api/v1/agent/context"

var ErrInvalidRequest = errors.New("invalid agent task request")

type ScopeSet struct {
	SecurityRead          string
	GraphActionsWrite     string
	FindingLifecycleWrite string
	SourceRuntimesWrite   string
	ReportsRun            string
}

type Dependencies struct {
	Origin                       func(*http.Request) string
	Caller                       func(*http.Request) CallerContext
	SupportedScopes              func() []string
	OAuthProtectedResourcePath   string
	OAuthAuthorizationServerPath string
	OAuthTokenPath               string
	Scopes                       ScopeSet
	AuthorizeFinding             func(context.Context, string) error
	AuthorizeSourceRuntime       func(context.Context, string) error
	AuthorizeTenant              func(context.Context, string) error
	AuthorizeExecutionScope      func(context.Context, string) error
	SyncRuntime                  func(context.Context, string, uint32) (RuntimeSyncResult, error)
	RunReport                    func(context.Context, string, map[string]string) (ReportRunResult, error)
	ErrorStatus                  func(error) int
	ErrorMessage                 func(int, error) string
}

type Handler struct {
	deps Dependencies
}

type ContextResponse struct {
	Version          string            `json:"version"`
	Links            map[string]string `json:"links"`
	Auth             AuthDiscovery     `json:"auth"`
	Caller           CallerContext     `json:"caller"`
	MutationContract MutationContract  `json:"mutation_contract"`
	Telemetry        TelemetryContext  `json:"telemetry"`
	Workflows        []Workflow        `json:"workflows"`
}

type AuthDiscovery struct {
	Schemes                   []string `json:"schemes"`
	ProtectedResourceMetadata string   `json:"protected_resource_metadata"`
	AuthorizationServer       string   `json:"authorization_server"`
	TokenEndpoint             string   `json:"token_endpoint"`
	RequiredDefaultScope      string   `json:"required_default_scope"`
	SupportedScopes           []string `json:"supported_scopes"`
}

type CallerContext struct {
	Authenticated bool     `json:"authenticated"`
	TenantID      string   `json:"tenant_id,omitempty"`
	ActorID       string   `json:"actor_id,omitempty"`
	AuthMode      string   `json:"auth_mode,omitempty"`
	ActorType     string   `json:"actor_type"`
	Scopes        []string `json:"scopes,omitempty"`
	UserAgent     string   `json:"user_agent"`
}

type MutationContract struct {
	DryRunField      string   `json:"dry_run_field"`
	ApprovalField    string   `json:"approval_field"`
	Idempotency      string   `json:"idempotency"`
	DefaultBehavior  string   `json:"default_behavior"`
	ExecutionRules   []string `json:"execution_rules"`
	SupportedActions []string `json:"supported_actions"`
}

type TelemetryContext struct {
	ActorTypeAttribute string   `json:"actor_type_attribute"`
	UserAgentAttribute string   `json:"user_agent_attribute"`
	RequestHeaders     []string `json:"request_headers"`
}

type Workflow struct {
	ID             string       `json:"id"`
	Resource       string       `json:"resource"`
	StateCheck     NextAction   `json:"state_check"`
	NextActions    []NextAction `json:"next_actions"`
	SlackBotIntent string       `json:"slack_bot_intent,omitempty"`
}

type NextAction struct {
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

type TaskRequest struct {
	TenantID    string            `json:"tenant_id,omitempty"`
	DryRun      bool              `json:"dry_run,omitempty"`
	Approved    bool              `json:"approved,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Parameters  map[string]string `json:"parameters,omitempty"`
	Idempotency string            `json:"idempotency_key,omitempty"`
}

type TaskResponse struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	Status      string         `json:"status"`
	Resource    ResourceRef    `json:"resource"`
	DryRun      bool           `json:"dry_run"`
	Approved    bool           `json:"approved"`
	Reason      string         `json:"reason,omitempty"`
	Mutation    *MutationRef   `json:"mutation,omitempty"`
	NextActions []NextAction   `json:"next_actions,omitempty"`
	Result      map[string]any `json:"result,omitempty"`
}

type ResourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Path string `json:"path"`
}

type MutationRef struct {
	Method           string            `json:"method"`
	Path             string            `json:"path"`
	RequiredScope    string            `json:"required_scope"`
	ApprovalRequired bool              `json:"approval_required"`
	DryRunSupported  bool              `json:"dry_run_supported"`
	Parameters       map[string]string `json:"parameters,omitempty"`
}

type RuntimeSyncResult struct {
	RuntimeID         string
	PagesRead         uint32
	EventsAppended    uint32
	EntitiesProjected uint32
	LinksProjected    uint32
}

type ReportRunResult struct {
	ReportID    string
	RunID       string
	Status      string
	GeneratedAt time.Time
}

func New(deps Dependencies) Handler {
	return Handler{deps: deps}
}

func (h Handler) Context(w http.ResponseWriter, r *http.Request) {
	origin := h.origin(r)
	writeJSON(w, http.StatusOK, ContextResponse{
		Version: agentplatform.ContractVersion,
		Links: map[string]string{
			"openapi":             origin + "/openapi.yaml",
			"agent_card":          origin + agentplatform.A2AAgentCardPath,
			"agent_platform":      origin + "/api/v1/agent-platform/contract",
			"capabilities":        origin + "/api/v1/agent-platform/capabilities",
			"event_subscriptions": origin + agentplatform.EventSubscriptionContractPath,
			"idempotency":         origin + agentplatform.IdempotencyContractPath,
		},
		Auth:             h.authDiscovery(origin),
		Caller:           h.caller(r),
		MutationContract: mutationContract(),
		Telemetry: TelemetryContext{
			ActorTypeAttribute: "client.actor_type",
			UserAgentAttribute: "user_agent.family",
			RequestHeaders:     []string{"User-Agent", "X-Request-Id", "X-Cerebro-Tenant", "Idempotency-Key"},
		},
		Workflows: h.workflows(),
	})
}

func (h Handler) FindingExplain(w http.ResponseWriter, r *http.Request) {
	findingID := r.PathValue("findingID")
	if err := h.authorizeFinding(r.Context(), findingID); err != nil {
		h.writeError(w, err)
		return
	}
	req, err := readTaskRequest(w, r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	response := h.baseTaskResponse("finding_explain", "finding", findingID, "/findings/"+findingID, req)
	response.Status = "planned"
	response.NextActions = h.findingNextActions(findingID)
	response.Result = map[string]any{
		"read_path":        "/findings/" + findingID,
		"evidence_request": "/api/v1/agent-platform/evidence-packets",
		"graph_reason":     "/api/v1/agent-platform/graph/reason",
	}
	writeJSON(w, http.StatusOK, response)
}

func (h Handler) FindingTriage(w http.ResponseWriter, r *http.Request) {
	findingID := r.PathValue("findingID")
	if err := h.authorizeFinding(r.Context(), findingID); err != nil {
		h.writeError(w, err)
		return
	}
	req, err := readTaskRequest(w, r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	response := h.baseTaskResponse("finding_triage", "finding", findingID, "/findings/"+findingID, req)
	response.Status = "planned"
	response.NextActions = h.findingNextActions(findingID)
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

func (h Handler) FindingAuditPacket(w http.ResponseWriter, r *http.Request) {
	findingID := r.PathValue("findingID")
	if err := h.authorizeFinding(r.Context(), findingID); err != nil {
		h.writeError(w, err)
		return
	}
	req, err := readTaskRequest(w, r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	response := h.baseTaskResponse("finding_audit_packet", "finding", findingID, "/findings/"+findingID, req)
	response.Status = "planned"
	response.NextActions = []NextAction{
		{ID: "build_evidence_packet", Label: "Build evidence packet", Method: http.MethodPost, Path: "/api/v1/agent-platform/evidence-packets", RequiredScope: h.deps.Scopes.SecurityRead, Stage: "explain", When: "Use scope_urn for the finding and include evidence URNs when known."},
		{ID: "read_control_packets", Label: "Read control packets", Method: http.MethodGet, Path: "/grc/control-packets", RequiredScope: h.deps.Scopes.SecurityRead, Stage: "explain", When: "Use when the finding maps to framework controls."},
	}
	response.Result = map[string]any{
		"scope_urn": "urn:cerebro:{tenant}:finding:" + findingID,
	}
	writeJSON(w, http.StatusOK, response)
}

func (h Handler) SourceRuntimeRetry(w http.ResponseWriter, r *http.Request) {
	runtimeID := r.PathValue("runtimeID")
	if err := h.authorizeSourceRuntime(r.Context(), runtimeID); err != nil {
		h.writeError(w, err)
		return
	}
	req, err := readTaskRequest(w, r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	response := h.baseTaskResponse("source_runtime_retry", "source_runtime", runtimeID, "/source-runtimes/"+runtimeID, req)
	response.Mutation = &MutationRef{
		Method:           http.MethodPost,
		Path:             "/source-runtimes/" + runtimeID + "/sync",
		RequiredScope:    h.deps.Scopes.SourceRuntimesWrite,
		ApprovalRequired: true,
		DryRunSupported:  true,
		Parameters:       req.Parameters,
	}
	if req.DryRun || !req.Approved {
		response.Status = "dry_run"
		response.DryRun = true
		response.NextActions = []NextAction{
			{ID: "approve_runtime_retry", Label: "Approve runtime retry", Method: http.MethodPost, Path: "/api/v1/agent/tasks/source-runtimes/" + runtimeID + "/retry", RequiredScope: h.deps.Scopes.SourceRuntimesWrite, Stage: "execute", DryRunSupported: true, ApprovalRequired: true, When: "Call with approved=true after review."},
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if err := h.authorizeExecutionScope(r.Context(), h.deps.Scopes.SourceRuntimesWrite); err != nil {
		h.writeError(w, err)
		return
	}
	pageLimit, err := pageLimitFromTask(req)
	if err != nil {
		h.writeError(w, err)
		return
	}
	result, err := h.syncRuntime(r.Context(), runtimeID, pageLimit)
	if err != nil {
		h.writeError(w, err)
		return
	}
	response.Status = "succeeded"
	response.Result = map[string]any{
		"runtime_id":         result.RuntimeID,
		"pages_read":         result.PagesRead,
		"events_appended":    result.EventsAppended,
		"entities_projected": result.EntitiesProjected,
		"links_projected":    result.LinksProjected,
	}
	writeJSON(w, http.StatusOK, response)
}

func (h Handler) ReportRun(w http.ResponseWriter, r *http.Request) {
	reportID := r.PathValue("reportID")
	req, err := readTaskRequest(w, r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if tenantID := strings.TrimSpace(firstNonEmpty(req.TenantID, req.Parameters["tenant_id"])); tenantID != "" {
		if err := h.authorizeTenant(r.Context(), tenantID); err != nil {
			h.writeError(w, err)
			return
		}
	}
	response := h.baseTaskResponse("report_run", "report", reportID, "/reports/"+reportID+"/runs", req)
	response.Mutation = &MutationRef{
		Method:           http.MethodPost,
		Path:             "/reports/" + reportID + "/runs",
		RequiredScope:    h.deps.Scopes.ReportsRun,
		ApprovalRequired: true,
		DryRunSupported:  true,
		Parameters:       req.Parameters,
	}
	if req.DryRun || !req.Approved {
		response.Status = "dry_run"
		response.DryRun = true
		response.NextActions = []NextAction{
			{ID: "approve_report_run", Label: "Approve report run", Method: http.MethodPost, Path: "/api/v1/agent/tasks/reports/" + reportID + "/run", RequiredScope: h.deps.Scopes.ReportsRun, Stage: "execute", DryRunSupported: true, ApprovalRequired: true, When: "Call with approved=true after checking report parameters."},
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if err := h.authorizeExecutionScope(r.Context(), h.deps.Scopes.ReportsRun); err != nil {
		h.writeError(w, err)
		return
	}
	result, err := h.runReport(r.Context(), reportID, req.Parameters)
	if err != nil {
		h.writeError(w, err)
		return
	}
	response.Status = "succeeded"
	response.Result = map[string]any{
		"report_id":    result.ReportID,
		"run_id":       result.RunID,
		"status":       result.Status,
		"generated_at": timestampString(result.GeneratedAt),
	}
	writeJSON(w, http.StatusOK, response)
}

func (h Handler) authDiscovery(origin string) AuthDiscovery {
	return AuthDiscovery{
		Schemes:                   []string{"Authorization: Bearer <token>", "X-Cerebro-API-Key: <key>"},
		ProtectedResourceMetadata: origin + h.deps.OAuthProtectedResourcePath,
		AuthorizationServer:       origin + h.deps.OAuthAuthorizationServerPath,
		TokenEndpoint:             origin + h.deps.OAuthTokenPath,
		RequiredDefaultScope:      h.deps.Scopes.SecurityRead,
		SupportedScopes:           h.supportedScopes(),
	}
}

func (h Handler) workflows() []Workflow {
	scopes := h.deps.Scopes
	return []Workflow{
		{
			ID:         "finding_triage",
			Resource:   "finding",
			StateCheck: NextAction{ID: "read_finding", Label: "Read finding", Method: http.MethodGet, Path: "/findings/{findingID}", RequiredScope: scopes.SecurityRead, Stage: "observe", When: "Start here before changing finding state."},
			NextActions: []NextAction{
				{ID: "explain_finding", Label: "Explain finding", Method: http.MethodPost, Path: "/api/v1/agent/tasks/findings/{findingID}/explain", RequiredScope: scopes.SecurityRead, Stage: "explain", When: "Use when a bot needs a short packet for a channel or review thread."},
				{ID: "triage_finding", Label: "Prepare triage", Method: http.MethodPost, Path: "/api/v1/agent/tasks/findings/{findingID}/triage", RequiredScope: scopes.SecurityRead, Stage: "recommend", When: "Use when the next owner, due date, note, or ticket is not decided yet."},
				{ID: "plan_graph_action", Label: "Dry-run graph action", Method: http.MethodPost, Path: "/platform/graph/actions", RequiredScope: scopes.GraphActionsWrite, Stage: "dry_run", DryRunSupported: true, ApprovalRequired: true, When: "Use for provider-backed actions tied to an eligible finding."},
			},
			SlackBotIntent: "Post finding summary, owner, evidence, and proposed next step.",
		},
		{
			ID:         "control_packet",
			Resource:   "control",
			StateCheck: NextAction{ID: "read_controls", Label: "Read controls", Method: http.MethodGet, Path: "/grc/controls", RequiredScope: scopes.SecurityRead, Stage: "observe", When: "Use before collecting evidence for control status."},
			NextActions: []NextAction{
				{ID: "build_control_packet", Label: "Build control packet", Method: http.MethodGet, Path: "/grc/control-packets", RequiredScope: scopes.SecurityRead, Stage: "explain", When: "Use when the team needs evidence and gaps for a control."},
				{ID: "custom_control_packet", Label: "Build scoped packet", Method: http.MethodPost, Path: "/grc/control-packets", RequiredScope: scopes.SecurityRead, Stage: "explain", When: "Use when the bot has a specific framework, control, or evidence scope."},
			},
			SlackBotIntent: "Post control status, missing evidence, stale evidence, and owners.",
		},
		{
			ID:         "report_run",
			Resource:   "report",
			StateCheck: NextAction{ID: "list_reports", Label: "List reports", Method: http.MethodGet, Path: "/reports", RequiredScope: scopes.SecurityRead, Stage: "observe", When: "Use before selecting a report id."},
			NextActions: []NextAction{
				{ID: "plan_report_run", Label: "Plan report run", Method: http.MethodPost, Path: "/api/v1/agent/tasks/reports/{reportID}/run", RequiredScope: scopes.SecurityRead, Stage: "dry_run", DryRunSupported: true, When: "Use when a bot needs to show parameters before running a report."},
				{ID: "run_report", Label: "Run report", Method: http.MethodPost, Path: "/api/v1/agent/tasks/reports/{reportID}/run", RequiredScope: scopes.ReportsRun, Stage: "execute", DryRunSupported: true, ApprovalRequired: true, When: "Use after a human approves the report parameters."},
			},
			SlackBotIntent: "Post report parameters, run status, and link to the report run.",
		},
		{
			ID:         "runtime_retry",
			Resource:   "source_runtime",
			StateCheck: NextAction{ID: "read_runtime", Label: "Read runtime", Method: http.MethodGet, Path: "/source-runtimes/{runtimeID}", RequiredScope: scopes.SecurityRead, Stage: "observe", When: "Use before retrying a runtime."},
			NextActions: []NextAction{
				{ID: "plan_runtime_retry", Label: "Plan runtime retry", Method: http.MethodPost, Path: "/api/v1/agent/tasks/source-runtimes/{runtimeID}/retry", RequiredScope: scopes.SecurityRead, Stage: "dry_run", DryRunSupported: true, When: "Use when a runtime is stale or failed and the bot needs the exact retry call."},
				{ID: "retry_runtime", Label: "Retry runtime", Method: http.MethodPost, Path: "/api/v1/agent/tasks/source-runtimes/{runtimeID}/retry", RequiredScope: scopes.SourceRuntimesWrite, Stage: "execute", DryRunSupported: true, ApprovalRequired: true, When: "Use after a human approves the retry."},
			},
			SlackBotIntent: "Post runtime status, last sync, failure reason, and retry plan.",
		},
	}
}

func ActorTypeFromUserAgent(value string) string {
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

func UserAgentFamily(value string) string {
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

func mutationContract() MutationContract {
	return MutationContract{
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

func (h Handler) baseTaskResponse(kind string, resourceType string, resourceID string, path string, req TaskRequest) TaskResponse {
	return TaskResponse{
		ID:       "agent-task:" + kind + ":" + resourceID,
		Kind:     kind,
		Status:   "planned",
		Resource: ResourceRef{Type: resourceType, ID: resourceID, Path: path},
		DryRun:   req.DryRun,
		Approved: req.Approved,
		Reason:   strings.TrimSpace(req.Reason),
	}
}

func (h Handler) findingNextActions(findingID string) []NextAction {
	scopes := h.deps.Scopes
	return []NextAction{
		{ID: "build_evidence_packet", Label: "Build evidence packet", Method: http.MethodPost, Path: "/api/v1/agent-platform/evidence-packets", RequiredScope: scopes.SecurityRead, Stage: "explain", When: "Use before posting a finding summary or making a recommendation."},
		{ID: "add_note", Label: "Add finding note", Method: http.MethodPost, Path: "/findings/" + findingID + "/notes", RequiredScope: scopes.FindingLifecycleWrite, Stage: "close_loop", ApprovalRequired: true, When: "Use after the team approves the note text."},
		{ID: "link_ticket", Label: "Link ticket", Method: http.MethodPost, Path: "/findings/" + findingID + "/tickets", RequiredScope: scopes.FindingLifecycleWrite, Stage: "close_loop", ApprovalRequired: true, When: "Use when a remediation ticket already exists."},
		{ID: "dry_run_graph_action", Label: "Dry-run graph action", Method: http.MethodPost, Path: "/platform/graph/actions", RequiredScope: scopes.GraphActionsWrite, Stage: "dry_run", DryRunSupported: true, ApprovalRequired: true, When: "Use for supported provider actions attached to the finding."},
	}
}

func readTaskRequest(w http.ResponseWriter, r *http.Request) (TaskRequest, error) {
	request := TaskRequest{Parameters: map[string]string{}}
	if r == nil || r.Body == nil {
		return request, nil
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	if err := decoder.Decode(&request); err != nil {
		if errors.Is(err, io.EOF) {
			return request, nil
		}
		return TaskRequest{}, fmt.Errorf("%w: decode agent task request: %w", ErrInvalidRequest, err)
	}
	if request.Parameters == nil {
		request.Parameters = map[string]string{}
	}
	return request, nil
}

func pageLimitFromTask(req TaskRequest) (uint32, error) {
	raw := strings.TrimSpace(req.Parameters["page_limit"])
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: page_limit must be a positive integer", ErrInvalidRequest)
	}
	if value == 0 {
		return 0, fmt.Errorf("%w: page_limit must be a positive integer", ErrInvalidRequest)
	}
	return uint32(value), nil
}

func (h Handler) origin(r *http.Request) string {
	origin := ""
	if h.deps.Origin != nil {
		origin = h.deps.Origin(r)
	}
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	if origin == "" {
		return "https://cerebro"
	}
	return origin
}

func (h Handler) caller(r *http.Request) CallerContext {
	if h.deps.Caller == nil {
		return CallerContext{ActorType: "unknown", UserAgent: "none"}
	}
	return h.deps.Caller(r)
}

func (h Handler) supportedScopes() []string {
	if h.deps.SupportedScopes == nil {
		return nil
	}
	return h.deps.SupportedScopes()
}

func (h Handler) authorizeFinding(ctx context.Context, findingID string) error {
	if h.deps.AuthorizeFinding == nil {
		return nil
	}
	return h.deps.AuthorizeFinding(ctx, findingID)
}

func (h Handler) authorizeSourceRuntime(ctx context.Context, runtimeID string) error {
	if h.deps.AuthorizeSourceRuntime == nil {
		return nil
	}
	return h.deps.AuthorizeSourceRuntime(ctx, runtimeID)
}

func (h Handler) authorizeTenant(ctx context.Context, tenantID string) error {
	if h.deps.AuthorizeTenant == nil {
		return nil
	}
	return h.deps.AuthorizeTenant(ctx, tenantID)
}

func (h Handler) authorizeExecutionScope(ctx context.Context, scope string) error {
	if h.deps.AuthorizeExecutionScope == nil {
		return nil
	}
	return h.deps.AuthorizeExecutionScope(ctx, scope)
}

func (h Handler) syncRuntime(ctx context.Context, runtimeID string, pageLimit uint32) (RuntimeSyncResult, error) {
	if h.deps.SyncRuntime == nil {
		return RuntimeSyncResult{}, errors.New("agent runtime sync is not configured")
	}
	return h.deps.SyncRuntime(ctx, runtimeID, pageLimit)
}

func (h Handler) runReport(ctx context.Context, reportID string, parameters map[string]string) (ReportRunResult, error) {
	if h.deps.RunReport == nil {
		return ReportRunResult{}, errors.New("agent report run is not configured")
	}
	return h.deps.RunReport(ctx, reportID, parameters)
}

func (h Handler) writeError(w http.ResponseWriter, err error) {
	status := h.status(err)
	message := err.Error()
	if h.deps.ErrorMessage != nil {
		message = h.deps.ErrorMessage(status, err)
	}
	writeJSON(w, status, map[string]any{"error": message})
}

func (h Handler) status(err error) int {
	if h.deps.ErrorStatus != nil {
		if status := h.deps.ErrorStatus(err); status != 0 {
			return status
		}
	}
	if errors.Is(err, ErrInvalidRequest) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func timestampString(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
