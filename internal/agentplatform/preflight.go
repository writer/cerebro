package agentplatform

import (
	"strings"
)

const (
	DefaultAgentRunCapabilityID = "graph-reasoning"
	defaultGraphContextMaxRows  = 25
	defaultGraphContextDepth    = 2
	defaultGraphContextChildren = 2
)

type AgentRunPreflightRequest struct {
	TenantID              string                `json:"tenant_id,omitempty"`
	ActorID               string                `json:"actor_id,omitempty"`
	CapabilityIDs         []string              `json:"capability_ids,omitempty"`
	Question              string                `json:"question,omitempty"`
	ScopeURN              string                `json:"scope_urn,omitempty"`
	Model                 string                `json:"model,omitempty"`
	RequestedScopes       []string              `json:"requested_scopes,omitempty"`
	ScopeUnrestricted     bool                  `json:"scope_unrestricted,omitempty"`
	ConnectorReadiness    map[string]string     `json:"connector_readiness,omitempty"`
	EvalStatusOverrides   map[string]string     `json:"eval_status_overrides,omitempty"`
	AllowPreview          bool                  `json:"allow_preview,omitempty"`
	SelectionReason       string                `json:"selection_reason,omitempty"`
	ProvenanceRequirement string                `json:"provenance_requirement,omitempty"`
	CoverageContext       *AgentCoverageContext `json:"coverage_context,omitempty"`
}

type AgentRunPreflight struct {
	Version              string                      `json:"version"`
	TenantID             string                      `json:"tenant_id,omitempty"`
	ActorID              string                      `json:"actor_id,omitempty"`
	Question             string                      `json:"question,omitempty"`
	ScopeURN             string                      `json:"scope_urn,omitempty"`
	Model                string                      `json:"model,omitempty"`
	Enabled              bool                        `json:"enabled"`
	Reason               string                      `json:"reason"`
	Blockers             []CapabilityDecisionBlocker `json:"blockers"`
	SelectedCapabilities []string                    `json:"selected_capabilities"`
	CapabilityDecisions  []CapabilityDecision        `json:"capability_decisions"`
	GraphContext         AgentGraphPlanningContext   `json:"graph_context"`
	ConnectorContext     []AgentConnectorGraphNode   `json:"connector_context"`
	CoverageContext      *AgentCoverageContext       `json:"coverage_context,omitempty"`
	Policy               AgentPolicyDecision         `json:"policy"`
	WriteBack            AgentWriteBackContract      `json:"write_back"`
	RuntimeEvents        []string                    `json:"runtime_events"`
	Provenance           []string                    `json:"provenance"`
}

type AgentGraphPlanningContext struct {
	TenantID           string                   `json:"tenant_id,omitempty"`
	ScopeURN           string                   `json:"scope_urn,omitempty"`
	ScopeTenantID      string                   `json:"scope_tenant_id,omitempty"`
	ReasoningSurface   string                   `json:"reasoning_surface"`
	ReadOnly           bool                     `json:"read_only"`
	CitationRequired   bool                     `json:"citation_required"`
	ProvenanceRequired bool                     `json:"provenance_required"`
	Budget             AgentContextBudget       `json:"budget"`
	QueryModes         []string                 `json:"query_modes"`
	SemanticViews      []AgentSemanticGraphView `json:"semantic_views"`
	ProvenanceSurfaces []string                 `json:"provenance_surfaces"`
}

type AgentSemanticGraphView struct {
	ID               string   `json:"id"`
	Purpose          string   `json:"purpose"`
	QueryMode        string   `json:"query_mode"`
	RequiredEvidence []string `json:"required_evidence,omitempty"`
}

type AgentContextBudget struct {
	MaxRows     int `json:"max_rows"`
	MaxDepth    int `json:"max_depth"`
	MaxChildren int `json:"max_children"`
}

type AgentCoverageContext struct {
	Version             string                   `json:"version"`
	TenantID            string                   `json:"tenant_id,omitempty"`
	SourceID            string                   `json:"source_id,omitempty"`
	GeneratedAt         string                   `json:"generated_at,omitempty"`
	TotalDimensions     int                      `json:"total_dimensions"`
	HighValueDimensions int                      `json:"high_value_dimensions"`
	BlindSpotCount      int                      `json:"blind_spot_count"`
	UnconfiguredCount   int                      `json:"unconfigured_count"`
	StaleCount          int                      `json:"stale_count"`
	FailedCount         int                      `json:"failed_count"`
	UnsupportedCount    int                      `json:"unsupported_count"`
	PartialCount        int                      `json:"partial_count"`
	TopBlindSpots       []AgentCoverageBlindSpot `json:"top_blind_spots,omitempty"`
}

type AgentCoverageBlindSpot struct {
	SourceID      string   `json:"source_id"`
	DimensionID   string   `json:"dimension_id"`
	DimensionType string   `json:"dimension_type"`
	Title         string   `json:"title"`
	State         string   `json:"state"`
	SupportLevel  string   `json:"support_level"`
	RuntimeID     string   `json:"runtime_id,omitempty"`
	Family        string   `json:"family,omitempty"`
	Warning       string   `json:"warning,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

type AgentConnectorGraphNode struct {
	SourceID           string   `json:"source_id"`
	NodeURN            string   `json:"node_urn"`
	OAuthNodeURN       string   `json:"oauth_node_urn,omitempty"`
	TenantID           string   `json:"tenant_id,omitempty"`
	Purpose            string   `json:"purpose"`
	AuthModels         []string `json:"auth_models"`
	RequiredScopes     []string `json:"required_scopes"`
	TokenOwner         string   `json:"token_owner"`
	CredentialBoundary string   `json:"credential_boundary"`
	OAuthSurface       string   `json:"oauth_surface"`
	MCPSurface         string   `json:"mcp_surface"`
	Readiness          string   `json:"readiness"`
	Required           bool     `json:"required"`
	Satisfied          bool     `json:"satisfied"`
}

type AgentPolicyDecision struct {
	Passing      bool               `json:"passing"`
	TenantForced bool               `json:"tenant_forced"`
	TenantID     string             `json:"tenant_id,omitempty"`
	Checks       []AgentPolicyCheck `json:"checks"`
}

type AgentPolicyCheck struct {
	ID      string   `json:"id"`
	Status  string   `json:"status"`
	Message string   `json:"message"`
	Fields  []string `json:"fields,omitempty"`
}

type AgentWriteBackContract struct {
	Required           bool     `json:"required"`
	TraceIDRequired    bool     `json:"trace_id_required"`
	RequiredEvents     []string `json:"required_events"`
	GraphUpdates       []string `json:"graph_updates"`
	ProvenanceSurfaces []string `json:"provenance_surfaces"`
}

func PreflightAgentRun(request AgentRunPreflightRequest) AgentRunPreflight {
	request = normalizeAgentRunPreflightRequest(request)
	capabilityIDs := request.CapabilityIDs
	if len(capabilityIDs) == 0 {
		capabilityIDs = []string{DefaultAgentRunCapabilityID}
	}

	decisions := make([]CapabilityDecision, 0, len(capabilityIDs))
	blockers := []CapabilityDecisionBlocker{}
	for _, capabilityID := range capabilityIDs {
		decision, ok := DecideCapability(CapabilityDecisionRequest{
			CapabilityID:          capabilityID,
			TenantID:              request.TenantID,
			ActorID:               request.ActorID,
			RequestedScopes:       request.RequestedScopes,
			ScopeUnrestricted:     request.ScopeUnrestricted,
			ConnectorReadiness:    request.ConnectorReadiness,
			EvalStatusOverrides:   request.EvalStatusOverrides,
			AllowPreview:          request.AllowPreview,
			SelectionReason:       request.SelectionReason,
			ProvenanceRequirement: request.ProvenanceRequirement,
		})
		if !ok {
			blockers = append(blockers, CapabilityDecisionBlocker{
				Code:    "capability_not_found",
				Message: "Requested capability was not found.",
				Fields:  []string{capabilityID},
			})
			continue
		}
		decisions = append(decisions, decision)
		if !decision.Enabled {
			blockers = append(blockers, CapabilityDecisionBlocker{
				Code:    "capability_blocked",
				Message: "Requested capability is blocked by one or more gates.",
				Fields:  []string{decision.CapabilityID},
			})
			blockers = append(blockers, decision.Blockers...)
		}
	}

	graphContext := agentGraphPlanningContext(request, decisions)
	connectorContext := agentConnectorGraphNodes(request, decisions)
	policy := agentPolicyDecision(request, decisions, graphContext, connectorContext)
	for _, check := range policy.Checks {
		if check.Status == "blocked" {
			blockers = append(blockers, CapabilityDecisionBlocker{
				Code:    check.ID,
				Message: check.Message,
				Fields:  cloneStrings(check.Fields),
			})
		}
	}

	runtimeEvents := agentPreflightRuntimeEvents(decisions)
	provenance := agentPreflightProvenance(decisions)
	writeBack := AgentWriteBackContract{
		Required:           true,
		TraceIDRequired:    true,
		RequiredEvents:     runtimeEvents,
		GraphUpdates:       []string{"agent_run_summary", "capability_selection", "knowledge_context", "connector_gate_status"},
		ProvenanceSurfaces: provenance,
	}

	enabled := len(blockers) == 0 && policy.Passing
	reason := "preflight_passed"
	if !enabled {
		reason = "blocked_by_policy"
	}
	return AgentRunPreflight{
		Version:              ContractVersion,
		TenantID:             request.TenantID,
		ActorID:              request.ActorID,
		Question:             request.Question,
		ScopeURN:             request.ScopeURN,
		Model:                request.Model,
		Enabled:              enabled,
		Reason:               reason,
		Blockers:             dedupeDecisionBlockers(blockers),
		SelectedCapabilities: enabledCapabilityIDs(decisions),
		CapabilityDecisions:  decisions,
		GraphContext:         graphContext,
		ConnectorContext:     connectorContext,
		CoverageContext:      cloneCoverageContext(request.CoverageContext),
		Policy:               policy,
		WriteBack:            writeBack,
		RuntimeEvents:        runtimeEvents,
		Provenance:           provenance,
	}
}

func normalizeAgentRunPreflightRequest(request AgentRunPreflightRequest) AgentRunPreflightRequest {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.ActorID = strings.TrimSpace(request.ActorID)
	request.Question = strings.TrimSpace(request.Question)
	request.ScopeURN = strings.TrimSpace(request.ScopeURN)
	request.Model = strings.TrimSpace(request.Model)
	request.SelectionReason = strings.TrimSpace(request.SelectionReason)
	request.ProvenanceRequirement = strings.TrimSpace(request.ProvenanceRequirement)
	request.CapabilityIDs = uniqueSortedStrings(request.CapabilityIDs)
	request.RequestedScopes = uniqueSortedStrings(request.RequestedScopes)
	if request.ConnectorReadiness == nil {
		request.ConnectorReadiness = map[string]string{}
	}
	if request.EvalStatusOverrides == nil {
		request.EvalStatusOverrides = map[string]string{}
	}
	request.CoverageContext = cloneCoverageContext(request.CoverageContext)
	return request
}

func agentGraphPlanningContext(request AgentRunPreflightRequest, decisions []CapabilityDecision) AgentGraphPlanningContext {
	return AgentGraphPlanningContext{
		TenantID:           request.TenantID,
		ScopeURN:           request.ScopeURN,
		ScopeTenantID:      tenantIDFromCerebroURN(request.ScopeURN),
		ReasoningSurface:   "graph-reasoning",
		ReadOnly:           true,
		CitationRequired:   true,
		ProvenanceRequired: true,
		Budget: AgentContextBudget{
			MaxRows:     defaultGraphContextMaxRows,
			MaxDepth:    defaultGraphContextDepth,
			MaxChildren: defaultGraphContextChildren,
		},
		QueryModes:         []string{"read_only_cypher", "bounded_neighborhood", "citation_grounded_summary"},
		SemanticViews:      agentSemanticGraphViews(),
		ProvenanceSurfaces: agentPreflightProvenance(decisions),
	}
}

func agentConnectorGraphNodes(request AgentRunPreflightRequest, decisions []CapabilityDecision) []AgentConnectorGraphNode {
	nodes := []AgentConnectorGraphNode{}
	seen := map[string]struct{}{}
	for _, decision := range decisions {
		for _, dependency := range decision.RequiredConnectors {
			key := dependency.SourceID
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			readiness := normalizedReadiness(request.ConnectorReadiness[dependency.SourceID])
			if readiness == "" {
				readiness = "unknown"
			}
			sourceURNPart := safeURNPart(dependency.SourceID)
			nodeURN := "urn:cerebro:" + safeURNPart(request.TenantID) + ":connector:" + sourceURNPart
			oauthNodeURN := ""
			if strings.TrimSpace(dependency.OAuthSurface) != "" {
				oauthNodeURN = "urn:cerebro:" + safeURNPart(request.TenantID) + ":oauth:" + sourceURNPart
			}
			nodes = append(nodes, AgentConnectorGraphNode{
				SourceID:           dependency.SourceID,
				NodeURN:            nodeURN,
				OAuthNodeURN:       oauthNodeURN,
				TenantID:           request.TenantID,
				Purpose:            dependency.Purpose,
				AuthModels:         cloneStrings(dependency.AuthModels),
				RequiredScopes:     cloneStrings(dependency.RequiredScopes),
				TokenOwner:         dependency.TokenOwner,
				CredentialBoundary: dependency.CredentialStore,
				OAuthSurface:       dependency.OAuthSurface,
				MCPSurface:         dependency.MCPSurface,
				Readiness:          readiness,
				Required:           true,
				Satisfied:          connectorReady(readiness),
			})
		}
	}
	return nodes
}

func agentPolicyDecision(request AgentRunPreflightRequest, decisions []CapabilityDecision, graphContext AgentGraphPlanningContext, connectors []AgentConnectorGraphNode) AgentPolicyDecision {
	checks := []AgentPolicyCheck{}
	if request.TenantID == "" {
		checks = append(checks, AgentPolicyCheck{ID: "tenant_required", Status: "blocked", Message: "Agent runs require an authenticated tenant."})
	} else {
		checks = append(checks, AgentPolicyCheck{ID: "tenant_forced", Status: "pass", Message: "Agent run tenant is derived from the authenticated principal.", Fields: []string{request.TenantID}})
	}
	switch {
	case graphContext.ScopeURN == "":
		checks = append(checks, AgentPolicyCheck{ID: "scope_tenant", Status: "not_applicable", Message: "No graph scope URN was requested."})
	case graphContext.ScopeTenantID == "":
		checks = append(checks, AgentPolicyCheck{ID: "scope_tenant", Status: "pass", Message: "Requested scope is not a tenant-bearing Cerebro URN."})
	case graphContext.ScopeTenantID == request.TenantID:
		checks = append(checks, AgentPolicyCheck{ID: "scope_tenant", Status: "pass", Message: "Requested graph scope belongs to the effective tenant.", Fields: []string{graphContext.ScopeURN}})
	default:
		checks = append(checks, AgentPolicyCheck{ID: "scope_tenant", Status: "blocked", Message: "Requested graph scope belongs to a different tenant.", Fields: []string{graphContext.ScopeURN}})
	}
	for _, decision := range decisions {
		status := "pass"
		message := "Capability gates passed."
		if !decision.Enabled {
			status = "blocked"
			message = "Capability gates blocked the run."
		}
		checks = append(checks, AgentPolicyCheck{ID: "capability:" + decision.CapabilityID, Status: status, Message: message, Fields: []string{decision.CapabilityID}})
	}
	for _, connector := range connectors {
		status := "pass"
		message := "Connector precondition passed."
		if !connector.Satisfied {
			status = "blocked"
			message = "Connector precondition is not satisfied."
		}
		checks = append(checks, AgentPolicyCheck{ID: "connector:" + connector.SourceID, Status: status, Message: message, Fields: []string{connector.NodeURN}})
	}
	checks = append(checks, agentCoveragePolicyChecks(request.CoverageContext)...)
	passing := true
	for _, check := range checks {
		if check.Status == "blocked" {
			passing = false
			break
		}
	}
	return AgentPolicyDecision{
		Passing:      passing,
		TenantForced: request.TenantID != "",
		TenantID:     request.TenantID,
		Checks:       checks,
	}
}

func agentSemanticGraphViews() []AgentSemanticGraphView {
	return []AgentSemanticGraphView{
		{ID: "source_coverage", Purpose: "Explain which connector-backed facts are present, stale, partial, unsupported, or missing.", QueryMode: "coverage_report", RequiredEvidence: []string{"connector_coverage_report"}},
		{ID: "graph_provenance", Purpose: "Explain why a node, edge, or finding exists in the graph and which projection metadata supports it.", QueryMode: "provenance_lookup", RequiredEvidence: []string{"projection_class", "source_id", "runtime_id"}},
		{ID: "effective_entitlements", Purpose: "Read tenant-scoped identity, group, role, entitlement, and capability paths.", QueryMode: "bounded_cypher", RequiredEvidence: []string{"tenant_id", "source_urns", "citation_status"}},
		{ID: "remediation_lifecycle", Purpose: "Read finding status, external lifecycle references, decisions, actions, outcomes, and reopen signals.", QueryMode: "bounded_cypher", RequiredEvidence: []string{"workflow_event", "external_ref", "finding_status"}},
		{ID: "attack_paths", Purpose: "Read composed reachability and privilege paths with graph citations.", QueryMode: "bounded_cypher", RequiredEvidence: []string{"path_nodes", "path_relations", "citation_status"}},
	}
}

func agentCoveragePolicyChecks(context *AgentCoverageContext) []AgentPolicyCheck {
	if context == nil {
		return []AgentPolicyCheck{{ID: "coverage_context", Status: "not_applicable", Message: "No connector coverage context was supplied."}}
	}
	if context.BlindSpotCount == 0 {
		return []AgentPolicyCheck{{ID: "coverage_context", Status: "pass", Message: "No high-value connector blind spots are reported.", Fields: []string{context.TenantID}}}
	}
	fields := make([]string, 0, len(context.TopBlindSpots)+1)
	fields = append(fields, context.TenantID)
	for _, blindSpot := range context.TopBlindSpots {
		if blindSpot.SourceID != "" && blindSpot.DimensionID != "" {
			fields = append(fields, blindSpot.SourceID+":"+blindSpot.DimensionID)
		}
	}
	return []AgentPolicyCheck{{
		ID:      "coverage_context",
		Status:  "warning",
		Message: "Connector coverage has high-value blind spots; graph answers must preserve coverage caveats.",
		Fields:  uniqueSortedStrings(fields),
	}}
}

func cloneCoverageContext(context *AgentCoverageContext) *AgentCoverageContext {
	if context == nil {
		return nil
	}
	cloned := *context
	cloned.TopBlindSpots = make([]AgentCoverageBlindSpot, len(context.TopBlindSpots))
	for i, blindSpot := range context.TopBlindSpots {
		cloned.TopBlindSpots[i] = blindSpot
		cloned.TopBlindSpots[i].Notes = cloneStrings(blindSpot.Notes)
	}
	return &cloned
}

func agentPreflightRuntimeEvents(decisions []CapabilityDecision) []string {
	events := []string{"agent.preflight.completed"}
	for _, decision := range decisions {
		events = append(events, decision.RuntimeEvents...)
	}
	return uniqueSortedStrings(events)
}

func agentPreflightProvenance(decisions []CapabilityDecision) []string {
	surfaces := []string{"agent-run-preflight"}
	for _, decision := range decisions {
		surfaces = append(surfaces, decision.Provenance...)
	}
	return uniqueSortedStrings(surfaces)
}

func enabledCapabilityIDs(decisions []CapabilityDecision) []string {
	ids := []string{}
	for _, decision := range decisions {
		if decision.Enabled {
			ids = append(ids, decision.CapabilityID)
		}
	}
	return uniqueSortedStrings(ids)
}

func dedupeDecisionBlockers(blockers []CapabilityDecisionBlocker) []CapabilityDecisionBlocker {
	seen := map[string]struct{}{}
	out := make([]CapabilityDecisionBlocker, 0, len(blockers))
	for _, blocker := range blockers {
		key := blocker.Code + "\x00" + strings.Join(blocker.Fields, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		blocker.Fields = cloneStrings(blocker.Fields)
		out = append(out, blocker)
	}
	return out
}

func tenantIDFromCerebroURN(urn string) string {
	parts := strings.SplitN(strings.TrimSpace(urn), ":", 5)
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
		return ""
	}
	return strings.TrimSpace(parts[2])
}

func safeURNPart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
