package agentplatform

import (
	"sort"
	"strings"
)

type CapabilityRegistryFilter struct {
	DomainID  string `json:"domain_id,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Risk      string `json:"risk,omitempty"`
	DefaultOn *bool  `json:"default_on,omitempty"`
}

type CapabilityRegistry struct {
	Version      string                   `json:"version"`
	Filters      CapabilityRegistryFilter `json:"filters"`
	Capabilities []Capability             `json:"capabilities"`
	Totals       CapabilityRegistryTotals `json:"totals"`
}

type CapabilityRegistryTotals struct {
	Capabilities int            `json:"capabilities"`
	DefaultOn    int            `json:"default_on"`
	DefaultOff   int            `json:"default_off"`
	ByDomain     map[string]int `json:"by_domain"`
	ByRisk       map[string]int `json:"by_risk"`
}

type CapabilityDecisionRequest struct {
	CapabilityID          string            `json:"capability_id"`
	TenantID              string            `json:"tenant_id,omitempty"`
	ActorID               string            `json:"actor_id,omitempty"`
	RequestedScopes       []string          `json:"requested_scopes,omitempty"`
	ScopeUnrestricted     bool              `json:"scope_unrestricted,omitempty"`
	ConnectorReadiness    map[string]string `json:"connector_readiness,omitempty"`
	EvalStatusOverrides   map[string]string `json:"eval_status_overrides,omitempty"`
	AllowPreview          bool              `json:"allow_preview,omitempty"`
	SelectionReason       string            `json:"selection_reason,omitempty"`
	ProvenanceRequirement string            `json:"provenance_requirement,omitempty"`
}

type CapabilityDecision struct {
	Version                 string                      `json:"version"`
	CapabilityID            string                      `json:"capability_id"`
	CapabilityVersion       string                      `json:"capability_version"`
	DomainID                string                      `json:"domain_id"`
	TenantID                string                      `json:"tenant_id,omitempty"`
	ActorID                 string                      `json:"actor_id,omitempty"`
	Enabled                 bool                        `json:"enabled"`
	Reason                  string                      `json:"reason"`
	Blockers                []CapabilityDecisionBlocker `json:"blockers"`
	RequiredScopes          []string                    `json:"required_scopes"`
	MissingScopes           []string                    `json:"missing_scopes,omitempty"`
	RequiredConnectors      []ConnectorDependency       `json:"required_connectors,omitempty"`
	RuntimeEvents           []string                    `json:"runtime_events"`
	Provenance              []string                    `json:"provenance"`
	Eval                    CapabilityEvalGate          `json:"eval"`
	Review                  ReviewStatus                `json:"review"`
	ConnectorInfrastructure *ConnectorInfrastructure    `json:"connector_infrastructure,omitempty"`
}

type CapabilityDecisionBlocker struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Fields  []string `json:"fields,omitempty"`
}

type CapabilityEvalGate struct {
	Required     bool     `json:"required"`
	Status       string   `json:"status"`
	Passing      bool     `json:"passing"`
	ScenarioSets []string `json:"scenario_sets"`
	Rubrics      []string `json:"rubrics"`
}

func ListCapabilities(filter CapabilityRegistryFilter) CapabilityRegistry {
	filter = normalizeCapabilityRegistryFilter(filter)
	capabilities := make([]Capability, 0, len(Capabilities))
	for _, capability := range Capabilities {
		if !matchesCapabilityFilter(capability, filter) {
			continue
		}
		capabilities = append(capabilities, cloneCapability(capability))
	}
	return CapabilityRegistry{
		Version:      ContractVersion,
		Filters:      filter,
		Capabilities: capabilities,
		Totals:       capabilityRegistryTotals(capabilities),
	}
}

func DecideCapability(request CapabilityDecisionRequest) (CapabilityDecision, bool) {
	request = normalizeCapabilityDecisionRequest(request)
	capability, ok := CapabilityByID(request.CapabilityID)
	if !ok {
		return CapabilityDecision{}, false
	}

	requiredScopes := uniqueSortedStrings(append(cloneStrings(capability.RequiredScopes), connectorRequiredScopes(capability.ConnectorDependencies)...))
	missingScopes := []string{}
	if !request.ScopeUnrestricted {
		missingScopes = missingStrings(requiredScopes, request.RequestedScopes)
	}
	requiredConnectors := requiredConnectorDependencies(capability.ConnectorDependencies)
	eval := capabilityEvalGate(capability, request.EvalStatusOverrides)
	blockers := make([]CapabilityDecisionBlocker, 0, 4)

	if !capability.DefaultOn && !request.AllowPreview {
		blockers = append(blockers, CapabilityDecisionBlocker{
			Code:    "preview_required",
			Message: "Capability is not default-on and requires explicit preview selection.",
		})
	}
	if len(missingScopes) > 0 {
		blockers = append(blockers, CapabilityDecisionBlocker{
			Code:    "missing_scope",
			Message: "Caller is missing one or more required scopes.",
			Fields:  missingScopes,
		})
	}
	for _, dependency := range requiredConnectors {
		readiness := normalizedReadiness(request.ConnectorReadiness[dependency.SourceID])
		if !connectorReady(readiness) {
			code := "connector_not_ready"
			message := "Required connector dependency is not ready."
			if readiness == "" {
				code = "connector_readiness_unknown"
				message = "Required connector dependency readiness was not provided."
			}
			blockers = append(blockers, CapabilityDecisionBlocker{
				Code:    code,
				Message: message,
				Fields:  []string{dependency.SourceID},
			})
		}
	}
	if eval.Required && !eval.Passing {
		blockers = append(blockers, CapabilityDecisionBlocker{
			Code:    "eval_not_passing",
			Message: "Capability eval gate is not passing.",
			Fields:  []string{eval.Status},
		})
	}
	if request.ProvenanceRequirement != "" && !containsValue(capability.Provenance, request.ProvenanceRequirement) {
		blockers = append(blockers, CapabilityDecisionBlocker{
			Code:    "provenance_requirement_missing",
			Message: "Capability does not satisfy the requested provenance surface.",
			Fields:  []string{request.ProvenanceRequirement},
		})
	}

	reason := "default_enabled"
	if request.AllowPreview && !capability.DefaultOn {
		reason = "preview_allowed"
	}
	if len(blockers) > 0 {
		reason = "blocked_by_policy"
	}
	if request.SelectionReason != "" && len(blockers) == 0 {
		reason = request.SelectionReason
	}

	return CapabilityDecision{
		Version:                 ContractVersion,
		CapabilityID:            capability.ID,
		CapabilityVersion:       capability.Version,
		DomainID:                capability.DomainID,
		TenantID:                request.TenantID,
		ActorID:                 request.ActorID,
		Enabled:                 len(blockers) == 0,
		Reason:                  reason,
		Blockers:                blockers,
		RequiredScopes:          requiredScopes,
		MissingScopes:           missingScopes,
		RequiredConnectors:      requiredConnectors,
		RuntimeEvents:           cloneStrings(capability.RuntimeEvents),
		Provenance:              cloneStrings(capability.Provenance),
		Eval:                    eval,
		Review:                  cloneReviewStatus(capability.Review),
		ConnectorInfrastructure: connectorInfrastructureForDecision(requiredConnectors),
	}, true
}

func CapabilityByID(id string) (Capability, bool) {
	id = strings.TrimSpace(id)
	for _, capability := range Capabilities {
		if capability.ID == id {
			return cloneCapability(capability), true
		}
	}
	return Capability{}, false
}

func normalizeCapabilityRegistryFilter(filter CapabilityRegistryFilter) CapabilityRegistryFilter {
	filter.DomainID = strings.TrimSpace(filter.DomainID)
	filter.Kind = strings.TrimSpace(filter.Kind)
	filter.Owner = strings.TrimSpace(filter.Owner)
	filter.Risk = strings.TrimSpace(filter.Risk)
	return filter
}

func normalizeCapabilityDecisionRequest(request CapabilityDecisionRequest) CapabilityDecisionRequest {
	request.CapabilityID = strings.TrimSpace(request.CapabilityID)
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.ActorID = strings.TrimSpace(request.ActorID)
	request.SelectionReason = strings.TrimSpace(request.SelectionReason)
	request.ProvenanceRequirement = strings.TrimSpace(request.ProvenanceRequirement)
	request.RequestedScopes = uniqueSortedStrings(request.RequestedScopes)
	if request.ConnectorReadiness == nil {
		request.ConnectorReadiness = map[string]string{}
	}
	if request.EvalStatusOverrides == nil {
		request.EvalStatusOverrides = map[string]string{}
	}
	return request
}

func matchesCapabilityFilter(capability Capability, filter CapabilityRegistryFilter) bool {
	if filter.DomainID != "" && capability.DomainID != filter.DomainID {
		return false
	}
	if filter.Kind != "" && capability.Kind != filter.Kind {
		return false
	}
	if filter.Owner != "" && capability.Owner != filter.Owner {
		return false
	}
	if filter.Risk != "" && capability.Risk != filter.Risk {
		return false
	}
	if filter.DefaultOn != nil && capability.DefaultOn != *filter.DefaultOn {
		return false
	}
	return true
}

func capabilityRegistryTotals(capabilities []Capability) CapabilityRegistryTotals {
	totals := CapabilityRegistryTotals{
		Capabilities: len(capabilities),
		ByDomain:     map[string]int{},
		ByRisk:       map[string]int{},
	}
	for _, capability := range capabilities {
		if capability.DefaultOn {
			totals.DefaultOn++
		} else {
			totals.DefaultOff++
		}
		totals.ByDomain[capability.DomainID]++
		totals.ByRisk[capability.Risk]++
	}
	return totals
}

func connectorRequiredScopes(dependencies []ConnectorDependency) []string {
	scopes := []string{}
	for _, dependency := range dependencies {
		scopes = append(scopes, dependency.RequiredScopes...)
	}
	return scopes
}

func requiredConnectorDependencies(dependencies []ConnectorDependency) []ConnectorDependency {
	required := []ConnectorDependency{}
	for _, dependency := range dependencies {
		if strings.EqualFold(strings.TrimSpace(dependency.Readiness), "required") {
			required = append(required, cloneConnectorDependency(dependency))
		}
	}
	return required
}

func capabilityEvalGate(capability Capability, overrides map[string]string) CapabilityEvalGate {
	status := strings.TrimSpace(overrides[capability.ID])
	if status == "" {
		status = capability.Eval.Status
	}
	status = strings.TrimSpace(status)
	return CapabilityEvalGate{
		Required:     capability.Eval.Required,
		Status:       status,
		Passing:      evalStatusPassing(status),
		ScenarioSets: cloneStrings(capability.Eval.ScenarioSets),
		Rubrics:      cloneStrings(capability.Eval.Rubrics),
	}
}

func evalStatusPassing(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "blocked", "failed", "failing", "missing", "not_run", "unknown":
		return false
	default:
		return true
	}
}

func normalizedReadiness(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func connectorReady(readiness string) bool {
	switch readiness {
	case "ready", "healthy", "available", "connected", "configured":
		return true
	default:
		return false
	}
}

func connectorInfrastructureForDecision(connectors []ConnectorDependency) *ConnectorInfrastructure {
	if len(connectors) == 0 {
		return nil
	}
	infrastructure := cloneConnectorInfrastructure(ConnectorInfrastructureProfile)
	return &infrastructure
}

func cloneCapability(capability Capability) Capability {
	capability.ConsoleSurfaces = cloneStrings(capability.ConsoleSurfaces)
	capability.RequiredScopes = cloneStrings(capability.RequiredScopes)
	capability.ConnectorDependencies = cloneConnectorDependencies(capability.ConnectorDependencies)
	capability.Eval.LocalCommands = cloneStrings(capability.Eval.LocalCommands)
	capability.Eval.ScenarioSets = cloneStrings(capability.Eval.ScenarioSets)
	capability.Eval.Rubrics = cloneStrings(capability.Eval.Rubrics)
	capability.RuntimeEvents = cloneStrings(capability.RuntimeEvents)
	capability.Provenance = cloneStrings(capability.Provenance)
	capability.Review = cloneReviewStatus(capability.Review)
	return capability
}

func cloneConnectorDependency(dependency ConnectorDependency) ConnectorDependency {
	dependency.AuthModels = cloneStrings(dependency.AuthModels)
	dependency.RequiredScopes = cloneStrings(dependency.RequiredScopes)
	return dependency
}

func cloneReviewStatus(review ReviewStatus) ReviewStatus {
	review.RequiredApprovers = cloneStrings(review.RequiredApprovers)
	return review
}

func missingStrings(required []string, available []string) []string {
	availableSet := stringSet(available)
	missing := []string{}
	for _, value := range required {
		if !scopeSetContains(availableSet, value) {
			missing = append(missing, value)
		}
	}
	return missing
}

func scopeSetContains(availableSet map[string]bool, required string) bool {
	for _, candidate := range scopeAliases(required) {
		if availableSet[candidate] {
			return true
		}
	}
	return false
}

func scopeAliases(scope string) []string {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return nil
	}
	aliases := []string{scope}
	if strings.HasPrefix(scope, "cerebro.") {
		aliases = append(aliases, strings.TrimPrefix(scope, "cerebro."))
	} else {
		aliases = append(aliases, "cerebro."+scope)
	}
	return aliases
}

func uniqueSortedStrings(values []string) []string {
	set := stringSet(values)
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func stringSet(values []string) map[string]bool {
	set := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = true
	}
	return set
}

func containsValue(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
