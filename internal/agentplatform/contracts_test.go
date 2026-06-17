package agentplatform

import "testing"

func TestContractDomainsHaveRequiredFields(t *testing.T) {
	if ContractVersion == "" {
		t.Fatal("contract version must be set")
	}
	snapshot := Snapshot()
	if snapshot.Version != ContractVersion {
		t.Fatalf("snapshot version = %q, want %q", snapshot.Version, ContractVersion)
	}
	for _, domain := range Domains {
		if domain.ID == "" || domain.Name == "" || domain.Principle == "" {
			t.Fatalf("domain has empty required field: %+v", domain)
		}
		if domain.ConsoleSurface == "" {
			t.Fatalf("domain %q must name a console surface", domain.ID)
		}
		if len(domain.Owns) == 0 {
			t.Fatalf("domain %q must name owned surfaces", domain.ID)
		}
		if len(domain.MustExpose) == 0 {
			t.Fatalf("domain %q must name exposed diagnostics", domain.ID)
		}
	}
}

func TestCapabilitiesHaveGovernanceAndEvals(t *testing.T) {
	if len(Capabilities) < len(Domains) {
		t.Fatalf("capability registry has %d entries, want at least one per domain", len(Capabilities))
	}
	ids := map[string]bool{}
	coveredDomains := map[string]bool{}
	runtimeEvents := runtimeEventNames()
	provenanceSurfaces := provenanceRequirementSurfaces()

	for _, capability := range Capabilities {
		if capability.ID == "" || capability.Name == "" || capability.Version == "" || capability.Owner == "" || capability.Kind == "" {
			t.Fatalf("capability has empty required field: %+v", capability)
		}
		if ids[capability.ID] {
			t.Fatalf("duplicate capability id %q", capability.ID)
		}
		ids[capability.ID] = true
		if _, ok := DomainByID(capability.DomainID); !ok {
			t.Fatalf("capability %q references unknown domain %q", capability.ID, capability.DomainID)
		}
		coveredDomains[capability.DomainID] = true
		if capability.DefaultOn {
			if !capability.Eval.Required || len(capability.Eval.LocalCommands) == 0 {
				t.Fatalf("default-on capability %q must have required local eval commands", capability.ID)
			}
		}
		if len(capability.ConsoleSurfaces) == 0 {
			t.Fatalf("capability %q must name console surfaces", capability.ID)
		}
		if capability.Review.State == "" || capability.Review.Cadence == "" {
			t.Fatalf("capability %q must define review state and cadence", capability.ID)
		}
		for _, event := range capability.RuntimeEvents {
			if !runtimeEvents[event] {
				t.Fatalf("capability %q references unknown runtime event %q", capability.ID, event)
			}
		}
		for _, surface := range capability.Provenance {
			if !provenanceSurfaces[surface] {
				t.Fatalf("capability %q references unknown provenance surface %q", capability.ID, surface)
			}
		}
	}
	for _, domain := range Domains {
		if !coveredDomains[domain.ID] {
			t.Fatalf("domain %q has no registered capability", domain.ID)
		}
	}
}

func TestConnectorInfrastructureIsFirstClass(t *testing.T) {
	infrastructure := ConnectorInfrastructureProfile
	for _, required := range []string{"oauth_authorization_code", "oauth_client_credentials"} {
		if !containsString(infrastructure.AuthModels, required) {
			t.Fatalf("connector infrastructure missing auth model %q", required)
		}
	}
	for _, required := range []string{"/oauth/token", "/oauth/revoke", "/api/v1/mcp"} {
		if !containsString(infrastructure.OAuthSurfaces, required) && !containsString(infrastructure.MCPSurfaces, required) {
			t.Fatalf("connector infrastructure missing surface %q", required)
		}
	}
	for _, required := range []string{"principal", "tenant", "scopes", "token owner", "surface"} {
		if !containsString(infrastructure.TokenBoundaries, required) {
			t.Fatalf("connector infrastructure missing token boundary %q", required)
		}
	}
	capability, ok := capabilityByID("connector-oauth-mcp")
	if !ok {
		t.Fatal("connector-oauth-mcp capability missing")
	}
	if len(capability.ConnectorDependencies) == 0 {
		t.Fatal("connector-oauth-mcp must declare connector dependencies")
	}
	for _, dependency := range capability.ConnectorDependencies {
		if dependency.TokenOwner == "" || dependency.CredentialStore == "" || dependency.OAuthSurface == "" || dependency.MCPSurface == "" {
			t.Fatalf("connector dependency must expose token owner, credential store, OAuth, and MCP surfaces: %+v", dependency)
		}
		if !dependency.TenantScoped {
			t.Fatalf("connector dependency %q must be tenant scoped", dependency.SourceID)
		}
	}
}

func TestSnapshotIncludesSecurityControlPlane(t *testing.T) {
	snapshot := Snapshot()
	if snapshot.SecurityControlPlane.Version != ContractVersion {
		t.Fatalf("security control plane version = %q, want %q", snapshot.SecurityControlPlane.Version, ContractVersion)
	}
	if len(snapshot.SecurityControlPlane.AgentProfiles) == 0 {
		t.Fatal("snapshot missing security agent profiles")
	}
	if len(snapshot.SecurityControlPlane.VerifierLayer) == 0 {
		t.Fatal("snapshot missing security verifier layer")
	}
	if len(snapshot.SecurityControlPlane.IntegrationStrategies) != 8 {
		t.Fatalf("integration strategies = %d, want 8", len(snapshot.SecurityControlPlane.IntegrationStrategies))
	}
}

func TestListCapabilitiesFiltersAndTotals(t *testing.T) {
	defaultOn := true
	registry := ListCapabilities(CapabilityRegistryFilter{
		DomainID:  "connectors",
		DefaultOn: &defaultOn,
	})

	if registry.Version != ContractVersion {
		t.Fatalf("version = %q, want %q", registry.Version, ContractVersion)
	}
	if registry.Totals.Capabilities == 0 {
		t.Fatal("filtered registry must include connector capabilities")
	}
	if registry.Totals.DefaultOff != 0 {
		t.Fatalf("default_off = %d, want 0", registry.Totals.DefaultOff)
	}
	if registry.Totals.ByDomain["connectors"] != registry.Totals.Capabilities {
		t.Fatalf("connector total = %d, want %d", registry.Totals.ByDomain["connectors"], registry.Totals.Capabilities)
	}
	for _, capability := range registry.Capabilities {
		if capability.DomainID != "connectors" || !capability.DefaultOn {
			t.Fatalf("capability does not match filter: %+v", capability)
		}
	}
}

func TestDecideCapabilityAllowsDefaultOnCapability(t *testing.T) {
	decision, ok := DecideCapability(CapabilityDecisionRequest{
		CapabilityID:    "grc-ask",
		TenantID:        "tenant-1",
		ActorID:         "actor-1",
		RequestedScopes: []string{"cosmo.security.read"},
	})
	if !ok {
		t.Fatal("grc-ask capability missing")
	}
	if !decision.Enabled {
		t.Fatalf("decision enabled = false, blockers = %+v", decision.Blockers)
	}
	if decision.Reason != "default_enabled" {
		t.Fatalf("reason = %q, want default_enabled", decision.Reason)
	}
	if decision.TenantID != "tenant-1" || decision.ActorID != "actor-1" {
		t.Fatalf("decision lost caller context: %+v", decision)
	}
	if len(decision.RuntimeEvents) == 0 || len(decision.Provenance) == 0 {
		t.Fatalf("decision must carry runtime events and provenance: %+v", decision)
	}
}

func TestDecideCapabilityReportsControlPlaneBlockers(t *testing.T) {
	decision, ok := DecideCapability(CapabilityDecisionRequest{
		CapabilityID:        "connector-oauth-mcp",
		RequestedScopes:     []string{"cosmo.security.read"},
		EvalStatusOverrides: map[string]string{"connector-oauth-mcp": "failed"},
	})
	if !ok {
		t.Fatal("connector-oauth-mcp capability missing")
	}
	if decision.Enabled {
		t.Fatal("decision enabled = true, want blocked")
	}
	for _, want := range []string{"missing_scope", "connector_readiness_unknown", "eval_not_passing"} {
		if !decisionHasBlocker(decision, want) {
			t.Fatalf("decision missing blocker %q: %+v", want, decision.Blockers)
		}
	}
	if len(decision.RequiredConnectors) == 0 {
		t.Fatal("decision must carry required connector dependencies")
	}
	if decision.ConnectorInfrastructure == nil || len(decision.ConnectorInfrastructure.AuthModels) == 0 {
		t.Fatal("connector decision must include connector infrastructure")
	}
}

func TestDecideCapabilityAllowsScopeUnrestrictedPrincipal(t *testing.T) {
	decision, ok := DecideCapability(CapabilityDecisionRequest{
		CapabilityID:      "graph-reasoning",
		TenantID:          "tenant-1",
		ScopeUnrestricted: true,
	})
	if !ok {
		t.Fatal("graph-reasoning capability missing")
	}
	if !decision.Enabled {
		t.Fatalf("decision enabled = false, blockers = %+v", decision.Blockers)
	}
	if len(decision.MissingScopes) != 0 {
		t.Fatalf("missing scopes = %+v, want none for unrestricted principal", decision.MissingScopes)
	}
}

func TestPreflightAgentRunBuildsGraphPlanningContext(t *testing.T) {
	preflight := PreflightAgentRun(AgentRunPreflightRequest{
		TenantID:        "tenant-1",
		ActorID:         "actor-1",
		CapabilityIDs:   []string{"graph-reasoning"},
		RequestedScopes: []string{"cosmo.security.read"},
		Question:        "What should I inspect?",
		ScopeURN:        "urn:cerebro:tenant-1:asset:app",
	})

	if !preflight.Enabled {
		t.Fatalf("preflight enabled = false, blockers = %+v", preflight.Blockers)
	}
	if preflight.Reason != "preflight_passed" {
		t.Fatalf("reason = %q, want preflight_passed", preflight.Reason)
	}
	if preflight.GraphContext.TenantID != "tenant-1" || preflight.GraphContext.ScopeTenantID != "tenant-1" {
		t.Fatalf("graph context = %+v", preflight.GraphContext)
	}
	if !preflight.GraphContext.ReadOnly || !preflight.GraphContext.CitationRequired || !preflight.GraphContext.ProvenanceRequired {
		t.Fatalf("graph context must be read-only, cited, and provenance-required: %+v", preflight.GraphContext)
	}
	if !containsString(preflight.RuntimeEvents, "agent.preflight.completed") || !containsString(preflight.Provenance, "agent-run-preflight") {
		t.Fatalf("preflight missing runtime/provenance contract: events=%v provenance=%v", preflight.RuntimeEvents, preflight.Provenance)
	}
	if !preflight.WriteBack.Required || !preflight.WriteBack.TraceIDRequired {
		t.Fatalf("write-back contract = %+v, want required trace-linked write-back", preflight.WriteBack)
	}
	if len(preflight.SecurityControlPlane.ActionLadder) == 0 || len(preflight.SecurityControlPlane.IntegrationStrategies) != 8 {
		t.Fatalf("preflight missing security control plane: %+v", preflight.SecurityControlPlane)
	}
}

func TestPreflightAgentRunBlocksScopeTenantMismatch(t *testing.T) {
	preflight := PreflightAgentRun(AgentRunPreflightRequest{
		TenantID:        "tenant-1",
		CapabilityIDs:   []string{"graph-reasoning"},
		RequestedScopes: []string{"cosmo.security.read"},
		ScopeURN:        "urn:cerebro:other:asset:app",
	})

	if preflight.Enabled {
		t.Fatalf("preflight enabled = true, want blocked")
	}
	if !decisionHasBlockerFromList(preflight.Blockers, "scope_tenant") {
		t.Fatalf("preflight blockers = %+v, want scope_tenant", preflight.Blockers)
	}
}

func TestPreflightAgentRunIncludesConnectorOAuthNodes(t *testing.T) {
	preflight := PreflightAgentRun(AgentRunPreflightRequest{
		TenantID:           "tenant-1",
		CapabilityIDs:      []string{"connector-oauth-mcp"},
		ScopeUnrestricted:  true,
		ConnectorReadiness: map[string]string{"catalog-managed": "connected"},
	})

	if !preflight.Enabled {
		t.Fatalf("preflight enabled = false, blockers = %+v", preflight.Blockers)
	}
	if len(preflight.ConnectorContext) != 1 {
		t.Fatalf("connector context = %+v, want one connector node", preflight.ConnectorContext)
	}
	connector := preflight.ConnectorContext[0]
	if connector.NodeURN != "urn:cerebro:tenant-1:connector:catalog-managed" || connector.OAuthNodeURN == "" {
		t.Fatalf("connector graph node = %+v", connector)
	}
	if !connector.Required || !connector.Satisfied || connector.TokenOwner == "" || connector.CredentialBoundary == "" {
		t.Fatalf("connector gate = %+v, want satisfied required OAuth/credential boundary", connector)
	}
}

func TestDecideCapabilityPreviewGate(t *testing.T) {
	blocked, ok := DecideCapability(CapabilityDecisionRequest{
		CapabilityID:    "runtime-response-actions",
		RequestedScopes: []string{"runtime.response.write"},
	})
	if !ok {
		t.Fatal("runtime-response-actions capability missing")
	}
	if blocked.Enabled || !decisionHasBlocker(blocked, "preview_required") {
		t.Fatalf("default-off capability must require preview: %+v", blocked)
	}

	allowed, ok := DecideCapability(CapabilityDecisionRequest{
		CapabilityID:    "runtime-response-actions",
		RequestedScopes: []string{"runtime.response.write"},
		AllowPreview:    true,
	})
	if !ok {
		t.Fatal("runtime-response-actions capability missing")
	}
	if !allowed.Enabled || allowed.Reason != "preview_allowed" {
		t.Fatalf("preview decision = %+v, want enabled preview_allowed", allowed)
	}
}

func TestRuntimeEventsAreUniqueAndReplayable(t *testing.T) {
	ids := map[string]bool{}
	terminalCount := 0
	for _, event := range RuntimeEvents {
		if event.Name == "" || event.DomainID == "" || event.Stage == "" {
			t.Fatalf("runtime event has empty required field: %+v", event)
		}
		if ids[event.Name] {
			t.Fatalf("duplicate runtime event name %q", event.Name)
		}
		ids[event.Name] = true
		if _, ok := DomainByID(event.DomainID); !ok {
			t.Fatalf("runtime event %q references unknown domain %q", event.Name, event.DomainID)
		}
		if !event.SequenceRequired || !event.Replayable {
			t.Fatalf("runtime event %q must require sequencing and replay", event.Name)
		}
		if event.Terminal {
			terminalCount++
		}
		if len(event.PayloadFields) == 0 {
			t.Fatalf("runtime event %q must define payload fields", event.Name)
		}
	}
	if terminalCount == 0 {
		t.Fatal("runtime event vocabulary must include terminal events")
	}
}

func TestProvenanceRequirementsCoverKnowledgeAndConnectors(t *testing.T) {
	requiredFields := []string{"source_urn", "scope", "citation_status", "fallback_reason"}
	ask, ok := provenanceRequirementBySurface("ask-answer")
	if !ok {
		t.Fatal("ask-answer provenance requirement missing")
	}
	for _, field := range requiredFields {
		if !containsString(ask.RequiredFields, field) {
			t.Fatalf("ask-answer provenance missing field %q", field)
		}
	}
	if !ask.CitationRequired || !ask.BudgetRequired || !ask.FallbackRequired {
		t.Fatalf("ask-answer provenance must require citations, budgets, and fallback: %+v", ask)
	}

	connector, ok := provenanceRequirementBySurface("connector-call")
	if !ok {
		t.Fatal("connector-call provenance requirement missing")
	}
	for _, field := range []string{"principal", "tenant", "scopes", "token_owner", "surface"} {
		if !containsString(connector.RequiredFields, field) {
			t.Fatalf("connector-call provenance missing field %q", field)
		}
	}
}

func runtimeEventNames() map[string]bool {
	events := map[string]bool{}
	for _, event := range RuntimeEvents {
		events[event.Name] = true
	}
	return events
}

func provenanceRequirementSurfaces() map[string]bool {
	surfaces := map[string]bool{}
	for _, requirement := range ProvenanceRequirements {
		surfaces[requirement.Surface] = true
	}
	return surfaces
}

func capabilityByID(id string) (Capability, bool) {
	for _, capability := range Capabilities {
		if capability.ID == id {
			return capability, true
		}
	}
	return Capability{}, false
}

func provenanceRequirementBySurface(surface string) (ProvenanceRequirement, bool) {
	for _, requirement := range ProvenanceRequirements {
		if requirement.Surface == surface {
			return requirement, true
		}
	}
	return ProvenanceRequirement{}, false
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func decisionHasBlocker(decision CapabilityDecision, code string) bool {
	return decisionHasBlockerFromList(decision.Blockers, code)
}

func decisionHasBlockerFromList(blockers []CapabilityDecisionBlocker, code string) bool {
	for _, blocker := range blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}

func TestInvariantsReferenceKnownDomains(t *testing.T) {
	ids := map[string]bool{}
	for _, invariant := range Invariants {
		if invariant.ID == "" || invariant.Statement == "" {
			t.Fatalf("invariant has empty required field: %+v", invariant)
		}
		if ids[invariant.ID] {
			t.Fatalf("duplicate invariant id %q", invariant.ID)
		}
		ids[invariant.ID] = true
		if _, ok := DomainByID(invariant.DomainID); !ok {
			t.Fatalf("invariant %q references unknown domain %q", invariant.ID, invariant.DomainID)
		}
	}
}
