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
