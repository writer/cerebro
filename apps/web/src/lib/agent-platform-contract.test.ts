import { describe, expect, it } from "vitest";

import {
  AGENT_PLATFORM_CONTRACT_VERSION,
  AGENT_PLATFORM_DOMAINS,
  AGENT_PLATFORM_FALLBACK_CONTRACT,
  AGENT_PLATFORM_INVARIANTS,
  agentPlatformCapabilitiesByDomain,
  agentPlatformDomainById,
  normalizeAgentPlatformContract,
} from "./agent-platform-contract";

describe("agent platform contract", () => {
  it("keeps a stable public-safe contract version", () => {
    expect(AGENT_PLATFORM_CONTRACT_VERSION).toBe("2026-06-16.cerebro-agent-platform");
  });

  it("covers the Cerebro agent platform domains", () => {
    expect(AGENT_PLATFORM_DOMAINS.map((domain) => domain.id)).toEqual([
      "runtime",
      "evals",
      "capabilities",
      "execution",
      "streaming-replay",
      "connectors",
      "knowledge",
    ]);

    for (const domain of AGENT_PLATFORM_DOMAINS) {
      expect(domain.name).toBeTruthy();
      expect(domain.principle).toBeTruthy();
      expect(domain.consoleSurface).toBeTruthy();
      expect(domain.owns.length).toBeGreaterThan(0);
      expect(domain.mustExpose.length).toBeGreaterThan(0);
    }
  });

  it("keeps invariants unique and attached to known domains", () => {
    const ids = new Set<string>();

    for (const invariant of AGENT_PLATFORM_INVARIANTS) {
      expect(ids.has(invariant.id)).toBe(false);
      ids.add(invariant.id);
      expect(agentPlatformDomainById(invariant.domainId)).toBeTruthy();
      expect(invariant.statement).toBeTruthy();
    }
  });

  it("groups capabilities by domain and keeps default-on entries evaluable", () => {
    const grouped = agentPlatformCapabilitiesByDomain();

    for (const domain of AGENT_PLATFORM_DOMAINS) {
      expect(grouped.get(domain.id)?.length).toBeGreaterThan(0);
    }

    for (const capability of AGENT_PLATFORM_FALLBACK_CONTRACT.capabilities) {
      expect(agentPlatformDomainById(capability.domainId)).toBeTruthy();
      expect(capability.runtimeEvents.length).toBeGreaterThan(0);
      expect(capability.provenance.length).toBeGreaterThan(0);
      if (capability.defaultOn) {
        expect(capability.eval.required).toBe(true);
        expect(capability.eval.localCommands.length).toBeGreaterThan(0);
      }
    }
  });

  it("keeps connector OAuth and MCP infrastructure explicit", () => {
    const connectorCapability = AGENT_PLATFORM_FALLBACK_CONTRACT.capabilities.find((capability) => capability.id === "connector-oauth-mcp");

    expect(connectorCapability?.connectorDependencies.length).toBeGreaterThan(0);
    expect(AGENT_PLATFORM_FALLBACK_CONTRACT.connectorInfrastructure.authModels).toContain("oauth_authorization_code");
    expect(AGENT_PLATFORM_FALLBACK_CONTRACT.connectorInfrastructure.authModels).toContain("oauth_client_credentials");
    expect(AGENT_PLATFORM_FALLBACK_CONTRACT.connectorInfrastructure.oauthSurfaces).toContain("/oauth/token");
    expect(AGENT_PLATFORM_FALLBACK_CONTRACT.connectorInfrastructure.mcpSurfaces).toContain("/api/v1/mcp");
    expect(AGENT_PLATFORM_FALLBACK_CONTRACT.connectorInfrastructure.tokenBoundaries).toEqual(
      expect.arrayContaining(["principal", "tenant", "scopes", "token owner", "surface"]),
    );
  });

  it("keeps runtime events and provenance requirements internally linked", () => {
    const eventNames = new Set(AGENT_PLATFORM_FALLBACK_CONTRACT.runtimeEvents.map((event) => event.name));
    const provenanceSurfaces = new Set(AGENT_PLATFORM_FALLBACK_CONTRACT.provenanceRequirements.map((requirement) => requirement.surface));

    for (const capability of AGENT_PLATFORM_FALLBACK_CONTRACT.capabilities) {
      for (const eventName of capability.runtimeEvents) {
        expect(eventNames.has(eventName)).toBe(true);
      }
      for (const provenanceSurface of capability.provenance) {
        expect(provenanceSurfaces.has(provenanceSurface)).toBe(true);
      }
    }

    const ask = AGENT_PLATFORM_FALLBACK_CONTRACT.provenanceRequirements.find((requirement) => requirement.surface === "ask-answer");
    expect(ask?.requiredFields).toEqual(expect.arrayContaining(["source_urn", "scope", "citation_status", "fallback_reason"]));
  });

  it("normalizes the backend snake_case payload", () => {
    const contract = normalizeAgentPlatformContract({
      version: AGENT_PLATFORM_CONTRACT_VERSION,
      domains: [
        {
          id: "runtime",
          name: "Runtime",
          principle: "Typed execution",
          console_surface: "Ask",
          owns: ["events"],
          must_expose: ["trace id"],
        },
      ],
      invariants: [{ id: "RUN-01", domain_id: "runtime", statement: "Stable events" }],
      capabilities: [
        {
          id: "test-capability",
          name: "Test capability",
          domain_id: "runtime",
          kind: "test",
          version: "1.0.0",
          owner: "cerebro-platform",
          risk: "low",
          default_on: true,
          summary: "Test",
          console_surfaces: ["Ask"],
          required_scopes: ["cosmo.security.read"],
          eval: {
            required: true,
            status: "required",
            local_commands: ["npm test"],
            scenario_sets: ["golden"],
            rubrics: ["groundedness"],
          },
          runtime_events: ["agent.run.started"],
          provenance: ["ask-answer"],
          review: {
            state: "required",
            cadence: "change",
            required_approvers: ["platform"],
          },
        },
      ],
      runtime_events: [
        {
          name: "agent.run.started",
          domain_id: "runtime",
          stage: "start",
          sequence_required: true,
          terminal: false,
          replayable: true,
          payload_fields: ["trace_id"],
          provenance_fields: ["trace_id"],
        },
      ],
      provenance_requirements: [
        {
          surface: "ask-answer",
          domain_id: "knowledge",
          required_fields: ["source_urn", "scope"],
          citation_required: true,
          budget_required: true,
          fallback_required: true,
        },
      ],
      connector_infrastructure: {
        auth_models: ["oauth_authorization_code"],
        oauth_surfaces: ["/oauth/token"],
        credential_stores: ["tenant-scoped credential broker"],
        token_boundaries: ["tenant"],
        mcp_surfaces: ["/api/v1/mcp"],
        required_controls: ["redaction"],
      },
    });

    expect(contract.domains[0].consoleSurface).toBe("Ask");
    expect(contract.invariants[0].domainId).toBe("runtime");
    expect(contract.capabilities[0].defaultOn).toBe(true);
    expect(contract.capabilities[0].eval.localCommands).toEqual(["npm test"]);
    expect(contract.runtimeEvents[0].sequenceRequired).toBe(true);
    expect(contract.connectorInfrastructure.oauthSurfaces).toEqual(["/oauth/token"]);
  });
});
