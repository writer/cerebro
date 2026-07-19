import { describe, expect, it } from "vitest";

import {
  buildConnectorCards,
  connectorAttentionTotal,
  connectorCapabilities,
  connectorCapabilityLabel,
  connectorPath,
  connectorProjectionTemplate,
  connectorResourceTypes,
  connectorResourceTypeStats,
  connectorResourceFamilyEventKind,
  connectorResourceFamilySchemaRef,
  connectorPrimaryAction,
  filterConnectorCards,
  providerAPIProofMetrics,
  providerAPIProofQueue,
  providerAPIProofState,
} from "./connector-view";
import { connectorDisplayName } from "./connectors";

describe("connector view model", () => {
  it("merges catalog entries with source health and prioritizes unhealthy connectors", () => {
    const cards = buildConnectorCards(
      [
        { source_id: "github", name: "GitHub", status: "connected", configured_runtimes: 1, healthy_runtimes: 1 },
        { source_id: "aws", name: "AWS", display_name: "Amazon Web Services", status: "available" },
      ],
      [
        {
          source_id: "aws",
          performance: "bad",
          next_action: "Investigate failed sync",
          total: 2,
          healthy: 0,
          stale: 0,
          degraded: 2,
          unknown: 0,
          cursor_pending: 0,
          cursor_unknown: 0,
          graph_current: 0,
          graph_behind: 0,
          graph_running: 0,
          graph_failed: 1,
          graph_not_observed: 0,
          graph_unknown: 0,
          backfills: 0,
          schedule_context_missing: 0,
        },
      ],
    );

    expect(cards[0]).toMatchObject({ source_id: "aws", readiness: "bad", nextAction: "Investigate failed sync" });
    expect(connectorDisplayName(cards[0])).toBe("Amazon Web Services");
    expect(connectorAttentionTotal(cards[0])).toBe(3);
    expect(cards[1]).toMatchObject({ source_id: "github", readiness: "healthy" });
  });

  it("filters by readiness and search text", () => {
    const cards = buildConnectorCards(
      [
        { source_id: "github", name: "GitHub", description: "Repository events", status: "connected", configured_runtimes: 1, healthy_runtimes: 1 },
        { source_id: "okta", name: "Okta", description: "Identity events", status: "available" },
      ],
      [],
    );

    expect(filterConnectorCards(cards, "identity", "all").map((card) => card.source_id)).toEqual(["okta"]);
    expect(filterConnectorCards(cards, "", "healthy").map((card) => card.source_id)).toEqual(["github"]);
  });

  it("builds shareable connector routes without leaking extra state", () => {
    expect(connectorPath("github", { runtime_id: "example-runtime", tenant_id: "" })).toBe("/connectors/github?runtime_id=example-runtime");
  });

  it("keeps catalog-only executable definitions in inspection mode", () => {
    const cards = buildConnectorCards(
      [
        {
          source_id: "auth0",
          name: "Auth0",
          status: "generateable",
          catalog_status: "generateable",
          runtime_executable: true,
        },
      ],
      [],
    );

    expect(cards[0]).toMatchObject({ source_id: "auth0", readiness: "not_configured" });
    expect(connectorPrimaryAction(cards[0])).toBe("Inspect");
    expect(filterConnectorCards(cards, "runtime ready", "all")).toHaveLength(1);
  });

  it("keeps restricted API-owned connectors visible without setup actions", () => {
    const cards = buildConnectorCards(
      [
        {
          source_id: "aws",
          name: "AWS",
          access_status: "restricted",
          access_reason: "limited preview",
          setup_allowed: false,
          requestable: true,
          requestable_reason: "limited preview",
          request_access_action: "Request in Access Hub",
          request_access_url: "https://access.example.com/request?source=aws",
          connection_methods: [{ id: "encrypted_submission" }],
        },
      ],
      [],
    );

    expect(cards[0]).toMatchObject({ source_id: "aws", nextAction: "limited preview" });
    expect(connectorPrimaryAction(cards[0])).toBe("Request in Access Hub");
    expect(filterConnectorCards(cards, "limited preview", "all")).toHaveLength(1);
  });

  it("renders provider capability labels with full public names", () => {
    expect(connectorCapabilityLabel("aws")).toBe("Amazon Web Services");
    expect(connectorCapabilityLabel("gcp")).toBe("Google Cloud Platform");
    expect(connectorCapabilityLabel("grc")).toBe("GRC");
  });

  it("prefers catalog resource families as capability chips for runtime-ready entries", () => {
    expect(connectorCapabilities({
      emitted_kinds: ["crowdstrike_falcon.findings"],
      catalog_categories: ["security", "endpoint"],
      resource_families: [
        { id: "endpoint_devices", label: "Endpoint devices" },
        { id: "findings", label: "Findings" },
        { id: "vulnerabilities", label: "Vulnerabilities" },
      ],
    }, 2)).toEqual(["Endpoint devices", "Findings"]);
  });

  it("normalizes resource type metadata from generated catalog definitions", () => {
    const family = {
      id: "users",
      label: "Users",
      path: "/api/v1/users",
      event: { kind: "okta.users", schema_ref: "okta/users/v1" },
      projection: { template: "identity_user" },
    };

    expect(connectorProjectionTemplate(family)).toBe("identity_user");
    expect(connectorResourceFamilyEventKind(family)).toBe("okta.users");
    expect(connectorResourceFamilySchemaRef(family)).toBe("okta/users/v1");
  });

  it("summarizes resource types without duplicate labels", () => {
    const card = {
      source_id: "okta",
      name: "Okta",
      integration_depth: { resource_families: 4, projection_templates: 3, high_value_families: 2, coverage_dimensions: 3 },
      resource_families: [
        { id: "users", label: "Users", projection_template: "identity_user", coverage: ["identity_configuration"], high_value: true },
        { id: "admins", label: "Admins", projection: { template: "identity_user" }, coverage: ["access_review"] },
        { id: "groups", label: "Groups", projection: { template: "identity_group" }, high_value: true },
      ],
    };

    expect(connectorResourceTypes(card)).toEqual([
      { template: "identity_user", label: "Users", resourceFamilies: 2 },
      { template: "identity_group", label: "Groups", resourceFamilies: 1 },
    ]);
    expect(connectorResourceTypeStats(card)).toEqual({
      catalogResourceTypes: 4,
      resourceTypes: 3,
      distinctResourceTypes: 3,
      highValueResourceTypes: 2,
      coverageItems: 3,
    });
  });

  it("uses compact connector counts when expanded resource families are omitted", () => {
    expect(connectorResourceTypeStats({ resource_family_count: 14, emitted_kind_count: 9 })).toEqual({
      catalogResourceTypes: 14,
      resourceTypes: 9,
      distinctResourceTypes: 0,
      highValueResourceTypes: 0,
      coverageItems: 0,
    });
  });

  it("classifies provider API proof work without treating docs as supported proof", () => {
    expect(providerAPIProofState({
      source_id: "docs-needed",
      name: "Docs needed",
      priority: 92,
      priority_tier: "urgent",
      missing_families: ["users"],
    })).toBe("needs_discovery");
    expect(providerAPIProofState({
      source_id: "mapping-needed",
      name: "Mapping needed",
      has_provider_api_contract: true,
      provider_api_references: ["provider-api-reference"],
      provider_api_missing_families: ["groups"],
    })).toBe("needs_mapping");
    expect(providerAPIProofState({
      source_id: "proof-needed",
      name: "Proof needed",
      has_provider_api_contract: true,
      has_provider_api_mapping: true,
      provider_api_references: ["provider-api-reference"],
      provider_api_auth_evidence: ["oauth_scopes"],
      provider_api_proof_score: 80,
      provider_api_proof_gaps: ["runtime_fixture_missing"],
    })).toBe("needs_proof");
    expect(providerAPIProofState({
      source_id: "verified",
      name: "Verified",
      has_provider_api_contract: true,
      has_provider_api_mapping: true,
      has_provider_api_proof: true,
      provider_api_references: ["provider-api-reference"],
      provider_api_auth_evidence: ["oauth_scopes"],
      provider_api_scope_evidence: ["read:users"],
      provider_api_proof_score: 100,
    })).toBe("verified");
  });

  it("prioritizes provider API proof queue by actionable state and evidence risk", () => {
    const cards = buildConnectorCards(
      [
        {
          source_id: "unscoped",
          name: "Unscoped source",
        },
        {
          source_id: "verified",
          name: "Verified source",
          has_provider_api_contract: true,
          has_provider_api_mapping: true,
          has_provider_api_proof: true,
          provider_api_references: ["provider-api-reference"],
          provider_api_auth_evidence: ["api_key"],
          provider_api_scope_evidence: ["read"],
          provider_api_proof_score: 100,
        },
        {
          source_id: "github",
          name: "GitHub",
          has_provider_api_contract: true,
          has_provider_api_mapping: true,
          provider_api_proof_score: 74,
          provider_api_proof_gaps: ["scope_evidence_missing"],
        },
        {
          source_id: "openai",
          name: "OpenAI",
          priority: 99,
          priority_tier: "urgent",
          priority_reasons: ["identity_family"],
          missing_families: ["users", "groups", "service_accounts"],
          next_action: "Find API reference.",
        },
        {
          source_id: "jira",
          name: "Jira",
          has_provider_api_contract: true,
          provider_api_references: ["jira-provider-api-reference"],
          provider_api_missing_families: ["audit_events", "groups"],
        },
      ],
      [],
    );

    const queue = providerAPIProofQueue(cards, { tenantID: "tenant-a" });

    expect(queue.map((item) => item.sourceID)).toEqual(["openai", "jira", "github"]);
    expect(queue[0]).toMatchObject({ label: "Find API source", tier: "urgent", priority: 111 });
    expect(queue[0].href).toBe("/connectors/openai?tenant_id=tenant-a");
    expect(providerAPIProofMetrics(cards)).toMatchObject({
      total: 4,
      needsAction: 3,
      needsDiscovery: 1,
      needsMapping: 1,
      needsProof: 1,
      verified: 1,
      averageScore: 87,
    });
  });
});
