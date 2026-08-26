import { describe, expect, it } from "vitest";

import { cacheGRCMetadata, readGRCMetadata, type GRCMetadataScope } from "./grc-metadata-cache";

const scopeA: GRCMetadataScope = {
  actor: "actor-a",
  apiKey: "key-a",
  tenantID: "tenant-a",
  workspaceID: "workspace-a",
};

const dashboardFor = (policyName: string) => ({
  controls: [{ framework_name: "SOC 2", control_id: "CC1" }],
  connectors: [{ runtime_id: "runtime-1", source_id: "github" }],
  findings: [{ rule_id: "rule-1", policy_id: "policy-1", policy_name: policyName }],
});

describe("GRC metadata cache scope", () => {
  it("keeps metadata isolated across actor, API key, tenant, and workspace changes", () => {
    cacheGRCMetadata(dashboardFor("Tenant A policy"), scopeA);

    expect(readGRCMetadata("policy:policy-1", scopeA)).toBe("Tenant A policy");
    for (const changedScope of [
      { ...scopeA, actor: "actor-b" },
      { ...scopeA, apiKey: "key-b" },
      { ...scopeA, tenantID: "tenant-b" },
      { ...scopeA, workspaceID: "workspace-b" },
    ]) {
      expect(readGRCMetadata("policy:policy-1", changedScope)).toBeNull();
    }

    cacheGRCMetadata(dashboardFor("Tenant B policy"), { ...scopeA, tenantID: "tenant-b" });
    expect(readGRCMetadata("policy:policy-1", scopeA)).toBe("Tenant A policy");
    expect(readGRCMetadata("policy:policy-1", { ...scopeA, tenantID: "tenant-b" })).toBe("Tenant B policy");
  });

  it("does not read or write metadata without an authenticated actor", () => {
    const unresolvedScope = { ...scopeA, actor: " " };
    cacheGRCMetadata(dashboardFor("unresolved policy"), unresolvedScope);

    expect(readGRCMetadata("policy:policy-1", unresolvedScope)).toBeNull();
  });
});
