import { describe, expect, it } from "vitest";

import { buildIntegrationOverview, buildIntegrationOverviewMap } from "../src/integrations/overview";
import { IntegrationCoverageRecord, FindingRecord, OrganizationSummary } from "../src/types";

describe("integration overview helpers", () => {
  const coverage: IntegrationCoverageRecord[] = [
    {
      integration: "github",
      providers: ["github", "gitlab"],
      status: "ok",
      scopes: {
        total: 10,
        healthy: 7,
        warning: 2,
        critical: 1,
      },
      accounts: { total: 3 },
      coverageRatio: 0.7,
      lastSuccess: new Date("2024-10-01T00:00:00Z"),
      evaluatedAt: new Date("2024-10-02T00:00:00Z"),
    },
  ];

  const findings: FindingRecord[] = [
    {
      findingId: "finding-1",
      orgId: "org-1",
      accountId: "acct-1",
      provider: "github",
      ruleId: "RULE-1",
      ruleVersion: 1,
      resourceId: "repo-1",
      principalId: null,
      firstSeen: new Date("2024-09-01T00:00:00Z"),
      lastSeen: new Date("2024-10-02T00:00:00Z"),
      status: "open",
      severity: "high",
      fingerprint: "fp-1",
      title: "Repo misconfiguration",
      summary: null,
      evidence: null,
    },
    {
      findingId: "finding-2",
      orgId: "org-1",
      accountId: "acct-2",
      provider: "github",
      ruleId: "RULE-2",
      ruleVersion: 1,
      resourceId: "repo-2",
      principalId: null,
      firstSeen: new Date("2024-09-15T00:00:00Z"),
      lastSeen: new Date("2024-10-02T00:00:00Z"),
      status: "closed",
      severity: "medium",
      fingerprint: "fp-2",
      title: "Outdated branch protection",
      summary: null,
      evidence: null,
    },
    {
      findingId: "finding-3",
      orgId: "org-2",
      accountId: "acct-3",
      provider: "GitLab",
      ruleId: "RULE-3",
      ruleVersion: 1,
      resourceId: "repo-3",
      principalId: null,
      firstSeen: new Date("2024-09-20T00:00:00Z"),
      lastSeen: new Date("2024-10-02T00:00:00Z"),
      status: "open",
      severity: "low",
      fingerprint: "fp-3",
      title: "Outdated dependency",
      summary: null,
      evidence: null,
    },
    {
      findingId: "finding-4",
      orgId: "org-2",
      accountId: "acct-4",
      provider: "GH",
      ruleId: "RULE-4",
      ruleVersion: 1,
      resourceId: "repo-4",
      principalId: null,
      firstSeen: new Date("2024-09-22T00:00:00Z"),
      lastSeen: new Date("2024-10-02T00:00:00Z"),
      status: "open",
      severity: "medium",
      fingerprint: "fp-4",
      title: "Missing codeowners",
      summary: null,
      evidence: null,
    },
  ];

  const organizations: OrganizationSummary[] = [
    {
      orgId: "org-1",
      name: "Acme Corp",
      createdAt: new Date("2023-07-01T00:00:00Z"),
    },
    {
      orgId: "org-2",
      name: "Globex",
      createdAt: new Date("2023-01-01T00:00:00Z"),
    },
  ];

  it("builds integration overviews with derived severity stats", () => {
    const [overview] = buildIntegrationOverview({ coverage, findings, organizations });

    expect(overview.integration).toBe("github");
    expect(overview.coverage.healthyPercentage).toBeCloseTo(0.7);
    expect(overview.findings).toHaveLength(3);
    expect(overview.openFindings).toBe(2);
    expect(overview.findingsBySeverity.high).toBe(1);
    expect(overview.organizations).toHaveLength(2);
    expect(overview.organizations.map((org) => org?.name)).toContain("Acme Corp");
    expect(overview.organizations.map((org) => org?.name)).toContain("Globex");
  });

  it("builds integration overview map keyed by integration", () => {
    const map = buildIntegrationOverviewMap({ coverage, findings, organizations });
    const github = map.github;
    expect(github).toBeDefined();
    expect(github?.coverage.overallScore).toBeLessThan(1);
  });

  it("allows custom provider aliases", () => {
    const map = buildIntegrationOverviewMap({
      coverage,
      findings,
      organizations,
      providerAliases: {
        github: ["gh"],
      },
    });

    const overview = map.github;
    expect(overview).toBeDefined();
    expect(overview?.findings.length).toBe(4);
  });
});
