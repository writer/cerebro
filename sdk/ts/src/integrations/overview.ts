import {
  FindingRecord,
  IntegrationCoverageHealth,
  IntegrationCoverageRecord,
  OrganizationSummary,
} from "../types.js";
import { computeCoverageHealth } from "./metrics.js";

export interface IntegrationOverview {
  integration: string;
  coverage: IntegrationCoverageHealth;
  findings: FindingRecord[];
  findingsBySeverity: Record<string, number>;
  openFindings: number;
  organizations: OrganizationSummary[];
}

export interface BuildIntegrationOverviewParams {
  coverage: IntegrationCoverageRecord[];
  findings: FindingRecord[];
  organizations: OrganizationSummary[];
}

export function buildIntegrationOverview({
  coverage,
  findings,
  organizations,
}: BuildIntegrationOverviewParams): IntegrationOverview[] {
  const orgIndex = new Map<string, OrganizationSummary>();
  for (const org of organizations) {
    orgIndex.set(org.orgId, org);
  }

  return coverage.map((record) => {
    const providers = new Set(record.providers ?? []);
    const relatedFindings = findings.filter((finding) => providers.has(finding.provider));
    const findingsBySeverity = relatedFindings.reduce<Record<string, number>>((acc, finding) => {
      const severity = finding.severity.toLowerCase();
      acc[severity] = (acc[severity] ?? 0) + 1;
      return acc;
    }, {});

    const relatedOrganizations = Array.from(
      new Set(relatedFindings.map((finding) => finding.orgId)),
    )
      .map((orgId) => orgIndex.get(orgId))
      .filter((org): org is OrganizationSummary => Boolean(org));

    const openFindings = relatedFindings.reduce((total, finding) => {
      return total + (finding.status.toLowerCase() === "open" ? 1 : 0);
    }, 0);

    return {
      integration: record.integration,
      coverage: computeCoverageHealth(record),
      findings: relatedFindings,
      findingsBySeverity,
      openFindings,
      organizations: relatedOrganizations,
    } satisfies IntegrationOverview;
  });
}

export function buildIntegrationOverviewMap(params: BuildIntegrationOverviewParams): Record<string, IntegrationOverview> {
  return buildIntegrationOverview(params).reduce<Record<string, IntegrationOverview>>((acc, overview) => {
    acc[overview.integration] = overview;
    return acc;
  }, {});
}
