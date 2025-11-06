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
  providerAliases?: Record<string, string[]>;
}

export function buildIntegrationOverview({
  coverage,
  findings,
  organizations,
  providerAliases = {},
}: BuildIntegrationOverviewParams): IntegrationOverview[] {
  const orgIndex = new Map<string, OrganizationSummary>();
  for (const org of organizations) {
    orgIndex.set(org.orgId, org);
  }

  const providerIndex = buildProviderIndex(coverage, providerAliases);

  return coverage.map((record) => {
    const normalizedIntegration = normalize(record.integration);
    const providerKeys = new Set<string>([
      normalizedIntegration,
      ...toArray(record.providers).map(normalize),
      ...(providerAliases[record.integration] ?? []).map(normalize),
    ]);

    const relatedFindings = findings.filter((finding) => {
      const providerKey = normalize(finding.provider);
      return providerKeys.has(providerKey) || providerIndex.get(providerKey) === normalizedIntegration;
    });
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

function buildProviderIndex(
  coverage: IntegrationCoverageRecord[],
  aliases: Record<string, string[]>,
): Map<string, string> {
  const map = new Map<string, string>();
  for (const record of coverage) {
    const integrationKey = normalize(record.integration);
    for (const provider of toArray(record.providers)) {
      map.set(normalize(provider), integrationKey);
    }
    for (const alias of aliases[record.integration] ?? []) {
      map.set(normalize(alias), integrationKey);
    }
  }
  return map;
}

function normalize(value: string | null | undefined): string {
  return (value ?? "").trim().toLowerCase();
}

function toArray<T>(value: T[] | T | null | undefined): T[] {
  if (Array.isArray(value)) return value;
  if (value === null || value === undefined) return [];
  return [value];
}
