import HttpClient, { RequestOptions } from "../httpClient.js";
import type { components } from "../generated/openapi.js";
import { createSchemaAdapter } from "../generated/adapters/schemaAdapters.js";
import {
  IntegrationAccountSummary,
  IntegrationCoverageRecord,
  IntegrationCoverageHealth,
  IntegrationScopeBreakdown,
} from "../types.js";
import { parseDate } from "../serialization.js";
import { computeCoverageHealth } from "../integrations/metrics.js";

type IntegrationCoveragePayload = components["schemas"]["IntegrationCoverageSummary"];
type IntegrationCoverageScopesPayload = components["schemas"]["IntegrationCoverageScopes"];
type IntegrationCoverageAccountsPayload = components["schemas"]["IntegrationCoverageAccounts"];

const adaptIntegrationCoverage = createSchemaAdapter("IntegrationCoverageSummary");

export interface IntegrationCoverageOptions {
  staleSeconds?: number;
}

export class IntegrationsClient {
  constructor(private readonly http: HttpClient) {}

  async getCoverage(options?: IntegrationCoverageOptions): Promise<IntegrationCoverageRecord[]> {
    const requestOpts: RequestOptions = {};
    if (options?.staleSeconds !== undefined) {
      requestOpts.searchParams = { stale_seconds: options.staleSeconds };
    }
    const payload = await this.http.get<IntegrationCoveragePayload[]>(
      "/api/v1/integrations/coverage",
      requestOpts,
    );
    return payload.map(mapCoverageRecord);
  }

  async getCoverageHealth(options?: IntegrationCoverageOptions): Promise<IntegrationCoverageHealth[]> {
    const coverage = await this.getCoverage(options);
    return coverage.map(computeCoverageHealth);
  }
}

function mapCoverageRecord(entry: IntegrationCoveragePayload): IntegrationCoverageRecord {
  return adaptIntegrationCoverage(entry, (data) => ({
    integration: data.integration,
    providers: Array.isArray(data.providers) ? [...data.providers] : [],
    status: data.status,
    scopes: mapScopes(data.scopes),
    accounts: mapAccounts(data.accounts),
    coverageRatio: data.coverageRatio,
    lastSuccess: coerceDate(data.lastSuccess, entry.last_success),
    evaluatedAt: coerceDate(data.evaluatedAt, entry.evaluated_at) ?? new Date(entry.evaluated_at),
  }));
}

function mapScopes(source: IntegrationCoverageScopesPayload): IntegrationScopeBreakdown {
  return {
    total: source.total,
    healthy: source.healthy,
    warning: source.warning,
    critical: source.critical,
  };
}

function mapAccounts(source: IntegrationCoverageAccountsPayload): IntegrationAccountSummary {
  return {
    total: source.total,
  };
}

function coerceDate(value: unknown, fallback?: string | null): Date | null {
  const parsed = parseDate(value as string | Date | null);
  if (parsed) return parsed;
  if (!fallback) return null;
  return parseDate(fallback) ?? new Date(fallback);
}

export default IntegrationsClient;
