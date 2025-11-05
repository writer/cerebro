import HttpClient, { RequestOptions } from "../httpClient.js";
import type { components } from "../generated/openapi.js";
import {
  IntegrationAccountSummary,
  IntegrationCoverageRecord,
  IntegrationScopeBreakdown,
} from "../types.js";
import { transformOpenApi } from "../serialization.js";

type IntegrationCoveragePayload = components["schemas"]["IntegrationCoverageSummary"];
type IntegrationCoverageScopesPayload = components["schemas"]["IntegrationCoverageScopes"];
type IntegrationCoverageAccountsPayload = components["schemas"]["IntegrationCoverageAccounts"];

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
}

function mapCoverageRecord(entry: IntegrationCoveragePayload): IntegrationCoverageRecord {
  return transformOpenApi(entry, (data) => ({
    integration: data.integration,
    providers: Array.isArray(data.providers) ? [...data.providers] : [],
    status: data.status,
    scopes: mapScopes(data.scopes),
    accounts: mapAccounts(data.accounts),
    coverageRatio: data.coverageRatio,
    lastSuccess: normalizeDate(data.lastSuccess, entry.last_success),
    evaluatedAt: normalizeDate(data.evaluatedAt, entry.evaluated_at) ?? new Date(entry.evaluated_at),
  }), {
    snakeCaseDateKeys: ["last_success", "evaluated_at"],
    deep: true,
  });
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

function normalizeDate(value: unknown, fallback?: string | null): Date | null {
  if (!value && !fallback) return null;
  const direct = typeof value === "string" || value instanceof Date ? parseDateValue(value) : null;
  if (direct) return direct;
  if (!fallback) return null;
  return parseDateValue(fallback);
}

function parseDateValue(value: string | Date | null | undefined): Date | null {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export default IntegrationsClient;
