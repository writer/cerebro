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
  integration?: string;
}

export interface IntegrationCoverageHistoryOptions {
  integration?: string;
  limit?: number;
  since?: Date | string;
  until?: Date | string;
}

export class IntegrationsClient {
  constructor(private readonly http: HttpClient) {}

  async getCoverage(options?: IntegrationCoverageOptions): Promise<IntegrationCoverageRecord[]> {
    const requestOpts: RequestOptions = { searchParams: {} };
    if (options?.staleSeconds !== undefined) {
      requestOpts.searchParams!.stale_seconds = options.staleSeconds;
    }
    if (options?.integration) {
      requestOpts.searchParams!.integration = options.integration;
    }
    if (requestOpts.searchParams && Object.keys(requestOpts.searchParams).length === 0) {
      delete requestOpts.searchParams;
    }
    const payload = await this.http.get<IntegrationCoveragePayload[]>(
      "/api/v1/integrations/coverage",
      requestOpts,
    );
    return payload.map(mapCoverageRecord);
  }

  async getCoverageHistory(options: IntegrationCoverageHistoryOptions = {}): Promise<IntegrationCoverageRecord[]> {
    const searchParams: Record<string, string> = {};
    if (options.integration) {
      searchParams.integration = options.integration;
    }
    if (options.limit !== undefined) {
      searchParams.limit = String(options.limit);
    }
    if (options.since) {
      searchParams.since = toIsoString(options.since);
    }
    if (options.until) {
      searchParams.until = toIsoString(options.until);
    }

    const payload = await this.http.get<IntegrationCoveragePayload[]>(
      "/api/v1/integrations/coverage/history",
      { searchParams: Object.keys(searchParams).length ? searchParams : undefined },
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

function toIsoString(value: Date | string): string {
  if (value instanceof Date) {
    return value.toISOString();
  }
  const parsed = parseDate(value) ?? new Date(value);
  return parsed.toISOString();
}

export default IntegrationsClient;
