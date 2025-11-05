import HttpClient, { RequestOptions } from "../httpClient.js";
import type { components } from "../generated/openapi.js";
import {
  IntegrationAccountSummary,
  IntegrationCoverageRecord,
  IntegrationScopeBreakdown,
} from "../types.js";
import { deserialize, parseDate } from "../serialization.js";

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
  const normalized = deserialize(entry, { dateKeys: ["last_success", "evaluated_at"] }) as IntegrationCoveragePayload & {
    last_success: Date | null;
    evaluated_at: Date | null;
  };
  return {
    integration: entry.integration,
    providers: entry.providers,
    status: entry.status,
    scopes: mapScopes(entry.scopes),
    accounts: mapAccounts(entry.accounts),
    coverageRatio: entry.coverage_ratio,
    lastSuccess: normalized.last_success ?? parseDate(entry.last_success),
    evaluatedAt: normalized.evaluated_at ?? parseDate(entry.evaluated_at) ?? new Date(entry.evaluated_at),
  };
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

export default IntegrationsClient;
