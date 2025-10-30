import HttpClient, { RequestOptions } from "../httpClient";
import {
  IntegrationAccountSummary,
  IntegrationCoverageRecord,
  IntegrationScopeBreakdown,
} from "../types";

interface IntegrationCoverageScopesPayload {
  total: number;
  healthy: number;
  warning: number;
  critical: number;
}

interface IntegrationCoverageAccountsPayload {
  total: number;
}

interface IntegrationCoveragePayload {
  integration: string;
  providers: string[];
  status: string;
  scopes: IntegrationCoverageScopesPayload;
  accounts: IntegrationCoverageAccountsPayload;
  coverage_ratio: number | null;
  last_success: string | null;
  evaluated_at: string;
}

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
  return {
    integration: entry.integration,
    providers: entry.providers,
    status: entry.status,
    scopes: mapScopes(entry.scopes),
    accounts: mapAccounts(entry.accounts),
    coverageRatio: entry.coverage_ratio,
    lastSuccess: parseDate(entry.last_success),
    evaluatedAt: parseDate(entry.evaluated_at) ?? new Date(entry.evaluated_at),
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

function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export default IntegrationsClient;
