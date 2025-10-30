import HttpClient, { RequestOptions } from "../httpClient";
import { FindingRecord } from "../types";

interface FindingPayload {
  finding_id: string;
  org_id: string;
  account_id: string;
  provider: string;
  rule_id: string;
  rule_version: number;
  resource_id: string | null;
  principal_id: string | null;
  first_seen: string;
  last_seen: string;
  status: string;
  severity: string;
  fingerprint: string;
  title: string;
  summary: string | null;
  evidence: Record<string, unknown> | null;
}

export interface ListFindingsOptions {
  orgId?: string;
  status?: string;
  severity?: string;
  provider?: string;
  skip?: number;
  limit?: number;
}

export class FindingsClient {
  constructor(private readonly http: HttpClient) {}

  async list(options: ListFindingsOptions = {}): Promise<FindingRecord[]> {
    const request: RequestOptions = {
      searchParams: this.buildSearchParams(options),
    };

    const payload = await this.http.get<FindingPayload[]>("/api/v1/findings", request);
    return payload.map(mapFinding);
  }

  async get(findingId: string): Promise<FindingRecord> {
    const payload = await this.http.get<FindingPayload>(`/api/v1/findings/${findingId}`);
    return mapFinding(payload);
  }

  private buildSearchParams(options: ListFindingsOptions): Record<string, string | number> | undefined {
    const params: Record<string, string | number> = {};
    if (options.orgId) params.org_id = options.orgId;
    if (options.status) params.status = options.status;
    if (options.severity) params.severity = options.severity;
    if (options.provider) params.provider = options.provider;
    if (options.skip !== undefined) params.skip = options.skip;
    if (options.limit !== undefined) params.limit = options.limit;
    return Object.keys(params).length ? params : undefined;
  }
}

function mapFinding(payload: FindingPayload): FindingRecord {
  return {
    findingId: payload.finding_id,
    orgId: payload.org_id,
    accountId: payload.account_id,
    provider: payload.provider,
    ruleId: payload.rule_id,
    ruleVersion: payload.rule_version,
    resourceId: payload.resource_id,
    principalId: payload.principal_id,
    firstSeen: parseDate(payload.first_seen) ?? new Date(payload.first_seen),
    lastSeen: parseDate(payload.last_seen) ?? new Date(payload.last_seen),
    status: payload.status,
    severity: payload.severity,
    fingerprint: payload.fingerprint,
    title: payload.title,
    summary: payload.summary,
    evidence: payload.evidence,
  };
}

function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export default FindingsClient;
