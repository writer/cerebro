import HttpClient, { RequestOptions } from "../httpClient.js";
import type { components } from "../generated/openapi.js";
import { createSchemaAdapter } from "../generated/adapters/schemaAdapters.js";
import { CursorPage, PageRequest } from "../pagination.js";
import { parseDate } from "../serialization.js";
import { FindingRecord } from "../types.js";

type FindingPayload = components["schemas"]["FindingResponse"];
type FindingPageResponse = components["schemas"]["FindingPageResponse"];

const adaptFinding = createSchemaAdapter("FindingResponse");

export interface ListFindingsOptions {
  orgId?: string;
  status?: string;
  severity?: string;
  provider?: string;
  skip?: number;
  limit?: number;
}

export interface ListFindingsPageOptions {
  orgId?: string;
  status?: string;
  severity?: string;
  provider?: string;
  cursor?: string | null;
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

  async listPage(options: ListFindingsPageOptions = {}): Promise<CursorPage<FindingRecord>> {
    const pageRequest: PageRequest = {
      cursor: options.cursor ?? undefined,
      limit: options.limit,
    };

    const params = this.buildPageSearchParams(options, pageRequest);
    const payload = await this.http.get<FindingPageResponse>("/api/v1/findings/page", {
      searchParams: params,
    });

    return {
      items: payload.items.map(mapFinding),
      nextCursor: payload.next_cursor ?? null,
    };
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

  private buildPageSearchParams(
    filters: ListFindingsPageOptions,
    page: PageRequest,
  ): Record<string, string | number> | undefined {
    const params: Record<string, string | number> = {};
    if (filters.orgId) params.org_id = filters.orgId;
    if (filters.status) params.status = filters.status;
    if (filters.severity) params.severity = filters.severity;
    if (filters.provider) params.provider = filters.provider;
    if (page.limit !== undefined) params.limit = page.limit;
    if (page.cursor) params.cursor = page.cursor;
    return Object.keys(params).length ? params : undefined;
  }
}

function mapFinding(payload: FindingPayload): FindingRecord {
  return adaptFinding(payload, (data) => ({
    findingId: data.findingId,
    orgId: data.orgId,
    accountId: data.accountId,
    provider: data.provider,
    ruleId: data.ruleId,
    ruleVersion: data.ruleVersion,
    resourceId: data.resourceId ?? null,
    principalId: data.principalId ?? null,
    firstSeen: coerceDate(data.firstSeen, payload.first_seen) ?? new Date(payload.first_seen),
    lastSeen: coerceDate(data.lastSeen, payload.last_seen) ?? new Date(payload.last_seen),
    status: data.status,
    severity: data.severity,
    fingerprint: data.fingerprint,
    title: data.title,
    summary: data.summary ?? null,
    evidence: data.evidence ?? null,
  }));
}

function coerceDate(value: unknown, fallback?: string | null): Date | null {
  const parsed = parseDate(value as string | Date | null);
  if (parsed) return parsed;
  if (!fallback) return null;
  return parseDate(fallback) ?? new Date(fallback);
}

export default FindingsClient;
