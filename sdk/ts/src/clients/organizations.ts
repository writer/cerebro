import HttpClient, { RequestOptions } from "../httpClient.js";
import type { components } from "../generated/openapi.js";
import { transformOpenApi } from "../serialization.js";
import { OrganizationSummary } from "../types.js";

type OrganizationPayload = components["schemas"]["OrganizationResponse"];

export interface ListOrganizationsOptions {
  skip?: number;
  limit?: number;
}

export class OrganizationsClient {
  constructor(private readonly http: HttpClient) {}

  async list(options: ListOrganizationsOptions = {}): Promise<OrganizationSummary[]> {
    const request: RequestOptions = {};
    if (options.skip !== undefined || options.limit !== undefined) {
      request.searchParams = {
        ...(options.skip !== undefined ? { skip: options.skip } : {}),
        ...(options.limit !== undefined ? { limit: options.limit } : {}),
      };
    }

    const payload = await this.http.get<OrganizationPayload[]>("/api/v1/organizations", request);
    return payload.map(mapOrganization);
  }

  async get(orgId: string): Promise<OrganizationSummary> {
    const payload = await this.http.get<OrganizationPayload>(`/api/v1/organizations/${orgId}`);
    return mapOrganization(payload);
  }
}

function mapOrganization(payload: OrganizationPayload): OrganizationSummary {
  return transformOpenApi(payload, (data) => ({
    orgId: data.orgId,
    name: data.name,
    createdAt: normalizeDate(data.createdAt, payload.created_at) ?? new Date(payload.created_at),
  }), {
    snakeCaseDateKeys: ["created_at"],
  });
}

function normalizeDate(value: unknown, fallback?: string | null): Date | null {
  if (value instanceof Date) return value;
  if (typeof value === "string") {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }
  if (!fallback) return null;
  const parsed = new Date(fallback);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export default OrganizationsClient;
