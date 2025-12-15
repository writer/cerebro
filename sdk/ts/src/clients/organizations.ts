import HttpClient, { RequestOptions } from "../httpClient.js";
import type { components } from "../generated/openapi.js";
import { createSchemaAdapter } from "../generated/adapters/schemaAdapters.js";
import { parseDate } from "../serialization.js";
import { OrganizationSummary } from "../types.js";

type OrganizationPayload = components["schemas"]["cerebro__api__schemas__main__OrganizationResponse"];

const adaptOrganization = createSchemaAdapter("cerebro__api__schemas__main__OrganizationResponse");

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
  return adaptOrganization(payload, (data) => ({
    orgId: data.orgId,
    name: data.name,
    createdAt: coerceDate(data.createdAt, payload.created_at) ?? new Date(payload.created_at),
  }));
}

function coerceDate(value: unknown, fallback?: string | null): Date | null {
  const parsed = parseDate(value as string | Date | null);
  if (parsed) return parsed;
  if (!fallback) return null;
  return parseDate(fallback) ?? new Date(fallback);
}

export default OrganizationsClient;
