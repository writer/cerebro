import HttpClient, { RequestOptions } from "../httpClient.js";
import { OrganizationSummary } from "../types.js";

interface OrganizationPayload {
  org_id: string;
  name: string;
  created_at: string;
}

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
  return {
    orgId: payload.org_id,
    name: payload.name,
    createdAt: parseDate(payload.created_at) ?? new Date(payload.created_at),
  };
}

function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export default OrganizationsClient;
