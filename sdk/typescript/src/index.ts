import type {
  CreatePlatformJobRequest,
  GetSourceRuntimeResponse,
  PlatformJobEventListResponse,
  PlatformJobListResponse,
  PlatformJobResponse,
  PutSourceRuntimeResponse,
  SourceRuntime,
} from "./generated/openapi-types.ts";

export type {
  GetSourceRuntimeResponse,
  PlatformJob,
  PlatformJobEvent,
  PlatformJobEventListResponse,
  PlatformJobListResponse,
  PlatformJobResponse,
  PutSourceRuntimeResponse,
  SourceRuntime,
} from "./generated/openapi-types.ts";

export interface ClientConfig {
  baseUrl: string;
  apiKey?: string;
  userAgent?: string;
  fetchImpl?: typeof fetch;
}

export interface EntityRef {
  urn: string;
  entity_type: string;
  label?: string;
}

export interface Claim {
  id?: string;
  subject_urn?: string;
  subject_ref?: EntityRef;
  predicate: string;
  object_urn?: string;
  object_ref?: EntityRef;
  object_value?: string;
  claim_type?: string;
  status?: string;
  source_event_id?: string;
  observed_at?: string;
  valid_from?: string;
  valid_to?: string;
  attributes?: Record<string, string>;
}

export interface ClaimOptions {
  id?: string;
  status?: string;
  source_event_id?: string;
  observed_at?: string;
  valid_from?: string;
  valid_to?: string;
  attributes?: Record<string, string>;
  claim_type?: string;
}

export interface WriteClaimsOptions {
  replace_existing?: boolean;
}

export interface ListClaimsOptions {
  claim_id?: string;
  subject_urn?: string;
  predicate?: string;
  object_urn?: string;
  object_value?: string;
  claim_type?: string;
  status?: string;
  source_event_id?: string;
  limit?: number;
}

export interface GraphEntity {
  urn: string;
  entity_type: string;
  label: string;
}

export interface GraphRelation {
  from_urn: string;
  relation: string;
  to_urn: string;
}

export interface GraphNeighborhood {
  root?: GraphEntity;
  neighbors?: GraphEntity[];
  relations?: GraphRelation[];
}

export interface GraphNeighborhoodError {
  root_urn: string;
  error: string;
}

export type GraphLayering = Record<string, GraphNeighborhood | GraphNeighborhoodError>;

export interface GraphSummary {
  roots: GraphEntity[];
  node_counts_by_type: Record<string, number>;
  relation_counts_by_type: Record<string, number>;
  neighborhood_sizes: Record<string, { neighbors: number; relations: number }>;
  errors: Record<string, string>;
}

export interface IntegrationOptions {
  runtimeId: string;
  tenantId: string;
  integration: string;
}

export type CreateJobRequest = CreatePlatformJobRequest;

export interface ListJobsOptions {
  tenant_id?: string;
  kind?: string;
  status?: string;
  limit?: number;
}

export class APIError extends Error {
  statusCode: number;
  code?: string;

  constructor(statusCode: number, message: string, code?: string) {
    super(`api request failed (${statusCode}${code ? ` ${code}` : ""}): ${message}`);
    this.statusCode = statusCode;
    this.code = code;
  }
}

export class Client {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly userAgent: string;
  private readonly fetchImpl: typeof fetch;

  constructor(config: ClientConfig) {
    if (!config.baseUrl) {
      throw new Error("baseUrl is required");
    }
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.apiKey = config.apiKey;
    this.userAgent = config.userAgent ?? "cerebro-sdk-typescript";
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  async putSourceRuntime(runtimeId: string, runtime: SourceRuntime): Promise<PutSourceRuntimeResponse> {
    return this.requestJson<PutSourceRuntimeResponse>("PUT", `/source-runtimes/${encodeURIComponent(runtimeId)}`, { runtime });
  }

  async getSourceRuntime(runtimeId: string): Promise<GetSourceRuntimeResponse> {
    return this.requestJson<GetSourceRuntimeResponse>("GET", `/source-runtimes/${encodeURIComponent(runtimeId)}`);
  }

  async writeClaims(runtimeId: string, claims: Claim[], options: WriteClaimsOptions = {}): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("POST", `/source-runtimes/${encodeURIComponent(runtimeId)}/claims`, {
      ...options,
      claims,
    });
  }

  async listClaims(runtimeId: string, options: ListClaimsOptions = {}): Promise<Record<string, unknown>> {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(options)) {
      if (value === undefined || value === null || value === "") {
        continue;
      }
      query.set(key, String(value));
    }
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return this.requestJson<Record<string, unknown>>("GET", `/source-runtimes/${encodeURIComponent(runtimeId)}/claims${suffix}`);
  }

  async getEntityNeighborhood(rootUrn: string, limit = 0): Promise<GraphNeighborhood> {
    const normalizedRootUrn = rootUrn.trim();
    if (!normalizedRootUrn) {
      throw new Error("rootUrn is required");
    }
    const query = new URLSearchParams({ root_urn: normalizedRootUrn });
    if (limit > 0) {
      query.set("limit", String(limit));
    }
    return this.requestJson<GraphNeighborhood>("GET", `/platform/graph/neighborhood?${query.toString()}`);
  }

  async createJob(request: CreateJobRequest, idempotencyKey = ""): Promise<PlatformJobResponse> {
    const headers: Record<string, string> = {};
    if (idempotencyKey) {
      headers["Idempotency-Key"] = idempotencyKey;
    }
    return this.requestJson<PlatformJobResponse>("POST", "/platform/jobs", request, headers);
  }

  async listJobs(options: ListJobsOptions = {}): Promise<PlatformJobListResponse> {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(options)) {
      if (value === undefined || value === null || value === "") {
        continue;
      }
      query.set(key, String(value));
    }
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return this.requestJson<PlatformJobListResponse>("GET", `/platform/jobs${suffix}`);
  }

  async getJob(jobId: string): Promise<PlatformJobResponse> {
    return this.requestJson<PlatformJobResponse>("GET", `/platform/jobs/${encodeURIComponent(jobId)}`);
  }

  async listJobEvents(jobId: string, limit = 0): Promise<PlatformJobEventListResponse> {
    const suffix = limit > 0 ? `?limit=${encodeURIComponent(String(limit))}` : "";
    return this.requestJson<PlatformJobEventListResponse>("GET", `/platform/jobs/${encodeURIComponent(jobId)}/events${suffix}`);
  }

  async cancelJob(jobId: string): Promise<PlatformJobResponse> {
    return this.requestJson<PlatformJobResponse>("POST", `/platform/jobs/${encodeURIComponent(jobId)}/cancel`);
  }

  integration(options: IntegrationOptions): IntegrationClient {
    return new IntegrationClient(this, options);
  }

  private async requestJson<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
    const { payload } = await this.requestJsonWithHeaders<T>(method, path, body, headers);
    return payload;
  }

  private async requestJsonWithHeaders<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<{ payload: T; headers: Headers }> {
    const response = await this.requestRaw(method, path, body, headers);
    const text = await response.text();
    return { payload: (text ? JSON.parse(text) : null) as T, headers: response.headers };
  }

  private async requestRaw(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<Response> {
    const initHeaders = new Headers(headers);
    initHeaders.set("Accept", initHeaders.get("Accept") ?? "application/json");
    initHeaders.set("User-Agent", initHeaders.get("User-Agent") ?? this.userAgent);
    if (this.apiKey) {
      initHeaders.set("Authorization", `Bearer ${this.apiKey}`);
    }
    let requestBody: BodyInit | undefined;
    if (body !== undefined) {
      initHeaders.set("Content-Type", initHeaders.get("Content-Type") ?? "application/json");
      requestBody = JSON.stringify(body);
    }
    const response = await this.fetchImpl(`${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`, {
      method,
      headers: initHeaders,
      body: requestBody,
    });
    if (!response.ok) {
      const text = await response.text();
      try {
        const decoded = text ? JSON.parse(text) : {};
        throw new APIError(response.status, decoded.error ?? text, decoded.code);
      } catch (error) {
        if (error instanceof APIError) {
          throw error;
        }
        throw new APIError(response.status, text || response.statusText);
      }
    }
    return response;
  }
}

export class IntegrationClient {
  private readonly client: Client;
  private readonly runtimeId: string;
  private readonly tenantId: string;
  private readonly integrationName: string;

  constructor(client: Client, options: IntegrationOptions) {
    if (!options.runtimeId) {
      throw new Error("runtimeId is required");
    }
    if (!options.tenantId) {
      throw new Error("tenantId is required");
    }
    if (!options.integration) {
      throw new Error("integration is required");
    }
    this.client = client;
    this.runtimeId = options.runtimeId;
    this.tenantId = options.tenantId;
    this.integrationName = options.integration;
  }

  async ensureRuntime(config: Record<string, string> = {}): Promise<PutSourceRuntimeResponse> {
    return this.client.putSourceRuntime(this.runtimeId, {
      source_id: "sdk",
      tenant_id: this.tenantId,
      config: {
        integration: this.integrationName,
        ...config,
      },
    });
  }

  async writeClaims(claims: Claim[], options: WriteClaimsOptions = {}): Promise<Record<string, unknown>> {
    return this.client.writeClaims(this.runtimeId, claims, options);
  }

  async listClaims(options: ListClaimsOptions = {}): Promise<Record<string, unknown>> {
    return this.client.listClaims(this.runtimeId, options);
  }

  async graphNeighborhood(root: EntityRef | string, limit = 0): Promise<GraphNeighborhood> {
    const rootUrn = typeof root === "string" ? root.trim() : root.urn.trim();
    return this.client.getEntityNeighborhood(rootUrn, limit);
  }

  async graphLayering(roots: Array<EntityRef | string>, limit = 0): Promise<GraphLayering> {
    const layering: GraphLayering = {};
    const seen = new Set<string>();
    for (const root of roots) {
      const rootUrn = typeof root === "string" ? root.trim() : root.urn.trim();
      if (!rootUrn) {
        throw new Error("graphLayering: root urn must be a non-empty string");
      }
      if (seen.has(rootUrn)) {
        continue;
      }
      seen.add(rootUrn);
      try {
        layering[rootUrn] = await this.graphNeighborhood(rootUrn, limit);
      } catch (error) {
        if (error instanceof APIError) {
          layering[rootUrn] = {
            root_urn: rootUrn,
            error: error.message,
          };
          continue;
        }
        throw error;
      }
    }
    return layering;
  }

  graphSummary(layering: GraphLayering): GraphSummary {
    return summarizeGraphLayering(layering);
  }

  ref(kind: string, externalId: string, label = ""): EntityRef {
    const normalizedKind = kind.trim();
    const normalizedExternalId = externalId.trim();
    if (!normalizedKind) {
      throw new Error("kind is required");
    }
    if (!normalizedExternalId) {
      throw new Error("externalId is required");
    }
    return {
      urn: this.buildURN(normalizedKind, normalizedExternalId),
      entity_type: normalizedKind,
      label: label.trim() || normalizedExternalId,
    };
  }

  exists(subject: EntityRef, options: ClaimOptions = {}): Claim {
    return this.buildClaim(subject, "exists", {
      ...options,
      claim_type: options.claim_type ?? "existence",
    });
  }

  attr(subject: EntityRef, predicate: string, value: string, options: ClaimOptions = {}): Claim {
    return this.buildClaim(subject, predicate, {
      ...options,
      claim_type: options.claim_type ?? "attribute",
      object_value: value.trim(),
    });
  }

  rel(subject: EntityRef, predicate: string, object: EntityRef, options: ClaimOptions = {}): Claim {
    return this.buildClaim(subject, predicate, {
      ...options,
      claim_type: options.claim_type ?? "relation",
      object_ref: object,
      object_urn: object.urn,
    });
  }

  private buildClaim(subject: EntityRef, predicate: string, options: ClaimOptions & {
    object_ref?: EntityRef;
    object_urn?: string;
    object_value?: string;
  }): Claim {
    const normalizedPredicate = predicate.trim();
    if (!subject.urn.trim()) {
      throw new Error("subject.urn is required");
    }
    if (!normalizedPredicate) {
      throw new Error("predicate is required");
    }
    return {
      id: options.id,
      subject_urn: subject.urn.trim(),
      subject_ref: subject,
      predicate: normalizedPredicate,
      object_ref: options.object_ref,
      object_urn: options.object_urn?.trim(),
      object_value: options.object_value?.trim(),
      claim_type: options.claim_type,
      status: options.status,
      source_event_id: options.source_event_id,
      observed_at: options.observed_at,
      valid_from: options.valid_from,
      valid_to: options.valid_to,
      attributes: options.attributes,
    };
  }

  private buildURN(kind: string, externalId: string): string {
    return ["urn", "cerebro", this.tenantId, "runtime", this.runtimeId, kind, externalId].join(":");
  }
}

export function summarizeGraphLayering(layering: GraphLayering): GraphSummary {
  const roots: GraphEntity[] = [];
  const nodeCounts = new Map<string, number>();
  const relationCounts = new Map<string, number>();
  const neighborhoodSizes: Record<string, { neighbors: number; relations: number }> = {};
  const errors: Record<string, string> = {};
  const seenNodes = new Set<string>();
  const seenRelations = new Set<string>();

  for (const [rootUrn, entry] of Object.entries(layering)) {
    if ("error" in entry) {
      errors[entry.root_urn || rootUrn] = entry.error;
      continue;
    }
    const root = entry.root;
    if (!root?.urn) {
      continue;
    }
    roots.push(root);
    neighborhoodSizes[root.urn] = {
      neighbors: entry.neighbors?.length ?? 0,
      relations: entry.relations?.length ?? 0,
    };
    for (const node of [root, ...(entry.neighbors ?? [])]) {
      if (!node?.urn || seenNodes.has(node.urn)) {
        continue;
      }
      seenNodes.add(node.urn);
      const entityType = node.entity_type || "unknown";
      nodeCounts.set(entityType, (nodeCounts.get(entityType) ?? 0) + 1);
    }
    for (const relation of entry.relations ?? []) {
      if (!relation?.from_urn || !relation?.relation || !relation?.to_urn) {
        continue;
      }
      const key = `${relation.from_urn}\u0000${relation.relation}\u0000${relation.to_urn}`;
      if (seenRelations.has(key)) {
        continue;
      }
      seenRelations.add(key);
      relationCounts.set(relation.relation, (relationCounts.get(relation.relation) ?? 0) + 1);
    }
  }

  return {
    roots,
    node_counts_by_type: Object.fromEntries(nodeCounts),
    relation_counts_by_type: Object.fromEntries(relationCounts),
    neighborhood_sizes: neighborhoodSizes,
    errors,
  };
}
