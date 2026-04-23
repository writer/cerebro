export interface ToolDefinition {
  id: string;
  version: string;
  tool_name: string;
  sdk_method?: string;
  title?: string;
  description: string;
  category?: string;
  http_method?: string;
  http_path?: string;
  required_permission?: string;
  input_schema?: Record<string, unknown>;
  example_input?: Record<string, unknown>;
  requires_approval?: boolean;
  execution_kind?: string;
  supports_async?: boolean;
  supports_progress?: boolean;
  status_resource?: string;
}

export interface ToolCallResponse {
  tool_id: string;
  tool_name?: string;
  sdk_method?: string;
  result?: unknown;
  raw_result?: unknown;
  invoked_at?: string;
  approval?: boolean;
  http_method?: string;
  http_path?: string;
  execution_kind?: string;
  supports_async?: boolean;
  supports_progress?: boolean;
  status_resource?: string;
}

export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers?: string[];
  scopes_supported?: string[];
  bearer_methods_supported?: string[];
  resource_documentation?: string;
  agent_sdk_endpoint?: string;
  mcp_endpoint?: string;
  mcp_protocol_version?: string;
}

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

export interface ListClaimsOptions {
  claim_id?: string;
  subject_urn?: string;
  predicate?: string;
  object_urn?: string;
  object_value?: string;
  claim_type?: string;
  status?: string;
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

export interface IntegrationOptions {
  runtimeId: string;
  tenantId: string;
  integration: string;
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

  async listTools(): Promise<ToolDefinition[]> {
    return this.requestJson<ToolDefinition[]>("GET", "/api/v1/agent-sdk/tools");
  }

  async callTool(toolId: string, args: unknown): Promise<ToolCallResponse> {
    return this.requestJson<ToolCallResponse>("POST", `/api/v1/agent-sdk/tools/${encodeURIComponent(toolId)}:call`, args);
  }

  async runReport(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("POST", "/api/v1/agent-sdk/report", payload);
  }

  async getProtectedResourceMetadata(): Promise<ProtectedResourceMetadata> {
    return this.requestJson<ProtectedResourceMetadata>("GET", "/.well-known/oauth-protected-resource");
  }

  async putSourceRuntime(runtimeId: string, runtime: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("PUT", `/source-runtimes/${encodeURIComponent(runtimeId)}`, { runtime });
  }

  async getSourceRuntime(runtimeId: string): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("GET", `/source-runtimes/${encodeURIComponent(runtimeId)}`);
  }

  async writeClaims(runtimeId: string, claims: Claim[]): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("POST", `/source-runtimes/${encodeURIComponent(runtimeId)}/claims`, { claims });
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
    return this.requestJson<GraphNeighborhood>("GET", `/graph/neighborhood?${query.toString()}`);
  }

  integration(options: IntegrationOptions): IntegrationClient {
    return new IntegrationClient(this, options);
  }

  async listManagedCredentials(): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("GET", "/api/v1/admin/agent-sdk/credentials");
  }

  async getManagedCredential(credentialId: string): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("GET", `/api/v1/admin/agent-sdk/credentials/${encodeURIComponent(credentialId)}`);
  }

  async createManagedCredential(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("POST", "/api/v1/admin/agent-sdk/credentials", payload);
  }

  async rotateManagedCredential(credentialId: string, payload: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("POST", `/api/v1/admin/agent-sdk/credentials/${encodeURIComponent(credentialId)}:rotate`, payload);
  }

  async revokeManagedCredential(credentialId: string, payload: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("POST", `/api/v1/admin/agent-sdk/credentials/${encodeURIComponent(credentialId)}:revoke`, payload);
  }

  async mcp(payload: Record<string, unknown>, sessionId = ""): Promise<{ response: Record<string, unknown>; sessionId: string }> {
    const headers: Record<string, string> = {};
    if (sessionId) {
      headers["Mcp-Session-Id"] = sessionId;
    }
    const { payload: response, headers: responseHeaders } = await this.requestJsonWithHeaders<Record<string, unknown>>("POST", "/api/v1/mcp", payload, headers);
    return { response, sessionId: responseHeaders.get("Mcp-Session-Id") ?? "" };
  }

  async openMCPStream(sessionId = ""): Promise<Response> {
    const headers: Record<string, string> = { Accept: "text/event-stream" };
    if (sessionId) {
      headers["Mcp-Session-Id"] = sessionId;
    }
    return this.requestRaw("GET", "/api/v1/mcp", undefined, headers);
  }

  async openReportRunStream(statusPath: string): Promise<Response> {
    return this.requestRaw("GET", `${statusPath}/stream`, undefined, { Accept: "text/event-stream" });
  }


  async accessReview(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_access_review", args);
  }


  async actuateRecommendation(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_actuate_recommendation", args);
  }


  async aiWorkloads(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_ai_workloads", args);
  }


  async annotate(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_annotate", args);
  }


  async autonomousCredentialResponse(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_autonomous_credential_response", args);
  }


  async autonomousWorkflowApprove(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_autonomous_workflow_approve", args);
  }


  async autonomousWorkflowStatus(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_autonomous_workflow_status", args);
  }


  async blastRadius(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_blast_radius", args);
  }


  async check(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_check", args);
  }


  async claim(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_claim", args);
  }


  async context(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_context", args);
  }


  async correlateEvents(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_correlate_events", args);
  }


  async decide(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_decide", args);
  }


  async diff(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_diff", args);
  }


  async entityHistory(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_entity_history", args);
  }


  async executionStatus(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_execution_status", args);
  }


  async findings(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_findings", args);
  }


  async graphChangelog(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_graph_changelog", args);
  }


  async graphQuery(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_graph_query", args);
  }


  async graphSimulate(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_graph_simulate", args);
  }


  async identityCalibration(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_identity_calibration", args);
  }


  async identityReview(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_identity_review", args);
  }


  async keyPersonRisk(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_key_person_risk", args);
  }


  async leverage(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_leverage", args);
  }


  async nlq(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_nlq", args);
  }


  async observe(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_observe", args);
  }


  async outcome(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_outcome", args);
  }


  async quality(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_quality", args);
  }


  async reconstruct(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_reconstruct", args);
  }


  async report(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_report", args);
  }


  async resolveIdentity(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_resolve_identity", args);
  }


  async riskScore(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_risk_score", args);
  }


  async simulate(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_simulate", args);
  }


  async splitIdentity(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_split_identity", args);
  }


  async templates(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_templates", args);
  }


  async timeline(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_timeline", args);
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

  async ensureRuntime(config: Record<string, string> = {}): Promise<Record<string, unknown>> {
    return this.client.putSourceRuntime(this.runtimeId, {
      source_id: "sdk",
      tenant_id: this.tenantId,
      config: {
        integration: this.integrationName,
        ...config,
      },
    });
  }

  async writeClaims(claims: Claim[]): Promise<Record<string, unknown>> {
    return this.client.writeClaims(this.runtimeId, claims);
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
      if (!rootUrn || seen.has(rootUrn)) {
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
