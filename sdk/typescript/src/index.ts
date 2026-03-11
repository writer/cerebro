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


  async annotate(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_annotate", args);
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


  async decide(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_decide", args);
  }


  async findings(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_findings", args);
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


  async leverage(args: unknown): Promise<ToolCallResponse> {
    return this.callTool("cerebro_leverage", args);
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
