import HttpClient from "../httpClient.js";
import {
  PolicySuggestionRecord,
  ToolApprovalRecord,
  ToolInvocationRecord,
  ToolInvocationSummary,
} from "../types.js";
import { AgentsClient } from "./agents.js";

export interface ListToolInvocationsOptions {
  status?: string;
  toolName?: string;
  limit?: number;
  since?: string | Date;
}

export interface CreateToolInvocationRequest {
  sessionId: string;
  toolName: string;
  toolVersion?: string;
  inputData: Record<string, unknown>;
  celPolicyKey?: string;
}

export interface UpdateToolInvocationOptions {
  invocationId: string;
  status?: string;
  outputData?: Record<string, unknown> | null;
  errorMessage?: string | null;
  errorCode?: string | null;
  celResult?: boolean | null;
  celContext?: Record<string, unknown> | null;
}

export interface ListToolApprovalsOptions {
  status?: string;
  limit?: number;
}

export interface UpdateApprovalStatusRequest {
  approvalId: string;
  status: string;
  decidedBy: string;
  decisionReason?: string | null;
}

export interface ToolingAdapter {
  listInvocations(options?: ListToolInvocationsOptions): Promise<ToolInvocationRecord[]>;
  getInvocation?(invocationId: string): Promise<ToolInvocationRecord | null>;
  createInvocation?(request: CreateToolInvocationRequest): Promise<ToolInvocationRecord>;
  updateInvocationResult?(options: UpdateToolInvocationOptions): Promise<ToolInvocationRecord>;
  listApprovals?(options?: ListToolApprovalsOptions): Promise<ToolApprovalRecord[]>;
  updateApprovalStatus?(request: UpdateApprovalStatusRequest): Promise<ToolApprovalRecord>;
  summarizeInvocations?(options?: ListToolInvocationsOptions): Promise<ToolInvocationSummary[]>;
}

export interface HttpToolingAdapterOptions {
  basePath?: string;
}

interface ToolInvocationPayload {
  id: string;
  session_id?: string;
  tool_name: string;
  tool_version?: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  error_message?: string | null;
  error_code?: string | null;
  input_data?: Record<string, unknown> | null;
  output_data?: Record<string, unknown> | null;
  cel_policy_key?: string | null;
  cel_expression?: string | null;
  cel_result?: boolean | null;
  cel_context?: Record<string, unknown> | null;
}

interface ToolApprovalPayload {
  id: string;
  org_id: string;
  tool_invocation_id: string;
  requested_by: string;
  requested_at: string;
  reason: string;
  status: string;
  decided_by?: string | null;
  decided_at?: string | null;
  decision_reason?: string | null;
  expires_at?: string | null;
  risk_assessment?: Record<string, unknown> | null;
}

interface ToolInvocationSummaryPayload {
  tool_name: string;
  status: string;
  count: number;
}

class HttpToolingAdapter implements ToolingAdapter {
  constructor(
    private readonly http: HttpClient,
    private readonly options: HttpToolingAdapterOptions = {},
  ) {}

  private get basePath(): string {
    return this.options.basePath ?? "/api/v1/agents/tooling";
  }

  async listInvocations(options: ListToolInvocationsOptions = {}): Promise<ToolInvocationRecord[]> {
    const params: Record<string, string | number> = {};
    if (options.status) params.status = options.status;
    if (options.toolName) params.tool_name = options.toolName;
    if (options.limit !== undefined) params.limit = options.limit;
    if (options.since) params.since = normaliseDate(options.since);

    const payload = await this.http.get<ToolInvocationPayload[]>(`${this.basePath}/invocations`, {
      searchParams: Object.keys(params).length ? params : undefined,
    });

    return payload.map(mapInvocation);
  }

  async getInvocation(invocationId: string): Promise<ToolInvocationRecord | null> {
    const payload = await this.http.get<ToolInvocationPayload | null>(`${this.basePath}/invocations/${invocationId}`);
    return payload ? mapInvocation(payload) : null;
  }

  async createInvocation(request: CreateToolInvocationRequest): Promise<ToolInvocationRecord> {
    const payload = await this.http.post<ToolInvocationPayload>(`${this.basePath}/invocations`, {
      body: {
        session_id: request.sessionId,
        tool_name: request.toolName,
        tool_version: request.toolVersion,
        input_data: request.inputData,
        cel_policy_key: request.celPolicyKey,
      },
    });

    return mapInvocation(payload);
  }

  async updateInvocationResult(options: UpdateToolInvocationOptions): Promise<ToolInvocationRecord> {
    const payload = await this.http.post<ToolInvocationPayload>(`${this.basePath}/invocations/${options.invocationId}/result`, {
      body: {
        status: options.status,
        output_data: options.outputData,
        error_message: options.errorMessage,
        error_code: options.errorCode,
        cel_result: options.celResult,
        cel_context: options.celContext,
      },
    });

    return mapInvocation(payload);
  }

  async listApprovals(options: ListToolApprovalsOptions = {}): Promise<ToolApprovalRecord[]> {
    const params: Record<string, string | number> = {};
    if (options.status) params.status = options.status;
    if (options.limit !== undefined) params.limit = options.limit;

    const payload = await this.http.get<ToolApprovalPayload[]>(`${this.basePath}/approvals`, {
      searchParams: Object.keys(params).length ? params : undefined,
    });

    return payload.map(mapApproval);
  }

  async updateApprovalStatus(request: UpdateApprovalStatusRequest): Promise<ToolApprovalRecord> {
    const payload = await this.http.post<ToolApprovalPayload>(`${this.basePath}/approvals/${request.approvalId}`, {
      body: {
        status: request.status,
        decided_by: request.decidedBy,
        decision_reason: request.decisionReason ?? null,
      },
    });

    return mapApproval(payload);
  }

  async summarizeInvocations(options: ListToolInvocationsOptions = {}): Promise<ToolInvocationSummary[]> {
    const params: Record<string, string | number> = {};
    if (options.status) params.status = options.status;
    if (options.toolName) params.tool_name = options.toolName;

    const payload = await this.http.get<ToolInvocationSummaryPayload[]>(`${this.basePath}/invocations/summary`, {
      searchParams: Object.keys(params).length ? params : undefined,
    });

    return payload.map((entry) => ({
      toolName: entry.tool_name,
      status: entry.status,
      count: entry.count,
    }));
  }
}

export class InMemoryToolingAdapter implements ToolingAdapter {
  private readonly invocations = new Map<string, ToolInvocationRecord>();
  private readonly approvals = new Map<string, ToolApprovalRecord>();

  async listInvocations(): Promise<ToolInvocationRecord[]> {
    return Array.from(this.invocations.values());
  }

  async getInvocation(invocationId: string): Promise<ToolInvocationRecord | null> {
    return this.invocations.get(invocationId) ?? null;
  }

  async createInvocation(request: CreateToolInvocationRequest): Promise<ToolInvocationRecord> {
    const record: ToolInvocationRecord = {
      invocationId: generateId(),
      sessionId: request.sessionId,
      toolName: request.toolName,
      toolVersion: request.toolVersion,
      status: "PENDING",
      startedAt: new Date(),
      completedAt: null,
      errorMessage: null,
      inputData: request.inputData,
      outputData: null,
      errorCode: null,
      celPolicyKey: request.celPolicyKey ?? null,
      celExpression: null,
      celResult: null,
      celContext: null,
    };
    this.invocations.set(record.invocationId, record);
    return record;
  }

  async updateInvocationResult(options: UpdateToolInvocationOptions): Promise<ToolInvocationRecord> {
    const existing = this.invocations.get(options.invocationId);
    if (!existing) {
      throw new Error(`Invocation '${options.invocationId}' not found`);
    }
    if (options.status) existing.status = options.status;
    if (options.outputData !== undefined) existing.outputData = options.outputData;
    if (options.errorMessage !== undefined) existing.errorMessage = options.errorMessage;
    if (options.errorCode !== undefined) existing.errorCode = options.errorCode;
    if (options.celResult !== undefined) existing.celResult = options.celResult;
    if (options.celContext !== undefined) existing.celContext = options.celContext;
    existing.completedAt = new Date();
    return existing;
  }

  async listApprovals(): Promise<ToolApprovalRecord[]> {
    return Array.from(this.approvals.values());
  }

  async updateApprovalStatus(request: UpdateApprovalStatusRequest): Promise<ToolApprovalRecord> {
    const approval = this.approvals.get(request.approvalId);
    if (!approval) {
      throw new Error(`Approval '${request.approvalId}' not found`);
    }
    approval.status = request.status;
    approval.decidedBy = request.decidedBy;
    approval.decidedAt = new Date();
    approval.decisionReason = request.decisionReason ?? null;
    return approval;
  }

  async summarizeInvocations(): Promise<ToolInvocationSummary[]> {
    const summary = new Map<string, number>();
    for (const invocation of this.invocations.values()) {
      const key = `${invocation.toolName}:${invocation.status}`;
      summary.set(key, (summary.get(key) ?? 0) + 1);
    }

    return Array.from(summary.entries()).map(([key, count]) => {
      const [toolName, status] = key.split(":");
      return { toolName, status, count };
    });
  }
}

export class AgentToolingClient {
  constructor(
    private readonly agents: AgentsClient,
    private readonly adapter?: ToolingAdapter,
  ) {}

  static fromHttpClient(http: HttpClient, agents: AgentsClient, options?: HttpToolingAdapterOptions): AgentToolingClient {
    return new AgentToolingClient(agents, new HttpToolingAdapter(http, options));
  }

  async listPolicySuggestions(options?: { limit?: number }): Promise<PolicySuggestionRecord[]> {
    return this.agents.listPolicySuggestions(options);
  }

  async simulatePolicyExpression(request: { expression: string; toolName?: string; limit?: number }) {
    return this.agents.simulatePolicyExpression(request);
  }

  async listInvocations(options?: ListToolInvocationsOptions): Promise<ToolInvocationRecord[]> {
    this.ensureAdapter("listInvocations");
    return this.adapter!.listInvocations(options);
  }

  async getInvocation(invocationId: string): Promise<ToolInvocationRecord | null> {
    this.ensureAdapter("getInvocation");
    return this.adapter!.getInvocation!(invocationId);
  }

  async createInvocation(request: CreateToolInvocationRequest): Promise<ToolInvocationRecord> {
    this.ensureAdapter("createInvocation");
    return this.adapter!.createInvocation!(request);
  }

  async updateInvocationResult(options: UpdateToolInvocationOptions): Promise<ToolInvocationRecord> {
    this.ensureAdapter("updateInvocationResult");
    return this.adapter!.updateInvocationResult!(options);
  }

  async listApprovals(options?: ListToolApprovalsOptions): Promise<ToolApprovalRecord[]> {
    this.ensureAdapter("listApprovals");
    return this.adapter!.listApprovals!(options);
  }

  async updateApprovalStatus(request: UpdateApprovalStatusRequest): Promise<ToolApprovalRecord> {
    this.ensureAdapter("updateApprovalStatus");
    return this.adapter!.updateApprovalStatus!(request);
  }

  async summarizeInvocations(options?: ListToolInvocationsOptions): Promise<ToolInvocationSummary[]> {
    this.ensureAdapter("summarizeInvocations");
    return this.adapter!.summarizeInvocations!(options);
  }

  private ensureAdapter(method: keyof ToolingAdapter): void {
    if (!this.adapter || !(method in this.adapter) || typeof (this.adapter as any)[method] !== "function") {
      throw new Error(`Tooling adapter does not implement '${method}'`);
    }
  }
}

function mapInvocation(payload: ToolInvocationPayload): ToolInvocationRecord {
  return {
    invocationId: payload.id,
    sessionId: payload.session_id,
    toolName: payload.tool_name,
    toolVersion: payload.tool_version,
    status: payload.status,
    startedAt: new Date(payload.started_at),
    completedAt: payload.completed_at ? new Date(payload.completed_at) : null,
    errorMessage: payload.error_message ?? null,
    errorCode: payload.error_code ?? null,
    inputData: payload.input_data ?? undefined,
    outputData: payload.output_data ?? undefined,
    celPolicyKey: payload.cel_policy_key ?? null,
    celExpression: payload.cel_expression ?? null,
    celResult: payload.cel_result ?? null,
    celContext: payload.cel_context ?? null,
  };
}

function mapApproval(payload: ToolApprovalPayload): ToolApprovalRecord {
  return {
    approvalId: payload.id,
    orgId: payload.org_id,
    toolInvocationId: payload.tool_invocation_id,
    requestedBy: payload.requested_by,
    requestedAt: new Date(payload.requested_at),
    reason: payload.reason,
    status: payload.status,
    decidedBy: payload.decided_by ?? null,
    decidedAt: payload.decided_at ? new Date(payload.decided_at) : null,
    decisionReason: payload.decision_reason ?? null,
    expiresAt: payload.expires_at ? new Date(payload.expires_at) : null,
    riskAssessment: payload.risk_assessment ?? {},
  };
}

function normaliseDate(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function generateId(): string {
  return Math.random().toString(36).slice(2, 10);
}
