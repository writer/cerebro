import HttpClient, { HttpStream } from "../httpClient.js";
import type { components } from "../generated/openapi.js";
import { createSchemaAdapter } from "../generated/adapters/schemaAdapters.js";
import { CursorPage, PageRequest, iterateCursor } from "../pagination.js";
import { parseDate, transformOpenApi } from "../serialization.js";
import {
  AgentMemoryHighlight,
  AgentMemoryRecord,
  AgentMemoryStats,
  AgentMessageRecord,
  AgentSessionDetail,
  AgentSessionList,
  AgentSessionRecord,
  ReviewQueuePendingSummary,
  ReviewQueuePrioritySummary,
  ReviewQueueStatusAggregate,
  ReviewQueueSummary,
  ReviewTaskCommentRecord,
  ReviewTaskHistoryRecord,
  ReviewTaskSlaStatus,
  ReviewTaskSlaSummary,
  ReviewNotificationRecord,
  ReviewTaskRecord,
  RuntimeEventRecord,
  RuntimeEventSummaryRecord,
  ToolInvocationRecord,
  WorkflowTemplateRecord,
  WorkflowTemplateStepRecord,
  PolicySuggestionRecord,
  PolicySimulationResultRecord,
  PolicySimulationExampleRecord,
} from "../types.js";

type ReviewQueueStatusPayload = components["schemas"]["ReviewQueueStatusSummary"];
type ReviewQueuePendingPayload = components["schemas"]["ReviewQueuePendingSummary"];
type ReviewQueuePriorityPayload = components["schemas"]["ReviewQueuePrioritySummary"];
type ReviewQueueSummaryPayload = components["schemas"]["ReviewQueueSummary"];
type ReviewTaskPayload = components["schemas"]["ReviewTaskResponse"];
type ReviewTaskPageResponse = components["schemas"]["ReviewTaskPageResponse"];
type SessionPayload = components["schemas"]["cerebro__api__routers__agents__SessionResponse"];
type SessionListResponsePayload = components["schemas"]["cerebro__api__routers__agents__SessionListResponse"];
type MessagePayload = components["schemas"]["cerebro__api__routers__agents__MessageResponse"];
type ToolInvocationPayload = components["schemas"]["cerebro__api__routers__agents__ToolInvocationResponse"] & {
  session_id?: string | null;
  tool_version?: string | null;
  error_code?: string | null;
  input_data?: Record<string, unknown> | null;
  output_data?: Record<string, unknown> | null;
  cel_policy_key?: string | null;
  cel_expression?: string | null;
  cel_result?: boolean | null;
  cel_context?: Record<string, unknown> | null;
};
type SessionWithMessagesPayload = components["schemas"]["SessionWithMessagesResponse"];
type MemoryEntryPayload = components["schemas"]["MemoryEntryResponse"];
type MemoryHighlightPayload = components["schemas"]["MemoryHighlightResponse"];
type MemoryStatsPayload = components["schemas"]["MemoryStatsResponse"];

const adaptReviewTask = createSchemaAdapter("ReviewTaskResponse");
const adaptReviewNotification = createSchemaAdapter("ReviewNotificationResponse");
const adaptRuntimeEvent = createSchemaAdapter("RuntimeEventResponse");
const adaptRuntimeSummary = createSchemaAdapter("RuntimeEventSummaryResponse");
const adaptSession = createSchemaAdapter("cerebro__api__routers__agents__SessionResponse");
const adaptMessage = createSchemaAdapter("cerebro__api__routers__agents__MessageResponse");
const adaptToolInvocation = createSchemaAdapter("cerebro__api__routers__agents__ToolInvocationResponse");
const adaptMemoryEntry = createSchemaAdapter("MemoryEntryResponse");
const adaptMemoryHighlight = createSchemaAdapter("MemoryHighlightResponse");
const adaptPolicySuggestion = createSchemaAdapter("PolicySuggestionResponse");
const adaptPolicySimulation = createSchemaAdapter("PolicySimulationResponse");
const adaptPolicySimulationExample = createSchemaAdapter("PolicySimulationExample");

export interface ListReviewTasksPageOptions {
  status?: string;
  limit?: number;
  cursor?: string | null;
}

export interface ListReviewTasksOptions {
  status?: string;
  limit?: number;
}

export interface ReviewTaskBulkUpdateRequest {
  taskIds: string[];
  status?: string | null;
  notes?: string | null;
  priority?: string | null;
  notificationChannel?: string | null;
  escalatedTo?: string | null;
  dueAt?: string | Date | null;
  ticketSummary?: string | null;
  ticketSystem?: string | null;
  ticketMetadata?: Record<string, unknown> | null;
}

export interface ListAgentSessionsOptions {
  agentType?: string;
  limit?: number;
  offset?: number;
}

export interface CreateAgentSessionRequest {
  agentType: string;
  context?: Record<string, unknown>;
  title?: string | null;
}

export interface GetAgentSessionOptions {
  messageLimit?: number;
}

export interface ListSessionMessagesOptions {
  limit?: number;
  offset?: number;
}

export interface SendAgentMessageRequest {
  message: string;
  stream?: boolean;
}

export interface AgentMessageAck<T = unknown> {
  kind: "ack";
  data: T;
}

export interface AgentMessageStreamHandle {
  kind: "stream";
  stream: HttpStream;
}

export type SendAgentMessageResult<T = unknown> = AgentMessageAck<T> | AgentMessageStreamHandle;

export interface ListSessionMemoryOptions {
  limit?: number;
  includeContent?: boolean;
}

interface ResolveReviewTaskPayload {
  status: string;
  notes?: string | null;
}

interface AssignReviewTaskPayload {
  assigned_to: string;
}

interface CommentPayload extends Record<string, unknown> {
  id: string;
  task_id: string;
  author: string;
  content: string;
  created_at: string;
  updated_at: string | null;
  metadata: Record<string, unknown> | null;
}

interface HistoryPayload extends Record<string, unknown> {
  id: string;
  task_id: string;
  changed_by: string;
  change_type: string;
  field_name: string | null;
  old_value: Record<string, unknown> | null;
  new_value: Record<string, unknown> | null;
  created_at: string;
  metadata: Record<string, unknown> | null;
}

interface SlaSummaryPayload extends Record<string, unknown> {
  total_pending: number;
  breached: number;
  at_risk: number;
  on_track: number;
  compliance_rate: number;
}

interface SlaStatusPayload extends Record<string, unknown> {
  task_id: string;
  sla_hours: number;
  elapsed_hours: number;
  remaining_hours: number;
  percentage_elapsed: number;
  is_breached: boolean;
  is_at_risk: boolean;
  created_at: string;
  due_at: string | null;
}

interface ReviewNotificationPayload extends Record<string, unknown> {
  id: string;
  task_id: string;
  org_id: string;
  channel: string;
  status: string;
  payload: Record<string, unknown>;
  created_at: string;
  delivered_at: string | null;
}

interface RuntimeEventPayload extends Record<string, unknown> {
  id: string;
  event_type: string;
  payload: Record<string, unknown>;
  created_at: string;
}

interface RuntimeEventSummaryPayload extends Record<string, unknown> {
  event_type: string;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
}

interface WorkflowStepPayload extends Record<string, unknown> {
  name: string;
  description: string;
  action: string;
  conditions: Record<string, unknown>;
  parameters: Record<string, unknown>;
  order: number;
}

interface WorkflowTemplatePayload extends Record<string, unknown> {
  id: string;
  name: string;
  description: string;
  trigger: string;
  conditions: Record<string, unknown>;
  steps: WorkflowStepPayload[];
  metadata: Record<string, unknown>;
}

type PolicySuggestionPayload = components["schemas"]["PolicySuggestionResponse"];
type PolicySimulationExamplePayload = components["schemas"]["PolicySimulationExample"];
type PolicySimulationResponsePayload = components["schemas"]["PolicySimulationResponse"];

export class AgentsClient {
  constructor(private readonly http: HttpClient) {}

  async getReviewQueueSummary(): Promise<ReviewQueueSummary> {
    const payload = await this.http.get<ReviewQueueSummaryPayload>(
      "/api/v1/agents/review-tasks/summary",
    );

    return {
      generatedAt: parseDate(payload.generated_at) ?? new Date(payload.generated_at),
      statusCounts: payload.status_counts.map(mapStatusAggregate),
      pending: mapPendingSummary(payload.pending),
      priorityBreakdown: payload.priority_breakdown.map(mapPrioritySummary),
    };
  }

  async listReviewTasks(options: ListReviewTasksOptions = {}): Promise<ReviewTaskRecord[]> {
    const params: Record<string, string | number> = {};
    if (options.status) params.status = options.status;
    if (options.limit !== undefined) params.limit = options.limit;

    const payload = await this.http.get<ReviewTaskPayload[]>("/api/v1/agents/review-tasks", {
      searchParams: Object.keys(params).length ? params : undefined,
    });

    return payload.map(mapReviewTask);
  }

  async listReviewTasksPage(options: ListReviewTasksPageOptions = {}): Promise<CursorPage<ReviewTaskRecord>> {
    const page: PageRequest = {
      cursor: options.cursor ?? undefined,
      limit: options.limit,
    };

    const searchParams: Record<string, string | number> = {};
    if (options.status) searchParams.status = options.status;
    if (page.limit !== undefined) searchParams.limit = page.limit;
    if (page.cursor) searchParams.cursor = page.cursor;

    const payload = await this.http.get<ReviewTaskPageResponse>("/api/v1/agents/review-tasks/page", {
      searchParams: Object.keys(searchParams).length ? searchParams : undefined,
    });

    return {
      items: payload.items.map(mapReviewTask),
      nextCursor: payload.next_cursor ?? null,
    };
  }

  async bulkUpdateReviewTasks(request: ReviewTaskBulkUpdateRequest): Promise<ReviewTaskRecord[]> {
    if (!request.taskIds || request.taskIds.length === 0) {
      return [];
    }

    const body: Record<string, unknown> = {
      task_ids: request.taskIds,
    };

    if (request.status !== undefined) body.status = request.status;
    if (request.notes !== undefined) body.notes = request.notes;
    if (request.priority !== undefined) body.priority = request.priority;
    if (request.notificationChannel !== undefined) body.notification_channel = request.notificationChannel;
    if (request.escalatedTo !== undefined) body.escalated_to = request.escalatedTo;
    if (request.ticketSummary !== undefined) body.ticket_summary = request.ticketSummary;
    if (request.ticketSystem !== undefined) body.ticket_system = request.ticketSystem;
    if (request.ticketMetadata !== undefined) body.ticket_metadata = request.ticketMetadata ?? null;

    if (request.dueAt !== undefined) {
      if (request.dueAt === null) {
        body.due_at = null;
      } else if (request.dueAt instanceof Date) {
        body.due_at = request.dueAt.toISOString();
      } else {
        body.due_at = request.dueAt;
      }
    }

    const payload = await this.http.post<ReviewTaskPayload[]>(
      "/api/v1/agents/review-tasks/bulk-update",
      { body },
    );

    return payload.map(mapReviewTask);
  }

  async resolveReviewTask(taskId: string, payload: ResolveReviewTaskPayload): Promise<ReviewTaskRecord> {
    const body = {
      status: payload.status,
      notes: payload.notes ?? null,
    };

    const response = await this.http.post<ReviewTaskPayload>(
      `/api/v1/agents/review-tasks/${taskId}/resolve`,
      { body },
    );

    return mapReviewTask(response);
  }

  async assignReviewTask(taskId: string, assignedTo: string): Promise<ReviewTaskRecord> {
    const response = await this.http.post<ReviewTaskPayload>(
      `/api/v1/agents/review-tasks/${taskId}/assign`,
      {
        body: {
          assigned_to: assignedTo,
        } satisfies AssignReviewTaskPayload,
      },
    );

    return mapReviewTask(response);
  }

  async addReviewTaskComment(
    taskId: string,
    content: string,
    metadata?: Record<string, unknown>,
  ): Promise<ReviewTaskCommentRecord> {
    const response = await this.http.post<CommentPayload>(
      `/api/v1/agents/review-tasks/${taskId}/comments`,
      {
        body: {
          content,
          metadata: metadata ?? null,
        },
      },
    );

    return mapComment(response);
  }

  async listReviewTaskComments(
    taskId: string,
    options: { limit?: number } = {},
  ): Promise<ReviewTaskCommentRecord[]> {
    const params = options.limit !== undefined ? { limit: options.limit } : undefined;
    const payload = await this.http.get<CommentPayload[]>(
      `/api/v1/agents/review-tasks/${taskId}/comments`,
      { searchParams: params },
    );

    return payload.map(mapComment);
  }

  async listReviewTaskHistory(
    taskId: string,
    options: { limit?: number } = {},
  ): Promise<ReviewTaskHistoryRecord[]> {
    const params = options.limit !== undefined ? { limit: options.limit } : undefined;
    const payload = await this.http.get<HistoryPayload[]>(
      `/api/v1/agents/review-tasks/${taskId}/history`,
      { searchParams: params },
    );

    return payload.map(mapHistory);
  }

  async getReviewTaskSlaSummary(): Promise<ReviewTaskSlaSummary> {
    const payload = await this.http.get<SlaSummaryPayload>("/api/v1/agents/review-tasks/sla/summary");
    return mapSlaSummary(payload);
  }

  async listReviewTasksSlaBreached(): Promise<ReviewTaskSlaStatus[]> {
    const payload = await this.http.get<SlaStatusPayload[]>("/api/v1/agents/review-tasks/sla/breached");
    return payload.map(mapSlaStatus);
  }

  async listReviewTasksSlaAtRisk(): Promise<ReviewTaskSlaStatus[]> {
    const payload = await this.http.get<SlaStatusPayload[]>("/api/v1/agents/review-tasks/sla/at-risk");
    return payload.map(mapSlaStatus);
  }

  async listReviewNotifications(options: { status?: string; limit?: number } = {}): Promise<ReviewNotificationRecord[]> {
    const params: Record<string, string | number> = {};
    if (options.status) params.status = options.status;
    if (options.limit !== undefined) params.limit = options.limit;

    const payload = await this.http.get<ReviewNotificationPayload[]>(
      "/api/v1/agents/review-tasks/notifications",
      { searchParams: Object.keys(params).length ? params : undefined },
    );

    return payload.map(mapNotification);
  }

  async listSessions(options: ListAgentSessionsOptions = {}): Promise<AgentSessionList> {
    const params: Record<string, string | number> = {};
    if (options.agentType) params.agent_type = options.agentType;
    if (options.limit !== undefined) params.limit = options.limit;
    if (options.offset !== undefined) params.offset = options.offset;

    const payload = await this.http.get<SessionListResponsePayload>(
      "/api/v1/agents/sessions",
      { searchParams: Object.keys(params).length ? params : undefined },
    );

    return {
      limit: payload.limit,
      offset: payload.offset,
      total: payload.total,
      sessions: payload.sessions.map(mapSession),
    };
  }

  async createSession(request: CreateAgentSessionRequest): Promise<AgentSessionRecord> {
    const body: Record<string, unknown> = {
      agent_type: request.agentType,
    };

    if (request.context !== undefined) body.context = request.context;
    if (request.title !== undefined) body.title = request.title;

    const payload = await this.http.post<SessionPayload>("/api/v1/agents/sessions", { body });
    return mapSession(payload);
  }

  async getSession(sessionId: string, options: GetAgentSessionOptions = {}): Promise<AgentSessionDetail> {
    const params = options.messageLimit !== undefined ? { message_limit: options.messageLimit } : undefined;

    const payload = await this.http.get<SessionWithMessagesPayload>(
      `/api/v1/agents/sessions/${sessionId}`,
      { searchParams: params },
    );

    return {
      session: mapSession(payload.session),
      messageCount: payload.message_count,
      messages: payload.messages.map(mapMessage),
      toolInvocations: (payload.tool_invocations ?? []).map(mapToolInvocation),
      metrics: payload.metrics ? { ...payload.metrics } : undefined,
    };
  }

  async listSessionMessages(sessionId: string, options: ListSessionMessagesOptions = {}): Promise<AgentMessageRecord[]> {
    const params: Record<string, string | number> = {};
    if (options.limit !== undefined) params.limit = options.limit;
    if (options.offset !== undefined) params.offset = options.offset;

    const payload = await this.http.get<MessagePayload[]>(
      `/api/v1/agents/sessions/${sessionId}/messages`,
      { searchParams: Object.keys(params).length ? params : undefined },
    );

    return payload.map(mapMessage);
  }

  iterateReviewTasks(options: ListReviewTasksPageOptions = {}): AsyncIterable<ReviewTaskRecord> {
    const baseOptions = { ...options };
    return iterateCursor(
      (cursor?: string | null) => this.listReviewTasksPage({ ...baseOptions, cursor: cursor ?? undefined }),
      baseOptions.cursor ?? null,
    );
  }

  async sendSessionMessage<T = unknown>(
    sessionId: string,
    request: SendAgentMessageRequest,
  ): Promise<SendAgentMessageResult<T>> {
    const body: Record<string, unknown> = { message: request.message };

    if (request.stream === true) {
      body.stream = true;
      const stream = await this.http.stream(
        `/api/v1/agents/sessions/${sessionId}/messages`,
        { method: "POST", body },
      );
      return { kind: "stream", stream };
    }

    if (request.stream !== undefined) {
      body.stream = request.stream;
    }

    const payload = await this.http.post<T>(
      `/api/v1/agents/sessions/${sessionId}/messages`,
      { body },
    );

    return { kind: "ack", data: payload };
  }

  async listSessionMemoryEntries(
    sessionId: string,
    options: ListSessionMemoryOptions = {},
  ): Promise<AgentMemoryRecord[]> {
    const params: Record<string, string | number | boolean> = {};
    if (options.limit !== undefined) params.limit = options.limit;
    if (options.includeContent !== undefined) params.include_content = options.includeContent;

    const payload = await this.http.get<MemoryEntryPayload[]>(
      `/api/v1/agents/sessions/${sessionId}/memory`,
      { searchParams: Object.keys(params).length ? params : undefined },
    );

    return payload.map(mapMemoryEntry);
  }

  async getSessionMemoryStats(sessionId: string): Promise<AgentMemoryStats> {
    const payload = await this.http.get<MemoryStatsPayload>(
      `/api/v1/agents/sessions/${sessionId}/memory/stats`,
    );

    return mapMemoryStats(payload);
  }

  async listSessionAnalytics(
    sessionId: string,
    options: { limit?: number; eventType?: string; cursor?: string; cursorId?: string } = {},
  ): Promise<RuntimeEventRecord[]> {
    const params: Record<string, string | number> = {};
    if (options.limit !== undefined) params.limit = options.limit;
    if (options.eventType) params.event_type = options.eventType;
    if (options.cursor) params.cursor = options.cursor;
    if (options.cursorId) params.cursor_id = options.cursorId;

    const payload = await this.http.get<RuntimeEventPayload[]>(
      `/api/v1/agents/sessions/${sessionId}/analytics`,
      { searchParams: Object.keys(params).length ? params : undefined },
    );

    return payload.map(mapRuntimeEvent);
  }

  async getSessionAnalyticsSummary(
    sessionId: string,
    options: { eventType?: string } = {},
  ): Promise<RuntimeEventSummaryRecord[]> {
    const params = options.eventType ? { event_type: options.eventType } : undefined;
    const payload = await this.http.get<RuntimeEventSummaryPayload[]>(
      `/api/v1/agents/sessions/${sessionId}/analytics/summary`,
      { searchParams: params },
    );

    return payload.map(mapRuntimeSummary);
  }

  async listWorkflowTemplates(options: { trigger?: string } = {}): Promise<WorkflowTemplateRecord[]> {
    const params = options.trigger ? { trigger: options.trigger } : undefined;
    const payload = await this.http.get<WorkflowTemplatePayload[]>(
      "/api/v1/agents/workflows/templates",
      { searchParams: params },
    );

    return payload.map(mapWorkflowTemplate);
  }

  async getWorkflowTemplate(templateId: string): Promise<WorkflowTemplateRecord> {
    const payload = await this.http.get<WorkflowTemplatePayload>(
      `/api/v1/agents/workflows/templates/${templateId}`,
    );
    return mapWorkflowTemplate(payload);
  }

  async evaluateWorkflows(request: { trigger: string; context: Record<string, unknown> }): Promise<WorkflowTemplateRecord[]> {
    const payload = await this.http.post<WorkflowTemplatePayload[]>(
      "/api/v1/agents/workflows/evaluate",
      {
        body: {
          trigger: request.trigger,
          context: request.context,
        },
      },
    );

    return payload.map(mapWorkflowTemplate);
  }

  async listPolicySuggestions(options: { limit?: number } = {}): Promise<PolicySuggestionRecord[]> {
    const params = options.limit !== undefined ? { limit: options.limit } : undefined;
    const payload = await this.http.get<PolicySuggestionPayload[]>(
      "/api/v1/agents/policy-suggestions",
      { searchParams: params },
    );

    return payload.map(mapPolicySuggestion);
  }

  async simulatePolicyExpression(
    request: { expression: string; toolName?: string; limit?: number },
  ): Promise<PolicySimulationResultRecord> {
    const body: Record<string, unknown> = { expression: request.expression };
    if (request.toolName !== undefined) body.tool_name = request.toolName;
    if (request.limit !== undefined) body.limit = request.limit;

    const payload = await this.http.post<PolicySimulationResponsePayload>(
      "/api/v1/agents/policy-suggestions/simulate",
      { body },
    );

    return mapPolicySimulation(payload);
  }
}

function mapStatusAggregate(entry: ReviewQueueStatusPayload): ReviewQueueStatusAggregate {
  return {
    status: entry.status,
    count: entry.count,
    unassigned: entry.unassigned,
    overdue: entry.overdue,
    oldestCreated: parseDate(entry.oldest_created),
    newestCreated: parseDate(entry.newest_created),
  };
}

function mapPendingSummary(entry: ReviewQueuePendingPayload): ReviewQueuePendingSummary {
  return {
    total: entry.total,
    unassigned: entry.unassigned,
    overdue: entry.overdue,
    nextDue: parseDate(entry.next_due),
    oldestCreated: parseDate(entry.oldest_created),
  };
}

function mapPrioritySummary(entry: ReviewQueuePriorityPayload): ReviewQueuePrioritySummary {
  return {
    priority: entry.priority,
    count: entry.count,
  };
}

function mapReviewTask(payload: ReviewTaskPayload): ReviewTaskRecord {
  return adaptReviewTask(payload, (data) => ({
    taskId: data.id,
    sessionId: data.sessionId,
    orgId: data.orgId,
    status: data.status,
    title: data.title,
    summary: data.summary,
    payload: data.payload ?? {},
    promotionTarget: data.promotionTarget !== undefined ? data.promotionTarget : null,
    priority: data.priority !== undefined ? data.priority : null,
    dueAt: coerceDate(data.dueAt, payload.due_at),
    escalatedTo: data.escalatedTo !== undefined ? data.escalatedTo : null,
    notificationChannel: data.notificationChannel !== undefined ? data.notificationChannel : null,
    ticketReference: data.ticketReference !== undefined ? data.ticketReference : null,
    createdBy: data.createdBy,
    createdAt: coerceDate(data.createdAt, payload.created_at) ?? new Date(payload.created_at),
    resolvedBy: data.resolvedBy !== undefined ? data.resolvedBy : null,
    resolvedAt: coerceDate(data.resolvedAt, payload.resolved_at),
    resolutionNotes: data.resolutionNotes !== undefined ? data.resolutionNotes : null,
  }));
}

function mapComment(payload: CommentPayload): ReviewTaskCommentRecord {
  return transformOpenApi(payload, (data) => ({
    commentId: data.id,
    taskId: data.taskId,
    author: data.author,
    content: data.content,
    createdAt: coerceDate(data.createdAt, payload.created_at) ?? new Date(payload.created_at),
    updatedAt: coerceDate(data.updatedAt, payload.updated_at),
    metadata: data.metadata ?? {},
  }), {
    snakeCaseDateKeys: ["created_at", "updated_at"],
    deep: true,
  });
}

function mapHistory(payload: HistoryPayload): ReviewTaskHistoryRecord {
  return transformOpenApi(payload, (data) => ({
    historyId: data.id,
    taskId: data.taskId,
    changedBy: data.changedBy,
    changeType: data.changeType,
    fieldName: data.fieldName,
    oldValue: data.oldValue,
    newValue: data.newValue,
    createdAt: coerceDate(data.createdAt, payload.created_at) ?? new Date(payload.created_at),
    metadata: data.metadata,
  }), {
    snakeCaseDateKeys: ["created_at"],
    deep: true,
  });
}

function mapNotification(payload: ReviewNotificationPayload): ReviewNotificationRecord {
  return adaptReviewNotification(payload, (data) => ({
    notificationId: data.id,
    taskId: data.taskId,
    orgId: data.orgId,
    channel: data.channel,
    status: data.status,
    payload: data.payload ?? {},
    createdAt: coerceDate(data.createdAt, payload.created_at) ?? new Date(payload.created_at),
    deliveredAt: coerceDate(data.deliveredAt, payload.delivered_at),
  }));
}

function mapRuntimeEvent(payload: RuntimeEventPayload): RuntimeEventRecord {
  return adaptRuntimeEvent(payload, (data) => ({
    eventId: data.id,
    eventType: data.eventType,
    payload: data.payload ?? {},
    createdAt: coerceDate(data.createdAt, payload.created_at) ?? new Date(payload.created_at),
  }));
}

function mapRuntimeSummary(payload: RuntimeEventSummaryPayload): RuntimeEventSummaryRecord {
  return adaptRuntimeSummary(payload, (data) => ({
    eventType: data.eventType,
    eventCount: data.eventCount,
    firstSeen: coerceDate(data.firstSeen, payload.first_seen),
    lastSeen: coerceDate(data.lastSeen, payload.last_seen),
  }));
}

function mapSlaSummary(payload: SlaSummaryPayload): ReviewTaskSlaSummary {
  return {
    totalPending: payload.total_pending,
    breached: payload.breached,
    atRisk: payload.at_risk,
    onTrack: payload.on_track,
    complianceRate: payload.compliance_rate,
  };
}

function mapSlaStatus(payload: SlaStatusPayload): ReviewTaskSlaStatus {
  return transformOpenApi(payload, (data) => ({
    taskId: data.taskId,
    slaHours: data.slaHours,
    elapsedHours: data.elapsedHours,
    remainingHours: data.remainingHours,
    percentageElapsed: data.percentageElapsed,
    isBreached: data.isBreached,
    isAtRisk: data.isAtRisk,
    createdAt: coerceDate(data.createdAt, payload.created_at) ?? new Date(payload.created_at),
    dueAt: coerceDate(data.dueAt, payload.due_at),
  }), {
    snakeCaseDateKeys: ["created_at", "due_at"],
  });
}

function mapWorkflowTemplate(payload: WorkflowTemplatePayload): WorkflowTemplateRecord {
  return {
    templateId: payload.id,
    name: payload.name,
    description: payload.description,
    trigger: payload.trigger,
    conditions: payload.conditions ?? {},
    steps: payload.steps?.map(mapWorkflowStep) ?? [],
    metadata: payload.metadata ?? {},
  };
}

function mapWorkflowStep(payload: WorkflowStepPayload): WorkflowTemplateStepRecord {
  return {
    name: payload.name,
    description: payload.description,
    action: payload.action,
    conditions: payload.conditions ?? {},
    parameters: payload.parameters ?? {},
    order: payload.order,
  };
}

function mapSession(payload: SessionPayload): AgentSessionRecord {
  return adaptSession(payload, (data) => ({
    sessionId: data.sessionId,
    orgId: data.orgId,
    agentType: data.agentType,
    status: data.status,
    title: data.title,
    createdBy: data.createdBy,
    createdAt: coerceDate(data.createdAt, payload.created_at) ?? new Date(payload.created_at),
    context: data.context ?? {},
  }));
}

function mapMessage(payload: MessagePayload): AgentMessageRecord {
  return adaptMessage(payload, (data) => ({
    messageId: data.messageId,
    role: data.role,
    content: data.content,
    metadata: data.metadata ?? {},
    createdAt: coerceDate(data.timestamp, payload.timestamp) ?? new Date(payload.timestamp),
  }));
}

function mapToolInvocation(payload: ToolInvocationPayload): ToolInvocationRecord {
  const sessionId = typeof payload.session_id === "string" ? payload.session_id : undefined;
  const toolVersion = typeof payload.tool_version === "string" ? payload.tool_version : undefined;
  const errorCode = payload.error_code ?? null;
  const inputData = payload.input_data ?? undefined;
  const outputData = payload.output_data ?? undefined;
  const celPolicyKey = payload.cel_policy_key ?? null;
  const celExpression = payload.cel_expression ?? null;
  const celResult = payload.cel_result ?? null;
  const celContext = payload.cel_context ?? null;

  return adaptToolInvocation(payload, (data) => ({
    invocationId: data.id,
    sessionId,
    toolName: data.toolName,
    toolVersion,
    status: data.status,
    startedAt: coerceDate(data.startedAt, payload.started_at) ?? new Date(payload.started_at),
    completedAt: coerceDate(data.completedAt, payload.completed_at),
    errorMessage: data.errorMessage ?? payload.error_message ?? null,
    errorCode,
    inputData,
    outputData,
    celPolicyKey,
    celExpression,
    celResult,
    celContext,
  }));
}

function mapMemoryEntry(payload: MemoryEntryPayload): AgentMemoryRecord {
  return adaptMemoryEntry(payload, (data) => ({
    entryId: data.id,
    summary: data.summary,
    role: data.role,
    decayScore: data.decayScore,
    tokenCount: data.tokenCount,
    createdAt: coerceDate(data.createdAt, payload.created_at) ?? new Date(payload.created_at),
    lastAccessedAt: coerceDate(data.lastAccessedAt, payload.last_accessed_at) ?? new Date(payload.last_accessed_at),
    scopes: Array.isArray(data.scopes)
      ? data.scopes.map((item) => ({ ...(item as Record<string, unknown>) }))
      : [],
    scopeLabels: Array.isArray(data.scopeLabels) ? [...data.scopeLabels] : [],
    metadata: data.metadata ?? {},
    content: data.content ?? null,
    annSelected: data.annSelected ?? null,
    lexicalSimilarity: data.lexicalSimilarity ?? null,
    embeddingSimilarity: data.embeddingSimilarity ?? null,
    combinedSimilarity: data.combinedSimilarity ?? null,
  }));
}

function mapMemoryHighlight(payload: MemoryHighlightPayload): AgentMemoryHighlight {
  return adaptMemoryHighlight(payload, (data) => ({
    entryId: data.id,
    summary: data.summary,
    role: data.role,
    decayScore: data.decayScore,
    lastAccessedAt: coerceDate(data.lastAccessedAt, payload.last_accessed_at) ?? new Date(payload.last_accessed_at),
    scopeLabels: Array.isArray(data.scopeLabels) ? [...data.scopeLabels] : [],
  }));
}

function mapMemoryStats(payload: MemoryStatsPayload): AgentMemoryStats {
  return {
    totalEntries: payload.total_entries,
    recentEntries: payload.recent_entries,
    presentedEntries: payload.presented_entries,
    averageDecay: payload.average_decay,
    tokenTotal: payload.token_total,
    roleDistribution: payload.role_distribution ?? {},
    scopeDistribution: payload.scope_distribution ?? {},
    topMemories: payload.top_memories?.map(mapMemoryHighlight) ?? [],
  };
}

function mapPolicySuggestion(payload: PolicySuggestionPayload): PolicySuggestionRecord {
  return adaptPolicySuggestion(payload, (data) => ({
    suggestionId: data.id,
    toolName: data.toolName,
    celExpression: data.celExpression,
    supportCount: data.supportCount,
    rejectCount: data.rejectCount,
    confidence: data.confidence,
    metadata: data.metadata ?? {},
    lastSeen: coerceDate(data.lastSeen, payload.last_seen) ?? new Date(payload.last_seen),
  }));
}

function mapPolicySimulation(payload: PolicySimulationResponsePayload): PolicySimulationResultRecord {
  return adaptPolicySimulation(payload, (data) => ({
    evaluatedCount: data.evaluatedCount,
    matchedCount: data.matchedCount,
    mismatchedCount: data.mismatchedCount,
    errorCount: data.errorCount,
    examples: payload.examples.map(mapPolicySimulationExample),
  }));
}

function coerceDate(value: unknown, fallback?: string | null): Date | null {
  const primary = parseDate(value as string | Date | null);
  if (primary) return primary;
  if (!fallback) return null;
  return parseDate(fallback) ?? new Date(fallback);
}

function mapPolicySimulationExample(payload: PolicySimulationExamplePayload): PolicySimulationExampleRecord {
  return adaptPolicySimulationExample(payload, (data) => ({
    invocationId: data.invocationId,
    sessionId: data.sessionId,
    toolName: data.toolName,
    matched: data.matched,
    status: data.status,
    startedAt: coerceDate(data.startedAt, payload.started_at),
    completedAt: coerceDate(data.completedAt, payload.completed_at),
    inputData: data.inputData ?? {},
    outputData: data.outputData ?? null,
    celContext: data.celContext ?? {},
    error: data.error,
    latencyMs: data.latencyMs ?? null,
  }));
}

export default AgentsClient;
