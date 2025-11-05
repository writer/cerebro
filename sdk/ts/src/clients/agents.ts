import HttpClient, { HttpStream } from "../httpClient.js";
import { CursorPage, PageRequest, iterateCursor } from "../pagination.js";
import { deserialize, parseDate } from "../serialization.js";
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

interface ReviewQueueStatusPayload {
  status: string;
  count: number;
  unassigned: number;
  overdue: number;
  oldest_created: string | null;
  newest_created: string | null;
}

interface ReviewQueuePendingPayload {
  total: number;
  unassigned: number;
  overdue: number;
  next_due: string | null;
  oldest_created: string | null;
}

interface ReviewQueuePriorityPayload {
  priority: string | null;
  count: number;
}

interface ReviewQueueSummaryPayload {
  generated_at: string;
  status_counts: ReviewQueueStatusPayload[];
  pending: ReviewQueuePendingPayload;
  priority_breakdown: ReviewQueuePriorityPayload[];
}

interface ReviewTaskPayload {
  id: string;
  session_id: string;
  org_id: string;
  status: string;
  title: string;
  summary: string | null;
  payload: Record<string, unknown>;
  promotion_target: string | null;
  priority: string | null;
  due_at: string | null;
  escalated_to: string | null;
  notification_channel: string | null;
  ticket_reference: string | null;
  created_by: string;
  created_at: string;
  resolved_by: string | null;
  resolved_at: string | null;
  resolution_notes: string | null;
}

interface ReviewTaskPageResponse {
  items: ReviewTaskPayload[];
  next_cursor: string | null;
}

interface SessionPayload {
  session_id: string;
  org_id: string;
  agent_type: string;
  status: string;
  title: string | null;
  created_by: string;
  created_at: string;
  context: Record<string, unknown>;
}

interface SessionListResponsePayload {
  limit: number;
  offset: number;
  total: number;
  sessions: SessionPayload[];
}

interface MessagePayload {
  message_id: string;
  role: string;
  content: string;
  metadata?: Record<string, unknown> | null;
  timestamp: string;
}

interface ToolInvocationPayload {
  id: string;
  session_id?: string;
  tool_name: string;
  tool_version?: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
  error_code?: string | null;
  input_data?: Record<string, unknown> | null;
  output_data?: Record<string, unknown> | null;
  cel_policy_key?: string | null;
  cel_expression?: string | null;
  cel_result?: boolean | null;
  cel_context?: Record<string, unknown> | null;
}

interface SessionWithMessagesPayload {
  session: SessionPayload;
  message_count: number;
  messages: MessagePayload[];
  metrics?: Record<string, unknown>;
  tool_invocations?: ToolInvocationPayload[];
}

interface MemoryEntryPayload {
  id: string;
  summary: string | null;
  role: string | null;
  decay_score: number;
  token_count: number;
  created_at: string;
  last_accessed_at: string;
  scopes: Record<string, unknown>[];
  scope_labels: string[];
  metadata: Record<string, unknown>;
  content?: string | null;
  ann_selected?: boolean | null;
  lexical_similarity?: number | null;
  embedding_similarity?: number | null;
  combined_similarity?: number | null;
}

interface MemoryHighlightPayload {
  id: string;
  summary: string | null;
  role: string | null;
  decay_score: number;
  last_accessed_at: string;
  scope_labels: string[];
}

interface MemoryStatsPayload {
  total_entries: number;
  recent_entries: number;
  presented_entries: number;
  average_decay: number;
  token_total: number;
  role_distribution: Record<string, number>;
  scope_distribution: Record<string, number>;
  top_memories: MemoryHighlightPayload[];
}

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

interface CommentPayload {
  id: string;
  task_id: string;
  author: string;
  content: string;
  created_at: string;
  updated_at: string | null;
  metadata: Record<string, unknown> | null;
}

interface HistoryPayload {
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

interface SlaSummaryPayload {
  total_pending: number;
  breached: number;
  at_risk: number;
  on_track: number;
  compliance_rate: number;
}

interface SlaStatusPayload {
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

interface ReviewNotificationPayload {
  id: string;
  task_id: string;
  org_id: string;
  channel: string;
  status: string;
  payload: Record<string, unknown>;
  created_at: string;
  delivered_at: string | null;
}

interface RuntimeEventPayload {
  id: string;
  event_type: string;
  payload: Record<string, unknown>;
  created_at: string;
}

interface RuntimeEventSummaryPayload {
  event_type: string;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
}

interface WorkflowStepPayload {
  name: string;
  description: string;
  action: string;
  conditions: Record<string, unknown>;
  parameters: Record<string, unknown>;
  order: number;
}

interface WorkflowTemplatePayload {
  id: string;
  name: string;
  description: string;
  trigger: string;
  conditions: Record<string, unknown>;
  steps: WorkflowStepPayload[];
  metadata: Record<string, unknown>;
}

interface PolicySuggestionPayload {
  id: string;
  tool_name: string;
  cel_expression: string;
  support_count: number;
  reject_count: number;
  confidence: number;
  metadata: Record<string, unknown>;
  last_seen: string;
}

interface PolicySimulationExamplePayload {
  invocation_id: string;
  session_id: string;
  tool_name: string;
  matched: boolean;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  input_data: Record<string, unknown>;
  output_data: Record<string, unknown> | null;
  cel_context: Record<string, unknown>;
  error: string | null;
  latency_ms: number | null;
}

interface PolicySimulationResponsePayload {
  evaluated_count: number;
  matched_count: number;
  mismatched_count: number;
  error_count: number;
  examples: PolicySimulationExamplePayload[];
}

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
      nextCursor: payload.next_cursor,
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
  const normalized = deserialize(payload, { dateKeys: ["due_at", "created_at", "resolved_at"] }) as ReviewTaskPayload & {
    due_at: Date | null;
    created_at: Date | null;
    resolved_at: Date | null;
  };
  return {
    taskId: payload.id,
    sessionId: payload.session_id,
    orgId: payload.org_id,
    status: payload.status,
    title: payload.title,
    summary: payload.summary,
    payload: payload.payload ?? {},
    promotionTarget: payload.promotion_target,
    priority: payload.priority,
    dueAt: normalized.due_at ?? parseDate(payload.due_at),
    escalatedTo: payload.escalated_to,
    notificationChannel: payload.notification_channel,
    ticketReference: payload.ticket_reference,
    createdBy: payload.created_by,
    createdAt: normalized.created_at ?? parseDate(payload.created_at) ?? new Date(payload.created_at),
    resolvedBy: payload.resolved_by,
    resolvedAt: normalized.resolved_at ?? parseDate(payload.resolved_at),
    resolutionNotes: payload.resolution_notes,
  };
}

function mapComment(payload: CommentPayload): ReviewTaskCommentRecord {
  const normalized = deserialize(payload, { dateKeys: ["created_at", "updated_at"] }) as CommentPayload & {
    created_at: Date | null;
    updated_at: Date | null;
  };
  return {
    commentId: payload.id,
    taskId: payload.task_id,
    author: payload.author,
    content: payload.content,
    createdAt: normalized.created_at ?? parseDate(payload.created_at) ?? new Date(payload.created_at),
    updatedAt: normalized.updated_at ?? parseDate(payload.updated_at),
    metadata: payload.metadata ?? {},
  };
}

function mapHistory(payload: HistoryPayload): ReviewTaskHistoryRecord {
  const normalized = deserialize(payload, { dateKeys: ["created_at"] }) as HistoryPayload & {
    created_at: Date | null;
  };
  return {
    historyId: payload.id,
    taskId: payload.task_id,
    changedBy: payload.changed_by,
    changeType: payload.change_type,
    fieldName: payload.field_name,
    oldValue: payload.old_value,
    newValue: payload.new_value,
    createdAt: normalized.created_at ?? parseDate(payload.created_at) ?? new Date(payload.created_at),
    metadata: payload.metadata,
  };
}

function mapNotification(payload: ReviewNotificationPayload): ReviewNotificationRecord {
  const normalized = deserialize(payload, { dateKeys: ["created_at", "delivered_at"] }) as ReviewNotificationPayload & {
    created_at: Date | null;
    delivered_at: Date | null;
  };
  return {
    notificationId: payload.id,
    taskId: payload.task_id,
    orgId: payload.org_id,
    channel: payload.channel,
    status: payload.status,
    payload: payload.payload ?? {},
    createdAt: normalized.created_at ?? parseDate(payload.created_at) ?? new Date(payload.created_at),
    deliveredAt: normalized.delivered_at ?? parseDate(payload.delivered_at),
  };
}

function mapRuntimeEvent(payload: RuntimeEventPayload): RuntimeEventRecord {
  const normalized = deserialize(payload, { dateKeys: ["created_at"] }) as RuntimeEventPayload & {
    created_at: Date | null;
  };
  return {
    eventId: payload.id,
    eventType: payload.event_type,
    payload: payload.payload ?? {},
    createdAt: normalized.created_at ?? parseDate(payload.created_at) ?? new Date(payload.created_at),
  };
}

function mapRuntimeSummary(payload: RuntimeEventSummaryPayload): RuntimeEventSummaryRecord {
  const normalized = deserialize(payload, { dateKeys: ["first_seen", "last_seen"] }) as RuntimeEventSummaryPayload & {
    first_seen: Date | null;
    last_seen: Date | null;
  };
  return {
    eventType: payload.event_type,
    eventCount: payload.event_count,
    firstSeen: normalized.first_seen ?? parseDate(payload.first_seen),
    lastSeen: normalized.last_seen ?? parseDate(payload.last_seen),
  };
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
  const normalized = deserialize(payload, { dateKeys: ["created_at", "due_at"] }) as SlaStatusPayload & {
    created_at: Date | null;
    due_at: Date | null;
  };
  return {
    taskId: payload.task_id,
    slaHours: payload.sla_hours,
    elapsedHours: payload.elapsed_hours,
    remainingHours: payload.remaining_hours,
    percentageElapsed: payload.percentage_elapsed,
    isBreached: payload.is_breached,
    isAtRisk: payload.is_at_risk,
    createdAt: normalized.created_at ?? parseDate(payload.created_at) ?? new Date(payload.created_at),
    dueAt: normalized.due_at ?? parseDate(payload.due_at),
  };
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
  const normalized = deserialize(payload, { dateKeys: ["created_at"] }) as SessionPayload & {
    created_at: Date | null;
  };
  return {
    sessionId: payload.session_id,
    orgId: payload.org_id,
    agentType: payload.agent_type,
    status: payload.status,
    title: payload.title,
    createdBy: payload.created_by,
    createdAt: normalized.created_at ?? parseDate(payload.created_at) ?? new Date(payload.created_at),
    context: payload.context ?? {},
  };
}

function mapMessage(payload: MessagePayload): AgentMessageRecord {
  const normalized = deserialize(payload, { dateKeys: ["timestamp"] }) as MessagePayload & {
    timestamp: Date | null;
  };
  return {
    messageId: payload.message_id,
    role: payload.role,
    content: payload.content,
    metadata: payload.metadata ?? {},
    createdAt: normalized.timestamp ?? parseDate(payload.timestamp) ?? new Date(payload.timestamp),
  };
}

function mapToolInvocation(payload: ToolInvocationPayload): ToolInvocationRecord {
  const normalized = deserialize(payload, { dateKeys: ["started_at", "completed_at"] }) as ToolInvocationPayload & {
    started_at: Date | null;
    completed_at: Date | null;
  };
  return {
    invocationId: payload.id,
    sessionId: payload.session_id,
    toolName: payload.tool_name,
    toolVersion: payload.tool_version,
    status: payload.status,
    startedAt: normalized.started_at ?? parseDate(payload.started_at) ?? new Date(payload.started_at),
    completedAt: normalized.completed_at ?? parseDate(payload.completed_at),
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

function mapMemoryEntry(payload: MemoryEntryPayload): AgentMemoryRecord {
  const normalized = deserialize(payload, { dateKeys: ["created_at", "last_accessed_at"] }) as MemoryEntryPayload & {
    created_at: Date | null;
    last_accessed_at: Date | null;
  };
  return {
    entryId: payload.id,
    summary: payload.summary,
    role: payload.role,
    decayScore: payload.decay_score,
    tokenCount: payload.token_count,
    createdAt: normalized.created_at ?? parseDate(payload.created_at) ?? new Date(payload.created_at),
    lastAccessedAt: normalized.last_accessed_at ?? parseDate(payload.last_accessed_at) ?? new Date(payload.last_accessed_at),
    scopes: payload.scopes ?? [],
    scopeLabels: payload.scope_labels ?? [],
    metadata: payload.metadata ?? {},
    content: payload.content ?? null,
    annSelected: payload.ann_selected ?? null,
    lexicalSimilarity: payload.lexical_similarity ?? null,
    embeddingSimilarity: payload.embedding_similarity ?? null,
    combinedSimilarity: payload.combined_similarity ?? null,
  };
}

function mapMemoryHighlight(payload: MemoryHighlightPayload): AgentMemoryHighlight {
  const normalized = deserialize(payload, { dateKeys: ["last_accessed_at"] }) as MemoryHighlightPayload & {
    last_accessed_at: Date | null;
  };
  return {
    entryId: payload.id,
    summary: payload.summary,
    role: payload.role,
    decayScore: payload.decay_score,
    lastAccessedAt: normalized.last_accessed_at ?? parseDate(payload.last_accessed_at) ?? new Date(payload.last_accessed_at),
    scopeLabels: payload.scope_labels ?? [],
  };
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
  return {
    suggestionId: payload.id,
    toolName: payload.tool_name,
    celExpression: payload.cel_expression,
    supportCount: payload.support_count,
    rejectCount: payload.reject_count,
    confidence: payload.confidence,
    metadata: payload.metadata ?? {},
    lastSeen: parseDate(payload.last_seen) ?? new Date(payload.last_seen),
  };
}

function mapPolicySimulation(payload: PolicySimulationResponsePayload): PolicySimulationResultRecord {
  return {
    evaluatedCount: payload.evaluated_count,
    matchedCount: payload.matched_count,
    mismatchedCount: payload.mismatched_count,
    errorCount: payload.error_count,
    examples: payload.examples.map(mapPolicySimulationExample),
  };
}

function mapPolicySimulationExample(payload: PolicySimulationExamplePayload): PolicySimulationExampleRecord {
  return {
    invocationId: payload.invocation_id,
    sessionId: payload.session_id,
    toolName: payload.tool_name,
    matched: payload.matched,
    status: payload.status,
    startedAt: parseDate(payload.started_at),
    completedAt: parseDate(payload.completed_at),
    inputData: payload.input_data ?? {},
    outputData: payload.output_data ?? null,
    celContext: payload.cel_context ?? {},
    error: payload.error,
    latencyMs: payload.latency_ms ?? null,
  };
}

export default AgentsClient;
