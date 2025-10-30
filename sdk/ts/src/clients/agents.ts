import HttpClient from "../httpClient";
import { CursorPage, PageRequest } from "../pagination";
import {
  ReviewQueuePendingSummary,
  ReviewQueuePrioritySummary,
  ReviewQueueStatusAggregate,
  ReviewQueueSummary,
  ReviewTaskCommentRecord,
  ReviewTaskHistoryRecord,
  ReviewTaskSlaStatus,
  ReviewTaskSlaSummary,
  ReviewNotificationRecord,
  RuntimeEventRecord,
  RuntimeEventSummaryRecord,
  WorkflowTemplateRecord,
  WorkflowTemplateStepRecord,
  PolicySuggestionRecord,
  PolicySimulationResultRecord,
  PolicySimulationExampleRecord,
  ReviewTaskRecord,
} from "../types";

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

export interface ListReviewTasksPageOptions {
  status?: string;
  limit?: number;
  cursor?: string | null;
}

export interface ListReviewTasksOptions {
  status?: string;
  limit?: number;
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
    dueAt: parseDate(payload.due_at),
    escalatedTo: payload.escalated_to,
    notificationChannel: payload.notification_channel,
    ticketReference: payload.ticket_reference,
    createdBy: payload.created_by,
    createdAt: parseDate(payload.created_at) ?? new Date(payload.created_at),
    resolvedBy: payload.resolved_by,
    resolvedAt: parseDate(payload.resolved_at),
    resolutionNotes: payload.resolution_notes,
  };
}

function mapComment(payload: CommentPayload): ReviewTaskCommentRecord {
  return {
    commentId: payload.id,
    taskId: payload.task_id,
    author: payload.author,
    content: payload.content,
    createdAt: parseDate(payload.created_at) ?? new Date(payload.created_at),
    updatedAt: parseDate(payload.updated_at),
    metadata: payload.metadata ?? {},
  };
}

function mapHistory(payload: HistoryPayload): ReviewTaskHistoryRecord {
  return {
    historyId: payload.id,
    taskId: payload.task_id,
    changedBy: payload.changed_by,
    changeType: payload.change_type,
    fieldName: payload.field_name,
    oldValue: payload.old_value,
    newValue: payload.new_value,
    createdAt: parseDate(payload.created_at) ?? new Date(payload.created_at),
    metadata: payload.metadata,
  };
}

function mapNotification(payload: ReviewNotificationPayload): ReviewNotificationRecord {
  return {
    notificationId: payload.id,
    taskId: payload.task_id,
    orgId: payload.org_id,
    channel: payload.channel,
    status: payload.status,
    payload: payload.payload ?? {},
    createdAt: parseDate(payload.created_at) ?? new Date(payload.created_at),
    deliveredAt: parseDate(payload.delivered_at),
  };
}

function mapRuntimeEvent(payload: RuntimeEventPayload): RuntimeEventRecord {
  return {
    eventId: payload.id,
    eventType: payload.event_type,
    payload: payload.payload ?? {},
    createdAt: parseDate(payload.created_at) ?? new Date(payload.created_at),
  };
}

function mapRuntimeSummary(payload: RuntimeEventSummaryPayload): RuntimeEventSummaryRecord {
  return {
    eventType: payload.event_type,
    eventCount: payload.event_count,
    firstSeen: parseDate(payload.first_seen),
    lastSeen: parseDate(payload.last_seen),
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
  return {
    taskId: payload.task_id,
    slaHours: payload.sla_hours,
    elapsedHours: payload.elapsed_hours,
    remainingHours: payload.remaining_hours,
    percentageElapsed: payload.percentage_elapsed,
    isBreached: payload.is_breached,
    isAtRisk: payload.is_at_risk,
    createdAt: parseDate(payload.created_at) ?? new Date(payload.created_at),
    dueAt: parseDate(payload.due_at),
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

function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export default AgentsClient;
