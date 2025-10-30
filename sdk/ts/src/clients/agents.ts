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

function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export default AgentsClient;
