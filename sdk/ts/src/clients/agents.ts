import HttpClient from "../httpClient";
import { CursorPage, PageRequest } from "../pagination";
import {
  ReviewQueuePendingSummary,
  ReviewQueuePrioritySummary,
  ReviewQueueStatusAggregate,
  ReviewQueueSummary,
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

function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export default AgentsClient;
