import HttpClient from "../httpClient";
import {
  ReviewQueuePendingSummary,
  ReviewQueuePrioritySummary,
  ReviewQueueStatusAggregate,
  ReviewQueueSummary,
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

function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export default AgentsClient;
