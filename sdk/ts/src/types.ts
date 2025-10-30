export interface RuntimeEventAggregate {
  count: number;
  lastSeen: Date | null;
}

export interface RuntimeMetadataSnapshot {
  payload: Record<string, unknown>;
  capturedAt: Date;
}

export interface RuntimeHealthRecord {
  runtime: string;
  windowStart: Date;
  windowEnd: Date;
  events: Record<string, RuntimeEventAggregate>;
  warnings: Record<string, RuntimeEventAggregate>;
  latestMetadata: RuntimeMetadataSnapshot | null;
}

export interface RuntimeHealthSummary {
  windowHours: number;
  generatedAt: Date;
  runtimes: RuntimeHealthRecord[];
}

export interface ReviewQueueStatusAggregate {
  status: string;
  count: number;
  unassigned: number;
  overdue: number;
  oldestCreated: Date | null;
  newestCreated: Date | null;
}

export interface ReviewQueuePendingSummary {
  total: number;
  unassigned: number;
  overdue: number;
  nextDue: Date | null;
  oldestCreated: Date | null;
}

export interface ReviewQueuePrioritySummary {
  priority: string | null;
  count: number;
}

export interface ReviewQueueSummary {
  generatedAt: Date;
  statusCounts: ReviewQueueStatusAggregate[];
  pending: ReviewQueuePendingSummary;
  priorityBreakdown: ReviewQueuePrioritySummary[];
}

export interface IntegrationScopeBreakdown {
  total: number;
  healthy: number;
  warning: number;
  critical: number;
}

export interface IntegrationAccountSummary {
  total: number;
}

export interface IntegrationCoverageRecord {
  integration: string;
  providers: string[];
  status: string;
  scopes: IntegrationScopeBreakdown;
  accounts: IntegrationAccountSummary;
  coverageRatio: number | null;
  lastSuccess: Date | null;
  evaluatedAt: Date;
}

export type IntegrationCoverageSummary = IntegrationCoverageRecord;
