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

export interface TokenResponse {
  accessToken: string;
  refreshToken?: string;
  tokenType: string;
  accessTokenExpiresIn: number;
  refreshTokenExpiresIn?: number;
  csrfToken: string;
}

export interface UserProfile {
  userId: string;
  username: string;
  email: string | null;
  isAdmin: boolean;
  orgId: string | null;
  scopes: string[];
}

export interface OrganizationSummary {
  orgId: string;
  name: string;
  createdAt: Date;
}

export interface FindingRecord {
  findingId: string;
  orgId: string;
  accountId: string;
  provider: string;
  ruleId: string;
  ruleVersion: number;
  resourceId: string | null;
  principalId: string | null;
  firstSeen: Date;
  lastSeen: Date;
  status: string;
  severity: string;
  fingerprint: string;
  title: string;
  summary: string | null;
  evidence: Record<string, unknown> | null;
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

export interface ReviewTaskRecord {
  taskId: string;
  sessionId: string;
  orgId: string;
  status: string;
  title: string;
  summary: string | null;
  payload: Record<string, unknown>;
  promotionTarget: string | null;
  priority: string | null;
  dueAt: Date | null;
  escalatedTo: string | null;
  notificationChannel: string | null;
  ticketReference: string | null;
  createdBy: string;
  createdAt: Date;
  resolvedBy: string | null;
  resolvedAt: Date | null;
  resolutionNotes: string | null;
}

export interface ReviewTaskCommentRecord {
  commentId: string;
  taskId: string;
  author: string;
  content: string;
  createdAt: Date;
  updatedAt: Date | null;
  metadata: Record<string, unknown>;
}

export interface ReviewTaskHistoryRecord {
  historyId: string;
  taskId: string;
  changedBy: string;
  changeType: string;
  fieldName: string | null;
  oldValue: Record<string, unknown> | null;
  newValue: Record<string, unknown> | null;
  createdAt: Date;
  metadata: Record<string, unknown> | null;
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
