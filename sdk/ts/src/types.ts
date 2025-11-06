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

export type EvidenceEntityType =
  | "identity"
  | "asset"
  | "configuration"
  | "activity"
  | "document"
  | "vulnerability"
  | "access"
  | "change"
  | "process"
  | "vendor"
  | "customer";

export interface EvidenceMetadataRecord {
  id: string;
  category: string;
  contentType: string;
  collectorId: string;
  collectorType: string;
  collectionMethod: string;
  sourceSystem?: string | null;
  contentSize: number;
  contentHash?: string | null;
  createdAt: Date;
  collectedAt?: Date | null;
  verifiedAt?: Date | null;
  sealedAt?: Date | null;
  status: string;
  retentionClass: string;
  expiresAt?: Date | null;
  cryptoProof?: Record<string, unknown> | null;
  chainOfCustody: Array<Record<string, unknown>>;
  piiDetected: boolean;
  sensitivityLevel: string;
  encryptionRequired: boolean;
  tags: Record<string, string>;
  relatedEvidenceIds: string[];
  parentBundleId?: string | null;
}

export interface VendorMetadataRecord extends EvidenceMetadataRecord {
  vendorId: string;
  vendorName: string;
  riskLevel: string;
  inherentRiskScore: number;
  residualRiskScore: number;
  businessCriticality: string;
  vendorCategory?: string | null;
  dataTypesProcessed: string[];
  certifications: string[];
  complianceFrameworks: string[];
  lastAssessmentDate?: Date | null;
  nextReviewDue?: Date | null;
  contractEndDate?: Date | null;
  lifecycleStage: string;
  relationshipOwner?: string | null;
  serviceRegions: string[];
  primaryContacts: string[];
  accessMonitoringEnabled: boolean;
  securityAlertsConfigured: boolean;
  incidentCountLastYear: number;
}

export interface VendorRiskSummary {
  level: string;
  inherentScore: number;
  residualScore: number;
  incidentCountLastYear: number;
  monitoring: {
    accessMonitoringEnabled: boolean;
    securityAlertsConfigured: boolean;
  };
}

export interface VendorComplianceSummary {
  certifications: string[];
  frameworks: string[];
  dataProcessingAgreements: string[];
  securityQuestionnaireCompleted: boolean;
  vulnerabilityDisclosurePolicy: boolean;
  penetrationTestResultsPresent: boolean;
}

export interface VendorRelationshipSummary {
  businessCriticality: string;
  annualSpend: number | null;
  contract: {
    startDate: Date;
    endDate: Date | null;
    nextReviewDue: Date;
  };
}

export interface VendorIntegrationSummary {
  integrationType: string;
  networkAccess: string[];
  authenticationMethods: string[];
}

export interface VendorMetadataEnvelope {
  evidence: VendorMetadataRecord;
  riskSummary: VendorRiskSummary;
  complianceSummary: VendorComplianceSummary;
  relationship: VendorRelationshipSummary;
  integration: VendorIntegrationSummary;
  lifecycleStage: string;
}

export interface CustomerMetadataRecord extends EvidenceMetadataRecord {
  customerId: string;
  customerName: string;
  segment: string;
  industry?: string | null;
  region?: string | null;
  lifecycleStage: string;
  healthScore: number;
  churnRiskScore: number;
  accountManager?: string | null;
  annualRecurringRevenue?: number | null;
  seatsCommitted?: number | null;
  adoptionMetrics: Record<string, number>;
  lastEngagementAt?: Date | null;
  nextQbrAt?: Date | null;
  supportTicketsOpen: number;
  advocacyLevel: string;
  successPrograms: string[];
}

export interface CustomerMetadataEnvelope {
  evidence: CustomerMetadataRecord;
  health: {
    score: number;
    band: string;
    churnRisk: number;
    lifecycleStage: string;
  };
  adoption: {
    productUsageScore: number;
    metrics: Record<string, number>;
    seatsCommitted: number;
  };
  engagement: {
    lastEngagementAt: Date;
    nextQbrAt: Date | null;
    openSupportTickets: number;
  };
  successPrograms: string[];
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

export interface ReviewTaskSlaSummary {
  totalPending: number;
  breached: number;
  atRisk: number;
  onTrack: number;
  complianceRate: number;
}

export interface ReviewTaskSlaStatus {
  taskId: string;
  slaHours: number;
  elapsedHours: number;
  remainingHours: number;
  percentageElapsed: number;
  isBreached: boolean;
  isAtRisk: boolean;
  createdAt: Date;
  dueAt: Date | null;
}

export interface SecuritySoftwareRecord {
  vendor: string;
  product: string;
  installed: boolean;
  running: boolean;
  installPath?: string;
  notes?: Record<string, string | undefined | null>;
}

export interface GenericSecurityMetadata {
  healthOk: boolean | null;
  healthIssues: string[];
  rawNotes: Record<string, string>;
}

export interface SentinelOneMetadata extends GenericSecurityMetadata {
  connectivityOk: boolean | null;
  antiTamperEnabled: boolean | null;
  agentEnabled: boolean | null;
  serviceActive: boolean | null;
  tokenPresent: boolean | null;
  tokenStale: boolean | null;
  managementProfilePresent: boolean | null;
  packageVersionMismatch: boolean | null;
  scanRecent: boolean | null;
  managementUrlHost: string | null;
  siteName: string | null;
  policyName: string | null;
  packageVersion: string | null;
  registrationTokenAgeHours: number | null;
  registrationTokenSizeBytes: number | null;
  scanLastSeenHours: number | null;
}

export interface KandjiMetadata extends GenericSecurityMetadata {
  libraryStateOk: boolean | null;
  lastRunRecent: boolean | null;
  lastRunHours: number | null;
  lastCheckInRecent: boolean | null;
  lastCheckInHours: number | null;
  enforced: boolean | null;
  hasPending: boolean | null;
  pendingItems: number | null;
}

export type SecuritySoftwareInsight =
  | {
      vendor: "SentinelOne";
      product: string;
      record: SecuritySoftwareRecord;
      metadata: SentinelOneMetadata;
    }
  | {
      vendor: "Kandji";
      product: string;
      record: SecuritySoftwareRecord;
      metadata: KandjiMetadata;
    }
  | {
      vendor: string;
      product: string;
      record: SecuritySoftwareRecord;
      metadata: GenericSecurityMetadata;
    };

export interface SecurityHealthVendorSummary {
  total: number;
  healthy: number;
  degraded: number;
  unknown: number;
}

export interface SecurityHealthSummary {
  total: number;
  healthy: number;
  degraded: number;
  unknown: number;
  vendors: Record<string, SecurityHealthVendorSummary>;
}

export interface SecurityInsightScore {
  score: number;
  maxScore: number;
  normalized: number;
  issues: string[];
  issueLabels: string[];
  highestSeverity: SecurityIssueSeverity | null;
  topIssue: SecurityIssueDefinition | null;
}

export type SecurityIssueSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface SecurityIssueDefinition {
  code: string;
  label: string;
  severity: SecurityIssueSeverity;
  weight: number;
  vendor?: string;
  remediation?: string;
  documentationUrl?: string;
}

export interface SecurityIssueFilterOptions {
  vendor?: string;
  severity?: SecurityIssueSeverity | SecurityIssueSeverity[];
}

export interface HostSecurityRecord {
  hostId: string;
  hostname?: string;
  securitySoftware: SecuritySoftwareRecord[];
}

export interface HostSecurityScoreSummary {
  averageScore: number | null;
  averageNormalized: number | null;
  bestScore: SecurityInsightScore | null;
  worstScore: SecurityInsightScore | null;
}

export interface HostSecurityInsight {
  hostId: string;
  hostname?: string;
  insights: SecuritySoftwareInsight[];
  health: SecurityHealthSummary;
  scorecard: HostSecurityScoreSummary;
}

export interface FleetSecuritySummary {
  totalHosts: number;
  hostsWithSecuritySoftware: number;
  totalInsights: number;
  health: SecurityHealthSummary;
  averageNormalizedScore: number | null;
  worstInsight: SecuritySoftwareInsight | null;
  worstScore: SecurityInsightScore | null;
  issues: FleetIssueSummary;
}

export interface SecurityIssueOccurrenceSummary {
  definition: SecurityIssueDefinition;
  occurrences: number;
  affectedVendors: string[];
  affectedProducts: string[];
  affectedHosts: string[];
}

export interface FleetIssueSummary {
  totalOccurrences: number;
  issues: SecurityIssueOccurrenceSummary[];
  severityBreakdown: Record<SecurityIssueSeverity, number>;
}

export interface ReviewNotificationRecord {
  notificationId: string;
  taskId: string;
  orgId: string;
  channel: string;
  status: string;
  payload: Record<string, unknown>;
  createdAt: Date;
  deliveredAt: Date | null;
}

export interface RuntimeEventRecord {
  eventId: string;
  eventType: string;
  payload: Record<string, unknown>;
  createdAt: Date;
}

export interface RuntimeEventSummaryRecord {
  eventType: string;
  eventCount: number;
  firstSeen: Date | null;
  lastSeen: Date | null;
}

export interface WorkflowTemplateStepRecord {
  name: string;
  description: string;
  action: string;
  conditions: Record<string, unknown>;
  parameters: Record<string, unknown>;
  order: number;
}

export interface WorkflowTemplateRecord {
  templateId: string;
  name: string;
  description: string;
  trigger: string;
  conditions: Record<string, unknown>;
  steps: WorkflowTemplateStepRecord[];
  metadata: Record<string, unknown>;
}

export interface PolicySuggestionRecord {
  suggestionId: string;
  toolName: string;
  celExpression: string;
  supportCount: number;
  rejectCount: number;
  confidence: number;
  metadata: Record<string, unknown>;
  lastSeen: Date;
}

export interface PolicySimulationExampleRecord {
  invocationId: string;
  sessionId: string;
  toolName: string;
  matched: boolean;
  status: string;
  startedAt: Date | null;
  completedAt: Date | null;
  inputData: Record<string, unknown>;
  outputData: Record<string, unknown> | null;
  celContext: Record<string, unknown>;
  error: string | null;
  latencyMs: number | null;
}

export interface PolicySimulationResultRecord {
  evaluatedCount: number;
  matchedCount: number;
  mismatchedCount: number;
  errorCount: number;
  examples: PolicySimulationExampleRecord[];
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

export interface IntegrationCoverageHealth extends IntegrationCoverageRecord {
  healthyPercentage: number;
  warningPercentage: number;
  criticalPercentage: number;
  overallScore: number;
}

export interface IntegrationCoverageTrendPoint {
  evaluatedAt: Date;
  coverageRatio: number | null;
}

export interface IntegrationCoverageTrend {
  integration: string;
  points: IntegrationCoverageTrendPoint[];
  rollingAverage: IntegrationCoverageTrendPoint[];
  latestChange: number | null;
  improving: boolean | null;
  anomaly?: CoverageAnomaly | null;
}

export interface CoverageAnomaly {
  threshold: number;
  delta: number;
  severity: "warning" | "critical";
}

export interface AgentSessionRecord {
  sessionId: string;
  orgId: string;
  agentType: string;
  status: string;
  title: string | null;
  createdBy: string;
  createdAt: Date;
  context: Record<string, unknown>;
}

export interface AgentSessionList {
  limit: number;
  offset: number;
  total: number;
  sessions: AgentSessionRecord[];
}

export interface ToolInvocationRecord {
  invocationId: string;
  sessionId?: string;
  toolName: string;
  toolVersion?: string;
  status: string;
  startedAt: Date;
  completedAt: Date | null;
  errorMessage: string | null;
  errorCode?: string | null;
  inputData?: Record<string, unknown>;
  outputData?: Record<string, unknown> | null;
  celPolicyKey?: string | null;
  celExpression?: string | null;
  celResult?: boolean | null;
  celContext?: Record<string, unknown> | null;
}

export interface AgentMessageRecord {
  messageId: string;
  role: string;
  content: string | Record<string, unknown>;
  metadata: Record<string, unknown>;
  createdAt: Date;
}

export interface AgentSessionDetail {
  session: AgentSessionRecord;
  messageCount: number;
  messages: AgentMessageRecord[];
  toolInvocations: ToolInvocationRecord[];
  metrics?: Record<string, unknown>;
}

export interface AgentAnalyticsSummary {
  totalSessions: number;
  activeSessions: number;
  messageCount: number;
  eventCount: number;
  skillTagCounts: Record<string, number>;
  agentTypeCounts: Record<string, number>;
}

export interface AgentMemoryRecord {
  entryId: string;
  summary: string | null;
  role: string | null;
  decayScore: number;
  tokenCount: number;
  createdAt: Date;
  lastAccessedAt: Date;
  scopes: Record<string, unknown>[];
  scopeLabels: string[];
  metadata: Record<string, unknown>;
  content: string | null;
  annSelected?: boolean | null;
  lexicalSimilarity?: number | null;
  embeddingSimilarity?: number | null;
  combinedSimilarity?: number | null;
}

export interface AgentMemoryHighlight {
  entryId: string;
  summary: string | null;
  role: string | null;
  decayScore: number;
  lastAccessedAt: Date;
  scopeLabels: string[];
}

export interface AgentMemoryStats {
  totalEntries: number;
  recentEntries: number;
  presentedEntries: number;
  averageDecay: number;
  tokenTotal: number;
  roleDistribution: Record<string, number>;
  scopeDistribution: Record<string, number>;
  topMemories: AgentMemoryHighlight[];
}

export interface ToolApprovalRecord {
  approvalId: string;
  orgId: string;
  toolInvocationId: string;
  requestedBy: string;
  requestedAt: Date;
  reason: string;
  status: string;
  decidedBy: string | null;
  decidedAt: Date | null;
  decisionReason: string | null;
  expiresAt: Date | null;
  riskAssessment: Record<string, unknown>;
}

export interface AgentNotificationRecord {
  notificationId: string;
  taskId: string;
  orgId: string;
  channel: string;
  status: string;
  payload: Record<string, unknown>;
  createdAt: Date;
  deliveredAt: Date | null;
}

export interface AgentTicketRecord {
  ticketId: string;
  taskId: string;
  orgId: string;
  system: string;
  status: string;
  details: Record<string, unknown>;
  externalId: string | null;
  createdAt: Date;
  updatedAt: Date | null;
}

export interface ToolInvocationSummary {
  toolName: string;
  status: string;
  count: number;
}

export interface AgentReviewExportRecord {
  task: ReviewTaskRecord;
  comments: ReviewTaskCommentRecord[];
  history: ReviewTaskHistoryRecord[];
}
