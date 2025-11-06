export type ReviewTaskStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "promoted"
  | "escalated";

export type ReviewTask = {
  id: string;
  session_id: string;
  org_id: string;
  status: ReviewTaskStatus;
  title: string;
  summary?: string | null;
  payload: Record<string, unknown>;
  promotion_target?: string | null;
  priority?: string | null;
  due_at?: string | null;
  escalated_to?: string | null;
  notification_channel?: string | null;
  ticket_reference?: string | null;
  created_by: string;
  created_at: string;
  resolved_by?: string | null;
  resolved_at?: string | null;
  resolution_notes?: string | null;
};

export type ReviewQueueStatusSummary = {
  status: string;
  count: number;
  unassigned: number;
  overdue: number;
  oldest_created?: string | null;
  newest_created?: string | null;
};

export type ReviewQueuePendingSummary = {
  total: number;
  unassigned: number;
  overdue: number;
  next_due?: string | null;
  oldest_created?: string | null;
};

export type ReviewQueuePrioritySummary = {
  priority?: string | null;
  count: number;
};

export type ReviewQueueSummary = {
  generated_at: string;
  status_counts: ReviewQueueStatusSummary[];
  pending: ReviewQueuePendingSummary;
  priority_breakdown: ReviewQueuePrioritySummary[];
};

export type ReviewNotification = {
  id: string;
  task_id: string;
  org_id: string;
  channel: string;
  status: string;
  payload: Record<string, unknown>;
  created_at: string;
  delivered_at?: string | null;
};

export type RuntimeEvent = {
  id: string;
  event_type: string;
  payload: Record<string, unknown>;
  created_at: string;
};

export type RuntimeEventSummary = {
  event_type: string;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
};

export type PolicySuggestion = {
  id: string;
  tool_name: string;
  cel_expression: string;
  support_count: number;
  reject_count: number;
  confidence: number;
  metadata: Record<string, unknown>;
  last_seen: string;
};

export type PolicySimulationExample = {
  invocation_id: string;
  session_id: string;
  tool_name: string;
  matched: boolean;
  status: string;
  started_at?: string | null;
  completed_at?: string | null;
  input_data: Record<string, unknown>;
  output_data?: Record<string, unknown> | null;
  cel_context: Record<string, unknown>;
  error?: string | null;
  latency_ms?: number | null;
};

export type PolicySimulationResult = {
  evaluated_count: number;
  matched_count: number;
  mismatched_count: number;
  error_count: number;
  examples: PolicySimulationExample[];
};

export type AgentMessage = {
  message_id: string;
  role: string;
  content: string;
  timestamp: string;
  metadata?: Record<string, unknown> | null;
};

export type SessionSummary = {
  session: {
    session_id: string;
    org_id: string;
    agent_type: string;
    title?: string | null;
    created_at: string;
    created_by: string;
    status: string;
    context: Record<string, unknown>;
  };
  messages: AgentMessage[];
  message_count: number;
  tool_invocations: Array<{
    id: string;
    tool_name: string;
    status: string;
    started_at: string;
    completed_at?: string | null;
    error_message?: string | null;
  }>;
  metrics: Record<string, unknown>;
};

export type AgentSessionListItem = {
  session_id: string;
  org_id: string;
  agent_type: string;
  title?: string | null;
  created_at: string;
  created_by: string;
  status: string;
  context: Record<string, unknown>;
};

export type SessionListResponse = {
  sessions: AgentSessionListItem[];
  total: number;
  limit: number;
  offset: number;
};

export type MemoryEntry = {
  id: string;
  role?: string | null;
  summary?: string | null;
  decay_score: number;
  last_accessed_at: string;
  created_at: string;
  scopes: Array<Record<string, unknown>>;
  scope_labels: string[];
  metadata: Record<string, unknown>;
  token_count: number;
  content?: string | null;
  embedding_similarity?: number | null;
  lexical_similarity?: number | null;
  combined_similarity?: number | null;
  ann_selected?: boolean | null;
};

export type MemoryStats = {
  total_entries: number;
  recent_entries: number;
  presented_entries: number;
  average_decay: number;
  token_total: number;
  role_distribution: Record<string, number>;
  scope_distribution: Record<string, number>;
  top_memories: Array<{
    id: string;
    summary?: string | null;
    decay_score: number;
    last_accessed_at: string;
    role?: string | null;
    scope_labels: string[];
  }>;
};

export type OrganizationSummary = {
  org_id: string;
  name: string;
  created_at: string;
};

export type IntegrationStatus = {
  integration: string;
  scope: string;
  last_timestamp: string | null;
  last_cursor: string | null;
  metadata: Record<string, unknown>;
};

export type IntegrationIssue = {
  integration: string;
  scope: string;
  status: string;
  issue_type: string;
  severity: "ok" | "warning" | "critical" | string;
  message: string;
  observed_at: string;
  last_timestamp: string | null;
  age_seconds: number | null;
  metadata: Record<string, unknown>;
};

export type IntegrationSyncJob = {
  task_id: string;
  integration: string;
  scope: string;
  queued_at: string;
};

export type IntegrationIssueHistoryEvent = {
  integration: string;
  scope: string;
  issue_type: string;
  severity: string;
  message: string;
  observed_at: string;
  last_timestamp: string | null;
  age_seconds: number | null;
  metadata: Record<string, unknown>;
};

export type IntegrationIssueTrendBucket = {
  bucket_start: string;
  bucket_end: string;
  counts: Record<string, number>;
};

export type IntegrationIssueHistory = {
  events: IntegrationIssueHistoryEvent[];
  buckets: IntegrationIssueTrendBucket[];
};

export type IntegrationSyncStatus = {
  task_id: string;
  status: string;
  finished: boolean;
  date_done: string | null;
  result: unknown;
};

export type ExecutiveSummaryProgress = {
  findings_burned_down_30d: number;
  new_controls_implemented: number;
  risk_score_change_30d: number;
  risk_score_change_7d: number;
};

export type ExecutiveSummaryResponse = {
  org_id: string;
  report_date: string;
  overall_risk_score: number;
  risk_level: string;
  risk_trend: string;
  total_assets: number;
  total_identities: number;
  active_findings: number;
  compliance_score: number;
  dimension_scores: Record<string, number>;
  top_5_risks: string[];
  progress_indicators: ExecutiveSummaryProgress;
};

export type SecurityMetricsResponse = {
  findings: {
    total: number;
    critical: number;
    high: number;
    open: number;
    trend_7d: number[];
    critical_trend_7d: number[];
  };
  sla_performance: {
    breaches: number;
    mttr_hours: number;
    new_24h: number;
    resolved_24h: number;
  };
  provider_breakdown?: ProviderFindingBreakdown[];
};

export type ProviderFindingBreakdown = {
  provider: string;
  open_findings: number;
  critical_open: number;
  high_open: number;
  new_last_24h: number;
  sla_breaches: number;
  mttr_hours: number | null;
};

export type ProviderFindingDetail = {
  finding_id: string;
  title: string;
  severity: string;
  status: string;
  first_seen: string | null;
  last_seen: string | null;
  resource_id: string | null;
  rule_name: string | null;
};

export type ProviderFindingsResponse = {
  provider: string;
  findings: ProviderFindingDetail[];
};

export type ComplianceStatusEntry = {
  total_controls: number;
  compliant_controls: number;
  compliance_percentage: number;
  status: string;
};

export type InvestmentRecommendation = {
  priority: string;
  category: string;
  recommendation: string;
  rationale: string;
  estimated_impact: string;
  investment_level: string;
};

export type IdentityAnalyticsSummary = {
  total_identities: number;
  high_privilege_identities: number;
  cross_provider_identities: number;
  avg_permissions_per_identity: number;
  max_permissions_per_identity: number;
};

export type IdentityAnalyticsRiskyIdentity = {
  principal_id: string;
  display_name: string | null;
  email: string | null;
  risk_score: number;
  risk_level: string;
  cross_provider_access: number;
  admin_access_count: number;
  mfa_status: string;
  top_risk_factor?: string | null;
};

export type IdentityPrivilegeAnomaly = {
  type: string;
  principal_id: string;
  principal_name?: string | null;
  description: string;
  risk_level: string;
  recommendation: string;
};

export type IdentityDrilldownPermission = {
  provider: string;
  permission: string;
  is_admin: boolean;
  granted_at?: string | null;
};

export type IdentityDrilldownFinding = {
  finding_id: string;
  title: string;
  severity: string;
  status: string;
  last_seen?: string | null;
};

export type IdentityDrilldownIdentity = {
  principal_id: string;
  display_name: string | null;
  email: string | null;
  risk_score: number;
  risk_level: string;
  providers: string[];
  permissions: IdentityDrilldownPermission[];
  open_findings: IdentityDrilldownFinding[];
  recommended_actions: string[];
  risk_factors: string[];
};

export type IdentityRemediationNote = {
  note_id: string;
  author_id: string | null;
  author?: string | null;
  note: string;
  created_at: string;
};

export type IdentityRemediationItem = {
  action_id: string;
  principal_id: string;
  priority: "low" | "medium" | "high";
  summary: string;
  recommended_action: string;
  evidence: string[];
  risk_level?: string;
  status: "pending" | "accepted" | "completed";
  notes: IdentityRemediationNote[];
  accepted_at: string | null;
  accepted_by: string | null;
  completed_at: string | null;
  completed_by: string | null;
  created_at: string | null;
  updated_at: string | null;
  source?: "analytics" | "manual";
};

export type IdentityRemediationBulkResponse = {
  updated: IdentityRemediationItem[];
};

export type IdentityDrilldownExportResponse = {
  org_id: string;
  generated_at: string;
  count: number;
  risk_level_filter?: string | null;
  drilldown: IdentityDrilldownIdentity[];
};

export type IdentityProviderBreakdown = {
  identity_count: number;
  unique_permissions: number;
  admin_grants: number;
  recent_activity_ratio: number;
  risk_level: string;
};

export type IdentityMfaCompliance = {
  total_users: number;
  mfa_enabled_users: number;
  compliance_rate: number;
  status: string;
};

export type IdentityAnalyticsResponse = {
  summary: IdentityAnalyticsSummary;
  privilege_distribution: Record<string, number>;
  privilege_segments: IdentityPrivilegeSegment[];
  top_risky_identities: IdentityAnalyticsRiskyIdentity[];
  privilege_anomalies: IdentityPrivilegeAnomaly[];
  mfa_compliance_by_provider: Record<string, IdentityMfaCompliance>;
  provider_breakdown: Record<string, IdentityProviderBreakdown>;
  provider_segments: IdentityProviderSegment[];
  drilldown_identities: IdentityDrilldownIdentity[];
  remediation_queue: IdentityRemediationItem[];
  risk_level_breakdown: Record<string, number>;
  generated_at: string;
};

export type IdentityPrivilegeSegment = {
  label: string;
  count: number;
};

export type IdentityProviderSegment = {
  provider: string;
  identity_count: number;
  admin_grants: number;
  risk_level: string;
};

export type RiskHeatmapArea = {
  provider: string;
  resource_type: string;
  risk_score: number;
  finding_count: number;
};

export type RiskImprovementOpportunity = {
  area: string;
  current_risk: number;
  potential_reduction: number;
  impact: string;
};

export type RiskHeatmapResponse = {
  heatmap_data: Record<string, Record<string, number>>;
  high_risk_areas: RiskHeatmapArea[];
  improvement_opportunities: RiskImprovementOpportunity[];
};

export type ComplianceTrendPoint = {
  date: string;
  score: number;
};

export type ComplianceTrendResponse = {
  overall: ComplianceTrendPoint[];
  frameworks: Record<string, ComplianceTrendPoint[]>;
  delta?: {
    overall: number;
    frameworks: Record<string, number>;
  };
};

export type ProviderFreshnessSummary = {
  last_synced_at: string | null;
  age_seconds: number | null;
  age_human: string | null;
  status: string;
  sources: string[];
};

export type DashboardFreshness = {
  providers: Record<string, ProviderFreshnessSummary>;
  warnings: string[];
};

export type DashboardMetadata = {
  generated_at: string;
  component_timings?: Record<string, number>;
  filters_applied?: {
    identity_risk_filter: string;
    compliance_trend_range: string;
  };
  cache_ttl_seconds?: number;
  supports_streaming_updates?: boolean;
  alert_thresholds?: Record<string, { warning: number; critical: number }>;
  data_freshness?: DashboardFreshness;
  data_as_of?: string | null;
};

export type ExecutiveDashboardResponse = {
  executive_summary: ExecutiveSummaryResponse;
  security_metrics: SecurityMetricsResponse;
  compliance_status: Record<string, ComplianceStatusEntry>;
  investment_recommendations: InvestmentRecommendation[];
  identity_analytics: IdentityAnalyticsResponse;
  risk_heatmap: RiskHeatmapResponse;
  compliance_trends: ComplianceTrendResponse;
  runtime_health?: RuntimeHealthDashboardEntry[];
  integration_coverage?: IntegrationCoverageDashboardEntry[];
  freshness?: Record<string, ProviderFreshnessSummary>;
  freshness_warnings?: string[];
  metadata: DashboardMetadata;
};

export type RuntimeHealthDashboardEntry = {
  runtime: string;
  window_start: string;
  window_end: string;
  events: Record<string, { count: number; last_seen: string | null }>;
  warnings: Record<string, { count: number; last_seen: string | null }>;
  latest_metadata?: {
    payload: Record<string, unknown>;
    captured_at: string;
  } | null;
  severity?: string;
};

export type IntegrationCoverageDashboardEntry = {
  integration: string;
  providers: string[];
  status: string;
  scopes: {
    total: number;
    healthy: number;
    warning: number;
    critical: number;
  };
  accounts: {
    total: number;
  };
  coverage_ratio?: number | null;
  last_success?: string | null;
  evaluated_at: string;
  severity?: string;
};
