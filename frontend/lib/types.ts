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

export type ExecutiveSummaryProgress = {
  findings_burned_down_30d: number;
  new_controls_implemented: number;
  risk_score_change_30d: number;
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

export type IdentityRemediationItem = {
  principal_id: string;
  priority: "low" | "medium" | "high";
  summary: string;
  recommended_action: string;
  evidence: string[];
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
  top_risky_identities: IdentityAnalyticsRiskyIdentity[];
  privilege_anomalies: IdentityPrivilegeAnomaly[];
  mfa_compliance_by_provider: Record<string, IdentityMfaCompliance>;
  provider_breakdown: Record<string, IdentityProviderBreakdown>;
  drilldown_identities: IdentityDrilldownIdentity[];
  remediation_queue: IdentityRemediationItem[];
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
};

export type ExecutiveDashboardResponse = {
  executive_summary: ExecutiveSummaryResponse;
  security_metrics: SecurityMetricsResponse;
  compliance_status: Record<string, ComplianceStatusEntry>;
  investment_recommendations: InvestmentRecommendation[];
  identity_analytics: IdentityAnalyticsResponse;
  risk_heatmap: RiskHeatmapResponse;
  compliance_trends: ComplianceTrendResponse;
};
