export type GRCSummary = {
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  overdue_findings: number;
  unassigned: number;
  controls_failing: number;
  evidence_items: number;
  connectors: number;
  stale_connectors: number;
};

export type GRCListMeta = {
  limit?: number;
  returned?: number;
  total?: number;
  truncated?: boolean;
};

export type GRCControlRef = {
  framework_name: string;
  framework_id?: string;
  control_id: string;
};

export type GRCCoverageControlRef = {
  framework_id?: string;
  framework_name?: string;
  control_id: string;
};

export type GRCFindingSourceCoverageRef = {
  source_id?: string;
  dimension_id?: string;
  dimension_type?: string;
  support_level?: string;
  high_value?: boolean;
  families?: string[];
  evidence_types?: string[];
  control_domains?: string[];
  matched_control_refs?: GRCCoverageControlRef[];
};

export type GRCFindingNote = {
  id: string;
  body: string;
  created_at?: string;
};

export type GRCFindingTicket = {
  url: string;
  name?: string;
  external_id?: string;
  linked_at?: string;
};

export type GRCFindingExternalRef = {
  system?: string;
  kind?: string;
  external_id?: string;
  url?: string;
  external_status?: string;
  external_status_reason?: string;
  lifecycle_owner?: string;
  observed_at?: string;
};

export type GRCFinding = {
  id: string;
  title: string;
  severity: string;
  status: string;
  disposition?: string;
  status_reason?: string;
  status_updated_at?: string;
  summary?: string;
  tenant_id?: string;
  runtime_id?: string;
  source_id?: string;
  entity?: string;
  resource_urns?: string[];
  rule_id?: string;
  policy_id?: string;
  policy_name?: string;
  controls?: GRCControlRef[];
  attributes?: Record<string, string>;
  evidence_type?: string;
  assessment_methods?: string[];
  auditor_guidance?: string | string[];
  risk_statement?: string;
  remediation_intent?: string;
  source_coverage_refs?: GRCFindingSourceCoverageRef[];
  risk_score?: number;
  likelihood_score?: number;
  impact_score?: number;
  confidence_score?: number;
  likelihood_level?: string;
  impact_level?: string;
  risk_reasons?: string[];
  risk_model_version?: string;
  evidence_count: number;
  assignee?: string;
  owner: string;
  sla_status: string;
  due_at?: string;
  first_observed_at?: string;
  last_observed_at?: string;
  notes?: GRCFindingNote[];
  tickets?: GRCFindingTicket[];
  external_refs?: GRCFindingExternalRef[];
};

export type GRCEvidence = {
  id: string;
  runtime_id?: string;
  rule_id?: string;
  finding_id?: string;
  finding_title?: string;
  run_id?: string;
  claim_ids?: string[];
  event_ids?: string[];
  graph_root_urns?: string[];
  created_at?: string;
};

export type GRCControl = {
  framework_name: string;
  framework_id?: string;
  framework_version?: string;
  framework_lifecycle?: "active" | "upcoming" | string;
  family_id?: string;
  family_name?: string;
  control_id: string;
  title?: string;
  owner_domain?: string;
  status: string;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  evidence_items: number;
  missing_evidence_items?: number;
  stale_evidence_items?: number;
  evidence_expectations?: number;
  evidence_score?: number;
  evidence_quality?: string;
  audit_summary?: string;
  mapped_rules?: string[];
  reasons?: string[];
  tags?: string[];
  findings?: GRCFinding[];
};

export type GRCEvidenceExpectation = {
  id: string;
  title?: string;
  type: string;
  description?: string;
  required?: boolean;
  assessment_methods?: string[];
  freshness_sla?: string;
  accepted_from?: string[];
};

export type GRCControlDefinition = {
  id: string;
  title?: string;
  objective?: string;
  intent?: string;
  applicability?: string[];
  assessment_methods?: string[];
  implementation_guidance?: string[];
  audit_procedure?: string[];
  failure_modes?: string[];
  remediation_guidance?: string[];
  exception_guidance?: string;
  evidence_expectations?: GRCEvidenceExpectation[];
  freshness_sla?: string;
  owner_domain?: string;
  automatable?: boolean;
  manual_evidence_allowed?: boolean;
  tags?: string[];
};

export type GRCControlArchetype = {
  id: string;
  family_id: string;
  family_name: string;
  family_description?: string;
  recommended?: boolean;
  control: GRCControlDefinition;
};

export type GRCControlReadiness = {
  status: string;
  score: number;
  missing_fields?: string[];
};

export type GRCReportReadinessBlocker = {
  code: string;
  label: string;
  count?: number;
};

export type GRCReportReadiness = {
  status: string;
  score: number;
  summary?: string;
  blockers?: GRCReportReadinessBlocker[];
};

export type GRCReportProvenance = {
  report_type: string;
  profile_id?: string;
  profile_name?: string;
  packet_version?: string;
  generated_at: string;
  control_count?: number;
  finding_count?: number;
  evidence_count?: number;
  runtime_count?: number;
  source_ids?: string[];
};

export type GRCReportScopeExclusions = {
  total: number;
  runtime_ids?: string[];
  excluded_families?: string[];
  excluded_asset_classes?: string[];
  excluded_kinds?: string[];
  excluded_resource_urns?: string[];
  excluded_resources?: Array<{ urn?: string; type?: string; id?: string; reason?: string }>;
  applied_to_incremental_fetch: boolean;
  filtered_before_graph_projection: boolean;
};

export type GRCReportIncrementalFetch = {
  status: string;
  policy_applied_before_read: boolean;
  event_filtering_before_projection: boolean;
  summary?: string;
};

export type GRCReportScope = {
  source_ids?: string[];
  runtime_ids?: string[];
  exclusions: GRCReportScopeExclusions;
  incremental_fetch: GRCReportIncrementalFetch;
};

export type GRCReportRedaction = {
  default_mode: "share_safe" | "internal" | string;
  available_modes?: string[];
  sensitive_fields?: string[];
  summary?: string;
};

export type GRCReportMetadata = {
  readiness: GRCReportReadiness;
  provenance: GRCReportProvenance;
  scope: GRCReportScope;
  redaction: GRCReportRedaction;
};

export type GRCAuditProgram = {
  id: string;
  name?: string;
  profile_id?: string;
  status: string;
  readiness_score: number;
  framework_count: number;
  control_count: number;
  evidence_request_count: number;
  evidence_packet_count: number;
  collection_source_count?: number;
  evidence_item_count?: number;
  resource_subject_count?: number;
  lineage_count?: number;
  claim_record_count?: number;
  evaluation_run_count?: number;
  graph_path_count?: number;
  open_review_count: number;
};

export type GRCFrameworkPosture = {
  id: string;
  name: string;
  version?: string;
  lifecycle?: string;
  status: string;
  control_count: number;
  passing_controls: number;
  needs_attention_controls: number;
  missing_evidence_count: number;
  stale_evidence_count: number;
  evidence_score: number;
};

export type GRCControlTestResult = {
  id: string;
  rule_id: string;
  control_id: string;
  status: string;
  result: string;
  evidence_quality?: string;
  finding_ids?: string[];
  evidence_ids?: string[];
  last_observed_at?: string;
};

export type GRCControlPosture = {
  id: string;
  framework_id?: string;
  framework_name?: string;
  title?: string;
  owner_domain?: string;
  framework_version?: string;
  framework_lifecycle?: string;
  family_id?: string;
  family_name?: string;
  status: string;
  evidence_quality?: string;
  evidence_score: number;
  audit_summary?: string;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  evidence_items: number;
  missing_evidence_items: number;
  stale_evidence_items: number;
  mapped_rules?: string[];
  reasons?: string[];
  tags?: string[];
  test_results?: GRCControlTestResult[];
  evidence_request_ids?: string[];
  evidence_packet_ids?: string[];
  finding_ids?: string[];
  exception_ids?: string[];
};

export type GRCEvidenceRequest = {
  id: string;
  control_id: string;
  framework_id?: string;
  title?: string;
  description?: string;
  type?: string;
  required: boolean;
  status: string;
  quality: string;
  freshness_sla?: string;
  assessment_methods?: string[];
  accepted_from?: string[];
  evidence_packet_ids?: string[];
  review_status: string;
  owner_domain?: string;
  due_at?: string;
  control_test_ids?: string[];
};

export type GRCEvidenceCitations = {
  evidence_ids?: string[];
  rule_ids?: string[];
  event_ids?: string[];
  claim_ids?: string[];
  graph_root_urns?: string[];
  run_ids?: string[];
};

export type GRCEvidenceFreshness = {
  status: string;
  sla?: string;
  reason?: string;
  observed_at?: string;
  expires_at?: string;
};

export type GRCEvidenceReview = {
  id: string;
  subject_id: string;
  status: string;
  reason?: string;
  actor?: string;
  updated_at?: string;
};

export type GRCPackagedEvidencePacket = {
  id: string;
  request_id?: string;
  control_id?: string;
  framework_id?: string;
  evidence_type?: string;
  status: string;
  quality?: string;
  reason?: string;
  source?: string;
  observed_at?: string;
  expires_at?: string;
  manual?: boolean;
  citations: GRCEvidenceCitations;
  freshness: GRCEvidenceFreshness;
  review?: GRCEvidenceReview;
  export_artifact: { format: string; path?: string };
};

export type GRCEvidenceActivity = {
  id: string;
  subject_id: string;
  type: string;
  message?: string;
  created_at: string;
};

export type GRCEvidenceExport = {
  id: string;
  formats: string[];
  redaction: string;
  path?: string;
};

export type GRCAssessmentScope = {
  id: string;
  report_type?: string;
  profile_id?: string;
  profile_name?: string;
  generated_at: string;
  source_ids?: string[];
  runtime_ids?: string[];
  control_count: number;
  finding_count: number;
  evidence_count: number;
  runtime_count: number;
  exclusion_count: number;
  collection_policy: string;
  policy_applied_before_read: boolean;
  filtered_before_graph_projection: boolean;
  redaction_mode?: string;
};

export type GRCCollectionSource = {
  id: string;
  runtime_id: string;
  source_id?: string;
  tenant_id?: string;
  status: string;
  last_synced_at?: string;
  finding_count: number;
  evidence_item_count: number;
  control_count: number;
};

export type GRCEvidenceItemRecord = {
  id: string;
  runtime_id?: string;
  source_id?: string;
  finding_id?: string;
  rule_id?: string;
  run_id?: string;
  run_ids?: string[];
  claim_ids?: string[];
  event_ids?: string[];
  graph_root_urns?: string[];
  graph_path_urns?: string[];
  created_at?: string;
  last_observed_at?: string;
  observation_count?: number;
  control_ids?: string[];
  evidence_request_ids?: string[];
  evidence_packet_ids?: string[];
};

export type GRCFindingWorkflow = {
  id: string;
  title?: string;
  severity?: string;
  status?: string;
  owner?: string;
  sla_status?: string;
  runtime_id?: string;
  source_id?: string;
  rule_id?: string;
  policy_id?: string;
  policy_name?: string;
  check_id?: string;
  check_name?: string;
  risk_score?: number;
  risk_reasons?: string[];
  due_at?: string;
  status_reason?: string;
  control_ids?: string[];
  evidence_ids?: string[];
  evidence_packet_ids?: string[];
  last_observed_at?: string;
  review_status: string;
};

export type GRCResourceSubject = {
  id: string;
  urn: string;
  kind?: string;
  control_ids?: string[];
  finding_ids?: string[];
  evidence_ids?: string[];
  evidence_packet_ids?: string[];
  last_observed_at?: string;
};

export type GRCEvidenceLineage = {
  id: string;
  evidence_id: string;
  finding_id?: string;
  runtime_id?: string;
  source_id?: string;
  rule_id?: string;
  run_ids?: string[];
  claim_ids?: string[];
  event_ids?: string[];
  graph_root_urns?: string[];
  evidence_request_ids?: string[];
  evidence_packet_ids?: string[];
  control_ids?: string[];
};

export type GRCClaimRecord = {
  id: string;
  evidence_ids?: string[];
  finding_ids?: string[];
  control_ids?: string[];
  evidence_packet_ids?: string[];
};

export type GRCEvaluationRun = {
  id: string;
  runtime_id?: string;
  source_id?: string;
  rule_ids?: string[];
  evidence_ids?: string[];
  finding_ids?: string[];
  control_ids?: string[];
  evidence_packet_ids?: string[];
};

export type GRCGraphEvidenceRecord = {
  id: string;
  evidence_id?: string;
  finding_id?: string;
  label?: string;
  attributes?: Record<string, string>;
  graph_path_ids?: string[];
};

export type GRCGraphPathRecord = {
  id: string;
  evidence_id?: string;
  finding_id?: string;
  from_urn?: string;
  from_type?: string;
  relation?: string;
  to_urn?: string;
  to_type?: string;
  observed_at?: string;
  attributes?: Record<string, string>;
};

export type GRCExceptionAcceptance = {
  id: string;
  control_id: string;
  framework_id?: string;
  type: string;
  status: string;
};

export type GRCEvidenceExportArtifact = {
  id: string;
  snapshot_id: string;
  format: string;
  redaction: string;
  path?: string;
  content_hash: string;
  included: boolean;
};

export type GRCAuditSnapshot = {
  id: string;
  hash: string;
  generated_at: string;
  control_count: number;
  evidence_request_count: number;
  evidence_packet_count: number;
  collection_source_count?: number;
  evidence_item_count?: number;
  resource_subject_count?: number;
  lineage_count?: number;
  claim_record_count?: number;
  evaluation_run_count?: number;
  graph_path_count?: number;
  open_review_count: number;
};

export type GRCQuestionnaireEvidenceRef = {
  id: string;
  evidence_packet_id?: string;
  evidence_type?: string;
  source?: string;
  source_id?: string;
  runtime_id?: string;
  freshness?: GRCEvidenceFreshness;
  review_state?: string;
};

export type GRCQuestionnaireEvidenceGap = {
  id: string;
  code: string;
  field?: string;
  reason?: string;
  control_id?: string;
  evidence_request_id?: string;
  evidence_packet_id?: string;
  review_state?: string;
};

export type GRCQuestionnaireEvidenceAnswer = {
  id: string;
  question_id: string;
  question: string;
  answer: string;
  answer_state: string;
  review_state: string;
  confidence?: { level?: string; score?: number; reason?: string };
  controls?: Array<{ id?: string; control_id?: string; title?: string; status?: string }>;
  source_evidence?: GRCQuestionnaireEvidenceRef[];
  policy_documents?: GRCQuestionnaireEvidenceRef[];
  evidence_packet_ids?: string[];
  citations?: GRCEvidenceCitations;
  freshness?: GRCEvidenceFreshness;
  missing_evidence?: GRCQuestionnaireEvidenceGap[];
  guardrails?: string[];
};

export type GRCEvidencePacketsResponse = {
  version: string;
  generated_at: string;
  program: GRCAuditProgram;
  frameworks: GRCFrameworkPosture[];
  controls: GRCControlPosture[];
  evidence_requests: GRCEvidenceRequest[];
  evidence_packets: GRCPackagedEvidencePacket[];
  evidence_reviews: GRCEvidenceReview[];
  activity: GRCEvidenceActivity[];
  assessment_scope?: GRCAssessmentScope;
  collection_sources?: GRCCollectionSource[];
  evidence_items?: GRCEvidenceItemRecord[];
  finding_workflow?: GRCFindingWorkflow[];
  resource_subjects?: GRCResourceSubject[];
  evidence_lineage?: GRCEvidenceLineage[];
  claim_records?: GRCClaimRecord[];
  evaluation_runs?: GRCEvaluationRun[];
  graph_evidence_rows?: GRCGraphEvidenceRecord[];
  graph_path_records?: GRCGraphPathRecord[];
  exceptions_acceptances?: GRCExceptionAcceptance[];
  questionnaire_answers?: GRCQuestionnaireEvidenceAnswer[];
  export_artifacts?: GRCEvidenceExportArtifact[];
  export: GRCEvidenceExport;
  snapshot: GRCAuditSnapshot;
  metadata: GRCReportMetadata;
};

export type GRCControlCoverageSummary = {
  selected_controls: number;
  mapped_controls: number;
  unmapped_controls: number;
  mapped_rules: number;
  auditor_ready_controls: number;
  needs_enrichment_controls: number;
  placeholder_controls: number;
};

export type GRCControlCoverageControl = {
  framework_id?: string;
  framework_name: string;
  framework_version?: string;
  framework_lifecycle?: "active" | "upcoming" | string;
  family_id: string;
  family_name: string;
  control_id: string;
  title?: string;
  owner_domain?: string;
  tags?: string[];
  evidence_expectation_ids?: string[];
  audit_readiness: GRCControlReadiness;
  coverage_status: string;
  rule_count: number;
  mapped_rules?: string[];
  evidence_plan?: {
    expectations?: GRCEvidenceExpectation[];
  };
};

export type GRCControlCoverageProfile = {
  id: string;
  name?: string;
  description?: string;
  summary: GRCControlCoverageSummary;
  controls?: GRCControlCoverageControl[];
  unmapped_controls?: GRCControlRef[];
};

export type GRCFramework = {
  id?: string;
  name: string;
  framework_version?: string;
  lifecycle: "active" | "upcoming" | string;
  description?: string;
  tags?: string[];
  family_count: number;
  control_count: number;
  maturity?: {
    status: string;
    score: number;
    summary?: string;
  };
  coverage?: {
    selected_controls: number;
    mapped_controls: number;
    unmapped_controls: number;
    mapped_rules: number;
  };
  readiness?: {
    auditor_ready_controls: number;
    needs_enrichment_controls: number;
    placeholder_controls: number;
  };
  gap_actions?: Array<{
    code: string;
    label: string;
    priority: number;
    count?: number;
  }>;
};

export type GRCFrameworksResponse = {
  version: string;
  frameworks: GRCFramework[];
  generated_at: string;
};

export type GRCControlPackSummary = {
  archetypes: number;
  controls: number;
  families: number;
  mapped_controls: number;
  unmapped_controls: number;
  mapped_rules: number;
  auditor_ready_controls: number;
  needs_enrichment_controls: number;
  placeholder_controls: number;
};

export type GRCControlPackPreview = {
  version: string;
  coverage: GRCControlCoverageProfile;
  summary: GRCControlPackSummary;
  files: Record<string, string>;
};

export type GRCControlArchetypesResponse = {
  version: string;
  archetypes: GRCControlArchetype[];
  generated_at: string;
};

export type GRCControlProfilesResponse = {
  profiles: GRCControlCoverageProfile[];
  generated_at: string;
};

export type GRCControlPackResponse = {
  preview: GRCControlPackPreview;
  generated_at: string;
};

export type GRCControlPackIssueResponse = {
  issues: Array<{ path?: string; message?: string; Path?: string; Message?: string }>;
  generated_at: string;
};

export type GRCConnector = {
  runtime_id: string;
  source_id?: string;
  tenant_id?: string;
  status: string;
  freshness: string;
  sync_lag_seconds?: number;
  checkpoint_watermark?: string;
  watermark_lag_seconds?: number;
  watermark_freshness?: string;
  last_synced_at?: string;
};

export type GRCSourceRuntimeHealthSummary = {
  source_id: string;
  total: number;
  healthy?: number;
  stale?: number;
  failed?: number;
  cursor_pending?: number;
  contract_probe_not_configured?: number;
  graph_not_observed?: number;
};

export type GRCSourceCoverageRecord = {
  source_id: string;
  tenant_id?: string;
  dimension_id: string;
  dimension_type: string;
  title?: string;
  state?: string;
  support_level?: string;
  runtime_id?: string;
  family?: string;
  last_synced_at?: string;
  owner_domain?: string;
  authority_domain?: string;
  high_value?: boolean;
  blind_spot?: boolean;
  warning?: string;
  known_unsupported_fields?: string[];
  notes?: string[];
  evidence_types?: string[];
  control_domains?: string[];
  control_refs?: GRCCoverageControlRef[];
  supported_runtime_families?: string[];
};

export type GRCSourceCoverageSummary = {
  source_id: string;
  total: number;
  healthy: number;
  partial: number;
  unsupported: number;
  unconfigured: number;
  stale: number;
  failed: number;
  unknown: number;
  blind_spots: number;
};

export type GRCCoverageRecord = GRCSourceCoverageRecord;
export type GRCCoverageSummary = GRCSourceCoverageSummary;

/**
 * @deprecated Product areas were a generated web fallback. Use route navigation,
 * coverage summaries, and source health data instead.
 */
export type GRCProductAreaWorkflow = {
  label: string;
  href: string;
};

/**
 * @deprecated Product areas were a generated web fallback. The app no longer
 * emits fixture product_areas or renders this response field.
 */
export type GRCProductAreaResponse = {
  id: string;
  title: string;
  description: string;
  href: string;
  workflows: GRCProductAreaWorkflow[];
  source_families?: string[];
  coverage_dimensions?: string[];
  evidence_types?: string[];
  control_domains?: string[];
  blind_spots?: GRCCoverageRecord[];
  detail?: string;
  signal?: string;
  status?: string;
};

export type GRCProgramReadinessSummary = {
  status: string;
  score: number;
  controls: number;
  passing_controls: number;
  failing_controls: number;
  missing_evidence_controls: number;
  stale_evidence_controls: number;
  manual_review_controls: number;
  evidence_items: number;
  missing_evidence_items: number;
  stale_evidence_items: number;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  connectors: number;
  stale_connectors: number;
  coverage_blind_spots: number;
  readiness_blockers?: GRCReportReadinessBlocker[];
};

export type GRCProgramFramework = {
  framework_name: string;
  framework_id?: string;
  framework_version?: string;
  framework_lifecycle?: string;
  status: string;
  score: number;
  controls: number;
  passing_controls: number;
  failing_controls: number;
  missing_evidence_controls: number;
  stale_evidence_controls: number;
  manual_review_controls: number;
  open_findings: number;
  evidence_items: number;
};

export type GRCProgramControl = {
  framework_name: string;
  framework_id?: string;
  framework_version?: string;
  framework_lifecycle?: string;
  control_id: string;
  title?: string;
  owner_domain?: string;
  status: string;
  score: number;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  evidence_items: number;
  missing_evidence_items?: number;
  stale_evidence_items?: number;
  evidence_expectations?: number;
  evidence_quality?: string;
  action: string;
  href?: string;
  reasons?: string[];
};

export type GRCProgramWorkItem = {
  id: string;
  kind: string;
  title: string;
  framework_name?: string;
  control_id?: string;
  status: string;
  action: string;
  assignee?: string;
  due_at?: string;
  owner_domain?: string;
  severity?: string;
  sla_status?: string;
  source_id?: string;
  open_findings?: number;
  critical_findings?: number;
  missing_evidence_items?: number;
  stale_evidence_items?: number;
  href?: string;
  reasons?: string[];
};

export type GRCProgramProofBundle = {
  id: string;
  title: string;
  description?: string;
  status: string;
  score: number;
  control_packet_path: string;
  export_path: string;
  reports_path: string;
  readiness: GRCReportReadiness;
  generated_at: string;
};

export type GRCProgramReadiness = {
  profile: GRCControlPacketProfile;
  summary: GRCProgramReadinessSummary;
  frameworks: GRCProgramFramework[];
  controls: GRCProgramControl[];
  work_items: GRCProgramWorkItem[];
  proof_bundle: GRCProgramProofBundle;
  connectors: GRCConnector[];
  source_summaries?: GRCSourceRuntimeHealthSummary[];
  coverage_blind_spots?: GRCCoverageRecord[];
  coverage_summaries?: GRCCoverageSummary[];
  /** @deprecated Use coverage_summaries and route navigation instead. */
  product_areas?: GRCProductAreaResponse[];
  metadata: GRCReportMetadata;
  generated_at: string;
};

export type GRCGraphNode = {
  urn: string;
  entity_type: string;
  label: string;
  attributes?: Record<string, string>;
};

export type GRCGraphRelation = {
  from_urn: string;
  relation: string;
  to_urn: string;
  attributes?: Record<string, string>;
};

export type GRCGraph = {
  root?: GRCGraphNode;
  neighbors?: GRCGraphNode[];
  relations?: GRCGraphRelation[];
};

export type GRCVendor = {
  urn: string;
  vendor_id?: string;
  name: string;
  source_id?: string;
  runtime_id?: string;
  provider?: string;
  status?: string;
  category?: string;
  website_url?: string;
  services_provided?: string;
  source_status?: string;
  lifecycle_state?: string;
  lifecycle_reason?: string;
  security_owner_user_id?: string;
  business_owner_user_id?: string;
  owner?: string;
  inherent_risk_level?: string;
  residual_risk_level?: string;
  risk_level: string;
  risk_score?: number;
  risk_score_level?: string;
  risk_score_source?: string;
  risk_tier?: string;
  review_cadence_days?: number;
  score_factors?: GRCRiskScoreFactor[];
  data_sensitivity?: string;
  access_level?: string;
  criticality?: string;
  subprocessor?: string;
  geography?: string;
  system_dependency?: string;
  risk_drivers?: string[];
  dpa_status?: string;
  baa_status?: string;
  soc2_status?: string;
  iso27001_status?: string;
  security_review_status?: string;
  privacy_review_status?: string;
  document_status?: string;
  owner_state: "assigned" | "missing" | string;
  review_state: "current" | "due_soon" | "overdue" | "not_scheduled" | string;
  review_due_at?: string;
  last_review_completed_at?: string;
  assessment_state?: string;
  assessment_progress?: number;
  open_assessments?: number;
  completed_assessments?: number;
  assessment_types?: string[];
  questionnaire_state?: string;
  questionnaire_progress?: number;
  last_assessment_at?: string;
  next_assessment_at?: string;
  evidence_freshness_state?: string;
  evidence_freshness?: GRCVendorFreshnessClock[];
  monitoring_state?: string;
  monitoring_signals?: GRCVendorMonitoringSignal[];
  external_rating?: string;
  external_rating_updated_at?: string;
  last_material_change_at?: string;
  spend_amount?: string;
  spend_currency?: string;
  contract_value?: string;
  contract_currency?: string;
  renewal_notice_at?: string;
  renewal_state?: string;
  primary_contact?: string;
  business_unit?: string;
  cost_center?: string;
  exposure_level?: string;
  exposure_reasons?: string[];
  packet_state?: string;
  packet_ready_items?: string[];
  packet_missing_items?: string[];
  remediation_state?: string;
  remediation_due_at?: string;
  open_remediation_items?: number;
  overdue_remediation_items?: number;
  offboarding_state?: string;
  offboarding_due_at?: string;
  data_deletion_state?: string;
  contract_start_at?: string;
  contract_renewal_at?: string;
  contract_termination_at?: string;
  contract_count: number;
  security_review_count: number;
  questionnaire_count: number;
  assurance_document_count: number;
  open_findings?: number;
  critical_findings?: number;
  high_findings?: number;
  evidence_items?: number;
  risk_queue_rank?: number;
  queue_reasons?: string[];
  next_actions?: GRCVendorAction[];
  close_actions?: GRCVendorCloseAction[];
  attributes?: Record<string, string>;
};

export type GRCRiskScoreFactor = {
  id: string;
  label: string;
  score: number;
  weight: number;
  reason?: string;
};

export type GRCVendorRiskScoring = {
  risk_score?: number;
  risk_score_level?: string;
  risk_score_source?: string;
  risk_tier?: string;
  review_cadence_days?: number;
  score_factors?: GRCRiskScoreFactor[];
};

export type GRCVendorFreshnessClock = {
  id: string;
  label: string;
  source: string;
  status: string;
  observed_at?: string;
  expires_at?: string;
  age_days?: number;
  stale_after_days?: number;
  reason?: string;
};

export type GRCVendorMonitoringSignal = {
  id: string;
  label: string;
  severity: string;
  source?: string;
  observed_at?: string;
  reason?: string;
};

export type GRCVendorAssessmentPosture = {
  assessment_state?: string;
  assessment_progress?: number;
  open_assessments?: number;
  completed_assessments?: number;
  assessment_types?: string[];
  questionnaire_state?: string;
  questionnaire_progress?: number;
  last_assessment_at?: string;
  next_assessment_at?: string;
};

export type GRCVendorMonitoringPosture = {
  monitoring_state?: string;
  monitoring_signals?: GRCVendorMonitoringSignal[];
  external_rating?: string;
  external_rating_updated_at?: string;
  last_material_change_at?: string;
};

export type GRCVendorCommercialPosture = {
  spend_amount?: string;
  spend_currency?: string;
  contract_value?: string;
  contract_currency?: string;
  renewal_notice_at?: string;
  renewal_state?: string;
  primary_contact?: string;
  business_unit?: string;
  cost_center?: string;
};

export type GRCVendorOperationalPosture = {
  exposure_level?: string;
  exposure_reasons?: string[];
  packet_state?: string;
  packet_ready_items?: string[];
  packet_missing_items?: string[];
  remediation_state?: string;
  remediation_due_at?: string;
  open_remediation_items?: number;
  overdue_remediation_items?: number;
  offboarding_state?: string;
  offboarding_due_at?: string;
  data_deletion_state?: string;
};

export type GRCVendorAction = {
  id: string;
  label: string;
  reason?: string;
  action_type?: string;
  target_state?: string;
  /** Backend queue priority. Higher numbers are handled first. */
  priority?: number;
};

export type GRCVendorCloseAction = {
  id: string;
  label: string;
  closes_when: string;
  finding_key?: string;
};

export type GRCVendorPacketRisk = {
  inherent_risk_level?: string;
  residual_risk_level?: string;
  risk_level: string;
  data_sensitivity?: string;
  access_level?: string;
  criticality?: string;
  subprocessor?: string;
  geography?: string;
  system_dependency?: string;
  drivers?: string[];
};

export type GRCVendorObligation = {
  id: string;
  label: string;
  status: string;
  source?: string;
  due_at?: string;
  expires_at?: string;
  reason?: string;
};

export type GRCVendorPacket = {
  version: string;
  vendor_urn: string;
  lifecycle?: {
    source_status?: string;
    lifecycle_state: string;
    lifecycle_reason?: string;
  };
  risk?: GRCVendorPacketRisk;
  risk_score?: GRCVendorRiskScoring;
  controls?: {
    dpa_status?: string;
    baa_status?: string;
    soc2_status?: string;
    iso27001_status?: string;
    security_review_status?: string;
    privacy_review_status?: string;
    document_status?: string;
  };
  assessments?: GRCVendorAssessmentPosture;
  monitoring?: GRCVendorMonitoringPosture;
  commercial?: GRCVendorCommercialPosture;
  operations?: GRCVendorOperationalPosture;
  evidence_freshness?: GRCVendorFreshnessClock[];
  review_history?: GRCVendorRelatedRecord[];
  obligations?: GRCVendorObligation[];
  owners?: GRCVendorRelatedRecord[];
  contacts?: GRCVendorRelatedRecord[];
  identifiers?: GRCVendorRelatedRecord[];
  fourth_parties?: GRCVendorRelatedRecord[];
  finding_counts?: {
    open_findings?: number;
    critical_findings?: number;
    high_findings?: number;
    evidence_items?: number;
  };
  next_actions?: GRCVendorAction[];
  close_actions?: GRCVendorCloseAction[];
};

export type GRCVendorDiscovery = {
  urn: string;
  discovery_id?: string;
  name: string;
  normalized_name?: string;
  source_id?: string;
  source_ids?: string[];
  runtime_id?: string;
  provider?: string;
  source_status: string;
  decision_state: string;
  category?: string;
  website_url?: string;
  confidence_score?: number;
  discovery_reason?: string;
  first_observed_at?: string;
  last_observed_at?: string;
  linked_vendor_urn?: string;
  decision_reason?: string;
  decision_updated_by?: string;
  decision_updated_at?: string;
  signals?: GRCVendorDiscoverySignal[];
  attributes?: Record<string, string>;
};

export type GRCVendorDiscoverySignal = {
  id: string;
  label: string;
  source_id?: string;
  runtime_id?: string;
  entity_type?: string;
  entity_urn?: string;
  confidence_score?: number;
  observed_at?: string;
  reason?: string;
  attributes?: Record<string, string>;
};

export type GRCVendorSummary = {
  total_vendors: number;
  active_vendors: number;
  high_risk_vendors: number;
  owner_missing_vendors: number;
  review_overdue_vendors: number;
  review_due_soon_vendors: number;
  review_not_scheduled: number;
  risk_queue_vendors?: number;
  stale_evidence_vendors?: number;
  restricted_vendors?: number;
  critical_tier_vendors?: number;
  assessment_due_vendors?: number;
  monitoring_alert_vendors?: number;
  renewal_due_vendors?: number;
  packet_blocked_vendors?: number;
  high_exposure_vendors?: number;
  remediation_due_vendors?: number;
  offboarding_due_vendors?: number;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  evidence_items: number;
};

export type GRCVendorDiscoverySummary = {
  total_discoveries: number;
  discovered: number;
  approved: number;
  rejected: number;
  ignored: number;
  linked: number;
  source_count?: number;
  evidence_signals?: number;
};

export type GRCVendorDiscoverySourceSummary = {
  source_id: string;
  provider?: string;
  runtime_id?: string;
  status?: string;
  freshness?: string;
  total: number;
  discovered: number;
  approved?: number;
  rejected?: number;
  ignored?: number;
  linked?: number;
  failed?: number;
  stale?: number;
  cursor_pending?: number;
  sync_lag_seconds?: number;
  last_error?: string;
  last_synced_at?: string;
};

export type GRCVendorDiscoveryDecision = {
  tenant_id: string;
  discovery_urn: string;
  source_id?: string;
  decision_event_id?: string;
  version?: number;
  decision: string;
  reason?: string;
  linked_vendor_urn?: string;
  updated_by?: string;
  attributes?: Record<string, string>;
  created_at: string;
  updated_at: string;
};

export type GRCVendorDiscoveryDecisionEvent = {
  id: string;
  tenant_id: string;
  discovery_urn: string;
  source_id?: string;
  decision: string;
  reason?: string;
  linked_vendor_urn?: string;
  updated_by?: string;
  attributes?: Record<string, string>;
  version: number;
  supersedes_event_id?: string;
  created_at: string;
};

export type GRCVendorRelatedRecord = {
  urn: string;
  entity_type: string;
  label: string;
  source_id?: string;
  runtime_id?: string;
  relation?: string;
  attributes?: Record<string, string>;
};

export type GRCVendorRelationships = {
  contracts?: GRCVendorRelatedRecord[];
  security_reviews?: GRCVendorRelatedRecord[];
  security_questionnaires?: GRCVendorRelatedRecord[];
  assurance_documents?: GRCVendorRelatedRecord[];
  assessments?: GRCVendorRelatedRecord[];
  owners?: GRCVendorRelatedRecord[];
  hosts?: GRCVendorRelatedRecord[];
  aliases?: GRCVendorRelatedRecord[];
  contacts?: GRCVendorRelatedRecord[];
  fourth_parties?: GRCVendorRelatedRecord[];
};

export type GRCVendorsResponse = {
  summary?: GRCVendorSummary;
  meta?: GRCListMeta;
  vendors: GRCVendor[];
  generated_at: string;
};

export type GRCVendorCreateRequest = {
  tenant_id?: string;
  name: string;
  vendor_id?: string;
  source_id?: string;
  runtime_id?: string;
  provider?: string;
  status?: string;
  category?: string;
  website_url?: string;
  services_provided?: string;
  owner?: string;
  security_owner_user_id?: string;
  business_owner_user_id?: string;
  lifecycle_state?: string;
  review_state?: string;
  risk_level?: string;
  discovery_urn?: string;
  attributes?: Record<string, string>;
};

export type GRCVendorCreateResponse = {
  vendor: GRCVendor;
  generated_at: string;
};

export type GRCVendorActionRequest = {
  tenant_id?: string;
  action: "assign_owner" | "change_lifecycle" | "start_review" | string;
  owner?: string;
  lifecycle_state?: string;
  review_state?: string;
  reason?: string;
};

export type GRCVendorActionResponse = {
  action: string;
  vendor: GRCVendor;
  generated_at: string;
};

export type GRCVendorDetailResponse = {
  vendor: GRCVendor;
  relationships?: GRCVendorRelationships;
  packet?: GRCVendorPacket;
  graph?: GRCGraph;
  findings?: GRCFinding[];
  evidence?: GRCEvidence[];
  generated_at: string;
};

export type GRCQuestionnaireDirection = "customer_security_review" | "vendor_review" | string;
export type GRCQuestionnaireStatus = "intake" | "processing" | "needs_input" | "ready_for_approval" | "approved" | "rejected" | string;
export type GRCQuestionnaireAnswerState = "supported" | "needs_review" | "partial" | "blocked" | "not_applicable" | string;
export type GRCQuestionnaireReviewState = "ready" | "needs_review" | "blocked" | "approved" | "rejected" | string;

export type GRCQuestionnaireRunSummary = {
  total_runs: number;
  customer_runs: number;
  vendor_runs: number;
  due_runs: number;
  blocked_answers: number;
  review_answers: number;
  ready_answers: number;
  stale_evidence: number;
  missing_evidence: number;
  unassigned: number;
};

export type GRCQuestionnaireQuestion = {
  id: string;
  question: string;
  normalized_question?: string;
  section?: string;
  required_answer_format?: string;
  mapped_controls?: string[];
  required_evidence_slots?: string[];
  owner_id?: string;
  answer_state: GRCQuestionnaireAnswerState;
  review_state: GRCQuestionnaireReviewState;
};

export type GRCQuestionnaireEvidenceSlot = {
  id: string;
  label?: string;
  state: string;
  required: boolean;
  citation_ids?: string[];
  missing_reasons?: string[];
};

export type GRCQuestionnaireCitation = {
  id: string;
  label?: string;
  source?: string;
  resource_urn?: string;
  evidence_packet_id?: string;
  evidence_id?: string;
  evidence_type?: string;
  control_id?: string;
  freshness_status?: string;
  observed_at?: string;
  expires_at?: string;
};

export type GRCQuestionnaireRunEvidenceGap = {
  id: string;
  code: string;
  reason?: string;
  slot_id?: string;
  control_id?: string;
  evidence_packet_id?: string;
  review_state?: string;
};

export type GRCQuestionnaireFreshness = {
  status: string;
  observed_at?: string;
  expires_at?: string;
  reason?: string;
};

export type GRCQuestionnaireRunAnswer = {
  id: string;
  question_id: string;
  question?: string;
  draft_answer?: string;
  answer_state: GRCQuestionnaireAnswerState;
  review_state: GRCQuestionnaireReviewState;
  confidence?: string;
  confidence_score?: number;
  controls?: string[];
  evidence_slots?: GRCQuestionnaireEvidenceSlot[];
  citations?: GRCQuestionnaireCitation[];
  missing_evidence?: GRCQuestionnaireRunEvidenceGap[];
  conflicts?: GRCQuestionnaireRunEvidenceGap[];
  freshness: GRCQuestionnaireFreshness;
  source_answer_id?: string;
  reviewer_decision?: string;
  reviewer_reason?: string;
  attributes?: Record<string, string>;
};

export type GRCQuestionnaireAssignment = {
  id: string;
  question_id?: string;
  gap_id?: string;
  slot_id?: string;
  team?: string;
  owner_id?: string;
  status: string;
  reason?: string;
  due_at?: string;
  created_at?: string;
  updated_at?: string;
};

export type GRCQuestionnaireDecision = {
  id: string;
  question_id?: string;
  actor_id?: string;
  decision: string;
  reason?: string;
  created_at?: string;
};

export type GRCQuestionnaireComment = {
  id: string;
  question_id?: string;
  actor_id?: string;
  body: string;
  created_at?: string;
};

export type GRCQuestionnaireTimelineEvent = {
  id: string;
  event_type: string;
  actor_id?: string;
  summary?: string;
  attributes?: Record<string, string>;
  created_at?: string;
};

export type GRCQuestionnaireRunEvent = {
  id: string;
  tenant_id: string;
  run_id: string;
  event_type: string;
  actor_id?: string;
  summary?: string;
  payload?: Record<string, string>;
  version: number;
  created_at: string;
};

export type GRCQuestionnaireRun = {
  id: string;
  run_id: string;
  tenant_id?: string;
  title: string;
  direction: GRCQuestionnaireDirection;
  requester?: string;
  customer_name?: string;
  vendor_urn?: string;
  vendor_id?: string;
  source_filename?: string;
  source_format?: string;
  status: GRCQuestionnaireStatus;
  owner_id?: string;
  assigned_team?: string;
  decision?: string;
  decision_reason?: string;
  due_at?: string;
  created_at: string;
  updated_at: string;
  question_count: number;
  answer_count: number;
  ready_answer_count: number;
  blocked_answer_count: number;
  review_answer_count: number;
  missing_evidence_count: number;
  stale_evidence_count: number;
  unassigned_count: number;
  questions?: GRCQuestionnaireQuestion[];
  answers?: GRCQuestionnaireRunAnswer[];
  assignments?: GRCQuestionnaireAssignment[];
  decisions?: GRCQuestionnaireDecision[];
  comments?: GRCQuestionnaireComment[];
  timeline?: GRCQuestionnaireTimelineEvent[];
  attributes?: Record<string, string>;
};

export type GRCQuestionnaireRunsResponse = {
  summary?: GRCQuestionnaireRunSummary;
  runs: GRCQuestionnaireRun[];
  generated_at: string;
};

export type GRCQuestionnaireRunResponse = {
  run: GRCQuestionnaireRun;
  events?: GRCQuestionnaireRunEvent[];
  generated_at: string;
};

export type GRCQuestionnaireVendorLinkRequest = {
  tenant_id?: string;
  vendor_urn?: string;
  vendor_id?: string;
  reason?: string;
  unlink?: boolean;
};

export type GRCVendorDiscoveriesResponse = {
  summary?: GRCVendorDiscoverySummary;
  meta?: GRCListMeta;
  source_summaries?: GRCVendorDiscoverySourceSummary[];
  discoveries: GRCVendorDiscovery[];
  decisions?: GRCVendorDiscoveryDecision[];
  decision_events?: GRCVendorDiscoveryDecisionEvent[];
  generated_at: string;
};

export type GRCVendorDiscoverySyncRequest = {
  tenant_id?: string;
  source_id?: string;
};

export type GRCVendorDiscoverySyncResponse = {
  status: string;
  source_id?: string;
  source_summaries?: GRCVendorDiscoverySourceSummary[];
  generated_at: string;
};

export type GRCVendorRiskVendor = GRCVendor;
export type GRCVendorRiskSummary = GRCVendorSummary;
export type GRCVendorRiskRelatedRecord = GRCVendorRelatedRecord;
export type GRCVendorRiskRelationships = GRCVendorRelationships;
export type GRCVendorRiskVendorsResponse = GRCVendorsResponse;
export type GRCVendorRiskDetailResponse = GRCVendorDetailResponse;

export type GRCInventoryCategory = {
  id: string;
  label: string;
  surface?: GRCInventorySurface;
  entity_types: string[];
  count: number;
};

export type GRCInventorySurface = "asset" | "component" | "signal" | "alias" | "raw_record" | "all" | string;
export type GRCInventoryReviewState = "baseline" | "needs_review" | "reported_issue" | "out_of_scope" | string;
export type GRCInventoryAccountabilityState = "not_required" | "known" | "candidate" | "required_missing" | "disputed" | string;

export type GRCInventoryReviewReason = {
  code: string;
  label: string;
};

export type GRCInventoryReviewDisposition = {
  state: GRCInventoryReviewState;
  label: string;
  detail?: string;
  reasons?: GRCInventoryReviewReason[];
};

export type GRCInventoryOwnerCandidate = {
  principal: string;
  confidence?: string;
  source?: string;
};

export type GRCInventoryAccountability = {
  state: GRCInventoryAccountabilityState;
  label: string;
  principal?: string;
  candidates?: GRCInventoryOwnerCandidate[];
  reasons?: GRCInventoryReviewReason[];
};

export type GRCInventoryAsset = {
  urn: string;
  entity_type: string;
  surface?: GRCInventorySurface;
  label: string;
  source_id?: string;
  runtime_id?: string;
  risk_score?: number;
  risk_level?: string;
  risk_reasons?: string[];
  scope_state?: "in_scope" | "out_of_scope" | string;
  scope_reason?: string;
  scope_updated_at?: string;
  asset_report_count?: number;
  latest_asset_report_status?: string;
  latest_asset_report_reason?: string;
  latest_asset_report_updated_at?: string;
  review_disposition?: GRCInventoryReviewDisposition;
  accountability?: GRCInventoryAccountability;
  attributes?: Record<string, string>;
};

export type GRCInventoryAssetReport = {
  id: string;
  tenant_id: string;
  asset_urn: string;
  source_id?: string;
  reason: string;
  reporter?: string;
  triage_status: "submitted" | "in_triage" | "accepted" | "rejected" | "resolved" | string;
  triage_reason?: string;
  triaged_by?: string;
  triaged_at?: string;
  attributes?: Record<string, string>;
  created_at: string;
  updated_at: string;
};

export type GRCInventoryScopeRecord = {
  tenant_id: string;
  asset_urn: string;
  source_id?: string;
  scope_state: "in_scope" | "out_of_scope" | string;
  reason?: string;
  updated_by?: string;
  attributes?: Record<string, string>;
  created_at?: string;
  updated_at?: string;
};

export type GRCInventoryAccountabilityUpdateResponse = {
  scope: GRCInventoryScopeRecord;
  generated_at: string;
};

export type GRCInventorySummary = {
  total_assets: number;
  in_scope_assets: number;
  out_of_scope_assets: number;
  high_risk_assets: number;
  unassigned_assets: number;
  baseline_assets?: number;
  needs_review_assets?: number;
  owner_required_assets?: number;
  accountable_assets?: number;
  reported_issue_assets?: number;
  org_groups: number;
  public_assets: number;
  scoped_coverage_pct: number;
  assigned_coverage_pct: number;
  surface_counts?: Record<string, number>;
};

export type GRCInventoryCategoriesResponse = {
  categories: GRCInventoryCategory[];
  generated_at: string;
};

export type GRCInventoryAssetsResponse = {
  assets: GRCInventoryAsset[];
  summary?: GRCInventorySummary;
  generated_at: string;
};

export type GRCInventoryTest = {
  name: string;
  owner: string;
  status: string;
  due_at?: string;
  control_id?: string;
  framework?: string;
  finding_id?: string;
  finding_title?: string;
};

export type GRCInventoryVulnerability = {
  id: string;
  title: string;
  severity: string;
  status: string;
  source_id?: string;
  finding_id?: string;
};

export type GRCInventoryTimelineEvent = {
  at?: string;
  kind: string;
  title: string;
  description?: string;
  status?: string;
};

export type GRCInventoryAction = {
  title: string;
  description: string;
  priority: string;
  href?: string;
};

export type GRCInventoryAssetDetail = {
  asset: GRCInventoryAsset;
  graph?: GRCGraph;
  findings: GRCFinding[];
  evidence: GRCEvidence[];
  controls: GRCControl[];
  tests: GRCInventoryTest[];
  vulnerabilities: GRCInventoryVulnerability[];
  asset_reports?: GRCInventoryAssetReport[];
  timeline?: GRCInventoryTimelineEvent[];
  actions?: GRCInventoryAction[];
  generated_at: string;
};

export type GRCResourceScopeRuntime = {
  runtime_id: string;
  tenant_id?: string;
  owner?: string;
  family?: string;
  status: string;
};

export type GRCResourceScopeResponse = {
  source_id: string;
  runtimes: GRCResourceScopeRuntime[];
  resources: GRCInventoryAsset[];
  summary?: GRCInventorySummary;
  generated_at: string;
};

export type GRCDashboard = {
  summary: GRCSummary;
  findings: GRCFinding[];
  controls: GRCControl[];
  evidence: GRCEvidence[];
  connectors: GRCConnector[];
  source_summaries?: GRCSourceRuntimeHealthSummary[];
  coverage_blind_spots?: GRCCoverageRecord[];
  coverage_summaries?: GRCCoverageSummary[];
  /** @deprecated Use coverage_summaries and route navigation instead. */
  product_areas?: GRCProductAreaResponse[];
  generated_at: string;
};

export type GRCTrendPoint = {
  date: string;
  opened: number;
  opened_critical: number;
  opened_high: number;
  closed: number;
  closed_critical: number;
  closed_high: number;
  closed_sla_breached: number;
  avg_time_to_close_seconds: number;
  open_total: number;
};

export type GRCTrendAgingBucket = {
  id: string;
  label: string;
  min_days: number;
  max_days?: number;
  count: number;
};

export type GRCTrendTargets = {
  mttr_seconds?: number;
  backlog?: number;
  sla_days?: number;
};

export type GRCTrendComparison = {
  previous_start: string;
  previous_end: string;
  opened_delta: number;
  closed_delta: number;
  current_open_delta: number;
  avg_time_to_close_seconds_delta: number;
  closed_sla_breached_delta: number;
};

export type GRCTrendSummary = {
  total_opened: number;
  total_closed: number;
  net: number;
  current_open: number;
  peak_open: number;
  opened_critical: number;
  opened_high: number;
  closed_critical: number;
  closed_high: number;
  closed_sla_breached: number;
  avg_time_to_close_seconds: number;
  closed_sla_breached_rate?: number;
};

export type GRCTrendAccuracy = {
  status_history: string;
  caveat: string;
};

export type GRCTrends = {
  interval: string;
  start: string;
  end: string;
  points: GRCTrendPoint[];
  aging_buckets?: GRCTrendAgingBucket[];
  summary?: GRCTrendSummary;
  targets?: GRCTrendTargets;
  comparison?: GRCTrendComparison;
  accuracy?: GRCTrendAccuracy;
  generated_at: string;
};

export type GRCAuditPacket = {
  id: string;
  finding: GRCFinding;
  evidence: GRCEvidence[];
  graph?: GRCGraph;
  controls?: GRCControlRef[];
  recommended_action: string;
  metadata?: GRCReportMetadata;
  generated_at: string;
};

export type GRCControlPacketProfile = {
  id: string;
  name?: string;
  description?: string;
};

export type GRCControlPostureSummary = {
  selection_id?: string;
  total: number;
  by_status: Record<string, number>;
};

export type GRCControlPacketFinding = {
  id?: string;
  rule_id?: string;
  title?: string;
  status?: string;
  severity?: string;
  first_observed_at?: string;
  last_observed_at?: string;
};

export type GRCControlEvidenceExpectationPosture = {
  id: string;
  title?: string;
  description?: string;
  type?: string;
  required: boolean;
  status: string;
  quality?: string;
  evidence_ids?: string[];
  stale_evidence_ids?: string[];
  freshness_sla?: string;
};

export type GRCControlEvidencePacketItem = {
  id?: string;
  rule_id?: string;
  evidence_type?: string;
  status?: string;
  quality?: string;
  source?: string;
  observed_at?: string;
  expires_at?: string;
  manual?: boolean;
};

export type GRCControlEvidenceReadiness = {
  score: number;
  rating: string;
  summary?: string;
  open_findings?: number;
  evidence_items?: number;
  required_expectations?: number;
  missing_evidence?: number;
  stale_evidence?: number;
  manual_evidence?: number;
};

export type GRCControlPacketControl = {
  selection_id?: string;
  control: {
    framework_id?: string;
    framework_name: string;
    framework_version?: string;
    framework_lifecycle?: "active" | "upcoming" | string;
    family_id?: string;
    family_name?: string;
    control_id: string;
    title?: string;
    owner_domain?: string;
  };
  status: string;
  reasons?: string[];
  tags?: string[];
  mapped_rules?: string[];
  findings?: GRCControlPacketFinding[];
  evidence: {
    summary?: {
      evidence_ids?: string[];
      missing_evidence_ids?: string[];
      stale_evidence_ids?: string[];
      manual_evidence_ids?: string[];
      evidence_expectation_ids?: string[];
      required_evidence_ids?: string[];
      freshness_sla?: string;
      latest_evidence_at?: string;
      evidence_due_at?: string;
    };
    expectations?: GRCControlEvidenceExpectationPosture[];
    items?: GRCControlEvidencePacketItem[];
  };
  audit_readiness: GRCControlEvidenceReadiness;
  overrides?: {
    exception_ids?: string[];
    not_applicable_ids?: string[];
  };
};

export type GRCControlEvidencePacket = {
  version: string;
  selection_id?: string;
  generated_at: string;
  summary: GRCControlPostureSummary;
  controls: GRCControlPacketControl[];
};

export type GRCControlEvidencePacketResponse = {
  profile: GRCControlPacketProfile;
  packet: GRCControlEvidencePacket;
  controls: GRCControl[];
  metadata?: GRCReportMetadata;
  generated_at: string;
};

export type GRCCustomControlEvidencePacketResponse = GRCControlEvidencePacketResponse & {
  files?: Record<string, string>;
};

export type GRCEntityImpact = {
  entity_urn: string;
  graph?: GRCGraph;
  findings: GRCFinding[];
  generated_at: string;
};

export type GRCPolicyControlRef = {
  urn: string;
  control_id?: string;
  framework?: string;
  title?: string;
};

export type GRCPolicyEvidenceRef = {
  urn: string;
  entity_type?: string;
  title?: string;
  document_id?: string;
  evidence_type?: string;
};

export type GRCPolicyTargetRef = {
  urn: string;
  entity_type?: string;
  label: string;
};

export type GRCPolicyAssignment = {
  target_urn: string;
  target_type?: string;
  label: string;
  scope?: string;
};

export type GRCPolicyAcceptanceSummary = {
  accepted: number;
  overdue: number;
  pending: number;
  total: number;
};

export type GRCPolicyExceptionSummary = {
  active: number;
  expiring: number;
  expired: number;
};

export type GRCPolicyLifecycleEvent = {
  id: string;
  urn: string;
  policy_id?: string;
  policy_version_id?: string;
  record_urn?: string;
  record_type?: string;
  event_kind?: string;
  action?: string;
  status?: string;
  actor?: string;
  reason?: string;
  occurred_at?: string;
  attributes?: Record<string, string>;
};

export type GRCPolicyLifecycleAction = {
  id: string;
  action: string;
  label: string;
  policy_id?: string;
  policy?: string;
  policy_version_id?: string;
  gap_id?: string;
  gap_ids?: string[];
  gap_state?: string;
  record_urn?: string;
  record_type?: string;
  status?: string;
  owner?: string;
  due_at?: string;
  reason?: string;
  date_field?: "due_at" | "effective_at" | "expires_at" | string;
  value_field?: string;
  value_label?: string;
  attributes?: Record<string, string>;
};

export type GRCPolicyLifecycleActionDefinition = {
  id: string;
  label: string;
  event_kind: string;
  record_type: string;
  status: string;
  requires_policy_id?: boolean;
  requires_version_id?: boolean;
  requires_record_id?: boolean;
  requires_gap_id?: boolean;
  date_field?: string;
  value_field?: string;
  value_label?: string;
};

export type GRCPolicyLifecycleActionRequest = {
  action: string;
  tenant_id?: string;
  source_id?: string;
  runtime_id?: string;
  policy_id?: string;
  policy_version_id?: string;
  template_id?: string;
  gap_id?: string;
  gap_ids?: string[];
  gap_state?: string;
  record_id?: string;
  record_urn?: string;
  title?: string;
  version?: string;
  status?: string;
  actor_user_id?: string;
  reason?: string;
  due_at?: string;
  effective_at?: string;
  expires_at?: string;
  idempotency_key?: string;
  assignees?: string[];
  approvers?: string[];
  reviewers?: string[];
  control_ids?: string[];
  evidence_urns?: string[];
  attributes?: Record<string, string>;
};

export type GRCPolicyLifecycleActionResponse = {
  action: string;
  status: string;
  event_id: string;
  event_kind: string;
  schema_ref: string;
  attributes?: Record<string, string>;
  generated_at: string;
};

export type GRCUploadEvent = {
  event_id: string;
  event_kind: string;
  schema_ref: string;
  record_id?: string;
  record_urn?: string;
  legacy_record_urn?: string;
};

export type GRCUploadStructuredField = {
  key?: string;
  label?: string;
  value?: string;
};

export type GRCUploadJobRef = {
  id?: string;
  status?: string;
};

export type GRCUploadParsedChunk = {
  index?: number;
  page?: number;
  text_preview?: string;
};

export type GRCUploadParseArtifact = {
  provider?: string;
  provider_file_id?: string;
  parse_id?: string;
  status?: string;
  text_preview?: string;
  chunk_count?: number;
  page_count?: number;
  chunks?: GRCUploadParsedChunk[];
};

export type GRCUploadExtractedField = {
  name?: string;
  value?: string;
  source?: string;
  confidence?: number;
  source_snippet?: string;
  review_state?: string;
};

export type GRCUploadReviewItem = {
  id?: string;
  state?: string;
  record_kind?: string;
  record_id?: string;
  field?: string;
  value?: string;
  reason?: string;
  action?: string;
  source_snippet?: string;
};

export type GRCUploadQualityCheck = {
  id?: string;
  status?: string;
  message?: string;
  action?: string;
};

export type GRCUploadEntityMatchHint = {
  record_kind?: string;
  record_id?: string;
  match_key?: string;
  strategy?: string;
  candidate_state?: string;
};

export type GRCUploadResponse = {
  upload_id: string;
  status?: string;
  target: "policy" | "vendor" | string;
  file_name: string;
  content_type?: string;
  file_sha256?: string;
  reducto_file_id?: string;
  reducto_parse_id?: string;
  parse_status?: string;
  text_preview?: string;
  chunk_count?: number;
  page_count?: number;
  review_state?: string;
  quality_status?: string;
  replayable?: boolean;
  job?: GRCUploadJobRef;
  parse_artifact?: GRCUploadParseArtifact;
  extracted_fields?: GRCUploadExtractedField[];
  review_items?: GRCUploadReviewItem[];
  quality_checks?: GRCUploadQualityCheck[];
  entity_match_hints?: GRCUploadEntityMatchHint[];
  structure_status?: string;
  structure_schema?: string;
  structured_summary?: string;
  structured_fields?: GRCUploadStructuredField[];
  projection_status?: string;
  projection_failures?: number;
  events: GRCUploadEvent[];
  generated_at: string;
};

export type GRCUploadReplayResponse = {
  upload_id?: string;
  status?: string;
  events_found?: number;
  events_projected?: number;
  entities_projected?: number;
  links_projected?: number;
  projection_failures?: number;
};

export type GRCPolicyVersionDiff = {
  policy_id?: string;
  policy_title?: string;
  from_version_id?: string;
  from_version?: string;
  to_version_id?: string;
  to_version?: string;
  status?: string;
  change_summary?: string;
  diff_summary?: string;
  diff_url?: string;
  created_at?: string;
  approved_at?: string;
};

export type GRCPolicyReminderPlan = {
  id: string;
  policy_id?: string;
  policy?: string;
  record_urn?: string;
  record_type?: string;
  action: string;
  owner?: string;
  recipients?: string[];
  due_at?: string;
  escalate_at?: string;
  channel?: string;
  reason?: string;
};

export type GRCPolicyTemplate = {
  id: string;
  urn: string;
  title: string;
  status?: string;
  category?: string;
  frameworks?: string[];
  owner?: string;
  controls?: GRCPolicyControlRef[];
  evidence?: GRCPolicyEvidenceRef[];
  attributes?: Record<string, string>;
};

export type GRCPolicyDocumentRef = {
  id?: string;
  urn: string;
  title: string;
  reference?: string;
};

export type GRCPolicyRiskRef = {
  id?: string;
  urn: string;
  title: string;
  status?: string;
};

export type GRCPolicyDocument = {
  id: string;
  urn: string;
  title: string;
  document_type?: string;
  document_class?: string;
  status?: string;
  owner?: string;
  version?: string;
  review_cadence?: string;
  next_review_due_at?: string;
  approved_at?: string;
  effective_at?: string;
  source_url?: string;
  policies?: GRCPolicyDocumentRef[];
  risks?: GRCPolicyRiskRef[];
  controls?: GRCPolicyControlRef[];
  evidence?: GRCPolicyEvidenceRef[];
  attributes?: Record<string, string>;
};

export type GRCPolicyRiskRegisterItem = {
  id: string;
  urn: string;
  title: string;
  status?: string;
  owner?: string;
  category?: string;
  inherent_risk?: string;
  residual_risk?: string;
  likelihood?: string;
  impact?: string;
  treatment?: string;
  review_due_at?: string;
  treatment_due_at?: string;
  source_document_id?: string;
  source_document_title?: string;
  policies?: GRCPolicyDocumentRef[];
  controls?: GRCPolicyControlRef[];
  evidence?: GRCPolicyEvidenceRef[];
  attributes?: Record<string, string>;
};

export type GRCPolicyGovernanceGap = {
  id: string;
  subject: string;
  subject_id?: string;
  title: string;
  status?: string;
  owner?: string;
  severity: string;
  reason: string;
  action: string;
  action_id?: string;
  rule_id?: string;
  gap_state?: string;
  due_at?: string;
  state_reason?: string;
  state_updated_at?: string;
  last_action?: string;
  last_actor?: string;
  missing_fields?: string[];
  source_fields?: Record<string, string>;
  trace?: GRCPolicyGovernanceGapTrace[];
  policy_id?: string;
  document_id?: string;
  risk_id?: string;
};

export type GRCPolicyGovernanceGapTrace = {
  event_id?: string;
  action?: string;
  actor?: string;
  status?: string;
  occurred_at?: string;
  reason?: string;
};

export type GRCPolicyGovernanceRule = {
  id: string;
  profile: string;
  subject: string;
  field: string;
  label: string;
  severity: string;
  required?: boolean;
  action_id: string;
  action: string;
  applies_to?: string[];
  confidence?: string;
};

export type GRCPolicyGovernanceGapRollup = {
  key: string;
  count: number;
};

export type GRCPolicyGovernanceGapRollups = {
  by_state?: GRCPolicyGovernanceGapRollup[];
  by_owner?: GRCPolicyGovernanceGapRollup[];
  by_severity?: GRCPolicyGovernanceGapRollup[];
  by_subject?: GRCPolicyGovernanceGapRollup[];
};

export type GRCPolicyVersion = {
  id: string;
  urn: string;
  policy_id?: string;
  title: string;
  version?: string;
  status?: string;
  author?: string;
  owner?: string;
  created_at?: string;
  approved_at?: string;
  effective_at?: string;
  change_summary?: string;
  diff_summary?: string;
  diff_url?: string;
  controls?: GRCPolicyControlRef[];
  evidence?: GRCPolicyEvidenceRef[];
  assignments?: GRCPolicyAssignment[];
};

export type GRCPolicyApproval = {
  id: string;
  urn: string;
  policy_id?: string;
  policy_version_id?: string;
  step?: string;
  status?: string;
  approvers?: string[];
  requested_by?: string;
  requested_at?: string;
  approved_at?: string;
  due_at?: string;
};

export type GRCPolicyAcceptance = {
  id: string;
  urn: string;
  policy_id?: string;
  policy_version_id?: string;
  person?: string;
  assignees?: string[];
  status?: string;
  accepted_at?: string;
  due_at?: string;
};

export type GRCPolicyReview = {
  id: string;
  urn: string;
  policy_id?: string;
  policy_version_id?: string;
  status?: string;
  cadence?: string;
  owner?: string;
  reviewers?: string[];
  review_due_at?: string;
  reviewed_at?: string;
};

export type GRCPolicyException = {
  id: string;
  urn: string;
  policy_id?: string;
  policy_version_id?: string;
  title: string;
  status?: string;
  owner?: string;
  approvers?: string[];
  targets?: GRCPolicyTargetRef[];
  controls?: GRCPolicyControlRef[];
  reason?: string;
  approved_at?: string;
  expires_at?: string;
};

export type GRCPolicyReminder = {
  id: string;
  urn: string;
  policy_id?: string;
  policy_version_id?: string;
  title: string;
  status?: string;
  channel?: string;
  recipients?: string[];
  escalated_to?: string[];
  due_at?: string;
  sent_at?: string;
};

export type GRCPolicyLifecycleMapping = {
  policy_id?: string;
  policy_title?: string;
  source_urn: string;
  source_type: string;
  target: GRCPolicyTargetRef;
  controls?: GRCPolicyControlRef[];
  evidence?: GRCPolicyEvidenceRef[];
};

export type GRCPolicyLifecycleWork = {
  id: string;
  policy_id?: string;
  policy?: string;
  record_urn: string;
  type: string;
  status?: string;
  owner?: string;
  due_at?: string;
  action: string;
};

export type GRCPolicyDocumentWork = {
  id: string;
  document_id?: string;
  document?: string;
  record_urn: string;
  type: string;
  status?: string;
  owner?: string;
  due_at?: string;
  action: string;
  policy_id?: string;
  risk_id?: string;
};

export type GRCPolicyLifecyclePolicy = {
  id: string;
  urn: string;
  title: string;
  status?: string;
  owner?: string;
  reviewer?: string;
  review_cadence?: string;
  next_review_due_at?: string;
  latest_version?: string;
  version_status?: string;
  approval_status?: string;
  acceptance_summary: GRCPolicyAcceptanceSummary;
  exception_summary: GRCPolicyExceptionSummary;
  versions?: GRCPolicyVersion[];
  approvals?: GRCPolicyApproval[];
  attestations?: GRCPolicyAcceptance[];
  reviews?: GRCPolicyReview[];
  exceptions?: GRCPolicyException[];
  events?: GRCPolicyLifecycleEvent[];
  actions?: GRCPolicyLifecycleAction[];
  version_diffs?: GRCPolicyVersionDiff[];
  reminder_plan?: GRCPolicyReminderPlan[];
  assignments?: GRCPolicyAssignment[];
  controls?: GRCPolicyControlRef[];
  evidence?: GRCPolicyEvidenceRef[];
  attributes?: Record<string, string>;
};

export type GRCPolicyLifecycleSummary = {
  policies: number;
  templates: number;
  lifecycle_events?: number;
  policy_documents?: number;
  risk_register_items?: number;
  draft_versions: number;
  draft_documents?: number;
  pending_approvals: number;
  overdue_reviews: number;
  documents_due_for_review?: number;
  governance_gaps?: number;
  policy_document_gaps?: number;
  risk_register_gaps?: number;
  open_governance_gaps?: number;
  in_progress_governance_gaps?: number;
  acknowledged_governance_gaps?: number;
  snoozed_governance_gaps?: number;
  accepted_governance_gaps?: number;
  resolved_governance_gaps?: number;
  high_governance_gaps?: number;
  open_exceptions: number;
  expiring_exceptions: number;
  open_risks?: number;
  high_risks?: number;
  attestation_coverage_pct: number;
  overdue_attestations: number;
  next_reminders?: number;
  mapped_controls: number;
  evidence_items: number;
};

export type GRCPolicyLifecycleResponse = {
  summary: GRCPolicyLifecycleSummary;
  templates: GRCPolicyTemplate[];
  policies: GRCPolicyLifecyclePolicy[];
  documents?: GRCPolicyDocument[];
  risk_register?: GRCPolicyRiskRegisterItem[];
  governance_gaps?: GRCPolicyGovernanceGap[];
  governance_rules?: GRCPolicyGovernanceRule[];
  governance_gap_rollups?: GRCPolicyGovernanceGapRollups;
  work_queue: GRCPolicyLifecycleWork[];
  document_work_queue?: GRCPolicyDocumentWork[];
  reminders: GRCPolicyReminder[];
  events?: GRCPolicyLifecycleEvent[];
  available_actions?: GRCPolicyLifecycleActionDefinition[];
  version_diffs?: GRCPolicyVersionDiff[];
  reminder_plan?: GRCPolicyReminderPlan[];
  mappings: GRCPolicyLifecycleMapping[];
  generated_at: string;
};

export const severityRank = (severity: string) => {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
      return 0;
    case "HIGH":
      return 1;
    case "MEDIUM":
      return 2;
    case "LOW":
      return 3;
    default:
      return 4;
  }
};

export const riskLevelFromScore = (score?: number) => {
  const value = Number(score ?? 0);
  if (value >= 85) return "critical";
  if (value >= 70) return "high";
  if (value >= 40) return "medium";
  if (value > 0) return "low";
  return "unknown";
};

export const riskSort = (left: GRCFinding, right: GRCFinding) => {
  const riskDelta = (right.risk_score ?? 0) - (left.risk_score ?? 0);
  if (riskDelta !== 0) return riskDelta;
  const severityDelta = severityRank(left.severity) - severityRank(right.severity);
  if (severityDelta !== 0) return severityDelta;
  return (right.last_observed_at ?? "").localeCompare(left.last_observed_at ?? "");
};

export const averageRiskScore = (findings: GRCFinding[]) => {
  const scored = findings.filter((finding) => typeof finding.risk_score === "number");
  if (scored.length === 0) return 0;
  return Math.round(scored.reduce((sum, finding) => sum + (finding.risk_score ?? 0), 0) / scored.length);
};

export const displayDate = (value?: string) => {
  if (!value) {
    return "—";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
};

export const displayDurationSeconds = (value?: number) => {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "—";
  }
  const seconds = Math.max(0, value);
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  }
  const minutes = seconds / 60;
  if (minutes < 60) {
    return `${Math.round(minutes)}m`;
  }
  const hours = minutes / 60;
  if (hours < 48) {
    return `${hours < 10 ? hours.toFixed(1) : Math.round(hours)}h`;
  }
  const days = hours / 24;
  return `${days < 10 ? days.toFixed(1) : Math.round(days)}d`;
};

const humanizedAcronyms: Record<string, string> = {
  api: "API",
  aws: "AWS",
  cli: "CLI",
  gcp: "GCP",
  gsm: "GSM",
  iam: "IAM",
  id: "ID",
  oidc: "OIDC",
  sso: "SSO",
  url: "URL",
};

export const humanize = (value?: string) =>
  (value || "unknown")
    .replace(/^FINDING_STATUS_/, "")
    .replace(/[_-]+/g, " ")
    .toLowerCase()
    .replace(/\b\w+\b/g, (word) => humanizedAcronyms[word] ?? `${word.charAt(0).toUpperCase()}${word.slice(1)}`);

export const shortEntity = (value?: string) => {
  if (!value) {
    return "—";
  }
  const parts = value.split(":").filter(Boolean);
  const tail = parts[parts.length - 1] ?? value;
  return tail.length > 42 ? `${tail.slice(0, 41)}…` : tail;
};

export const encodeEntityPath = (urn: string) => encodeURIComponent(urn);
