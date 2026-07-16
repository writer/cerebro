export type ConnectorCatalogEntry = {
  source_id: string;
  name?: string;
  display_name?: string;
  description?: string;
  emitted_kinds?: string[];
  status?: "available" | "connected" | "degraded" | "needs_attention" | string;
  catalog_status?: ConnectorCatalogStatus | string;
  classifier_output?: string;
  auth_model?: string;
  runtime_executable?: boolean;
  missing_features?: string[];
  catalog_categories?: string[];
  verification_endpoint?: string;
  resource_families?: ConnectorCatalogResourceFamily[];
  configured_runtimes?: number;
  healthy_runtimes?: number;
  needs_attention_runtimes?: number;
  connection_methods?: ConnectorConnectionMethodInput[];
  scope_options?: ConnectorScopeOption[];
  catalog_schema_version?: string;
  catalog_current_version?: number;
  catalog_source_path?: string;
  definition_origin?: string;
  readiness_stage?: ConnectorReadinessStage | string;
  integration_depth?: ConnectorIntegrationDepth;
  integration_level?: string;
  integration_score?: number;
  resource_family_count?: number;
  emitted_kind_count?: number;
  scope_option_count?: number;
  access_status?: ConnectorAccessStatus | string;
  access_reason?: string;
  setup_allowed?: boolean;
  requestable?: boolean;
  requestable_reason?: string;
  request_access_url?: string;
  request_access_action?: string;
  priority?: number;
  priority_tier?: "urgent" | "high" | "standard" | "backlog" | string;
  priority_reasons?: string[];
  catalog_path?: string;
  package_path?: string;
  missing_families?: string[];
  existing_references?: string[];
  search_queries?: string[];
  next_action?: string;
  has_provider_api_contract?: boolean;
  has_provider_api_mapping?: boolean;
  has_provider_api_proof?: boolean;
  provider_api_status?: string;
  provider_api_basis?: string;
  provider_api_verified_at?: string;
  provider_api_transport?: string;
  provider_api_auth?: string;
  provider_api_auth_mechanics?: string;
  provider_api_base_url?: string;
  provider_api_endpoint?: string;
  provider_api_spec_url?: string;
  provider_api_spec_kind?: string;
  provider_api_references?: string[];
  provider_api_auth_evidence?: string[];
  provider_api_scope_evidence?: string[];
  provider_api_mapped_families?: string[];
  provider_api_missing_families?: string[];
  provider_api_proof_score?: number;
  provider_api_proof_level?: string;
  provider_api_proof_gaps?: string[];
};

export type ConnectorLibraryPage = {
  total?: number;
  returned?: number;
  limit?: number;
  has_more?: boolean;
  next_cursor?: string;
};

export type ConnectorLibraryResponse = {
  connectors?: ConnectorCatalogEntry[];
  view?: string;
  page?: ConnectorLibraryPage;
  generated_at?: string;
  tenant_id?: string;
  runtime_store?: string;
  catalog_version?: string;
  catalog_source_commit?: string;
  credential_transport?: {
    available?: boolean;
    algorithm?: string;
    key_url?: string;
  };
  credential_vault?: {
    available?: boolean;
    detail?: string;
  };
  credential_stores?: ConnectorCredentialStore[];
};

export type ConnectorCatalogStatus =
  | "catalog_ready"
  | "generateable"
  | "needs_auth_extension"
  | "needs_bespoke_runtime";

export type ConnectorAccessStatus =
  | "available"
  | "catalog_only"
  | "restricted";

export type ConnectorReadinessStage =
  | "setup_enabled"
  | "api_restricted"
  | "sourcegen_ready"
  | "catalog_ready"
  | "auth_extension_required"
  | "runtime_required"
  | "runtime_unknown";

export type ConnectorCoverageControlRef = {
  framework_id?: string;
  framework_name?: string;
  control_id: string;
};

export type ConnectorCoverageDimension = {
  id?: string;
  dimension_id?: string;
  type?: string;
  dimension_type?: string;
  title?: string;
  label?: string;
  families?: string[];
  support?: string;
  support_level?: string;
  state?: string;
  high_value?: boolean;
  blind_spot?: boolean;
  warning?: string;
  known_unsupported_fields?: string[];
  notes?: string[];
  evidence_types?: string[];
  control_domains?: string[];
  control_refs?: ConnectorCoverageControlRef[];
  matched_control_refs?: ConnectorCoverageControlRef[];
  supported_runtime_families?: string[];
};

export type ConnectorIntegrationDepth = {
  level?: string;
  score?: number;
  auth_model?: string;
  resource_families?: number;
  emitted_kinds?: number;
  coverage_dimensions?: number;
  high_value_families?: number;
  projection_templates?: number;
  scope_options?: number;
  runtime_executable?: boolean;
  setup_enabled?: boolean;
};

export type ConnectorCatalogResourceFamily = {
  id: string;
  label?: string;
  path?: string;
  method?: string;
  record_selector?: string;
  id_field?: string;
  name_field?: string;
  event_kind?: string;
  schema_ref?: string;
  event?: {
    kind?: string;
    schema_ref?: string;
  };
  projection_template?: string;
  projection?: {
    template?: string;
    fields?: Record<string, string>;
  };
  coverage?: Array<string | ConnectorCoverageDimension>;
  high_value?: boolean;
};

export type ConnectorOperationsSummary = {
  status: "not_configured" | "healthy" | "needs_refresh" | "poor" | "bad" | string;
  status_reason?: string;
  top_issue?: string;
  total_connections?: number;
  healthy_connections?: number;
  needs_attention?: number;
  last_activity_at?: string;
  sync_frequency_seconds?: number;
  resource_types?: number;
  emitted_kinds?: number;
};

export type ConnectorConnectionSummary = {
  runtime_id: string;
  source_id: string;
  tenant_id?: string;
  family?: string;
  status?: string;
  graph_status?: string;
  contract_probe_state?: string;
  last_activity_at?: string;
  checkpoint_watermark?: string;
  watermark_lag_seconds?: number;
  records_accepted?: number;
  records_rejected?: number;
  entities_projected?: number;
  links_projected?: number;
  cursor_pending?: boolean;
  checkpoint_cursor_present?: boolean;
  next_action?: string;
  scope_policy?: ConnectorScopePolicy;
};

export type ConnectorActivity = {
  id: string;
  runtime_id: string;
  source_id: string;
  tenant_id?: string;
  family?: string;
  type: "sync" | "graph" | string;
  status: "success" | "failed" | "needs_refresh" | "running" | "incomplete" | string;
  title: string;
  description?: string;
  occurred_at?: string;
  duration_seconds?: number;
  records_accepted?: number;
  records_rejected?: number;
  entities_projected?: number;
  links_projected?: number;
  failure_class?: string;
};

export type ConnectorDiagnosticTimeline = {
  stage: "setup" | "preflight" | "source_sync" | "contract_probe" | "graph_projection" | "finding_evaluation" | string;
  stage_order?: number;
  status: "success" | "warning" | "failed" | "running" | "pending" | string;
  title: string;
  description?: string;
  occurred_at?: string;
  runtime_id?: string;
  correlation_id?: string;
  next_action?: string;
  failure_class?: string;
  records_accepted?: number;
  records_rejected?: number;
  entities_projected?: number;
  links_projected?: number;
  findings_evaluated?: number;
  findings_opened?: number;
  duration_seconds?: number;
};

export type ConnectorDetailResponse = {
  generated_at?: string;
  tenant_id?: string;
  connector?: ConnectorCatalogEntry;
  summary?: ConnectorOperationsSummary;
  connections?: ConnectorConnectionSummary[];
  activity?: ConnectorActivity[];
  diagnostic_timeline?: ConnectorDiagnosticTimeline[];
};

export type ConnectorActivityResponse = {
  generated_at?: string;
  tenant_id?: string;
  source_id?: string;
  activity?: ConnectorActivity[];
  diagnostic_timeline?: ConnectorDiagnosticTimeline[];
};

export type ConnectorCredentialKey = {
  key_id: string;
  algorithm: string;
  jwk: JsonWebKey;
};

export type ConnectorCredentialStatus = "pending" | "valid" | "invalid" | "revoked" | "rotating" | string;

export type ConnectorCredential = {
  id: string;
  tenant_id: string;
  source_id: string;
  runtime_id: string;
  credential_store_id: ConnectorCredentialStoreID | string;
  auth_method: ConnectorConnectionMethodID | string;
  status: ConnectorCredentialStatus;
  key_id: string;
  fields: string[];
  created_by?: string;
  updated_by?: string;
  revoked_by?: string;
  previous_credential_id?: string;
  created_at?: string;
  updated_at?: string;
  revoked_at?: string;
  last_used_at?: string;
  last_validated_at?: string;
};

export type ConnectorCredentialAuditEvent = {
  id: string;
  credential_id: string;
  tenant_id: string;
  source_id: string;
  runtime_id: string;
  event_type: "stored" | "rotated" | "revoked" | "used" | "validated" | string;
  actor?: string;
  status?: string;
  detail?: string;
  created_at?: string;
};

export type ConnectorCredentialListResponse = {
  source_id: string;
  tenant_id: string;
  runtime_id?: string;
  credentials: ConnectorCredential[];
};

export type ConnectorCredentialDetailResponse = {
  source_id: string;
  credential: ConnectorCredential;
  audit?: ConnectorCredentialAuditEvent[];
};

export type ConnectorCredentialBrokerResponse = {
  source_id: string;
  tenant_id: string;
  runtime_id: string;
  status: "stored" | "rotated" | "existing" | string;
  credential: ConnectorCredential;
  credential_references: Record<string, string>;
};

export type ConnectorScopeResource = {
  urn?: string;
  type?: string;
  id?: string;
  reason?: string;
};

export type ConnectorScopePolicy = {
  mode?: "exclude" | string;
  excluded_families?: string[];
  excluded_asset_classes?: string[];
  excluded_kinds?: string[];
  excluded_resource_urns?: string[];
  excluded_resources?: ConnectorScopeResource[];
};

export type ConnectorScopeOption = {
  id: string;
  label: string;
  type?: string;
  families?: string[];
  support?: string;
  high_value?: boolean;
  known_unsupported_fields?: string[];
  notes?: string[];
  evidence_types?: string[];
  control_domains?: string[];
  control_refs?: ConnectorCoverageControlRef[];
};

export type ConnectorCredentialStoreID =
  | "cerebro_vault"
  | "infisical"
  | "google_secret_manager"
  | "aws_secrets_manager"
  | "azure_key_vault"
  | "hashicorp_vault"
  | "environment_managed";

export type ConnectorCredentialStoreMode =
  | "encrypted_submission"
  | "reference"
  | "environment_managed";

export type ConnectorCredentialStore = {
  id: string;
  label?: string;
  provider?: string;
  available?: boolean;
  default?: boolean;
  mode?: string;
  status?: string;
  detail?: string;
  description?: string;
  reference_prefixes?: string[];
  reference_namespace_template?: string;
  reference_field_template?: string;
  reference_placeholder?: string;
  native_resolution_available?: boolean;
  setup_steps?: ConnectorCredentialStoreSetupStep[];
  required_config?: ConnectorCredentialStoreConfigField[];
};

export type ConnectorCredentialStoreSetupStep = {
  id?: string;
  label?: string;
  description?: string;
  command?: string;
};

export type ConnectorCredentialStoreConfigField = {
  env?: string;
  label?: string;
  required?: boolean;
  description?: string;
};

export type NormalizedCredentialStore = {
  id: ConnectorCredentialStoreID;
  label: string;
  shortLabel: string;
  provider: string;
  description: string;
  mode: ConnectorCredentialStoreMode;
  available: boolean;
  default: boolean;
  status: string;
  detail: string;
  referencePrefixes: string[];
  referenceNamespaceTemplate?: string;
  referenceFieldTemplate?: string;
  referencePlaceholder?: string;
  nativeResolutionAvailable: boolean;
  setupSteps: ConnectorCredentialStoreSetupStep[];
  requiredConfig: ConnectorCredentialStoreConfigField[];
  disabledReason?: string;
};

export type ConnectorField = {
  key: string;
  label: string;
  type?: "text" | "password";
  placeholder?: string;
  required?: boolean;
  secret?: boolean;
  reference_only?: boolean;
  help?: string;
};

export type ConnectorFieldSet = {
  config: ConnectorField[];
  credentials: ConnectorField[];
};

export type ConnectorDisplayMetadata = {
  logoText: string;
  category: string;
  provider: string;
  accentClass: string;
  authBadge?: string;
};

export type ConnectorConnectionMethodID =
  | "encrypted_submission"
  | "aws_sso_profile"
  | "infisical_cli"
  | "environment_managed"
  | "external_reference";

export type ConnectorConnectionMethodInput = {
  id: string;
  label?: string;
  short_label?: string;
  description?: string;
  category?: string;
  credential_stores?: string[];
  config_fields?: ConnectorField[];
  credential_fields?: ConnectorField[];
  requires_secrets?: boolean;
  recommended?: boolean;
  saveable?: boolean;
  unavailable_reason?: string;
  shortLabel?: string;
  status?: "ready" | "guided" | "unavailable";
  commands?: string[];
  steps?: Array<string | ConnectorSetupStep>;
  prerequisites?: ConnectorPrerequisite[];
  product_groups?: ConnectorProductGroup[];
  deployment_guides?: ConnectorDeploymentGuide[];
  region_guidance?: ConnectorRegionGuidance;
  security_notes?: string[];
  disabledReason?: string;
};

export type ConnectorConnectionMethod = Omit<
  ConnectorConnectionMethodInput,
  "commands" | "steps" | "prerequisites" | "product_groups" | "deployment_guides" | "region_guidance" | "security_notes"
> & {
  id: ConnectorConnectionMethodID;
  label: string;
  description: string;
  shortLabel: string;
  category: string;
  status: "ready" | "guided" | "unavailable";
  commands: string[];
  steps: ConnectorSetupStep[];
  prerequisites: ConnectorPrerequisite[];
  product_groups: ConnectorProductGroup[];
  deployment_guides: ConnectorDeploymentGuide[];
  region_guidance?: ConnectorRegionGuidance;
  security_notes: string[];
  disabledReason?: string;
};

export type ConnectorPrerequisite = {
  id: string;
  label: string;
  description?: string;
  required?: boolean;
};

export type ConnectorSetupStep = {
  id: string;
  label: string;
  description?: string;
  commands?: string[];
};

export type ConnectorProductGroup = {
  id: string;
  label: string;
  description?: string;
  families?: string[];
  default_enabled?: boolean;
  required?: boolean;
  permission_note?: string;
  cost_note?: string;
};

export type ConnectorDeploymentGuide = {
  id: string;
  label: string;
  language?: string;
  description?: string;
  body?: string;
};

export type ConnectorRegionGuidance = {
  default_region?: string;
  examples?: string[];
  supports_global?: boolean;
  supports_multi_region?: boolean;
  description?: string;
};

export type ConnectorCredentialContext = {
  sourceID: string;
  tenantID: string;
  runtimeID: string;
  credentialStoreID: ConnectorCredentialStoreID;
};

export type ConnectorConnectionPayload = {
  runtime_id: string;
  tenant_id: string;
  check_only?: boolean;
  auth_method: ConnectorConnectionMethodID;
  credential_store_id: ConnectorCredentialStoreID;
  config: Record<string, string>;
  scope_policy?: ConnectorScopePolicy;
  credential_references?: Record<string, string>;
  encrypted_credentials?: Awaited<ReturnType<typeof encryptConnectorCredentials>>;
};

export type ConnectorPreflightStatus = "ready" | "warning" | "blocked" | string;

export type ConnectorPreflightCheck = {
  id: string;
  label: string;
  status: "passed" | "warning" | "blocked" | "skipped" | string;
  severity: "success" | "warning" | "error" | "info" | string;
  detail?: string;
  next_action?: string;
  blocking?: boolean;
};

export type ConnectorScopePreview = {
  mode?: string;
  available_resource_types?: number;
  disabled_resource_types?: number;
  enabled_resource_types?: number;
  excluded_families?: string[];
  exact_resource_count?: number;
};

export type ConnectorCredentialBoundary = {
  mode?: ConnectorConnectionMethodID | string;
  credential_store_id?: ConnectorCredentialStoreID | string;
  store_status?: string;
  store_detail?: string;
  sends_secrets?: boolean;
  reference_only?: boolean;
  reference_namespace?: string;
  reference_prefixes?: string[];
  native_resolution_available?: boolean;
  fields_accepted?: string[];
  reference_templates?: ConnectorReferenceTemplate[];
};

export type ConnectorReferenceTemplate = {
  field: string;
  label?: string;
  required?: boolean;
  reference: string;
  description?: string;
};

export type ConnectorPreflightResponse = {
  generated_at?: string;
  source_id: string;
  runtime_id?: string;
  tenant_id?: string;
  auth_method?: ConnectorConnectionMethodID | string;
  credential_store_id?: ConnectorCredentialStoreID | string;
  status: ConnectorPreflightStatus;
  summary: string;
  next_action: string;
  checks: ConnectorPreflightCheck[];
  diagnostic_timeline?: ConnectorDiagnosticTimeline[];
  scope_preview?: ConnectorScopePreview;
  credential_boundary?: ConnectorCredentialBoundary;
};

export type ConnectorRuntimeObject = {
  id?: string;
  source_id?: string;
  tenant_id?: string;
  metadata?: {
    name?: string;
  };
  [key: string]: unknown;
};

export type ConnectorConnectionResponse = {
  source_id: string;
  runtime?: ConnectorRuntimeObject;
  credential?: ConnectorCredential;
  scope_policy?: ConnectorScopePolicy;
  status?: "checked" | "stored" | string;
};

export type ConnectorConnectedContext = {
  sourceID: string;
  tenantID: string;
  runtimeID: string;
  response?: ConnectorConnectionResponse;
};

export type ConnectorDepositRequest = {
  tenant_id?: string;
  runtime_id: string;
  family_id?: string;
  batch_id?: string;
  idempotency_key?: string;
  occurred_at?: string;
  full_state?: boolean;
  record?: Record<string, unknown>;
  records?: Record<string, unknown>[];
};

export type ConnectorDepositResponse = {
  source_id: string;
  runtime_id: string;
  tenant_id: string;
  family_id: string;
  records_accepted: number;
  records_rejected: number;
  events_appended: number;
  entities_projected: number;
  links_projected: number;
  errors?: Array<{
    index: number;
    source_event_id?: string;
    detail: string;
  }>;
};

const runtimeRecordValue = (value: unknown, keys: string[]) => {
  if (!value || typeof value !== "object") return "";
  const record = value as Record<string, unknown>;
  for (const key of keys) {
    const candidate = record[key];
    if (typeof candidate === "string" && candidate.trim()) return candidate.trim();
  }
  return "";
};

export const connectorConnectedContextFromResponse = (
  response: ConnectorConnectionResponse | undefined,
  fallback: { sourceID: string; tenantID: string; runtimeID: string },
): ConnectorConnectedContext => {
  const runtime = response?.runtime;
  return {
    sourceID: response?.source_id?.trim() || response?.credential?.source_id?.trim() || runtimeRecordValue(runtime, ["source_id", "sourceId"]) || fallback.sourceID,
    tenantID: response?.credential?.tenant_id?.trim() || runtimeRecordValue(runtime, ["tenant_id", "tenantId"]) || fallback.tenantID,
    runtimeID: response?.credential?.runtime_id?.trim() || runtimeRecordValue(runtime, ["id", "runtime_id", "runtimeId"]) || runtime?.metadata?.name?.trim() || fallback.runtimeID,
    response,
  };
};

export type ConnectorDefinitionStage = "draft" | "sandbox" | "pilot" | "approved" | "certified";
export type ConnectorDefinitionValidationStatus = "ready" | "warning" | "blocked";

export type ConnectorDefinitionField = {
  key: string;
  label?: string;
  required?: boolean;
  secret?: boolean;
  reference_only?: boolean;
  help?: string;
  placeholder?: string;
};

export type ConnectorDefinitionResourceFamily = {
  id: string;
  label?: string;
  path?: string;
  method?: "GET" | "POST" | string;
  list_key?: string;
  record_selector?: string;
  id_field: string;
  name_field?: string;
  updated_at_field?: string;
  event?: {
    kind?: string;
    schema_ref?: string;
  };
  projection?: {
    template?: string;
  };
  coverage?: ConnectorCoverageDimension[];
  event_kind?: string;
  default_enabled?: boolean;
};

export type ConnectorDefinitionIngestMode = "pull" | "deposit";

export type ConnectorDefinitionIngest = {
  mode?: ConnectorDefinitionIngestMode | string;
  deposit?: {
    resource_families?: string[];
    full_state_sync?: boolean;
  };
};

export type ConnectorDefinitionTransport = {
  base_url?: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  verification?: {
    method?: string;
    path?: string;
    expect_status?: number[];
  };
};

export type ConnectorDefinitionScopeOption = {
  id?: string;
  label?: string;
  type?: string;
  families?: string[];
  support?: string;
  high_value?: boolean;
  known_unsupported_fields?: string[];
  notes?: string[];
  evidence_types?: string[];
  control_domains?: string[];
  control_refs?: ConnectorCoverageControlRef[];
  default_enabled?: boolean;
  permission_note?: string;
  needs_user_review?: boolean;
  unsupported_notes?: string[];
};

export type ConnectorDefinitionCheck = {
  id: string;
  label: string;
  status: ConnectorDefinitionValidationStatus | string;
  severity: "info" | "warning" | "error" | string;
  detail?: string;
  next_action?: string;
  blocking?: boolean;
};

export type ConnectorDefinitionValidation = {
  status?: ConnectorDefinitionValidationStatus | string;
  summary?: string;
  checks?: ConnectorDefinitionCheck[];
  observed_at?: string;
};

export type ConnectorDefinitionPromotion = {
  eligible_stages?: ConnectorDefinitionStage[];
  required_gates?: string[];
  last_target?: string;
  next_action?: string;
};

export type ConnectorDefinition = {
  id?: string;
  tenant_id: string;
  source_id: string;
  display_name: string;
  description?: string;
  runtime: "json_api" | string;
  stage: ConnectorDefinitionStage | string;
  current_version?: number;
  config_fields?: ConnectorDefinitionField[];
  transport?: ConnectorDefinitionTransport;
  ingest?: ConnectorDefinitionIngest;
  auth: {
    model: "none" | "api_key" | "bearer_token" | "basic" | "oauth_client_credentials" | string;
    credential_fields?: ConnectorDefinitionField[];
    supported_store_ids?: string[];
    requires_references?: boolean;
  };
  resource_families?: ConnectorDefinitionResourceFamily[];
  scope_options?: ConnectorDefinitionScopeOption[];
  validation?: ConnectorDefinitionValidation;
  promotion?: ConnectorDefinitionPromotion;
  created_at?: string;
  updated_at?: string;
};

export type ConnectorDefinitionListResponse = {
  generated_at?: string;
  tenant_id?: string;
  runtime_store?: string;
  definitions?: ConnectorDefinition[];
};

export type ConnectorDefinitionResponse = {
  generated_at?: string;
  definition?: ConnectorDefinition;
};

export type ConnectorDefinitionValidationResponse = {
  generated_at?: string;
  definition?: ConnectorDefinition;
  validation?: ConnectorDefinitionValidation;
  promotion?: ConnectorDefinitionPromotion;
};

export type ConnectorDefinitionPromotionResponse = {
  generated_at?: string;
  result?: {
    definition?: ConnectorDefinition;
    promoted?: boolean;
    target_stage?: ConnectorDefinitionStage | string;
    next_action?: string;
  };
};

export type ConnectorDefinitionPreviewResponse = {
  generated_at?: string;
  definition?: ConnectorDefinition;
  status?: "checked" | "previewed" | string;
  events?: unknown[];
  pages_read?: number;
  next_cursor?: string;
};

export type SourceActivationPlanStatus = "ready" | "warning" | "blocked";

export type SourceActivationSupportCheck = {
  id: string;
  category: string;
  status: "ready" | "missing" | string;
  detail?: string;
};

export type SourceActivationSupportReport = {
  definition_id?: string;
  source_id?: string;
  grammar_version?: string;
  verdict?: "supported" | "extension_required" | "bespoke_required" | string;
  supported_features?: string[];
  missing_features?: string[];
  checks?: SourceActivationSupportCheck[];
  validation?: ConnectorDefinitionValidation;
};

export type SourceActivationPromotionPlanStep = {
  id: string;
  title: string;
  category: string;
  status: SourceActivationPlanStatus | string;
  detail?: string;
  action?: string;
  blocking?: boolean;
};

export type SourceActivationPromotionPlanMetrics = {
  resource_families?: number;
  config_fields?: number;
  credential_fields?: number;
  scope_options?: number;
  generated_files?: number;
  ready_checks?: number;
  warning_checks?: number;
  blocked_checks?: number;
};

export type SourceActivationScaffoldPlan = {
  source_id?: string;
  source_type?: string;
  auth_model?: string;
  dry_run?: boolean;
  files?: string[];
  health_endpoint?: string;
  source_health_receipt?: string;
  pr_body?: string;
  next_steps?: string[];
};

export type SourceActivationPromotionPlan = {
  generated_at?: string;
  definition?: ConnectorDefinition;
  support?: SourceActivationSupportReport;
  status?: SourceActivationPlanStatus | string;
  summary?: string;
  next_stage?: ConnectorDefinitionStage | string;
  checklist?: SourceActivationPromotionPlanStep[];
  blockers?: string[];
  warnings?: string[];
  metrics?: SourceActivationPromotionPlanMetrics;
  scaffold?: SourceActivationScaffoldPlan;
  commands?: string[];
};

export type ConnectorDefinitionPlanResponse = {
  generated_at?: string;
  plan?: SourceActivationPromotionPlan;
};

export const CONNECTOR_CREDENTIAL_TRANSPORT_ALGORITHM = "RSA-OAEP-256+A256GCM";
export const CONNECTOR_CREDENTIAL_TRANSIT_JWK_ALGORITHM = "RSA-OAEP-256";

export const connectorDefinitionStages: ConnectorDefinitionStage[] = ["draft", "sandbox", "pilot", "approved", "certified"];

export const connectorDefinitionStageLabels: Record<ConnectorDefinitionStage, string> = {
  draft: "Draft",
  sandbox: "Sandbox",
  pilot: "Pilot",
  approved: "Approved",
  certified: "Certified",
};

export const connectorDefinitionStageDescription: Record<ConnectorDefinitionStage, string> = {
  draft: "Shape the manifest with docs, auth, resources, and scope.",
  sandbox: "Run bounded probes and sample mapping checks before durable ingestion.",
  pilot: "Use with one workspace or tenant under visible limits.",
  approved: "Make available inside the organization connector library.",
  certified: "Eligible for hardened source/code promotion.",
};

export const connectorDefinitionValidationLabel = (status?: string) => {
  if (status === "ready") return "Ready";
  if (status === "warning") return "Needs review";
  if (status === "blocked") return "Blocked";
  return "Not validated";
};

export const sourceActivationPlanStatusLabel = (status?: string) => {
  if (status === "ready") return "Ready";
  if (status === "warning") return "Needs review";
  if (status === "blocked") return "Blocked";
  return "Not planned";
};

export const sourceActivationPlanStatusIntent = (status?: string) => {
  if (status === "ready") return "success";
  if (status === "warning") return "warning";
  if (status === "blocked") return "danger";
  return "neutral";
};

export const sourceActivationPlanPath = (definitionID?: string, tenantID?: string) => {
  const query = new URLSearchParams();
  if (definitionID) query.set("definition_id", definitionID);
  if (tenantID) query.set("tenant_id", tenantID);
  const queryString = query.toString();
  return `/connectors/activation${queryString ? `?${queryString}` : ""}`;
};

export const sourceActivationPlanCategoryCounts = (plan?: Pick<SourceActivationPromotionPlan, "checklist"> | null) =>
  (plan?.checklist ?? []).reduce<Record<string, number>>((counts, step) => {
    const category = step.category || "other";
    counts[category] = (counts[category] ?? 0) + 1;
    return counts;
  }, {});

export const connectorDefinitionBlockingChecks = (definition?: Pick<ConnectorDefinition, "validation"> | null) =>
  definition?.validation?.checks?.filter((check) => check.blocking || check.status === "blocked").length ?? 0;

export const connectorDefinitionNextStage = (definition?: Pick<ConnectorDefinition, "stage" | "promotion"> | null) => {
  const advertised = definition?.promotion?.eligible_stages?.find((stage): stage is ConnectorDefinitionStage =>
    connectorDefinitionStages.includes(stage as ConnectorDefinitionStage),
  );
  if (advertised) return advertised;
  const index = connectorDefinitionStages.indexOf(definition?.stage as ConnectorDefinitionStage);
  if (index >= 0 && index + 1 < connectorDefinitionStages.length) return connectorDefinitionStages[index + 1];
  return undefined;
};

export const connectorDefinitionStatus = (definition?: Pick<ConnectorDefinition, "validation"> | null) => {
  const status = definition?.validation?.status;
  if (status === "ready" || status === "warning" || status === "blocked") return status;
  return "not_configured";
};

export const normalizeConnectorDefinitionID = (value: string) =>
  value.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^[-_]+|[-_]+$/g, "");

export const defaultConnectorDefinitionDraft = (tenantID = ""): ConnectorDefinition => ({
  tenant_id: tenantID,
  source_id: "custom_api",
  display_name: "Custom API",
  description: "Read-only connector definition for a custom API.",
  runtime: "json_api",
  stage: "draft",
  config_fields: [
    {
      key: "base_url",
      label: "Base URL",
      required: true,
      help: "Stored as runtime configuration; do not put API tokens here.",
      placeholder: "https://api.example.com",
    },
  ],
  transport: {
    base_url: "${config.base_url}",
    verification: {
      method: "GET",
      path: "/health",
      expect_status: [200],
    },
  },
  ingest: {
    mode: "pull",
  },
  auth: {
    model: "bearer_token",
    requires_references: true,
    supported_store_ids: ["cerebro_vault"],
    credential_fields: [
      {
        key: "token",
        label: "Bearer token",
        required: true,
        secret: true,
        reference_only: true,
      },
    ],
  },
  resource_families: [
    {
      id: "assets",
      label: "Assets",
      path: "/v1/assets",
      method: "GET",
      list_key: "items",
      id_field: "id",
      name_field: "name",
      default_enabled: true,
    },
  ],
});

const sourceAliases: Record<string, string[]> = {
  aws: ["aws", "amazon", "amazon-web-services"],
  gcp: ["gcp", "google-cloud", "google-cloud-platform"],
  google_workspace: ["google-workspace", "workspace", "gsuite"],
  github: ["github", "github-cloud"],
  okta: ["okta"],
};

const connectorCategoryDisplayCatalog: Record<string, Pick<ConnectorDisplayMetadata, "category" | "accentClass">> = {
  access: { category: "Access management", accentClass: "bg-indigo-50 text-indigo-700 ring-indigo-200 dark:bg-indigo-500/15 dark:text-indigo-100 dark:ring-indigo-500/25" },
  artifacts: { category: "Artifact registry", accentClass: "bg-cyan-50 text-cyan-700 ring-cyan-200 dark:bg-cyan-500/15 dark:text-cyan-100 dark:ring-cyan-500/25" },
  asm: { category: "Attack surface management", accentClass: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-500/15 dark:text-red-100 dark:ring-red-500/25" },
  audit: { category: "Audit management", accentClass: "bg-violet-50 text-violet-700 ring-violet-200 dark:bg-violet-500/15 dark:text-violet-100 dark:ring-violet-500/25" },
  background_checks: { category: "Background checks", accentClass: "bg-sky-50 text-sky-700 ring-sky-200 dark:bg-sky-500/15 dark:text-sky-100 dark:ring-sky-500/25" },
  business: { category: "Business system", accentClass: "bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-200 dark:bg-fuchsia-500/15 dark:text-fuchsia-100 dark:ring-fuchsia-500/25" },
  ci: { category: "CI/CD", accentClass: "bg-lime-50 text-lime-800 ring-lime-200 dark:bg-lime-500/15 dark:text-lime-100 dark:ring-lime-500/25" },
  cloud: { category: "Cloud security", accentClass: "bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-500/15 dark:text-blue-100 dark:ring-blue-500/25" },
  code: { category: "Code hosting", accentClass: "bg-zinc-100 text-zinc-800 ring-zinc-200 dark:bg-zinc-500/15 dark:text-zinc-100 dark:ring-zinc-500/25" },
  code_quality: { category: "Code quality", accentClass: "bg-teal-50 text-teal-700 ring-teal-200 dark:bg-teal-500/15 dark:text-teal-100 dark:ring-teal-500/25" },
  code_scanning: { category: "Code scanning", accentClass: "bg-rose-50 text-rose-700 ring-rose-200 dark:bg-rose-500/15 dark:text-rose-100 dark:ring-rose-500/25" },
  collaboration: { category: "Collaboration", accentClass: "bg-sky-50 text-sky-700 ring-sky-200 dark:bg-sky-500/15 dark:text-sky-100 dark:ring-sky-500/25" },
  compliance: { category: "Compliance", accentClass: "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-100 dark:ring-emerald-500/25" },
  containers: { category: "Container security", accentClass: "bg-cyan-50 text-cyan-700 ring-cyan-200 dark:bg-cyan-500/15 dark:text-cyan-100 dark:ring-cyan-500/25" },
  crm: { category: "CRM", accentClass: "bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-200 dark:bg-fuchsia-500/15 dark:text-fuchsia-100 dark:ring-fuchsia-500/25" },
  customer_data: { category: "Customer data", accentClass: "bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-500/15 dark:text-blue-100 dark:ring-blue-500/25" },
  data: { category: "Data platform", accentClass: "bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-500/15 dark:text-blue-100 dark:ring-blue-500/25" },
  database: { category: "Database", accentClass: "bg-cyan-50 text-cyan-700 ring-cyan-200 dark:bg-cyan-500/15 dark:text-cyan-100 dark:ring-cyan-500/25" },
  design: { category: "Design collaboration", accentClass: "bg-pink-50 text-pink-700 ring-pink-200 dark:bg-pink-500/15 dark:text-pink-100 dark:ring-pink-500/25" },
  dev: { category: "Developer platform", accentClass: "bg-lime-50 text-lime-800 ring-lime-200 dark:bg-lime-500/15 dark:text-lime-100 dark:ring-lime-500/25" },
  document_management: { category: "Document management", accentClass: "bg-sky-50 text-sky-700 ring-sky-200 dark:bg-sky-500/15 dark:text-sky-100 dark:ring-sky-500/25" },
  endpoint: { category: "Endpoint security", accentClass: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-500/15 dark:text-red-100 dark:ring-red-500/25" },
  erp: { category: "ERP", accentClass: "bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-200 dark:bg-fuchsia-500/15 dark:text-fuchsia-100 dark:ring-fuchsia-500/25" },
  feature_flags: { category: "Feature flags", accentClass: "bg-lime-50 text-lime-800 ring-lime-200 dark:bg-lime-500/15 dark:text-lime-100 dark:ring-lime-500/25" },
  finance: { category: "Finance", accentClass: "bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-200 dark:bg-fuchsia-500/15 dark:text-fuchsia-100 dark:ring-fuchsia-500/25" },
  grc: { category: "GRC", accentClass: "bg-violet-50 text-violet-700 ring-violet-200 dark:bg-violet-500/15 dark:text-violet-100 dark:ring-violet-500/25" },
  hr: { category: "HR system", accentClass: "bg-sky-50 text-sky-700 ring-sky-200 dark:bg-sky-500/15 dark:text-sky-100 dark:ring-sky-500/25" },
  iac: { category: "Infrastructure as code", accentClass: "bg-lime-50 text-lime-800 ring-lime-200 dark:bg-lime-500/15 dark:text-lime-100 dark:ring-lime-500/25" },
  identity: { category: "Identity and access", accentClass: "bg-indigo-50 text-indigo-700 ring-indigo-200 dark:bg-indigo-500/15 dark:text-indigo-100 dark:ring-indigo-500/25" },
  incident: { category: "Incident management", accentClass: "bg-amber-50 text-amber-800 ring-amber-200 dark:bg-amber-500/15 dark:text-amber-100 dark:ring-amber-500/25" },
  itsm: { category: "ITSM", accentClass: "bg-amber-50 text-amber-800 ring-amber-200 dark:bg-amber-500/15 dark:text-amber-100 dark:ring-amber-500/25" },
  knowledge: { category: "Knowledge management", accentClass: "bg-sky-50 text-sky-700 ring-sky-200 dark:bg-sky-500/15 dark:text-sky-100 dark:ring-sky-500/25" },
  mdm: { category: "MDM", accentClass: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-500/15 dark:text-red-100 dark:ring-red-500/25" },
  observability: { category: "Observability", accentClass: "bg-teal-50 text-teal-700 ring-teal-200 dark:bg-teal-500/15 dark:text-teal-100 dark:ring-teal-500/25" },
  privacy: { category: "Privacy", accentClass: "bg-violet-50 text-violet-700 ring-violet-200 dark:bg-violet-500/15 dark:text-violet-100 dark:ring-violet-500/25" },
  productivity: { category: "Productivity suite", accentClass: "bg-sky-50 text-sky-700 ring-sky-200 dark:bg-sky-500/15 dark:text-sky-100 dark:ring-sky-500/25" },
  project: { category: "Project management", accentClass: "bg-sky-50 text-sky-700 ring-sky-200 dark:bg-sky-500/15 dark:text-sky-100 dark:ring-sky-500/25" },
  saas: { category: "SaaS application", accentClass: "bg-sky-50 text-sky-700 ring-sky-200 dark:bg-sky-500/15 dark:text-sky-100 dark:ring-sky-500/25" },
  sca: { category: "Software composition analysis", accentClass: "bg-rose-50 text-rose-700 ring-rose-200 dark:bg-rose-500/15 dark:text-rose-100 dark:ring-rose-500/25" },
  secrets: { category: "Secrets management", accentClass: "bg-indigo-50 text-indigo-700 ring-indigo-200 dark:bg-indigo-500/15 dark:text-indigo-100 dark:ring-indigo-500/25" },
  security: { category: "Security platform", accentClass: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-500/15 dark:text-red-100 dark:ring-red-500/25" },
  security_training: { category: "Security training", accentClass: "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-100 dark:ring-emerald-500/25" },
  siem: { category: "SIEM", accentClass: "bg-teal-50 text-teal-700 ring-teal-200 dark:bg-teal-500/15 dark:text-teal-100 dark:ring-teal-500/25" },
  soar: { category: "SOAR", accentClass: "bg-teal-50 text-teal-700 ring-teal-200 dark:bg-teal-500/15 dark:text-teal-100 dark:ring-teal-500/25" },
  support: { category: "Support operations", accentClass: "bg-amber-50 text-amber-800 ring-amber-200 dark:bg-amber-500/15 dark:text-amber-100 dark:ring-amber-500/25" },
  threat_intel: { category: "Threat intelligence", accentClass: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-500/15 dark:text-red-100 dark:ring-red-500/25" },
  vulnerability: { category: "Vulnerability management", accentClass: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-500/15 dark:text-red-100 dark:ring-red-500/25" },
  warehouse: { category: "Data warehouse", accentClass: "bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-500/15 dark:text-blue-100 dark:ring-blue-500/25" },
};

const connectorDisplayCatalog: Record<string, ConnectorDisplayMetadata> = {
  anthropic: { logoText: "A", category: "AI platform", provider: "Anthropic", accentClass: "bg-orange-50 text-orange-700 ring-orange-200 dark:bg-orange-500/15 dark:text-orange-100 dark:ring-orange-500/25" },
  aws: { logoText: "AWS", category: "Cloud provider", provider: "Amazon Web Services", accentClass: "bg-amber-50 text-amber-800 ring-amber-200 dark:bg-amber-500/15 dark:text-amber-100 dark:ring-amber-500/25", authBadge: "SSO ready" },
  azure: { logoText: "Az", category: "Cloud provider", provider: "Microsoft Azure", accentClass: "bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-500/15 dark:text-blue-100 dark:ring-blue-500/25" },
  cloudflare: { logoText: "CF", category: "Edge platform", provider: "Cloudflare", accentClass: "bg-orange-50 text-orange-700 ring-orange-200 dark:bg-orange-500/15 dark:text-orange-100 dark:ring-orange-500/25" },
  gcp: { logoText: "G", category: "Cloud provider", provider: "Google Cloud Platform", accentClass: "bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-500/15 dark:text-blue-100 dark:ring-blue-500/25" },
  github: { logoText: "GH", category: "Code hosting", provider: "GitHub", accentClass: "bg-zinc-100 text-zinc-800 ring-zinc-200 dark:bg-zinc-500/15 dark:text-zinc-100 dark:ring-zinc-500/25" },
  google_workspace: { logoText: "GW", category: "Identity and workspace", provider: "Google Workspace", accentClass: "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-100 dark:ring-emerald-500/25" },
  okta: { logoText: "Ok", category: "Identity provider", provider: "Okta", accentClass: "bg-indigo-50 text-indigo-700 ring-indigo-200 dark:bg-indigo-500/15 dark:text-indigo-100 dark:ring-indigo-500/25" },
  openai: { logoText: "OAI", category: "AI platform", provider: "OpenAI", accentClass: "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-100 dark:ring-emerald-500/25" },
};

const defaultFieldSet: ConnectorFieldSet = {
  config: [],
  credentials: [{ key: "token", label: "API token", type: "password", required: true }],
};

const credentialStoreCatalog: Record<
  ConnectorCredentialStoreID,
  Omit<
    NormalizedCredentialStore,
    "available" | "default" | "status" | "detail" | "referencePrefixes" | "referencePlaceholder" | "nativeResolutionAvailable" | "setupSteps" | "requiredConfig" | "disabledReason"
  >
> = {
  cerebro_vault: {
    id: "cerebro_vault",
    label: "Managed credential vault",
    shortLabel: "Vault",
    provider: "Backend",
    description: "Encrypted credential envelope for connector runtime secrets.",
    mode: "encrypted_submission",
  },
  google_secret_manager: {
    id: "google_secret_manager",
    label: "Google Secret Manager",
    shortLabel: "GSM",
    provider: "Google Cloud Platform",
    description: "Deployment-backed Google Secret Manager storage for connector credentials.",
    mode: "reference",
    referenceNamespaceTemplate: "CEREBRO_SOURCE_<SOURCE>_*",
    referenceFieldTemplate: "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>",
  },
  infisical: {
    id: "infisical",
    label: "Infisical",
    shortLabel: "Infisical",
    provider: "Infisical",
    description: "Deployment-backed Infisical project and environment path for connector credentials.",
    mode: "reference",
    referenceNamespaceTemplate: "CEREBRO_SOURCE_<SOURCE>_*",
    referenceFieldTemplate: "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>",
  },
  aws_secrets_manager: {
    id: "aws_secrets_manager",
    label: "AWS Secrets Manager",
    shortLabel: "AWS SM",
    provider: "Amazon Web Services",
    description: "Deployment-backed AWS Secrets Manager storage for connector credentials.",
    mode: "reference",
    referenceNamespaceTemplate: "cerebro/<tenant>/<source>/<runtime>/credentials",
    referenceFieldTemplate: "aws-sm:<region>:cerebro/<tenant>/<source>/<runtime>/credentials#<field>",
  },
  azure_key_vault: {
    id: "azure_key_vault",
    label: "Azure Key Vault",
    shortLabel: "Azure",
    provider: "Microsoft Azure",
    description: "Deployment-backed Azure Key Vault storage for connector credentials.",
    mode: "reference",
    referenceNamespaceTemplate: "CEREBRO_SOURCE_<SOURCE>_*",
    referenceFieldTemplate: "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>",
  },
  hashicorp_vault: {
    id: "hashicorp_vault",
    label: "HashiCorp Vault",
    shortLabel: "Vault",
    provider: "HashiCorp",
    description: "Deployment-backed HashiCorp Vault storage for connector credentials.",
    mode: "reference",
    referenceNamespaceTemplate: "CEREBRO_SOURCE_<SOURCE>_*",
    referenceFieldTemplate: "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>",
  },
  environment_managed: {
    id: "environment_managed",
    label: "Environment-managed credentials",
    shortLabel: "Env",
    provider: "Deployment",
    description: "Credentials are supplied by the deployment environment, not entered in this console.",
    mode: "environment_managed",
    referenceNamespaceTemplate: "CEREBRO_SOURCE_<SOURCE>_*",
    referenceFieldTemplate: "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>",
  },
};

export const credentialStoreOrder: ConnectorCredentialStoreID[] = [
  "cerebro_vault",
  "infisical",
  "google_secret_manager",
  "aws_secrets_manager",
  "azure_key_vault",
  "hashicorp_vault",
  "environment_managed",
];

const connectorFieldSets: Record<string, ConnectorFieldSet> = {
  aws: {
    config: [
      { key: "account_id", label: "Account ID", required: true },
      { key: "region", label: "Region", placeholder: "us-east-1" },
      { key: "role_arn", label: "Role ARN" },
    ],
    credentials: [
      { key: "access_key_id", label: "Access key ID", required: true },
      { key: "secret_access_key", label: "Secret access key", type: "password", required: true },
      { key: "session_token", label: "Session token", type: "password" },
    ],
  },
  github: {
    config: [
      { key: "owner", label: "Owner" },
      { key: "repo", label: "Repository" },
      { key: "family", label: "Family", placeholder: "audit" },
    ],
    credentials: [{ key: "token", label: "Token", type: "password", required: true }],
  },
  google_workspace: {
    config: [
      { key: "domain", label: "Domain", required: true },
      { key: "family", label: "Family" },
    ],
    credentials: [{ key: "token", label: "Access token", type: "password", required: true }],
  },
  gcp: {
    config: [
      { key: "project_id", label: "Project ID", required: true },
      { key: "family", label: "Family" },
      { key: "wif_audience", label: "WIF audience" },
      { key: "wif_service_account_email", label: "WIF service account" },
    ],
    credentials: [{ key: "token", label: "Access token", type: "password" }],
  },
  okta: {
    config: [
      { key: "domain", label: "Okta domain", required: true },
      { key: "family", label: "Family", placeholder: "user" },
    ],
    credentials: [{ key: "token", label: "SSWS token", type: "password", required: true }],
  },
  openai: {
    config: [{ key: "family", label: "Family" }],
    credentials: [{ key: "api_key", label: "API key", type: "password", required: true }],
  },
  anthropic: {
    config: [{ key: "family", label: "Family" }],
    credentials: [{ key: "api_key", label: "API key", type: "password", required: true }],
  },
};

export const fieldSetForConnector = (sourceID: string): ConnectorFieldSet =>
  connectorFieldSets[sourceID] ?? defaultFieldSet;

export const connectorSlug = (sourceID: string) =>
  sourceID.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");

export const connectorAliasCandidates = (connector: Pick<ConnectorCatalogEntry, "source_id" | "name" | "display_name">) => {
  const sourceID = connector.source_id.trim().toLowerCase();
  const nameSlug = connectorSlug(connector.name || sourceID);
  const displayNameSlug = connector.display_name ? connectorSlug(connector.display_name) : "";
  return new Set([sourceID, connectorSlug(sourceID), nameSlug, displayNameSlug, ...(sourceAliases[sourceID] ?? [])].filter(Boolean));
};

export const connectorMatchesSlug = (connector: Pick<ConnectorCatalogEntry, "source_id" | "name" | "display_name">, slug: string) => {
  const normalizedSlug = connectorSlug(slug);
  return connectorAliasCandidates(connector).has(normalizedSlug);
};

const humanizeConnectorToken = (value: string) =>
  value
    .trim()
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());

const connectorCategoryMetadata = (categories?: string[]) => {
  for (const category of categories ?? []) {
    const normalized = category.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
    const match = connectorCategoryDisplayCatalog[normalized];
    if (match) return match;
  }
  const first = categories?.find((category) => category.trim());
  if (!first) return undefined;
  return {
    category: humanizeConnectorToken(first),
    accentClass: "bg-slate-100 text-slate-700 ring-slate-200 dark:bg-slate-500/15 dark:text-slate-100 dark:ring-slate-500/25",
  };
};

const connectorLabelText = (connector: Pick<ConnectorCatalogEntry, "source_id" | "name" | "display_name">) =>
  connector.display_name?.trim()
  || connector.name?.trim()
  || humanizeConnectorToken(connector.source_id);

const connectorLogoText = (connector: Pick<ConnectorCatalogEntry, "source_id" | "name" | "display_name">) => {
  const label = connectorLabelText(connector);
  const words = label.replace(/([a-z])([A-Z])/g, "$1 $2").split(/[^a-z0-9]+/i).filter(Boolean);
  if (words.length >= 2) return words.slice(0, 2).map((word) => word[0]).join("").toUpperCase();
  return label.replace(/[^a-z0-9]/gi, "").slice(0, 3).toUpperCase() || "?";
};

export const connectorDisplayMetadata = (
  connector: Pick<ConnectorCatalogEntry, "source_id" | "name" | "display_name" | "emitted_kinds" | "catalog_categories">,
): ConnectorDisplayMetadata => {
  const catalog = connectorDisplayCatalog[connector.source_id];
  if (catalog) return catalog;
  const categoryMetadata = connectorCategoryMetadata(connector.catalog_categories);
  const emittedPrefix = connector.emitted_kinds?.[0]?.split(".")[0];
  return {
    logoText: connectorLogoText(connector),
    category: categoryMetadata?.category || (emittedPrefix ? `${humanizeConnectorToken(emittedPrefix)} source` : "Connector"),
    provider: connectorLabelText(connector),
    accentClass: categoryMetadata?.accentClass || "bg-slate-100 text-slate-700 ring-slate-200 dark:bg-slate-500/15 dark:text-slate-100 dark:ring-slate-500/25",
  };
};

export const connectorDisplayName = (connector: Pick<ConnectorCatalogEntry, "source_id" | "name" | "display_name" | "emitted_kinds">) =>
  connector.display_name?.trim()
  || connectorDisplayMetadata(connector).provider
  || connector.name
  || connector.source_id;

export const connectionMethodsForConnector = (
  connector: Pick<ConnectorCatalogEntry, "source_id" | "name" | "display_name" | "connection_methods">,
  stores: NormalizedCredentialStore[],
): ConnectorConnectionMethod[] => {
  const availableEncryptedStore = stores.find((store) => store.available && store.mode === "encrypted_submission");
  const availableReferenceStore = stores.find((store) => store.available && store.mode === "reference");
  const availableEnvironmentStore = stores.find((store) => store.available && store.mode === "environment_managed");
  const displayName = connector.display_name || connector.name || connector.source_id;
  const advertised = (connector.connection_methods ?? [])
    .filter((method) => knownConnectionMethodID(method.id))
    .map((method) => enrichConnectionMethod(method, connector));
  if (advertised.length > 0) return advertised;

  const fallbackMethods: ConnectorConnectionMethodInput[] = [
    ...(connector.source_id === "aws"
      ? [{
          id: "aws_sso_profile" as const,
          label: "AWS IAM Identity Center",
          shortLabel: "IAM Identity Center",
          status: availableEnvironmentStore ? "ready" as const : "unavailable" as const,
          description: "Use the AWS CLI browser/device-code flow, then save a deployment-managed profile or role reference. No AWS secret key is typed into the browser.",
          credential_stores: ["environment_managed"],
          config_fields: [
            { key: "account_id", label: "Account ID", required: true },
            { key: "profile", label: "Profile", required: true, placeholder: "cerebro-readonly" },
            { key: "region", label: "Region", placeholder: "us-east-1" },
            { key: "role_arn", label: "Role ARN" },
          ],
          credential_fields: [],
          saveable: Boolean(availableEnvironmentStore),
          commands: [
            "aws configure sso --profile cerebro-aws",
            "aws sso login --profile cerebro-aws",
            "aws sts get-caller-identity --profile cerebro-aws",
          ],
          steps: [
            "Configure or select an AWS SSO profile for the account this source should read.",
            "Complete the CLI login in the browser or with a device code.",
            "Verify the caller identity, then store the profile/role reference in the selected secret store.",
          ],
          disabledReason: availableEnvironmentStore ? undefined : "AWS SSO needs an environment-managed store enabled by the backend.",
        }]
      : []),
    {
      id: "infisical_cli",
      label: "Infisical CLI handoff",
      shortLabel: "Infisical",
      status: availableEnvironmentStore ? "ready" : "unavailable",
      description: `Authenticate with Infisical locally and place ${displayName} connection material in an environment-managed path. The backend should consume the reference server-side.`,
      credential_stores: ["environment_managed"],
      config_fields: fieldSetForConnector(connector.source_id).config,
      credential_fields: referenceFields(fieldSetForConnector(connector.source_id).credentials, connector.source_id),
      saveable: Boolean(availableEnvironmentStore),
      commands: [
        "infisical login status --json",
        "infisical login",
        "infisical init --env=<env> --path=<path>",
        "infisical run --env=<env> --path=<path> -- <start-cerebro>",
      ],
      steps: [
        "Confirm the CLI session or complete SSO in Infisical.",
        "Choose the project, environment, and connector path that deployment automation will read.",
        "Save only reference metadata; do not paste Infisical tokens into this page.",
      ],
      disabledReason: availableEnvironmentStore ? undefined : "Infisical handoff needs an environment-managed store enabled by the backend.",
    },
    {
      id: "external_reference",
      label: "Secret store reference",
      shortLabel: "Secret store",
      status: availableReferenceStore ? "ready" : "unavailable",
      description: "Use a deployment-owned secret store reference such as GSM, AWS Secrets Manager, Azure Key Vault, or environment-managed material.",
      credential_stores: ["infisical", "google_secret_manager", "aws_secrets_manager", "azure_key_vault", "hashicorp_vault"],
      config_fields: fieldSetForConnector(connector.source_id).config,
      credential_fields: referenceFields(fieldSetForConnector(connector.source_id).credentials, connector.source_id),
      saveable: Boolean(availableReferenceStore),
      commands: [],
      steps: [
        "Choose the store enabled by this deployment.",
        "Create or rotate secret material outside the browser.",
        "Submit non-secret connection metadata and let the backend resolve the reference.",
      ],
      disabledReason: availableReferenceStore ? undefined : "No reference-backed external store is enabled by this deployment.",
    },
    {
      id: "encrypted_submission",
      label: "Encrypted browser submission",
      shortLabel: "Manual",
      status: availableEncryptedStore ? "ready" : "unavailable",
      description: "Enter a one-time credential payload that is encrypted with the connector transit key before submission and cleared after every attempt.",
      credential_stores: ["cerebro_vault"],
      config_fields: fieldSetForConnector(connector.source_id).config,
      credential_fields: fieldSetForConnector(connector.source_id).credentials,
      requires_secrets: true,
      saveable: Boolean(availableEncryptedStore),
      commands: [],
      steps: [
        "Select an available encrypted credential store.",
        "Enter only the credential fields required for the connector.",
        "The backend stores the encrypted credential payload and never returns secret values to the frontend.",
      ],
      disabledReason: availableEncryptedStore ? undefined : "Encrypted submission is unavailable until Cerebro advertises a ready vault and transport key.",
    },
  ];
  return fallbackMethods.map((method) => enrichConnectionMethod(method, connector));
};

const knownConnectionMethodID = (value: string): value is ConnectorConnectionMethodID =>
  ["encrypted_submission", "aws_sso_profile", "infisical_cli", "environment_managed", "external_reference"].includes(value);

const enrichConnectionMethod = (
  method: ConnectorConnectionMethodInput,
  connector: Pick<ConnectorCatalogEntry, "source_id" | "name" | "display_name">,
): ConnectorConnectionMethod => {
  const id = knownConnectionMethodID(method.id) ? method.id : "encrypted_submission";
  const saveable = Boolean(method.saveable);
  const steps = normalizeConnectionMethodSteps(method.steps) ?? connectionMethodSteps(id);
  const stepCommands = steps.flatMap((step) => step.commands ?? []);
  const commands = method.commands ?? (stepCommands.length > 0 ? stepCommands : connectionMethodCommands(id, connector));
  return {
    ...method,
    id,
    label: method.label || connectionMethodShortLabel(id),
    description: method.description || connectionMethodShortLabel(id),
    shortLabel: method.shortLabel || method.short_label || connectionMethodShortLabel(id),
    category: method.category || (method.recommended ? "Recommended" : "Connection"),
    status: method.status || (saveable ? (id === "infisical_cli" || id === "aws_sso_profile" ? "guided" : "ready") : "unavailable"),
    commands,
    steps,
    prerequisites: method.prerequisites ?? connectionMethodPrerequisites(id),
    product_groups: method.product_groups ?? [],
    deployment_guides: method.deployment_guides ?? [],
    region_guidance: method.region_guidance,
    security_notes: method.security_notes ?? connectionMethodSecurityNotes(id),
    disabledReason: method.disabledReason || method.unavailable_reason,
    config_fields: method.config_fields ?? [],
    credential_fields: method.credential_fields ?? [],
  };
};

const normalizeConnectionMethodSteps = (steps?: Array<string | ConnectorSetupStep>) => {
  if (!Array.isArray(steps)) return undefined;
  return steps
    .map((step, index): ConnectorSetupStep | null => {
      if (typeof step === "string") {
        const label = step.trim();
        return label ? { id: `step_${index + 1}`, label } : null;
      }
      const label = step.label?.trim();
      if (!label) return null;
      return {
        id: step.id?.trim() || `step_${index + 1}`,
        label,
        description: step.description?.trim(),
        commands: step.commands?.filter(Boolean),
      };
    })
    .filter((step): step is ConnectorSetupStep => Boolean(step));
};

const connectionMethodShortLabel = (id: ConnectorConnectionMethodID) => {
  switch (id) {
    case "aws_sso_profile":
      return "AWS IAM Identity Center";
    case "infisical_cli":
      return "Infisical";
    case "environment_managed":
      return "Environment-managed credentials";
    case "external_reference":
      return "Secret store reference";
    case "encrypted_submission":
    default:
      return "Manual";
  }
};

const connectionMethodCommands = (
  id: ConnectorConnectionMethodID,
  connector: Pick<ConnectorCatalogEntry, "source_id" | "name" | "display_name">,
) => {
  const sourceSlugValue = connectorSlug(connector.source_id);
  switch (id) {
    case "aws_sso_profile":
      return [
        "aws configure sso --profile cerebro-aws",
        "aws sso login --profile cerebro-aws",
        "aws sts get-caller-identity --profile cerebro-aws",
      ];
    case "infisical_cli":
      return [
        "infisical login status --json",
        "infisical login",
        `infisical run --env=<env> --path=/cerebro/connectors/${sourceSlugValue} -- <start-cerebro>`,
      ];
    default:
      return [];
  }
};

const connectionMethodSteps = (id: ConnectorConnectionMethodID): ConnectorSetupStep[] => {
  switch (id) {
    case "aws_sso_profile":
      return [
        { id: "authenticate", label: "Authenticate the AWS CLI profile on the server." },
        { id: "save_profile", label: "Save the profile and account configuration." },
        { id: "validate", label: "Preflight validates the source before persisting the runtime." },
      ];
    case "infisical_cli":
      return [
        { id: "authenticate", label: "Authenticate Infisical outside the browser." },
        { id: "inject", label: "Inject the expected environment references into the Cerebro runtime." },
        { id: "save", label: "Save references only; secret values stay server-side." },
      ];
    case "environment_managed":
      return [
        { id: "populate", label: "Populate the referenced environment values in the runtime." },
        { id: "submit", label: "Submit references and non-secret config." },
        { id: "validate", label: "Preflight validates before saving." },
      ];
    case "external_reference":
      return [
        { id: "choose_store", label: "Choose the backing store." },
        { id: "expose_reference", label: "Expose the selected secret to Cerebro as server-resolvable references." },
        { id: "submit", label: "Submit references only; secret values stay outside the browser." },
      ];
    case "encrypted_submission":
    default:
      return [
        { id: "enter", label: "Enter the required credential fields." },
        { id: "encrypt", label: "The browser encrypts the payload with the connector transit key." },
        { id: "store", label: "Preflight validates and stores a sealed credential reference." },
      ];
  }
};

const connectionMethodPrerequisites = (id: ConnectorConnectionMethodID): ConnectorPrerequisite[] => [
  {
    id: "backend_store",
    label: id === "encrypted_submission" ? "Encrypted credential transport is ready" : "Backend can resolve the reference",
    required: true,
  },
  {
    id: "source_check",
    label: "Source check passes before save",
    required: true,
  },
];

const connectionMethodSecurityNotes = (id: ConnectorConnectionMethodID) => [
  id === "encrypted_submission"
    ? "Secret material is encrypted before submission and never returned by the API."
    : "Only server-resolvable references are submitted from the browser.",
  "Runtime responses redact credential fields.",
];

const referenceFields = (fields: ConnectorField[], sourceID: string): ConnectorField[] =>
  fields.map((field) => ({
    ...field,
    type: "text",
    secret: false,
    reference_only: true,
    placeholder: field.placeholder || `env:CEREBRO_SOURCE_${sourceID.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_${field.key.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`,
  }));

export const connectorStatus = (connector: ConnectorCatalogEntry) => {
  if ((connector.configured_runtimes ?? 0) === 0) return "not_configured";
  if (connector.status === "needs_attention") return "bad";
  if (connector.status === "degraded") return "poor";
  if (connector.status === "connected") return "healthy";
  return connector.status || "available";
};

export const connectorCatalogStatusLabel = (status?: string) => {
  switch (status) {
    case "catalog_ready":
      return "Catalog ready";
    case "generateable":
      return "Runtime ready";
    case "needs_auth_extension":
      return "Auth extension needed";
    case "needs_bespoke_runtime":
      return "Bespoke runtime needed";
    default:
      return status?.trim() || "No catalog status";
  }
};

export const connectorHasAdvertisedSetup = (connector: Pick<ConnectorCatalogEntry, "connection_methods">) =>
  (connector.connection_methods?.length ?? 0) > 0;

export const connectorSetupAllowed = (
  connector: Pick<ConnectorCatalogEntry, "setup_allowed" | "connection_methods">,
) => connector.setup_allowed ?? connectorHasAdvertisedSetup(connector);

export const connectorAccessStatusLabel = (status?: string) => {
  switch (status) {
    case "available":
      return "Setup available";
    case "catalog_only":
      return "Catalog only";
    case "restricted":
      return "Restricted";
    default:
      return status?.trim() || "Access unknown";
  }
};

export const connectorReadinessStageLabel = (stage?: string) => {
  switch (stage) {
    case "setup_enabled":
      return "Setup enabled";
    case "api_restricted":
      return "API restricted";
    case "sourcegen_ready":
    case "generateable":
      return "Runtime ready";
    case "catalog_ready":
      return "Catalog ready";
    case "auth_extension_required":
    case "needs_auth_extension":
      return "Auth extension needed";
    case "runtime_required":
    case "needs_bespoke_runtime":
      return "Runtime needed";
    case "runtime_unknown":
      return "Runtime unknown";
    default:
      return stage?.trim() || "Stage unknown";
  }
};

export const connectorDefinitionOriginLabel = (origin?: string) => {
  switch (origin) {
    case "compiled_source":
      return "Compiled source";
    case "builtin_catalog":
      return "Built-in catalog";
    default:
      return origin?.trim() || "Origin unknown";
  }
};

export const connectorIntegrationDepthLabel = (
  connector: Pick<ConnectorCatalogEntry, "integration_depth">,
) => {
  const depth = connector.integration_depth;
  if (!depth) return "Depth unknown";
  const level = depth.level?.trim() || "basic";
  const score = typeof depth.score === "number" ? `${depth.score}/100` : "unscored";
  return `${level.slice(0, 1).toUpperCase()}${level.slice(1)} · ${score}`;
};

export const connectorRequestActionLabel = (
  connector: Pick<ConnectorCatalogEntry, "request_access_action" | "access_status">,
) => {
  const configured = connector.request_access_action?.trim();
  if (configured) return configured;
  return connector.access_status === "catalog_only" ? "Request connector" : "Request access";
};

export const connectorIsCatalogOnly = (
  connector: Pick<ConnectorCatalogEntry, "catalog_status" | "connection_methods" | "configured_runtimes" | "setup_allowed">,
) => Boolean(connector.catalog_status && !connectorSetupAllowed(connector) && (connector.configured_runtimes ?? 0) === 0);

export const connectorRuntimeSurfaceLabel = (
  connector: Pick<ConnectorCatalogEntry, "catalog_status" | "runtime_executable" | "connection_methods" | "access_status" | "setup_allowed">,
) => {
  if (connectorSetupAllowed(connector)) return "Runtime supported";
  if (connector.access_status === "restricted") return "Restricted";
  if (connector.runtime_executable) return "Runtime ready";
  if (connector.catalog_status) return connectorCatalogStatusLabel(connector.catalog_status);
  return "Runtime unknown";
};

export const connectorDiagnosticStageLabel = (stage?: string) => {
  switch (stage) {
    case "setup":
      return "Setup";
    case "preflight":
      return "Preflight";
    case "source_sync":
      return "Source sync";
    case "contract_probe":
      return "Contract probe";
    case "graph_projection":
      return "Graph projection";
    case "finding_evaluation":
      return "Finding evaluation";
    default:
      return stage?.trim() || "Diagnostic stage";
  }
};

export const connectorDiagnosticStatusLabel = (status?: string) => {
  switch (status) {
    case "success":
      return "Healthy";
    case "warning":
      return "Needs attention";
    case "failed":
      return "Failed";
    case "running":
      return "Running";
    case "pending":
      return "Pending";
    default:
      return status?.trim() || "Unknown";
  }
};

export const connectorSearchText = (connector: ConnectorCatalogEntry) =>
  [
    connector.source_id,
    connector.name,
    connector.display_name,
    connector.description,
    connector.status,
    connector.catalog_status,
    connector.catalog_schema_version,
    connector.catalog_source_path,
    connector.definition_origin,
    connector.readiness_stage,
    connector.access_status,
    connector.access_reason,
    connector.requestable_reason,
    connector.request_access_action,
    connector.auth_model,
    connector.verification_endpoint,
    connector.priority_tier,
    connector.catalog_path,
    connector.package_path,
    connector.next_action,
    connector.provider_api_status,
    connector.provider_api_basis,
    connector.provider_api_transport,
    connector.provider_api_auth,
    connector.provider_api_auth_mechanics,
    connector.provider_api_base_url,
    connector.provider_api_endpoint,
    connector.provider_api_spec_url,
    connector.provider_api_spec_kind,
    connector.provider_api_proof_level,
    connector.integration_depth?.level,
    connector.integration_depth?.score,
    connectorRuntimeSurfaceLabel(connector),
    ...(connector.priority_reasons ?? []),
    ...(connector.missing_families ?? []),
    ...(connector.existing_references ?? []),
    ...(connector.search_queries ?? []),
    ...(connector.provider_api_references ?? []),
    ...(connector.provider_api_auth_evidence ?? []),
    ...(connector.provider_api_scope_evidence ?? []),
    ...(connector.provider_api_mapped_families ?? []),
    ...(connector.provider_api_missing_families ?? []),
    ...(connector.provider_api_proof_gaps ?? []),
    ...(connector.emitted_kinds ?? []),
    ...(connector.catalog_categories ?? []),
    ...(connector.resource_families ?? []).flatMap((family) => [
      family.id,
      family.label,
      family.path,
      family.method,
      family.record_selector,
      family.id_field,
      family.name_field,
      family.event_kind,
      family.event?.kind,
      family.schema_ref,
      family.event?.schema_ref,
      family.projection_template,
      family.projection?.template,
      family.projection?.fields ? Object.values(family.projection.fields) : [],
      ...(family.coverage ?? []).flatMap(connectorCoverageSearchValues),
    ]),
    ...(connector.scope_options ?? []).flatMap(connectorScopeOptionSearchValues),
  ]
    .filter(Boolean)
    .join("\n")
    .toLowerCase();

export const connectorCoverageControlRefLabel = (ref?: ConnectorCoverageControlRef) => {
  if (!ref) return "";
  return [ref.framework_name || ref.framework_id, ref.control_id].filter(Boolean).join(" ");
};

export const connectorCoverageSearchValues = (coverage: string | ConnectorCoverageDimension): string[] => {
  if (typeof coverage === "string") return [coverage];
  return [
    coverage.id,
    coverage.dimension_id,
    coverage.type,
    coverage.dimension_type,
    coverage.title,
    coverage.label,
    coverage.support,
    coverage.support_level,
    coverage.state,
    coverage.warning,
    coverage.families,
    coverage.known_unsupported_fields,
    coverage.notes,
    coverage.evidence_types,
    coverage.control_domains,
    coverage.supported_runtime_families,
    coverage.control_refs?.map(connectorCoverageControlRefLabel),
    coverage.matched_control_refs?.map(connectorCoverageControlRefLabel),
  ]
    .flat()
    .filter((value): value is string => typeof value === "string" && value.trim().length > 0);
};

export const connectorScopeOptionSearchValues = (option: ConnectorScopeOption | ConnectorDefinitionScopeOption): string[] => [
  option.id,
  option.label,
  option.type,
  option.support,
  option.families,
  option.known_unsupported_fields,
  option.notes,
  option.evidence_types,
  option.control_domains,
  option.control_refs?.map(connectorCoverageControlRefLabel),
]
  .flat()
  .filter((value): value is string => typeof value === "string" && value.trim().length > 0);

const knownCredentialStoreID = (value: string): value is ConnectorCredentialStoreID =>
  Object.prototype.hasOwnProperty.call(credentialStoreCatalog, value);

const safeStoreDetail = (detail?: string) => {
  const value = detail?.trim();
  if (!value) return "";
  if (/ready/i.test(value)) return "Ready";
  if (/state store unavailable/i.test(value)) return "State store unavailable";
  if (/credential key unavailable/i.test(value)) return "Credential key unavailable";
  if (/unavailable|disabled|not configured/i.test(value)) return "Unavailable";
  return "Configured by deployment";
};

const safeStringList = (values?: string[]) =>
  (Array.isArray(values) ? values : []).map((value) => String(value ?? "").trim()).filter(Boolean);

const defaultReferencePrefixes = (id: ConnectorCredentialStoreID, mode: ConnectorCredentialStoreMode) => {
  if (mode === "encrypted_submission") return [];
  if (id === "aws_secrets_manager") return ["env:", "aws-sm:"];
  return ["env:"];
};

const defaultReferencePlaceholder = (id: ConnectorCredentialStoreID, mode: ConnectorCredentialStoreMode) => {
  if (mode === "encrypted_submission") return undefined;
  if (id === "aws_secrets_manager") return "aws-sm:us-east-1:cerebro/<tenant>/<source>/<runtime>/credentials#<field>";
  return "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>";
};

export const normalizeCredentialStores = (library?: ConnectorLibraryResponse | null): NormalizedCredentialStore[] => {
  const advertised = new Map<string, ConnectorCredentialStore>();
  (library?.credential_stores ?? []).forEach((store) => {
    if (store && typeof store.id === "string" && knownCredentialStoreID(store.id)) {
      advertised.set(store.id, store);
    }
  });

  const fallbackVaultAvailable = Boolean(library?.credential_vault?.available && library?.credential_transport?.available);
  const stores = credentialStoreOrder.map((id) => {
    const catalog = credentialStoreCatalog[id];
    const server = advertised.get(id);
    const isFallbackVault = id === "cerebro_vault" && !server;
    const available = Boolean(server?.available ?? (isFallbackVault ? fallbackVaultAvailable : false));
    const detail = safeStoreDetail(server?.detail ?? (isFallbackVault ? library?.credential_vault?.detail : undefined));
    const rawMode = server?.mode === "external_reference" ? "reference" : server?.mode;
    const mode = (rawMode && ["encrypted_submission", "reference", "environment_managed"].includes(rawMode)
      ? rawMode
      : catalog.mode) as ConnectorCredentialStoreMode;
    const status = server?.status?.trim() || (available ? "ready" : "needs_configuration");
    const referencePrefixes = safeStringList(server?.reference_prefixes);
    const label = id === "environment_managed" ? catalog.label : server?.label?.trim() || catalog.label;
    const disabledReason = available
      ? undefined
      : id === "cerebro_vault"
        ? detail || "Credential transport or vault is unavailable."
        : status === "needs_configuration"
          ? "Enable this store in the Cerebro backend configuration."
          : "Store is not enabled in this deployment.";
    return {
      ...catalog,
      label,
      provider: server?.provider?.trim() || catalog.provider,
      description: server?.description?.trim() || catalog.description,
      mode,
      available,
      default: Boolean(server?.default),
      status,
      detail: detail || (available ? "Ready" : "Unavailable"),
      referencePrefixes: referencePrefixes.length > 0 ? referencePrefixes : defaultReferencePrefixes(id, mode),
      referenceNamespaceTemplate: server?.reference_namespace_template?.trim() || undefined,
      referenceFieldTemplate: server?.reference_field_template?.trim() || undefined,
      referencePlaceholder: server?.reference_placeholder?.trim() || defaultReferencePlaceholder(id, mode),
      nativeResolutionAvailable: Boolean(server?.native_resolution_available),
      setupSteps: Array.isArray(server?.setup_steps) ? server.setup_steps : [],
      requiredConfig: Array.isArray(server?.required_config) ? server.required_config : [],
      disabledReason,
    };
  });

  const defaultID = stores.find((store) => store.default && store.available)?.id
    ?? stores.find((store) => store.available)?.id
    ?? "cerebro_vault";
  return stores.map((store) => ({ ...store, default: store.id === defaultID }));
};

export const defaultCredentialStoreID = (stores: NormalizedCredentialStore[]): ConnectorCredentialStoreID =>
  stores.find((store) => store.default && store.available)?.id
  ?? stores.find((store) => store.available)?.id
  ?? stores.find((store) => store.default)?.id
  ?? "cerebro_vault";

export const connectorSubmitErrorMessage = (status?: number) => {
  if (status === 400) return "Connection request was not accepted. Check required fields and credential store availability.";
  if (status === 401 || status === 403) return "You do not have permission to create this connector connection.";
  if (status === 404) return "Connector source was not found.";
  if (status === 503) return "Credential storage or runtime services are unavailable.";
  return "Connection failed. No credential details were displayed.";
};

export const connectorCredentialErrorMessage = (status?: number) => {
  if (status === 400) return "Credential request was not accepted. Check tenant, connection ID, and required fields.";
  if (status === 401 || status === 403) return "You do not have permission to manage credentials for this tenant.";
  if (status === 404) return "Credential or connector source was not found.";
  if (status === 503) return "Credential broker is unavailable.";
  return "Credential request failed. Secret values were not displayed.";
};

const withCredentialQuery = (path: string, params: Record<string, string | undefined> = {}) => {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value?.trim()) query.set(key, value.trim());
  });
  const queryString = query.toString();
  return queryString ? `${path}?${queryString}` : path;
};

export const connectorCredentialsPath = (
  sourceID: string,
  params: { tenantID?: string; runtimeID?: string; status?: ConnectorCredentialStatus } = {},
) => withCredentialQuery(`/connectors/${encodeURIComponent(sourceID)}/credentials`, {
  tenant_id: params.tenantID,
  runtime_id: params.runtimeID,
  status: params.status,
});

export const connectorCredentialPath = (sourceID: string, credentialID: string) =>
  `/connectors/${encodeURIComponent(sourceID)}/credentials/${encodeURIComponent(credentialID)}`;

export const connectorCredentialRotatePath = (sourceID: string, credentialID: string) =>
  `${connectorCredentialPath(sourceID, credentialID)}/rotate`;

export const connectorCredentialRevokePath = (sourceID: string, credentialID: string) =>
  `${connectorCredentialPath(sourceID, credentialID)}/revoke`;

export const connectorDepositsPath = (sourceID: string) =>
  `/connectors/${encodeURIComponent(sourceID)}/deposits`;

export const sourceRuntimeSyncPath = (runtimeID: string, pageLimit = 1) => {
  const query = new URLSearchParams();
  if (pageLimit > 0) query.set("page_limit", String(pageLimit));
  const queryString = query.toString();
  return `/source-runtimes/${encodeURIComponent(runtimeID)}/sync${queryString ? `?${queryString}` : ""}`;
};

export const connectorCredentialStatusLabel = (status?: ConnectorCredentialStatus) => {
  switch (status) {
    case "valid":
      return "Valid";
    case "revoked":
      return "Revoked";
    case "invalid":
      return "Invalid";
    case "rotating":
      return "Rotating";
    case "pending":
      return "Pending";
    default:
      return status?.trim() || "Unknown";
  }
};

export const connectorCredentialHealth = (credential?: Pick<ConnectorCredential, "status" | "last_used_at" | "updated_at"> | null) => {
  if (!credential) return "unknown";
  if (credential.status === "revoked" || credential.status === "invalid") return "bad";
  if (credential.status === "pending" || credential.status === "rotating") return "warning";
  return "healthy";
};

const uniqueClean = (values: string[], lower = true) => {
  const seen = new Set<string>();
  const result: string[] = [];
  values.forEach((value) => {
    const trimmed = value.trim();
    const normalized = lower ? trimmed.toLowerCase() : trimmed;
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    result.push(normalized);
  });
  return result.sort((left, right) => left.localeCompare(right));
};

export const normalizeScopePolicy = (policy?: ConnectorScopePolicy): ConnectorScopePolicy | undefined => {
  const excludedFamilies = uniqueClean(policy?.excluded_families ?? []);
  const excludedAssetClasses = uniqueClean(policy?.excluded_asset_classes ?? []);
  const excludedKinds = uniqueClean(policy?.excluded_kinds ?? []);
  const excludedResourceURNs = uniqueClean(policy?.excluded_resource_urns ?? [], false);
  const excludedResources = (policy?.excluded_resources ?? [])
    .map((resource) => ({
      urn: resource.urn?.trim(),
      type: resource.type?.trim().toLowerCase(),
      id: resource.id?.trim(),
      reason: resource.reason?.trim(),
    }))
    .filter((resource) => resource.urn || (resource.type && resource.id));
  if (
    excludedFamilies.length === 0 &&
    excludedAssetClasses.length === 0 &&
    excludedKinds.length === 0 &&
    excludedResourceURNs.length === 0 &&
    excludedResources.length === 0
  ) {
    return undefined;
  }
  return {
    mode: "exclude",
    ...(excludedFamilies.length > 0 ? { excluded_families: excludedFamilies } : {}),
    ...(excludedAssetClasses.length > 0 ? { excluded_asset_classes: excludedAssetClasses } : {}),
    ...(excludedKinds.length > 0 ? { excluded_kinds: excludedKinds } : {}),
    ...(excludedResourceURNs.length > 0 ? { excluded_resource_urns: excludedResourceURNs } : {}),
    ...(excludedResources.length > 0 ? { excluded_resources: excludedResources } : {}),
  };
};

export const scopePolicyExclusionCount = (policy?: ConnectorScopePolicy) =>
  (policy?.excluded_families?.length ?? 0) +
  (policy?.excluded_asset_classes?.length ?? 0) +
  (policy?.excluded_kinds?.length ?? 0) +
  (policy?.excluded_resource_urns?.length ?? 0) +
  (policy?.excluded_resources?.length ?? 0);

export const connectorScopeOptionFamilies = (option: ConnectorScopeOption) => {
  const families = option.families?.length ? option.families : [option.id];
  return uniqueClean(families);
};

const validateConnectorCredentialKey = (key: ConnectorCredentialKey) => {
  if (!key?.key_id || typeof key.key_id !== "string") {
    throw new Error("Credential transport key is missing an id.");
  }
  if (key.algorithm !== CONNECTOR_CREDENTIAL_TRANSPORT_ALGORITHM) {
    throw new Error("Credential transport algorithm is not supported.");
  }
  const jwk = key.jwk as Record<string, unknown> | undefined;
  if (!jwk || typeof jwk !== "object") {
    throw new Error("Credential transport key is missing.");
  }
  const forbiddenPrivateFields = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
  if (forbiddenPrivateFields.some((field) => Object.prototype.hasOwnProperty.call(jwk, field))) {
    throw new Error("Credential transport key unexpectedly included private material.");
  }
  if (jwk.kty !== "RSA" || jwk.alg !== CONNECTOR_CREDENTIAL_TRANSIT_JWK_ALGORITHM) {
    throw new Error("Credential transport key type is not supported.");
  }
  if (jwk.use && jwk.use !== "enc") {
    throw new Error("Credential transport key use is not supported.");
  }
  if (Array.isArray(jwk.key_ops) && !jwk.key_ops.includes("encrypt")) {
    throw new Error("Credential transport key cannot encrypt.");
  }
  if (typeof jwk.n !== "string" || typeof jwk.e !== "string") {
    throw new Error("Credential transport key is incomplete.");
  }
  return key.jwk;
};

const connectorCredentialAAD = (keyID: string, context?: ConnectorCredentialContext) =>
  new TextEncoder().encode(
    context
      ? ["connector-credential", "v1", keyID, context.sourceID, context.tenantID, context.runtimeID, context.credentialStoreID].join("\0")
      : keyID,
  );

export async function encryptConnectorCredentials(
  key: ConnectorCredentialKey,
  fields: Record<string, string>,
  context?: ConnectorCredentialContext,
) {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is unavailable");
  }
  const jwk = validateConnectorCredentialKey(key);
  const plaintext = new TextEncoder().encode(JSON.stringify(fields));
  const rsaKey = await globalThis.crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["wrapKey"],
  );
  const aesKey = await globalThis.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  try {
    const ciphertext = await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: connectorCredentialAAD(key.key_id, context) },
      aesKey,
      plaintext,
    );
    const wrappedKey = await globalThis.crypto.subtle.wrapKey("raw", aesKey, rsaKey, { name: "RSA-OAEP" });
    return {
      key_id: key.key_id,
      algorithm: key.algorithm,
      wrapped_key: arrayBufferToBase64(wrappedKey),
      nonce: arrayBufferToBase64(nonce),
      ciphertext: arrayBufferToBase64(ciphertext),
    };
  } finally {
    plaintext.fill(0);
  }
}

const arrayBufferToBase64 = (buffer: ArrayBuffer | Uint8Array) => {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
};
