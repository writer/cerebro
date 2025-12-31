/* eslint-disable */
// Auto-generated schema adapters
import type { components } from '../openapi.js';
import { transformOpenApi, type OpenApiTransformOptions, type Camelize } from '../../serialization.js';
export const schemaAdapterDefinitions = {
  "AccessReviewRequest": {
    schema: "AccessReviewRequest",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "AccountCreate": {
    schema: "AccountCreate",
    snakeCaseDateKeys: [],
  },
  "AccountResponse": {
    schema: "AccountResponse",
    snakeCaseDateKeys: [],
  },
  "AddReviewCommentRequest": {
    schema: "AddReviewCommentRequest",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "AgentHealth": {
    schema: "AgentHealth",
    snakeCaseDateKeys: ["last_heartbeat"],
    deep: true,
  },
  "ArtifactPackCreate": {
    schema: "ArtifactPackCreate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "ArtifactPackDefinition": {
    schema: "ArtifactPackDefinition",
    snakeCaseDateKeys: ["last_deployed_at"],
    deep: true,
  },
  "ArtifactPackTaskCreate": {
    schema: "ArtifactPackTaskCreate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "ArtifactPackTrigger": {
    schema: "ArtifactPackTrigger",
    snakeCaseDateKeys: [],
  },
  "ArtifactPackTriggerCreate": {
    schema: "ArtifactPackTriggerCreate",
    snakeCaseDateKeys: [],
  },
  "ArtifactPackUpdate": {
    schema: "ArtifactPackUpdate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "ArtifactTaskDefinition": {
    schema: "ArtifactTaskDefinition",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "ArtifactTaskParameter": {
    schema: "ArtifactTaskParameter",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "ArtifactTaskResources": {
    schema: "ArtifactTaskResources",
    snakeCaseDateKeys: [],
  },
  "ArtifactTool": {
    schema: "ArtifactTool",
    snakeCaseDateKeys: [],
  },
  "AssignReviewTaskRequest": {
    schema: "AssignReviewTaskRequest",
    snakeCaseDateKeys: [],
  },
  "AttackPathQuery": {
    schema: "AttackPathQuery",
    snakeCaseDateKeys: [],
  },
  "BlastRadiusQuery": {
    schema: "BlastRadiusQuery",
    snakeCaseDateKeys: [],
  },
  "BlastRadiusRequest": {
    schema: "BlastRadiusRequest",
    snakeCaseDateKeys: ["at_time"],
  },
  "Body_login_form_api_v1_auth_login_post": {
    schema: "Body_login_form_api_v1_auth_login_post",
    snakeCaseDateKeys: [],
  },
  "Body_login_oauth2_api_v1_auth_login_post": {
    schema: "Body_login_oauth2_api_v1_auth_login_post",
    snakeCaseDateKeys: [],
  },
  "BulkReviewUpdateRequest": {
    schema: "BulkReviewUpdateRequest",
    snakeCaseDateKeys: ["due_at"],
    deep: true,
  },
  "cerebro__api__routers__agents__MessageResponse": {
    schema: "cerebro__api__routers__agents__MessageResponse",
    snakeCaseDateKeys: ["timestamp"],
    deep: true,
  },
  "cerebro__api__routers__v2__agents__SessionListResponse": {
    schema: "cerebro__api__routers__v2__agents__SessionListResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "cerebro__api__routers__v2__agents__SessionResponse": {
    schema: "cerebro__api__routers__v2__agents__SessionResponse",
    snakeCaseDateKeys: ["created_at"],
    deep: true,
  },
  "cerebro__api__routers__v2__agents__ToolInvocationResponse": {
    schema: "cerebro__api__routers__v2__agents__ToolInvocationResponse",
    snakeCaseDateKeys: ["completed_at","started_at"],
    deep: true,
  },
  "cerebro__api__routers__v2__findings__FindingResponse": {
    schema: "cerebro__api__routers__v2__findings__FindingResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "cerebro__api__routers__v2__findings__FindingStats": {
    schema: "cerebro__api__routers__v2__findings__FindingStats",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "cerebro__api__routers__v2__organizations__OrganizationResponse": {
    schema: "cerebro__api__routers__v2__organizations__OrganizationResponse",
    snakeCaseDateKeys: ["created_at"],
    deep: true,
  },
  "cerebro__api__schemas__main__FindingUpdate": {
    schema: "cerebro__api__schemas__main__FindingUpdate",
    snakeCaseDateKeys: [],
  },
  "cerebro__api__schemas__main__OrganizationCreate": {
    schema: "cerebro__api__schemas__main__OrganizationCreate",
    snakeCaseDateKeys: [],
  },
  "ChangeReplayRequest": {
    schema: "ChangeReplayRequest",
    snakeCaseDateKeys: ["end_time","start_time"],
    deep: true,
  },
  "CodeMetrics": {
    schema: "CodeMetrics",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "CollectionRequest": {
    schema: "CollectionRequest",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "CollectionResponse": {
    schema: "CollectionResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "ComplianceEvidence": {
    schema: "ComplianceEvidence",
    snakeCaseDateKeys: ["collected_at"],
    deep: true,
  },
  "ComplianceStatusResponse": {
    schema: "ComplianceStatusResponse",
    snakeCaseDateKeys: ["assessment_date"],
    deep: true,
  },
  "ConfigSnapshotResponse": {
    schema: "ConfigSnapshotResponse",
    snakeCaseDateKeys: ["captured_at"],
    deep: true,
  },
  "ConfigurationDrift": {
    schema: "ConfigurationDrift",
    snakeCaseDateKeys: [],
  },
  "ControlSummary": {
    schema: "ControlSummary",
    snakeCaseDateKeys: [],
  },
  "CreateSessionRequest": {
    schema: "CreateSessionRequest",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "CustomerCreateRequest": {
    schema: "CustomerCreateRequest",
    snakeCaseDateKeys: ["last_engagement_at","next_qbr_at"],
    deep: true,
  },
  "DependencyGraph": {
    schema: "DependencyGraph",
    snakeCaseDateKeys: ["timestamp"],
    deep: true,
  },
  "DependencyScan": {
    schema: "DependencyScan",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "DependencyVulnerability": {
    schema: "DependencyVulnerability",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "EmailConfigCreate": {
    schema: "EmailConfigCreate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "EmailConfigResponse": {
    schema: "EmailConfigResponse",
    snakeCaseDateKeys: ["created_at","updated_at"],
    deep: true,
  },
  "EmailConfigUpdate": {
    schema: "EmailConfigUpdate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "EmailNotificationResponse": {
    schema: "EmailNotificationResponse",
    snakeCaseDateKeys: ["created_at","sent_at"],
    deep: true,
  },
  "EmailNotificationStatsResponse": {
    schema: "EmailNotificationStatsResponse",
    snakeCaseDateKeys: [],
  },
  "EndpointThreat": {
    schema: "EndpointThreat",
    snakeCaseDateKeys: ["detected_at","resolved_at","updated_at"],
    deep: true,
  },
  "ErrorResponse": {
    schema: "ErrorResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "EvidenceBundleRequest": {
    schema: "EvidenceBundleRequest",
    snakeCaseDateKeys: ["period_end","period_start"],
    deep: true,
  },
  "EvidenceCollectionRequest": {
    schema: "EvidenceCollectionRequest",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "ExceptionRequest": {
    schema: "ExceptionRequest",
    snakeCaseDateKeys: [],
  },
  "FindingCreate": {
    schema: "FindingCreate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "FindingPageResponse": {
    schema: "FindingPageResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "FindingResponse": {
    schema: "FindingResponse",
    snakeCaseDateKeys: ["first_seen","last_seen"],
    deep: true,
  },
  "FindingStats": {
    schema: "FindingStats",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "FindingUpdate": {
    schema: "FindingUpdate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "ForensicReplayRequest": {
    schema: "ForensicReplayRequest",
    snakeCaseDateKeys: ["target_time"],
    deep: true,
  },
  "FrameworkSummary": {
    schema: "FrameworkSummary",
    snakeCaseDateKeys: [],
  },
  "FrontendObservationTelemetry": {
    schema: "FrontendObservationTelemetry",
    snakeCaseDateKeys: ["occurred_at"],
    deep: true,
  },
  "HostEvent": {
    schema: "HostEvent",
    snakeCaseDateKeys: ["timestamp"],
    deep: true,
  },
  "HostEventBatch": {
    schema: "HostEventBatch",
    snakeCaseDateKeys: ["collected_at"],
    deep: true,
  },
  "HostTelemetry": {
    schema: "HostTelemetry",
    snakeCaseDateKeys: ["collected_at"],
    deep: true,
  },
  "HTTPValidationError": {
    schema: "HTTPValidationError",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "IdentityAnomalyRequest": {
    schema: "IdentityAnomalyRequest",
    snakeCaseDateKeys: [],
  },
  "IntegrationAdminOverview": {
    schema: "IntegrationAdminOverview",
    snakeCaseDateKeys: ["last_synced_at","next_scheduled_sync_at"],
    deep: true,
  },
  "IntegrationCoverageAccounts": {
    schema: "IntegrationCoverageAccounts",
    snakeCaseDateKeys: [],
  },
  "IntegrationCoverageScopes": {
    schema: "IntegrationCoverageScopes",
    snakeCaseDateKeys: [],
  },
  "IntegrationCoverageSummary": {
    schema: "IntegrationCoverageSummary",
    snakeCaseDateKeys: ["evaluated_at","last_success"],
    deep: true,
  },
  "IntegrationIssueHistoryEvent": {
    schema: "IntegrationIssueHistoryEvent",
    snakeCaseDateKeys: ["last_timestamp","observed_at"],
    deep: true,
  },
  "IntegrationIssueHistoryResponse": {
    schema: "IntegrationIssueHistoryResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "IntegrationIssueResponse": {
    schema: "IntegrationIssueResponse",
    snakeCaseDateKeys: ["last_timestamp","observed_at"],
    deep: true,
  },
  "IntegrationIssueTrendBucket": {
    schema: "IntegrationIssueTrendBucket",
    snakeCaseDateKeys: ["bucket_end","bucket_start"],
    deep: true,
  },
  "IntegrationStatus": {
    schema: "IntegrationStatus",
    snakeCaseDateKeys: ["last_timestamp"],
    deep: true,
  },
  "IntegrationSyncJobResponse": {
    schema: "IntegrationSyncJobResponse",
    snakeCaseDateKeys: ["queued_at"],
  },
  "IntegrationSyncRequest": {
    schema: "IntegrationSyncRequest",
    snakeCaseDateKeys: [],
  },
  "IntegrationSyncStatusResponse": {
    schema: "IntegrationSyncStatusResponse",
    snakeCaseDateKeys: ["date_done"],
  },
  "JMLCampaignRequest": {
    schema: "JMLCampaignRequest",
    snakeCaseDateKeys: [],
  },
  "LoginRequest": {
    schema: "LoginRequest",
    snakeCaseDateKeys: [],
  },
  "MemoryEntryResponse": {
    schema: "MemoryEntryResponse",
    snakeCaseDateKeys: ["created_at","last_accessed_at"],
    deep: true,
  },
  "MemoryHighlightResponse": {
    schema: "MemoryHighlightResponse",
    snakeCaseDateKeys: ["last_accessed_at"],
    deep: true,
  },
  "MemoryStatsResponse": {
    schema: "MemoryStatsResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "MessageCreate": {
    schema: "MessageCreate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "MessageResponse": {
    schema: "MessageResponse",
    snakeCaseDateKeys: ["created_at"],
    deep: true,
  },
  "NetworkConnection": {
    schema: "NetworkConnection",
    snakeCaseDateKeys: [],
  },
  "OrganizationCreate": {
    schema: "OrganizationCreate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "OrganizationResponse": {
    schema: "OrganizationResponse",
    snakeCaseDateKeys: ["created_at"],
  },
  "OrganizationUpdate": {
    schema: "OrganizationUpdate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "PaginatedResponse": {
    schema: "PaginatedResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "PaginationMeta": {
    schema: "PaginationMeta",
    snakeCaseDateKeys: [],
  },
  "PolicySimulationExample": {
    schema: "PolicySimulationExample",
    snakeCaseDateKeys: ["completed_at","started_at"],
    deep: true,
  },
  "PolicySimulationRequest": {
    schema: "PolicySimulationRequest",
    snakeCaseDateKeys: [],
  },
  "PolicySimulationResponse": {
    schema: "PolicySimulationResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "PolicySuggestionResponse": {
    schema: "PolicySuggestionResponse",
    snakeCaseDateKeys: ["last_seen"],
    deep: true,
  },
  "PreAuditRunRequest": {
    schema: "PreAuditRunRequest",
    snakeCaseDateKeys: ["audit_date"],
    deep: true,
  },
  "PreAuditRunResponse": {
    schema: "PreAuditRunResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "PrincipalResponse": {
    schema: "PrincipalResponse",
    snakeCaseDateKeys: [],
  },
  "ProcessSnapshot": {
    schema: "ProcessSnapshot",
    snakeCaseDateKeys: ["start_time"],
    deep: true,
  },
  "QuarantineRequest": {
    schema: "QuarantineRequest",
    snakeCaseDateKeys: [],
  },
  "QueryRequest": {
    schema: "QueryRequest",
    snakeCaseDateKeys: [],
  },
  "QueryResponse": {
    schema: "QueryResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "RefreshTokenRequest": {
    schema: "RefreshTokenRequest",
    snakeCaseDateKeys: [],
  },
  "RemediationActionUpdateRequest": {
    schema: "RemediationActionUpdateRequest",
    snakeCaseDateKeys: [],
  },
  "RemediationBulkUpdateRequest": {
    schema: "RemediationBulkUpdateRequest",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "RemediationNoteRequest": {
    schema: "RemediationNoteRequest",
    snakeCaseDateKeys: [],
  },
  "RepositoryTelemetry": {
    schema: "RepositoryTelemetry",
    snakeCaseDateKeys: ["timestamp"],
    deep: true,
  },
  "ResolveReviewTaskRequest": {
    schema: "ResolveReviewTaskRequest",
    snakeCaseDateKeys: [],
  },
  "ResourceResponse": {
    schema: "ResourceResponse",
    snakeCaseDateKeys: ["created_at"],
  },
  "RestorationApproval": {
    schema: "RestorationApproval",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "RestorationRequest": {
    schema: "RestorationRequest",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "ReviewDecisionRequest": {
    schema: "ReviewDecisionRequest",
    snakeCaseDateKeys: [],
  },
  "ReviewNotificationResponse": {
    schema: "ReviewNotificationResponse",
    snakeCaseDateKeys: ["created_at","delivered_at"],
    deep: true,
  },
  "ReviewQueuePendingSummary": {
    schema: "ReviewQueuePendingSummary",
    snakeCaseDateKeys: ["next_due","oldest_created"],
  },
  "ReviewQueuePrioritySummary": {
    schema: "ReviewQueuePrioritySummary",
    snakeCaseDateKeys: [],
  },
  "ReviewQueueStatusSummary": {
    schema: "ReviewQueueStatusSummary",
    snakeCaseDateKeys: ["newest_created","oldest_created"],
  },
  "ReviewQueueSummary": {
    schema: "ReviewQueueSummary",
    snakeCaseDateKeys: ["generated_at"],
    deep: true,
  },
  "ReviewTaskPageResponse": {
    schema: "ReviewTaskPageResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "ReviewTaskResponse": {
    schema: "ReviewTaskResponse",
    snakeCaseDateKeys: ["created_at","due_at","resolved_at"],
    deep: true,
  },
  "RuleCreate": {
    schema: "RuleCreate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "RuleResponse": {
    schema: "RuleResponse",
    snakeCaseDateKeys: ["created_at"],
    deep: true,
  },
  "RuntimeEventResponse": {
    schema: "RuntimeEventResponse",
    snakeCaseDateKeys: ["created_at"],
    deep: true,
  },
  "RuntimeEventSummaryResponse": {
    schema: "RuntimeEventSummaryResponse",
    snakeCaseDateKeys: ["first_seen","last_seen"],
  },
  "RuntimeTelemetry": {
    schema: "RuntimeTelemetry",
    snakeCaseDateKeys: ["timestamp"],
    deep: true,
  },
  "SecretsScanResult": {
    schema: "SecretsScanResult",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "SecurityEvent": {
    schema: "SecurityEvent",
    snakeCaseDateKeys: ["timestamp"],
    deep: true,
  },
  "SendMessageRequest": {
    schema: "SendMessageRequest",
    snakeCaseDateKeys: [],
  },
  "ServalConfigRequest": {
    schema: "ServalConfigRequest",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "ServalConfigResponse": {
    schema: "ServalConfigResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "SessionCreate": {
    schema: "SessionCreate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "SessionListResponse": {
    schema: "SessionListResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "SessionResponse": {
    schema: "SessionResponse",
    snakeCaseDateKeys: ["created_at"],
    deep: true,
  },
  "SessionUpdate": {
    schema: "SessionUpdate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "SessionWithMessagesResponse": {
    schema: "SessionWithMessagesResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "SlackNotificationResponse": {
    schema: "SlackNotificationResponse",
    snakeCaseDateKeys: ["created_at","sent_at"],
  },
  "SlackNotificationStats": {
    schema: "SlackNotificationStats",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "SlackWebhookCreate": {
    schema: "SlackWebhookCreate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "SlackWebhookResponse": {
    schema: "SlackWebhookResponse",
    snakeCaseDateKeys: ["created_at","updated_at"],
    deep: true,
  },
  "SlackWebhookUpdate": {
    schema: "SlackWebhookUpdate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "SoftwarePackage": {
    schema: "SoftwarePackage",
    snakeCaseDateKeys: ["install_time"],
    deep: true,
  },
  "TableDetailInfo": {
    schema: "TableDetailInfo",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "TableDetailResponse": {
    schema: "TableDetailResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "TableInfo": {
    schema: "TableInfo",
    snakeCaseDateKeys: [],
  },
  "TablesResponse": {
    schema: "TablesResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "TelemetryAlertItem": {
    schema: "TelemetryAlertItem",
    snakeCaseDateKeys: ["triggered_at"],
    deep: true,
  },
  "TelemetryAlertsResponse": {
    schema: "TelemetryAlertsResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "TelemetryHealthResponse": {
    schema: "TelemetryHealthResponse",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "TestCreateRequest": {
    schema: "TestCreateRequest",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "Token": {
    schema: "Token",
    snakeCaseDateKeys: [],
  },
  "TokenResponse": {
    schema: "TokenResponse",
    snakeCaseDateKeys: [],
  },
  "TokenUsageResponse": {
    schema: "TokenUsageResponse",
    snakeCaseDateKeys: [],
  },
  "ToolInvocationResponse": {
    schema: "ToolInvocationResponse",
    snakeCaseDateKeys: ["completed_at","started_at"],
  },
  "User": {
    schema: "User",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "ValidationError": {
    schema: "ValidationError",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "VendorCreateRequest": {
    schema: "VendorCreateRequest",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "WebhookConfigCreate": {
    schema: "WebhookConfigCreate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "WebhookConfigResponse": {
    schema: "WebhookConfigResponse",
    snakeCaseDateKeys: ["created_at","updated_at"],
    deep: true,
  },
  "WebhookConfigUpdate": {
    schema: "WebhookConfigUpdate",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "WebhookNotificationResponse": {
    schema: "WebhookNotificationResponse",
    snakeCaseDateKeys: ["created_at","sent_at"],
    deep: true,
  },
  "WebhookNotificationStatsResponse": {
    schema: "WebhookNotificationStatsResponse",
    snakeCaseDateKeys: [],
  },
  "WhatIfScenario": {
    schema: "WhatIfScenario",
    snakeCaseDateKeys: [],
    deep: true,
  },
  "WorkflowEvaluationRequest": {
    schema: "WorkflowEvaluationRequest",
    snakeCaseDateKeys: [],
    deep: true,
  },
} as const;

export type SchemaName = keyof typeof schemaAdapterDefinitions;

type SchemaDefinition<Name extends SchemaName> = typeof schemaAdapterDefinitions[Name];
type SchemaPayload<Name extends SchemaName> = components['schemas'][SchemaDefinition<Name>['schema']];

export function adaptSchema<Name extends SchemaName, TResult>(
  schema: Name,
  payload: SchemaPayload<Name>,
  projector: (record: Camelize<SchemaPayload<Name>>) => TResult,
  options: OpenApiTransformOptions = {},
): TResult {
  const definition = schemaAdapterDefinitions[schema];
  const mergedSnakeCaseKeys = mergeDateKeys(definition?.snakeCaseDateKeys, options.snakeCaseDateKeys);
  const definitionDeep = definition && Object.prototype.hasOwnProperty.call(definition, "deep")
    ? (definition as { deep?: boolean }).deep
    : undefined;
  const mergedOptions: OpenApiTransformOptions = {
    ...options,
    snakeCaseDateKeys: mergedSnakeCaseKeys,
    deep: options.deep ?? definitionDeep,
  };
  return transformOpenApi(
    payload as Record<string, unknown>,
    projector as (record: Camelize<Record<string, unknown>>) => TResult,
    mergedOptions,
  );
}

export function createSchemaAdapter<Name extends SchemaName>(schema: Name) {
  return function adapt<TResult>(
    payload: SchemaPayload<Name>,
    projector: (record: Camelize<SchemaPayload<Name>>) => TResult,
    options: OpenApiTransformOptions = {},
  ): TResult {
    return adaptSchema(schema, payload, projector, options);
  };
}

function mergeDateKeys(
  baseKeys: readonly string[] | undefined,
  overrideKeys: readonly string[] | undefined,
): readonly string[] | undefined {
  if (!baseKeys?.length && !overrideKeys?.length) {
    return overrideKeys ?? baseKeys;
  }
  const merged = new Set<string>([...(baseKeys ?? []), ...(overrideKeys ?? [])]);
  return Array.from(merged);
}
