# Generated Config Environment Variables

Generated from `internal/app/app_config.go` (`LoadConfig`) via `go run ./scripts/generate_config_docs/main.go`.

Total variables: **377**

| Variable | Reader(s) | Default(s) | Config Field(s) | Validation rule(s) |
|---|---|---|---|---|
| `AGENT_PENDING_TOOL_APPROVAL_TTL` | `getEnvDuration` | `defaultAgentPendingToolApprovalTTL` | `AgentPendingToolApprovalTTL` | `must be greater than 0` |
| `AGENT_REMOTE_TOOLS_DISCOVER_TIMEOUT` | `getEnvDuration` | `5 * time.Second` | `AgentRemoteToolsDiscoverTimeout` | `-` |
| `AGENT_REMOTE_TOOLS_ENABLED` | `getEnvBool` | `false` | `AgentRemoteToolsEnabled` | `-` |
| `AGENT_REMOTE_TOOLS_MANIFEST_SUBJECT` | `getEnv` | `"ensemble.tools.manifest"` | `AgentRemoteToolsManifestSubject` | `-` |
| `AGENT_REMOTE_TOOLS_MAX_TOOLS` | `getEnvInt` | `200` | `AgentRemoteToolsMaxTools` | `-` |
| `AGENT_REMOTE_TOOLS_REQUEST_PREFIX` | `getEnv` | `"ensemble.tools.request"` | `AgentRemoteToolsRequestPrefix` | `-` |
| `AGENT_REMOTE_TOOLS_REQUEST_TIMEOUT` | `getEnvDuration` | `30 * time.Second` | `AgentRemoteToolsRequestTimeout` | `-` |
| `AGENT_TOOL_PUBLISHER_ENABLED` | `getEnvBool` | `false` | `AgentToolPublisherEnabled` | `-` |
| `AGENT_TOOL_PUBLISHER_MANIFEST_SUBJECT` | `getEnv` | `"cerebro.tools.manifest"` | `AgentToolPublisherManifestSubject` | `-` |
| `AGENT_TOOL_PUBLISHER_REQUEST_PREFIX` | `getEnv` | `"cerebro.tools.request"` | `AgentToolPublisherRequestPrefix` | `-` |
| `AGENT_TOOL_PUBLISHER_REQUEST_TIMEOUT` | `getEnvDuration` | `30 * time.Second` | `AgentToolPublisherRequestTimeout` | `-` |
| `ALERT_ROUTER_CONFIG_PATH` | `getEnv` | `""` | `AlertRouterConfigPath` | `-` |
| `ALERT_ROUTER_ENABLED` | `getEnvBool` | `true` | `AlertRouterEnabled` | `-` |
| `ALERT_ROUTER_NOTIFY_PREFIX` | `getEnv` | `"ensemble.notify"` | `AlertRouterNotifyPrefix` | `-` |
| `ALERT_ROUTER_STATE_FILE` | `getEnv` | `filepath.Join(".cerebro", "alert-router", "state.db")` | `AlertRouterStateFile` | `-` |
| `ANTHROPIC_API_KEY` | `getEnv` | `""` | `AnthropicAPIKey` | `-` |
| `API_AUTHORIZATION_SERVERS` | `getEnv` | `""` | `APIAuthorizationServers` | `-` |
| `API_AUTH_ENABLED` | `getEnvBool` | `true` | `-` | `-` |
| `API_CORS_ALLOWED_ORIGINS` | `getEnv` | `""` | `CORSAllowedOrigins` | `-` |
| `API_CREDENTIALS_JSON` | `getEnv` | `""` | `-` | `-` |
| `API_CREDENTIAL_STATE_FILE` | `getEnv` | `filepath.Join(".cerebro", "api-credentials", "state.json")` | `APICredentialStateFile` | `-` |
| `API_IDLE_TIMEOUT` | `getEnvDuration` | `defaultAPIIdleTimeout` | `APIIdleTimeout` | `must be greater than 0` |
| `API_KEYS` | `getEnv` | `""` | `-` | `-` |
| `API_MAX_BODY_BYTES` | `getEnvInt` | `int(defaultAPIMaxBodyBytes)` | `APIMaxBodyBytes` | `must be greater than 0` |
| `API_PORT` | `getEnvInt` | `8080` | `Port` | `must be between 1 and 65535` |
| `API_READ_TIMEOUT` | `getEnvDuration` | `defaultAPIReadTimeout` | `APIReadTimeout` | `must be greater than 0` |
| `API_REQUEST_TIMEOUT` | `getEnvDuration` | `defaultAPIRequestTimeout` | `APIRequestTimeout` | `health checks must not outlive the API request timeout`, `must be greater than 0`, `request timeout must not exceed the server write timeout` |
| `API_WRITE_TIMEOUT` | `getEnvDuration` | `defaultAPIWriteTimeout` | `APIWriteTimeout` | `must be greater than 0`, `request timeout must not exceed the server write timeout` |
| `AUTH0_CLIENT_ID` | `getEnv` | `""` | `Auth0ClientID` | `-` |
| `AUTH0_CLIENT_SECRET` | `getEnv` | `""` | `Auth0ClientSecret` | `-` |
| `AUTH0_DOMAIN` | `getEnv` | `""` | `Auth0Domain` | `-` |
| `AWS_REGION` | `getEnv` | `""`, `"us-east-1"` | `GraphSearchOpenSearchRegion`, `GraphStoreNeptuneRegion`, `S3InputRegion` | `-` |
| `AZURE_CLIENT_ID` | `getEnv` | `""` | `AzureClientID` | `-` |
| `AZURE_CLIENT_SECRET` | `getEnv` | `""` | `AzureClientSecret` | `-` |
| `AZURE_SUBSCRIPTION_ID` | `getEnv` | `""` | `AzureSubscriptionID` | `-` |
| `AZURE_TENANT_ID` | `getEnv` | `""` | `AzureTenantID` | `-` |
| `BAMBOOHR_API_TOKEN` | `getEnv` | `""` | `BambooHRAPIToken` | `-` |
| `BAMBOOHR_URL` | `getEnv` | `""` | `BambooHRURL` | `-` |
| `CEREBRO_ACCESS_REVIEW_RETENTION_DAYS` | `getEnvInt` | `365` | `AccessReviewRetentionDays` | `-` |
| `CEREBRO_AUDIT_RETENTION_DAYS` | `getEnvInt` | `90` | `AuditRetentionDays` | `-` |
| `CEREBRO_CREDENTIAL_FILE_DIR` | `bootstrapConfigValue` | `""` | `CredentialFileDir` | `credential-source settings must be present and valid for the selected source backend` |
| `CEREBRO_CREDENTIAL_SOURCE` | `bootstrapConfigValue` | `secretsource.KindEnv` | `CredentialSource` | `credential-source settings must be present and valid for the selected source backend`, `must be one of env, file, vault` |
| `CEREBRO_CREDENTIAL_VAULT_ADDRESS` | `bootstrapConfigValue` | `""` | `CredentialVaultAddress` | `credential-source settings must be present and valid for the selected source backend` |
| `CEREBRO_CREDENTIAL_VAULT_KV_VERSION` | `bootstrapConfigInt` | `2` | `CredentialVaultKVVersion` | `credential-source settings must be present and valid for the selected source backend` |
| `CEREBRO_CREDENTIAL_VAULT_NAMESPACE` | `bootstrapConfigValue` | `""` | `CredentialVaultNamespace` | `credential-source settings must be present and valid for the selected source backend` |
| `CEREBRO_CREDENTIAL_VAULT_PATH` | `bootstrapConfigValue` | `""` | `CredentialVaultPath` | `credential-source settings must be present and valid for the selected source backend` |
| `CEREBRO_CREDENTIAL_VAULT_TOKEN` | `bootstrapConfigValue` | `""` | `CredentialVaultToken` | `credential-source settings must be present and valid for the selected source backend` |
| `CEREBRO_DEV_MODE` | `getEnvBool` | `false` | `-` | `when CEREBRO_DEV_MODE=true, LOG_LEVEL must be debug unless CEREBRO_DEV_MODE_ACK=true` |
| `CEREBRO_DEV_MODE_ACK` | `getEnvBool` | `false` | `-` | `when CEREBRO_DEV_MODE=true, LOG_LEVEL must be debug unless CEREBRO_DEV_MODE_ACK=true` |
| `CEREBRO_GRAPH_FRESHNESS_DEFAULT_SLA` | `getEnvDuration` | `6 * time.Hour` | `GraphFreshnessDefaultSLA` | `-` |
| `CEREBRO_GRAPH_RETENTION_DAYS` | `getEnvInt` | `180` | `GraphRetentionDays` | `-` |
| `CEREBRO_HEALTH_CHECK_TIMEOUT` | `getEnvDuration` | `defaultHealthCheckTimeout` | `HealthCheckTimeout` | `health checks must not outlive the API request timeout`, `must be greater than 0` |
| `CEREBRO_INIT_TIMEOUT` | `getEnvDuration` | `2 * time.Minute` | `InitTimeout` | `must be greater than or equal to 0` |
| `CEREBRO_OTEL_ENABLED` | `getEnvBool` | `false` | `TracingEnabled` | `-` |
| `CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT` | `getEnv` | `getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "")` | `TracingOTLPEndpoint` | `-` |
| `CEREBRO_OTEL_EXPORTER_OTLP_HEADERS` | `getEnv` | `getEnv("OTEL_EXPORTER_OTLP_HEADERS", "")` | `TracingOTLPHeaders` | `-` |
| `CEREBRO_OTEL_EXPORTER_OTLP_INSECURE` | `getEnvBool` | `getEnvBool("OTEL_EXPORTER_OTLP_INSECURE", false)` | `TracingOTLPInsecure` | `-` |
| `CEREBRO_OTEL_EXPORT_TIMEOUT` | `getEnvDuration` | `5 * time.Second` | `TracingExportTimeout` | `-` |
| `CEREBRO_OTEL_SAMPLE_RATIO` | `` | `` | `-` | `must be between 0 and 1` |
| `CEREBRO_OTEL_SERVICE_NAME` | `getEnv` | `"cerebro"` | `TracingServiceName` | `-` |
| `CEREBRO_RETENTION_JOB_INTERVAL` | `getEnvDuration` | `24 * time.Hour` | `RetentionJobInterval` | `-` |
| `CEREBRO_SECRETS_RELOAD_INTERVAL` | `getEnvDuration` | `0` | `SecretsReloadInterval` | `-` |
| `CEREBRO_SESSION_RETENTION_DAYS` | `getEnvInt` | `30` | `SessionRetentionDays` | `-` |
| `CEREBRO_SHUTDOWN_TIMEOUT` | `getEnvDuration` | `defaultShutdownTimeout` | `ShutdownTimeout` | `must be greater than 0` |
| `CEREBRO_THREAT_INTEL_SYNC_ATTEMPTS` | `getEnvInt` | `defaultThreatIntelSyncAttempts` | `ThreatIntelSyncAttempts` | `must be greater than 0` |
| `CEREBRO_THREAT_INTEL_SYNC_BACKOFF` | `getEnvDuration` | `defaultThreatIntelSyncBackoff` | `ThreatIntelSyncBackoff` | `must be greater than 0` |
| `CEREBRO_THREAT_INTEL_SYNC_MAX_AGE` | `getEnvDuration` | `defaultThreatIntelSyncMaxAge` | `ThreatIntelSyncMaxAge` | `must be greater than 0` |
| `CEREBRO_THREAT_INTEL_SYNC_TIMEOUT` | `getEnvDuration` | `defaultThreatIntelSyncTimeout` | `ThreatIntelSyncTimeout` | `must be greater than 0` |
| `CEREBRO_TICKETING_PROVIDER_VALIDATE_TIMEOUT` | `getEnvDuration` | `defaultTicketingProviderValidateTimeout` | `TicketingProviderValidateTimeout` | `must be greater than 0` |
| `CEREBRO_TOOL_ACCESS_REVIEW_REQUIRES_APPROVAL` | `getEnvBool` | `true` | `CerebroAccessReviewNeedsApproval` | `-` |
| `CEREBRO_TOOL_SIMULATE_REQUIRES_APPROVAL` | `getEnvBool` | `true` | `CerebroSimulateNeedsApproval` | `-` |
| `CLOUDFLARE_API_TOKEN` | `getEnv` | `""` | `CloudflareAPIToken` | `-` |
| `CLOUDTRAIL_LOOKBACK_DAYS` | `getEnvInt` | `7` | `CloudTrailLookbackDays` | `-` |
| `CLOUDTRAIL_REGION` | `getEnv` | `""` | `CloudTrailRegion` | `-` |
| `CLOUDTRAIL_TRAIL_ARN` | `getEnv` | `""` | `CloudTrailTrailARN` | `-` |
| `CROWDSTRIKE_CLIENT_ID` | `getEnv` | `""` | `CrowdStrikeClientID` | `-` |
| `CROWDSTRIKE_CLIENT_SECRET` | `getEnv` | `""` | `CrowdStrikeClientSecret` | `-` |
| `CYBERARK_API_TOKEN` | `getEnv` | `""` | `CyberArkAPIToken` | `-` |
| `CYBERARK_URL` | `getEnv` | `""` | `CyberArkURL` | `-` |
| `DATADOG_API_KEY` | `getEnv` | `""` | `DatadogAPIKey` | `-` |
| `DATADOG_APP_KEY` | `getEnv` | `""` | `DatadogAppKey` | `-` |
| `DATADOG_SITE` | `getEnv` | `"datadoghq.com"` | `DatadogSite` | `-` |
| `DUO_API_HOSTNAME` | `getEnv` | `""` | `DuoURL` | `-` |
| `DUO_IKEY` | `getEnv` | `""` | `DuoIntegrationKey` | `-` |
| `DUO_INTEGRATION_KEY` | `getEnv` | `getEnv("DUO_IKEY", "")` | `DuoIntegrationKey` | `-` |
| `DUO_SECRET_KEY` | `getEnv` | `getEnv("DUO_SKEY", "")` | `DuoSecretKey` | `-` |
| `DUO_SKEY` | `getEnv` | `""` | `DuoSecretKey` | `-` |
| `DUO_URL` | `getEnv` | `getEnv("DUO_API_HOSTNAME", "")` | `DuoURL` | `-` |
| `ENTRA_CLIENT_ID` | `getEnv` | `""` | `EntraClientID` | `-` |
| `ENTRA_CLIENT_SECRET` | `getEnv` | `""` | `EntraClientSecret` | `-` |
| `ENTRA_TENANT_ID` | `getEnv` | `""` | `EntraTenantID` | `-` |
| `EXECUTION_STORE_FILE` | `getEnv` | `filepath.Join(".cerebro", "executions.db")` | `ExecutionStoreFile`, `FunctionScanStateFile`, `ImageScanStateFile`, `NATSConsumerDedupStateFile`, `WorkloadScanStateFile` | `-` |
| `FIGMA_API_TOKEN` | `getEnv` | `""` | `FigmaAPIToken` | `-` |
| `FIGMA_BASE_URL` | `getEnv` | `"https://api.figma.com"` | `FigmaBaseURL` | `-` |
| `FIGMA_TEAM_ID` | `getEnv` | `""` | `FigmaTeamID` | `-` |
| `FINDINGS_MAX_IN_MEMORY` | `getEnvInt` | `findings.DefaultMaxFindings` | `FindingsMaxInMemory` | `must be greater than or equal to 0` |
| `FINDINGS_RESOLVED_RETENTION` | `getEnvDuration` | `findings.DefaultResolvedRetention` | `FindingsResolvedRetention` | `must be greater than or equal to 0` |
| `FINDINGS_SEMANTIC_DEDUP_ENABLED` | `getEnvBool` | `findings.DefaultSemanticDedupEnabled` | `FindingsSemanticDedupEnabled` | `enables semantic finding identity across policy/version drift` |
| `FINDING_ATTESTATION_ATTEST_REOBSERVED` | `getEnvBool` | `false` | `FindingAttestationAttestReobserved` | `-` |
| `FINDING_ATTESTATION_ENABLED` | `getEnvBool` | `false` | `FindingAttestationEnabled` | `when FINDING_ATTESTATION_ENABLED=true, the signing key is required and timeout must be positive` |
| `FINDING_ATTESTATION_KEY_ID` | `getEnv` | `""` | `FindingAttestationKeyID` | `-` |
| `FINDING_ATTESTATION_LOG_URL` | `getEnv` | `""` | `FindingAttestationLogURL` | `-` |
| `FINDING_ATTESTATION_SIGNING_KEY` | `getEnv` | `""` | `FindingAttestationSigningKey` | `when FINDING_ATTESTATION_ENABLED=true, the signing key is required and timeout must be positive` |
| `FINDING_ATTESTATION_TIMEOUT` | `getEnvDuration` | `3 * time.Second` | `FindingAttestationTimeout` | `when FINDING_ATTESTATION_ENABLED=true, the signing key is required and timeout must be positive` |
| `FORGEROCK_API_TOKEN` | `getEnv` | `""` | `ForgeRockAPIToken` | `-` |
| `FORGEROCK_URL` | `getEnv` | `""` | `ForgeRockURL` | `-` |
| `FUNCTION_SCAN_CLAMAV_BINARY` | `getEnv` | `""` | `FunctionScanClamAVBinary` | `-` |
| `FUNCTION_SCAN_CLEANUP_TIMEOUT` | `getEnvDuration` | `2 * time.Minute` | `FunctionScanCleanupTimeout` | `-` |
| `FUNCTION_SCAN_GITLEAKS_BINARY` | `getEnv` | `""` | `FunctionScanGitleaksBinary` | `-` |
| `FUNCTION_SCAN_ROOTFS_BASE_PATH` | `getEnv` | `filepath.Join(".cerebro", "function-scan", "rootfs")` | `FunctionScanRootFSBasePath` | `-` |
| `FUNCTION_SCAN_STATE_FILE` | `getEnv` | `getEnv("EXECUTION_STORE_FILE", filepath.Join(".cerebro", "executions.db"))` | `FunctionScanStateFile` | `-` |
| `FUNCTION_SCAN_TRIVY_BINARY` | `getEnv` | `"trivy"` | `FunctionScanTrivyBinary` | `-` |
| `GITHUB_ORG` | `getEnv` | `""` | `GitHubOrg` | `-` |
| `GITHUB_TOKEN` | `getEnv` | `""` | `GitHubToken` | `-` |
| `GITLAB_BASE_URL` | `getEnv` | `"https://gitlab.com"` | `GitLabBaseURL` | `-` |
| `GITLAB_TOKEN` | `getEnv` | `""` | `GitLabToken` | `-` |
| `GONG_ACCESS_KEY` | `getEnv` | `""` | `GongAccessKey` | `-` |
| `GONG_ACCESS_SECRET` | `getEnv` | `""` | `GongAccessSecret` | `-` |
| `GONG_BASE_URL` | `getEnv` | `"https://api.gong.io"` | `GongBaseURL` | `-` |
| `GOOGLE_WORKSPACE_ADMIN_EMAIL` | `getEnv` | `""` | `GoogleWorkspaceAdminEmail` | `-` |
| `GOOGLE_WORKSPACE_CREDENTIALS_FILE` | `getEnv` | `""` | `GoogleWorkspaceCredentialsFile` | `-` |
| `GOOGLE_WORKSPACE_CREDENTIALS_JSON` | `getEnv` | `""` | `GoogleWorkspaceCredentialsJSON` | `-` |
| `GOOGLE_WORKSPACE_DOMAIN` | `getEnv` | `""` | `GoogleWorkspaceDomain` | `-` |
| `GOOGLE_WORKSPACE_IMPERSONATOR_EMAIL` | `getEnv` | `""` | `GoogleWorkspaceImpersonatorEmail` | `-` |
| `GRAPH_CONSISTENCY_CHECK_ENABLED` | `getEnvBool` | `false` | `GraphConsistencyCheckEnabled` | `-` |
| `GRAPH_CONSISTENCY_CHECK_INTERVAL` | `getEnvDuration` | `6 * time.Hour` | `GraphConsistencyCheckInterval` | `-` |
| `GRAPH_CONSISTENCY_CHECK_TIMEOUT` | `getEnvDuration` | `defaultGraphConsistencyCheckTimeout` | `GraphConsistencyCheckTimeout` | `must be greater than 0` |
| `GRAPH_CROSS_TENANT_MIN_SUPPORT` | `getEnvInt` | `2` | `GraphCrossTenantMinSupport` | `when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true, signing key is required and skew/TTL/support thresholds must be positive` |
| `GRAPH_CROSS_TENANT_MIN_TENANTS` | `getEnvInt` | `2` | `GraphCrossTenantMinTenants` | `when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true, signing key is required and skew/TTL/support thresholds must be positive` |
| `GRAPH_CROSS_TENANT_REPLAY_TTL` | `getEnvDuration` | `24 * time.Hour` | `GraphCrossTenantReplayTTL` | `when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true, signing key is required and skew/TTL/support thresholds must be positive` |
| `GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST` | `getEnvBool` | `false` | `GraphCrossTenantRequireSignedIngest` | `when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true, signing key is required and skew/TTL/support thresholds must be positive` |
| `GRAPH_CROSS_TENANT_SIGNATURE_MAX_SKEW` | `getEnvDuration` | `5 * time.Minute` | `GraphCrossTenantSignatureSkew` | `when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true, signing key is required and skew/TTL/support thresholds must be positive` |
| `GRAPH_CROSS_TENANT_SIGNING_KEY` | `getEnv` | `""` | `GraphCrossTenantSigningKey` | `when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true, signing key is required and skew/TTL/support thresholds must be positive` |
| `GRAPH_EVENT_MAPPER_DEAD_LETTER_PATH` | `getEnv` | `filepath.Join(findings.DefaultFilePath(), "graph-event-mapper.dlq.jsonl")` | `GraphEventMapperDeadLetterPath` | `-` |
| `GRAPH_EVENT_MAPPER_VALIDATION_MODE` | `getEnv` | `"enforce"` | `GraphEventMapperValidationMode` | `must be one of warn, enforce` |
| `GRAPH_MIGRATE_LEGACY_ACTIVITY_ON_START` | `getEnvBool` | `false` | `GraphMigrateLegacyActivityOnStart` | `-` |
| `GRAPH_POST_SYNC_UPDATE_TIMEOUT` | `getEnvDuration` | `defaultGraphPostSyncUpdateTimeout` | `GraphPostSyncUpdateTimeout` | `must be greater than 0` |
| `GRAPH_PROPERTY_HISTORY_MAX_ENTRIES` | `getEnvInt` | `graph.DefaultTemporalHistoryMaxEntries` | `GraphPropertyHistoryMaxEntries` | `non-positive values fall back to the default max property-history depth` |
| `GRAPH_PROPERTY_HISTORY_TTL` | `getEnvDuration` | `graph.DefaultTemporalHistoryTTL` | `GraphPropertyHistoryTTL` | `non-positive values fall back to the default property-history TTL` |
| `GRAPH_RISK_ENGINE_STATE_TIMEOUT` | `getEnvDuration` | `defaultGraphRiskEngineStateTimeout` | `GraphRiskEngineStateTimeout` | `must be greater than 0` |
| `GRAPH_SCHEMA_VALIDATION_MODE` | `getEnv` | `"warn"` | `GraphSchemaValidationMode` | `must be one of off, warn, enforce` |
| `GRAPH_SEARCH_BACKEND` | `getEnv` | `defaultGraphSearchBackend()` | `GraphSearchBackend` | `must be one of graph, opensearch`, `when GRAPH_SEARCH_BACKEND=opensearch, the OpenSearch endpoint, region, and index are required` |
| `GRAPH_SEARCH_MAX_CANDIDATES` | `getEnvInt` | `100` | `GraphSearchMaxCandidates` | `must be greater than 0` |
| `GRAPH_SEARCH_OPENSEARCH_ENDPOINT` | `getEnv` | `""` | `GraphSearchOpenSearchEndpoint` | `when GRAPH_SEARCH_BACKEND=opensearch, the OpenSearch endpoint, region, and index are required` |
| `GRAPH_SEARCH_OPENSEARCH_INDEX` | `getEnv` | `""` | `GraphSearchOpenSearchIndex` | `when GRAPH_SEARCH_BACKEND=opensearch, the OpenSearch endpoint, region, and index are required` |
| `GRAPH_SEARCH_OPENSEARCH_REGION` | `getEnv` | `getEnv("AWS_REGION", "")` | `GraphSearchOpenSearchRegion` | `when GRAPH_SEARCH_BACKEND=opensearch, the OpenSearch endpoint, region, and index are required` |
| `GRAPH_SEARCH_REQUEST_TIMEOUT` | `getEnvDuration` | `5 * time.Second` | `GraphSearchRequestTimeout` | `must be greater than 0` |
| `GRAPH_SNAPSHOT_MAX_RETAINED` | `getEnvInt` | `10` | `GraphSnapshotMaxRetained` | `-` |
| `GRAPH_SNAPSHOT_PATH` | `getEnv` | `filepath.Join(".cerebro", "graph-snapshots")` | `GraphSnapshotPath` | `-` |
| `GRAPH_STORE_BACKEND` | `getEnv` | `defaultGraphStoreBackend()` | `GraphStoreBackend` | `must be neptune`, `when GRAPH_STORE_BACKEND=neptune, the Neptune data API endpoint is required` |
| `GRAPH_STORE_NEPTUNE_ENDPOINT` | `getEnv` | `""` | `GraphStoreNeptuneEndpoint` | `when GRAPH_STORE_BACKEND=neptune, the Neptune data API endpoint is required` |
| `GRAPH_STORE_NEPTUNE_POOL_DRAIN_TIMEOUT` | `getEnvDuration` | `defaultNeptunePool.DrainTimeout` | `GraphStoreNeptunePoolDrainTimeout` | `-` |
| `GRAPH_STORE_NEPTUNE_POOL_HEALTHCHECK_INTERVAL` | `getEnvDuration` | `defaultNeptunePool.HealthCheckInterval` | `GraphStoreNeptunePoolHealthCheckInterval` | `-` |
| `GRAPH_STORE_NEPTUNE_POOL_HEALTHCHECK_TIMEOUT` | `getEnvDuration` | `defaultNeptunePool.HealthCheckTimeout` | `GraphStoreNeptunePoolHealthCheckTimeout` | `-` |
| `GRAPH_STORE_NEPTUNE_POOL_MAX_CLIENT_LIFETIME` | `getEnvDuration` | `defaultNeptunePool.MaxClientLifetime` | `GraphStoreNeptunePoolMaxClientLifetime` | `-` |
| `GRAPH_STORE_NEPTUNE_POOL_MAX_CLIENT_USES` | `getEnvInt` | `defaultNeptunePool.MaxClientUses` | `GraphStoreNeptunePoolMaxClientUses` | `-` |
| `GRAPH_STORE_NEPTUNE_POOL_SIZE` | `getEnvInt` | `defaultNeptunePool.Size` | `GraphStoreNeptunePoolSize` | `-` |
| `GRAPH_STORE_NEPTUNE_REGION` | `getEnv` | `getEnv("AWS_REGION", "us-east-1")` | `GraphStoreNeptuneRegion` | `-` |
| `GRAPH_TENANT_SHARD_IDLE_TTL` | `getEnvDuration` | `defaultGraphTenantShardIdleTTL` | `GraphTenantShardIdleTTL` | `must be greater than 0` |
| `GRAPH_TENANT_WARM_SHARD_MAX_RETAINED` | `getEnvInt` | `defaultGraphTenantWarmShardMaxRetained` | `GraphTenantWarmShardMaxRetained` | `must be greater than 0` |
| `GRAPH_TENANT_WARM_SHARD_TTL` | `getEnvDuration` | `defaultGraphTenantWarmShardTTL` | `GraphTenantWarmShardTTL` | `must be greater than 0` |
| `GRAPH_WRITER_LEASE_BUCKET` | `getEnv` | `defaultGraphWriterLeaseBucket` | `GraphWriterLeaseBucket` | `-` |
| `GRAPH_WRITER_LEASE_ENABLED` | `getEnvBool` | `false` | `GraphWriterLeaseEnabled` | `-` |
| `GRAPH_WRITER_LEASE_HEARTBEAT` | `getEnvDuration` | `5 * time.Second` | `GraphWriterLeaseHeartbeat` | `-` |
| `GRAPH_WRITER_LEASE_NAME` | `getEnv` | `defaultGraphWriterLeaseName` | `GraphWriterLeaseName` | `-` |
| `GRAPH_WRITER_LEASE_OWNER_ID` | `getEnv` | `defaultGraphWriterLeaseOwnerID()` | `GraphWriterLeaseOwnerID` | `-` |
| `GRAPH_WRITER_LEASE_TTL` | `getEnvDuration` | `15 * time.Second` | `GraphWriterLeaseTTL` | `-` |
| `IMAGE_SCAN_CLAMAV_BINARY` | `getEnv` | `""` | `ImageScanClamAVBinary` | `-` |
| `IMAGE_SCAN_CLEANUP_TIMEOUT` | `getEnvDuration` | `2 * time.Minute` | `ImageScanCleanupTimeout` | `-` |
| `IMAGE_SCAN_GITLEAKS_BINARY` | `getEnv` | `""` | `ImageScanGitleaksBinary` | `-` |
| `IMAGE_SCAN_ROOTFS_BASE_PATH` | `getEnv` | `filepath.Join(".cerebro", "image-scan", "rootfs")` | `ImageScanRootFSBasePath` | `-` |
| `IMAGE_SCAN_STATE_FILE` | `getEnv` | `getEnv("EXECUTION_STORE_FILE", filepath.Join(".cerebro", "executions.db"))` | `ImageScanStateFile` | `-` |
| `IMAGE_SCAN_TRIVY_BINARY` | `getEnv` | `"trivy"` | `ImageScanTrivyBinary` | `-` |
| `INTUNE_CLIENT_ID` | `getEnv` | `""` | `IntuneClientID` | `-` |
| `INTUNE_CLIENT_SECRET` | `getEnv` | `""` | `IntuneClientSecret` | `-` |
| `INTUNE_TENANT_ID` | `getEnv` | `""` | `IntuneTenantID` | `-` |
| `JAMF_BASE_URL` | `getEnv` | `""` | `JamfBaseURL` | `-` |
| `JAMF_CLIENT_ID` | `getEnv` | `""` | `JamfClientID` | `-` |
| `JAMF_CLIENT_SECRET` | `getEnv` | `""` | `JamfClientSecret` | `-` |
| `JIRA_API_TOKEN` | `getEnv` | `""` | `JiraAPIToken` | `-` |
| `JIRA_BASE_URL` | `getEnv` | `""` | `JiraBaseURL` | `-` |
| `JIRA_CLOSE_TRANSITIONS` | `getEnv` | `"Done,Closed,Resolve Issue"` | `JiraCloseTransitions` | `-` |
| `JIRA_EMAIL` | `getEnv` | `""` | `JiraEmail` | `-` |
| `JIRA_PROJECT` | `getEnv` | `"SEC"` | `JiraProject` | `-` |
| `JOB_DATABASE_URL` | `getEnv` | `""` | `JobDatabaseURL` | `when JOB_DATABASE_URL is configured, NATS settings must be present and worker timing/count controls must be positive` |
| `JOB_MAX_ATTEMPTS` | `getEnvInt` | `3` | `JobMaxAttempts` | `when JOB_DATABASE_URL is configured, NATS settings must be present and worker timing/count controls must be positive` |
| `JOB_NATS_CONSUMER` | `getEnv` | `"job-worker"` | `JobNATSConsumer` | `when JOB_DATABASE_URL is configured, NATS settings must be present and worker timing/count controls must be positive` |
| `JOB_NATS_STREAM` | `getEnv` | `"CEREBRO_JOBS"` | `JobNATSStream` | `when JOB_DATABASE_URL is configured, NATS settings must be present and worker timing/count controls must be positive` |
| `JOB_NATS_SUBJECT` | `getEnv` | `"cerebro.jobs"` | `JobNATSSubject` | `when JOB_DATABASE_URL is configured, NATS settings must be present and worker timing/count controls must be positive` |
| `JOB_POLL_WAIT` | `getEnvDuration` | `10 * time.Second` | `JobPollWait` | `when JOB_DATABASE_URL is configured, NATS settings must be present and worker timing/count controls must be positive` |
| `JOB_VISIBILITY_TIMEOUT` | `getEnvDuration` | `30 * time.Second` | `JobVisibilityTimeout` | `when JOB_DATABASE_URL is configured, NATS settings must be present and worker timing/count controls must be positive` |
| `JOB_WORKER_CONCURRENCY` | `getEnvInt` | `4` | `JobWorkerConcurrency` | `when JOB_DATABASE_URL is configured, NATS settings must be present and worker timing/count controls must be positive` |
| `JUMPCLOUD_API_TOKEN` | `getEnv` | `""` | `JumpCloudAPIToken` | `-` |
| `JUMPCLOUD_ORG_ID` | `getEnv` | `""` | `JumpCloudOrgID` | `-` |
| `JUMPCLOUD_URL` | `getEnv` | `"https://console.jumpcloud.com"` | `JumpCloudURL` | `-` |
| `KANDJI_API_TOKEN` | `getEnv` | `""` | `KandjiAPIToken` | `-` |
| `KANDJI_API_URL` | `getEnv` | `""` | `KandjiAPIURL` | `-` |
| `KOLIDE_API_TOKEN` | `getEnv` | `""` | `KolideAPIToken` | `-` |
| `KOLIDE_BASE_URL` | `getEnv` | `"https://api.kolide.com/v1"` | `KolideBaseURL` | `-` |
| `LINEAR_API_KEY` | `getEnv` | `""` | `LinearAPIKey` | `-` |
| `LINEAR_TEAM_ID` | `getEnv` | `""` | `LinearTeamID` | `-` |
| `LOG_LEVEL` | `getEnv` | `"info"` | `LogLevel` | `must be one of debug, info, warn, error`, `when CEREBRO_DEV_MODE=true, LOG_LEVEL must be debug unless CEREBRO_DEV_MODE_ACK=true` |
| `MALWARE_SCAN_CLAMAV_HOST` | `getEnv` | `""` | `MalwareScanClamAVHost` | `-` |
| `MALWARE_SCAN_CLAMAV_PORT` | `getEnvInt` | `0` | `MalwareScanClamAVPort` | `-` |
| `MALWARE_SCAN_VIRUSTOTAL_API_KEY` | `getEnv` | `""` | `MalwareScanVirusTotalAPIKey` | `-` |
| `NATS_CONSUMER_ACK_WAIT` | `getEnvDuration` | `120 * time.Second` | `NATSConsumerAckWait` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled` |
| `NATS_CONSUMER_BATCH_SIZE` | `getEnvInt` | `50` | `NATSConsumerBatchSize` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled` |
| `NATS_CONSUMER_DEAD_LETTER_PATH` | `getEnv` | `filepath.Join(findings.DefaultFilePath(), "nats-consumer.dlq.jsonl")` | `NATSConsumerDeadLetterPath` | `-` |
| `NATS_CONSUMER_DEDUP_ENABLED` | `getEnvBool` | `true` | `NATSConsumerDedupEnabled` | `-` |
| `NATS_CONSUMER_DEDUP_MAX_RECORDS` | `getEnvInt` | `100000` | `NATSConsumerDedupMaxRecords` | `-` |
| `NATS_CONSUMER_DEDUP_STATE_FILE` | `getEnv` | `getEnv("EXECUTION_STORE_FILE", filepath.Join(".cerebro", "executions.db"))` | `NATSConsumerDedupStateFile` | `-` |
| `NATS_CONSUMER_DEDUP_TTL` | `getEnvDuration` | `24 * time.Hour` | `NATSConsumerDedupTTL` | `-` |
| `NATS_CONSUMER_DRAIN_TIMEOUT` | `getEnvDuration` | `30 * time.Second` | `NATSConsumerDrainTimeout` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled` |
| `NATS_CONSUMER_DROP_HEALTH_LOOKBACK` | `getEnvDuration` | `5 * time.Minute` | `NATSConsumerDropHealthLookback` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled` |
| `NATS_CONSUMER_DROP_HEALTH_THRESHOLD` | `getEnvInt` | `1` | `NATSConsumerDropHealthThreshold` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled` |
| `NATS_CONSUMER_DURABLE` | `getEnv` | `"cerebro_graph_builder"` | `NATSConsumerDurable` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled` |
| `NATS_CONSUMER_ENABLED` | `getEnvBool` | `false` | `NATSConsumerEnabled` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled` |
| `NATS_CONSUMER_FETCH_TIMEOUT` | `getEnvDuration` | `2 * time.Second` | `NATSConsumerFetchTimeout` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled` |
| `NATS_CONSUMER_GRAPH_STALENESS_THRESHOLD` | `getEnvDuration` | `15 * time.Minute` | `NATSConsumerGraphStalenessThreshold` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled` |
| `NATS_CONSUMER_IN_PROGRESS_INTERVAL` | `getEnvDuration` | `15 * time.Second` | `NATSConsumerInProgressInterval` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled` |
| `NATS_CONSUMER_STREAM` | `getEnv` | `"ENSEMBLE_TAP"` | `NATSConsumerStream` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled` |
| `NATS_CONSUMER_SUBJECTS` | `getEnv` | `"ensemble.tap.>"` | `NATSConsumerSubjects` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled` |
| `NATS_JETSTREAM_AUTH_MODE` | `getEnv` | `"none"` | `NATSJetStreamAuthMode` | `-` |
| `NATS_JETSTREAM_CONNECT_TIMEOUT` | `getEnvDuration` | `5 * time.Second` | `NATSJetStreamConnectTimeout` | `when NATS_JETSTREAM_ENABLED=true, required values must be present and timing/retention values must be positive` |
| `NATS_JETSTREAM_ENABLED` | `getEnvBool` | `false` | `NATSJetStreamEnabled` | `when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled`, `when NATS_JETSTREAM_ENABLED=true, required values must be present and timing/retention values must be positive` |
| `NATS_JETSTREAM_FLUSH_INTERVAL` | `getEnvDuration` | `10 * time.Second` | `NATSJetStreamFlushInterval` | `when NATS_JETSTREAM_ENABLED=true, required values must be present and timing/retention values must be positive` |
| `NATS_JETSTREAM_NKEY_SEED` | `getEnv` | `""` | `NATSJetStreamNKeySeed` | `-` |
| `NATS_JETSTREAM_OUTBOX_CRITICAL_AGE` | `getEnvDuration` | `6 * time.Hour` | `NATSJetStreamOutboxCriticalAge` | `-` |
| `NATS_JETSTREAM_OUTBOX_CRITICAL_PERCENT` | `getEnvInt` | `90` | `NATSJetStreamOutboxCriticalPercent` | `-` |
| `NATS_JETSTREAM_OUTBOX_DLQ_PATH` | `getEnv` | `""` | `NATSJetStreamOutboxDLQPath` | `-` |
| `NATS_JETSTREAM_OUTBOX_MAX_AGE` | `getEnvDuration` | `7 * 24 * time.Hour` | `NATSJetStreamOutboxMaxAge` | `when NATS_JETSTREAM_ENABLED=true, required values must be present and timing/retention values must be positive` |
| `NATS_JETSTREAM_OUTBOX_MAX_ITEMS` | `getEnvInt` | `10000` | `NATSJetStreamOutboxMaxItems` | `when NATS_JETSTREAM_ENABLED=true, required values must be present and timing/retention values must be positive` |
| `NATS_JETSTREAM_OUTBOX_MAX_RETRY` | `getEnvInt` | `10` | `NATSJetStreamOutboxMaxRetry` | `when NATS_JETSTREAM_ENABLED=true, required values must be present and timing/retention values must be positive` |
| `NATS_JETSTREAM_OUTBOX_PATH` | `getEnv` | `filepath.Join(findings.DefaultFilePath(), "jetstream-outbox.jsonl")` | `NATSJetStreamOutboxPath` | `-` |
| `NATS_JETSTREAM_OUTBOX_WARN_AGE` | `getEnvDuration` | `time.Hour` | `NATSJetStreamOutboxWarnAge` | `-` |
| `NATS_JETSTREAM_OUTBOX_WARN_PERCENT` | `getEnvInt` | `70` | `NATSJetStreamOutboxWarnPercent` | `-` |
| `NATS_JETSTREAM_PASSWORD` | `getEnv` | `""` | `NATSJetStreamPassword` | `-` |
| `NATS_JETSTREAM_PUBLISH_TIMEOUT` | `getEnvDuration` | `3 * time.Second` | `NATSJetStreamPublishTimeout` | `when NATS_JETSTREAM_ENABLED=true, required values must be present and timing/retention values must be positive` |
| `NATS_JETSTREAM_RETRY_ATTEMPTS` | `getEnvInt` | `3` | `NATSJetStreamRetryAttempts` | `-` |
| `NATS_JETSTREAM_RETRY_BACKOFF` | `getEnvDuration` | `500 * time.Millisecond` | `NATSJetStreamRetryBackoff` | `-` |
| `NATS_JETSTREAM_SOURCE` | `getEnv` | `"cerebro"` | `NATSJetStreamSource` | `-` |
| `NATS_JETSTREAM_STREAM` | `getEnv` | `"CEREBRO_EVENTS"` | `NATSJetStreamStream` | `when NATS_JETSTREAM_ENABLED=true, required values must be present and timing/retention values must be positive` |
| `NATS_JETSTREAM_SUBJECT_PREFIX` | `getEnv` | `"cerebro.events"` | `NATSJetStreamSubjectPrefix` | `when NATS_JETSTREAM_ENABLED=true, required values must be present and timing/retention values must be positive` |
| `NATS_JETSTREAM_TLS_CA_FILE` | `getEnv` | `""` | `NATSJetStreamTLSCAFile` | `-` |
| `NATS_JETSTREAM_TLS_CERT_FILE` | `getEnv` | `""` | `NATSJetStreamTLSCertFile` | `-` |
| `NATS_JETSTREAM_TLS_ENABLED` | `getEnvBool` | `false` | `NATSJetStreamTLSEnabled` | `-` |
| `NATS_JETSTREAM_TLS_INSECURE_SKIP_VERIFY` | `getEnvBool` | `false` | `NATSJetStreamTLSInsecure` | `-` |
| `NATS_JETSTREAM_TLS_KEY_FILE` | `getEnv` | `""` | `NATSJetStreamTLSKeyFile` | `-` |
| `NATS_JETSTREAM_TLS_SERVER_NAME` | `getEnv` | `""` | `NATSJetStreamTLSServerName` | `-` |
| `NATS_JETSTREAM_USERNAME` | `getEnv` | `""` | `NATSJetStreamUsername` | `-` |
| `NATS_JETSTREAM_USER_JWT` | `getEnv` | `""` | `NATSJetStreamUserJWT` | `-` |
| `NATS_URLS` | `getEnv` | `"nats://127.0.0.1:4222"` | `NATSJetStreamURLs` | `when JOB_DATABASE_URL is configured, NATS settings must be present and worker timing/count controls must be positive`, `when NATS_JETSTREAM_ENABLED=true, required values must be present and timing/retention values must be positive` |
| `OKTA_API_TOKEN` | `getEnv` | `""` | `OktaAPIToken` | `-` |
| `OKTA_DOMAIN` | `getEnv` | `""` | `OktaDomain` | `-` |
| `ONELOGIN_CLIENT_ID` | `getEnv` | `""` | `OneLoginClientID` | `-` |
| `ONELOGIN_CLIENT_SECRET` | `getEnv` | `""` | `OneLoginClientSecret` | `-` |
| `ONELOGIN_URL` | `getEnv` | `""` | `OneLoginURL` | `-` |
| `OPENAI_API_KEY` | `getEnv` | `""` | `OpenAIAPIKey` | `-` |
| `ORACLE_IDCS_API_TOKEN` | `getEnv` | `""` | `OracleIDCSAPIToken` | `-` |
| `ORACLE_IDCS_URL` | `getEnv` | `""` | `OracleIDCSURL` | `-` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `getEnv` | `""` | `TracingOTLPEndpoint` | `-` |
| `OTEL_EXPORTER_OTLP_HEADERS` | `getEnv` | `""` | `TracingOTLPHeaders` | `-` |
| `OTEL_EXPORTER_OTLP_INSECURE` | `getEnvBool` | `false` | `TracingOTLPInsecure` | `-` |
| `PAGERDUTY_ROUTING_KEY` | `getEnv` | `""` | `PagerDutyKey` | `-` |
| `PANTHER_API_TOKEN` | `getEnv` | `""` | `PantherAPIToken` | `-` |
| `PANTHER_BASE_URL` | `getEnv` | `"https://api.runpanther.io/public_api/v1"` | `PantherBaseURL` | `-` |
| `PINGIDENTITY_API_URL` | `getEnv` | `"https://api.pingone.com"` | `PingIdentityAPIURL` | `-` |
| `PINGIDENTITY_AUTH_URL` | `getEnv` | `"https://auth.pingone.com"` | `PingIdentityAuthURL` | `-` |
| `PINGIDENTITY_CLIENT_ID` | `getEnv` | `getEnv("PINGONE_CLIENT_ID", "")` | `PingIdentityClientID` | `-` |
| `PINGIDENTITY_CLIENT_SECRET` | `getEnv` | `getEnv("PINGONE_CLIENT_SECRET", "")` | `PingIdentityClientSecret` | `-` |
| `PINGIDENTITY_ENVIRONMENT_ID` | `getEnv` | `getEnv("PINGONE_ENVIRONMENT_ID", "")` | `PingIdentityEnvironmentID` | `-` |
| `PINGONE_CLIENT_ID` | `getEnv` | `""` | `PingIdentityClientID` | `-` |
| `PINGONE_CLIENT_SECRET` | `getEnv` | `""` | `PingIdentityClientSecret` | `-` |
| `PINGONE_ENVIRONMENT_ID` | `getEnv` | `""` | `PingIdentityEnvironmentID` | `-` |
| `PLATFORM_REPORT_RUN_STATE_FILE` | `getEnv` | `filepath.Join(".cerebro", "report-runs", "state.json")` | `PlatformReportRunStateFile` | `-` |
| `PLATFORM_REPORT_SNAPSHOT_PATH` | `getEnv` | `filepath.Join(".cerebro", "report-runs", "snapshots")` | `PlatformReportSnapshotPath` | `-` |
| `POLICIES_PATH` | `getEnv` | `"policies"` | `PoliciesPath` | `-` |
| `QUALYS_PASSWORD` | `getEnv` | `""` | `QualysPassword` | `-` |
| `QUALYS_PLATFORM` | `getEnv` | `"US1"` | `QualysPlatform` | `-` |
| `QUALYS_USERNAME` | `getEnv` | `""` | `QualysUsername` | `-` |
| `QUERY_POLICY_ROW_LIMIT` | `getEnvInt` | `snowflake.MaxReadOnlyQueryLimit` | `QueryPolicyRowLimit` | `must be greater than 0` |
| `RAMP_API_URL` | `getEnv` | `"https://api.ramp.com/developer/v1"` | `RampAPIURL` | `-` |
| `RAMP_CLIENT_ID` | `getEnv` | `""` | `RampClientID` | `-` |
| `RAMP_CLIENT_SECRET` | `getEnv` | `""` | `RampClientSecret` | `-` |
| `RAMP_TOKEN_URL` | `getEnv` | `"https://api.ramp.com/developer/v1/token"` | `RampTokenURL` | `-` |
| `RATE_LIMIT_ENABLED` | `getEnvBool` | `true` | `-` | `when RATE_LIMIT_ENABLED=true, requests and window must be positive` |
| `RATE_LIMIT_REQUESTS` | `getEnvInt` | `1000` | `RateLimitRequests` | `when RATE_LIMIT_ENABLED=true, requests and window must be positive` |
| `RATE_LIMIT_TRUSTED_PROXIES` | `getEnv` | `""` | `RateLimitTrustedProxies` | `-` |
| `RATE_LIMIT_WINDOW` | `getEnvDuration` | `time.Hour` | `RateLimitWindow` | `when RATE_LIMIT_ENABLED=true, requests and window must be positive` |
| `RBAC_STATE_FILE` | `getEnv` | `""` | `RBACStateFile` | `-` |
| `RIPPLING_API_TOKEN` | `getEnv` | `""` | `RipplingAPIToken` | `-` |
| `RIPPLING_API_URL` | `getEnv` | `""` | `RipplingAPIURL` | `-` |
| `S3_INPUT_BUCKET` | `getEnv` | `""` | `S3InputBucket` | `-` |
| `S3_INPUT_FORMAT` | `getEnv` | `"auto"` | `S3InputFormat` | `-` |
| `S3_INPUT_MAX_OBJECTS` | `getEnvInt` | `200` | `S3InputMaxObjects` | `-` |
| `S3_INPUT_PREFIX` | `getEnv` | `""` | `S3InputPrefix` | `-` |
| `S3_INPUT_REGION` | `getEnv` | `getEnv("AWS_REGION", "us-east-1")` | `S3InputRegion` | `-` |
| `SAILPOINT_API_TOKEN` | `getEnv` | `""` | `SailPointAPIToken` | `-` |
| `SAILPOINT_URL` | `getEnv` | `""` | `SailPointURL` | `-` |
| `SALESFORCE_CLIENT_ID` | `getEnv` | `""` | `SalesforceClientID` | `-` |
| `SALESFORCE_CLIENT_SECRET` | `getEnv` | `""` | `SalesforceClientSecret` | `-` |
| `SALESFORCE_INSTANCE_URL` | `getEnv` | `""` | `SalesforceInstanceURL` | `-` |
| `SALESFORCE_PASSWORD` | `getEnv` | `""` | `SalesforcePassword` | `-` |
| `SALESFORCE_SECURITY_TOKEN` | `getEnv` | `""` | `SalesforceSecurityToken` | `-` |
| `SALESFORCE_USERNAME` | `getEnv` | `""` | `SalesforceUsername` | `-` |
| `SAVIYNT_API_TOKEN` | `getEnv` | `""` | `SaviyntAPIToken` | `-` |
| `SAVIYNT_URL` | `getEnv` | `""` | `SaviyntURL` | `-` |
| `SCAN_ADAPTIVE_CONCURRENCY` | `getEnvBool` | `true` | `ScanAdaptiveConcurrency` | `-` |
| `SCAN_INTERVAL` | `getEnv` | `""` | `ScanInterval` | `-` |
| `SCAN_MAX_CONCURRENCY` | `getEnvInt` | `6` | `ScanMaxConcurrent` | `-` |
| `SCAN_MIN_CONCURRENCY` | `getEnvInt` | `2` | `ScanMinConcurrent` | `-` |
| `SCAN_POLICIES_PATH` | `getEnv` | `""` | `ScanPoliciesPath` | `-` |
| `SCAN_RETRY_ATTEMPTS` | `getEnvInt` | `3` | `ScanRetryAttempts` | `-` |
| `SCAN_RETRY_BACKOFF` | `getEnvDuration` | `2 * time.Second` | `ScanRetryBackoff` | `-` |
| `SCAN_RETRY_MAX_BACKOFF` | `getEnvDuration` | `30 * time.Second` | `ScanRetryMaxBackoff` | `-` |
| `SCAN_TABLES` | `getEnv` | `""` | `ScanTables` | `-` |
| `SCAN_TABLE_TIMEOUT` | `getEnvDuration` | `30 * time.Minute` | `ScanTableTimeout` | `-` |
| `SECURITY_DIGEST_INTERVAL` | `getEnv` | `""` | `SecurityDigestInterval` | `-` |
| `SEMGREP_API_TOKEN` | `getEnv` | `""` | `SemgrepAPIToken` | `-` |
| `SENTINELONE_API_TOKEN` | `getEnv` | `""` | `SentinelOneAPIToken` | `-` |
| `SENTINELONE_BASE_URL` | `getEnv` | `""` | `SentinelOneBaseURL` | `-` |
| `SERVICENOW_API_TOKEN` | `getEnv` | `""` | `ServiceNowAPIToken` | `-` |
| `SERVICENOW_PASSWORD` | `getEnv` | `""` | `ServiceNowPassword` | `-` |
| `SERVICENOW_URL` | `getEnv` | `""` | `ServiceNowURL` | `-` |
| `SERVICENOW_USERNAME` | `getEnv` | `""` | `ServiceNowUsername` | `-` |
| `SLACK_API_TOKEN` | `getEnv` | `""` | `SlackAPIToken` | `-` |
| `SLACK_SIGNING_SECRET` | `getEnv` | `""` | `SlackSigningSecret` | `-` |
| `SLACK_WEBHOOK_URL` | `getEnv` | `""` | `SlackWebhookURL` | `-` |
| `SNOWFLAKE_ACCOUNT` | `getEnv` | `""` | `-` | `when the Snowflake backend is selected or any Snowflake auth field is set, all three auth fields are required` |
| `SNOWFLAKE_DATABASE` | `getEnv` | `"CEREBRO"` | `SnowflakeDatabase` | `-` |
| `SNOWFLAKE_PRIVATE_KEY` | `getEnv` | `""` | `-` | `when the Snowflake backend is selected or any Snowflake auth field is set, all three auth fields are required` |
| `SNOWFLAKE_ROLE` | `getEnv` | `""` | `SnowflakeRole` | `-` |
| `SNOWFLAKE_SCHEMA` | `getEnv` | `"CEREBRO"` | `SnowflakeSchema` | `-` |
| `SNOWFLAKE_USER` | `getEnv` | `""` | `-` | `when the Snowflake backend is selected or any Snowflake auth field is set, all three auth fields are required` |
| `SNOWFLAKE_WAREHOUSE` | `getEnv` | `"COMPUTE_WH"` | `SnowflakeWarehouse` | `-` |
| `SNYK_API_TOKEN` | `getEnv` | `""` | `SnykAPIToken` | `-` |
| `SNYK_ORG_ID` | `getEnv` | `""` | `SnykOrgID` | `-` |
| `SOCKET_API_TOKEN` | `getEnv` | `""` | `SocketAPIToken` | `-` |
| `SOCKET_API_URL` | `getEnv` | `"https://api.socket.dev/v0"` | `SocketAPIURL` | `-` |
| `SOCKET_ORG` | `getEnv` | `""` | `SocketOrgSlug` | `-` |
| `SPLUNK_TOKEN` | `getEnv` | `""` | `SplunkToken` | `-` |
| `SPLUNK_URL` | `getEnv` | `""` | `SplunkURL` | `-` |
| `TAILSCALE_API_KEY` | `getEnv` | `""` | `TailscaleAPIKey` | `-` |
| `TAILSCALE_TAILNET` | `getEnv` | `""` | `TailscaleTailnet` | `-` |
| `TENABLE_ACCESS_KEY` | `getEnv` | `""` | `TenableAccessKey` | `-` |
| `TENABLE_SECRET_KEY` | `getEnv` | `""` | `TenableSecretKey` | `-` |
| `TFC_TOKEN` | `getEnv` | `""` | `TerraformCloudToken` | `-` |
| `VANTA_API_TOKEN` | `getEnv` | `""` | `VantaAPIToken` | `-` |
| `VANTA_BASE_URL` | `getEnv` | `"https://api.vanta.com"` | `VantaBaseURL` | `-` |
| `VAULT_ADDRESS` | `getEnv` | `""` | `VaultAddress` | `-` |
| `VAULT_NAMESPACE` | `getEnv` | `""` | `VaultNamespace` | `-` |
| `VAULT_TOKEN` | `getEnv` | `""` | `VaultToken` | `-` |
| `VULNDB_STATE_FILE` | `getEnv` | `filepath.Join(".cerebro", "vulndb.db")` | `VulnDBStateFile` | `-` |
| `WAREHOUSE_BACKEND` | `getEnv` | `defaultWarehouseBackend` | `WarehouseBackend` | `backend-specific connection settings must be present when an alternative warehouse backend is selected`, `must be one of snowflake, sqlite, postgres` |
| `WAREHOUSE_POSTGRES_DSN` | `getEnv` | `""` | `WarehousePostgresDSN` | `backend-specific connection settings must be present when an alternative warehouse backend is selected` |
| `WAREHOUSE_SQLITE_PATH` | `getEnv` | `defaultWarehouseSQLitePath` | `WarehouseSQLitePath` | `backend-specific connection settings must be present when an alternative warehouse backend is selected` |
| `WEBHOOK_URLS` | `getEnv` | `""` | `WebhookURLs` | `-` |
| `WIZ_API_URL` | `getEnv` | `""` | `WizAPIURL` | `-` |
| `WIZ_AUDIENCE` | `getEnv` | `"wiz-api"` | `WizAudience` | `-` |
| `WIZ_CLIENT_ID` | `getEnv` | `""` | `WizClientID` | `-` |
| `WIZ_CLIENT_SECRET` | `getEnv` | `""` | `WizClientSecret` | `-` |
| `WIZ_TOKEN_URL` | `getEnv` | `"https://auth.app.wiz.io/oauth/token"` | `WizTokenURL` | `-` |
| `WORKDAY_API_TOKEN` | `getEnv` | `""` | `WorkdayAPIToken` | `-` |
| `WORKDAY_URL` | `getEnv` | `""` | `WorkdayURL` | `-` |
| `WORKLOAD_SCAN_CLAMAV_BINARY` | `getEnv` | `""` | `WorkloadScanClamAVBinary` | `-` |
| `WORKLOAD_SCAN_CLEANUP_TIMEOUT` | `getEnvDuration` | `2 * time.Minute` | `WorkloadScanCleanupTimeout` | `-` |
| `WORKLOAD_SCAN_GITLEAKS_BINARY` | `getEnv` | `""` | `WorkloadScanGitleaksBinary` | `-` |
| `WORKLOAD_SCAN_MAX_CONCURRENT_SNAPSHOTS` | `getEnvInt` | `2` | `WorkloadScanMaxConcurrentSnapshots` | `-` |
| `WORKLOAD_SCAN_MOUNT_BASE_PATH` | `getEnv` | `filepath.Join(".cerebro", "workload-scan", "mounts")` | `WorkloadScanMountBasePath` | `-` |
| `WORKLOAD_SCAN_RECONCILE_OLDER_THAN` | `getEnvDuration` | `30 * time.Minute` | `WorkloadScanReconcileOlderThan` | `-` |
| `WORKLOAD_SCAN_STATE_FILE` | `getEnv` | `getEnv("EXECUTION_STORE_FILE", filepath.Join(".cerebro", "executions.db"))` | `WorkloadScanStateFile` | `-` |
| `WORKLOAD_SCAN_TRIVY_BINARY` | `getEnv` | `"trivy"` | `WorkloadScanTrivyBinary` | `-` |
| `ZOOM_ACCOUNT_ID` | `getEnv` | `""` | `ZoomAccountID` | `-` |
| `ZOOM_API_URL` | `getEnv` | `"https://api.zoom.us/v2"` | `ZoomAPIURL` | `-` |
| `ZOOM_CLIENT_ID` | `getEnv` | `""` | `ZoomClientID` | `-` |
| `ZOOM_CLIENT_SECRET` | `getEnv` | `""` | `ZoomClientSecret` | `-` |
| `ZOOM_TOKEN_URL` | `getEnv` | `"https://zoom.us/oauth/token"` | `ZoomTokenURL` | `-` |
