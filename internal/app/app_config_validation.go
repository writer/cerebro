package app

import (
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graphingest"
)

// ConfigValidationError aggregates all invalid config problems discovered during
// config load and semantic validation.
type ConfigValidationError struct {
	Problems []string
}

// ConfigValidationRule documents a startup validation rule and the env vars it constrains.
type ConfigValidationRule struct {
	EnvVars  []string
	Summary  string
	Category string
}

func (e *ConfigValidationError) Error() string {
	if e == nil || len(e.Problems) == 0 {
		return "invalid config"
	}
	if len(e.Problems) == 1 {
		return "invalid config: " + e.Problems[0]
	}
	return "invalid config:\n- " + strings.Join(e.Problems, "\n- ")
}

func normalizeConfigProblems(problems []string) []string {
	seen := make(map[string]struct{}, len(problems))
	out := make([]string, 0, len(problems))
	for _, problem := range problems {
		problem = strings.TrimSpace(problem)
		if problem == "" {
			continue
		}
		if _, ok := seen[problem]; ok {
			continue
		}
		seen[problem] = struct{}{}
		out = append(out, problem)
	}
	return out
}

func addConfigProblem(problems []string, format string, args ...any) []string {
	return append(problems, fmt.Sprintf(format, args...))
}

// ConfigValidationRules returns the catalog of startup validation rules used by Config.Validate.
func ConfigValidationRules() []ConfigValidationRule {
	return []ConfigValidationRule{
		{EnvVars: []string{"API_PORT"}, Summary: "must be between 1 and 65535", Category: "range"},
		{EnvVars: []string{"API_REQUEST_TIMEOUT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"API_READ_TIMEOUT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"API_WRITE_TIMEOUT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"API_IDLE_TIMEOUT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"API_MAX_BODY_BYTES"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"CEREBRO_HEALTH_CHECK_TIMEOUT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"CEREBRO_SHUTDOWN_TIMEOUT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"AGENT_PENDING_TOOL_APPROVAL_TTL"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"LOG_LEVEL"}, Summary: "must be one of debug, info, warn, error", Category: "enum"},
		{EnvVars: []string{"CEREBRO_OTEL_SAMPLE_RATIO"}, Summary: "must be between 0 and 1", Category: "range"},
		{EnvVars: []string{"QUERY_POLICY_ROW_LIMIT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"CEREBRO_INIT_TIMEOUT"}, Summary: "must be greater than or equal to 0", Category: "range"},
		{EnvVars: []string{"GRAPH_RISK_ENGINE_STATE_TIMEOUT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"CEREBRO_THREAT_INTEL_SYNC_TIMEOUT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"CEREBRO_THREAT_INTEL_SYNC_MAX_AGE"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"CEREBRO_THREAT_INTEL_SYNC_ATTEMPTS"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"CEREBRO_THREAT_INTEL_SYNC_BACKOFF"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"CEREBRO_TICKETING_PROVIDER_VALIDATE_TIMEOUT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"GRAPH_CONSISTENCY_CHECK_TIMEOUT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"GRAPH_POST_SYNC_UPDATE_TIMEOUT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"CEREBRO_HEALTH_CHECK_TIMEOUT", "API_REQUEST_TIMEOUT"}, Summary: "health checks must not outlive the API request timeout", Category: "dependency"},
		{EnvVars: []string{"API_REQUEST_TIMEOUT", "API_WRITE_TIMEOUT"}, Summary: "request timeout must not exceed the server write timeout", Category: "dependency"},
		{EnvVars: []string{"FINDINGS_MAX_IN_MEMORY"}, Summary: "must be greater than or equal to 0", Category: "range"},
		{EnvVars: []string{"FINDINGS_RESOLVED_RETENTION"}, Summary: "must be greater than or equal to 0", Category: "range"},
		{EnvVars: []string{"FINDINGS_SEMANTIC_DEDUP_ENABLED"}, Summary: "enables semantic finding identity across policy/version drift", Category: "behavior"},
		{
			EnvVars:  []string{"WAREHOUSE_BACKEND"},
			Summary:  "must be one of snowflake, sqlite, postgres",
			Category: "enum",
		},
		{
			EnvVars:  []string{"CEREBRO_CREDENTIAL_SOURCE"},
			Summary:  "must be one of env, file, vault",
			Category: "enum",
		},
		{
			EnvVars: []string{
				"CEREBRO_CREDENTIAL_SOURCE",
				"CEREBRO_CREDENTIAL_FILE_DIR",
				"CEREBRO_CREDENTIAL_VAULT_ADDRESS",
				"CEREBRO_CREDENTIAL_VAULT_TOKEN",
				"CEREBRO_CREDENTIAL_VAULT_NAMESPACE",
				"CEREBRO_CREDENTIAL_VAULT_PATH",
				"CEREBRO_CREDENTIAL_VAULT_KV_VERSION",
			},
			Summary:  "credential-source settings must be present and valid for the selected source backend",
			Category: "dependency",
		},
		{
			EnvVars:  []string{"WAREHOUSE_BACKEND", "WAREHOUSE_SQLITE_PATH", "WAREHOUSE_POSTGRES_DSN"},
			Summary:  "backend-specific connection settings must be present when an alternative warehouse backend is selected",
			Category: "dependency",
		},
		{
			EnvVars:  []string{"SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PRIVATE_KEY"},
			Summary:  "when the Snowflake backend is selected or any Snowflake auth field is set, all three auth fields are required",
			Category: "dependency",
		},
		{
			EnvVars: []string{
				"NATS_JETSTREAM_ENABLED",
				"NATS_URLS",
				"NATS_JETSTREAM_STREAM",
				"NATS_JETSTREAM_SUBJECT_PREFIX",
				"NATS_JETSTREAM_PUBLISH_TIMEOUT",
				"NATS_JETSTREAM_CONNECT_TIMEOUT",
				"NATS_JETSTREAM_FLUSH_INTERVAL",
				"NATS_JETSTREAM_OUTBOX_MAX_AGE",
				"NATS_JETSTREAM_OUTBOX_MAX_ITEMS",
				"NATS_JETSTREAM_OUTBOX_MAX_RETRY",
			},
			Summary:  "when NATS_JETSTREAM_ENABLED=true, required values must be present and timing/retention values must be positive",
			Category: "dependency",
		},
		{
			EnvVars: []string{
				"NATS_CONSUMER_ENABLED",
				"NATS_JETSTREAM_ENABLED",
				"NATS_CONSUMER_STREAM",
				"NATS_CONSUMER_DURABLE",
				"NATS_CONSUMER_SUBJECTS",
				"NATS_CONSUMER_BATCH_SIZE",
				"NATS_CONSUMER_ACK_WAIT",
				"NATS_CONSUMER_FETCH_TIMEOUT",
				"NATS_CONSUMER_IN_PROGRESS_INTERVAL",
				"NATS_CONSUMER_DRAIN_TIMEOUT",
				"NATS_CONSUMER_DROP_HEALTH_LOOKBACK",
				"NATS_CONSUMER_DROP_HEALTH_THRESHOLD",
				"NATS_CONSUMER_GRAPH_STALENESS_THRESHOLD",
			},
			Summary:  "when NATS_CONSUMER_ENABLED=true, JetStream must also be enabled; identifiers must be present; durations must be positive; drop threshold must be non-negative; dedupe settings must be valid when enabled",
			Category: "dependency",
		},
		{
			EnvVars: []string{
				"JOB_DATABASE_URL",
				"NATS_URLS",
				"JOB_NATS_STREAM",
				"JOB_NATS_SUBJECT",
				"JOB_NATS_CONSUMER",
				"JOB_WORKER_CONCURRENCY",
				"JOB_VISIBILITY_TIMEOUT",
				"JOB_POLL_WAIT",
				"JOB_MAX_ATTEMPTS",
			},
			Summary:  "when JOB_DATABASE_URL is configured, NATS settings must be present and worker timing/count controls must be positive",
			Category: "dependency",
		},
		{
			EnvVars:  []string{"FINDING_ATTESTATION_ENABLED", "FINDING_ATTESTATION_SIGNING_KEY", "FINDING_ATTESTATION_TIMEOUT"},
			Summary:  "when FINDING_ATTESTATION_ENABLED=true, the signing key is required and timeout must be positive",
			Category: "dependency",
		},
		{
			EnvVars:  []string{"RATE_LIMIT_ENABLED", "RATE_LIMIT_REQUESTS", "RATE_LIMIT_WINDOW"},
			Summary:  "when RATE_LIMIT_ENABLED=true, requests and window must be positive",
			Category: "dependency",
		},
		{
			EnvVars: []string{
				"GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST",
				"GRAPH_CROSS_TENANT_SIGNING_KEY",
				"GRAPH_CROSS_TENANT_SIGNATURE_MAX_SKEW",
				"GRAPH_CROSS_TENANT_REPLAY_TTL",
				"GRAPH_CROSS_TENANT_MIN_TENANTS",
				"GRAPH_CROSS_TENANT_MIN_SUPPORT",
			},
			Summary:  "when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true, signing key is required and skew/TTL/support thresholds must be positive",
			Category: "dependency",
		},
		{EnvVars: []string{"GRAPH_STORE_BACKEND"}, Summary: "must be neptune", Category: "enum"},
		{
			EnvVars:  []string{"GRAPH_STORE_BACKEND", "GRAPH_STORE_NEPTUNE_ENDPOINT"},
			Summary:  "when GRAPH_STORE_BACKEND=neptune, the Neptune data API endpoint is required",
			Category: "dependency",
		},
		{EnvVars: []string{"GRAPH_SEARCH_BACKEND"}, Summary: "must be one of graph, opensearch", Category: "enum"},
		{
			EnvVars:  []string{"GRAPH_SEARCH_BACKEND", "GRAPH_SEARCH_OPENSEARCH_ENDPOINT", "GRAPH_SEARCH_OPENSEARCH_REGION", "GRAPH_SEARCH_OPENSEARCH_INDEX"},
			Summary:  "when GRAPH_SEARCH_BACKEND=opensearch, the OpenSearch endpoint, region, and index are required",
			Category: "dependency",
		},
		{EnvVars: []string{"GRAPH_SEARCH_REQUEST_TIMEOUT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"GRAPH_SEARCH_MAX_CANDIDATES"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"GRAPH_TENANT_SHARD_IDLE_TTL"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"GRAPH_TENANT_WARM_SHARD_TTL"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"GRAPH_TENANT_WARM_SHARD_MAX_RETAINED"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"GRAPH_PROPERTY_HISTORY_MAX_ENTRIES"}, Summary: "non-positive values fall back to the default max property-history depth", Category: "behavior"},
		{EnvVars: []string{"GRAPH_PROPERTY_HISTORY_TTL"}, Summary: "non-positive values fall back to the default property-history TTL", Category: "behavior"},
		{EnvVars: []string{"GRAPH_SCHEMA_VALIDATION_MODE"}, Summary: "must be one of off, warn, enforce", Category: "enum"},
		{EnvVars: []string{"GRAPH_EVENT_MAPPER_VALIDATION_MODE"}, Summary: "must be one of warn, enforce", Category: "enum"},
	}
}

func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}

	problems := append([]string(nil), c.loadProblems...)
	testProcess := runningUnderGoTest()

	if c.Port < 1 || c.Port > 65535 {
		problems = addConfigProblem(problems, "API_PORT must be between 1 and 65535")
	}
	if c.APIRequestTimeout <= 0 {
		problems = addConfigProblem(problems, "API_REQUEST_TIMEOUT must be > 0")
	}
	if c.APIReadTimeout <= 0 {
		problems = addConfigProblem(problems, "API_READ_TIMEOUT must be > 0")
	}
	if c.APIWriteTimeout <= 0 {
		problems = addConfigProblem(problems, "API_WRITE_TIMEOUT must be > 0")
	}
	if c.APIIdleTimeout <= 0 {
		problems = addConfigProblem(problems, "API_IDLE_TIMEOUT must be > 0")
	}
	if c.APIMaxBodyBytes <= 0 {
		problems = addConfigProblem(problems, "API_MAX_BODY_BYTES must be > 0")
	}
	if c.HealthCheckTimeout <= 0 {
		problems = addConfigProblem(problems, "CEREBRO_HEALTH_CHECK_TIMEOUT must be > 0")
	}
	if c.ShutdownTimeout <= 0 {
		problems = addConfigProblem(problems, "CEREBRO_SHUTDOWN_TIMEOUT must be > 0")
	}
	if c.AgentPendingToolApprovalTTL <= 0 {
		problems = addConfigProblem(problems, "AGENT_PENDING_TOOL_APPROVAL_TTL must be > 0")
	}

	switch strings.ToLower(strings.TrimSpace(c.LogLevel)) {
	case "", "debug", "info", "warn", "error":
	default:
		problems = addConfigProblem(problems, "LOG_LEVEL must be one of debug, info, warn, error")
	}

	if c.TracingSampleRatio < 0 || c.TracingSampleRatio > 1 {
		problems = addConfigProblem(problems, "CEREBRO_OTEL_SAMPLE_RATIO must be between 0 and 1")
	}
	if c.QueryPolicyRowLimit <= 0 {
		problems = addConfigProblem(problems, "QUERY_POLICY_ROW_LIMIT must be greater than 0")
	}
	if c.InitTimeout < 0 {
		problems = addConfigProblem(problems, "CEREBRO_INIT_TIMEOUT must be >= 0")
	}
	if c.GraphRiskEngineStateTimeout <= 0 {
		problems = addConfigProblem(problems, "GRAPH_RISK_ENGINE_STATE_TIMEOUT must be > 0")
	}
	if c.ThreatIntelSyncTimeout <= 0 {
		problems = addConfigProblem(problems, "CEREBRO_THREAT_INTEL_SYNC_TIMEOUT must be > 0")
	}
	if c.ThreatIntelSyncMaxAge <= 0 {
		problems = addConfigProblem(problems, "CEREBRO_THREAT_INTEL_SYNC_MAX_AGE must be > 0")
	}
	if c.ThreatIntelSyncAttempts <= 0 {
		problems = addConfigProblem(problems, "CEREBRO_THREAT_INTEL_SYNC_ATTEMPTS must be > 0")
	}
	if c.ThreatIntelSyncBackoff <= 0 {
		problems = addConfigProblem(problems, "CEREBRO_THREAT_INTEL_SYNC_BACKOFF must be > 0")
	}
	if c.TicketingProviderValidateTimeout <= 0 {
		problems = addConfigProblem(problems, "CEREBRO_TICKETING_PROVIDER_VALIDATE_TIMEOUT must be > 0")
	}
	if c.GraphConsistencyCheckTimeout <= 0 {
		problems = addConfigProblem(problems, "GRAPH_CONSISTENCY_CHECK_TIMEOUT must be > 0")
	}
	if c.GraphPostSyncUpdateTimeout <= 0 {
		problems = addConfigProblem(problems, "GRAPH_POST_SYNC_UPDATE_TIMEOUT must be > 0")
	}
	if c.HealthCheckTimeout > 0 && c.APIRequestTimeout > 0 && c.HealthCheckTimeout > c.APIRequestTimeout {
		problems = addConfigProblem(problems, "CEREBRO_HEALTH_CHECK_TIMEOUT must be <= API_REQUEST_TIMEOUT")
	}
	if c.APIRequestTimeout > 0 && c.APIWriteTimeout > 0 && c.APIRequestTimeout > c.APIWriteTimeout {
		problems = addConfigProblem(problems, "API_REQUEST_TIMEOUT must be <= API_WRITE_TIMEOUT")
	}
	if c.FindingsMaxInMemory < 0 {
		problems = addConfigProblem(problems, "FINDINGS_MAX_IN_MEMORY must be >= 0")
	}
	if c.FindingsResolvedRetention < 0 {
		problems = addConfigProblem(problems, "FINDINGS_RESOLVED_RETENTION must be >= 0")
	}
	if c.GraphTenantShardIdleTTL <= 0 {
		problems = addConfigProblem(problems, "GRAPH_TENANT_SHARD_IDLE_TTL must be > 0")
	}
	if c.GraphTenantWarmShardTTL <= 0 {
		problems = addConfigProblem(problems, "GRAPH_TENANT_WARM_SHARD_TTL must be > 0")
	}
	if c.GraphTenantWarmShardMaxRetained <= 0 {
		problems = addConfigProblem(problems, "GRAPH_TENANT_WARM_SHARD_MAX_RETAINED must be > 0")
	}
	if c.GraphPropertyHistoryMaxEntries < 0 {
		problems = addConfigProblem(problems, "GRAPH_PROPERTY_HISTORY_MAX_ENTRIES must be >= 0")
	}
	if c.GraphPropertyHistoryTTL < 0 {
		problems = addConfigProblem(problems, "GRAPH_PROPERTY_HISTORY_TTL must be >= 0")
	}
	if c.GraphWriterLeaseEnabled {
		if !c.NATSJetStreamEnabled {
			problems = addConfigProblem(problems, "NATS_JETSTREAM_ENABLED must be true when GRAPH_WRITER_LEASE_ENABLED=true")
		}
		if strings.TrimSpace(c.GraphWriterLeaseBucket) == "" {
			problems = addConfigProblem(problems, "GRAPH_WRITER_LEASE_BUCKET is required when GRAPH_WRITER_LEASE_ENABLED=true")
		}
		if strings.TrimSpace(c.GraphWriterLeaseName) == "" {
			problems = addConfigProblem(problems, "GRAPH_WRITER_LEASE_NAME is required when GRAPH_WRITER_LEASE_ENABLED=true")
		}
		if strings.TrimSpace(c.GraphWriterLeaseOwnerID) == "" {
			problems = addConfigProblem(problems, "GRAPH_WRITER_LEASE_OWNER_ID is required when GRAPH_WRITER_LEASE_ENABLED=true")
		}
		if c.GraphWriterLeaseTTL <= 0 {
			problems = addConfigProblem(problems, "GRAPH_WRITER_LEASE_TTL must be > 0 when GRAPH_WRITER_LEASE_ENABLED=true")
		}
		if c.GraphWriterLeaseHeartbeat <= 0 {
			problems = addConfigProblem(problems, "GRAPH_WRITER_LEASE_HEARTBEAT must be > 0 when GRAPH_WRITER_LEASE_ENABLED=true")
		}
		if c.GraphWriterLeaseTTL > 0 && c.GraphWriterLeaseHeartbeat >= c.GraphWriterLeaseTTL {
			problems = addConfigProblem(problems, "GRAPH_WRITER_LEASE_HEARTBEAT must be less than GRAPH_WRITER_LEASE_TTL when GRAPH_WRITER_LEASE_ENABLED=true")
		}
	}

	switch strings.ToLower(strings.TrimSpace(c.WarehouseBackend)) {
	case "", "snowflake", "sqlite", "postgres":
	default:
		problems = addConfigProblem(problems, "WAREHOUSE_BACKEND must be one of snowflake, sqlite, postgres")
	}

	switch strings.ToLower(strings.TrimSpace(c.CredentialSource)) {
	case "", "env", "file", "vault":
	default:
		problems = addConfigProblem(problems, "CEREBRO_CREDENTIAL_SOURCE must be one of env, file, vault")
	}

	switch strings.ToLower(strings.TrimSpace(c.CredentialSource)) {
	case "file":
		if strings.TrimSpace(c.CredentialFileDir) == "" {
			problems = addConfigProblem(problems, "CEREBRO_CREDENTIAL_FILE_DIR is required when CEREBRO_CREDENTIAL_SOURCE=file")
		}
	case "vault":
		if strings.TrimSpace(c.CredentialVaultAddress) == "" {
			problems = addConfigProblem(problems, "CEREBRO_CREDENTIAL_VAULT_ADDRESS is required when CEREBRO_CREDENTIAL_SOURCE=vault")
		}
		if strings.TrimSpace(c.CredentialVaultToken) == "" {
			problems = addConfigProblem(problems, "CEREBRO_CREDENTIAL_VAULT_TOKEN is required when CEREBRO_CREDENTIAL_SOURCE=vault")
		}
		if strings.TrimSpace(c.CredentialVaultPath) == "" {
			problems = addConfigProblem(problems, "CEREBRO_CREDENTIAL_VAULT_PATH is required when CEREBRO_CREDENTIAL_SOURCE=vault")
		}
		if c.CredentialVaultKVVersion != 1 && c.CredentialVaultKVVersion != 2 {
			problems = addConfigProblem(problems, "CEREBRO_CREDENTIAL_VAULT_KV_VERSION must be 1 or 2 when CEREBRO_CREDENTIAL_SOURCE=vault")
		}
		if !credentialVaultAddressAllowed(c.CredentialVaultAddress) {
			problems = addConfigProblem(problems, "CEREBRO_CREDENTIAL_VAULT_ADDRESS must use https unless it targets localhost or a loopback address")
		}
	}

	hasSnowflakeAuth := strings.TrimSpace(c.SnowflakeAccount) != "" ||
		strings.TrimSpace(c.SnowflakeUser) != "" ||
		strings.TrimSpace(c.SnowflakePrivateKey) != ""
	requiresSnowflakeAuth := strings.EqualFold(strings.TrimSpace(c.WarehouseBackend), "snowflake") || hasSnowflakeAuth
	if requiresSnowflakeAuth {
		if strings.TrimSpace(c.SnowflakeAccount) == "" {
			problems = addConfigProblem(problems, "SNOWFLAKE_ACCOUNT is required when the Snowflake warehouse backend is configured")
		}
		if strings.TrimSpace(c.SnowflakeUser) == "" {
			problems = addConfigProblem(problems, "SNOWFLAKE_USER is required when the Snowflake warehouse backend is configured")
		}
		if strings.TrimSpace(c.SnowflakePrivateKey) == "" {
			problems = addConfigProblem(problems, "SNOWFLAKE_PRIVATE_KEY is required when the Snowflake warehouse backend is configured")
		}
	}

	if strings.EqualFold(strings.TrimSpace(c.WarehouseBackend), "sqlite") {
		if strings.TrimSpace(c.WarehouseSQLitePath) == "" {
			problems = addConfigProblem(problems, "WAREHOUSE_SQLITE_PATH is required when WAREHOUSE_BACKEND=sqlite")
		}
	}

	if strings.EqualFold(strings.TrimSpace(c.WarehouseBackend), "postgres") {
		if strings.TrimSpace(c.WarehousePostgresDSN) == "" {
			problems = addConfigProblem(problems, "WAREHOUSE_POSTGRES_DSN is required when WAREHOUSE_BACKEND=postgres")
		}
	}

	if c.NATSJetStreamEnabled {
		if len(c.NATSJetStreamURLs) == 0 {
			problems = addConfigProblem(problems, "NATS_URLS must include at least one URL when NATS_JETSTREAM_ENABLED=true")
		}
		if strings.TrimSpace(c.NATSJetStreamStream) == "" {
			problems = addConfigProblem(problems, "NATS_JETSTREAM_STREAM is required when NATS_JETSTREAM_ENABLED=true")
		}
		if strings.TrimSpace(c.NATSJetStreamSubjectPrefix) == "" {
			problems = addConfigProblem(problems, "NATS_JETSTREAM_SUBJECT_PREFIX is required when NATS_JETSTREAM_ENABLED=true")
		}
		if c.NATSJetStreamPublishTimeout <= 0 {
			problems = addConfigProblem(problems, "NATS_JETSTREAM_PUBLISH_TIMEOUT must be > 0 when NATS_JETSTREAM_ENABLED=true")
		}
		if c.NATSJetStreamConnectTimeout <= 0 {
			problems = addConfigProblem(problems, "NATS_JETSTREAM_CONNECT_TIMEOUT must be > 0 when NATS_JETSTREAM_ENABLED=true")
		}
		if c.NATSJetStreamFlushInterval <= 0 {
			problems = addConfigProblem(problems, "NATS_JETSTREAM_FLUSH_INTERVAL must be > 0 when NATS_JETSTREAM_ENABLED=true")
		}
		if c.NATSJetStreamOutboxMaxAge <= 0 {
			problems = addConfigProblem(problems, "NATS_JETSTREAM_OUTBOX_MAX_AGE must be > 0 when NATS_JETSTREAM_ENABLED=true")
		}
		if c.NATSJetStreamOutboxMaxItems <= 0 {
			problems = addConfigProblem(problems, "NATS_JETSTREAM_OUTBOX_MAX_ITEMS must be > 0 when NATS_JETSTREAM_ENABLED=true")
		}
		if c.NATSJetStreamOutboxMaxRetry < 0 {
			problems = addConfigProblem(problems, "NATS_JETSTREAM_OUTBOX_MAX_RETRY must be >= 0 when NATS_JETSTREAM_ENABLED=true")
		}
		if c.NATSJetStreamTLSEnabled && c.NATSJetStreamTLSInsecure && !getEnvBool("CEREBRO_ALLOW_INSECURE_TLS", false) {
			problems = addConfigProblem(problems, "NATS_JETSTREAM_TLS_INSECURE_SKIP_VERIFY requires CEREBRO_ALLOW_INSECURE_TLS=true")
		}
	}

	if c.NATSConsumerEnabled {
		if !c.NATSJetStreamEnabled {
			problems = addConfigProblem(problems, "NATS_JETSTREAM_ENABLED must be true when NATS_CONSUMER_ENABLED=true")
		}
		if strings.TrimSpace(c.NATSConsumerStream) == "" {
			problems = addConfigProblem(problems, "NATS_CONSUMER_STREAM is required when NATS_CONSUMER_ENABLED=true")
		}
		if strings.TrimSpace(c.NATSConsumerDurable) == "" {
			problems = addConfigProblem(problems, "NATS_CONSUMER_DURABLE is required when NATS_CONSUMER_ENABLED=true")
		}
		if len(c.NATSConsumerSubjects) == 0 {
			problems = addConfigProblem(problems, "NATS_CONSUMER_SUBJECTS must include at least one subject when NATS_CONSUMER_ENABLED=true")
		}
		if c.NATSConsumerBatchSize <= 0 {
			problems = addConfigProblem(problems, "NATS_CONSUMER_BATCH_SIZE must be > 0 when NATS_CONSUMER_ENABLED=true")
		}
		if c.NATSConsumerAckWait <= 0 {
			problems = addConfigProblem(problems, "NATS_CONSUMER_ACK_WAIT must be > 0 when NATS_CONSUMER_ENABLED=true")
		}
		if c.NATSConsumerFetchTimeout <= 0 {
			problems = addConfigProblem(problems, "NATS_CONSUMER_FETCH_TIMEOUT must be > 0 when NATS_CONSUMER_ENABLED=true")
		}
		if c.NATSConsumerInProgressInterval <= 0 {
			problems = addConfigProblem(problems, "NATS_CONSUMER_IN_PROGRESS_INTERVAL must be > 0 when NATS_CONSUMER_ENABLED=true")
		}
		if c.NATSConsumerDrainTimeout <= 0 {
			problems = addConfigProblem(problems, "NATS_CONSUMER_DRAIN_TIMEOUT must be > 0 when NATS_CONSUMER_ENABLED=true")
		}
		if c.NATSConsumerDropHealthLookback <= 0 {
			problems = addConfigProblem(problems, "NATS_CONSUMER_DROP_HEALTH_LOOKBACK must be > 0 when NATS_CONSUMER_ENABLED=true")
		}
		if c.NATSConsumerDropHealthThreshold < 0 {
			problems = addConfigProblem(problems, "NATS_CONSUMER_DROP_HEALTH_THRESHOLD must be >= 0 when NATS_CONSUMER_ENABLED=true")
		}
		if c.NATSConsumerDedupEnabled {
			if strings.TrimSpace(c.NATSConsumerDedupStateFile) == "" {
				problems = addConfigProblem(problems, "NATS_CONSUMER_DEDUP_STATE_FILE is required when NATS_CONSUMER_DEDUP_ENABLED=true")
			}
			if c.NATSConsumerDedupTTL <= 0 {
				problems = addConfigProblem(problems, "NATS_CONSUMER_DEDUP_TTL must be > 0 when NATS_CONSUMER_DEDUP_ENABLED=true")
			}
			if c.NATSConsumerDedupMaxRecords <= 0 {
				problems = addConfigProblem(problems, "NATS_CONSUMER_DEDUP_MAX_RECORDS must be > 0 when NATS_CONSUMER_DEDUP_ENABLED=true")
			}
		}
		if c.NATSConsumerGraphStalenessThreshold <= 0 {
			problems = addConfigProblem(problems, "NATS_CONSUMER_GRAPH_STALENESS_THRESHOLD must be > 0 when NATS_CONSUMER_ENABLED=true")
		}
	}

	if strings.TrimSpace(c.JobDatabaseURL) != "" {
		if len(c.NATSJetStreamURLs) == 0 {
			problems = addConfigProblem(problems, "NATS_URLS must include at least one URL when JOB_DATABASE_URL is configured")
		}
		if strings.TrimSpace(c.JobNATSStream) == "" {
			problems = addConfigProblem(problems, "JOB_NATS_STREAM is required when JOB_DATABASE_URL is configured")
		}
		if strings.TrimSpace(c.JobNATSSubject) == "" {
			problems = addConfigProblem(problems, "JOB_NATS_SUBJECT is required when JOB_DATABASE_URL is configured")
		}
		if strings.TrimSpace(c.JobNATSConsumer) == "" {
			problems = addConfigProblem(problems, "JOB_NATS_CONSUMER is required when JOB_DATABASE_URL is configured")
		}
		if c.JobWorkerConcurrency <= 0 {
			problems = addConfigProblem(problems, "JOB_WORKER_CONCURRENCY must be > 0 when JOB_DATABASE_URL is configured")
		}
		if c.JobVisibilityTimeout <= 0 {
			problems = addConfigProblem(problems, "JOB_VISIBILITY_TIMEOUT must be > 0 when JOB_DATABASE_URL is configured")
		}
		if c.JobPollWait <= 0 {
			problems = addConfigProblem(problems, "JOB_POLL_WAIT must be > 0 when JOB_DATABASE_URL is configured")
		}
		if c.JobMaxAttempts <= 0 {
			problems = addConfigProblem(problems, "JOB_MAX_ATTEMPTS must be > 0 when JOB_DATABASE_URL is configured")
		}
	}

	if c.FindingAttestationEnabled {
		if strings.TrimSpace(c.FindingAttestationSigningKey) == "" {
			problems = addConfigProblem(problems, "FINDING_ATTESTATION_SIGNING_KEY is required when FINDING_ATTESTATION_ENABLED=true")
		}
		if c.FindingAttestationTimeout <= 0 {
			problems = addConfigProblem(problems, "FINDING_ATTESTATION_TIMEOUT must be > 0 when FINDING_ATTESTATION_ENABLED=true")
		}
	}

	if c.RateLimitEnabled {
		if c.RateLimitRequests <= 0 {
			problems = addConfigProblem(problems, "RATE_LIMIT_REQUESTS must be > 0 when RATE_LIMIT_ENABLED=true")
		}
		if c.RateLimitWindow <= 0 {
			problems = addConfigProblem(problems, "RATE_LIMIT_WINDOW must be > 0 when RATE_LIMIT_ENABLED=true")
		}
	}

	if c.WorkloadScanMaxConcurrentSnapshots <= 0 {
		problems = addConfigProblem(problems, "WORKLOAD_SCAN_MAX_CONCURRENT_SNAPSHOTS must be > 0")
	}
	if c.WorkloadScanCleanupTimeout <= 0 {
		problems = addConfigProblem(problems, "WORKLOAD_SCAN_CLEANUP_TIMEOUT must be > 0")
	}
	if c.WorkloadScanReconcileOlderThan <= 0 {
		problems = addConfigProblem(problems, "WORKLOAD_SCAN_RECONCILE_OLDER_THAN must be > 0")
	}
	if c.ImageScanCleanupTimeout <= 0 {
		problems = addConfigProblem(problems, "IMAGE_SCAN_CLEANUP_TIMEOUT must be > 0")
	}

	if c.GraphCrossTenantRequireSignedIngest {
		if strings.TrimSpace(c.GraphCrossTenantSigningKey) == "" {
			problems = addConfigProblem(problems, "GRAPH_CROSS_TENANT_SIGNING_KEY is required when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true")
		}
		if c.GraphCrossTenantSignatureSkew <= 0 {
			problems = addConfigProblem(problems, "GRAPH_CROSS_TENANT_SIGNATURE_MAX_SKEW must be > 0 when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true")
		}
		if c.GraphCrossTenantReplayTTL <= 0 {
			problems = addConfigProblem(problems, "GRAPH_CROSS_TENANT_REPLAY_TTL must be > 0 when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true")
		}
		if c.GraphCrossTenantMinTenants <= 0 {
			problems = addConfigProblem(problems, "GRAPH_CROSS_TENANT_MIN_TENANTS must be > 0 when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true")
		}
		if c.GraphCrossTenantMinSupport <= 0 {
			problems = addConfigProblem(problems, "GRAPH_CROSS_TENANT_MIN_SUPPORT must be > 0 when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true")
		}
	}

	if c.graphStoreBackend() != graph.StoreBackendNeptune {
		problems = addConfigProblem(problems, "GRAPH_STORE_BACKEND must be neptune")
	}
	if !testProcess && !c.allowMissingGraphStoreEndpoint() && strings.TrimSpace(c.GraphStoreNeptuneEndpoint) == "" {
		problems = addConfigProblem(problems, "GRAPH_STORE_NEPTUNE_ENDPOINT is required when GRAPH_STORE_BACKEND=neptune")
	}
	if c.GraphStoreNeptunePoolSize <= 0 {
		problems = addConfigProblem(problems, "GRAPH_STORE_NEPTUNE_POOL_SIZE must be > 0 when GRAPH_STORE_BACKEND=neptune")
	}
	if c.GraphStoreNeptunePoolHealthCheckInterval < 0 {
		problems = addConfigProblem(problems, "GRAPH_STORE_NEPTUNE_POOL_HEALTHCHECK_INTERVAL must be >= 0 when GRAPH_STORE_BACKEND=neptune")
	}
	if c.GraphStoreNeptunePoolHealthCheckInterval > 0 && c.GraphStoreNeptunePoolHealthCheckTimeout <= 0 {
		problems = addConfigProblem(problems, "GRAPH_STORE_NEPTUNE_POOL_HEALTHCHECK_TIMEOUT must be > 0 when GRAPH_STORE_NEPTUNE_POOL_HEALTHCHECK_INTERVAL>0")
	}
	if c.GraphStoreNeptunePoolMaxClientLifetime < 0 {
		problems = addConfigProblem(problems, "GRAPH_STORE_NEPTUNE_POOL_MAX_CLIENT_LIFETIME must be >= 0 when GRAPH_STORE_BACKEND=neptune")
	}
	if c.GraphStoreNeptunePoolMaxClientUses < 0 {
		problems = addConfigProblem(problems, "GRAPH_STORE_NEPTUNE_POOL_MAX_CLIENT_USES must be >= 0 when GRAPH_STORE_BACKEND=neptune")
	}
	if c.GraphStoreNeptunePoolDrainTimeout <= 0 {
		problems = addConfigProblem(problems, "GRAPH_STORE_NEPTUNE_POOL_DRAIN_TIMEOUT must be > 0 when GRAPH_STORE_BACKEND=neptune")
	}
	switch c.graphSearchBackend() {
	case graph.EntitySearchBackendGraph, graph.EntitySearchBackendOpenSearch:
	default:
		problems = addConfigProblem(problems, "GRAPH_SEARCH_BACKEND must be one of graph, opensearch")
	}
	if c.graphSearchBackend() == graph.EntitySearchBackendOpenSearch {
		if strings.TrimSpace(c.GraphSearchOpenSearchEndpoint) == "" {
			problems = addConfigProblem(problems, "GRAPH_SEARCH_OPENSEARCH_ENDPOINT is required when GRAPH_SEARCH_BACKEND=opensearch")
		}
		if strings.TrimSpace(c.GraphSearchOpenSearchRegion) == "" {
			problems = addConfigProblem(problems, "GRAPH_SEARCH_OPENSEARCH_REGION is required when GRAPH_SEARCH_BACKEND=opensearch")
		}
		if strings.TrimSpace(c.GraphSearchOpenSearchIndex) == "" {
			problems = addConfigProblem(problems, "GRAPH_SEARCH_OPENSEARCH_INDEX is required when GRAPH_SEARCH_BACKEND=opensearch")
		}
	}
	if c.GraphSearchRequestTimeout <= 0 {
		problems = addConfigProblem(problems, "GRAPH_SEARCH_REQUEST_TIMEOUT must be > 0")
	}
	if c.GraphSearchMaxCandidates <= 0 {
		problems = addConfigProblem(problems, "GRAPH_SEARCH_MAX_CANDIDATES must be > 0")
	}
	switch strings.ToLower(strings.TrimSpace(c.GraphSchemaValidationMode)) {
	case "", string(graph.SchemaValidationOff), string(graph.SchemaValidationWarn), string(graph.SchemaValidationEnforce):
	default:
		problems = addConfigProblem(problems, "GRAPH_SCHEMA_VALIDATION_MODE must be one of off, warn, enforce")
	}
	switch graphingest.MapperValidationMode(strings.ToLower(strings.TrimSpace(c.GraphEventMapperValidationMode))) {
	case "", graphingest.MapperValidationWarn, graphingest.MapperValidationEnforce:
	default:
		problems = addConfigProblem(problems, "GRAPH_EVENT_MAPPER_VALIDATION_MODE must be one of warn, enforce")
	}

	problems = normalizeConfigProblems(problems)
	if len(problems) == 0 {
		return nil
	}
	return &ConfigValidationError{Problems: problems}
}
