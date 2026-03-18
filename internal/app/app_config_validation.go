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
		{EnvVars: []string{"LOG_LEVEL"}, Summary: "must be one of debug, info, warn, error", Category: "enum"},
		{EnvVars: []string{"CEREBRO_OTEL_SAMPLE_RATIO"}, Summary: "must be between 0 and 1", Category: "range"},
		{EnvVars: []string{"QUERY_POLICY_ROW_LIMIT"}, Summary: "must be greater than 0", Category: "range"},
		{EnvVars: []string{"CEREBRO_INIT_TIMEOUT"}, Summary: "must be greater than or equal to 0", Category: "range"},
		{EnvVars: []string{"FINDINGS_MAX_IN_MEMORY"}, Summary: "must be greater than or equal to 0", Category: "range"},
		{EnvVars: []string{"FINDINGS_RESOLVED_RETENTION"}, Summary: "must be greater than or equal to 0", Category: "range"},
		{EnvVars: []string{"FINDINGS_SEMANTIC_DEDUP_ENABLED"}, Summary: "enables semantic finding identity across policy/version drift", Category: "behavior"},
		{
			EnvVars:  []string{"SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PRIVATE_KEY"},
			Summary:  "when any Snowflake auth field is set, all three are required",
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
		{EnvVars: []string{"GRAPH_SCHEMA_VALIDATION_MODE"}, Summary: "must be one of off, warn, enforce", Category: "enum"},
		{EnvVars: []string{"GRAPH_EVENT_MAPPER_VALIDATION_MODE"}, Summary: "must be one of warn, enforce", Category: "enum"},
	}
}

func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}

	problems := append([]string(nil), c.loadProblems...)

	if c.Port < 1 || c.Port > 65535 {
		problems = addConfigProblem(problems, "API_PORT must be between 1 and 65535")
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
	if c.FindingsMaxInMemory < 0 {
		problems = addConfigProblem(problems, "FINDINGS_MAX_IN_MEMORY must be >= 0")
	}
	if c.FindingsResolvedRetention < 0 {
		problems = addConfigProblem(problems, "FINDINGS_RESOLVED_RETENTION must be >= 0")
	}

	hasSnowflakeAuth := strings.TrimSpace(c.SnowflakeAccount) != "" ||
		strings.TrimSpace(c.SnowflakeUser) != "" ||
		strings.TrimSpace(c.SnowflakePrivateKey) != ""
	if hasSnowflakeAuth {
		if strings.TrimSpace(c.SnowflakeAccount) == "" {
			problems = addConfigProblem(problems, "SNOWFLAKE_ACCOUNT is required when Snowflake auth is configured")
		}
		if strings.TrimSpace(c.SnowflakeUser) == "" {
			problems = addConfigProblem(problems, "SNOWFLAKE_USER is required when Snowflake auth is configured")
		}
		if strings.TrimSpace(c.SnowflakePrivateKey) == "" {
			problems = addConfigProblem(problems, "SNOWFLAKE_PRIVATE_KEY is required when Snowflake auth is configured")
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
