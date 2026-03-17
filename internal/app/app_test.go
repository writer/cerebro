package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/apiauth"
	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/metrics"
	"github.com/evalops/cerebro/internal/policy"
	"github.com/evalops/cerebro/internal/snowflake"
	"github.com/evalops/cerebro/internal/warehouse"
	dto "github.com/prometheus/client_model/go"
)

func TestLoadConfig(t *testing.T) {
	// Set some env vars
	t.Setenv("API_PORT", "9999")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("RBAC_STATE_FILE", "/tmp/rbac-state.json")
	t.Setenv("SECURITY_DIGEST_INTERVAL", "24h")

	cfg := LoadConfig()

	if cfg.Port != 9999 {
		t.Errorf("expected port 9999, got %d", cfg.Port)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("expected log level debug, got %s", cfg.LogLevel)
	}

	if cfg.RBACStateFile != "/tmp/rbac-state.json" {
		t.Errorf("expected RBAC state file to be set, got %s", cfg.RBACStateFile)
	}

	if cfg.SecurityDigestInterval != "24h" {
		t.Errorf("expected security digest interval 24h, got %s", cfg.SecurityDigestInterval)
	}
}

func TestLoadConfigCredentialFileSourceOverridesSecretsOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "OPENAI_API_KEY"), []byte("file-openai-key\n"), 0o600); err != nil {
		t.Fatalf("write openai secret: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "API_KEYS"), []byte("file-key:file-user\n"), 0o600); err != nil {
		t.Fatalf("write api keys secret: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "LOG_LEVEL"), []byte("debug\n"), 0o600); err != nil {
		t.Fatalf("write log level attempt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "API_AUTH_ENABLED"), []byte("false\n"), 0o600); err != nil {
		t.Fatalf("write api auth attempt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "GRAPH_CROSS_TENANT_SIGNING_KEY"), []byte("file-graph-signing-key\n"), 0o600); err != nil {
		t.Fatalf("write graph signing key attempt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "FINDING_ATTESTATION_SIGNING_KEY"), []byte("file-attestation-signing-key\n"), 0o600); err != nil {
		t.Fatalf("write finding signing key attempt: %v", err)
	}

	t.Setenv("CEREBRO_CREDENTIAL_SOURCE", "file")
	t.Setenv("CEREBRO_CREDENTIAL_FILE_DIR", dir)
	t.Setenv("OPENAI_API_KEY", "env-openai-key")
	t.Setenv("API_KEYS", "env-key:env-user")
	t.Setenv("LOG_LEVEL", "warn")
	t.Setenv("API_AUTH_ENABLED", "true")
	t.Setenv("GRAPH_CROSS_TENANT_SIGNING_KEY", "env-graph-signing-key")
	t.Setenv("FINDING_ATTESTATION_SIGNING_KEY", "env-finding-signing-key")

	cfg := LoadConfig()
	if cfg.CredentialSource != "file" {
		t.Fatalf("expected credential source file, got %q", cfg.CredentialSource)
	}
	if cfg.OpenAIAPIKey != "file-openai-key" {
		t.Fatalf("expected file-backed openai key, got %q", cfg.OpenAIAPIKey)
	}
	if cfg.APIKeys["file-key"] != "file-user" || len(cfg.APIKeys) != 1 {
		t.Fatalf("expected file-backed api key map, got %#v", cfg.APIKeys)
	}
	if cfg.LogLevel != "warn" {
		t.Fatalf("expected non-secret config to continue using env/config, got %q", cfg.LogLevel)
	}
	if !cfg.APIAuthEnabled {
		t.Fatal("expected credential file source to be unable to disable API auth")
	}
	if cfg.GraphCrossTenantSigningKey != "env-graph-signing-key" {
		t.Fatalf("expected graph signing key to remain on raw env/config path, got %q", cfg.GraphCrossTenantSigningKey)
	}
	if cfg.FindingAttestationSigningKey != "env-finding-signing-key" {
		t.Fatalf("expected finding attestation signing key to remain on raw env/config path, got %q", cfg.FindingAttestationSigningKey)
	}
}

func TestLoadConfigCredentialVaultSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secret/data/cerebro" {
			t.Fatalf("unexpected vault path %q", r.URL.Path)
		}
		if got := r.Header.Get("X-Vault-Token"); got != "bootstrap-token" {
			t.Fatalf("unexpected vault token %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"data":{"OPENAI_API_KEY":"vault-openai-key","API_CREDENTIALS_JSON":[{"key":"vault-key","user_id":"vault-user"}],"LOG_LEVEL":"debug","API_AUTH_ENABLED":"false"}}}`)
	}))
	defer server.Close()

	t.Setenv("CEREBRO_CREDENTIAL_SOURCE", "vault")
	t.Setenv("CEREBRO_CREDENTIAL_VAULT_ADDRESS", server.URL)
	t.Setenv("CEREBRO_CREDENTIAL_VAULT_TOKEN", "bootstrap-token")
	t.Setenv("CEREBRO_CREDENTIAL_VAULT_PATH", "secret/cerebro")
	t.Setenv("CEREBRO_CREDENTIAL_VAULT_KV_VERSION", "2")
	t.Setenv("LOG_LEVEL", "error")
	t.Setenv("API_AUTH_ENABLED", "true")

	cfg := LoadConfig()
	if cfg.CredentialSource != "vault" {
		t.Fatalf("expected credential source vault, got %q", cfg.CredentialSource)
	}
	if cfg.OpenAIAPIKey != "vault-openai-key" {
		t.Fatalf("expected vault-backed openai key, got %q", cfg.OpenAIAPIKey)
	}
	if cfg.APIKeys["vault-key"] != "vault-user" || len(cfg.APIKeys) != 1 {
		t.Fatalf("expected vault-backed api credentials, got %#v", cfg.APIKeys)
	}
	if cfg.LogLevel != "error" {
		t.Fatalf("expected non-secret env config to survive vault credential source, got %q", cfg.LogLevel)
	}
	if !cfg.APIAuthEnabled {
		t.Fatal("expected vault credential source to be unable to disable API auth")
	}
}

func TestLoadConfigCredentialSourceValidation(t *testing.T) {
	t.Setenv("CEREBRO_CREDENTIAL_SOURCE", "vault")
	cfg := LoadConfig()

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for incomplete vault credential source")
	}
	if !strings.Contains(err.Error(), "CEREBRO_CREDENTIAL_VAULT_ADDRESS is required") {
		t.Fatalf("expected vault address validation failure, got %v", err)
	}
}

func TestLoadConfigCrossTenantIngestControls(t *testing.T) {
	t.Setenv("GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST", "true")
	t.Setenv("GRAPH_CROSS_TENANT_SIGNING_KEY", "test-signing-key")
	t.Setenv("GRAPH_CROSS_TENANT_SIGNATURE_MAX_SKEW", "7m")
	t.Setenv("GRAPH_CROSS_TENANT_REPLAY_TTL", "2h")
	t.Setenv("GRAPH_CROSS_TENANT_MIN_TENANTS", "4")
	t.Setenv("GRAPH_CROSS_TENANT_MIN_SUPPORT", "5")

	cfg := LoadConfig()
	if !cfg.GraphCrossTenantRequireSignedIngest {
		t.Fatal("expected signed ingest requirement to be enabled")
	}
	if cfg.GraphCrossTenantSigningKey != "test-signing-key" {
		t.Fatalf("expected graph signing key to be set, got %q", cfg.GraphCrossTenantSigningKey)
	}
	if cfg.GraphCrossTenantSignatureSkew != 7*time.Minute {
		t.Fatalf("expected signature skew 7m, got %v", cfg.GraphCrossTenantSignatureSkew)
	}
	if cfg.GraphCrossTenantReplayTTL != 2*time.Hour {
		t.Fatalf("expected replay ttl 2h, got %v", cfg.GraphCrossTenantReplayTTL)
	}
	if cfg.GraphCrossTenantMinTenants != 4 {
		t.Fatalf("expected min tenants 4, got %d", cfg.GraphCrossTenantMinTenants)
	}
	if cfg.GraphCrossTenantMinSupport != 5 {
		t.Fatalf("expected min support 5, got %d", cfg.GraphCrossTenantMinSupport)
	}
}

func TestLoadConfigPlatformReportPersistencePaths(t *testing.T) {
	t.Setenv("PLATFORM_REPORT_RUN_STATE_FILE", "/tmp/cerebro-report-runs.json")
	t.Setenv("PLATFORM_REPORT_SNAPSHOT_PATH", "/tmp/cerebro-report-snapshots")

	cfg := LoadConfig()
	if cfg.PlatformReportRunStateFile != "/tmp/cerebro-report-runs.json" {
		t.Fatalf("expected report run state file to be set, got %q", cfg.PlatformReportRunStateFile)
	}
	if cfg.PlatformReportSnapshotPath != "/tmp/cerebro-report-snapshots" {
		t.Fatalf("expected report snapshot path to be set, got %q", cfg.PlatformReportSnapshotPath)
	}
}

func TestLoadConfigWorkloadScanPathsAndControls(t *testing.T) {
	t.Setenv("EXECUTION_STORE_FILE", "/tmp/cerebro-executions.db")
	t.Setenv("WORKLOAD_SCAN_STATE_FILE", "/tmp/cerebro-workload-scan.db")
	t.Setenv("WORKLOAD_SCAN_MOUNT_BASE_PATH", "/tmp/cerebro-workload-mounts")
	t.Setenv("WORKLOAD_SCAN_MAX_CONCURRENT_SNAPSHOTS", "7")
	t.Setenv("WORKLOAD_SCAN_CLEANUP_TIMEOUT", "4m")
	t.Setenv("WORKLOAD_SCAN_RECONCILE_OLDER_THAN", "45m")
	t.Setenv("WORKLOAD_SCAN_TRIVY_BINARY", "/usr/local/bin/trivy-workload")
	t.Setenv("WORKLOAD_SCAN_GITLEAKS_BINARY", "/usr/local/bin/gitleaks-workload")
	t.Setenv("WORKLOAD_SCAN_CLAMAV_BINARY", "/usr/local/bin/clamscan-workload")

	cfg := LoadConfig()
	if cfg.ExecutionStoreFile != "/tmp/cerebro-executions.db" {
		t.Fatalf("expected execution store file to be set, got %q", cfg.ExecutionStoreFile)
	}
	if cfg.WorkloadScanStateFile != "/tmp/cerebro-workload-scan.db" {
		t.Fatalf("expected workload scan state file to be set, got %q", cfg.WorkloadScanStateFile)
	}
	if cfg.WorkloadScanMountBasePath != "/tmp/cerebro-workload-mounts" {
		t.Fatalf("expected workload scan mount base path to be set, got %q", cfg.WorkloadScanMountBasePath)
	}
	if cfg.WorkloadScanMaxConcurrentSnapshots != 7 {
		t.Fatalf("expected workload scan max concurrent snapshots 7, got %d", cfg.WorkloadScanMaxConcurrentSnapshots)
	}
	if cfg.WorkloadScanCleanupTimeout != 4*time.Minute {
		t.Fatalf("expected workload scan cleanup timeout 4m, got %s", cfg.WorkloadScanCleanupTimeout)
	}
	if cfg.WorkloadScanReconcileOlderThan != 45*time.Minute {
		t.Fatalf("expected workload scan reconcile older than 45m, got %s", cfg.WorkloadScanReconcileOlderThan)
	}
	if cfg.WorkloadScanTrivyBinary != "/usr/local/bin/trivy-workload" {
		t.Fatalf("expected workload scan trivy binary override, got %q", cfg.WorkloadScanTrivyBinary)
	}
	if cfg.WorkloadScanGitleaksBinary != "/usr/local/bin/gitleaks-workload" {
		t.Fatalf("expected workload scan gitleaks binary override, got %q", cfg.WorkloadScanGitleaksBinary)
	}
	if cfg.WorkloadScanClamAVBinary != "/usr/local/bin/clamscan-workload" {
		t.Fatalf("expected workload scan clamav binary override, got %q", cfg.WorkloadScanClamAVBinary)
	}
}

func TestLoadConfigMalwareScannerControls(t *testing.T) {
	t.Setenv("MALWARE_SCAN_CLAMAV_HOST", "clamav.internal")
	t.Setenv("MALWARE_SCAN_CLAMAV_PORT", "3310")
	t.Setenv("MALWARE_SCAN_VIRUSTOTAL_API_KEY", "vt-test-key")

	cfg := LoadConfig()
	if cfg.MalwareScanClamAVHost != "clamav.internal" {
		t.Fatalf("expected malware scan clamd host override, got %q", cfg.MalwareScanClamAVHost)
	}
	if cfg.MalwareScanClamAVPort != 3310 {
		t.Fatalf("expected malware scan clamd port override, got %d", cfg.MalwareScanClamAVPort)
	}
	if cfg.MalwareScanVirusTotalAPIKey != "vt-test-key" {
		t.Fatalf("expected malware scan vt api key override, got %q", cfg.MalwareScanVirusTotalAPIKey)
	}
}

func TestLoadConfigImageScanPathsAndControls(t *testing.T) {
	t.Setenv("EXECUTION_STORE_FILE", "/tmp/cerebro-executions.db")
	t.Setenv("IMAGE_SCAN_ROOTFS_BASE_PATH", "/tmp/cerebro-image-rootfs")
	t.Setenv("IMAGE_SCAN_CLEANUP_TIMEOUT", "5m")
	t.Setenv("IMAGE_SCAN_TRIVY_BINARY", "/usr/local/bin/trivy")
	t.Setenv("IMAGE_SCAN_GITLEAKS_BINARY", "/usr/local/bin/gitleaks-image")
	t.Setenv("IMAGE_SCAN_CLAMAV_BINARY", "/usr/local/bin/clamscan-image")

	cfg := LoadConfig()
	if cfg.ImageScanStateFile != "/tmp/cerebro-executions.db" {
		t.Fatalf("expected image scan state file to default to shared execution store, got %q", cfg.ImageScanStateFile)
	}
	if cfg.ImageScanRootFSBasePath != "/tmp/cerebro-image-rootfs" {
		t.Fatalf("expected image scan rootfs base path to be set, got %q", cfg.ImageScanRootFSBasePath)
	}
	if cfg.ImageScanCleanupTimeout != 5*time.Minute {
		t.Fatalf("expected image scan cleanup timeout 5m, got %s", cfg.ImageScanCleanupTimeout)
	}
	if cfg.ImageScanTrivyBinary != "/usr/local/bin/trivy" {
		t.Fatalf("expected image scan trivy binary override, got %q", cfg.ImageScanTrivyBinary)
	}
	if cfg.ImageScanGitleaksBinary != "/usr/local/bin/gitleaks-image" {
		t.Fatalf("expected image scan gitleaks binary override, got %q", cfg.ImageScanGitleaksBinary)
	}
	if cfg.ImageScanClamAVBinary != "/usr/local/bin/clamscan-image" {
		t.Fatalf("expected image scan clamav binary override, got %q", cfg.ImageScanClamAVBinary)
	}
}

func TestLoadConfigFunctionScanPathsAndControls(t *testing.T) {
	t.Setenv("EXECUTION_STORE_FILE", "/tmp/cerebro-executions.db")
	t.Setenv("FUNCTION_SCAN_ROOTFS_BASE_PATH", "/tmp/cerebro-function-rootfs")
	t.Setenv("FUNCTION_SCAN_CLEANUP_TIMEOUT", "6m")
	t.Setenv("FUNCTION_SCAN_TRIVY_BINARY", "/usr/local/bin/trivy-function")
	t.Setenv("FUNCTION_SCAN_GITLEAKS_BINARY", "/usr/local/bin/gitleaks-function")
	t.Setenv("FUNCTION_SCAN_CLAMAV_BINARY", "/usr/local/bin/clamscan-function")

	cfg := LoadConfig()
	if cfg.FunctionScanStateFile != "/tmp/cerebro-executions.db" {
		t.Fatalf("expected function scan state file to default to shared execution store, got %q", cfg.FunctionScanStateFile)
	}
	if cfg.FunctionScanRootFSBasePath != "/tmp/cerebro-function-rootfs" {
		t.Fatalf("expected function scan rootfs base path to be set, got %q", cfg.FunctionScanRootFSBasePath)
	}
	if cfg.FunctionScanCleanupTimeout != 6*time.Minute {
		t.Fatalf("expected function scan cleanup timeout 6m, got %s", cfg.FunctionScanCleanupTimeout)
	}
	if cfg.FunctionScanTrivyBinary != "/usr/local/bin/trivy-function" {
		t.Fatalf("expected function scan trivy binary override, got %q", cfg.FunctionScanTrivyBinary)
	}
	if cfg.FunctionScanGitleaksBinary != "/usr/local/bin/gitleaks-function" {
		t.Fatalf("expected function scan gitleaks binary override, got %q", cfg.FunctionScanGitleaksBinary)
	}
	if cfg.FunctionScanClamAVBinary != "/usr/local/bin/clamscan-function" {
		t.Fatalf("expected function scan clamav binary override, got %q", cfg.FunctionScanClamAVBinary)
	}
}

func TestLoadConfigGraphSchemaValidationMode(t *testing.T) {
	t.Setenv("GRAPH_SCHEMA_VALIDATION_MODE", "enforce")
	cfg := LoadConfig()
	if cfg.GraphSchemaValidationMode != "enforce" {
		t.Fatalf("expected graph schema validation mode enforce, got %q", cfg.GraphSchemaValidationMode)
	}
}

func TestLoadConfigGraphPropertyHistoryControls(t *testing.T) {
	t.Setenv("GRAPH_PROPERTY_HISTORY_MAX_ENTRIES", "17")
	t.Setenv("GRAPH_PROPERTY_HISTORY_TTL", "36h")

	cfg := LoadConfig()
	if cfg.GraphPropertyHistoryMaxEntries != 17 {
		t.Fatalf("expected graph property history max entries 17, got %d", cfg.GraphPropertyHistoryMaxEntries)
	}
	if cfg.GraphPropertyHistoryTTL != 36*time.Hour {
		t.Fatalf("expected graph property history ttl 36h, got %s", cfg.GraphPropertyHistoryTTL)
	}
}

func TestLoadConfigGraphTenantShardControls(t *testing.T) {
	t.Setenv("GRAPH_TENANT_SHARD_IDLE_TTL", "27m")
	t.Setenv("GRAPH_TENANT_WARM_SHARD_TTL", "3h")
	t.Setenv("GRAPH_TENANT_WARM_SHARD_MAX_RETAINED", "2")

	cfg := LoadConfig()
	if cfg.GraphTenantShardIdleTTL != 27*time.Minute {
		t.Fatalf("expected graph tenant shard idle ttl 27m, got %s", cfg.GraphTenantShardIdleTTL)
	}
	if cfg.GraphTenantWarmShardTTL != 3*time.Hour {
		t.Fatalf("expected graph tenant warm shard ttl 3h, got %s", cfg.GraphTenantWarmShardTTL)
	}
	if cfg.GraphTenantWarmShardMaxRetained != 2 {
		t.Fatalf("expected graph tenant warm shard max retained 2, got %d", cfg.GraphTenantWarmShardMaxRetained)
	}
}

func TestLoadConfigGraphEventMapperControls(t *testing.T) {
	t.Setenv("GRAPH_EVENT_MAPPER_VALIDATION_MODE", "warn")
	t.Setenv("GRAPH_EVENT_MAPPER_DEAD_LETTER_PATH", "/tmp/test-graph-mapper.dlq.jsonl")
	t.Setenv("GRAPH_MIGRATE_LEGACY_ACTIVITY_ON_START", "true")
	cfg := LoadConfig()
	if cfg.GraphEventMapperValidationMode != "warn" {
		t.Fatalf("expected graph event mapper validation mode warn, got %q", cfg.GraphEventMapperValidationMode)
	}
	if cfg.GraphEventMapperDeadLetterPath != "/tmp/test-graph-mapper.dlq.jsonl" {
		t.Fatalf("expected graph event mapper dead-letter path to be set, got %q", cfg.GraphEventMapperDeadLetterPath)
	}
	if !cfg.GraphMigrateLegacyActivityOnStart {
		t.Fatal("expected graph legacy activity migration on start to be enabled")
	}
}

func TestLoadConfigNATSConsumerControls(t *testing.T) {
	t.Setenv("NATS_CONSUMER_DEAD_LETTER_PATH", "/tmp/test-nats-consumer.dlq.jsonl")
	t.Setenv("NATS_CONSUMER_DROP_HEALTH_LOOKBACK", "7m")
	t.Setenv("NATS_CONSUMER_DROP_HEALTH_THRESHOLD", "3")
	t.Setenv("NATS_CONSUMER_IN_PROGRESS_INTERVAL", "11s")
	t.Setenv("NATS_CONSUMER_DRAIN_TIMEOUT", "41s")
	t.Setenv("NATS_CONSUMER_GRAPH_STALENESS_THRESHOLD", "19m")
	t.Setenv("CEREBRO_INIT_TIMEOUT", "95s")

	cfg := LoadConfig()
	if cfg.NATSConsumerDeadLetterPath != "/tmp/test-nats-consumer.dlq.jsonl" {
		t.Fatalf("expected nats consumer dead-letter path to be set, got %q", cfg.NATSConsumerDeadLetterPath)
	}
	if cfg.NATSConsumerDropHealthLookback != 7*time.Minute {
		t.Fatalf("expected nats consumer drop health lookback 7m, got %s", cfg.NATSConsumerDropHealthLookback)
	}
	if cfg.NATSConsumerDropHealthThreshold != 3 {
		t.Fatalf("expected nats consumer drop health threshold 3, got %d", cfg.NATSConsumerDropHealthThreshold)
	}
	if cfg.NATSConsumerInProgressInterval != 11*time.Second {
		t.Fatalf("expected nats consumer in-progress interval 11s, got %s", cfg.NATSConsumerInProgressInterval)
	}
	if cfg.NATSConsumerDrainTimeout != 41*time.Second {
		t.Fatalf("expected nats consumer drain timeout 41s, got %s", cfg.NATSConsumerDrainTimeout)
	}
	if cfg.NATSConsumerGraphStalenessThreshold != 19*time.Minute {
		t.Fatalf("expected nats consumer graph staleness threshold 19m, got %s", cfg.NATSConsumerGraphStalenessThreshold)
	}
	if cfg.InitTimeout != 95*time.Second {
		t.Fatalf("expected init timeout 95s, got %s", cfg.InitTimeout)
	}
}

func TestLoadConfigNATSConsumerZeroDropHealthThreshold(t *testing.T) {
	t.Setenv("NATS_CONSUMER_DROP_HEALTH_THRESHOLD", "0")
	cfg := LoadConfig()
	if cfg.NATSConsumerDropHealthThreshold != 0 {
		t.Fatalf("expected nats consumer drop health threshold 0, got %d", cfg.NATSConsumerDropHealthThreshold)
	}
}

func TestLoadConfigGraphOntologySLOThresholds(t *testing.T) {
	t.Setenv("GRAPH_ONTOLOGY_FALLBACK_WARN_PERCENT", "14.5")
	t.Setenv("GRAPH_ONTOLOGY_FALLBACK_CRITICAL_PERCENT", "31")
	t.Setenv("GRAPH_ONTOLOGY_SCHEMA_VALID_WARN_PERCENT", "97.2")
	t.Setenv("GRAPH_ONTOLOGY_SCHEMA_VALID_CRITICAL_PERCENT", "90")

	cfg := LoadConfig()
	if cfg.GraphOntologyFallbackWarnPct != 14.5 {
		t.Fatalf("expected fallback warn percent 14.5, got %v", cfg.GraphOntologyFallbackWarnPct)
	}
	if cfg.GraphOntologyFallbackCriticalPct != 31 {
		t.Fatalf("expected fallback critical percent 31, got %v", cfg.GraphOntologyFallbackCriticalPct)
	}
	if cfg.GraphOntologySchemaValidWarnPct != 97.2 {
		t.Fatalf("expected schema valid warn percent 97.2, got %v", cfg.GraphOntologySchemaValidWarnPct)
	}
	if cfg.GraphOntologySchemaValidCriticalPct != 90 {
		t.Fatalf("expected schema valid critical percent 90, got %v", cfg.GraphOntologySchemaValidCriticalPct)
	}
}

func TestLoadConfigRetention(t *testing.T) {
	t.Setenv("CEREBRO_AUDIT_RETENTION_DAYS", "45")
	t.Setenv("CEREBRO_SESSION_RETENTION_DAYS", "21")
	t.Setenv("CEREBRO_GRAPH_RETENTION_DAYS", "14")
	t.Setenv("CEREBRO_ACCESS_REVIEW_RETENTION_DAYS", "90")
	t.Setenv("CEREBRO_RETENTION_JOB_INTERVAL", "2h")

	cfg := LoadConfig()

	if cfg.AuditRetentionDays != 45 {
		t.Fatalf("expected audit retention days 45, got %d", cfg.AuditRetentionDays)
	}
	if cfg.SessionRetentionDays != 21 {
		t.Fatalf("expected session retention days 21, got %d", cfg.SessionRetentionDays)
	}
	if cfg.GraphRetentionDays != 14 {
		t.Fatalf("expected graph retention days 14, got %d", cfg.GraphRetentionDays)
	}
	if cfg.AccessReviewRetentionDays != 90 {
		t.Fatalf("expected access review retention days 90, got %d", cfg.AccessReviewRetentionDays)
	}
	if cfg.RetentionJobInterval != 2*time.Hour {
		t.Fatalf("expected retention job interval 2h, got %v", cfg.RetentionJobInterval)
	}
}

func TestLoadConfigRetentionDefaults(t *testing.T) {
	cfg := LoadConfig()
	if cfg.AuditRetentionDays != 90 {
		t.Fatalf("expected audit retention default 90, got %d", cfg.AuditRetentionDays)
	}
	if cfg.SessionRetentionDays != 30 {
		t.Fatalf("expected session retention default 30, got %d", cfg.SessionRetentionDays)
	}
	if cfg.GraphRetentionDays != 180 {
		t.Fatalf("expected graph retention default 180, got %d", cfg.GraphRetentionDays)
	}
	if cfg.AccessReviewRetentionDays != 365 {
		t.Fatalf("expected access review retention default 365, got %d", cfg.AccessReviewRetentionDays)
	}
	if cfg.NATSConsumerAckWait != 120*time.Second {
		t.Fatalf("expected nats consumer ack wait default 120s, got %s", cfg.NATSConsumerAckWait)
	}
}

func TestLoadConfigTracing(t *testing.T) {
	t.Setenv("CEREBRO_OTEL_ENABLED", "true")
	t.Setenv("CEREBRO_OTEL_SERVICE_NAME", "cerebro-test")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4318")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_INSECURE", "true")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_HEADERS", "x-api-key=abc123,env=dev")
	t.Setenv("CEREBRO_OTEL_SAMPLE_RATIO", "0.5")
	t.Setenv("CEREBRO_OTEL_EXPORT_TIMEOUT", "4s")

	cfg := LoadConfig()
	if !cfg.TracingEnabled {
		t.Fatal("expected tracing to be enabled")
	}
	if cfg.TracingServiceName != "cerebro-test" {
		t.Fatalf("expected tracing service name cerebro-test, got %q", cfg.TracingServiceName)
	}
	if cfg.TracingOTLPEndpoint != "localhost:4318" {
		t.Fatalf("expected tracing endpoint localhost:4318, got %q", cfg.TracingOTLPEndpoint)
	}
	if !cfg.TracingOTLPInsecure {
		t.Fatal("expected tracing OTLP insecure to be true")
	}
	if cfg.TracingSampleRatio != 0.5 {
		t.Fatalf("expected tracing sample ratio 0.5, got %v", cfg.TracingSampleRatio)
	}
	if cfg.TracingExportTimeout != 4*time.Second {
		t.Fatalf("expected tracing export timeout 4s, got %v", cfg.TracingExportTimeout)
	}
	if cfg.TracingOTLPHeaders["x-api-key"] != "abc123" || cfg.TracingOTLPHeaders["env"] != "dev" {
		t.Fatalf("unexpected tracing headers: %#v", cfg.TracingOTLPHeaders)
	}
}

func TestLoadConfigSecretsReloadInterval(t *testing.T) {
	t.Setenv("CEREBRO_SECRETS_RELOAD_INTERVAL", "90s")

	cfg := LoadConfig()
	if cfg.SecretsReloadInterval != 90*time.Second {
		t.Fatalf("expected secrets reload interval 90s, got %v", cfg.SecretsReloadInterval)
	}
}

func TestLoadConfig_ConfigFileFallback(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "cerebro.yaml")
	configBody := `
api:
  port: 9191
log_level: warn
snowflake:
  database: FILE_DB
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	t.Setenv("CEREBRO_CONFIG_FILE", configPath)
	t.Setenv("CEREBRO_CONFIG_ROOT", filepath.Dir(configPath))
	t.Setenv("API_PORT", "")
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("SNOWFLAKE_DATABASE", "")

	cfg := LoadConfig()

	if cfg.Port != 9191 {
		t.Fatalf("expected API_PORT from config file, got %d", cfg.Port)
	}
	if cfg.LogLevel != "warn" {
		t.Fatalf("expected LOG_LEVEL from config file, got %q", cfg.LogLevel)
	}
	if cfg.SnowflakeDatabase != "FILE_DB" {
		t.Fatalf("expected SNOWFLAKE_DATABASE from config file, got %q", cfg.SnowflakeDatabase)
	}
}

func TestLoadConfig_ConfigFileRespectsEnvOverride(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "cerebro.toml")
	configBody := `API_PORT = 9191
LOG_LEVEL = "warn"
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	t.Setenv("CEREBRO_CONFIG_FILE", configPath)
	t.Setenv("CEREBRO_CONFIG_ROOT", filepath.Dir(configPath))
	t.Setenv("API_PORT", "9292")
	t.Setenv("LOG_LEVEL", "error")

	cfg := LoadConfig()

	if cfg.Port != 9292 {
		t.Fatalf("expected env API_PORT to override config file, got %d", cfg.Port)
	}
	if cfg.LogLevel != "error" {
		t.Fatalf("expected env LOG_LEVEL to override config file, got %q", cfg.LogLevel)
	}
}

func TestLoadConfigWebhookURLs(t *testing.T) {
	t.Setenv("WEBHOOK_URLS", "https://example.com/hook1, https://example.com/hook2")

	cfg := LoadConfig()

	expected := []string{"https://example.com/hook1", "https://example.com/hook2"}
	if !reflect.DeepEqual(cfg.WebhookURLs, expected) {
		t.Fatalf("expected webhook URLs %v, got %v", expected, cfg.WebhookURLs)
	}
}

func TestLoadConfigCORSAllowedOrigins(t *testing.T) {
	t.Setenv("API_CORS_ALLOWED_ORIGINS", "https://app.example.com, https://admin.example.com")

	cfg := LoadConfig()

	expected := []string{"https://app.example.com", "https://admin.example.com"}
	if !reflect.DeepEqual(cfg.CORSAllowedOrigins, expected) {
		t.Fatalf("expected CORS origins %v, got %v", expected, cfg.CORSAllowedOrigins)
	}
}

func TestLoadConfigQueryPolicyRowLimit(t *testing.T) {
	t.Setenv("QUERY_POLICY_ROW_LIMIT", "321")

	cfg := LoadConfig()
	if cfg.QueryPolicyRowLimit != 321 {
		t.Fatalf("expected query policy row limit 321, got %d", cfg.QueryPolicyRowLimit)
	}
}

func TestLoadConfigJiraCloseTransitions(t *testing.T) {
	t.Setenv("JIRA_CLOSE_TRANSITIONS", "Done, Closed, Resolve Issue")

	cfg := LoadConfig()

	expected := []string{"Done", "Closed", "Resolve Issue"}
	if !reflect.DeepEqual(cfg.JiraCloseTransitions, expected) {
		t.Fatalf("expected Jira close transitions %v, got %v", expected, cfg.JiraCloseTransitions)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear any env vars that might affect defaults
	t.Setenv("API_PORT", "")
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("WAREHOUSE_BACKEND", "")
	t.Setenv("SNOWFLAKE_SCHEMA", "")
	t.Setenv("SNOWFLAKE_DATABASE", "")
	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")

	cfg := LoadConfig()

	if cfg.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Port)
	}

	if cfg.LogLevel != "info" {
		t.Errorf("expected default log level info, got %s", cfg.LogLevel)
	}

	if cfg.SnowflakeDatabase != "CEREBRO" {
		t.Errorf("expected default database CEREBRO, got %s", cfg.SnowflakeDatabase)
	}

	if cfg.SnowflakeSchema != "CEREBRO" {
		t.Errorf("expected default schema CEREBRO, got %s", cfg.SnowflakeSchema)
	}
	if cfg.WarehouseBackend != "sqlite" {
		t.Errorf("expected default warehouse backend sqlite without Snowflake auth, got %s", cfg.WarehouseBackend)
	}
	if cfg.WarehouseSQLitePath == "" {
		t.Error("expected default sqlite warehouse path to be set")
	}
}

func TestLoadConfig_DefaultsToSnowflakeBackendWhenAuthPresent(t *testing.T) {
	t.Setenv("WAREHOUSE_BACKEND", "")
	t.Setenv("SNOWFLAKE_ACCOUNT", "acct")
	t.Setenv("SNOWFLAKE_USER", "user")
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----")

	cfg := LoadConfig()
	if cfg.WarehouseBackend != "snowflake" {
		t.Fatalf("expected snowflake warehouse backend with auth present, got %q", cfg.WarehouseBackend)
	}
}

func TestNew_APIAuthEnabledWithoutKeys(t *testing.T) {
	t.Setenv("API_AUTH_ENABLED", "true")
	t.Setenv("API_KEYS", "")

	ctx := context.Background()
	_, err := New(ctx)
	if err == nil {
		t.Fatal("expected error when API auth enabled without API_KEYS")
	}
}

func TestNewWithConfig_APIAuthEnabledWithoutKeys(t *testing.T) {
	cfg := LoadConfig()
	cfg.APIAuthEnabled = true
	cfg.APIKeys = nil
	cfg.APICredentials = map[string]apiauth.Credential{}

	_, err := NewWithConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error when API auth enabled without API_KEYS")
	}
}

func TestLoadConfigValidateAggregatesProblems(t *testing.T) {
	t.Setenv("API_PORT", "not-a-port")
	t.Setenv("API_CREDENTIALS_JSON", "{")
	t.Setenv("QUERY_POLICY_ROW_LIMIT", "0")
	t.Setenv("NATS_CONSUMER_ENABLED", "true")
	t.Setenv("NATS_JETSTREAM_ENABLED", "false")
	t.Setenv("GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST", "true")
	t.Setenv("GRAPH_TENANT_SHARD_IDLE_TTL", "-1s")
	t.Setenv("GRAPH_TENANT_WARM_SHARD_TTL", "-1s")
	t.Setenv("GRAPH_TENANT_WARM_SHARD_MAX_RETAINED", "0")
	t.Setenv("GRAPH_PROPERTY_HISTORY_MAX_ENTRIES", "-1")
	t.Setenv("GRAPH_PROPERTY_HISTORY_TTL", "-1s")

	cfg := LoadConfig()
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected config validation error")
	}

	var validationErr *ConfigValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ConfigValidationError, got %T", err)
	}

	wantProblems := []string{
		"API_PORT must be a valid integer",
		"decode API_CREDENTIALS_JSON:",
		"QUERY_POLICY_ROW_LIMIT must be greater than 0",
		"NATS_JETSTREAM_ENABLED must be true when NATS_CONSUMER_ENABLED=true",
		"GRAPH_CROSS_TENANT_SIGNING_KEY is required when GRAPH_CROSS_TENANT_REQUIRE_SIGNED_INGEST=true",
		"GRAPH_TENANT_SHARD_IDLE_TTL must be > 0",
		"GRAPH_TENANT_WARM_SHARD_TTL must be > 0",
		"GRAPH_TENANT_WARM_SHARD_MAX_RETAINED must be > 0",
		"GRAPH_PROPERTY_HISTORY_MAX_ENTRIES must be >= 0",
		"GRAPH_PROPERTY_HISTORY_TTL must be >= 0",
	}
	for _, want := range wantProblems {
		found := false
		for _, problem := range validationErr.Problems {
			if strings.Contains(problem, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected validation problem containing %q, got %#v", want, validationErr.Problems)
		}
	}
}

func TestConfigureGraphRuntimeBehaviorAppliesPropertyHistoryConfig(t *testing.T) {
	metrics.Register()

	application := &App{
		Config: &Config{
			GraphSchemaValidationMode:      "enforce",
			GraphPropertyHistoryMaxEntries: 17,
			GraphPropertyHistoryTTL:        3 * time.Hour,
		},
	}
	g := graph.New()

	application.configureGraphRuntimeBehavior(g)

	if g.SchemaValidationMode() != graph.SchemaValidationEnforce {
		t.Fatalf("expected graph schema validation enforce, got %q", g.SchemaValidationMode())
	}
	maxEntries, ttl := g.TemporalHistoryConfig()
	if maxEntries != 17 {
		t.Fatalf("expected graph property history max entries 17, got %d", maxEntries)
	}
	if ttl != 3*time.Hour {
		t.Fatalf("expected graph property history ttl 3h, got %s", ttl)
	}
	if got := gaugeValue(t, metrics.GraphPropertyHistoryDepth); got != 17 {
		t.Fatalf("expected graph property history depth gauge 17, got %v", got)
	}
}

func gaugeValue(t *testing.T, gauge interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var metric dto.Metric
	if err := gauge.Write(&metric); err != nil {
		t.Fatalf("write gauge metric: %v", err)
	}
	return metric.GetGauge().GetValue()
}

func TestNewWithConfigFailsFastOnInvalidConfig(t *testing.T) {
	cfg := LoadConfig()
	cfg.Port = 0
	cfg.QueryPolicyRowLimit = 0

	_, err := NewWithConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected config validation error")
	}
	if !strings.Contains(err.Error(), "API_PORT must be between 1 and 65535") {
		t.Fatalf("expected port validation error, got %v", err)
	}
	if !strings.Contains(err.Error(), "QUERY_POLICY_ROW_LIMIT must be greater than 0") {
		t.Fatalf("expected query row limit validation error, got %v", err)
	}
}

func TestNewWithConfig_UsesProvidedPoliciesPath(t *testing.T) {
	t.Setenv("CEDAR_POLICIES_PATH", filepath.Join(t.TempDir(), "missing-policies"))

	cfg := LoadConfig()
	policiesPath := "policies"
	if _, err := os.Stat(policiesPath); err != nil {
		policiesPath = filepath.Join("..", "..", "policies")
	}
	cfg.PoliciesPath = policiesPath
	cfg.APIAuthEnabled = false
	cfg.APIKeys = nil

	app, err := NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewWithConfig() failed: %v", err)
	}
	defer func() {
		if closeErr := app.Close(); closeErr != nil {
			t.Fatalf("Close() failed: %v", closeErr)
		}
	}()

	if app.Config.PoliciesPath != policiesPath {
		t.Fatalf("expected policies path %q, got %q", policiesPath, app.Config.PoliciesPath)
	}
}

func TestNew_WithoutSnowflake(t *testing.T) {
	// Clear snowflake config to test initialization without it
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")
	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")

	ctx := context.Background()
	app, err := New(ctx)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		if closeErr := app.Close(); closeErr != nil {
			t.Fatalf("Close() failed: %v", closeErr)
		}
	}()

	// Core services should be initialized
	if app.Policy == nil {
		t.Error("Policy engine should be initialized")
	}

	if app.Findings == nil {
		t.Error("Findings store should be initialized")
	}

	if app.Scanner == nil {
		t.Error("Scanner should be initialized")
	}

	if app.Cache == nil {
		t.Error("Cache should be initialized")
	}

	// Feature services should be initialized
	if app.Agents == nil {
		t.Error("Agents should be initialized")
	}

	if app.Ticketing == nil {
		t.Error("Ticketing should be initialized")
	}

	if app.Identity == nil {
		t.Error("Identity should be initialized")
	}

	if app.AttackPath == nil {
		t.Error("AttackPath should be initialized")
	}

	if app.Providers == nil {
		t.Error("Providers should be initialized")
	}

	if app.Webhooks == nil {
		t.Error("Webhooks should be initialized")
	}

	if app.Notifications == nil {
		t.Error("Notifications should be initialized")
	}

	if app.Scheduler == nil {
		t.Error("Scheduler should be initialized")
	}

	// New services should be initialized
	if app.RBAC == nil {
		t.Error("RBAC should be initialized")
	}

	if app.ThreatIntel == nil {
		t.Error("ThreatIntel should be initialized")
	}

	if app.Health == nil {
		t.Error("Health should be initialized")
	}

	if app.Lineage == nil {
		t.Error("Lineage should be initialized")
	}

	if app.Remediation == nil {
		t.Error("Remediation should be initialized")
	}

	if app.RuntimeDetect == nil {
		t.Error("RuntimeDetect should be initialized")
	}

	if app.RuntimeIngest == nil {
		t.Error("RuntimeIngest should be initialized")
	}

	if app.RuntimeRespond == nil {
		t.Error("RuntimeRespond should be initialized")
	}
}

func TestNew_WebhookURLs(t *testing.T) {
	t.Setenv("WEBHOOK_URLS", "https://1.1.1.1/hook")
	t.Setenv("SLACK_WEBHOOK_URL", "")
	t.Setenv("PAGERDUTY_ROUTING_KEY", "")

	ctx := context.Background()
	app, err := New(ctx)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		if closeErr := app.Close(); closeErr != nil {
			t.Fatalf("Close() failed: %v", closeErr)
		}
	}()

	hooks := app.Webhooks.ListWebhooks()
	if len(hooks) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(hooks))
	}
	if hooks[0].URL != "https://1.1.1.1/hook" {
		t.Fatalf("expected webhook URL https://1.1.1.1/hook, got %s", hooks[0].URL)
	}
	if len(hooks[0].Events) == 0 {
		t.Fatalf("expected webhook to have events configured")
	}

	if !containsString(app.Notifications.ListNotifiers(), "webhook") {
		t.Fatalf("expected webhook notifier to be registered")
	}
}

func TestNew_ServicesWired(t *testing.T) {
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")
	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")

	ctx := context.Background()
	app, err := New(ctx)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		if closeErr := app.Close(); closeErr != nil {
			t.Fatalf("Close() failed: %v", closeErr)
		}
	}()

	// Verify policy engine loaded policies
	policies := app.Policy.ListPolicies()
	if len(policies) == 0 {
		t.Log("No policies loaded - may need policies directory")
	}

	// Verify RBAC has default roles
	roles := app.RBAC.ListRoles()
	if len(roles) == 0 {
		t.Error("RBAC should have default roles")
	}

	// Verify remediation has default rules
	rules := app.Remediation.ListRules()
	if len(rules) == 0 {
		t.Error("Remediation should have default rules")
	}

	// Verify runtime detection has rules
	detectionRules := app.RuntimeDetect.ListRules()
	if len(detectionRules) == 0 {
		t.Error("RuntimeDetect should have detection rules")
	}

	// Verify health checks registered
	healthResults := app.Health.RunAll(ctx)
	if len(healthResults) == 0 {
		t.Error("Health should have registered checks")
	}
}

func TestNew_ExplicitMappingsOnlyFailsOnUnmappedPolicy(t *testing.T) {
	t.Setenv("CEREBRO_POLICY_EXPLICIT_MAPPINGS_ONLY", "true")
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")
	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")

	policiesDir := t.TempDir()
	policyJSON := `{
		"id": "strict-unmapped",
		"name": "Strict Unmapped",
		"effect": "forbid",
		"resource": "unknown::resource",
		"conditions": ["enabled == true"],
		"severity": "high"
	}`
	if err := os.WriteFile(filepath.Join(policiesDir, "strict.json"), []byte(policyJSON), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICIES_PATH", policiesDir)

	_, err := New(context.Background())
	if err == nil {
		t.Fatal("expected app initialization to fail in explicit mappings-only mode")
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestConfigProviderValues_DerivesProviderAwareFields(t *testing.T) {
	cfg := &Config{
		ZoomAccountID:      "acct",
		ZoomClientID:       "client",
		ZoomClientSecret:   "secret",
		ZoomAPIURL:         "https://api.zoom.us/v2",
		ZoomTokenURL:       "https://zoom.us/oauth/token",
		SlackAPIToken:      "xoxb-token",
		Auth0Domain:        "tenant.auth0.com",
		Auth0ClientID:      "auth0-client",
		Auth0ClientSecret:  "auth0-secret",
		EntraTenantID:      "entra-tenant",
		EntraClientID:      "entra-client",
		EntraClientSecret:  "entra-secret",
		S3InputBucket:      "cerebro-inputs",
		S3InputPrefix:      "audit/",
		S3InputRegion:      "us-west-2",
		S3InputFormat:      "jsonl",
		S3InputMaxObjects:  250,
		IntuneTenantID:     "",
		IntuneClientID:     "",
		IntuneClientSecret: "",
	}

	zoom := cfg.ProviderValues("zoom")
	if zoom["base_url"] != cfg.ZoomAPIURL {
		t.Fatalf("expected zoom base_url %q, got %q", cfg.ZoomAPIURL, zoom["base_url"])
	}
	if _, ok := zoom["api_url"]; ok {
		t.Fatalf("expected zoom provider values to avoid api_url key alias")
	}

	slack := cfg.ProviderValues("slack")
	if slack["token"] != cfg.SlackAPIToken {
		t.Fatalf("expected slack token %q, got %q", cfg.SlackAPIToken, slack["token"])
	}

	auth0 := cfg.ProviderValues("auth0")
	if auth0["domain"] != cfg.Auth0Domain || auth0["client_id"] != cfg.Auth0ClientID {
		t.Fatalf("expected auth0 provider values to include configured credentials")
	}

	intune := cfg.ProviderValues("intune")
	if intune["tenant_id"] != cfg.EntraTenantID || intune["client_id"] != cfg.EntraClientID || intune["client_secret"] != cfg.EntraClientSecret {
		t.Fatalf("expected intune provider values to inherit Entra fallback credentials")
	}

	s3 := cfg.ProviderValues("s3")
	if s3["bucket"] != cfg.S3InputBucket || s3["prefix"] != cfg.S3InputPrefix || s3["region"] != cfg.S3InputRegion {
		t.Fatalf("expected s3 provider values to include bucket/prefix/region")
	}
	if s3["max_objects"] != "250" {
		t.Fatalf("expected s3 max_objects 250, got %q", s3["max_objects"])
	}
}

func TestMergeProviderAwareConfig_FillsEmptyMatchingKeysOnly(t *testing.T) {
	base := map[string]interface{}{"token": "", "url": "https://example"}
	provider := map[string]string{"token": "secret-token", "api_token": "should-not-be-added"}

	merged := mergeProviderAwareConfig(base, provider)
	if merged["token"] != "secret-token" {
		t.Fatalf("expected token to be backfilled from provider-aware config")
	}
	if _, ok := merged["api_token"]; ok {
		t.Fatalf("expected unknown provider-aware keys to be ignored when not present in base config")
	}
}

func TestInitProviders_RegistersExpandedProviderSet(t *testing.T) {
	app := &App{
		Config: &Config{
			QualysUsername:            "qualys-user",
			QualysPassword:            "qualys-pass",
			QualysPlatform:            "US1",
			ZoomAccountID:             "zoom-account-id",
			ZoomClientID:              "zoom-client-id",
			ZoomClientSecret:          "zoom-client-secret",
			ZoomAPIURL:                "https://api.zoom.us/v2",
			ZoomTokenURL:              "https://zoom.us/oauth/token",
			WizClientID:               "wiz-client-id",
			WizClientSecret:           "wiz-client-secret",
			WizAPIURL:                 "https://api.us1.app.wiz.io/graphql",
			FigmaAPIToken:             "figma-token",
			FigmaTeamID:               "figma-team-id",
			FigmaBaseURL:              "https://api.figma.com",
			SocketAPIToken:            "socket-token",
			SocketOrgSlug:             "writer",
			SocketAPIURL:              "https://api.socket.dev/v0",
			RampClientID:              "ramp-client-id",
			RampClientSecret:          "ramp-client-secret",
			RampAPIURL:                "https://api.ramp.com/developer/v1",
			RampTokenURL:              "https://api.ramp.com/developer/v1/token",
			GongAccessKey:             "gong-access-key",
			GongAccessSecret:          "gong-access-secret",
			GongBaseURL:               "https://api.gong.io",
			VantaAPIToken:             "vanta-token",
			VantaBaseURL:              "https://api.vanta.com",
			PantherAPIToken:           "panther-token",
			PantherBaseURL:            "https://api.runpanther.io/public_api/v1",
			KolideAPIToken:            "kolide-token",
			KolideBaseURL:             "https://api.kolide.com/v1",
			GitLabToken:               "gitlab-token",
			GitLabBaseURL:             "https://gitlab.example.com",
			Auth0Domain:               "tenant.auth0.com",
			Auth0ClientID:             "auth0-client-id",
			Auth0ClientSecret:         "auth0-client-secret",
			TerraformCloudToken:       "terraform-cloud-token",
			SemgrepAPIToken:           "semgrep-token",
			ServiceNowURL:             "https://writer.service-now.com",
			ServiceNowAPIToken:        "servicenow-token",
			WorkdayURL:                "https://api.workday.com",
			WorkdayAPIToken:           "workday-token",
			BambooHRURL:               "https://api.bamboohr.com/v1",
			BambooHRAPIToken:          "bamboohr-token",
			OneLoginURL:               "https://api.us.onelogin.com",
			OneLoginClientID:          "onelogin-client-id",
			OneLoginClientSecret:      "onelogin-client-secret",
			JumpCloudURL:              "https://console.jumpcloud.com",
			JumpCloudAPIToken:         "jumpcloud-token",
			JumpCloudOrgID:            "jumpcloud-org",
			DuoURL:                    "https://api-123.duosecurity.com",
			DuoIntegrationKey:         "duo-ikey",
			DuoSecretKey:              "duo-skey",
			PingIdentityEnvironmentID: "env-123",
			PingIdentityClientID:      "pingidentity-client-id",
			PingIdentityClientSecret:  "pingidentity-client-secret",
			PingIdentityAPIURL:        "https://api.pingone.com",
			PingIdentityAuthURL:       "https://auth.pingone.com",
			CyberArkURL:               "https://tenant.id.cyberark.cloud/scim/v2",
			CyberArkAPIToken:          "cyberark-token",
			SailPointURL:              "https://tenant.api.identitynow.com/scim/v2",
			SailPointAPIToken:         "sailpoint-token",
			SaviyntURL:                "https://tenant.saviyntcloud.com/scim/v2",
			SaviyntAPIToken:           "saviynt-token",
			ForgeRockURL:              "https://tenant.id.forgerock.cloud/scim/v2",
			ForgeRockAPIToken:         "forgerock-token",
			OracleIDCSURL:             "https://tenant.id.oracleidcs.cloud/admin/v1",
			OracleIDCSAPIToken:        "oracle-idcs-token",
			SplunkURL:                 "https://splunk.example.com",
			SplunkToken:               "splunk-token",
			CloudflareAPIToken:        "cloudflare-token",
			SalesforceInstanceURL:     "https://example.my.salesforce.com",
			SalesforceClientID:        "salesforce-client-id",
			SalesforceClientSecret:    "salesforce-client-secret",
			SalesforceUsername:        "salesforce-user",
			SalesforcePassword:        "salesforce-pass",
			VaultAddress:              "https://vault.example.com",
			VaultToken:                "vault-token",
			SlackAPIToken:             "xoxb-token",
			RipplingAPIURL:            "https://api.rippling.com",
			RipplingAPIToken:          "rippling-token",
			JamfBaseURL:               "https://example.jamfcloud.com",
			JamfClientID:              "jamf-client-id",
			JamfClientSecret:          "jamf-client-secret",
			EntraTenantID:             "entra-tenant",
			EntraClientID:             "entra-client-id",
			EntraClientSecret:         "entra-client-secret",
			JiraBaseURL:               "https://example.atlassian.net",
			JiraEmail:                 "admin@example.com",
			JiraAPIToken:              "jira-token",
			KandjiAPIURL:              "https://api.kandji.io/api/v1",
			KandjiAPIToken:            "kandji-token",
			S3InputBucket:             "cerebro-inputs",
			S3InputPrefix:             "security/",
			S3InputRegion:             "us-west-2",
			S3InputFormat:             "jsonl",
			S3InputMaxObjects:         250,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	app.initProviders(context.Background())

	expectedProviders := []string{"qualys", "zoom", "wiz", "figma", "socket", "ramp", "gong", "vanta", "panther", "kolide", "gitlab", "auth0", "terraform_cloud", "semgrep", "servicenow", "workday", "bamboohr", "onelogin", "jumpcloud", "duo", "pingidentity", "cyberark", "sailpoint", "saviynt", "forgerock", "oracle_idcs", "splunk", "cloudflare", "salesforce", "vault", "slack", "rippling", "jamf", "intune", "atlassian", "kandji", "s3"}
	for _, name := range expectedProviders {
		if _, ok := app.Providers.Get(name); !ok {
			t.Errorf("expected provider %q to be registered", name)
		}
	}
}

func TestInitProviders_SkipsExpandedProvidersWithoutConfig(t *testing.T) {
	app := &App{
		Config: &Config{},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	app.initProviders(context.Background())

	notExpected := []string{"qualys", "zoom", "wiz", "figma", "socket", "ramp", "gong", "vanta", "panther", "kolide", "gitlab", "auth0", "terraform_cloud", "semgrep", "servicenow", "workday", "bamboohr", "onelogin", "jumpcloud", "duo", "pingidentity", "cyberark", "sailpoint", "saviynt", "forgerock", "oracle_idcs", "splunk", "cloudflare", "salesforce", "vault", "slack", "rippling", "jamf", "intune", "atlassian", "kandji", "s3", "cloudtrail"}
	for _, name := range notExpected {
		if _, ok := app.Providers.Get(name); ok {
			t.Errorf("did not expect provider %q to be registered", name)
		}
	}
}

func TestScanQueryPolicies_DedupAndSuppressionFlow(t *testing.T) {
	originalExecuteReadOnlyQueryFn := executeReadOnlyQueryFn
	t.Cleanup(func() {
		executeReadOnlyQueryFn = originalExecuteReadOnlyQueryFn
	})

	executeReadOnlyQueryFn = func(context.Context, warehouse.QueryWarehouse, string) (*snowflake.QueryResult, error) {
		return &snowflake.QueryResult{Rows: []map[string]interface{}{
			{"_cq_id": "asset-1", "_cq_table": "assets", "name": "Asset 1"},
			{"id": "asset-1", "_cq_table": "assets", "name": "Asset 1 duplicate"},
		}}, nil
	}

	engine := policy.NewEngine()
	engine.AddPolicy(&policy.Policy{
		ID:          "query-policy",
		Name:        "Query Policy",
		Description: "query finding",
		Severity:    "high",
		Query:       "SELECT _cq_id FROM assets",
	})

	store := findings.NewStore()
	app := &App{
		Config:          &Config{},
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Policy:          engine,
		Findings:        store,
		Warehouse:       &warehouse.MemoryWarehouse{},
		AvailableTables: []string{"assets"},
	}

	first := app.ScanQueryPolicies(context.Background())
	if first.Policies != 1 {
		t.Fatalf("expected 1 query policy, got %d", first.Policies)
	}
	if len(first.Errors) != 0 {
		t.Fatalf("expected no query policy errors, got %v", first.Errors)
	}
	if len(first.Findings) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(first.Findings))
	}

	findingID := first.Findings[0].ID
	app.Findings.Upsert(context.Background(), first.Findings[0])
	if !store.Suppress(findingID) {
		t.Fatalf("expected suppress to succeed for finding %s", findingID)
	}

	suppressed, ok := store.Get(findingID)
	if !ok {
		t.Fatalf("expected finding %s in store", findingID)
	}
	if suppressed.Status != "SUPPRESSED" {
		t.Fatalf("expected suppressed status, got %s", suppressed.Status)
	}

	second := app.ScanQueryPolicies(context.Background())
	if len(second.Findings) != 1 {
		t.Fatalf("expected 1 deduplicated finding on second scan, got %d", len(second.Findings))
	}
	app.Findings.Upsert(context.Background(), second.Findings[0])

	after, ok := store.Get(findingID)
	if !ok {
		t.Fatalf("expected finding %s after second scan", findingID)
	}
	if after.Status != "SUPPRESSED" {
		t.Fatalf("expected suppressed finding to remain suppressed after rescan, got %s", after.Status)
	}
}

func TestScanQueryPolicies_SkipsDisallowedTables(t *testing.T) {
	originalExecuteReadOnlyQueryFn := executeReadOnlyQueryFn
	t.Cleanup(func() {
		executeReadOnlyQueryFn = originalExecuteReadOnlyQueryFn
	})

	queryCallCount := 0
	executeReadOnlyQueryFn = func(context.Context, warehouse.QueryWarehouse, string) (*snowflake.QueryResult, error) {
		queryCallCount++
		return &snowflake.QueryResult{}, nil
	}

	engine := policy.NewEngine()
	engine.AddPolicy(&policy.Policy{
		ID:          "query-policy",
		Name:        "Query Policy",
		Description: "query finding",
		Severity:    "high",
		Query:       "SELECT id FROM disallowed_table",
	})

	app := &App{
		Config:          &Config{},
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Policy:          engine,
		Warehouse:       &warehouse.MemoryWarehouse{},
		AvailableTables: []string{"allowed_table"},
	}

	result := app.ScanQueryPolicies(context.Background())
	if queryCallCount != 0 {
		t.Fatalf("expected query execution to be skipped, got %d calls", queryCallCount)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for disallowed table, got %d", len(result.Findings))
	}
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors for disallowed table skip, got %v", result.Errors)
	}
}

func TestScanQueryPolicies_AddsTruncationMetaFinding(t *testing.T) {
	originalExecuteReadOnlyQueryFn := executeReadOnlyQueryFn
	t.Cleanup(func() {
		executeReadOnlyQueryFn = originalExecuteReadOnlyQueryFn
	})

	observedQuery := ""
	executeReadOnlyQueryFn = func(_ context.Context, _ warehouse.QueryWarehouse, query string) (*snowflake.QueryResult, error) {
		observedQuery = query
		return &snowflake.QueryResult{Rows: []map[string]interface{}{
			{"_cq_id": "asset-1", "_cq_table": "assets", "name": "Asset 1"},
			{"_cq_id": "asset-2", "_cq_table": "assets", "name": "Asset 2"},
		}}, nil
	}

	engine := policy.NewEngine()
	engine.AddPolicy(&policy.Policy{
		ID:          "query-policy",
		Name:        "Query Policy",
		Description: "query finding",
		Severity:    "high",
		Query:       "SELECT _cq_id FROM assets",
	})

	app := &App{
		Config:          &Config{QueryPolicyRowLimit: 2},
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Policy:          engine,
		Warehouse:       &warehouse.MemoryWarehouse{},
		AvailableTables: []string{"assets"},
	}

	result := app.ScanQueryPolicies(context.Background())
	if result.Policies != 1 {
		t.Fatalf("expected 1 query policy, got %d", result.Policies)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("expected no query policy errors, got %v", result.Errors)
	}
	if len(result.Findings) != 3 {
		t.Fatalf("expected 2 row findings plus 1 truncation meta finding, got %d", len(result.Findings))
	}

	metaID := "query-policy:query-result-limit"
	var meta *policy.Finding
	for i := range result.Findings {
		if result.Findings[i].ID == metaID {
			meta = &result.Findings[i]
			break
		}
	}
	if meta == nil {
		t.Fatalf("expected truncation meta finding %q", metaID)
	}
	if meta.ResourceType != "query_policy_scan" {
		t.Fatalf("expected meta resource type query_policy_scan, got %q", meta.ResourceType)
	}
	if observedQuery == "" || !strings.Contains(observedQuery, "LIMIT 2") {
		t.Fatalf("expected bounded query to include LIMIT 2, got %q", observedQuery)
	}
}

func TestApp_Close(t *testing.T) {
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")
	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")

	ctx := context.Background()
	app, _ := New(ctx)

	err := app.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestGetEnv(t *testing.T) {
	t.Setenv("TEST_VAR", "test_value")

	val := getEnv("TEST_VAR", "default")
	if val != "test_value" {
		t.Errorf("expected test_value, got %s", val)
	}

	val = getEnv("NONEXISTENT_VAR", "default")
	if val != "default" {
		t.Errorf("expected default, got %s", val)
	}
}

func TestGetEnvInt(t *testing.T) {
	t.Setenv("TEST_INT", "42")

	val := getEnvInt("TEST_INT", 0)
	if val != 42 {
		t.Errorf("expected 42, got %d", val)
	}

	val = getEnvInt("NONEXISTENT_INT", 100)
	if val != 100 {
		t.Errorf("expected 100, got %d", val)
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"1", true},
		{"yes", true},
		{"false", false},
		{"0", false},
		{"no", false},
	}

	for _, tt := range tests {
		t.Setenv("TEST_BOOL", tt.value)
		got := getEnvBool("TEST_BOOL", false)
		if got != tt.want {
			t.Errorf("getEnvBool(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestGetEnvDuration(t *testing.T) {
	t.Setenv("TEST_DUR", "5m")

	val := getEnvDuration("TEST_DUR", time.Hour)
	if val != 5*time.Minute {
		t.Errorf("expected 5m, got %v", val)
	}

	val = getEnvDuration("NONEXISTENT_DUR", time.Hour)
	if val != time.Hour {
		t.Errorf("expected 1h, got %v", val)
	}
}

func TestGetEnvFloat(t *testing.T) {
	t.Setenv("TEST_FLOAT", "0.25")

	val := getEnvFloat("TEST_FLOAT", 1.0)
	if val != 0.25 {
		t.Errorf("expected 0.25, got %v", val)
	}

	val = getEnvFloat("NONEXISTENT_FLOAT", 0.75)
	if val != 0.75 {
		t.Errorf("expected fallback 0.75, got %v", val)
	}
}

func TestParseKeyValueCSV(t *testing.T) {
	parsed := parseKeyValueCSV("x-api-key=abc123, env=dev,invalid,no-value= ")
	if parsed["x-api-key"] != "abc123" {
		t.Fatalf("expected x-api-key=abc123, got %q", parsed["x-api-key"])
	}
	if parsed["env"] != "dev" {
		t.Fatalf("expected env=dev, got %q", parsed["env"])
	}
	if _, ok := parsed["invalid"]; ok {
		t.Fatalf("did not expect invalid entry to be parsed: %#v", parsed)
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"debug", "DEBUG"},
		{"info", "INFO"},
		{"warn", "WARN"},
		{"error", "ERROR"},
		{"unknown", "INFO"}, // default
	}

	for _, tt := range tests {
		got := parseLogLevel(tt.input)
		if got.String() != tt.want {
			t.Errorf("parseLogLevel(%q) = %s, want %s", tt.input, got.String(), tt.want)
		}
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"1h", time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"5s", 5 * time.Second, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		got, err := parseDuration(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("parseDuration(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestSplitTables(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"a,b,c", 3},
		{"  a , b , c  ", 3},
		{"single", 1},
		{"", 0},
		{",,,", 0},
	}

	for _, tt := range tests {
		got := splitTables(tt.input)
		if len(got) != tt.want {
			t.Errorf("splitTables(%q) len = %d, want %d", tt.input, len(got), tt.want)
		}
	}
}

func TestConfig_Fields(t *testing.T) {
	cfg := &Config{ //nolint:govet // false positive - all fields are tested below
		Port:                   8080,
		LogLevel:               "info",
		SnowflakeDatabase:      "CEREBRO",
		SnowflakeSchema:        "CEREBRO",
		PoliciesPath:           "policies",
		ScanInterval:           "1h",
		SecurityDigestInterval: "24h",
		RateLimitEnabled:       true,
		RateLimitRequests:      1000,
		RateLimitWindow:        time.Hour,
		CORSAllowedOrigins:     []string{"https://app.example.com"},
	}

	if cfg.Port != 8080 {
		t.Error("Port field incorrect")
	}
	if cfg.LogLevel != "info" {
		t.Error("LogLevel field incorrect")
	}
	if cfg.SnowflakeDatabase != "CEREBRO" {
		t.Error("SnowflakeDatabase field incorrect")
	}
	if cfg.SnowflakeSchema != "CEREBRO" {
		t.Error("SnowflakeSchema field incorrect")
	}
	if cfg.PoliciesPath != "policies" {
		t.Error("PoliciesPath field incorrect")
	}
	if cfg.ScanInterval != "1h" {
		t.Error("ScanInterval field incorrect")
	}
	if cfg.SecurityDigestInterval != "24h" {
		t.Error("SecurityDigestInterval field incorrect")
	}
	if cfg.RateLimitEnabled != true {
		t.Error("RateLimitEnabled field incorrect")
	}
	if cfg.RateLimitRequests != 1000 {
		t.Error("RateLimitRequests field incorrect")
	}
	if cfg.RateLimitWindow != time.Hour {
		t.Error("RateLimitWindow field incorrect")
	}
	if !reflect.DeepEqual(cfg.CORSAllowedOrigins, []string{"https://app.example.com"}) {
		t.Error("CORSAllowedOrigins field incorrect")
	}
}
