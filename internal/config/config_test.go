package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("CEREBRO_HTTP_ADDR", "")
	t.Setenv("CEREBRO_SHUTDOWN_TIMEOUT", "")
	t.Setenv("CEREBRO_IMAGE_TAG", "")
	t.Setenv("CEREBRO_DEV_MODE", "")
	t.Setenv("CEREBRO_DEV_MODE_ACK", "")
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", "")
	t.Setenv("CEREBRO_JETSTREAM_URL", "")
	t.Setenv("CEREBRO_JETSTREAM_SUBJECT_PREFIX", "")
	t.Setenv("CEREBRO_JETSTREAM_DRAIN_TIMEOUT", "")
	t.Setenv("CEREBRO_JETSTREAM_PUBLISH_MAX_IN_FLIGHT", "")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", "")
	t.Setenv("CEREBRO_POSTGRES_DSN", "")
	t.Setenv("CEREBRO_POSTGRES_MAX_OPEN_CONNS", "")
	t.Setenv("CEREBRO_POSTGRES_MAX_IDLE_CONNS", "")
	t.Setenv("CEREBRO_POSTGRES_CONN_MAX_LIFETIME", "")
	t.Setenv("CEREBRO_POSTGRES_CONN_MAX_IDLE_TIME", "")
	t.Setenv("CEREBRO_CACHE_MODE", "")
	t.Setenv("CEREBRO_CACHE_URL", "")
	t.Setenv("CEREBRO_CACHE_NAMESPACE", "")
	t.Setenv("CEREBRO_CACHE_DEFAULT_TTL", "")
	t.Setenv("CEREBRO_CACHE_STALE_TTL", "")
	t.Setenv("CEREBRO_CACHE_MAX_PAYLOAD_BYTES", "")
	t.Setenv("CEREBRO_CACHE_ENABLED", "")
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", "")
	t.Setenv("CEREBRO_NEO4J_URI", "")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "")
	t.Setenv("CEREBRO_NEO4J_DATABASE", "")
	t.Setenv("CEREBRO_NEO4J_QUERY_TIMEOUT", "")
	clearGraphAgentEnv(t)
	clearOpenTelemetryEnv(t)
	t.Setenv("CEREBRO_KUZU_PATH", "")
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "")
	t.Setenv("CEREBRO_API_KEYS", "")
	t.Setenv("CEREBRO_API_KEYS_FILE", "")
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON", "")
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON_FILE", "")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_SECRETS", "")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_SECRETS_FILE", "")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_AUDIENCE", "")
	t.Setenv("CEREBRO_ALLOWED_TENANTS", "")
	t.Setenv("CEREBRO_PUBLIC_ORIGIN", "")
	t.Setenv("CEREBRO_TRUSTED_PROXY_CIDRS", "")
	t.Setenv("CEREBRO_TRUSTED_PROXY_COUNT", "")
	t.Setenv("CEREBRO_RATE_LIMIT_ENABLED", "")
	t.Setenv("CEREBRO_RATE_LIMIT_RPS", "")
	t.Setenv("CEREBRO_RATE_LIMIT_BURST", "")
	t.Setenv("CEREBRO_RATE_LIMIT_EXEMPT_PATHS", "")
	t.Setenv("CEREBRO_CONNECTOR_CREDENTIAL_KEY", "")
	t.Setenv("CEREBRO_CONNECTOR_CREDENTIAL_KEY_FILE", "")
	t.Setenv("CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY", "")
	t.Setenv("CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY_FILE", "")
	t.Setenv("CEREBRO_CONNECTOR_HIDDEN_SOURCES", "")
	t.Setenv("CEREBRO_CONNECTOR_RESTRICTED_SOURCES", "")
	t.Setenv("CEREBRO_CONNECTOR_RESTRICTION_REASON", "")
	t.Setenv("CEREBRO_CONNECTOR_REQUEST_ACCESS_URL", "")
	t.Setenv("CEREBRO_CONNECTOR_REQUEST_ACCESS_ACTION", "")
	t.Setenv("CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BASE_URL", "")
	t.Setenv("CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN", "")
	t.Setenv("CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN_FILE", "")
	t.Setenv("CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_TIMEOUT", "")
	clearMCPOAuthEnv(t)
	clearDeviceAuthEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":8080")
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Fatalf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, 10*time.Second)
	}
	if cfg.AppendLog.Driver != "" {
		t.Fatalf("AppendLog.Driver = %q, want empty", cfg.AppendLog.Driver)
	}
	if cfg.StateStore.Driver != "" {
		t.Fatalf("StateStore.Driver = %q, want empty", cfg.StateStore.Driver)
	}
	if cfg.Cache.Driver != CacheDriverOff || cfg.Cache.DefaultTTL != 30*time.Second || cfg.Cache.StaleTTL != 5*time.Minute || cfg.Cache.MaxPayloadBytes != 1<<20 {
		t.Fatalf("Cache defaults = %#v", cfg.Cache)
	}
	if cfg.GraphStore.Driver != "" {
		t.Fatalf("GraphStore.Driver = %q, want empty", cfg.GraphStore.Driver)
	}
	if cfg.GraphAgentLLM.Provider != "" || cfg.GraphAgentLLM.MaxTokens != 0 {
		t.Fatalf("GraphAgentLLM = %#v, want empty/default", cfg.GraphAgentLLM)
	}
	if cfg.GraphActions.AccessApprovals.Timeout != 10*time.Second || cfg.GraphActions.AccessApprovals.BaseURL != "" || cfg.GraphActions.AccessApprovals.BearerToken != "" {
		t.Fatalf("GraphActions.AccessApprovals defaults = %#v", cfg.GraphActions.AccessApprovals)
	}
	if cfg.OTEL.Enabled || cfg.OTEL.Protocol != "http/protobuf" || cfg.OTEL.TraceSampleRate != 1 || cfg.OTEL.MetricInterval != time.Minute {
		t.Fatalf("OTEL defaults = %#v", cfg.OTEL)
	}
	if !cfg.Auth.Enabled {
		t.Fatal("Auth.Enabled = false, want true safe default")
	}
	if !cfg.RateLimit.Enabled {
		t.Fatal("RateLimit.Enabled = false, want true safe default")
	}
	wantExemptPaths := []string{"/healthz", "/livez", "/metrics", "/.well-known/"}
	if len(cfg.RateLimit.ExemptPaths) != len(wantExemptPaths) {
		t.Fatalf("RateLimit.ExemptPaths = %#v, want %#v", cfg.RateLimit.ExemptPaths, wantExemptPaths)
	}
	for i, want := range wantExemptPaths {
		if cfg.RateLimit.ExemptPaths[i] != want {
			t.Fatalf("RateLimit.ExemptPaths = %#v, want %#v", cfg.RateLimit.ExemptPaths, wantExemptPaths)
		}
	}
	if cfg.StateStore.PostgresMaxOpenConns != defaultPostgresMaxOpenConns || cfg.StateStore.PostgresMaxIdleConns != defaultPostgresMaxIdleConns || cfg.StateStore.PostgresConnMaxLifetime != defaultPostgresConnMaxLifetime || cfg.StateStore.PostgresConnMaxIdleTime != defaultPostgresConnMaxIdleTime {
		t.Fatalf("StateStore Postgres pool defaults = %#v", cfg.StateStore)
	}
	if cfg.Auth.DeviceAuth.ReplicaCount != 1 {
		t.Fatalf("DeviceAuth.ReplicaCount = %d, want 1", cfg.Auth.DeviceAuth.ReplicaCount)
	}
	if cfg.Auth.DeviceAuth.RefreshTTL != defaultDeviceAuthRefreshTTL {
		t.Fatalf("DeviceAuth.RefreshTTL = %v, want %v", cfg.Auth.DeviceAuth.RefreshTTL, defaultDeviceAuthRefreshTTL)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("CEREBRO_HTTP_ADDR", "127.0.0.1:9000")
	t.Setenv("CEREBRO_SHUTDOWN_TIMEOUT", "3s")
	t.Setenv("CEREBRO_IMAGE_TAG", "v9.9.9")
	t.Setenv("CEREBRO_DEV_MODE", "")
	t.Setenv("CEREBRO_DEV_MODE_ACK", "")
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", AppendLogDriverJetStream)
	t.Setenv("CEREBRO_JETSTREAM_URL", "nats://127.0.0.1:4222")
	t.Setenv("CEREBRO_JETSTREAM_SUBJECT_PREFIX", "cerebro.events")
	t.Setenv("CEREBRO_JETSTREAM_DRAIN_TIMEOUT", "4s")
	t.Setenv("CEREBRO_JETSTREAM_PUBLISH_MAX_IN_FLIGHT", "12")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", StateStoreDriverPostgres)
	t.Setenv("CEREBRO_POSTGRES_DSN", "postgres://127.0.0.1:5432/cerebro?sslmode=disable")
	t.Setenv("CEREBRO_POSTGRES_MAX_OPEN_CONNS", "20")
	t.Setenv("CEREBRO_POSTGRES_MAX_IDLE_CONNS", "5")
	t.Setenv("CEREBRO_POSTGRES_CONN_MAX_LIFETIME", "30m")
	t.Setenv("CEREBRO_POSTGRES_CONN_MAX_IDLE_TIME", "5m")
	t.Setenv("CEREBRO_CACHE_MODE", CacheDriverValkey)
	t.Setenv("CEREBRO_CACHE_URL", "rediss://cache.example.internal:6379")
	t.Setenv("CEREBRO_CACHE_NAMESPACE", "cerebro:test")
	t.Setenv("CEREBRO_CACHE_DEFAULT_TTL", "45s")
	t.Setenv("CEREBRO_CACHE_STALE_TTL", "10m")
	t.Setenv("CEREBRO_CACHE_MAX_PAYLOAD_BYTES", "2097152")
	t.Setenv("CEREBRO_CACHE_ENABLED", "")
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", GraphStoreDriverNeo4j)
	t.Setenv("CEREBRO_NEO4J_URI", "neo4j+s://example.databases.neo4j.io")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "neo4j")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "test-password")
	t.Setenv("CEREBRO_NEO4J_DATABASE", "cerebro")
	t.Setenv("CEREBRO_NEO4J_QUERY_TIMEOUT", "45s")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_PROVIDER", "stub")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_MODEL", "claude-sonnet-4-6")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_MODEL_SONNET", "anthropic.claude-sonnet-example")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_MODEL_OPUS", "anthropic.claude-opus-example")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_MODEL_HAIKU", "anthropic.claude-haiku-example")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_MAX_TOKENS", "900")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_TEMPERATURE", "0.25")
	t.Setenv("CEREBRO_OPENROUTER_API_KEY", "openrouter-test-key")
	t.Setenv("CEREBRO_BEDROCK_REGION", "us-east-1")
	t.Setenv("CEREBRO_OTEL_ENABLED", "true")
	t.Setenv("CEREBRO_OTEL_SERVICE_NAME", "cerebro-test")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel-collector.example.com:4317")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://otel-collector.example.com:4317/v1/traces")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "https://otel-collector.example.com:4317/v1/metrics")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_HEADERS", "x-scope=security,tenant=writer")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_INSECURE", "false")
	t.Setenv("CEREBRO_OTEL_TRACES_SAMPLE_RATE", "0.25")
	t.Setenv("CEREBRO_OTEL_METRICS_EXPORT_INTERVAL", "15s")
	t.Setenv("CEREBRO_KUZU_PATH", "")
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_API_KEYS", "token-1:ci:writer,token-2:ops:security")
	t.Setenv("CEREBRO_API_KEYS_FILE", "")
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON", "")
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON_FILE", "")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_SECRETS", "")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_SECRETS_FILE", "")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_AUDIENCE", "")
	t.Setenv("CEREBRO_ALLOWED_TENANTS", "security,writer,writer")
	t.Setenv("CEREBRO_PUBLIC_ORIGIN", "https://api.writer.com")
	t.Setenv("CEREBRO_TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 192.168.0.0/16")
	t.Setenv("CEREBRO_TRUSTED_PROXY_COUNT", "1")
	t.Setenv("CEREBRO_RATE_LIMIT_ENABLED", "true")
	t.Setenv("CEREBRO_RATE_LIMIT_RPS", "42.5")
	t.Setenv("CEREBRO_RATE_LIMIT_BURST", "60")
	t.Setenv("CEREBRO_RATE_LIMIT_EXEMPT_PATHS", "/health,/ready")
	t.Setenv("CEREBRO_CONNECTOR_CREDENTIAL_KEY", "connector-vault-key")
	t.Setenv("CEREBRO_CONNECTOR_CREDENTIAL_KEY_FILE", "")
	t.Setenv("CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY", "connector-transit-key")
	t.Setenv("CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY_FILE", "")
	t.Setenv("CEREBRO_CONNECTOR_HIDDEN_SOURCES", "internal_source")
	t.Setenv("CEREBRO_CONNECTOR_RESTRICTED_SOURCES", "aws,auth0")
	t.Setenv("CEREBRO_CONNECTOR_RESTRICTION_REASON", "limited preview")
	t.Setenv("CEREBRO_CONNECTOR_REQUEST_ACCESS_URL", "https://access.example.com/request?source={source_id}&tenant={tenant_id}")
	t.Setenv("CEREBRO_CONNECTOR_REQUEST_ACCESS_ACTION", "Request in Access Hub")
	t.Setenv("CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BASE_URL", "https://access-approvals.example.com/")
	t.Setenv("CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN", "graph-action-token")
	t.Setenv("CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN_FILE", "")
	t.Setenv("CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_TIMEOUT", "7s")
	t.Setenv("CEREBRO_CONNECTOR_SECRET_STORES", "aws_secrets_manager,infisical")
	t.Setenv("CEREBRO_CONNECTOR_SECRET_STORES_FILE", "")
	t.Setenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_REGION", "us-east-1")
	t.Setenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_PROFILE", "cerebro-security")
	t.Setenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_ROLE_ARN", "arn:aws:iam::123456789012:role/cerebro-secrets")
	t.Setenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_EXTERNAL_ID", "external-writer")
	t.Setenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_ENDPOINT", "http://127.0.0.1:4566")
	clearMCPOAuthEnv(t)
	clearDeviceAuthEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != "127.0.0.1:9000" {
		t.Fatalf("HTTPAddr = %q, want %q", cfg.HTTPAddr, "127.0.0.1:9000")
	}
	if cfg.ShutdownTimeout != 3*time.Second {
		t.Fatalf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, 3*time.Second)
	}
	if cfg.ImageTag != "v9.9.9" {
		t.Fatalf("ImageTag = %q, want %q", cfg.ImageTag, "v9.9.9")
	}
	if cfg.AppendLog.Driver != AppendLogDriverJetStream {
		t.Fatalf("AppendLog.Driver = %q, want %q", cfg.AppendLog.Driver, AppendLogDriverJetStream)
	}
	if cfg.AppendLog.JetStreamSubjectPrefix != "cerebro.events" {
		t.Fatalf("JetStreamSubjectPrefix = %q, want %q", cfg.AppendLog.JetStreamSubjectPrefix, "cerebro.events")
	}
	if cfg.AppendLog.JetStreamDrainTimeout != 4*time.Second {
		t.Fatalf("JetStreamDrainTimeout = %v, want 4s", cfg.AppendLog.JetStreamDrainTimeout)
	}
	if cfg.AppendLog.JetStreamPublishMaxInFlight != 12 {
		t.Fatalf("JetStreamPublishMaxInFlight = %d, want 12", cfg.AppendLog.JetStreamPublishMaxInFlight)
	}
	if cfg.StateStore.Driver != StateStoreDriverPostgres {
		t.Fatalf("StateStore.Driver = %q, want %q", cfg.StateStore.Driver, StateStoreDriverPostgres)
	}
	if cfg.StateStore.PostgresMaxOpenConns != 20 || cfg.StateStore.PostgresMaxIdleConns != 5 || cfg.StateStore.PostgresConnMaxLifetime != 30*time.Minute || cfg.StateStore.PostgresConnMaxIdleTime != 5*time.Minute {
		t.Fatalf("StateStore pool config = %#v", cfg.StateStore)
	}
	if cfg.Cache.Driver != CacheDriverValkey || cfg.Cache.URL != "rediss://cache.example.internal:6379" || cfg.Cache.Namespace != "cerebro:test" || cfg.Cache.DefaultTTL != 45*time.Second || cfg.Cache.StaleTTL != 10*time.Minute || cfg.Cache.MaxPayloadBytes != 2097152 {
		t.Fatalf("Cache config = %#v", cfg.Cache)
	}
	if cfg.GraphStore.Driver != GraphStoreDriverNeo4j {
		t.Fatalf("GraphStore.Driver = %q, want %q", cfg.GraphStore.Driver, GraphStoreDriverNeo4j)
	}
	if cfg.GraphStore.Neo4jQueryTimeout != 45*time.Second {
		t.Fatalf("Neo4jQueryTimeout = %v, want 45s", cfg.GraphStore.Neo4jQueryTimeout)
	}
	if cfg.GraphAgentLLM.Provider != "stub" || cfg.GraphAgentLLM.MaxTokens != 900 || cfg.GraphAgentLLM.Temperature != 0.25 {
		t.Fatalf("GraphAgentLLM = %#v", cfg.GraphAgentLLM)
	}
	if cfg.GraphAgentLLM.SonnetModel != "anthropic.claude-sonnet-example" || cfg.GraphAgentLLM.OpusModel == "" || cfg.GraphAgentLLM.HaikuModel == "" {
		t.Fatalf("GraphAgentLLM model mapping = %#v", cfg.GraphAgentLLM)
	}
	if cfg.GraphAgentLLM.OpenRouterAPIKey != "openrouter-test-key" {
		t.Fatal("GraphAgentLLM.OpenRouterAPIKey was not loaded")
	}
	if cfg.GraphAgentLLM.BedrockRegion != "us-east-1" {
		t.Fatalf("GraphAgentLLM.BedrockRegion = %q, want us-east-1", cfg.GraphAgentLLM.BedrockRegion)
	}
	if !cfg.OTEL.Enabled || cfg.OTEL.Protocol != "grpc" || cfg.OTEL.ServiceName != "cerebro-test" {
		t.Fatalf("OTEL = %#v, want enabled grpc config", cfg.OTEL)
	}
	if cfg.OTEL.Endpoint != "https://otel-collector.example.com:4317" || cfg.OTEL.TracesEndpoint == "" || cfg.OTEL.MetricsEndpoint == "" {
		t.Fatalf("OTEL endpoints = %#v", cfg.OTEL)
	}
	if cfg.OTEL.Headers["x-scope"] != "security" || cfg.OTEL.Headers["tenant"] != "writer" {
		t.Fatalf("OTEL headers = %#v", cfg.OTEL.Headers)
	}
	if cfg.OTEL.Insecure || cfg.OTEL.TraceSampleRate != 0.25 || cfg.OTEL.MetricInterval != 15*time.Second {
		t.Fatalf("OTEL exporter options = %#v", cfg.OTEL)
	}
	if !cfg.Auth.Enabled {
		t.Fatal("Auth.Enabled = false, want true")
	}
	if !cfg.RateLimit.Enabled || cfg.RateLimit.RequestsPerSecond != 42.5 || cfg.RateLimit.BurstSize != 60 {
		t.Fatalf("RateLimit = %#v", cfg.RateLimit)
	}
	if got := cfg.RateLimit.ExemptPaths; len(got) != 2 || got[0] != "/health" || got[1] != "/ready" {
		t.Fatalf("RateLimit.ExemptPaths = %#v", got)
	}
	if got := cfg.Auth.RequestOrigin.PublicOrigin; got != "https://api.writer.com" {
		t.Fatalf("PublicOrigin = %q, want https://api.writer.com", got)
	}
	if got := cfg.Auth.RequestOrigin.TrustedProxyCount; got != 1 {
		t.Fatalf("TrustedProxyCount = %d, want 1", got)
	}
	if got := cfg.Auth.RequestOrigin.TrustedProxyCIDRs; len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "192.168.0.0/16" {
		t.Fatalf("TrustedProxyCIDRs = %#v, want two configured CIDRs", got)
	}
	if len(cfg.Auth.APIKeys) != 2 {
		t.Fatalf("Auth.APIKeys length = %d, want 2", len(cfg.Auth.APIKeys))
	}
	if cfg.Auth.APIKeys[0].Principal != "ci" || cfg.Auth.APIKeys[0].TenantID != "writer" {
		t.Fatalf("Auth.APIKeys[0] = %#v", cfg.Auth.APIKeys[0])
	}
	if got := cfg.Auth.AllowedTenants; len(got) != 2 || got[0] != "security" || got[1] != "writer" {
		t.Fatalf("Auth.AllowedTenants = %#v, want [security writer]", got)
	}
	if cfg.ConnectorCredentials.Key != "connector-vault-key" || cfg.ConnectorCredentials.TransitPrivateKey != "connector-transit-key" {
		t.Fatalf("ConnectorCredentials = %#v", cfg.ConnectorCredentials)
	}
	if got := cfg.ConnectorSecretStores.Enabled; len(got) != 2 || got[0] != "aws_secrets_manager" || got[1] != "infisical" {
		t.Fatalf("ConnectorSecretStores.Enabled = %#v, want configured stores", got)
	}
	if got := cfg.ConnectorAccess.HiddenSources; len(got) != 1 || got[0] != "internal_source" {
		t.Fatalf("ConnectorAccess.HiddenSources = %#v, want internal_source", got)
	}
	if got := cfg.ConnectorAccess.RestrictedSources; len(got) != 2 || got[0] != "auth0" || got[1] != "aws" {
		t.Fatalf("ConnectorAccess.RestrictedSources = %#v, want auth0/aws", got)
	}
	if cfg.ConnectorAccess.RestrictionReason != "limited preview" {
		t.Fatalf("ConnectorAccess.RestrictionReason = %q, want limited preview", cfg.ConnectorAccess.RestrictionReason)
	}
	if cfg.ConnectorAccess.RequestAccessURL != "https://access.example.com/request?source={source_id}&tenant={tenant_id}" {
		t.Fatalf("ConnectorAccess.RequestAccessURL = %q, want configured request URL template", cfg.ConnectorAccess.RequestAccessURL)
	}
	if cfg.ConnectorAccess.RequestAccessAction != "Request in Access Hub" {
		t.Fatalf("ConnectorAccess.RequestAccessAction = %q, want configured request action", cfg.ConnectorAccess.RequestAccessAction)
	}
	if cfg.GraphActions.AccessApprovals.BaseURL != "https://access-approvals.example.com" || cfg.GraphActions.AccessApprovals.BearerToken != "graph-action-token" || cfg.GraphActions.AccessApprovals.Timeout != 7*time.Second {
		t.Fatalf("GraphActions.AccessApprovals = %#v, want configured access-approvals target", cfg.GraphActions.AccessApprovals)
	}
	if cfg.ConnectorSecretStores.AWSSecretsManager.Region != "us-east-1" ||
		cfg.ConnectorSecretStores.AWSSecretsManager.Profile != "cerebro-security" ||
		cfg.ConnectorSecretStores.AWSSecretsManager.RoleARN == "" ||
		cfg.ConnectorSecretStores.AWSSecretsManager.ExternalID != "external-writer" ||
		cfg.ConnectorSecretStores.AWSSecretsManager.Endpoint != "http://127.0.0.1:4566" {
		t.Fatalf("ConnectorSecretStores.AWSSecretsManager = %#v", cfg.ConnectorSecretStores.AWSSecretsManager)
	}
}

func TestLoadParsesMountedAPISecretFiles(t *testing.T) {
	clearDependencyEnv(t)
	sum := sha256.Sum256([]byte("scoped-token"))
	t.Setenv("CEREBRO_API_KEYS_FILE", writeConfigTestFile(t, "api-keys", "mounted-token:mounted:writer\n"))
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON_FILE", writeConfigTestFile(t, "api-credentials.json", `[
		{
			"credential_id": "mounted-credential",
			"client_id": "mounted-client",
			"key_sha256": "`+hex.EncodeToString(sum[:])+`",
			"allowed_tenants": ["writer"],
			"scopes": ["cerebro.cosmo.security.read"]
		}
	]`))
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_SECRETS_FILE", writeConfigTestFile(t, "capability-secrets", "secret-2,secret-1\n"))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Auth.APIKeys) != 1 || cfg.Auth.APIKeys[0].Key != "mounted-token" || cfg.Auth.APIKeys[0].Principal != "mounted" {
		t.Fatalf("Auth.APIKeys = %#v", cfg.Auth.APIKeys)
	}
	if len(cfg.Auth.APICredentials) != 1 || cfg.Auth.APICredentials[0].ID != "mounted-credential" {
		t.Fatalf("Auth.APICredentials = %#v", cfg.Auth.APICredentials)
	}
	if got := cfg.Auth.CapabilityTokenSecrets; len(got) != 2 || got[0] != "secret-1" || got[1] != "secret-2" {
		t.Fatalf("CapabilityTokenSecrets = %#v, want sorted mounted secrets", got)
	}
}

func TestLoadRejectsConflictingMountedConfigValue(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON", `[]`)
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON_FILE", writeConfigTestFile(t, "api-credentials.json", `[]`))

	_, err := Load()
	if !errors.Is(err, errConfigValueConflict) {
		t.Fatalf("Load() error = %v, want errConfigValueConflict", err)
	}
}

func TestLoadParsesDeviceAuthSigningKeysFile(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_DEVICE_AUTH_CURRENT_KID", "k1")
	t.Setenv("CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON_FILE", writeConfigTestFile(t, "device-keys.json", `[{"kid":"k1","public_pem":"public","private_pem":"private"}]`))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Auth.DeviceAuth.SigningKeys) != 1 || cfg.Auth.DeviceAuth.SigningKeys[0].KID != "k1" {
		t.Fatalf("DeviceAuth.SigningKeys = %#v", cfg.Auth.DeviceAuth.SigningKeys)
	}
}

func TestLoadParsesMCPOAuthJSONFiles(t *testing.T) {
	setValidMCPOAuthEnv(t)
	t.Setenv("CEREBRO_MCP_OAUTH_CLIENTS_JSON", "")
	t.Setenv("CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON", "")
	t.Setenv("CEREBRO_MCP_OAUTH_CLIENTS_JSON_FILE", writeConfigTestFile(t, "mcp-clients.json", `[
		{"client_id":"droid","redirect_uris":["http://127.0.0.1/callback"],"public":true}
	]`))
	t.Setenv("CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON_FILE", writeConfigTestFile(t, "mcp-entitlements.json", `[
		{"groups":["secops"],"allowed_tenants":["writer"],"scopes":["cerebro.cosmo.security.read"]}
	]`))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Auth.MCPOAuth.Clients) != 1 || cfg.Auth.MCPOAuth.Clients[0].ClientID != "droid" {
		t.Fatalf("MCPOAuth.Clients = %#v", cfg.Auth.MCPOAuth.Clients)
	}
	if len(cfg.Auth.MCPOAuth.Entitlements) != 1 || cfg.Auth.MCPOAuth.Entitlements[0].Groups[0] != "secops" {
		t.Fatalf("MCPOAuth.Entitlements = %#v", cfg.Auth.MCPOAuth.Entitlements)
	}
}

func TestLoadEnablesOTELWhenEndpointConfigured(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_INSECURE", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.OTEL.Enabled {
		t.Fatal("OTEL.Enabled = false, want true when endpoint is configured")
	}
}

func TestLoadRejectsPlainHTTPRemoteOTELEndpoint(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_OTEL_ENABLED", "true")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector.example.com:4318")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_INSECURE", "true")

	_, err := Load()
	if !errors.Is(err, errUnsafeOTLPTransportMode) {
		t.Fatalf("Load() error = %v, want remote plain HTTP OTLP rejection", err)
	}
}

func TestLoadRejectsLoopbackHTTPOTELEndpointWithoutInsecure(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_OTEL_ENABLED", "true")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")

	_, err := Load()
	if !errors.Is(err, errUnsafeOTLPTransportMode) {
		t.Fatalf("Load() error = %v, want loopback HTTP to require insecure flag", err)
	}
}

func TestLoadRejectsInsecureFlagForHTTPSOTELEndpoint(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_OTEL_ENABLED", "true")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel-collector.example.com:4318")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_INSECURE", "true")

	_, err := Load()
	if !errors.Is(err, errUnsafeOTLPTransportMode) {
		t.Fatalf("Load() error = %v, want insecure HTTPS OTLP rejection", err)
	}
}

func TestLoadRejectsInsecureOTLPWithoutEndpoint(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_OTEL_ENABLED", "true")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_INSECURE", "true")

	_, err := Load()
	if !errors.Is(err, errUnsafeOTLPTransportMode) {
		t.Fatalf("Load() error = %v, want insecure OTLP without endpoint rejection", err)
	}
}

func TestLoadRejectsMalformedOTELEndpoint(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_OTEL_ENABLED", "true")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector.example.com:4318")

	_, err := Load()
	if !errors.Is(err, errInvalidOTLPEndpoint) {
		t.Fatalf("Load() error = %v, want malformed OTLP endpoint rejection", err)
	}
}

func writeConfigTestFile(t *testing.T, name string, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config test file: %v", err)
	}
	return path
}

func clearDependencyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CEREBRO_HTTP_ADDR", "")
	t.Setenv("CEREBRO_SHUTDOWN_TIMEOUT", "")
	t.Setenv("CEREBRO_IMAGE_TAG", "")
	t.Setenv("CEREBRO_DEV_MODE", "")
	t.Setenv("CEREBRO_DEV_MODE_ACK", "")
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", "")
	t.Setenv("CEREBRO_JETSTREAM_URL", "")
	t.Setenv("CEREBRO_JETSTREAM_SUBJECT_PREFIX", "")
	t.Setenv("CEREBRO_JETSTREAM_DRAIN_TIMEOUT", "")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", "")
	t.Setenv("CEREBRO_POSTGRES_DSN", "")
	t.Setenv("CEREBRO_POSTGRES_MAX_OPEN_CONNS", "")
	t.Setenv("CEREBRO_POSTGRES_MAX_IDLE_CONNS", "")
	t.Setenv("CEREBRO_POSTGRES_CONN_MAX_LIFETIME", "")
	t.Setenv("CEREBRO_POSTGRES_CONN_MAX_IDLE_TIME", "")
	t.Setenv("CEREBRO_CACHE_MODE", "")
	t.Setenv("CEREBRO_CACHE_URL", "")
	t.Setenv("CEREBRO_CACHE_NAMESPACE", "")
	t.Setenv("CEREBRO_CACHE_DEFAULT_TTL", "")
	t.Setenv("CEREBRO_CACHE_STALE_TTL", "")
	t.Setenv("CEREBRO_CACHE_MAX_PAYLOAD_BYTES", "")
	t.Setenv("CEREBRO_CACHE_ENABLED", "")
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", "")
	t.Setenv("CEREBRO_NEO4J_URI", "")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "")
	t.Setenv("CEREBRO_NEO4J_DATABASE", "")
	t.Setenv("CEREBRO_NEO4J_QUERY_TIMEOUT", "")
	clearGraphAgentEnv(t)
	clearOpenTelemetryEnv(t)
	t.Setenv("CEREBRO_KUZU_PATH", "")
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "")
	t.Setenv("CEREBRO_API_KEYS", "")
	t.Setenv("CEREBRO_API_KEYS_FILE", "")
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON", "")
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON_FILE", "")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_SECRETS", "")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_SECRETS_FILE", "")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_AUDIENCE", "")
	t.Setenv("CEREBRO_ALLOWED_TENANTS", "")
	t.Setenv("CEREBRO_PUBLIC_ORIGIN", "")
	t.Setenv("CEREBRO_TRUSTED_PROXY_CIDRS", "")
	t.Setenv("CEREBRO_TRUSTED_PROXY_COUNT", "")
	t.Setenv("CEREBRO_RATE_LIMIT_ENABLED", "")
	t.Setenv("CEREBRO_RATE_LIMIT_RPS", "")
	t.Setenv("CEREBRO_RATE_LIMIT_BURST", "")
	t.Setenv("CEREBRO_RATE_LIMIT_EXEMPT_PATHS", "")
	t.Setenv("CEREBRO_CONNECTOR_CREDENTIAL_KEY", "")
	t.Setenv("CEREBRO_CONNECTOR_CREDENTIAL_KEY_FILE", "")
	t.Setenv("CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY", "")
	t.Setenv("CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY_FILE", "")
	t.Setenv("CEREBRO_CONNECTOR_SECRET_STORES", "")
	t.Setenv("CEREBRO_CONNECTOR_SECRET_STORES_FILE", "")
	t.Setenv("CEREBRO_CONNECTOR_HIDDEN_SOURCES", "")
	t.Setenv("CEREBRO_CONNECTOR_RESTRICTED_SOURCES", "")
	t.Setenv("CEREBRO_CONNECTOR_RESTRICTION_REASON", "")
	t.Setenv("CEREBRO_CONNECTOR_REQUEST_ACCESS_URL", "")
	t.Setenv("CEREBRO_CONNECTOR_REQUEST_ACCESS_ACTION", "")
	t.Setenv("CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BASE_URL", "")
	t.Setenv("CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN", "")
	t.Setenv("CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN_FILE", "")
	t.Setenv("CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_TIMEOUT", "")
	t.Setenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_REGION", "")
	t.Setenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_PROFILE", "")
	t.Setenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_ROLE_ARN", "")
	t.Setenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_EXTERNAL_ID", "")
	t.Setenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_ENDPOINT", "")
	clearMCPOAuthEnv(t)
	clearDeviceAuthEnv(t)
}

func clearGraphAgentEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_PROVIDER", "")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_MODEL", "")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_MODEL_SONNET", "")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_MODEL_OPUS", "")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_MODEL_HAIKU", "")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_MAX_TOKENS", "")
	t.Setenv("CEREBRO_GRAPH_AGENT_LLM_TEMPERATURE", "")
	t.Setenv("CEREBRO_OPENROUTER_API_KEY", "")
	t.Setenv("CEREBRO_BEDROCK_REGION", "")
}

func clearOpenTelemetryEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CEREBRO_OTEL_ENABLED", "")
	t.Setenv("CEREBRO_OTEL_SERVICE_NAME", "")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_PROTOCOL", "")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_HEADERS", "")
	t.Setenv("CEREBRO_OTEL_EXPORTER_OTLP_INSECURE", "")
	t.Setenv("CEREBRO_OTEL_TRACES_SAMPLE_RATE", "")
	t.Setenv("CEREBRO_OTEL_METRICS_EXPORT_INTERVAL", "")
}

func clearDeviceAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CEREBRO_DEVICE_AUTH_ENABLED", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_ISSUER", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_AUDIENCE", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_CURRENT_KID", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_ACCESS_TTL", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_REFRESH_TTL", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_BOOTSTRAP_TOKEN_TTL", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_IDEMPOTENCY_TTL", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_CLOCK_SKEW", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_ENROLL_RPS", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_ENROLL_BURST", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_TOKEN_RPS", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_TOKEN_BURST", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_DPOP_PROOF_TTL", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_REPLICA_COUNT", "")
	t.Setenv("CEREBRO_REPLICA_COUNT", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_RISK_ELEVATED", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_RISK_HIGH", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_ATTESTATION_REQUIRED", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_APPLE_TEAM_ID", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_APPLE_BUNDLE_IDS", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON", "")
	t.Setenv("CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON_FILE", "")
}

func clearMCPOAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CEREBRO_MCP_OAUTH_ENABLED", "")
	t.Setenv("CEREBRO_MCP_OAUTH_ISSUER", "")
	t.Setenv("CEREBRO_MCP_OAUTH_RESOURCE", "")
	t.Setenv("CEREBRO_MCP_OAUTH_CLIENTS_JSON", "")
	t.Setenv("CEREBRO_MCP_OAUTH_CLIENTS_JSON_FILE", "")
	t.Setenv("CEREBRO_MCP_OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED", "")
	t.Setenv("CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON", "")
	t.Setenv("CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON_FILE", "")
	t.Setenv("CEREBRO_MCP_OAUTH_ACCESS_TTL", "")
	t.Setenv("CEREBRO_MCP_OAUTH_REFRESH_TTL", "")
	t.Setenv("CEREBRO_MCP_OAUTH_CODE_TTL", "")
	t.Setenv("CEREBRO_MCP_OAUTH_STATE_TTL", "")
	t.Setenv("CEREBRO_MCP_OAUTH_TENANT_ID", "")
	t.Setenv("CEREBRO_MCP_OAUTH_ALLOWED_TENANTS", "")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER", "")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_AUTHORIZATION_ENDPOINT", "")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_TOKEN_ENDPOINT", "")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_JWKS_URI", "")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID", "")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET", "")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI", "")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_SCOPES", "")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_GROUPS_CLAIM", "")
	t.Setenv("CEREBRO_MCP_OAUTH_SECURITY_GROUPS", "")
}

func TestLoadRejectsRequiredDeviceAuthAttestationWithoutVerifier(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_DEVICE_AUTH_ATTESTATION_REQUIRED", "true")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsDeviceAuthMultipleReplicasWithoutSharedDPoPReplay(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_DEVICE_AUTH_REPLICA_COUNT", "2")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsDeviceAuthGenericMultipleReplicasWithoutSharedDPoPReplay(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_REPLICA_COUNT", "2")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsDeviceAuthEnabledWithoutCurrentKID(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON", `[{"kid":"k1","public_pem":"public"}]`)
	t.Setenv("CEREBRO_DEVICE_AUTH_CURRENT_KID", "")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadDevModeRequiresExplicitAck(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_DEV_MODE", "true")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadDevModeDisablesAuthAndRateLimit(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_DEV_MODE", "true")
	t.Setenv("CEREBRO_DEV_MODE_ACK", "true")
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_RATE_LIMIT_ENABLED", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.DevMode {
		t.Fatal("DevMode = false, want true")
	}
	if cfg.Auth.Enabled {
		t.Fatal("Auth.Enabled = true, want false in dev mode")
	}
	if cfg.RateLimit.Enabled {
		t.Fatal("RateLimit.Enabled = true, want false in dev mode")
	}
}

func TestLoadRejectsInvalidRequestOriginConfig(t *testing.T) {
	for _, tt := range []struct {
		name string
		key  string
		val  string
	}{
		{name: "public origin with path", key: "CEREBRO_PUBLIC_ORIGIN", val: "https://api.writer.com/cerebro"},
		{name: "invalid proxy cidr", key: "CEREBRO_TRUSTED_PROXY_CIDRS", val: "not-cidr"},
		{name: "negative proxy count", key: "CEREBRO_TRUSTED_PROXY_COUNT", val: "-1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clearDependencyEnv(t)
			t.Setenv(tt.key, tt.val)
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want invalid request-origin config error")
			}
		})
	}
}

func TestLoadParsesStructuredAPICredentials(t *testing.T) {
	clearDependencyEnv(t)
	sum := sha256.Sum256([]byte("scoped-token"))
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON", `[
		{
			"credential_id": "cred-cosmo-security",
			"client_id": "cosmo",
			"name": "Cosmo Security",
			"kind": "agent",
			"key_sha256": "`+hex.EncodeToString(sum[:])+`",
			"principal": "cosmo-security",
			"allowed_tenants": ["writer", "writer"],
			"scopes": ["cerebro.cosmo.security.read", "cerebro.cosmo.security.read"],
			"roles": ["cerebro.viewer", "cerebro.viewer"]
		}
	]`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Auth.APICredentials) != 1 {
		t.Fatalf("Auth.APICredentials length = %d, want 1", len(cfg.Auth.APICredentials))
	}
	credential := cfg.Auth.APICredentials[0]
	if credential.ID != "cred-cosmo-security" || credential.ClientID != "cosmo" || credential.Principal != "cosmo-security" {
		t.Fatalf("credential attribution = %#v", credential)
	}
	if got := credential.AllowedTenants; len(got) != 1 || got[0] != "writer" {
		t.Fatalf("AllowedTenants = %#v, want [writer]", got)
	}
	if got := credential.Scopes; len(got) != 1 || got[0] != "cerebro.cosmo.security.read" {
		t.Fatalf("Scopes = %#v, want [cerebro.cosmo.security.read]", got)
	}
	if got := credential.Roles; len(got) != 1 || got[0] != "cerebro.viewer" {
		t.Fatalf("Roles = %#v, want [cerebro.viewer]", got)
	}
}

func TestLoadParsesCapabilityTokenConfig(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_SECRETS", "secret-1, secret-1, secret-2")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Auth.CapabilityTokenSecrets; len(got) != 2 || got[0] != "secret-1" || got[1] != "secret-2" {
		t.Fatalf("CapabilityTokenSecrets = %#v, want [secret-1 secret-2]", got)
	}
	if cfg.Auth.CapabilityTokenAudience != "cerebro-api" {
		t.Fatalf("CapabilityTokenAudience = %q, want cerebro-api", cfg.Auth.CapabilityTokenAudience)
	}
}

func TestLoadParsesMCPOAuthConfig(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_SECRETS", "secret-1")
	t.Setenv("CEREBRO_PUBLIC_ORIGIN", "https://cerebro.example")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", StateStoreDriverPostgres)
	t.Setenv("CEREBRO_POSTGRES_DSN", "postgres://127.0.0.1:5432/cerebro?sslmode=disable")
	t.Setenv("CEREBRO_MCP_OAUTH_ENABLED", "true")
	t.Setenv("CEREBRO_MCP_OAUTH_CLIENTS_JSON", `[{"client_id":"droid","redirect_uris":["http://127.0.0.1/callback"],"public":true}]`)
	t.Setenv("CEREBRO_MCP_OAUTH_TENANT_ID", "writer")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER", "https://sso.example")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID", "writer-client")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET", "writer-secret")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI", "https://cerebro.example/oauth/callback")
	t.Setenv("CEREBRO_MCP_OAUTH_SECURITY_GROUPS", "secops,secops")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Auth.MCPOAuth.Enabled {
		t.Fatal("MCPOAuth.Enabled = false, want true")
	}
	if cfg.Auth.MCPOAuth.Issuer != "https://cerebro.example" || cfg.Auth.MCPOAuth.Resource != "https://cerebro.example/api/v1/mcp" {
		t.Fatalf("MCPOAuth issuer/resource = %#v", cfg.Auth.MCPOAuth)
	}
	if len(cfg.Auth.MCPOAuth.Clients) != 1 || cfg.Auth.MCPOAuth.Clients[0].ClientID != "droid" {
		t.Fatalf("MCPOAuth.Clients = %#v", cfg.Auth.MCPOAuth.Clients)
	}
	if cfg.Auth.MCPOAuth.DynamicClientRegistration {
		t.Fatal("MCPOAuth.DynamicClientRegistration = true, want false by default")
	}
	if cfg.Auth.MCPOAuth.RefreshTTL != 24*time.Hour {
		t.Fatalf("MCPOAuth.RefreshTTL = %v, want 24h", cfg.Auth.MCPOAuth.RefreshTTL)
	}
	if got := cfg.Auth.MCPOAuth.Upstream.SecurityGroups; len(got) != 1 || got[0] != "secops" {
		t.Fatalf("SecurityGroups = %#v, want [secops]", got)
	}
}

func TestLoadParsesMCPOAuthM2MClientAndEntitlements(t *testing.T) {
	setValidMCPOAuthEnv(t)
	t.Setenv("CEREBRO_MCP_OAUTH_CLIENTS_JSON", `[
		{"client_id":"droid","redirect_uris":["http://127.0.0.1/callback"],"public":true},
		{"client_id":"panopticon","client_secret":"secret","grant_types":["client_credentials"],"allowed_tenants":["writer"],"scopes":["cerebro.cosmo.security.read"],"roles":["cerebro.viewer"]}
	]`)
	t.Setenv("CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON", `[{"groups":["secops"],"allowed_tenants":["writer"],"scopes":["cerebro.cosmo.security.read"],"roles":["cerebro.viewer"]}]`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Auth.MCPOAuth.Clients[1].GrantTypes; len(got) != 1 || got[0] != "client_credentials" {
		t.Fatalf("M2M grant types = %#v", got)
	}
	if got := cfg.Auth.MCPOAuth.Clients[1].Roles; len(got) != 1 || got[0] != "cerebro.viewer" {
		t.Fatalf("M2M roles = %#v", got)
	}
	if len(cfg.Auth.MCPOAuth.Entitlements) != 1 || cfg.Auth.MCPOAuth.Entitlements[0].Groups[0] != "secops" {
		t.Fatalf("Entitlements = %#v", cfg.Auth.MCPOAuth.Entitlements)
	}
	if got := cfg.Auth.MCPOAuth.Entitlements[0].Roles; len(got) != 1 || got[0] != "cerebro.viewer" {
		t.Fatalf("Entitlement roles = %#v", got)
	}
}

func TestLoadRejectsMCPOAuthHTTPNonLoopbackURLs(t *testing.T) {
	for _, tt := range []struct {
		name  string
		key   string
		value string
	}{
		{name: "public origin", key: "CEREBRO_PUBLIC_ORIGIN", value: "http://cerebro.example"},
		{name: "upstream issuer", key: "CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER", value: "http://sso.example"},
		{name: "upstream redirect", key: "CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI", value: "http://cerebro.example/oauth/callback"},
		{name: "upstream token endpoint", key: "CEREBRO_MCP_OAUTH_UPSTREAM_TOKEN_ENDPOINT", value: "http://sso.example/oauth/token"},
		{name: "client redirect", key: "CEREBRO_MCP_OAUTH_CLIENTS_JSON", value: `[{"client_id":"droid","redirect_uris":["http://evil.example/callback"],"public":true}]`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setValidMCPOAuthEnv(t)
			t.Setenv(tt.key, tt.value)
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want MCP OAuth HTTPS requirement error")
			}
		})
	}
}

func TestLoadRejectsMCPOAuthPublicClientWithSecret(t *testing.T) {
	setValidMCPOAuthEnv(t)
	t.Setenv("CEREBRO_MCP_OAUTH_CLIENTS_JSON", `[{"client_id":"droid","client_secret":"secret","redirect_uris":["http://127.0.0.1/callback"],"public":true}]`)
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want public client secret rejection")
	}
}

func setValidMCPOAuthEnv(t *testing.T) {
	t.Helper()
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_SECRETS", "secret-1")
	t.Setenv("CEREBRO_PUBLIC_ORIGIN", "https://cerebro.example")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", StateStoreDriverPostgres)
	t.Setenv("CEREBRO_POSTGRES_DSN", "postgres://127.0.0.1:5432/cerebro?sslmode=disable")
	t.Setenv("CEREBRO_MCP_OAUTH_ENABLED", "true")
	t.Setenv("CEREBRO_MCP_OAUTH_CLIENTS_JSON", `[{"client_id":"droid","redirect_uris":["http://127.0.0.1/callback"],"public":true}]`)
	t.Setenv("CEREBRO_MCP_OAUTH_TENANT_ID", "writer")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER", "https://sso.example")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID", "writer-client")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET", "writer-secret")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI", "https://cerebro.example/oauth/callback")
	t.Setenv("CEREBRO_MCP_OAUTH_SECURITY_GROUPS", "secops")
}

func TestLoadRejectsMCPOAuthWithoutClientsWhenDCRDisabled(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_CAPABILITY_TOKEN_SECRETS", "secret-1")
	t.Setenv("CEREBRO_PUBLIC_ORIGIN", "https://cerebro.example")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", StateStoreDriverPostgres)
	t.Setenv("CEREBRO_POSTGRES_DSN", "postgres://127.0.0.1:5432/cerebro?sslmode=disable")
	t.Setenv("CEREBRO_MCP_OAUTH_ENABLED", "true")
	t.Setenv("CEREBRO_MCP_OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED", "false")
	t.Setenv("CEREBRO_MCP_OAUTH_TENANT_ID", "writer")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER", "https://sso.example")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID", "writer-client")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET", "writer-secret")
	t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI", "https://cerebro.example/oauth/callback")
	t.Setenv("CEREBRO_MCP_OAUTH_SECURITY_GROUPS", "secops")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want client/DCR requirement error")
	}
}

func TestLoadRejectsMCPOAuthWithoutProductionRequirements(t *testing.T) {
	for _, tt := range []struct {
		name  string
		unset string
		value string
	}{
		{name: "api auth", unset: "CEREBRO_API_AUTH_ENABLED", value: "false"},
		{name: "public origin", unset: "CEREBRO_PUBLIC_ORIGIN"},
		{name: "state store", unset: "CEREBRO_POSTGRES_DSN"},
		{name: "capability secret", unset: "CEREBRO_CAPABILITY_TOKEN_SECRETS"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clearDependencyEnv(t)
			t.Setenv("CEREBRO_API_AUTH_ENABLED", "true")
			t.Setenv("CEREBRO_CAPABILITY_TOKEN_SECRETS", "secret-1")
			t.Setenv("CEREBRO_PUBLIC_ORIGIN", "https://cerebro.example")
			t.Setenv("CEREBRO_STATE_STORE_DRIVER", StateStoreDriverPostgres)
			t.Setenv("CEREBRO_POSTGRES_DSN", "postgres://127.0.0.1:5432/cerebro?sslmode=disable")
			t.Setenv("CEREBRO_MCP_OAUTH_ENABLED", "true")
			t.Setenv("CEREBRO_MCP_OAUTH_CLIENTS_JSON", `[{"client_id":"droid","redirect_uris":["http://127.0.0.1/callback"],"public":true}]`)
			t.Setenv("CEREBRO_MCP_OAUTH_TENANT_ID", "writer")
			t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER", "https://sso.example")
			t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID", "writer-client")
			t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET", "writer-secret")
			t.Setenv("CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI", "https://cerebro.example/oauth/callback")
			t.Setenv("CEREBRO_MCP_OAUTH_SECURITY_GROUPS", "secops")
			t.Setenv(tt.unset, tt.value)

			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want MCP OAuth production requirement error")
			}
		})
	}
}

func TestLoadRejectsScopedCredentialWithoutTenant(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON", `[{"key":"token","scopes":["cerebro.cosmo.security.read"]}]`)

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsRoleCredentialWithoutTenant(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON", `[{"key":"token","roles":["cerebro.viewer"]}]`)

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsUnknownAPICredentialRole(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON", `[{"key":"token","tenant_id":"writer","roles":["cerebro.viewr"]}]`)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want unknown role error")
	}
	if !errors.Is(err, errUnknownRBACRole) {
		t.Fatalf("Load() error = %v, want unknown API credential role", err)
	}
}

func TestLoadRejectsUnknownMCPOAuthRoles(t *testing.T) {
	for _, tt := range []struct {
		name         string
		clientsJSON  string
		entitlesJSON string
	}{
		{
			name:        "client",
			clientsJSON: `[{"client_id":"panopticon","client_secret":"secret","grant_types":["client_credentials"],"tenant_id":"writer","roles":["cerebro.viewr"]}]`,
		},
		{
			name:         "entitlement",
			clientsJSON:  `[{"client_id":"droid","redirect_uris":["http://127.0.0.1/callback"],"public":true}]`,
			entitlesJSON: `[{"groups":["secops"],"tenant_id":"writer","roles":["cerebro.viewr"]}]`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setValidMCPOAuthEnv(t)
			t.Setenv("CEREBRO_MCP_OAUTH_CLIENTS_JSON", tt.clientsJSON)
			if tt.entitlesJSON != "" {
				t.Setenv("CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON", tt.entitlesJSON)
			}

			_, err := Load()
			if err == nil {
				t.Fatal("Load() error = nil, want unknown role error")
			}
			if !errors.Is(err, errUnknownRBACRole) {
				t.Fatalf("Load() error = %v, want unknown role rejection", err)
			}
		})
	}
}

func TestLoadRejectsMalformedStructuredAPICredentials(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "true")
	t.Setenv("CEREBRO_API_CREDENTIALS_JSON", `{"key":"token"}`)

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsInvalidAuthEnabledBool(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_API_AUTH_ENABLED", "maybe")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsLegacyKuzuPath(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_KUZU_PATH", "/tmp/cerebro.kuzu")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
	if !errors.Is(err, errLegacyKuzuPath) {
		t.Fatalf("Load() error = %v, want errLegacyKuzuPath", err)
	}
}

func TestLoadFromNeo4jEnv(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", GraphStoreDriverNeo4j)
	t.Setenv("CEREBRO_NEO4J_URI", "neo4j+s://example.databases.neo4j.io")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "neo4j")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "test-password")
	t.Setenv("CEREBRO_NEO4J_DATABASE", "cerebro")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.GraphStore.Driver != GraphStoreDriverNeo4j {
		t.Fatalf("GraphStore.Driver = %q, want %q", cfg.GraphStore.Driver, GraphStoreDriverNeo4j)
	}
	if cfg.GraphStore.Neo4jURI != "neo4j+s://example.databases.neo4j.io" {
		t.Fatalf("GraphStore.Neo4jURI = %q", cfg.GraphStore.Neo4jURI)
	}
	if cfg.GraphStore.Neo4jUsername != "neo4j" {
		t.Fatalf("GraphStore.Neo4jUsername = %q", cfg.GraphStore.Neo4jUsername)
	}
	if cfg.GraphStore.Neo4jPassword != "test-password" {
		t.Fatal("GraphStore.Neo4jPassword was not loaded")
	}
	if cfg.GraphStore.Neo4jDatabase != "cerebro" {
		t.Fatalf("GraphStore.Neo4jDatabase = %q", cfg.GraphStore.Neo4jDatabase)
	}
}

func TestLoadInfersNeo4jDriverFromURI(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", "")
	t.Setenv("CEREBRO_NEO4J_URI", "bolt://127.0.0.1:7687")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "neo4j")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "test-password")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.GraphStore.Driver != GraphStoreDriverNeo4j {
		t.Fatalf("GraphStore.Driver = %q, want %q", cfg.GraphStore.Driver, GraphStoreDriverNeo4j)
	}
}

func TestLoadRejectsMissingNeo4jURI(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", GraphStoreDriverNeo4j)
	t.Setenv("CEREBRO_NEO4J_URI", "")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "neo4j")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "test-password")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsMissingNeo4jUsername(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", GraphStoreDriverNeo4j)
	t.Setenv("CEREBRO_NEO4J_URI", "bolt://127.0.0.1:7687")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "test-password")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsMissingNeo4jPassword(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", GraphStoreDriverNeo4j)
	t.Setenv("CEREBRO_NEO4J_URI", "bolt://127.0.0.1:7687")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "neo4j")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsInvalidDuration(t *testing.T) {
	t.Setenv("CEREBRO_SHUTDOWN_TIMEOUT", "not-a-duration")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsNegativeJetStreamPublishMaxInFlight(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", AppendLogDriverJetStream)
	t.Setenv("CEREBRO_JETSTREAM_URL", "nats://127.0.0.1:4222")
	t.Setenv("CEREBRO_JETSTREAM_PUBLISH_MAX_IN_FLIGHT", "-1")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadInfersDriversFromURLs(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_SHUTDOWN_TIMEOUT", "")
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", "")
	t.Setenv("CEREBRO_JETSTREAM_URL", "nats://127.0.0.1:4222")
	t.Setenv("CEREBRO_JETSTREAM_SUBJECT_PREFIX", "")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", "")
	t.Setenv("CEREBRO_POSTGRES_DSN", "postgres://127.0.0.1:5432/cerebro?sslmode=disable")
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", "")
	t.Setenv("CEREBRO_NEO4J_URI", "bolt://127.0.0.1:7687")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "neo4j")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "test-password")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.AppendLog.Driver != AppendLogDriverJetStream {
		t.Fatalf("AppendLog.Driver = %q, want %q", cfg.AppendLog.Driver, AppendLogDriverJetStream)
	}
	if cfg.AppendLog.JetStreamSubjectPrefix != "events" {
		t.Fatalf("JetStreamSubjectPrefix = %q, want %q", cfg.AppendLog.JetStreamSubjectPrefix, "events")
	}
	if cfg.StateStore.Driver != StateStoreDriverPostgres {
		t.Fatalf("StateStore.Driver = %q, want %q", cfg.StateStore.Driver, StateStoreDriverPostgres)
	}
	if cfg.GraphStore.Driver != GraphStoreDriverNeo4j {
		t.Fatalf("GraphStore.Driver = %q, want %q", cfg.GraphStore.Driver, GraphStoreDriverNeo4j)
	}
}

func TestLoadInfersCacheDriverFromURL(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_CACHE_URL", "redis://127.0.0.1:6379")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Cache.Driver != CacheDriverRedis {
		t.Fatalf("Cache.Driver = %q, want %q", cfg.Cache.Driver, CacheDriverRedis)
	}
	if cfg.Cache.Namespace != "cerebro" {
		t.Fatalf("Cache.Namespace = %q, want cerebro", cfg.Cache.Namespace)
	}
}

func TestLoadRejectsMissingCacheURL(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_CACHE_MODE", CacheDriverRedis)
	t.Setenv("CEREBRO_CACHE_URL", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsUnsupportedCacheDriver(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_CACHE_MODE", "memcached")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsUnknownAppendLogDriver(t *testing.T) {
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", "unknown")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsMissingJetStreamURL(t *testing.T) {
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", AppendLogDriverJetStream)
	t.Setenv("CEREBRO_JETSTREAM_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsMissingPostgresDSN(t *testing.T) {
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", StateStoreDriverPostgres)
	t.Setenv("CEREBRO_POSTGRES_DSN", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsKuzuDriver(t *testing.T) {
	clearDependencyEnv(t)
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", "kuzu")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsUnsupportedGraphStoreDriver(t *testing.T) {
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", "alternate")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}
