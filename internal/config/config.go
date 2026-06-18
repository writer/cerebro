package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultHTTPAddr = ":8080"
const defaultShutdownTimeout = 10 * time.Second
const defaultJetStreamSubjectPrefix = "events"

const (
	defaultPostgresMaxOpenConns    = 25
	defaultPostgresMaxIdleConns    = 5
	defaultPostgresConnMaxLifetime = 5 * time.Minute
	defaultPostgresConnMaxIdleTime = time.Minute
	maxConfigFileBytes             = 4 << 20
)

const (
	AppendLogDriverJetStream = "jetstream"
	StateStoreDriverPostgres = "postgres"
	GraphStoreDriverNeo4j    = "neo4j"
	CacheDriverOff           = "off"
	CacheDriverMemory        = "memory"
	CacheDriverRedis         = "redis"
	CacheDriverValkey        = "valkey"
)

var (
	errConfigValueConflict     = errors.New("config value and file are both set")
	errInvalidOTLPEndpoint     = errors.New("invalid otlp endpoint")
	errLegacyKuzuPath          = errors.New("CEREBRO_KUZU_PATH is no longer supported")
	errUnsafeOTLPTransportMode = errors.New("unsafe otlp transport mode")
)

// Config is the minimal bootstrap configuration for the rewrite skeleton.
type Config struct {
	HTTPAddr              string
	ShutdownTimeout       time.Duration
	ImageTag              string
	DevMode               bool
	AppendLog             AppendLogConfig
	StateStore            StateStoreConfig
	GraphStore            GraphStoreConfig
	GraphAgentLLM         GraphAgentLLMConfig
	Cache                 CacheConfig
	Auth                  AuthConfig
	ConnectorCredentials  ConnectorCredentialConfig
	ConnectorSecretStores ConnectorSecretStoreConfig
	ConnectorAccess       ConnectorAccessConfig
	OTEL                  OpenTelemetryConfig
	RateLimit             RateLimitConfig
}

// RateLimitConfig controls global API rate limiting.
type RateLimitConfig struct {
	Enabled           bool
	RequestsPerSecond float64
	BurstSize         int
	// ExemptPaths are route patterns that bypass rate limiting (e.g., liveness, metrics)
	ExemptPaths []string
}

// AppendLogConfig selects and configures the append-log driver.
type AppendLogConfig struct {
	Driver                 string
	JetStreamURL           string
	JetStreamSubjectPrefix string
	JetStreamDrainTimeout  time.Duration
}

// StateStoreConfig selects and configures the current-state store driver.
type StateStoreConfig struct {
	Driver                  string
	PostgresDSN             string
	PostgresMaxOpenConns    int
	PostgresMaxIdleConns    int
	PostgresConnMaxLifetime time.Duration
	PostgresConnMaxIdleTime time.Duration
}

// GraphStoreConfig selects and configures the graph projection store driver.
type GraphStoreConfig struct {
	Driver            string
	Neo4jURI          string
	Neo4jUsername     string
	Neo4jPassword     string
	Neo4jDatabase     string
	Neo4jQueryTimeout time.Duration
}

// CacheConfig controls optional shared query/response caching.
type CacheConfig struct {
	Driver          string
	URL             string
	Namespace       string
	DefaultTTL      time.Duration
	StaleTTL        time.Duration
	MaxPayloadBytes int
}

// GraphAgentLLMConfig selects and configures the graph ask LLM adapter.
type GraphAgentLLMConfig struct {
	Provider         string
	Model            string
	SonnetModel      string
	OpusModel        string
	HaikuModel       string
	MaxTokens        int
	Temperature      float64
	OpenRouterAPIKey string
	BedrockRegion    string
}

// ConnectorCredentialConfig controls Cerebro-managed connector credential sealing.
type ConnectorCredentialConfig struct {
	Key               string
	TransitPrivateKey string
}

// ConnectorSecretStoreConfig controls operator-managed connector secret-store references.
type ConnectorSecretStoreConfig struct {
	Enabled           []string
	AWSSecretsManager AWSSecretsManagerStoreConfig
}

// ConnectorAccessConfig controls connector catalog visibility and setup gates.
type ConnectorAccessConfig struct {
	HiddenSources       []string
	RestrictedSources   []string
	RestrictionReason   string
	RequestAccessURL    string
	RequestAccessAction string
}

// AWSSecretsManagerStoreConfig controls AWS Secrets Manager reference resolution.
type AWSSecretsManagerStoreConfig struct {
	Region     string
	Profile    string
	RoleARN    string
	ExternalID string
	Endpoint   string
}

// OpenTelemetryConfig controls OTLP trace and metric export.
type OpenTelemetryConfig struct {
	Enabled         bool
	ServiceName     string
	Protocol        string
	Endpoint        string
	TracesEndpoint  string
	MetricsEndpoint string
	Headers         map[string]string
	Insecure        bool
	TraceSampleRate float64
	MetricInterval  time.Duration
}

// APIKey grants one bearer token access to the bootstrap API.
type APIKey struct {
	Key       string
	Principal string
	TenantID  string
}

// APICredential grants scoped bearer access with stable attribution metadata.
type APICredential struct {
	ID             string
	ClientID       string
	Name           string
	Kind           string
	Key            string
	KeySHA256      string
	Principal      string
	TenantID       string
	AllowedTenants []string
	Scopes         []string
	Roles          []string
}

// AuthConfig controls optional API authentication and tenant scoping.
type AuthConfig struct {
	Enabled                 bool
	APIKeys                 []APIKey
	APICredentials          []APICredential
	CapabilityTokenSecrets  []string
	CapabilityTokenAudience string
	AllowedTenants          []string
	DeviceAuth              DeviceAuthConfig
	MCPOAuth                MCPOAuthConfig
	RequestOrigin           RequestOriginConfig
}

// MCPOAuthClient is one OAuth client allowed to request MCP access tokens from
// Cerebro. Redirect URI comparison is exact-match.
type MCPOAuthClient struct {
	ClientID           string   `json:"client_id"`
	ClientSecret       string   `json:"client_secret,omitempty"`
	ClientSecretSHA256 string   `json:"client_secret_sha256,omitempty"`
	Name               string   `json:"name,omitempty"`
	RedirectURIs       []string `json:"redirect_uris"`
	GrantTypes         []string `json:"grant_types,omitempty"`
	Public             bool     `json:"public,omitempty"`
	TenantID           string   `json:"tenant_id,omitempty"`
	AllowedTenants     []string `json:"allowed_tenants,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
	Roles              []string `json:"roles,omitempty"`
	Groups             []string `json:"groups,omitempty"`
}

// MCPOAuthEntitlement maps an authenticated upstream user/client to the
// tenants and scopes Cerebro may place into OAuth-issued MCP tokens.
type MCPOAuthEntitlement struct {
	Subject        string   `json:"subject,omitempty"`
	Email          string   `json:"email,omitempty"`
	ClientID       string   `json:"client_id,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	TenantID       string   `json:"tenant_id,omitempty"`
	AllowedTenants []string `json:"allowed_tenants,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	Roles          []string `json:"roles,omitempty"`
}

// MCPOAuthConfig configures Cerebro's OAuth 2.1 authorization-server surface
// for MCP clients. Cerebro acts as the authorization server to MCP clients and
// delegates human login to the upstream Writer OIDC provider.
type MCPOAuthConfig struct {
	Enabled                   bool
	Issuer                    string
	Resource                  string
	Clients                   []MCPOAuthClient
	DynamicClientRegistration bool
	AccessTTL                 time.Duration
	RefreshTTL                time.Duration
	CodeTTL                   time.Duration
	StateTTL                  time.Duration
	TenantID                  string
	AllowedTenants            []string
	Entitlements              []MCPOAuthEntitlement
	Upstream                  MCPOAuthUpstreamConfig
}

// MCPOAuthUpstreamConfig describes the upstream Writer OIDC application that
// authenticates the human before Cerebro issues an MCP capability token.
type MCPOAuthUpstreamConfig struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	ClientID              string
	ClientSecret          string
	RedirectURI           string
	Scopes                []string
	GroupsClaim           string
	SecurityGroups        []string
}

// RequestOriginConfig controls how bootstrap reconstructs client IPs and public
// request URLs when requests traverse explicitly trusted reverse proxies.
type RequestOriginConfig struct {
	PublicOrigin      string
	TrustedProxyCIDRs []string
	TrustedProxyCount int
}

// DeviceAuthSigningKey is one Ed25519 keypair the issuer can sign with. This
// bootstrap path requires PrivatePEM on the current signing key; external KMS
// signing is intentionally unsupported until a signer implementation is wired.
type DeviceAuthSigningKey struct {
	KID        string `json:"kid"`
	PublicPEM  string `json:"public_pem"`
	PrivatePEM string `json:"private_pem,omitempty"`
}

// DeviceAuthConfig configures the SeCheck device-auth surface. The surface is
// disabled when Enabled is false.
type DeviceAuthConfig struct {
	Enabled                     bool
	Issuer                      string
	Audience                    string
	AccessTTL                   time.Duration
	RefreshTTL                  time.Duration
	BootstrapTokenTTL           time.Duration
	IdempotencyTTL              time.Duration
	ClockSkew                   time.Duration
	SigningKeys                 []DeviceAuthSigningKey
	CurrentKID                  string
	EnrollPerIPRatePerSecond    float64
	EnrollPerIPBurst            int
	TokenPerDeviceRatePerSecond float64
	TokenPerDeviceBurst         int
	// DPoPProofTTL bounds how long an RFC 9449 DPoP proof JWT remains
	// valid; defaults to 60s if zero.
	DPoPProofTTL time.Duration
	// ReplicaCount is the number of concurrently serving bootstrap API
	// replicas for this device-auth deployment. Values greater than one
	// require shared DPoP replay state.
	ReplicaCount int
	// RiskElevatedThreshold and RiskHighThreshold map composite risk
	// scores (0..100) to "elevated" and "high" levels. Defaults are 30
	// and 70.
	RiskElevatedThreshold int
	RiskHighThreshold     int
	// Attestation configures the device-bound proof verifiers wired into
	// Service.Enroll.
	Attestation DeviceAuthAttestationConfig
}

// DeviceAuthAttestationConfig configures the Phase-2 device-bound proof
// verifiers. When Required is true, enroll requests must carry a non-empty
// attestation statement; when false, a missing statement returns a
// software-assurance result.
type DeviceAuthAttestationConfig struct {
	Required bool
	Apple    DeviceAuthAppleConfig
}

// DeviceAuthAppleConfig configures the Apple App Attest verifier.
type DeviceAuthAppleConfig struct {
	TeamID    string
	BundleIDs []string
}

// Load reads and validates process configuration.
func Load() (Config, error) {
	if strings.TrimSpace(os.Getenv("CEREBRO_KUZU_PATH")) != "" {
		return Config{}, fmt.Errorf("%w; configure Neo4j with CEREBRO_NEO4J_URI, CEREBRO_NEO4J_USERNAME, and CEREBRO_NEO4J_PASSWORD", errLegacyKuzuPath)
	}
	apiCredentialsRaw, err := readConfigValue("CEREBRO_API_CREDENTIALS_JSON")
	if err != nil {
		return Config{}, err
	}
	apiCredentials, err := parseAPICredentials(apiCredentialsRaw)
	if err != nil {
		return Config{}, err
	}
	apiKeysRaw, err := readConfigValue("CEREBRO_API_KEYS")
	if err != nil {
		return Config{}, err
	}
	capabilityTokenSecretsRaw, err := readConfigValue("CEREBRO_CAPABILITY_TOKEN_SECRETS")
	if err != nil {
		return Config{}, err
	}
	connectorCredentialKey, err := readConfigValue("CEREBRO_CONNECTOR_CREDENTIAL_KEY")
	if err != nil {
		return Config{}, err
	}
	connectorCredentialTransitPrivateKey, err := readConfigValue("CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY")
	if err != nil {
		return Config{}, err
	}
	connectorSecretStoresRaw, err := readConfigValue("CEREBRO_CONNECTOR_SECRET_STORES")
	if err != nil {
		return Config{}, err
	}
	devMode, err := parseBoolEnv("CEREBRO_DEV_MODE")
	if err != nil {
		return Config{}, err
	}
	devModeAck, err := parseBoolEnv("CEREBRO_DEV_MODE_ACK")
	if err != nil {
		return Config{}, err
	}
	if devMode && !devModeAck {
		return Config{}, fmt.Errorf("CEREBRO_DEV_MODE requires CEREBRO_DEV_MODE_ACK=1")
	}
	cfg := Config{
		HTTPAddr:        strings.TrimSpace(os.Getenv("CEREBRO_HTTP_ADDR")),
		ShutdownTimeout: defaultShutdownTimeout,
		ImageTag:        strings.TrimSpace(os.Getenv("CEREBRO_IMAGE_TAG")),
		DevMode:         devMode,
		AppendLog: AppendLogConfig{
			Driver:                 strings.TrimSpace(os.Getenv("CEREBRO_APPEND_LOG_DRIVER")),
			JetStreamURL:           strings.TrimSpace(os.Getenv("CEREBRO_JETSTREAM_URL")),
			JetStreamSubjectPrefix: strings.TrimSpace(os.Getenv("CEREBRO_JETSTREAM_SUBJECT_PREFIX")),
		},
		StateStore: StateStoreConfig{
			Driver:      strings.TrimSpace(os.Getenv("CEREBRO_STATE_STORE_DRIVER")),
			PostgresDSN: strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN")),
		},
		GraphStore: GraphStoreConfig{
			Driver:        strings.TrimSpace(os.Getenv("CEREBRO_GRAPH_STORE_DRIVER")),
			Neo4jURI:      strings.TrimSpace(os.Getenv("CEREBRO_NEO4J_URI")),
			Neo4jUsername: strings.TrimSpace(os.Getenv("CEREBRO_NEO4J_USERNAME")),
			Neo4jPassword: strings.TrimSpace(os.Getenv("CEREBRO_NEO4J_PASSWORD")),
			Neo4jDatabase: strings.TrimSpace(os.Getenv("CEREBRO_NEO4J_DATABASE")),
		},
		Cache: CacheConfig{
			Driver:    strings.ToLower(strings.TrimSpace(os.Getenv("CEREBRO_CACHE_MODE"))),
			URL:       strings.TrimSpace(os.Getenv("CEREBRO_CACHE_URL")),
			Namespace: strings.TrimSpace(os.Getenv("CEREBRO_CACHE_NAMESPACE")),
		},
		GraphAgentLLM: GraphAgentLLMConfig{
			Provider:      strings.TrimSpace(os.Getenv("CEREBRO_GRAPH_AGENT_LLM_PROVIDER")),
			Model:         strings.TrimSpace(os.Getenv("CEREBRO_GRAPH_AGENT_LLM_MODEL")),
			SonnetModel:   strings.TrimSpace(os.Getenv("CEREBRO_GRAPH_AGENT_LLM_MODEL_SONNET")),
			OpusModel:     strings.TrimSpace(os.Getenv("CEREBRO_GRAPH_AGENT_LLM_MODEL_OPUS")),
			HaikuModel:    strings.TrimSpace(os.Getenv("CEREBRO_GRAPH_AGENT_LLM_MODEL_HAIKU")),
			BedrockRegion: strings.TrimSpace(os.Getenv("CEREBRO_BEDROCK_REGION")),
		},
		ConnectorCredentials: ConnectorCredentialConfig{
			Key:               connectorCredentialKey,
			TransitPrivateKey: connectorCredentialTransitPrivateKey,
		},
		ConnectorSecretStores: ConnectorSecretStoreConfig{
			Enabled: parseCSV(connectorSecretStoresRaw),
			AWSSecretsManager: AWSSecretsManagerStoreConfig{
				Region:     strings.TrimSpace(os.Getenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_REGION")),
				Profile:    strings.TrimSpace(os.Getenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_PROFILE")),
				RoleARN:    strings.TrimSpace(os.Getenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_ROLE_ARN")),
				ExternalID: strings.TrimSpace(os.Getenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_EXTERNAL_ID")),
				Endpoint:   strings.TrimSpace(os.Getenv("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_ENDPOINT")),
			},
		},
		ConnectorAccess: ConnectorAccessConfig{
			HiddenSources:       parseCSV(os.Getenv("CEREBRO_CONNECTOR_HIDDEN_SOURCES")),
			RestrictedSources:   parseCSV(os.Getenv("CEREBRO_CONNECTOR_RESTRICTED_SOURCES")),
			RestrictionReason:   strings.TrimSpace(os.Getenv("CEREBRO_CONNECTOR_RESTRICTION_REASON")),
			RequestAccessURL:    strings.TrimSpace(os.Getenv("CEREBRO_CONNECTOR_REQUEST_ACCESS_URL")),
			RequestAccessAction: strings.TrimSpace(os.Getenv("CEREBRO_CONNECTOR_REQUEST_ACCESS_ACTION")),
		},
		OTEL: OpenTelemetryConfig{
			ServiceName:     strings.TrimSpace(os.Getenv("CEREBRO_OTEL_SERVICE_NAME")),
			Protocol:        strings.TrimSpace(os.Getenv("CEREBRO_OTEL_EXPORTER_OTLP_PROTOCOL")),
			Endpoint:        strings.TrimSpace(os.Getenv("CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT")),
			TracesEndpoint:  strings.TrimSpace(os.Getenv("CEREBRO_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")),
			MetricsEndpoint: strings.TrimSpace(os.Getenv("CEREBRO_OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")),
		},
		Auth: AuthConfig{
			APIKeys:                 parseAPIKeys(apiKeysRaw),
			APICredentials:          apiCredentials,
			CapabilityTokenSecrets:  parseCSV(capabilityTokenSecretsRaw),
			CapabilityTokenAudience: strings.TrimSpace(os.Getenv("CEREBRO_CAPABILITY_TOKEN_AUDIENCE")),
			AllowedTenants:          parseCSV(os.Getenv("CEREBRO_ALLOWED_TENANTS")),
			RequestOrigin: RequestOriginConfig{
				PublicOrigin:      strings.TrimRight(strings.TrimSpace(os.Getenv("CEREBRO_PUBLIC_ORIGIN")), "/"),
				TrustedProxyCIDRs: parseCSV(os.Getenv("CEREBRO_TRUSTED_PROXY_CIDRS")),
			},
		},
	}
	authEnabled, err := parseBoolEnvDefault("CEREBRO_API_AUTH_ENABLED", !cfg.DevMode)
	if err != nil {
		return Config{}, err
	}
	cfg.Auth.Enabled = authEnabled
	if cfg.DevMode {
		cfg.Auth.Enabled = false
	}
	otelEnabled, err := parseBoolEnv("CEREBRO_OTEL_ENABLED")
	if err != nil {
		return Config{}, err
	}
	cfg.OTEL.Enabled = otelEnabled || (!envHasValue("CEREBRO_OTEL_ENABLED") && cfg.OTEL.hasExporterConfig())
	if cfg.OTEL.Insecure, err = parseBoolEnv("CEREBRO_OTEL_EXPORTER_OTLP_INSECURE"); err != nil {
		return Config{}, err
	}
	if cfg.OTEL.TraceSampleRate, err = parseFloatEnv("CEREBRO_OTEL_TRACES_SAMPLE_RATE", 1); err != nil {
		return Config{}, err
	}
	if cfg.OTEL.TraceSampleRate < 0 || cfg.OTEL.TraceSampleRate > 1 {
		return Config{}, fmt.Errorf("CEREBRO_OTEL_TRACES_SAMPLE_RATE must be between 0 and 1")
	}
	if cfg.OTEL.MetricInterval, err = parseDurationEnv("CEREBRO_OTEL_METRICS_EXPORT_INTERVAL", time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.OTEL.MetricInterval <= 0 {
		return Config{}, fmt.Errorf("CEREBRO_OTEL_METRICS_EXPORT_INTERVAL must be greater than zero")
	}
	if cfg.OTEL.Headers, err = parseKeyValueHeaderEnv("CEREBRO_OTEL_EXPORTER_OTLP_HEADERS"); err != nil {
		return Config{}, err
	}
	if cfg.OTEL.Protocol == "" {
		cfg.OTEL.Protocol = "http/protobuf"
	}
	switch cfg.OTEL.Protocol {
	case "grpc", "http/protobuf":
	default:
		return Config{}, fmt.Errorf("unsupported CEREBRO_OTEL_EXPORTER_OTLP_PROTOCOL %q", cfg.OTEL.Protocol)
	}
	if err := validateOpenTelemetryEndpoints(cfg.OTEL); err != nil {
		return Config{}, err
	}
	if cfg.Auth.RequestOrigin.TrustedProxyCount, err = parseIntEnv("CEREBRO_TRUSTED_PROXY_COUNT", 0); err != nil {
		return Config{}, err
	}
	if cfg.Auth.RequestOrigin.TrustedProxyCount < 0 {
		return Config{}, fmt.Errorf("CEREBRO_TRUSTED_PROXY_COUNT must be greater than or equal to zero")
	}
	if err := validateRequestOriginConfig(cfg.Auth.RequestOrigin); err != nil {
		return Config{}, err
	}
	if len(cfg.Auth.CapabilityTokenSecrets) > 0 && cfg.Auth.CapabilityTokenAudience == "" {
		cfg.Auth.CapabilityTokenAudience = "cerebro-api"
	}
	mcpOAuth, err := loadMCPOAuthConfig(cfg.Auth.RequestOrigin.PublicOrigin)
	if err != nil {
		return Config{}, err
	}
	cfg.Auth.MCPOAuth = mcpOAuth
	deviceAuth, err := loadDeviceAuthConfig()
	if err != nil {
		return Config{}, err
	}
	cfg.Auth.DeviceAuth = deviceAuth
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = defaultHTTPAddr
	}
	if cfg.GraphAgentLLM.MaxTokens, err = parseIntEnv("CEREBRO_GRAPH_AGENT_LLM_MAX_TOKENS", 0); err != nil {
		return Config{}, err
	}
	if cfg.GraphAgentLLM.Temperature, err = parseFloatEnv("CEREBRO_GRAPH_AGENT_LLM_TEMPERATURE", 0); err != nil {
		return Config{}, err
	}
	if cfg.AppendLog.JetStreamDrainTimeout, err = parseDurationEnv("CEREBRO_JETSTREAM_DRAIN_TIMEOUT", 0); err != nil {
		return Config{}, err
	}
	if cfg.StateStore.PostgresMaxOpenConns, err = parseIntEnv("CEREBRO_POSTGRES_MAX_OPEN_CONNS", 0); err != nil {
		return Config{}, err
	}
	if cfg.StateStore.PostgresMaxIdleConns, err = parseIntEnv("CEREBRO_POSTGRES_MAX_IDLE_CONNS", 0); err != nil {
		return Config{}, err
	}
	if cfg.StateStore.PostgresConnMaxLifetime, err = parseDurationEnv("CEREBRO_POSTGRES_CONN_MAX_LIFETIME", 0); err != nil {
		return Config{}, err
	}
	if cfg.StateStore.PostgresConnMaxIdleTime, err = parseDurationEnv("CEREBRO_POSTGRES_CONN_MAX_IDLE_TIME", 0); err != nil {
		return Config{}, err
	}
	cfg.StateStore = ApplyPostgresPoolDefaults(cfg.StateStore)
	if cfg.GraphStore.Neo4jQueryTimeout, err = parseDurationEnv("CEREBRO_NEO4J_QUERY_TIMEOUT", 0); err != nil {
		return Config{}, err
	}
	if cfg.Cache.DefaultTTL, err = parseDurationEnv("CEREBRO_CACHE_DEFAULT_TTL", 30*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.Cache.StaleTTL, err = parseDurationEnv("CEREBRO_CACHE_STALE_TTL", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.Cache.MaxPayloadBytes, err = parseIntEnv("CEREBRO_CACHE_MAX_PAYLOAD_BYTES", 1<<20); err != nil {
		return Config{}, err
	}
	if cfg.Cache.MaxPayloadBytes <= 0 {
		return Config{}, fmt.Errorf("CEREBRO_CACHE_MAX_PAYLOAD_BYTES must be greater than zero")
	}
	if cfg.Cache.Namespace == "" {
		cfg.Cache.Namespace = "cerebro"
	}
	if enabled, err := parseBoolEnv("CEREBRO_CACHE_ENABLED"); err != nil {
		return Config{}, err
	} else if envHasValue("CEREBRO_CACHE_ENABLED") && !enabled {
		cfg.Cache.Driver = CacheDriverOff
	} else if envHasValue("CEREBRO_CACHE_ENABLED") && enabled && cfg.Cache.Driver == "" {
		cfg.Cache.Driver = CacheDriverRedis
	}
	if cfg.Cache.Driver == "" {
		if cfg.Cache.URL != "" {
			cfg.Cache.Driver = CacheDriverRedis
		} else {
			cfg.Cache.Driver = CacheDriverOff
		}
	}
	switch cfg.Cache.Driver {
	case CacheDriverOff:
	case CacheDriverMemory:
	case CacheDriverRedis, CacheDriverValkey:
		if cfg.Cache.URL == "" {
			return Config{}, fmt.Errorf("CEREBRO_CACHE_URL is required when CEREBRO_CACHE_MODE=%q", cfg.Cache.Driver)
		}
	default:
		return Config{}, fmt.Errorf("unsupported CEREBRO_CACHE_MODE %q", cfg.Cache.Driver)
	}
	cfg.GraphAgentLLM.OpenRouterAPIKey = strings.TrimSpace(os.Getenv("CEREBRO_OPENROUTER_API_KEY"))
	if raw, ok := os.LookupEnv("CEREBRO_SHUTDOWN_TIMEOUT"); ok && strings.TrimSpace(raw) != "" {
		duration, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil {
			return Config{}, fmt.Errorf("parse CEREBRO_SHUTDOWN_TIMEOUT: %w", err)
		}
		cfg.ShutdownTimeout = duration
	}
	if cfg.ShutdownTimeout <= 0 {
		return Config{}, fmt.Errorf("CEREBRO_SHUTDOWN_TIMEOUT must be greater than zero")
	}
	if cfg.AppendLog.Driver == "" && cfg.AppendLog.JetStreamURL != "" {
		cfg.AppendLog.Driver = AppendLogDriverJetStream
	}
	switch cfg.AppendLog.Driver {
	case "":
	case AppendLogDriverJetStream:
		if cfg.AppendLog.JetStreamURL == "" {
			return Config{}, fmt.Errorf("CEREBRO_JETSTREAM_URL is required when CEREBRO_APPEND_LOG_DRIVER=%q", AppendLogDriverJetStream)
		}
		if cfg.AppendLog.JetStreamSubjectPrefix == "" {
			cfg.AppendLog.JetStreamSubjectPrefix = defaultJetStreamSubjectPrefix
		}
	default:
		return Config{}, fmt.Errorf("unsupported CEREBRO_APPEND_LOG_DRIVER %q", cfg.AppendLog.Driver)
	}
	if cfg.StateStore.Driver == "" && cfg.StateStore.PostgresDSN != "" {
		cfg.StateStore.Driver = StateStoreDriverPostgres
	}
	switch cfg.StateStore.Driver {
	case "":
	case StateStoreDriverPostgres:
		if cfg.StateStore.PostgresDSN == "" {
			return Config{}, fmt.Errorf("CEREBRO_POSTGRES_DSN is required when CEREBRO_STATE_STORE_DRIVER=%q", StateStoreDriverPostgres)
		}
	default:
		return Config{}, fmt.Errorf("unsupported CEREBRO_STATE_STORE_DRIVER %q", cfg.StateStore.Driver)
	}
	if cfg.GraphStore.Driver == "" && cfg.GraphStore.Neo4jURI != "" {
		cfg.GraphStore.Driver = GraphStoreDriverNeo4j
	}
	switch cfg.GraphStore.Driver {
	case "":
	case GraphStoreDriverNeo4j:
		if cfg.GraphStore.Neo4jURI == "" {
			return Config{}, fmt.Errorf("CEREBRO_NEO4J_URI is required when CEREBRO_GRAPH_STORE_DRIVER=%q", GraphStoreDriverNeo4j)
		}
		if cfg.GraphStore.Neo4jUsername == "" {
			return Config{}, fmt.Errorf("CEREBRO_NEO4J_USERNAME is required when CEREBRO_GRAPH_STORE_DRIVER=%q", GraphStoreDriverNeo4j)
		}
		if cfg.GraphStore.Neo4jPassword == "" {
			return Config{}, fmt.Errorf("CEREBRO_NEO4J_PASSWORD is required when CEREBRO_GRAPH_STORE_DRIVER=%q", GraphStoreDriverNeo4j)
		}
	default:
		return Config{}, fmt.Errorf("unsupported CEREBRO_GRAPH_STORE_DRIVER %q", cfg.GraphStore.Driver)
	}
	if cfg.Auth.MCPOAuth.Enabled {
		if !cfg.Auth.Enabled {
			return Config{}, fmt.Errorf("CEREBRO_API_AUTH_ENABLED=true is required when CEREBRO_MCP_OAUTH_ENABLED=true")
		}
		if cfg.Auth.RequestOrigin.PublicOrigin == "" {
			return Config{}, fmt.Errorf("CEREBRO_PUBLIC_ORIGIN is required when CEREBRO_MCP_OAUTH_ENABLED=true")
		}
		if cfg.StateStore.Driver != StateStoreDriverPostgres {
			return Config{}, fmt.Errorf("CEREBRO_STATE_STORE_DRIVER=postgres and CEREBRO_POSTGRES_DSN are required when CEREBRO_MCP_OAUTH_ENABLED=true")
		}
		if len(cfg.Auth.CapabilityTokenSecrets) == 0 {
			return Config{}, fmt.Errorf("CEREBRO_CAPABILITY_TOKEN_SECRETS is required when CEREBRO_MCP_OAUTH_ENABLED=true")
		}
	}

	// Rate limiting configuration
	if cfg.RateLimit.Enabled, err = parseBoolEnvDefault("CEREBRO_RATE_LIMIT_ENABLED", !cfg.DevMode); err != nil {
		return Config{}, err
	}
	if cfg.DevMode {
		cfg.RateLimit.Enabled = false
	}
	if cfg.RateLimit.RequestsPerSecond, err = parseFloatEnv("CEREBRO_RATE_LIMIT_RPS", 100); err != nil {
		return Config{}, err
	}
	if cfg.RateLimit.BurstSize, err = parseIntEnv("CEREBRO_RATE_LIMIT_BURST", 150); err != nil {
		return Config{}, err
	}
	cfg.RateLimit.ExemptPaths = parseCSV(os.Getenv("CEREBRO_RATE_LIMIT_EXEMPT_PATHS"))
	if len(cfg.RateLimit.ExemptPaths) == 0 {
		cfg.RateLimit.ExemptPaths = []string{"/healthz", "/livez", "/metrics", "/.well-known/"}
	}

	return cfg, nil
}

func ApplyPostgresPoolDefaults(cfg StateStoreConfig) StateStoreConfig {
	if cfg.PostgresMaxOpenConns == 0 {
		cfg.PostgresMaxOpenConns = defaultPostgresMaxOpenConns
	}
	if cfg.PostgresMaxIdleConns == 0 {
		cfg.PostgresMaxIdleConns = defaultPostgresMaxIdleConns
	}
	if cfg.PostgresMaxIdleConns > cfg.PostgresMaxOpenConns {
		cfg.PostgresMaxIdleConns = cfg.PostgresMaxOpenConns
	}
	if cfg.PostgresConnMaxLifetime == 0 {
		cfg.PostgresConnMaxLifetime = defaultPostgresConnMaxLifetime
	}
	if cfg.PostgresConnMaxIdleTime == 0 {
		cfg.PostgresConnMaxIdleTime = defaultPostgresConnMaxIdleTime
	}
	return cfg
}

func (cfg AuthConfig) HasCredentialMaterial() bool {
	return len(cfg.APIKeys) > 0 || len(cfg.APICredentials) > 0 || len(cfg.CapabilityTokenSecrets) > 0
}

func readConfigValue(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	filePath := strings.TrimSpace(os.Getenv(name + "_FILE"))
	if value != "" && filePath != "" {
		return "", fmt.Errorf("%w: %s and %s_FILE", errConfigValueConflict, name, name)
	}
	if filePath == "" {
		return value, nil
	}
	// #nosec G304 G703 -- file path is an operator-configured mounted secret path.
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	if len(data) > maxConfigFileBytes {
		return "", fmt.Errorf("%s_FILE exceeds %d bytes", name, maxConfigFileBytes)
	}
	return strings.TrimSpace(string(data)), nil
}

func validateRequestOriginConfig(cfg RequestOriginConfig) error {
	if raw := strings.TrimSpace(cfg.PublicOrigin); raw != "" {
		parsed, err := url.Parse(strings.TrimRight(raw, "/"))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("CEREBRO_PUBLIC_ORIGIN must be an http(s) origin")
		}
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return fmt.Errorf("CEREBRO_PUBLIC_ORIGIN must use http or https")
		}
		if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Trim(parsed.Path, "/") != "" {
			return fmt.Errorf("CEREBRO_PUBLIC_ORIGIN must not include user info, path, query, or fragment")
		}
	}
	for _, rawCIDR := range cfg.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(rawCIDR)); err != nil {
			return fmt.Errorf("CEREBRO_TRUSTED_PROXY_CIDRS contains invalid CIDR %q: %w", rawCIDR, err)
		}
	}
	return nil
}

func (cfg OpenTelemetryConfig) hasExporterConfig() bool {
	return strings.TrimSpace(cfg.Endpoint) != "" || strings.TrimSpace(cfg.TracesEndpoint) != "" || strings.TrimSpace(cfg.MetricsEndpoint) != ""
}

func validateOpenTelemetryEndpoints(cfg OpenTelemetryConfig) error {
	for _, endpoint := range []struct {
		name  string
		value string
	}{
		{name: "CEREBRO_OTEL_EXPORTER_OTLP_ENDPOINT", value: cfg.Endpoint},
		{name: "CEREBRO_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", value: cfg.TracesEndpoint},
		{name: "CEREBRO_OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", value: cfg.MetricsEndpoint},
	} {
		raw := strings.TrimSpace(endpoint.value)
		if raw == "" {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Hostname() == "" {
			return fmt.Errorf("%w: %s must be an absolute http(s) URL", errInvalidOTLPEndpoint, endpoint.name)
		}
		if parsed.User != nil {
			return fmt.Errorf("%w: %s must not include user info", errInvalidOTLPEndpoint, endpoint.name)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("%w: %s must use http or https", errInvalidOTLPEndpoint, endpoint.name)
		}
		loopback := isLoopbackHost(parsed.Hostname())
		if parsed.Scheme == "http" && (!cfg.Insecure || !loopback) {
			return fmt.Errorf("%w: %s plain HTTP OTLP endpoints are only allowed for loopback collectors with CEREBRO_OTEL_EXPORTER_OTLP_INSECURE=true", errUnsafeOTLPTransportMode, endpoint.name)
		}
		if cfg.Insecure && (parsed.Scheme != "http" || !loopback) {
			return fmt.Errorf("%w: CEREBRO_OTEL_EXPORTER_OTLP_INSECURE is only allowed with loopback HTTP OTLP endpoints", errUnsafeOTLPTransportMode)
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	normalized := strings.ToLower(strings.TrimSpace(host))
	if normalized == "localhost" {
		return true
	}
	ip := net.ParseIP(normalized)
	return ip != nil && ip.IsLoopback()
}

func envHasValue(name string) bool {
	raw, ok := os.LookupEnv(name)
	return ok && strings.TrimSpace(raw) != ""
}

func parseBoolEnv(name string) (bool, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "t", "true", "y", "yes", "on":
		return true, nil
	case "0", "f", "false", "n", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be a boolean", name)
	}
}

func parseBoolEnvDefault(name string, defaultValue bool) (bool, error) {
	if !envHasValue(name) {
		return defaultValue, nil
	}
	return parseBoolEnv(name)
}

func parseIntEnv(name string, defaultValue int) (int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return defaultValue, nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	if value < 0 {
		return 0, fmt.Errorf("%s must be greater than or equal to zero", name)
	}
	return value, nil
}

func parseFloatEnv(name string, defaultValue float64) (float64, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return defaultValue, nil
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	if value < 0 {
		return 0, fmt.Errorf("%s must be greater than or equal to zero", name)
	}
	return value, nil
}

func parseKeyValueHeaderEnv(name string) (map[string]string, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, nil
	}
	headers := map[string]string{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		key, value, ok := strings.Cut(entry, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" {
			return nil, fmt.Errorf("%s must contain comma-separated key=value entries", name)
		}
		headers[key] = value
	}
	return headers, nil
}

func parseCSV(raw string) []string {
	seen := map[string]struct{}{}
	var values []string
	for _, item := range strings.Split(raw, ",") {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func normalizeStringSlice(values []string) []string {
	return parseCSV(strings.Join(values, ","))
}

func parseAPIKeys(raw string) []APIKey {
	var keys []APIKey
	for _, item := range strings.Split(raw, ",") {
		parts := strings.Split(strings.TrimSpace(item), ":")
		if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
			continue
		}
		key := APIKey{Key: strings.TrimSpace(parts[0])}
		if len(parts) > 1 {
			key.Principal = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			key.TenantID = strings.TrimSpace(parts[2])
		}
		keys = append(keys, key)
	}
	return keys
}

func parseAPICredentials(raw string) ([]APICredential, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	type credentialJSON struct {
		ID             string   `json:"id"`
		CredentialID   string   `json:"credential_id"`
		ClientID       string   `json:"client_id"`
		Name           string   `json:"name"`
		Kind           string   `json:"kind"`
		Key            string   `json:"key"`
		KeySHA256      string   `json:"key_sha256"`
		Principal      string   `json:"principal"`
		TenantID       string   `json:"tenant_id"`
		AllowedTenants []string `json:"allowed_tenants"`
		Scopes         []string `json:"scopes"`
		Roles          []string `json:"roles"`
	}
	var entries []credentialJSON
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("parse CEREBRO_API_CREDENTIALS_JSON: %w", err)
	}
	credentials := make([]APICredential, 0, len(entries))
	for index, entry := range entries {
		credential := APICredential{
			ID:             strings.TrimSpace(firstNonEmpty(entry.CredentialID, entry.ID)),
			ClientID:       strings.TrimSpace(entry.ClientID),
			Name:           strings.TrimSpace(entry.Name),
			Kind:           strings.TrimSpace(entry.Kind),
			Key:            strings.TrimSpace(entry.Key),
			KeySHA256:      strings.ToLower(strings.TrimSpace(entry.KeySHA256)),
			Principal:      strings.TrimSpace(entry.Principal),
			TenantID:       strings.TrimSpace(entry.TenantID),
			AllowedTenants: normalizeStringSlice(entry.AllowedTenants),
			Scopes:         normalizeStringSlice(entry.Scopes),
			Roles:          normalizeStringSlice(entry.Roles),
		}
		if credential.Key == "" && credential.KeySHA256 == "" {
			return nil, fmt.Errorf("CEREBRO_API_CREDENTIALS_JSON[%d] must set key or key_sha256", index)
		}
		if (len(credential.Scopes) > 0 || len(credential.Roles) > 0) && credential.TenantID == "" && len(credential.AllowedTenants) == 0 {
			return nil, fmt.Errorf("CEREBRO_API_CREDENTIALS_JSON[%d] scoped credentials must set tenant_id or allowed_tenants", index)
		}
		if credential.Principal == "" {
			credential.Principal = firstNonEmpty(credential.Name, credential.ClientID, credential.ID)
		}
		credentials = append(credentials, credential)
	}
	return credentials, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
