package config

import (
	"encoding/json"
	"errors"
	"fmt"
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
	AppendLogDriverJetStream = "jetstream"
	StateStoreDriverPostgres = "postgres"
	GraphStoreDriverNeo4j    = "neo4j"
)

var errLegacyKuzuPath = errors.New("CEREBRO_KUZU_PATH is no longer supported")

// Config is the minimal bootstrap configuration for the rewrite skeleton.
type Config struct {
	HTTPAddr        string
	ShutdownTimeout time.Duration
	ImageTag        string
	AppendLog       AppendLogConfig
	StateStore      StateStoreConfig
	GraphStore      GraphStoreConfig
	GraphAgentLLM   GraphAgentLLMConfig
	Auth            AuthConfig
}

// AppendLogConfig selects and configures the append-log driver.
type AppendLogConfig struct {
	Driver                 string
	JetStreamURL           string
	JetStreamSubjectPrefix string
}

// StateStoreConfig selects and configures the current-state store driver.
type StateStoreConfig struct {
	Driver      string
	PostgresDSN string
}

// GraphStoreConfig selects and configures the graph projection store driver.
type GraphStoreConfig struct {
	Driver        string
	Neo4jURI      string
	Neo4jUsername string
	Neo4jPassword string
	Neo4jDatabase string
}

// GraphAgentLLMConfig selects and configures the graph ask LLM adapter.
type GraphAgentLLMConfig struct {
	Provider    string
	Model       string
	SonnetModel string
	OpusModel   string
	HaikuModel  string
	MaxTokens   int
	Temperature float64
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
}

// DeviceAuthSigningKey is one Ed25519 keypair the issuer can sign with. The
// production deployment leaves PrivatePEM empty and uses an external KMS
// signer; the dev/test path supplies an inline PEM for both halves.
type DeviceAuthSigningKey struct {
	KID        string `json:"kid"`
	PublicPEM  string `json:"public_pem"`
	PrivatePEM string `json:"private_pem,omitempty"`
}

// DeviceAuthConfig configures the SeCheck device-auth surface. The surface is
// disabled when Enabled is false.
type DeviceAuthConfig struct {
	Enabled                  bool
	Issuer                   string
	Audience                 string
	AccessTTL                time.Duration
	RefreshTTL               time.Duration
	BootstrapTokenTTL        time.Duration
	IdempotencyTTL           time.Duration
	ClockSkew                time.Duration
	SigningKeys              []DeviceAuthSigningKey
	CurrentKID               string
	EnrollPerIPRatePerSecond float64
	EnrollPerIPBurst         int
	TokenPerDeviceRatePerSecond float64
	TokenPerDeviceBurst      int
}

// Load reads and validates process configuration.
func Load() (Config, error) {
	if strings.TrimSpace(os.Getenv("CEREBRO_KUZU_PATH")) != "" {
		return Config{}, fmt.Errorf("%w; configure Neo4j with CEREBRO_NEO4J_URI, CEREBRO_NEO4J_USERNAME, and CEREBRO_NEO4J_PASSWORD", errLegacyKuzuPath)
	}
	apiCredentials, err := parseAPICredentials(os.Getenv("CEREBRO_API_CREDENTIALS_JSON"))
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		HTTPAddr:        strings.TrimSpace(os.Getenv("CEREBRO_HTTP_ADDR")),
		ShutdownTimeout: defaultShutdownTimeout,
		ImageTag:        strings.TrimSpace(os.Getenv("CEREBRO_IMAGE_TAG")),
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
		GraphAgentLLM: GraphAgentLLMConfig{
			Provider:    strings.TrimSpace(os.Getenv("CEREBRO_GRAPH_AGENT_LLM_PROVIDER")),
			Model:       strings.TrimSpace(os.Getenv("CEREBRO_GRAPH_AGENT_LLM_MODEL")),
			SonnetModel: strings.TrimSpace(os.Getenv("CEREBRO_GRAPH_AGENT_LLM_MODEL_SONNET")),
			OpusModel:   strings.TrimSpace(os.Getenv("CEREBRO_GRAPH_AGENT_LLM_MODEL_OPUS")),
			HaikuModel:  strings.TrimSpace(os.Getenv("CEREBRO_GRAPH_AGENT_LLM_MODEL_HAIKU")),
		},
		Auth: AuthConfig{
			APIKeys:                 parseAPIKeys(os.Getenv("CEREBRO_API_KEYS")),
			APICredentials:          apiCredentials,
			CapabilityTokenSecrets:  parseCSV(os.Getenv("CEREBRO_CAPABILITY_TOKEN_SECRETS")),
			CapabilityTokenAudience: strings.TrimSpace(os.Getenv("CEREBRO_CAPABILITY_TOKEN_AUDIENCE")),
			AllowedTenants:          parseCSV(os.Getenv("CEREBRO_ALLOWED_TENANTS")),
		},
	}
	authEnabled, err := parseBoolEnv("CEREBRO_API_AUTH_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	cfg.Auth.Enabled = authEnabled
	if len(cfg.Auth.CapabilityTokenSecrets) > 0 && cfg.Auth.CapabilityTokenAudience == "" {
		cfg.Auth.CapabilityTokenAudience = "cerebro-api"
	}
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
	if cfg.Auth.Enabled && len(cfg.Auth.APIKeys) == 0 && len(cfg.Auth.APICredentials) == 0 && len(cfg.Auth.CapabilityTokenSecrets) == 0 {
		return Config{}, fmt.Errorf("CEREBRO_API_KEYS, CEREBRO_API_CREDENTIALS_JSON, or CEREBRO_CAPABILITY_TOKEN_SECRETS is required when CEREBRO_API_AUTH_ENABLED=true")
	}
	return cfg, nil
}

func parseBoolEnv(name string, defaultValue bool) (bool, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return defaultValue, nil
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
		}
		if credential.Key == "" && credential.KeySHA256 == "" {
			return nil, fmt.Errorf("CEREBRO_API_CREDENTIALS_JSON[%d] must set key or key_sha256", index)
		}
		if len(credential.Scopes) > 0 && credential.TenantID == "" && len(credential.AllowedTenants) == 0 {
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
