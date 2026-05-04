package config

import (
	"errors"
	"fmt"
	"os"
	"sort"
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
	AppendLog       AppendLogConfig
	StateStore      StateStoreConfig
	GraphStore      GraphStoreConfig
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

// APIKey grants one bearer token access to the bootstrap API.
type APIKey struct {
	Key       string
	Principal string
	TenantID  string
}

// AuthConfig controls optional API authentication and tenant scoping.
type AuthConfig struct {
	Enabled        bool
	APIKeys        []APIKey
	AllowedTenants []string
}

// Load reads and validates process configuration.
func Load() (Config, error) {
	if strings.TrimSpace(os.Getenv("CEREBRO_KUZU_PATH")) != "" {
		return Config{}, fmt.Errorf("%w; configure Neo4j with CEREBRO_NEO4J_URI, CEREBRO_NEO4J_USERNAME, and CEREBRO_NEO4J_PASSWORD", errLegacyKuzuPath)
	}
	cfg := Config{
		HTTPAddr:        strings.TrimSpace(os.Getenv("CEREBRO_HTTP_ADDR")),
		ShutdownTimeout: defaultShutdownTimeout,
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
		Auth: AuthConfig{
			APIKeys:        parseAPIKeys(os.Getenv("CEREBRO_API_KEYS")),
			AllowedTenants: parseCSV(os.Getenv("CEREBRO_ALLOWED_TENANTS")),
		},
	}
	authEnabled, err := parseBoolEnv("CEREBRO_API_AUTH_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	cfg.Auth.Enabled = authEnabled
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = defaultHTTPAddr
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
	if cfg.Auth.Enabled && len(cfg.Auth.APIKeys) == 0 {
		return Config{}, fmt.Errorf("CEREBRO_API_KEYS is required when CEREBRO_API_AUTH_ENABLED=true")
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
