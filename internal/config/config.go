package config

import (
	"fmt"
	"os"
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

// Config is the minimal bootstrap configuration for the rewrite skeleton.
type Config struct {
	HTTPAddr        string
	ShutdownTimeout time.Duration
	AppendLog       AppendLogConfig
	StateStore      StateStoreConfig
	GraphStore      GraphStoreConfig
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

// Load reads and validates process configuration.
func Load() (Config, error) {
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
	}
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
	return cfg, nil
}
