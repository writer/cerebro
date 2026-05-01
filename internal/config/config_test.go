package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("CEREBRO_HTTP_ADDR", "")
	t.Setenv("CEREBRO_SHUTDOWN_TIMEOUT", "")
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", "")
	t.Setenv("CEREBRO_JETSTREAM_URL", "")
	t.Setenv("CEREBRO_JETSTREAM_SUBJECT_PREFIX", "")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", "")
	t.Setenv("CEREBRO_POSTGRES_DSN", "")
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", "")
	t.Setenv("CEREBRO_KUZU_PATH", "")
	t.Setenv("CEREBRO_NEO4J_URI", "")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "")
	t.Setenv("CEREBRO_NEO4J_DATABASE", "")

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
	if cfg.GraphStore.Driver != "" {
		t.Fatalf("GraphStore.Driver = %q, want empty", cfg.GraphStore.Driver)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("CEREBRO_HTTP_ADDR", "127.0.0.1:9000")
	t.Setenv("CEREBRO_SHUTDOWN_TIMEOUT", "3s")
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", AppendLogDriverJetStream)
	t.Setenv("CEREBRO_JETSTREAM_URL", "nats://127.0.0.1:4222")
	t.Setenv("CEREBRO_JETSTREAM_SUBJECT_PREFIX", "cerebro.events")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", StateStoreDriverPostgres)
	t.Setenv("CEREBRO_POSTGRES_DSN", "postgres://127.0.0.1:5432/cerebro?sslmode=disable")
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", GraphStoreDriverKuzu)
	t.Setenv("CEREBRO_KUZU_PATH", "/tmp/cerebro-kuzu")
	t.Setenv("CEREBRO_NEO4J_URI", "")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "")
	t.Setenv("CEREBRO_NEO4J_DATABASE", "")

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
	if cfg.AppendLog.Driver != AppendLogDriverJetStream {
		t.Fatalf("AppendLog.Driver = %q, want %q", cfg.AppendLog.Driver, AppendLogDriverJetStream)
	}
	if cfg.AppendLog.JetStreamSubjectPrefix != "cerebro.events" {
		t.Fatalf("JetStreamSubjectPrefix = %q, want %q", cfg.AppendLog.JetStreamSubjectPrefix, "cerebro.events")
	}
	if cfg.StateStore.Driver != StateStoreDriverPostgres {
		t.Fatalf("StateStore.Driver = %q, want %q", cfg.StateStore.Driver, StateStoreDriverPostgres)
	}
	if cfg.GraphStore.Driver != GraphStoreDriverKuzu {
		t.Fatalf("GraphStore.Driver = %q, want %q", cfg.GraphStore.Driver, GraphStoreDriverKuzu)
	}
}

func TestLoadFromNeo4jEnv(t *testing.T) {
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", GraphStoreDriverNeo4j)
	t.Setenv("CEREBRO_KUZU_PATH", "")
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
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", "")
	t.Setenv("CEREBRO_KUZU_PATH", "")
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
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", GraphStoreDriverNeo4j)
	t.Setenv("CEREBRO_NEO4J_URI", "")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "neo4j")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "test-password")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsMissingNeo4jUsername(t *testing.T) {
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", GraphStoreDriverNeo4j)
	t.Setenv("CEREBRO_NEO4J_URI", "bolt://127.0.0.1:7687")
	t.Setenv("CEREBRO_NEO4J_USERNAME", "")
	t.Setenv("CEREBRO_NEO4J_PASSWORD", "test-password")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsMissingNeo4jPassword(t *testing.T) {
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

func TestLoadInfersDriversFromURLs(t *testing.T) {
	t.Setenv("CEREBRO_SHUTDOWN_TIMEOUT", "")
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", "")
	t.Setenv("CEREBRO_JETSTREAM_URL", "nats://127.0.0.1:4222")
	t.Setenv("CEREBRO_JETSTREAM_SUBJECT_PREFIX", "")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", "")
	t.Setenv("CEREBRO_POSTGRES_DSN", "postgres://127.0.0.1:5432/cerebro?sslmode=disable")
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", "")
	t.Setenv("CEREBRO_KUZU_PATH", "/tmp/cerebro-kuzu")

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
	if cfg.GraphStore.Driver != GraphStoreDriverKuzu {
		t.Fatalf("GraphStore.Driver = %q, want %q", cfg.GraphStore.Driver, GraphStoreDriverKuzu)
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

func TestLoadRejectsMissingKuzuPath(t *testing.T) {
	t.Setenv("CEREBRO_KUZU_PATH", "")
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", GraphStoreDriverKuzu)
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsUnsupportedGraphStoreDriver(t *testing.T) {
	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", "alternate")
	t.Setenv("CEREBRO_KUZU_PATH", "/tmp/cerebro-kuzu")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}
