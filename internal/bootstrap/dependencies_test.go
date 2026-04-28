package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/config"
)

func TestOpenDependenciesAllowsUnconfiguredStores(t *testing.T) {
	deps, closeAll, err := OpenDependencies(context.Background(), config.Config{})
	if err != nil {
		t.Fatalf("OpenDependencies() error = %v", err)
	}
	if deps.AppendLog != nil {
		t.Fatal("AppendLog != nil, want nil")
	}
	if deps.StateStore != nil {
		t.Fatal("StateStore != nil, want nil")
	}
	if deps.GraphStore != nil {
		t.Fatal("GraphStore != nil, want nil")
	}
	if err := closeAll(); err != nil {
		t.Fatalf("closeAll() error = %v", err)
	}
}

func TestOpenDependenciesRejectsIncompleteJetStreamConfig(t *testing.T) {
	_, _, err := OpenDependencies(context.Background(), config.Config{
		AppendLog: config.AppendLogConfig{Driver: config.AppendLogDriverJetStream},
	})
	if err == nil {
		t.Fatal("OpenDependencies() error = nil, want non-nil")
	}
}

func TestOpenDependenciesRejectsIncompletePostgresConfig(t *testing.T) {
	_, _, err := OpenDependencies(context.Background(), config.Config{
		StateStore: config.StateStoreConfig{Driver: config.StateStoreDriverPostgres},
	})
	if err == nil {
		t.Fatal("OpenDependencies() error = nil, want non-nil")
	}
}

func TestOpenDependenciesRejectsIncompleteKuzuConfig(t *testing.T) {
	_, _, err := OpenDependencies(context.Background(), config.Config{
		GraphStore: config.GraphStoreConfig{Driver: config.GraphStoreDriverKuzu},
	})
	if err == nil {
		t.Fatal("OpenDependencies() error = nil, want non-nil")
	}
}

func TestOpenDependenciesRejectsIncompleteNeo4jConfig(t *testing.T) {
	_, _, err := OpenDependencies(context.Background(), config.Config{
		GraphStore: config.GraphStoreConfig{Driver: config.GraphStoreDriverNeo4j},
	})
	if err == nil {
		t.Fatal("OpenDependencies() error = nil, want non-nil")
	}
}

func TestOpenDependenciesConfiguresKuzu(t *testing.T) {
	deps, closeAll, err := OpenDependencies(context.Background(), config.Config{
		GraphStore: config.GraphStoreConfig{
			Driver:   config.GraphStoreDriverKuzu,
			KuzuPath: filepath.Join(t.TempDir(), "graph"),
		},
	})
	if err != nil {
		t.Fatalf("OpenDependencies() error = %v", err)
	}
	if deps.GraphStore == nil {
		t.Fatal("GraphStore = nil, want non-nil")
	}
	if err := closeAll(); err != nil {
		t.Fatalf("closeAll() error = %v", err)
	}
}

func TestOpenDependenciesConfiguresNeo4jLive(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_E2E") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_E2E=1 to run live Neo4j e2e tests")
	}
	deps, closeAll, err := OpenDependencies(context.Background(), config.Config{
		GraphStore: config.GraphStoreConfig{
			Driver:        config.GraphStoreDriverNeo4j,
			Neo4jURI:      os.Getenv("CEREBRO_NEO4J_URI"),
			Neo4jUsername: os.Getenv("CEREBRO_NEO4J_USERNAME"),
			Neo4jPassword: os.Getenv("CEREBRO_NEO4J_PASSWORD"),
			Neo4jDatabase: os.Getenv("CEREBRO_NEO4J_DATABASE"),
		},
	})
	if err != nil {
		t.Fatalf("OpenDependencies() error = %v", err)
	}
	if deps.GraphStore == nil {
		t.Fatal("GraphStore = nil, want non-nil")
	}
	if err := closeAll(); err != nil {
		t.Fatalf("closeAll() error = %v", err)
	}
}
