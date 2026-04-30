package bootstrap

import (
	"context"
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
