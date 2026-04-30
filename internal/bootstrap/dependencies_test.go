package bootstrap

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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

func TestPingDependenciesUsesIndependentTimeouts(t *testing.T) {
	const slowPingDelay = 300 * time.Millisecond
	deps := Dependencies{
		AppendLog: stubAppendLogFunc(func(context.Context) error {
			time.Sleep(slowPingDelay)
			return nil
		}),
		StateStore: stubStateStoreFunc(func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("state store ping context has no deadline")
			}
			if remaining := time.Until(deadline); remaining < dependencyPingTimeout-(slowPingDelay/2) {
				t.Fatalf("state store ping deadline has %v remaining, want a fresh timeout near %v", remaining, dependencyPingTimeout)
			}
			return nil
		}),
	}

	if err := pingDependencies(context.Background(), deps); err != nil {
		t.Fatalf("pingDependencies() error = %v", err)
	}
}

type stubAppendLogFunc func(context.Context) error

func (f stubAppendLogFunc) Ping(ctx context.Context) error { return f(ctx) }
func (f stubAppendLogFunc) Append(context.Context, *cerebrov1.EventEnvelope) error {
	return nil
}

type stubStateStoreFunc func(context.Context) error

func (f stubStateStoreFunc) Ping(ctx context.Context) error { return f(ctx) }

func TestOpenDependenciesRejectsIncompleteKuzuConfig(t *testing.T) {
	_, _, err := OpenDependencies(context.Background(), config.Config{
		GraphStore: config.GraphStoreConfig{Driver: config.GraphStoreDriverKuzu},
	})
	if err == nil {
		t.Fatal("OpenDependencies() error = nil, want non-nil")
	}
}

func TestOpenDependenciesRejectsUnsupportedGraphStoreDriver(t *testing.T) {
	_, _, err := OpenDependencies(context.Background(), config.Config{
		GraphStore: config.GraphStoreConfig{Driver: "alternate"},
	})
	if err == nil {
		t.Fatal("OpenDependencies() error = nil, want non-nil")
	}
}
