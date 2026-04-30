package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	appendlogjetstream "github.com/writer/cerebro/internal/appendlog/jetstream"
	"github.com/writer/cerebro/internal/config"
	graphstorekuzu "github.com/writer/cerebro/internal/graphstore/kuzu"
	statestorepostgres "github.com/writer/cerebro/internal/statestore/postgres"
)

const dependencyPingTimeout = 5 * time.Second

type closer func(context.Context) error

// OpenDependencies dials the configured append-log and current-state drivers.
func OpenDependencies(ctx context.Context, cfg config.Config) (Dependencies, func() error, error) {
	var (
		deps    Dependencies
		closers []closer
	)
	closeAll := func() error {
		var errs []error
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dependencyPingTimeout)
		defer cancel()
		for i := len(closers) - 1; i >= 0; i-- {
			if err := closers[i](closeCtx); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	fail := func(err error) (Dependencies, func() error, error) {
		_ = closeAll()
		return Dependencies{}, func() error { return nil }, err
	}

	if cfg.AppendLog.Driver == config.AppendLogDriverJetStream {
		appendLog, err := appendlogjetstream.Open(cfg.AppendLog)
		if err != nil {
			return fail(fmt.Errorf("open append log: %w", err))
		}
		deps.AppendLog = appendLog
		closers = append(closers, func(context.Context) error {
			return appendLog.Close()
		})
	}
	if cfg.StateStore.Driver == config.StateStoreDriverPostgres {
		stateStore, err := statestorepostgres.Open(cfg.StateStore)
		if err != nil {
			return fail(fmt.Errorf("open state store: %w", err))
		}
		deps.StateStore = stateStore
		closers = append(closers, func(context.Context) error {
			return stateStore.Close()
		})
	}
	switch cfg.GraphStore.Driver {
	case "":
	case config.GraphStoreDriverKuzu:
		graphStore, err := graphstorekuzu.Open(cfg.GraphStore)
		if err != nil {
			return fail(fmt.Errorf("open graph store: %w", err))
		}
		deps.GraphStore = graphStore
		closers = append(closers, func(context.Context) error {
			return graphStore.Close()
		})
	default:
		return fail(fmt.Errorf("unsupported graph store driver %q", cfg.GraphStore.Driver))
	}
	if err := pingDependencies(ctx, deps); err != nil {
		return fail(err)
	}
	return deps, closeAll, nil
}

func pingDependencies(ctx context.Context, deps Dependencies) error {
	if deps.AppendLog != nil {
		if err := pingDependency(ctx, "append log", deps.AppendLog); err != nil {
			return err
		}
	}
	if deps.StateStore != nil {
		if err := pingDependency(ctx, "state store", deps.StateStore); err != nil {
			return err
		}
	}
	if deps.GraphStore != nil {
		if err := pingDependency(ctx, "graph store", deps.GraphStore); err != nil {
			return err
		}
	}
	return nil
}

func pingDependency(ctx context.Context, name string, dependency pinger) error {
	pingCtx, cancel := context.WithTimeout(ctx, dependencyPingTimeout)
	defer cancel()
	if err := dependency.Ping(pingCtx); err != nil {
		return fmt.Errorf("ping %s: %w", name, err)
	}
	return nil
}
