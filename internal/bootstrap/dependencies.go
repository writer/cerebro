package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	appendlogjetstream "github.com/writer/cerebro/internal/appendlog/jetstream"
	"github.com/writer/cerebro/internal/config"
	statestorepostgres "github.com/writer/cerebro/internal/statestore/postgres"
)

const dependencyPingTimeout = 5 * time.Second

type closer interface {
	Close() error
}

// OpenDependencies dials the configured append-log and current-state drivers.
func OpenDependencies(ctx context.Context, cfg config.Config) (Dependencies, func() error, error) {
	var (
		deps    Dependencies
		closers []closer
	)
	closeAll := func() error {
		var errs []error
		for i := len(closers) - 1; i >= 0; i-- {
			if err := closers[i].Close(); err != nil {
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
		closers = append(closers, appendLog)
	}
	if cfg.StateStore.Driver == config.StateStoreDriverPostgres {
		stateStore, err := statestorepostgres.Open(cfg.StateStore)
		if err != nil {
			return fail(fmt.Errorf("open state store: %w", err))
		}
		deps.StateStore = stateStore
		closers = append(closers, stateStore)
	}
	pingCtx, cancel := context.WithTimeout(ctx, dependencyPingTimeout)
	defer cancel()
	if deps.AppendLog != nil {
		if err := deps.AppendLog.Ping(pingCtx); err != nil {
			return fail(fmt.Errorf("ping append log: %w", err))
		}
	}
	if deps.StateStore != nil {
		if err := deps.StateStore.Ping(pingCtx); err != nil {
			return fail(fmt.Errorf("ping state store: %w", err))
		}
	}
	return deps, closeAll, nil
}
