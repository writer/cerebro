package api

import (
	"context"
	"errors"

	"github.com/writer/cerebro/internal/executions"
	"github.com/writer/cerebro/internal/executionstore"
)

var (
	errPlatformExecutionStoreNotConfigured = errors.New("platform execution store not configured")
	errPlatformExecutionStoreUnavailable   = errors.New("platform execution store unavailable")
)

// platformExecutionService narrows the platform execution handler down to the
// execution-listing behavior it actually consumes.
type platformExecutionService interface {
	ListExecutions(ctx context.Context, opts executions.ListOptions) ([]executions.Summary, error)
}

type serverPlatformExecutionService struct {
	deps *serverDependencies
}

func newPlatformExecutionService(deps *serverDependencies) platformExecutionService {
	return serverPlatformExecutionService{deps: deps}
}

func (s serverPlatformExecutionService) ListExecutions(ctx context.Context, opts executions.ListOptions) ([]executions.Summary, error) {
	if s.deps == nil || s.deps.Config == nil {
		return nil, errPlatformExecutionStoreNotConfigured
	}
	store := s.deps.ExecutionStore
	if store == nil {
		var err error
		store, err = executionstore.NewSQLiteStore(s.deps.Config.ExecutionStoreFile)
		if err != nil {
			return nil, errors.Join(errPlatformExecutionStoreUnavailable, err)
		}
		defer func() { _ = store.Close() }()
	}
	return executions.List(ctx, store, opts)
}
