package api

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/workloadscan"
)

var (
	errPlatformWorkloadScanStateUnavailable = errors.New("workload scan state unavailable")
	errPlatformWorkloadScanPrioritizeFailed = errors.New("failed to prioritize workload scan targets")
)

// platformWorkloadScanService narrows the workload-scan target handler down to
// graph resolution and target prioritization.
type platformWorkloadScanService interface {
	PrioritizeTargets(ctx context.Context, opts workloadscan.PrioritizationOptions) ([]workloadscan.TargetPriority, error)
}

type serverPlatformWorkloadScanService struct {
	deps *serverDependencies
}

func newPlatformWorkloadScanService(deps *serverDependencies) platformWorkloadScanService {
	return serverPlatformWorkloadScanService{deps: deps}
}

func (s serverPlatformWorkloadScanService) PrioritizeTargets(ctx context.Context, opts workloadscan.PrioritizationOptions) ([]workloadscan.TargetPriority, error) {
	g, err := currentOrStoredTenantGraphView(ctx, s.deps)
	if err != nil {
		return nil, err
	}
	store, closeStore, err := s.runStore()
	if err != nil {
		return nil, errors.Join(errPlatformWorkloadScanStateUnavailable, err)
	}
	if closeStore != nil {
		defer closeStore()
	}
	targets, err := workloadscan.PrioritizeTargets(ctx, g, store, opts)
	if err != nil {
		return nil, errors.Join(errPlatformWorkloadScanPrioritizeFailed, err)
	}
	return targets, nil
}

func (s serverPlatformWorkloadScanService) runStore() (workloadscan.RunStore, func(), error) {
	if s.deps == nil || s.deps.Config == nil {
		return nil, nil, nil
	}
	if s.deps.ExecutionStore != nil {
		return workloadscan.NewSQLiteRunStoreWithExecutionStore(s.deps.ExecutionStore), nil, nil
	}
	path := strings.TrimSpace(s.deps.Config.WorkloadScanStateFile)
	if path == "" {
		return nil, nil, nil
	}
	store, err := workloadscan.NewSQLiteRunStore(path)
	if err != nil {
		return nil, nil, err
	}
	return store, func() { _ = store.Close() }, nil
}

func currentUTC() time.Time {
	return time.Now().UTC()
}
