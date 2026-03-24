package app

import (
	"context"
	"fmt"
	"time"

	"github.com/writer/cerebro/internal/health"
)

func (a *App) graphDualWriteReconciliationHealthCheck() health.Checker {
	return func(ctx context.Context) health.CheckResult {
		start := time.Now().UTC()
		result := health.CheckResult{
			Name:      "graph_dual_write_reconciliation",
			Timestamp: start,
		}
		if a == nil || a.graphStoreDualWriteReplayQueue == nil {
			result.Status = health.StatusHealthy
			result.Message = "graph dual-write durable replay disabled"
			result.Latency = time.Since(start)
			return result
		}
		stats, err := a.graphStoreDualWriteReplayQueue.Stats(ctx)
		if err != nil {
			result.Status = health.StatusUnknown
			result.Message = err.Error()
			result.Latency = time.Since(start)
			return result
		}
		switch {
		case stats.DeadLettered > 0:
			result.Status = health.StatusDegraded
			result.Message = fmt.Sprintf("graph dual-write replay has %d dead-lettered mutations", stats.DeadLettered)
		case stats.Pending > 0 || stats.Leased > 0:
			result.Status = health.StatusHealthy
			result.Message = fmt.Sprintf("graph dual-write replay pending=%d leased=%d", stats.Pending, stats.Leased)
		default:
			result.Status = health.StatusHealthy
			result.Message = "graph dual-write replay queue empty"
		}
		result.Latency = time.Since(start)
		return result
	}
}
