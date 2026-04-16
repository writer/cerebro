package app

import (
	"context"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

const (
	defaultTapGraphReadyWaitTimeout = 15 * time.Second
	defaultTapGraphReadyRetryDelay  = 5 * time.Second
)

func (a *App) ensureSecurityGraph() *graph.Graph {
	if a == nil {
		return nil
	}
	if !a.retainHotSecurityGraph() {
		return nil
	}

	a.securityGraphInitMu.Lock()
	defer a.securityGraphInitMu.Unlock()

	if a.SecurityGraph == nil {
		a.SecurityGraph = graph.New()
		a.configureGraphRuntimeBehavior(a.SecurityGraph)
	}
	return a.SecurityGraph
}

func (a *App) waitForSecurityGraphReady(ctx context.Context) error {
	if a == nil || a.graphReady == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	waitCtx := ctx
	cancel := func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		if timeout := a.tapGraphReadyWaitTimeout(); timeout > 0 {
			waitCtx, cancel = context.WithTimeout(ctx, timeout)
		}
	}
	defer cancel()

	select {
	case <-a.graphReady:
		return nil
	case <-waitCtx.Done():
		return waitCtx.Err()
	}
}

func (a *App) tapGraphReadyWaitTimeout() time.Duration {
	if a != nil && a.Config != nil && a.Config.NATSConsumerAckWait > 0 {
		if timeout := a.Config.NATSConsumerAckWait / 4; timeout > 0 && timeout < defaultTapGraphReadyWaitTimeout {
			return timeout
		}
	}
	return defaultTapGraphReadyWaitTimeout
}

func (a *App) tapGraphReadyRetryDelay() time.Duration {
	if a != nil && a.Config != nil && a.Config.NATSConsumerFetchTimeout > 0 {
		return a.Config.NATSConsumerFetchTimeout
	}
	return defaultTapGraphReadyRetryDelay
}
