package bootstrap

import (
	"context"
	"errors"
	"time"
)

const complianceMonitorPollInterval = 15 * time.Second

func (a *App) RunDueComplianceMonitors(ctx context.Context) (int, error) {
	if a == nil || a.services.monitors == nil {
		return 0, nil
	}
	now := time.Now().UTC()
	timeCount, timeErr := a.services.monitors.RunDue(ctx, now)
	changeCount, changeErr := a.services.monitors.RunDueChanges(ctx, now)
	return timeCount + changeCount, errors.Join(timeErr, changeErr)
}

func (a *App) StartComplianceMonitorScheduler(ctx context.Context, logf func(string, ...any)) <-chan struct{} {
	done := make(chan struct{})
	if a == nil || a.services.monitors == nil {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(complianceMonitorPollInterval)
		defer ticker.Stop()
		for {
			if _, err := a.RunDueComplianceMonitors(ctx); err != nil && ctx.Err() == nil && logf != nil {
				logf("run due compliance monitors: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}
