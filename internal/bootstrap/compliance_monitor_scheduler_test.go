package bootstrap

import (
	"context"
	"testing"
	"time"
)

func TestComplianceMonitorSchedulerClosesWhenUnavailable(t *testing.T) {
	t.Parallel()
	done := (&App{}).StartComplianceMonitorScheduler(context.Background(), t.Logf)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unavailable compliance monitor scheduler did not close")
	}
}
