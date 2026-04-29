package a

import (
	"context"
	"time"
)

func ok(ctx context.Context) {
	// OK: waiting on a context.
	<-ctx.Done()
	// OK: using a timer explicitly.
	t := time.NewTimer(time.Second)
	defer t.Stop()
	<-t.C
}

func bad() {
	time.Sleep(time.Second) // want `time.Sleep is forbidden`
}

func badAfter(ctx context.Context) {
	select {
	case <-time.After(time.Second): // want `time.After leaks timers`
	case <-ctx.Done():
	}
}

// SleepInClosure is still bad.
var _ = func() {
	time.Sleep(time.Millisecond) // want `time.Sleep is forbidden`
}
