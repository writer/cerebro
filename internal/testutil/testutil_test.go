package testutil

import (
	"testing"
	"time"
)

func TestLoggerReturnsNonNil(t *testing.T) {
	if Logger() == nil {
		t.Fatal("expected Logger to return a non-nil logger")
	}
}

func TestContextCancelsOnCleanup(t *testing.T) {
	done := make(chan struct{})

	t.Run("subtest", func(t *testing.T) {
		ctx := Context(t)
		go func() {
			<-ctx.Done()
			close(done)
		}()
	})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected Context to be canceled when subtest cleanup runs")
	}
}
