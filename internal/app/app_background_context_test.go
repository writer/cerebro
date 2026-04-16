package app

import (
	"context"
	"testing"
)

type backgroundContextKey string

func TestAppBackgroundContextPreservesValuesWithoutCancellation(t *testing.T) {
	base := context.WithValue(context.Background(), backgroundContextKey("trace"), "trace-123")
	cancelable, cancel := context.WithCancel(base)
	application := &App{rootCtx: cancelable}

	cancel()

	ctx := application.backgroundContext()
	if got := ctx.Value(backgroundContextKey("trace")); got != "trace-123" {
		t.Fatalf("backgroundContext() value = %v, want trace-123", got)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("backgroundContext() should ignore parent cancellation, got %v", err)
	}
}
