package panicsafe

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/telemetry"
)

// ErrTaskPanicked lets completion-sensitive callers fail instead of hanging
// when a protected background task exits through panic recovery.
var ErrTaskPanicked = errors.New("background task panicked")

// Payload names a recovered panic value crossing into the panicsafe package.
type Payload struct {
	Value any
}

// Repanic rethrows a recovered panic value at explicit process-edge boundaries
// where Go runtime or standard-library sentinels must preserve panic semantics.
func Repanic(payload Payload) {
	panic(payload.Value)
}

type recoveredPanicError struct{}

func (recoveredPanicError) Error() string { return ErrTaskPanicked.Error() }
func (recoveredPanicError) Unwrap() error { return ErrTaskPanicked }

// Go starts one background task, captures a bounded panic event, and prevents
// the panic from terminating the process. The returned channel closes after
// the task exits so tests and shutdown paths can observe completion when needed.
func Go(ctx context.Context, name string, fn func()) <-chan struct{} {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unnamed"
	}
	done := make(chan struct{})
	run := func() {
		defer close(done)
		defer func() {
			if recovered := recover(); recovered != nil {
				telemetry.CaptureError(ctx, "background.task.panic", recoveredPanicError{}, telemetry.Attrs(
					telemetry.Field{Key: "component", Value: "background_task"},
					telemetry.Field{Key: "operation", Value: name},
					telemetry.Field{Key: "panic_type", Value: fmt.Sprintf("%T", recovered)},
				))
			}
		}()
		fn()
	}
	go run()
	return done
}
