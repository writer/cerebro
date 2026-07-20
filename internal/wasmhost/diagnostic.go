package wasmhost

import (
	"context"
	"errors"
)

// DiagnosticKind identifies a stable class of embedded Wasm host failure.
type DiagnosticKind string

const (
	DiagnosticInvalidInput    DiagnosticKind = "invalid_input"
	DiagnosticABIViolation    DiagnosticKind = "abi_violation"
	DiagnosticMemoryViolation DiagnosticKind = "memory_violation"
	DiagnosticGuestStatus     DiagnosticKind = "guest_status"
	DiagnosticOutputInvalid   DiagnosticKind = "output_invalid"
	DiagnosticTimeout         DiagnosticKind = "timeout"
	DiagnosticCanceled        DiagnosticKind = "canceled"
)

var (
	ErrInvalidInput    = errors.New("embedded Wasm input is invalid")
	ErrABIViolation    = errors.New("embedded Wasm ABI contract was violated")
	ErrMemoryViolation = errors.New("embedded Wasm memory contract was violated")
	ErrGuestStatus     = errors.New("embedded Wasm guest returned a failure status")
	ErrOutputInvalid   = errors.New("embedded Wasm output is invalid")
	ErrTimeout         = errors.New("embedded Wasm call timed out")
	ErrCanceled        = errors.New("embedded Wasm call was canceled")
)

// Diagnostic adds a machine-readable kind without changing the rendered error.
// Cause remains available through errors.Is and errors.As.
type Diagnostic struct {
	kind  DiagnosticKind
	cause error
}

func (d *Diagnostic) Error() string        { return d.cause.Error() }
func (d *Diagnostic) Unwrap() error        { return d.cause }
func (d *Diagnostic) Kind() DiagnosticKind { return d.kind }

func (d *Diagnostic) Is(target error) bool {
	return target == sentinelForKind(d.kind)
}

// Diagnose assigns kind to err. It returns nil when err is nil and does not
// replace an existing Wasm diagnostic.
func Diagnose(kind DiagnosticKind, err error) error {
	if err == nil {
		return nil
	}
	var diagnostic *Diagnostic
	if errors.As(err, &diagnostic) {
		return err
	}
	return &Diagnostic{kind: kind, cause: err}
}

// DiagnoseContext assigns cancellation and deadline kinds when the error or
// active context reports either state. Other errors are returned unchanged.
func DiagnoseContext(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled) || ctx != nil && errors.Is(ctx.Err(), context.Canceled):
		return &Diagnostic{kind: DiagnosticCanceled, cause: err}
	case errors.Is(err, context.DeadlineExceeded) || ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		return &Diagnostic{kind: DiagnosticTimeout, cause: err}
	default:
		return err
	}
}

// DiagnoseContextOr uses a cancellation or deadline kind when present and
// otherwise assigns fallback.
func DiagnoseContextOr(ctx context.Context, fallback DiagnosticKind, err error) error {
	if err == nil {
		return nil
	}
	contextual := DiagnoseContext(ctx, err)
	if _, ok := DiagnosticKindOf(contextual); ok {
		return contextual
	}
	return Diagnose(fallback, err)
}

// DiagnosticKindOf returns the first embedded Wasm diagnostic kind in err.
func DiagnosticKindOf(err error) (DiagnosticKind, bool) {
	var diagnostic *Diagnostic
	if !errors.As(err, &diagnostic) {
		return "", false
	}
	return diagnostic.kind, true
}

func sentinelForKind(kind DiagnosticKind) error {
	switch kind {
	case DiagnosticInvalidInput:
		return ErrInvalidInput
	case DiagnosticABIViolation:
		return ErrABIViolation
	case DiagnosticMemoryViolation:
		return ErrMemoryViolation
	case DiagnosticGuestStatus:
		return ErrGuestStatus
	case DiagnosticOutputInvalid:
		return ErrOutputInvalid
	case DiagnosticTimeout:
		return ErrTimeout
	case DiagnosticCanceled:
		return ErrCanceled
	default:
		return nil
	}
}
