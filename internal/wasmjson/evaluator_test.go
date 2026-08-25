package wasmjson

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/wasmhost"
)

func TestEvaluatorRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	evaluator := New(Config{})
	for _, payload := range [][]byte{nil, []byte("x")} {
		_, err := evaluator.Evaluate(context.Background(), payload)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("Evaluate(%d bytes) error = %v; want %v", len(payload), err, ErrInvalidConfig)
		}
		if !errors.Is(err, wasmhost.ErrInvalidInput) {
			t.Fatalf("Evaluate(%d bytes) error = %v; want typed invalid input", len(payload), err)
		}
	}
}

func TestEvaluatorWarmRejectsInvalidConfiguration(t *testing.T) {
	evaluator := New(Config{})
	err := evaluator.Warm(context.Background())
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Warm() error = %v, want %v", err, ErrInvalidConfig)
	}
	if !errors.Is(err, wasmhost.ErrInvalidInput) {
		t.Fatalf("Warm() error = %v, want typed invalid input", err)
	}
}

func TestEvaluatorBoundsInputWithoutExposingPayload(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Module = []byte{0}
	evaluator := New(config)
	marker := "input-marker-that-must-not-be-logged"
	_, err := evaluator.Evaluate(context.Background(), []byte(marker))
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("Evaluate() error = %v; want %v", err, ErrInputTooLarge)
	}
	if !errors.Is(err, wasmhost.ErrInvalidInput) {
		t.Fatalf("Evaluate() error = %v; want typed invalid input", err)
	}
}

func TestEvaluatorCachesInitializationError(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.MaxInputBytes = 1
	evaluator := New(config)
	var cached error
	for range 2 {
		_, err := evaluator.Evaluate(context.Background(), nil)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("Evaluate() error = %v; want %v", err, ErrInvalidConfig)
		}
		if cached != nil && !errors.Is(err, cached) {
			t.Fatalf("Evaluate() error = %v; want cached error %v", err, cached)
		}
		cached = err
	}
}

func TestEvaluatorPointerPreservesMemoryViolation(t *testing.T) {
	t.Parallel()
	evaluator := New(testConfig())
	_, err := evaluator.pointer(nil, "test allocation")
	if !errors.Is(err, wasmhost.ErrMemoryViolation) {
		t.Fatalf("pointer() error = %v; want typed memory violation", err)
	}
}

func testConfig() Config {
	return Config{
		Name:              "test evaluator",
		ABIVersion:        1,
		ABIVersionExport:  "abi_version",
		AllocateExport:    "alloc",
		EvaluateExport:    "evaluate",
		MemoryLimitPages:  1,
		MaxInputBytes:     1,
		MaxOutputBytes:    1,
		InitializeTimeout: time.Second,
		CallTimeout:       time.Second,
	}
}
