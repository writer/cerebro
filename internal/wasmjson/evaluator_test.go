package wasmjson

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEvaluatorRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	evaluator := New(Config{})
	_, err := evaluator.Evaluate(context.Background(), nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Evaluate() error = %v; want %v", err, ErrInvalidConfig)
	}
}

func TestEvaluatorBoundsInputWithoutExposingPayload(t *testing.T) {
	t.Parallel()
	evaluator := New(testConfig())
	marker := "input-marker-that-must-not-be-logged"
	_, err := evaluator.Evaluate(context.Background(), []byte(marker))
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("Evaluate() error = %v; want %v", err, ErrInputTooLarge)
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
