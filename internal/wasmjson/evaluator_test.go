package wasmjson

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestEvaluatorRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	evaluator := New(Config{})
	_, err := evaluator.Evaluate(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("Evaluate() error = %v; want missing name", err)
	}
}

func TestEvaluatorBoundsInputWithoutExposingPayload(t *testing.T) {
	t.Parallel()
	evaluator := New(testConfig())
	marker := "input-marker-that-must-not-be-logged"
	_, err := evaluator.Evaluate(context.Background(), []byte(marker))
	if err == nil {
		t.Fatal("Evaluate() error = nil")
	}
	if !strings.Contains(err.Error(), "input is") || strings.Contains(err.Error(), marker) {
		t.Fatalf("Evaluate() error = %q; want bounded error without input", err)
	}
}

func TestEvaluatorCachesInitializationError(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.MaxInputBytes = 1
	evaluator := New(config)
	for range 2 {
		_, err := evaluator.Evaluate(context.Background(), nil)
		if err == nil || !strings.Contains(err.Error(), "module is empty") {
			t.Fatalf("Evaluate() error = %v; want empty module", err)
		}
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
