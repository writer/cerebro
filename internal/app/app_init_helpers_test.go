package app

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/writer/cerebro/internal/policy"
)

func TestRunInitStep_Success(t *testing.T) {
	called := false
	err := runInitStep("cache", func() {
		called = true
	})
	if err != nil {
		t.Fatalf("runInitStep returned error: %v", err)
	}
	if !called {
		t.Fatal("expected init function to run")
	}
}

func TestInitPhase1_ExplicitMappingsModeReturnsError(t *testing.T) {
	t.Setenv("CEREBRO_POLICY_EXPLICIT_MAPPINGS_ONLY", "true")

	a := &App{
		Config: &Config{
			PoliciesPath: filepath.Join(t.TempDir(), "missing-policies"),
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if err := a.initPhase1(context.Background()); err == nil {
		t.Fatal("expected explicit-mappings-only mode to fail when policy loading fails")
	}
}

func TestInitPhase3_InitializesScannerAndDSPM(t *testing.T) {
	a := &App{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Policy: policy.NewEngine(),
	}

	a.initPhase3()

	if a.Scanner == nil {
		t.Fatal("expected scanner to be initialized")
	}
	if a.DSPM == nil {
		t.Fatal("expected DSPM scanner to be initialized")
	}
}

func TestRunInitTasksConcurrently_RunsAllTasks(t *testing.T) {
	var called atomic.Int32
	tasks := []concurrentInitTask{
		{name: "task-1", run: func(context.Context) { called.Add(1) }},
		{name: "task-2", run: func(context.Context) { called.Add(1) }},
		{name: "task-3", run: func(context.Context) { called.Add(1) }},
	}

	if err := runInitTasksConcurrently(context.Background(), tasks); err != nil {
		t.Fatalf("runInitTasksConcurrently returned error: %v", err)
	}
	if called.Load() != int32(len(tasks)) {
		t.Fatalf("expected %d task runs, got %d", len(tasks), called.Load())
	}
}

func TestRunInitTasksConcurrently_PropagatesTaskPanic(t *testing.T) {
	tasks := []concurrentInitTask{
		{
			name: "panic-task",
			run: func(context.Context) {
				panic("boom")
			},
		},
	}

	err := runInitTasksConcurrently(context.Background(), tasks)
	if err == nil {
		t.Fatal("expected panic-wrapped init error")
	}
	if !strings.Contains(err.Error(), "panic-task init panic") {
		t.Fatalf("expected task name in error, got: %v", err)
	}
}

func TestValidateRequiredServices_ReturnsSortedMissingList(t *testing.T) {
	a := &App{}

	err := a.validateRequiredServices()
	if err == nil {
		t.Fatal("expected validation error when required services are missing")
	}

	const prefix = "required services not initialized: "
	if !strings.HasPrefix(err.Error(), prefix) {
		t.Fatalf("unexpected error prefix: %v", err)
	}

	missing := strings.Split(strings.TrimPrefix(err.Error(), prefix), ", ")
	if len(missing) == 0 {
		t.Fatalf("expected missing services in error: %v", err)
	}
	if !sort.StringsAreSorted(missing) {
		t.Fatalf("expected sorted missing services, got: %v", missing)
	}
}
