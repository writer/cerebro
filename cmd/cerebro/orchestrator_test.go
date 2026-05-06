package main

import (
	"context"
	"os"
	"syscall"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceruntime"
)

func TestAppendOrchestratorRunBoundsForeverHistory(t *testing.T) {
	var runs []*orchestratorIterationResult
	for i := uint32(1); i <= 3; i++ {
		runs = appendOrchestratorRun(runs, &orchestratorIterationResult{Iteration: i}, true)
	}
	if len(runs) != 1 || runs[0].Iteration != 3 {
		t.Fatalf("forever runs = %#v, want only latest iteration", runs)
	}
}

func TestAppendOrchestratorRunPreservesFiniteHistory(t *testing.T) {
	var runs []*orchestratorIterationResult
	for i := uint32(1); i <= 2; i++ {
		runs = appendOrchestratorRun(runs, &orchestratorIterationResult{Iteration: i}, false)
	}
	if len(runs) != 2 || runs[0].Iteration != 1 || runs[1].Iteration != 2 {
		t.Fatalf("finite runs = %#v, want all iterations", runs)
	}
}

func TestShouldPrintOrchestratorResultSkipsNilStartupFailure(t *testing.T) {
	if shouldPrintOrchestratorResult(nil) {
		t.Fatal("shouldPrintOrchestratorResult(nil) = true, want false")
	}
	if !shouldPrintOrchestratorResult(&orchestratorResult{}) {
		t.Fatal("shouldPrintOrchestratorResult(non-nil) = false, want true")
	}
}

func TestParseOrchestratorOptionsRejectsZeroLimit(t *testing.T) {
	if _, err := parseOrchestratorOptions([]string{"limit=0"}); err == nil {
		t.Fatal("parseOrchestratorOptions(limit=0) error = nil, want error")
	}
}

func TestOrchestratorShutdownSignalsIncludeSIGTERM(t *testing.T) {
	signals := orchestratorShutdownSignals()
	if len(signals) != 2 || signals[0] != os.Interrupt || signals[1] != syscall.SIGTERM {
		t.Fatalf("orchestratorShutdownSignals() = %#v, want interrupt and SIGTERM", signals)
	}
}

func TestRunOrchestratorIterationStopsAfterSyncFailure(t *testing.T) {
	store := &orchestratorRuntimeStore{
		runtime: &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
	}
	result, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		sourceruntime.New(nil, store, nil, nil),
		nil,
		nil,
		orchestratorOptions{},
		1,
	)
	if err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want sync failure")
	}
	if got := len(result.Runtimes); got != 1 {
		t.Fatalf("runtime result count = %d, want 1", got)
	}
	if result.Runtimes[0].FindingRules != "" || result.Runtimes[0].GraphIngest != "" {
		t.Fatalf("downstream stages ran after sync failure: %#v", result.Runtimes[0])
	}
}

func TestTouchOrchestratorRuntimePersistsRuntimeForScanRotation(t *testing.T) {
	store := &touchRuntimeStore{}
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1"}

	if err := touchOrchestratorRuntime(context.Background(), store, runtime); err != nil {
		t.Fatalf("touchOrchestratorRuntime() error = %v", err)
	}
	if store.touchID != "runtime-1" {
		t.Fatalf("touched runtime id = %q, want runtime-1", store.touchID)
	}
	if store.putID != "" {
		t.Fatalf("PutSourceRuntime() touched stale runtime snapshot %q", store.putID)
	}
}

type touchRuntimeStore struct {
	touchID string
	putID   string
}

func (s *touchRuntimeStore) Ping(context.Context) error { return nil }

func (s *touchRuntimeStore) TouchSourceRuntime(_ context.Context, runtimeID string) error {
	s.touchID = runtimeID
	return nil
}

func (s *touchRuntimeStore) PutSourceRuntime(_ context.Context, runtime *cerebrov1.SourceRuntime) error {
	s.putID = runtime.GetId()
	return nil
}

func (s *touchRuntimeStore) GetSourceRuntime(context.Context, string) (*cerebrov1.SourceRuntime, error) {
	return nil, nil
}

type orchestratorRuntimeStore struct {
	runtime *cerebrov1.SourceRuntime
}

func (s *orchestratorRuntimeStore) Ping(context.Context) error { return nil }

func (s *orchestratorRuntimeStore) PutSourceRuntime(context.Context, *cerebrov1.SourceRuntime) error {
	return nil
}

func (s *orchestratorRuntimeStore) GetSourceRuntime(context.Context, string) (*cerebrov1.SourceRuntime, error) {
	return s.runtime, nil
}

func (s *orchestratorRuntimeStore) ListSourceRuntimes(context.Context, ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error) {
	return []*cerebrov1.SourceRuntime{s.runtime}, nil
}

func (s *orchestratorRuntimeStore) TouchSourceRuntime(context.Context, string) error {
	return nil
}
