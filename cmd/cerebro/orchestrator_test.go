package main

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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

func TestTouchOrchestratorRuntimePersistsRuntimeForScanRotation(t *testing.T) {
	store := &touchRuntimeStore{}
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-1"}

	if err := touchOrchestratorRuntime(context.Background(), store, runtime); err != nil {
		t.Fatalf("touchOrchestratorRuntime() error = %v", err)
	}
	if store.putID != "runtime-1" {
		t.Fatalf("touched runtime id = %q, want runtime-1", store.putID)
	}
}

type touchRuntimeStore struct {
	putID string
}

func (s *touchRuntimeStore) Ping(context.Context) error { return nil }

func (s *touchRuntimeStore) PutSourceRuntime(_ context.Context, runtime *cerebrov1.SourceRuntime) error {
	s.putID = runtime.GetId()
	return nil
}

func (s *touchRuntimeStore) GetSourceRuntime(context.Context, string) (*cerebrov1.SourceRuntime, error) {
	return nil, nil
}
