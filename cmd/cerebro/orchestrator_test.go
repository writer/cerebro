package main

import "testing"

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
