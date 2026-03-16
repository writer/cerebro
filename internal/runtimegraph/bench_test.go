package runtimegraph

import (
	"strconv"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/runtime"
)

func BenchmarkMaterializeObservationsIntoGraphDeferredFinalize(b *testing.B) {
	const batchSize = 50
	const totalObservations = 10000

	observations := make([]*runtime.RuntimeObservation, 0, totalObservations)
	baseTime := time.Date(2026, 3, 16, 21, 0, 0, 0, time.UTC)
	for i := 0; i < totalObservations; i++ {
		observations = append(observations, &runtime.RuntimeObservation{
			ID:          "runtime:process_exec:" + strconv.Itoa(i),
			Source:      "tetragon",
			Kind:        runtime.ObservationKindProcessExec,
			ObservedAt:  baseTime.Add(time.Duration(i) * time.Second),
			RecordedAt:  baseTime.Add(time.Duration(i)*time.Second + time.Millisecond),
			WorkloadRef: "deployment:prod/api",
			Process: &runtime.ProcessEvent{
				Name: "sh",
				Path: "/bin/sh",
			},
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g := graph.New()
		g.AddNode(&graph.Node{
			ID:   "deployment:prod/api",
			Kind: graph.NodeKindDeployment,
			Name: "api",
		})
		g.BuildIndex()

		for start := 0; start < len(observations); start += batchSize {
			end := start + batchSize
			if end > len(observations) {
				end = len(observations)
			}
			MaterializeObservationsIntoGraph(g, observations[start:end], baseTime)
		}
		FinalizeMaterializedGraph(g, baseTime)
	}
}
