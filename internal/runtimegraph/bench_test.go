package runtimegraph

import (
	"strconv"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/runtime"
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

func BenchmarkBuildObservationWriteRequest(b *testing.B) {
	observation := &runtime.RuntimeObservation{
		ID:          "runtime:process_exec:bench",
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  time.Date(2026, 3, 16, 21, 30, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 21, 30, 0, int(time.Millisecond), time.UTC),
		WorkloadRef: "deployment:prod/api",
		WorkloadUID: "uid-api",
		Cluster:     "prod-cluster",
		Namespace:   "prod",
		NodeName:    "worker-a",
		ContainerID: "containerd://bench",
		ImageRef:    "ghcr.io/upstream/api:latest",
		ImageID:     "sha256:bench",
		PrincipalID: "root",
		Metadata: map[string]any{
			"signal_name": "process_exec",
			"severity":    "medium",
		},
		Process: &runtime.ProcessEvent{
			Name:    "sh",
			Path:    "/bin/sh",
			Cmdline: "sh -c id",
			User:    "root",
		},
		Tags: []string{"runtime", "process"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := BuildObservationWriteRequest(observation); err != nil {
			b.Fatalf("BuildObservationWriteRequest: %v", err)
		}
	}
}

func BenchmarkWriteObservation(b *testing.B) {
	req, err := BuildObservationWriteRequest(&runtime.RuntimeObservation{
		ID:          "runtime:process_exec:write",
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  time.Date(2026, 3, 16, 21, 45, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 3, 16, 21, 45, 0, int(time.Millisecond), time.UTC),
		WorkloadRef: "deployment:prod/api",
		Cluster:     "prod-cluster",
		Namespace:   "prod",
		ContainerID: "containerd://bench",
		Process: &runtime.ProcessEvent{
			Name:    "sh",
			Path:    "/bin/sh",
			Cmdline: "sh -c id",
			User:    "root",
		},
	})
	if err != nil {
		b.Fatalf("BuildObservationWriteRequest: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g := graph.New()
		g.AddNode(&graph.Node{
			ID:   "deployment:prod/api",
			Kind: graph.NodeKindDeployment,
			Name: "api",
		})
		if _, err := graph.WriteObservation(g, req); err != nil {
			b.Fatalf("WriteObservation: %v", err)
		}
	}
}
