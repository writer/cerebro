package runtimegraph

import (
	"fmt"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func BenchmarkCompactHistoricalObservations(b *testing.B) {
	now := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	policy := DefaultObservationCompactionPolicy()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		g := buildObservationCompactionBenchmarkGraph(now, 1000)
		b.StartTimer()
		_ = CompactHistoricalObservations(g, now, policy)
	}
}

func buildObservationCompactionBenchmarkGraph(now time.Time, observationCount int) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "workload:prod/api", Kind: graph.NodeKindWorkload, Name: "api"})
	for i := 0; i < observationCount; i++ {
		observedAt := now.Add(-8 * time.Hour).Add(time.Duration(i) * time.Second)
		metadata := map[string]any{
			"process_name": fmt.Sprintf("proc-%02d", i%12),
			"process_path": fmt.Sprintf("/bin/proc-%02d", i%12),
		}
		if _, err := graph.WriteObservation(g, graph.ObservationWriteRequest{
			ID:              fmt.Sprintf("observation:bench:%d", i),
			SubjectID:       "workload:prod/api",
			ObservationType: "process_exec",
			Summary:         "process_exec",
			SourceSystem:    "runtime",
			SourceEventID:   fmt.Sprintf("bench:%d", i),
			ObservedAt:      observedAt,
			ValidFrom:       observedAt,
			RecordedAt:      observedAt,
			TransactionFrom: observedAt,
			Confidence:      1.0,
			Metadata:        metadata,
		}); err != nil {
			panic(err)
		}
	}
	return g
}
