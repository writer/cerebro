package graph

import (
	"context"
	"encoding/json"
	"testing"
)

func TestRunBenchmarkSuiteProducesMachineReadableMeasurements(t *testing.T) {
	t.Parallel()

	report, err := RunBenchmarkSuite(context.Background(), []BenchmarkCase{{
		Backend:    "memory",
		Fixture:    "unit",
		Workload:   "count-nodes",
		NodeCount:  2,
		EdgeCount:  1,
		BatchSize:  3,
		Iterations: 3,
		Run: func(context.Context) (BenchmarkRunResult, error) {
			return BenchmarkRunResult{
				ResultSize: 2,
				Metadata:   map[string]any{"kind": "unit"},
			}, nil
		},
	}})
	if err != nil {
		t.Fatalf("RunBenchmarkSuite() error = %v", err)
	}
	if report == nil {
		t.Fatal("expected benchmark report")
	}
	if len(report.Measurements) != 1 {
		t.Fatalf("measurement count = %d, want 1", len(report.Measurements))
	}
	measurement := report.Measurements[0]
	if measurement.Backend != "memory" || measurement.Workload != "count-nodes" {
		t.Fatalf("measurement identity = %#v", measurement)
	}
	if len(measurement.SamplesMS) != 3 {
		t.Fatalf("sample count = %d, want 3", len(measurement.SamplesMS))
	}
	if measurement.BatchSize != 3 {
		t.Fatalf("batch size = %d, want 3", measurement.BatchSize)
	}
	if measurement.ResultSizeMin != 2 || measurement.ResultSizeMax != 2 {
		t.Fatalf("result size range = [%d,%d], want [2,2]", measurement.ResultSizeMin, measurement.ResultSizeMax)
	}
	if measurement.Metadata["kind"] != "unit" {
		t.Fatalf("metadata = %#v, want kind=unit", measurement.Metadata)
	}

	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal(report) error = %v", err)
	}
	if len(payload) == 0 {
		t.Fatal("expected machine-readable payload")
	}
}

func TestRunBenchmarkSuiteRejectsInvalidIterations(t *testing.T) {
	t.Parallel()

	_, err := RunBenchmarkSuite(context.Background(), []BenchmarkCase{{
		Backend:    "memory",
		Fixture:    "unit",
		Workload:   "invalid",
		Iterations: 0,
		Run: func(context.Context) (BenchmarkRunResult, error) {
			return BenchmarkRunResult{}, nil
		},
	}})
	if err == nil {
		t.Fatal("expected invalid iteration error")
	}
}

func TestBenchmarkRunHelpersSupportMemoryBackedDurableStores(t *testing.T) {
	t.Parallel()

	base := New()
	alice := contractStoreTestNode("user:alice", NodeKindUser, "Alice")
	api := contractStoreTestNode("service:api", NodeKindService, "API")
	db := contractStoreTestNode("service:db", NodeKindService, "DB")
	base.AddNodesBatch([]*Node{alice, api, db})
	base.AddEdgesBatch([]*Edge{
		contractStoreTestEdge("edge:alice:api", alice.ID, api.ID, EdgeKindCanRead),
		contractStoreTestEdge("edge:api:db", api.ID, db.ID, EdgeKindCalls),
	})

	backends := []struct {
		name  string
		store GraphStore
	}{
		{name: "memory", store: GraphStore(base.Clone())},
		{name: "neptune", store: NewBenchmarkMemoryBackedNeptuneStore(base)},
	}

	for _, backend := range backends {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			t.Parallel()

			blastRun := NewBlastRadiusBenchmarkRun(backend.store, alice.ID, 2)
			blast, err := blastRun(context.Background())
			if err != nil {
				t.Fatalf("NewBlastRadiusBenchmarkRun() error = %v", err)
			}
			if blast.ResultSize != 2 {
				t.Fatalf("blast result size = %d, want 2", blast.ResultSize)
			}

			reverseRun := NewReverseAccessBenchmarkRun(backend.store, db.ID, 2)
			reverse, err := reverseRun(context.Background())
			if err != nil {
				t.Fatalf("NewReverseAccessBenchmarkRun() error = %v", err)
			}
			if reverse.ResultSize != 1 {
				t.Fatalf("reverse result size = %d, want 1", reverse.ResultSize)
			}

			effectiveRun := NewEffectiveAccessBenchmarkRun(backend.store, alice.ID, db.ID, 2)
			effective, err := effectiveRun(context.Background())
			if err != nil {
				t.Fatalf("NewEffectiveAccessBenchmarkRun() error = %v", err)
			}
			if effective.ResultSize != 3 {
				t.Fatalf("effective result size = %d, want 3", effective.ResultSize)
			}

			subgraphRun := NewExtractSubgraphBenchmarkRun(backend.store, alice.ID, ExtractSubgraphOptions{
				MaxDepth:  2,
				Direction: ExtractSubgraphDirectionOutgoing,
			})
			subgraph, err := subgraphRun(context.Background())
			if err != nil {
				t.Fatalf("NewExtractSubgraphBenchmarkRun() error = %v", err)
			}
			if subgraph.ResultSize != 3 {
				t.Fatalf("subgraph result size = %d, want 3", subgraph.ResultSize)
			}

			reportRun := NewSnapshotReportBenchmarkRun(backend.store, StoreReportProbe{
				Name: "node-count",
				Build: func(g *Graph) (any, error) {
					return map[string]any{"nodes": g.NodeCount()}, nil
				},
			})
			reportResult, err := reportRun(context.Background())
			if err != nil {
				t.Fatalf("NewSnapshotReportBenchmarkRun() error = %v", err)
			}
			if reportResult.ResultSize != 1 {
				t.Fatalf("report result size = %d, want 1", reportResult.ResultSize)
			}
		})
	}
}
