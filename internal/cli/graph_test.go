package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func TestGraphCommands(t *testing.T) {
	if graphCmd == nil {
		t.Fatal("graphCmd should not be nil")
	}
	if graphCmd.Name() != "graph" {
		t.Fatalf("expected graph command, got %s", graphCmd.Name())
	}
	subcommands := graphCmd.Commands()
	foundProfileScale := false
	for _, cmd := range subcommands {
		if cmd.Name() == "profile-scale" {
			foundProfileScale = true
			break
		}
	}
	if !foundProfileScale {
		t.Fatal("expected graph profile-scale subcommand")
	}
}

func TestRunGraphProfileScaleJSON(t *testing.T) {
	currentOutput := graphProfileOutput
	currentTiers := append([]int(nil), graphProfileTiers...)
	currentIterations := graphProfileQueryIterations
	currentFn := graphProfileSyntheticScaleFn
	t.Cleanup(func() {
		graphProfileOutput = currentOutput
		graphProfileTiers = currentTiers
		graphProfileQueryIterations = currentIterations
		graphProfileSyntheticScaleFn = currentFn
	})

	graphProfileOutput = FormatJSON
	graphProfileTiers = []int{42}
	graphProfileQueryIterations = 2
	graphProfileSyntheticScaleFn = func(spec graph.ScaleProfileSpec) (*graph.ScaleProfileReport, error) {
		if len(spec.Tiers) != 1 || spec.Tiers[0] != 42 {
			t.Fatalf("unexpected tiers: %#v", spec.Tiers)
		}
		if spec.QueryIterations != 2 {
			t.Fatalf("unexpected query iterations: %d", spec.QueryIterations)
		}
		return &graph.ScaleProfileReport{
			GeneratedAt:     time.Date(2026, 3, 12, 22, 0, 0, 0, time.UTC),
			Workload:        "synthetic_estate_v1",
			QueryIterations: 2,
			Measurements: []graph.ScaleProfileMeasurement{
				{ResourceCount: 42, NodeCount: 100, EdgeCount: 200},
			},
			RecommendedPath: "tenant_sharded_hot_graph",
			Recommendation:  "test recommendation",
		}, nil
	}

	output := captureStdout(t, func() {
		if err := graphProfileScaleCmd.RunE(graphProfileScaleCmd, nil); err != nil {
			t.Fatalf("unexpected graph profile error: %v", err)
		}
	})

	var report graph.ScaleProfileReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("expected JSON output, got error: %v\noutput=%s", err, output)
	}
	if report.RecommendedPath != "tenant_sharded_hot_graph" {
		t.Fatalf("unexpected recommended path: %s", report.RecommendedPath)
	}
}

func TestRunGraphProfileScaleTable(t *testing.T) {
	currentOutput := graphProfileOutput
	currentFn := graphProfileSyntheticScaleFn
	t.Cleanup(func() {
		graphProfileOutput = currentOutput
		graphProfileSyntheticScaleFn = currentFn
	})

	graphProfileOutput = FormatTable
	graphProfileSyntheticScaleFn = func(spec graph.ScaleProfileSpec) (*graph.ScaleProfileReport, error) {
		return &graph.ScaleProfileReport{
			GeneratedAt:     time.Date(2026, 3, 12, 22, 0, 0, 0, time.UTC),
			Workload:        "synthetic_estate_v1",
			QueryIterations: 1,
			Measurements: []graph.ScaleProfileMeasurement{
				{ResourceCount: 1000, AccountCount: 2, NodeCount: 3000, EdgeCount: 4500, HeapAllocBytes: 64 * 1024 * 1024, IndexDurationMS: 12.5, SearchDurationMS: 1.5, BlastRadiusColdDurationMS: 2.5, CopyOnWriteDurationMS: 8.5, SnapshotCompressedBytes: 1024 * 1024},
			},
			RecommendedPath: "single_node_hot_graph",
			Recommendation:  "keep a single hot graph in process",
		}, nil
	}

	output := captureStdout(t, func() {
		if err := graphProfileScaleCmd.RunE(graphProfileScaleCmd, nil); err != nil {
			t.Fatalf("unexpected graph profile error: %v", err)
		}
	})

	for _, needle := range []string{"Graph Scale Profile", "1000", "single_node_hot_graph", "keep a single hot graph in process"} {
		if !strings.Contains(output, needle) {
			t.Fatalf("expected output to contain %q, got %s", needle, output)
		}
	}
}
