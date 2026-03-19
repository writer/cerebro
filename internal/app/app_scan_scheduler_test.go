package app

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/scanner"
)

func TestCurrentOrStoredScheduledScanGraphView_UsesPersistedSnapshotWhenLiveGraphUnavailable(t *testing.T) {
	g := orgTopologyTestGraph(time.Now().UTC())
	app := &App{
		GraphSnapshots: mustPersistToolGraph(t, g),
	}

	got := app.currentOrStoredScheduledScanGraphView(context.Background(), ScanTuning{})
	if got == nil {
		t.Fatal("expected persisted snapshot graph view")
	}
	if got.NodeCount() != g.NodeCount() {
		t.Fatalf("expected %d nodes, got %d", g.NodeCount(), got.NodeCount())
	}
	if _, ok := got.GetNode("svc:core"); !ok {
		t.Fatal("expected persisted graph view to include svc:core")
	}
}

func TestCurrentOrStoredScheduledScanGraphView_PreservesLiveGraphWaitWhenPresent(t *testing.T) {
	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:live", Kind: graph.NodeKindService, Name: "live"})
	live.BuildIndex()

	app := &App{
		SecurityGraph:  live,
		GraphSnapshots: mustPersistToolGraph(t, orgTopologyTestGraph(time.Now().UTC())),
		graphReady:     make(chan struct{}),
	}

	got := app.currentOrStoredScheduledScanGraphView(context.Background(), ScanTuning{
		GraphWaitTimeout: 5 * time.Millisecond,
	})
	if got != nil {
		t.Fatalf("expected no graph view while live graph is still waiting, got %p", got)
	}
}

func TestRunScheduledGraphAnalyses_UsesPersistedSnapshotWhenLiveGraphUnavailable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := policy.NewEngine()
	addOrgTestPolicy(t, engine, &policy.Policy{
		ID:          "org-bus-factor-critical",
		Name:        "Critical System With Bus Factor 1",
		Description: "criticality high with single owner",
		Severity:    "high",
		Resource:    "org::system",
		Conditions: []string{
			"criticality == 'high'",
			"bus_factor <= 1",
		},
	})

	findingStore := findings.NewStore()
	app := &App{
		Logger:         logger,
		Policy:         engine,
		Scanner:        scanner.NewScanner(engine, scanner.ScanConfig{}, logger),
		Findings:       findingStore,
		GraphSnapshots: mustPersistToolGraph(t, orgTopologyTestGraph(time.Now().UTC())),
	}

	summary := app.runScheduledGraphAnalyses(context.Background(), ScanTuning{}, nil)
	if summary.orgTopologyErrorCount != 0 {
		t.Fatalf("expected no org topology errors, got %d", summary.orgTopologyErrorCount)
	}
	if summary.orgTopologyFindingCount == 0 {
		t.Fatal("expected org topology findings from persisted snapshot")
	}

	stored := findingStore.List(findings.FindingFilter{})
	if !slices.ContainsFunc(stored, func(f *findings.Finding) bool {
		return f != nil && f.PolicyID == "org-bus-factor-critical"
	}) {
		t.Fatalf("expected stored finding for persisted snapshot org topology policy, got %v", stored)
	}
}
