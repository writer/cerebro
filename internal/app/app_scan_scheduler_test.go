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

func TestCurrentOrStoredScheduledScanGraphView_UsesConfiguredStoreWhenLiveGraphUnavailable(t *testing.T) {
	g := orgTopologyTestGraph(time.Now().UTC())
	app := &App{}
	setConfiguredSnapshotGraphFromGraph(t, app, g)

	got := app.currentOrStoredScheduledScanGraphView(context.Background(), ScanTuning{})
	if got == nil {
		t.Fatal("expected configured graph view")
		return
	}
	if got.NodeCount() != g.NodeCount() {
		t.Fatalf("expected %d nodes, got %d", g.NodeCount(), got.NodeCount())
	}
	if _, ok := got.GetNode("svc:core"); !ok {
		t.Fatal("expected configured graph view to include svc:core")
	}
}

func TestCurrentOrStoredScheduledScanGraphView_PreservesLiveGraphWaitWhenPresent(t *testing.T) {
	live := graph.New()
	live.AddNode(&graph.Node{ID: "service:live", Kind: graph.NodeKindService, Name: "live"})
	live.BuildIndex()

	app := &App{
		SecurityGraph: live,
		graphReady:    make(chan struct{}),
	}
	setConfiguredSnapshotGraphFromGraph(t, app, orgTopologyTestGraph(time.Now().UTC()))

	got := app.currentOrStoredScheduledScanGraphView(context.Background(), ScanTuning{
		GraphWaitTimeout: 5 * time.Millisecond,
	})
	if got != nil {
		t.Fatalf("expected no graph view while live graph is still waiting, got %p", got)
	}
}

func TestRunScheduledGraphAnalyses_UsesConfiguredStoreWhenLiveGraphUnavailable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := policy.NewEngine()
	addOrgTestPolicy(t, engine, &policy.Policy{
		ID:          "org-bus-factor-critical",
		Name:        "Critical System With Bus Factor 1",
		Description: "criticality high with single owner",
		Severity:    "high",
		Resource:    "org::system",
		Conditions: []string{
			"resource.criticality == 'high'",
			"resource.bus_factor <= 1",
		},
	})

	findingStore := findings.NewStore()
	app := &App{
		Logger:   logger,
		Policy:   engine,
		Scanner:  scanner.NewScanner(engine, scanner.ScanConfig{}, logger),
		Findings: findingStore,
	}
	setConfiguredSnapshotGraphFromGraph(t, app, orgTopologyTestGraph(time.Now().UTC()))

	summary := app.runScheduledGraphAnalyses(context.Background(), ScanTuning{}, nil)
	if summary.orgTopologyErrorCount != 0 {
		t.Fatalf("expected no org topology errors, got %d", summary.orgTopologyErrorCount)
	}
	if summary.orgTopologyFindingCount == 0 {
		t.Fatal("expected org topology findings from configured graph")
	}

	stored := findingStore.List(findings.FindingFilter{})
	if !slices.ContainsFunc(stored, func(f *findings.Finding) bool {
		return f != nil && f.PolicyID == "org-bus-factor-critical"
	}) {
		t.Fatalf("expected stored finding for configured graph org topology policy, got %v", stored)
	}
}
