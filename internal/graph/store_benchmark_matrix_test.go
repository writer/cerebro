package graph_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	graphpkg "github.com/writer/cerebro/internal/graph"
	reports "github.com/writer/cerebro/internal/graph/reports"
)

type benchmarkFixture struct {
	name               string
	graph              *graphpkg.Graph
	now                time.Time
	traversalRootID    string
	claimID            string
	evaluationRunID    string
	evaluationThreadID string
}

func TestRunBenchmarkSuiteSupportsBackendAndFixtureMatrix(t *testing.T) {
	t.Parallel()

	fixtures := []benchmarkFixture{
		buildSecurityBenchmarkFixture(t, 128),
		buildWorldModelBenchmarkFixture(t, 128),
	}

	var cases []graphpkg.BenchmarkCase
	for _, fixture := range fixtures {
		cases = append(cases, benchmarkCasesForFixture(fixture, 1)...)
	}

	report, err := graphpkg.RunBenchmarkSuite(context.Background(), cases)
	if err != nil {
		t.Fatalf("RunBenchmarkSuite() error = %v", err)
	}
	if report == nil {
		t.Fatal("expected benchmark report")
	}
	if len(report.Measurements) != len(cases) {
		t.Fatalf("measurement count = %d, want %d", len(report.Measurements), len(cases))
	}

	backends := make(map[string]bool)
	fixtureNames := make(map[string]bool)
	workloads := make(map[string]bool)
	for _, measurement := range report.Measurements {
		backends[measurement.Backend] = true
		fixtureNames[measurement.Fixture] = true
		workloads[measurement.Workload] = true
		if measurement.Iterations != 1 {
			t.Fatalf("unexpected iterations for %#v", measurement)
		}
	}

	for _, backend := range []string{"memory", "neptune"} {
		if !backends[backend] {
			t.Fatalf("missing backend %q in %#v", backend, backends)
		}
	}
	for _, fixtureName := range []string{"security-estate", "world-model"} {
		if !fixtureNames[fixtureName] {
			t.Fatalf("missing fixture %q in %#v", fixtureName, fixtureNames)
		}
	}
	for _, workload := range []string{
		"bounded-traversal",
		"claim-conflicts",
		"claim-timeline",
		"evaluation-temporal-analysis",
		"playbook-effectiveness",
	} {
		if !workloads[workload] {
			t.Fatalf("missing workload %q in %#v", workload, workloads)
		}
	}
}

func TestBenchmarkRunsHandleEmptyAndCyclicGraphs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 24, 6, 0, 0, 0, time.UTC)
	empty := benchmarkFixture{
		name:            "empty",
		graph:           graphpkg.New(),
		now:             now,
		traversalRootID: "missing",
	}
	cyclicGraph := graphpkg.New()
	root := &graphpkg.Node{ID: "user:cycle", Kind: graphpkg.NodeKindUser, Name: "cycle"}
	mid := &graphpkg.Node{ID: "service:cycle", Kind: graphpkg.NodeKindService, Name: "cycle"}
	cyclicGraph.AddNodesBatch([]*graphpkg.Node{root, mid})
	cyclicGraph.AddEdgesBatch([]*graphpkg.Edge{
		{ID: "edge:cycle:self", Source: root.ID, Target: root.ID, Kind: graphpkg.EdgeKindCanRead, Effect: graphpkg.EdgeEffectAllow},
		{ID: "edge:cycle:mid", Source: root.ID, Target: mid.ID, Kind: graphpkg.EdgeKindCanRead, Effect: graphpkg.EdgeEffectAllow},
		{ID: "edge:mid:root", Source: mid.ID, Target: root.ID, Kind: graphpkg.EdgeKindCalls, Effect: graphpkg.EdgeEffectAllow},
	})
	cyclic := benchmarkFixture{
		name:            "cyclic",
		graph:           cyclicGraph,
		now:             now,
		traversalRootID: root.ID,
	}

	for _, fixture := range []benchmarkFixture{empty, cyclic} {
		for _, c := range benchmarkBlastRadiusCasesForFixture(fixture, 1) {
			if _, err := graphpkg.RunBenchmarkSuite(context.Background(), []graphpkg.BenchmarkCase{c}); err != nil {
				t.Fatalf("%s/%s: RunBenchmarkSuite() error = %v", fixture.name, c.Backend, err)
			}
		}
	}
}

func TestBenchmarkRunsHandleHighFanoutGraph(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 24, 7, 0, 0, 0, time.UTC)
	g := graphpkg.New()
	root := &graphpkg.Node{ID: "user:fanout", Kind: graphpkg.NodeKindUser, Name: "fanout"}
	g.AddNode(root)
	for i := 0; i < 1024; i++ {
		serviceID := fmt.Sprintf("service:fanout:%04d", i)
		g.AddNode(&graphpkg.Node{ID: serviceID, Kind: graphpkg.NodeKindService, Name: serviceID})
		g.AddEdge(&graphpkg.Edge{
			ID:     fmt.Sprintf("edge:fanout:%04d", i),
			Source: root.ID,
			Target: serviceID,
			Kind:   graphpkg.EdgeKindCanRead,
			Effect: graphpkg.EdgeEffectAllow,
		})
	}
	fixture := benchmarkFixture{
		name:            "fanout",
		graph:           g,
		now:             now,
		traversalRootID: root.ID,
	}

	for _, c := range benchmarkBlastRadiusCasesForFixture(fixture, 1) {
		report, err := graphpkg.RunBenchmarkSuite(context.Background(), []graphpkg.BenchmarkCase{c})
		if err != nil {
			t.Fatalf("%s: RunBenchmarkSuite() error = %v", c.Backend, err)
		}
		if len(report.Measurements) != 1 || report.Measurements[0].ResultSizeMax != 1024 {
			t.Fatalf("%s: unexpected measurement %#v", c.Backend, report.Measurements)
		}
	}
}

func benchmarkCasesForFixture(fixture benchmarkFixture, iterations int) []graphpkg.BenchmarkCase {
	cases := benchmarkBlastRadiusCasesForFixture(fixture, iterations)
	nodeCount := fixture.graph.NodeCount()
	edgeCount := fixture.graph.EdgeCount()
	for _, backend := range benchmarkBackendStores(fixture.graph) {
		cases = append(cases,
			graphpkg.BenchmarkCase{
				Backend:    backend.name,
				Fixture:    fixture.name,
				Workload:   "claim-conflicts",
				NodeCount:  nodeCount,
				EdgeCount:  edgeCount,
				BatchSize:  1,
				Iterations: iterations,
				Run: graphpkg.NewSnapshotReportBenchmarkRun(backend.store, reports.ClaimConflictReportProbe("claim-conflicts", reports.ClaimConflictReportOptions{
					ValidAt:      fixture.now,
					RecordedAt:   fixture.now,
					MaxConflicts: 25,
				})),
			},
			graphpkg.BenchmarkCase{
				Backend:    backend.name,
				Fixture:    fixture.name,
				Workload:   "claim-timeline",
				NodeCount:  nodeCount,
				EdgeCount:  edgeCount,
				BatchSize:  1,
				Iterations: iterations,
				Run:        graphpkg.NewClaimTimelineBenchmarkRun(backend.store, fixture.claimID, graphpkg.ClaimTimelineOptions{ValidAt: fixture.now, RecordedAt: fixture.now}),
			},
			graphpkg.BenchmarkCase{
				Backend:    backend.name,
				Fixture:    fixture.name,
				Workload:   "evaluation-temporal-analysis",
				NodeCount:  nodeCount,
				EdgeCount:  edgeCount,
				BatchSize:  1,
				Iterations: iterations,
				Run: graphpkg.NewSnapshotReportBenchmarkRun(backend.store, reports.EvaluationTemporalAnalysisReportProbe("evaluation-temporal-analysis", reports.EvaluationTemporalAnalysisReportOptions{
					Now:             fixture.now,
					EvaluationRunID: fixture.evaluationRunID,
					ConversationID:  fixture.evaluationThreadID,
					TimelineLimit:   25,
				})),
			},
			graphpkg.BenchmarkCase{
				Backend:    backend.name,
				Fixture:    fixture.name,
				Workload:   "playbook-effectiveness",
				NodeCount:  nodeCount,
				EdgeCount:  edgeCount,
				BatchSize:  1,
				Iterations: iterations,
				Run: graphpkg.NewSnapshotReportBenchmarkRun(backend.store, reports.PlaybookEffectivenessReportProbe("playbook-effectiveness", reports.PlaybookEffectivenessReportOptions{
					Now:          fixture.now,
					Window:       30 * 24 * time.Hour,
					MaxPlaybooks: 25,
				})),
			},
		)
	}
	return cases
}

func benchmarkBlastRadiusCasesForFixture(fixture benchmarkFixture, iterations int) []graphpkg.BenchmarkCase {
	nodeCount := fixture.graph.NodeCount()
	edgeCount := fixture.graph.EdgeCount()
	cases := make([]graphpkg.BenchmarkCase, 0, 3)
	for _, backend := range benchmarkBackendStores(fixture.graph) {
		cases = append(cases, graphpkg.BenchmarkCase{
			Backend:    backend.name,
			Fixture:    fixture.name,
			Workload:   "bounded-traversal",
			NodeCount:  nodeCount,
			EdgeCount:  edgeCount,
			BatchSize:  1,
			Iterations: iterations,
			Run:        graphpkg.NewBlastRadiusBenchmarkRun(backend.store, fixture.traversalRootID, 3),
		})
	}
	return cases
}

type benchmarkBackendStore struct {
	name  string
	store graphpkg.GraphStore
}

func benchmarkBackendStores(base *graphpkg.Graph) []benchmarkBackendStore {
	return []benchmarkBackendStore{
		{name: "memory", store: graphpkg.GraphStore(base.Clone())},
		{name: "neptune", store: graphpkg.NewBenchmarkMemoryBackedNeptuneStore(base)},
	}
}

func buildSecurityBenchmarkFixture(tb testing.TB, targetNodes int) benchmarkFixture {
	tb.Helper()

	now := time.Date(2026, 3, 24, 8, 0, 0, 0, time.UTC)
	g := graphpkg.New()
	root := addSecurityTraversalSeed(g, now, "security")
	claimID := addKnowledgeBenchmarkSeed(tb, g, now, "security")
	runID, conversationID := addEvaluationTemporalBenchmarkSeed(tb, g, now, "security")
	addPlaybookBenchmarkSeed(g, now, "security")
	padSecurityFixture(g, targetNodes, now)
	return benchmarkFixture{
		name:               "security-estate",
		graph:              g,
		now:                now,
		traversalRootID:    root,
		claimID:            claimID,
		evaluationRunID:    runID,
		evaluationThreadID: conversationID,
	}
}

func buildWorldModelBenchmarkFixture(tb testing.TB, targetNodes int) benchmarkFixture {
	tb.Helper()

	now := time.Date(2026, 3, 24, 9, 0, 0, 0, time.UTC)
	g := graphpkg.New()
	root := addSecurityTraversalSeed(g, now, "world")
	claimID := addKnowledgeBenchmarkSeed(tb, g, now, "world")
	runID, conversationID := addEvaluationTemporalBenchmarkSeed(tb, g, now, "world")
	addPlaybookBenchmarkSeed(g, now, "world")
	padWorldModelFixture(tb, g, targetNodes, now)
	return benchmarkFixture{
		name:               "world-model",
		graph:              g,
		now:                now,
		traversalRootID:    root,
		claimID:            claimID,
		evaluationRunID:    runID,
		evaluationThreadID: conversationID,
	}
}

func addSecurityTraversalSeed(g *graphpkg.Graph, now time.Time, prefix string) string {
	rootID := "user:" + prefix + ":root"
	apiID := "service:" + prefix + ":api"
	dbID := "service:" + prefix + ":db"
	bucketID := "bucket:" + prefix + ":logs"
	g.AddNodesBatch([]*graphpkg.Node{
		{ID: rootID, Kind: graphpkg.NodeKindUser, Name: rootID},
		{ID: apiID, Kind: graphpkg.NodeKindService, Name: apiID},
		{ID: dbID, Kind: graphpkg.NodeKindService, Name: dbID},
		{ID: bucketID, Kind: graphpkg.NodeKindBucket, Name: bucketID},
	})
	g.AddEdgesBatch([]*graphpkg.Edge{
		{ID: "edge:" + prefix + ":root-api", Source: rootID, Target: apiID, Kind: graphpkg.EdgeKindCanRead, Effect: graphpkg.EdgeEffectAllow},
		{ID: "edge:" + prefix + ":api-db", Source: apiID, Target: dbID, Kind: graphpkg.EdgeKindCalls, Effect: graphpkg.EdgeEffectAllow},
		{ID: "edge:" + prefix + ":db-bucket", Source: dbID, Target: bucketID, Kind: graphpkg.EdgeKindCanWrite, Effect: graphpkg.EdgeEffectAllow},
	})
	return rootID
}

func addKnowledgeBenchmarkSeed(tb testing.TB, g *graphpkg.Graph, now time.Time, prefix string) string {
	tb.Helper()

	subjectID := "service:" + prefix + ":payments"
	if _, ok := g.GetNode(subjectID); !ok {
		g.AddNode(&graphpkg.Node{
			ID:   subjectID,
			Kind: graphpkg.NodeKindService,
			Name: subjectID,
			Properties: map[string]any{
				"service_id":       subjectID,
				"observed_at":      now.Add(-30 * time.Minute).Format(time.RFC3339),
				"valid_from":       now.Add(-30 * time.Minute).Format(time.RFC3339),
				"recorded_at":      now.Add(-30 * time.Minute).Format(time.RFC3339),
				"transaction_from": now.Add(-30 * time.Minute).Format(time.RFC3339),
			},
		})
	}
	for _, evidenceID := range []string{
		"evidence:" + prefix + ":owner-alice",
		"evidence:" + prefix + ":owner-bob",
		"evidence:" + prefix + ":exposure-private",
		"evidence:" + prefix + ":exposure-public",
	} {
		g.AddNode(&graphpkg.Node{
			ID:   evidenceID,
			Kind: graphpkg.NodeKindEvidence,
			Name: evidenceID,
			Properties: map[string]any{
				"observed_at":      now.Add(-20 * time.Minute).Format(time.RFC3339),
				"valid_from":       now.Add(-20 * time.Minute).Format(time.RFC3339),
				"recorded_at":      now.Add(-20 * time.Minute).Format(time.RFC3339),
				"transaction_from": now.Add(-20 * time.Minute).Format(time.RFC3339),
			},
		})
	}

	writeClaim := func(req graphpkg.ClaimWriteRequest) {
		tb.Helper()
		if _, err := graphpkg.WriteClaim(g, req); err != nil {
			tb.Fatalf("WriteClaim(%q) error = %v", req.ID, err)
		}
	}

	writeClaim(graphpkg.ClaimWriteRequest{
		ID:              "claim:" + prefix + ":owner:alice",
		SubjectID:       subjectID,
		Predicate:       "owner",
		ObjectValue:     "alice@example.com",
		EvidenceIDs:     []string{"evidence:" + prefix + ":owner-alice"},
		SourceName:      "bench",
		SourceType:      "system",
		SourceSystem:    "benchmark",
		ObservedAt:      now.Add(-15 * time.Minute),
		RecordedAt:      now.Add(-15 * time.Minute),
		TransactionFrom: now.Add(-15 * time.Minute),
	})
	writeClaim(graphpkg.ClaimWriteRequest{
		ID:              "claim:" + prefix + ":owner:bob",
		SubjectID:       subjectID,
		Predicate:       "owner",
		ObjectValue:     "bob@example.com",
		EvidenceIDs:     []string{"evidence:" + prefix + ":owner-bob"},
		SourceName:      "bench",
		SourceType:      "system",
		SourceSystem:    "benchmark",
		ObservedAt:      now.Add(-14 * time.Minute),
		RecordedAt:      now.Add(-14 * time.Minute),
		TransactionFrom: now.Add(-14 * time.Minute),
	})
	writeClaim(graphpkg.ClaimWriteRequest{
		ID:              "claim:" + prefix + ":exposure:private",
		SubjectID:       subjectID,
		Predicate:       "exposure",
		ObjectValue:     "private",
		EvidenceIDs:     []string{"evidence:" + prefix + ":exposure-private"},
		SourceName:      "bench",
		SourceType:      "system",
		SourceSystem:    "benchmark",
		ObservedAt:      now.Add(-10 * time.Minute),
		RecordedAt:      now.Add(-10 * time.Minute),
		TransactionFrom: now.Add(-10 * time.Minute),
	})
	writeClaim(graphpkg.ClaimWriteRequest{
		ID:                "claim:" + prefix + ":exposure:public",
		SubjectID:         subjectID,
		Predicate:         "exposure",
		ObjectValue:       "public",
		EvidenceIDs:       []string{"evidence:" + prefix + ":exposure-public"},
		SupersedesClaimID: "claim:" + prefix + ":exposure:private",
		SourceName:        "bench",
		SourceType:        "system",
		SourceSystem:      "benchmark",
		ObservedAt:        now.Add(-5 * time.Minute),
		RecordedAt:        now.Add(-5 * time.Minute),
		TransactionFrom:   now.Add(-5 * time.Minute),
	})
	return "claim:" + prefix + ":exposure:public"
}

func addEvaluationTemporalBenchmarkSeed(tb testing.TB, g *graphpkg.Graph, now time.Time, prefix string) (string, string) {
	tb.Helper()

	runID := "run-eval-" + prefix
	conversationID := "conv-" + prefix
	baseAt := now.Add(-3 * time.Hour).UTC()
	threadID := "thread:evaluation:" + runID + ":" + conversationID
	decisionID := "decision:evaluation:" + runID + ":" + conversationID + ":turn-1"
	actionSuccessID := "action:evaluation:" + runID + ":" + conversationID + ":call-1"
	outcomeID := "outcome:evaluation:" + runID + ":" + conversationID
	serviceID := "service:" + prefix + ":eval"

	g.AddNode(&graphpkg.Node{
		ID:   serviceID,
		Kind: graphpkg.NodeKindService,
		Name: serviceID,
		Properties: map[string]any{
			"service_id":       serviceID,
			"observed_at":      baseAt.Add(-30 * time.Minute).Format(time.RFC3339),
			"valid_from":       baseAt.Add(-30 * time.Minute).Format(time.RFC3339),
			"recorded_at":      baseAt.Add(-30 * time.Minute).Format(time.RFC3339),
			"transaction_from": baseAt.Add(-30 * time.Minute).Format(time.RFC3339),
			"source_system":    "platform_eval",
		},
	})
	g.AddNode(&graphpkg.Node{
		ID:   threadID,
		Kind: graphpkg.NodeKind("communication_thread"),
		Name: conversationID,
		Properties: map[string]any{
			"thread_id":         conversationID,
			"channel_id":        runID,
			"conversation_id":   conversationID,
			"evaluation_run_id": runID,
			"agent_email":       "agent@example.com",
			"observed_at":       baseAt.Format(time.RFC3339),
			"valid_from":        baseAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&graphpkg.Node{
		ID:   decisionID,
		Kind: graphpkg.NodeKindDecision,
		Name: "turn-1",
		Properties: map[string]any{
			"decision_type":     "tool_selection",
			"status":            "completed",
			"conversation_id":   conversationID,
			"evaluation_run_id": runID,
			"turn_id":           "turn-1",
			"agent_email":       "agent@example.com",
			"made_at":           baseAt.Add(5 * time.Minute).Format(time.RFC3339),
			"observed_at":       baseAt.Add(5 * time.Minute).Format(time.RFC3339),
			"valid_from":        baseAt.Add(5 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&graphpkg.Node{
		ID:   actionSuccessID,
		Kind: graphpkg.NodeKindAction,
		Name: "call-1",
		Properties: map[string]any{
			"action_type":       "tool_call",
			"status":            "succeeded",
			"conversation_id":   conversationID,
			"evaluation_run_id": runID,
			"turn_id":           "turn-1",
			"tool_call_id":      "call-1",
			"agent_email":       "agent@example.com",
			"observed_at":       baseAt.Add(10 * time.Minute).Format(time.RFC3339),
			"valid_from":        baseAt.Add(10 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&graphpkg.Node{
		ID:   outcomeID,
		Kind: graphpkg.NodeKindOutcome,
		Name: "negative",
		Properties: map[string]any{
			"outcome_type":      "evaluation_conversation",
			"verdict":           "negative",
			"quality_score":     0.25,
			"conversation_id":   conversationID,
			"evaluation_run_id": runID,
			"observed_at":       baseAt.Add(20 * time.Minute).Format(time.RFC3339),
			"valid_from":        baseAt.Add(20 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddEdgesBatch([]*graphpkg.Edge{
		{ID: "edge:" + prefix + ":decision-thread", Source: decisionID, Target: threadID, Kind: graphpkg.EdgeKindTargets, Effect: graphpkg.EdgeEffectAllow},
		{ID: "edge:" + prefix + ":action-decision", Source: actionSuccessID, Target: decisionID, Kind: graphpkg.EdgeKindBasedOn, Effect: graphpkg.EdgeEffectAllow},
		{ID: "edge:" + prefix + ":outcome-thread", Source: outcomeID, Target: threadID, Kind: graphpkg.EdgeKindTargets, Effect: graphpkg.EdgeEffectAllow},
	})
	return runID, conversationID
}

func addPlaybookBenchmarkSeed(g *graphpkg.Graph, now time.Time, prefix string) {
	targetID := "service:" + prefix + ":payments"
	if _, ok := g.GetNode(targetID); !ok {
		g.AddNode(&graphpkg.Node{
			ID:   targetID,
			Kind: graphpkg.NodeKindService,
			Name: targetID,
			Properties: map[string]any{
				"observed_at": now.Format(time.RFC3339),
				"valid_from":  now.Format(time.RFC3339),
			},
		})
	}

	runID := "run-playbook-" + prefix
	playbookID := "pb-" + prefix
	threadID := "thread:playbook:" + runID
	stageID := "decision:playbook:" + runID + ":approve"
	actionID := "action:playbook:" + runID + ":patch"
	outcomeID := "outcome:playbook:" + runID
	targetIDs := []string{targetID}

	g.AddNode(&graphpkg.Node{
		ID:   threadID,
		Kind: graphpkg.NodeKind("communication_thread"),
		Name: "Remediate",
		Properties: map[string]any{
			"thread_id":       runID,
			"channel_id":      playbookID,
			"source_system":   "platform_playbook",
			"playbook_id":     playbookID,
			"playbook_name":   "Remediate",
			"playbook_run_id": runID,
			"status":          "started",
			"target_ids":      targetIDs,
			"tenant_id":       "tenant-acme",
			"observed_at":     now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":      now.Add(-2 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&graphpkg.Node{
		ID:   stageID,
		Kind: graphpkg.NodeKindDecision,
		Name: "Approve Fix",
		Properties: map[string]any{
			"decision_type":     "playbook_stage",
			"source_system":     "platform_playbook",
			"playbook_id":       playbookID,
			"playbook_name":     "Remediate",
			"playbook_run_id":   runID,
			"stage_id":          "approve",
			"stage_name":        "Approve Fix",
			"stage_order":       2,
			"status":            "completed",
			"approval_required": true,
			"approval_status":   "approved",
			"made_at":           now.Add(-105 * time.Minute).Format(time.RFC3339),
			"target_ids":        targetIDs,
			"tenant_id":         "tenant-acme",
			"observed_at":       now.Add(-105 * time.Minute).Format(time.RFC3339),
			"valid_from":        now.Add(-105 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddNode(&graphpkg.Node{
		ID:   actionID,
		Kind: graphpkg.NodeKindAction,
		Name: "Apply patch",
		Properties: map[string]any{
			"action_type":     "automation",
			"source_system":   "platform_playbook",
			"playbook_id":     playbookID,
			"playbook_name":   "Remediate",
			"playbook_run_id": runID,
			"stage_id":        "approve",
			"action_id":       "patch",
			"status":          "succeeded",
			"title":           "Apply patch",
			"performed_at":    now.Add(-100 * time.Minute).Format(time.RFC3339),
			"target_ids":      targetIDs,
			"tenant_id":       "tenant-acme",
			"observed_at":     now.Add(-100 * time.Minute).Format(time.RFC3339),
			"valid_from":      now.Add(-100 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddNode(&graphpkg.Node{
		ID:   outcomeID,
		Kind: graphpkg.NodeKindOutcome,
		Name: "Remediate positive",
		Properties: map[string]any{
			"outcome_type":    "playbook_run",
			"source_system":   "platform_playbook",
			"playbook_id":     playbookID,
			"playbook_name":   "Remediate",
			"playbook_run_id": runID,
			"verdict":         "positive",
			"status":          "completed",
			"rollback_state":  "stable",
			"target_ids":      targetIDs,
			"tenant_id":       "tenant-acme",
			"final_stage_id":  "approve",
			"observed_at":     now.Add(-90 * time.Minute).Format(time.RFC3339),
			"valid_from":      now.Add(-90 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddEdgesBatch([]*graphpkg.Edge{
		{ID: "edge:" + prefix + ":playbook-stage", Source: stageID, Target: threadID, Kind: graphpkg.EdgeKindTargets, Effect: graphpkg.EdgeEffectAllow},
		{ID: "edge:" + prefix + ":playbook-action", Source: actionID, Target: stageID, Kind: graphpkg.EdgeKindBasedOn, Effect: graphpkg.EdgeEffectAllow},
		{ID: "edge:" + prefix + ":playbook-outcome", Source: outcomeID, Target: threadID, Kind: graphpkg.EdgeKindTargets, Effect: graphpkg.EdgeEffectAllow},
	})
}

func padSecurityFixture(g *graphpkg.Graph, targetNodes int, now time.Time) {
	for g.NodeCount() < targetNodes {
		index := g.NodeCount()
		userID := fmt.Sprintf("user:security:%04d", index)
		serviceID := fmt.Sprintf("service:security:%04d", index)
		g.AddNodesBatch([]*graphpkg.Node{
			{ID: userID, Kind: graphpkg.NodeKindUser, Name: userID},
			{ID: serviceID, Kind: graphpkg.NodeKindService, Name: serviceID},
		})
		g.AddEdge(&graphpkg.Edge{
			ID:     fmt.Sprintf("edge:security:%04d", index),
			Source: userID,
			Target: serviceID,
			Kind:   graphpkg.EdgeKindCanRead,
			Effect: graphpkg.EdgeEffectAllow,
		})
		if _, ok := g.GetNode("service:security:core"); !ok {
			g.AddNode(&graphpkg.Node{
				ID:   "service:security:core",
				Kind: graphpkg.NodeKindService,
				Name: "service:security:core",
				Properties: map[string]any{
					"observed_at": now.Format(time.RFC3339),
					"valid_from":  now.Format(time.RFC3339),
				},
			})
		}
		g.AddEdge(&graphpkg.Edge{
			ID:     fmt.Sprintf("edge:security:core:%04d", index),
			Source: serviceID,
			Target: "service:security:core",
			Kind:   graphpkg.EdgeKindCalls,
			Effect: graphpkg.EdgeEffectAllow,
		})
	}
}

func padWorldModelFixture(tb testing.TB, g *graphpkg.Graph, targetNodes int, now time.Time) {
	tb.Helper()
	for g.NodeCount() < targetNodes {
		index := g.NodeCount()
		subjectID := fmt.Sprintf("service:world:%04d", index)
		evidenceID := fmt.Sprintf("evidence:world:%04d", index)
		g.AddNode(&graphpkg.Node{
			ID:   subjectID,
			Kind: graphpkg.NodeKindService,
			Name: subjectID,
			Properties: map[string]any{
				"observed_at":      now.Add(-time.Duration(index) * time.Second).Format(time.RFC3339),
				"valid_from":       now.Add(-time.Duration(index) * time.Second).Format(time.RFC3339),
				"recorded_at":      now.Add(-time.Duration(index) * time.Second).Format(time.RFC3339),
				"transaction_from": now.Add(-time.Duration(index) * time.Second).Format(time.RFC3339),
			},
		})
		g.AddNode(&graphpkg.Node{
			ID:   evidenceID,
			Kind: graphpkg.NodeKindEvidence,
			Name: evidenceID,
			Properties: map[string]any{
				"observed_at":      now.Add(-time.Duration(index) * time.Second).Format(time.RFC3339),
				"valid_from":       now.Add(-time.Duration(index) * time.Second).Format(time.RFC3339),
				"recorded_at":      now.Add(-time.Duration(index) * time.Second).Format(time.RFC3339),
				"transaction_from": now.Add(-time.Duration(index) * time.Second).Format(time.RFC3339),
			},
		})
		if _, err := graphpkg.WriteClaim(g, graphpkg.ClaimWriteRequest{
			ID:              fmt.Sprintf("claim:world:%04d", index),
			SubjectID:       subjectID,
			Predicate:       "status",
			ObjectValue:     "active",
			EvidenceIDs:     []string{evidenceID},
			SourceName:      "bench",
			SourceType:      "system",
			SourceSystem:    "benchmark",
			ObservedAt:      now.Add(-time.Duration(index) * time.Second),
			RecordedAt:      now.Add(-time.Duration(index) * time.Second),
			TransactionFrom: now.Add(-time.Duration(index) * time.Second),
		}); err != nil {
			tb.Fatalf("WriteClaim(world %d) error = %v", index, err)
		}
	}
}
