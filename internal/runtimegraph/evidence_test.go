package runtimegraph

import (
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/runtime"
)

func TestBuildFindingEvidenceNodeUsesDetectionProvenance(t *testing.T) {
	finding := &runtime.RuntimeFinding{
		ID:           "finding-1",
		RuleID:       "crypto-mining-process",
		RuleName:     "Cryptocurrency Mining Process",
		Category:     runtime.CategoryCryptoMining,
		Severity:     "high",
		ResourceID:   "deployment:prod/api",
		ResourceType: "workload",
		Description:  "Detected miner process",
		MITRE:        []string{"T1496"},
		Remediation:  "Isolate workload",
		Timestamp:    time.Date(2026, 3, 16, 20, 0, 0, 0, time.UTC),
		Observation: &runtime.RuntimeObservation{
			ID:         "runtime:process_exec:abc",
			Kind:       runtime.ObservationKindProcessExec,
			Source:     "tetragon",
			ObservedAt: time.Date(2026, 3, 16, 19, 59, 55, 0, time.UTC),
		},
	}

	node, err := BuildFindingEvidenceNode(finding)
	if err != nil {
		t.Fatalf("BuildFindingEvidenceNode returned error: %v", err)
	}

	if node.Kind != graph.NodeKindEvidence {
		t.Fatalf("node.Kind = %q, want %q", node.Kind, graph.NodeKindEvidence)
	}
	if node.Provider != runtimeFindingEvidenceSourceSystem {
		t.Fatalf("node.Provider = %q, want %q", node.Provider, runtimeFindingEvidenceSourceSystem)
	}
	if !strings.HasPrefix(node.ID, "evidence:runtime_finding:finding-1") {
		t.Fatalf("node.ID = %q, want evidence:runtime_finding:finding-1*", node.ID)
	}
	if got := testMetadataString(node.Properties, "evidence_type"); got != "runtime_finding" {
		t.Fatalf("evidence_type = %q, want runtime_finding", got)
	}
	if got := testMetadataString(node.Properties, "detail"); got != "Detected miner process" {
		t.Fatalf("detail = %q, want Detected miner process", got)
	}
	if got := testMetadataString(node.Properties, "source_system"); got != runtimeFindingEvidenceSourceSystem {
		t.Fatalf("source_system = %q, want %q", got, runtimeFindingEvidenceSourceSystem)
	}
	if got := testMetadataString(node.Properties, "runtime_source"); got != "tetragon" {
		t.Fatalf("runtime_source = %q, want tetragon", got)
	}
	if got := testMetadataString(node.Properties, "rule_id"); got != "crypto-mining-process" {
		t.Fatalf("rule_id = %q, want crypto-mining-process", got)
	}
	if got := testMetadataString(node.Properties, "severity"); got != "high" {
		t.Fatalf("severity = %q, want high", got)
	}
	if got := testMetadataString(node.Properties, "observed_at"); got != "2026-03-16T20:00:00Z" {
		t.Fatalf("observed_at = %q, want 2026-03-16T20:00:00Z", got)
	}
	if issues := graph.GlobalSchemaRegistry().ValidateNode(node); len(issues) != 0 {
		t.Fatalf("ValidateNode returned issues: %+v", issues)
	}
}

func TestBuildFindingEvidenceNodeFallsBackToObservationTimestamp(t *testing.T) {
	finding := &runtime.RuntimeFinding{
		ID:          "finding-2",
		RuleID:      "reverse-shell",
		RuleName:    "Reverse Shell",
		Category:    runtime.CategoryReverseShell,
		Severity:    "critical",
		Description: "Detected reverse shell connection",
		Observation: &runtime.RuntimeObservation{
			ID:         "runtime:network_flow:def",
			Kind:       runtime.ObservationKindNetworkFlow,
			Source:     "falco",
			ObservedAt: time.Date(2026, 3, 16, 20, 5, 0, 0, time.UTC),
		},
	}

	node, err := BuildFindingEvidenceNode(finding)
	if err != nil {
		t.Fatalf("BuildFindingEvidenceNode returned error: %v", err)
	}

	if got := testMetadataString(node.Properties, "observed_at"); got != "2026-03-16T20:05:00Z" {
		t.Fatalf("observed_at = %q, want 2026-03-16T20:05:00Z", got)
	}
	if got := testMetadataString(node.Properties, "runtime_source"); got != "falco" {
		t.Fatalf("runtime_source = %q, want falco", got)
	}
}

func TestBuildFindingEvidenceNodeUsesStableHashWhenFindingIDMissing(t *testing.T) {
	finding := &runtime.RuntimeFinding{
		RuleID:      "reverse-shell",
		RuleName:    "Reverse Shell",
		Category:    runtime.CategoryReverseShell,
		Severity:    "critical",
		ResourceID:  "deployment:prod/api",
		Description: "Detected reverse shell connection",
		Timestamp:   time.Date(2026, 3, 16, 20, 5, 0, 0, time.UTC),
	}

	first, err := BuildFindingEvidenceNode(finding)
	if err != nil {
		t.Fatalf("first BuildFindingEvidenceNode returned error: %v", err)
	}
	second, err := BuildFindingEvidenceNode(finding)
	if err != nil {
		t.Fatalf("second BuildFindingEvidenceNode returned error: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("evidence IDs differ for identical finding without ID: %q vs %q", first.ID, second.ID)
	}
	if strings.Contains(first.ID, "runtime_finding:runtime_finding:") {
		t.Fatalf("node.ID = %q, want deterministic hash-based ID instead of synthetic source event ID", first.ID)
	}

	changed := *finding
	changed.RuleID = "crypto-mining-process"
	third, err := BuildFindingEvidenceNode(&changed)
	if err != nil {
		t.Fatalf("third BuildFindingEvidenceNode returned error: %v", err)
	}
	if first.ID == third.ID {
		t.Fatalf("distinct finding content produced same evidence ID %q", first.ID)
	}
}

func TestMaterializeFindingEvidenceIntoGraphAddsEvidenceNodes(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "observation:runtime:process_exec:seed",
		Kind: graph.NodeKindObservation,
		Name: "seed observation",
	})
	findings := []*runtime.RuntimeFinding{
		{
			ID:          "finding-3",
			RuleID:      "container-escape-nsenter",
			RuleName:    "Container Escape via nsenter",
			Category:    runtime.CategoryContainerEscape,
			Severity:    "critical",
			Description: "Detected nsenter execution",
			Timestamp:   time.Date(2026, 3, 16, 20, 10, 0, 0, time.UTC),
			Observation: &runtime.RuntimeObservation{
				ID: "runtime:process_exec:seed",
			},
		},
	}

	result := MaterializeFindingEvidenceIntoGraph(g, findings, time.Date(2026, 3, 16, 20, 11, 0, 0, time.UTC))
	if result.FindingsConsidered != 1 {
		t.Fatalf("FindingsConsidered = %d, want 1", result.FindingsConsidered)
	}
	if result.EvidenceNodesUpserted != 1 {
		t.Fatalf("EvidenceNodesUpserted = %d, want 1", result.EvidenceNodesUpserted)
	}
	if result.BasedOnEdgesCreated != 1 {
		t.Fatalf("BasedOnEdgesCreated = %d, want 1", result.BasedOnEdgesCreated)
	}
	if result.FindingsSkipped != 0 {
		t.Fatalf("FindingsSkipped = %d, want 0", result.FindingsSkipped)
	}
	if len(g.GetNodesByKind(graph.NodeKindEvidence)) != 1 {
		t.Fatalf("evidence node count = %d, want 1", len(g.GetNodesByKind(graph.NodeKindEvidence)))
	}
	evidenceNode := g.GetNodesByKind(graph.NodeKindEvidence)[0]
	outEdges := g.GetOutEdges(evidenceNode.ID)
	if len(outEdges) != 1 {
		t.Fatalf("len(outEdges) = %d, want 1", len(outEdges))
	}
	if outEdges[0].Kind != graph.EdgeKindBasedOn || outEdges[0].Target != "observation:runtime:process_exec:seed" {
		t.Fatalf("edge = %+v, want based_on edge to observation", outEdges[0])
	}
	meta := g.Metadata()
	if meta.BuiltAt.IsZero() {
		t.Fatal("metadata.BuiltAt should not be zero")
	}
	if meta.NodeCount != g.NodeCount() || meta.EdgeCount != g.EdgeCount() {
		t.Fatalf("metadata counts = %d/%d, want %d/%d", meta.NodeCount, meta.EdgeCount, g.NodeCount(), g.EdgeCount())
	}
}

func TestMaterializeFindingEvidenceIntoGraphSkipsFindingsWithoutTemporalContext(t *testing.T) {
	g := graph.New()
	result := MaterializeFindingEvidenceIntoGraph(g, []*runtime.RuntimeFinding{
		{
			ID:          "finding-4",
			RuleID:      "container-drift-shell",
			RuleName:    "Unexpected Shell",
			Category:    runtime.CategoryContainerDrift,
			Severity:    "medium",
			Description: "Detected unexpected shell",
		},
	}, time.Date(2026, 3, 16, 20, 12, 0, 0, time.UTC))

	if result.FindingsConsidered != 1 {
		t.Fatalf("FindingsConsidered = %d, want 1", result.FindingsConsidered)
	}
	if result.EvidenceNodesUpserted != 0 {
		t.Fatalf("EvidenceNodesUpserted = %d, want 0", result.EvidenceNodesUpserted)
	}
	if result.FindingsSkipped != 1 {
		t.Fatalf("FindingsSkipped = %d, want 1", result.FindingsSkipped)
	}
	if result.InvalidFindings != 1 {
		t.Fatalf("InvalidFindings = %d, want 1", result.InvalidFindings)
	}
}

func TestMaterializeFindingEvidenceIntoGraphSkipsBasedOnEdgeWhenObservationMissing(t *testing.T) {
	g := graph.New()
	result := MaterializeFindingEvidenceIntoGraph(g, []*runtime.RuntimeFinding{
		{
			ID:          "finding-missing-observation",
			RuleID:      "container-drift-shell",
			RuleName:    "Unexpected Shell",
			Category:    runtime.CategoryContainerDrift,
			Severity:    "medium",
			Description: "Detected unexpected shell",
			Timestamp:   time.Date(2026, 3, 16, 20, 12, 0, 0, time.UTC),
			Observation: &runtime.RuntimeObservation{
				ID: "runtime:process_exec:missing",
			},
		},
	}, time.Date(2026, 3, 16, 20, 13, 0, 0, time.UTC))

	if result.EvidenceNodesUpserted != 1 {
		t.Fatalf("EvidenceNodesUpserted = %d, want 1", result.EvidenceNodesUpserted)
	}
	if result.BasedOnEdgesCreated != 0 {
		t.Fatalf("BasedOnEdgesCreated = %d, want 0", result.BasedOnEdgesCreated)
	}
	evidenceNode := g.GetNodesByKind(graph.NodeKindEvidence)[0]
	if got := len(g.GetOutEdges(evidenceNode.ID)); got != 0 {
		t.Fatalf("len(outEdges) = %d, want 0", got)
	}
}

func TestMaterializeFindingEvidenceIntoGraphDoesNotDuplicateBasedOnEdges(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "observation:runtime:process_exec:repeat",
		Kind: graph.NodeKindObservation,
		Name: "repeat observation",
	})

	finding := &runtime.RuntimeFinding{
		ID:          "finding-repeat",
		RuleID:      "container-drift-shell",
		RuleName:    "Unexpected Shell",
		Category:    runtime.CategoryContainerDrift,
		Severity:    "medium",
		Description: "Detected unexpected shell",
		Timestamp:   time.Date(2026, 3, 16, 20, 12, 0, 0, time.UTC),
		Observation: &runtime.RuntimeObservation{
			ID: "runtime:process_exec:repeat",
		},
	}

	first := MaterializeFindingEvidenceIntoGraph(g, []*runtime.RuntimeFinding{finding}, time.Date(2026, 3, 16, 20, 13, 0, 0, time.UTC))
	second := MaterializeFindingEvidenceIntoGraph(g, []*runtime.RuntimeFinding{finding}, time.Date(2026, 3, 16, 20, 14, 0, 0, time.UTC))

	if first.BasedOnEdgesCreated != 1 {
		t.Fatalf("first BasedOnEdgesCreated = %d, want 1", first.BasedOnEdgesCreated)
	}
	if second.BasedOnEdgesCreated != 0 {
		t.Fatalf("second BasedOnEdgesCreated = %d, want 0", second.BasedOnEdgesCreated)
	}
	evidenceNode := g.GetNodesByKind(graph.NodeKindEvidence)[0]
	if got := len(g.GetOutEdges(evidenceNode.ID)); got != 1 {
		t.Fatalf("len(outEdges) = %d, want 1", got)
	}
}

func TestMaterializeFindingEvidenceIntoGraphRefreshesBuiltAtOnSubsequentWrites(t *testing.T) {
	g := graph.New()

	firstNow := time.Date(2026, 3, 16, 20, 20, 0, 0, time.UTC)
	secondNow := firstNow.Add(5 * time.Minute)

	firstResult := MaterializeFindingEvidenceIntoGraph(g, []*runtime.RuntimeFinding{
		{
			ID:          "finding-built-at-1",
			RuleID:      "reverse-shell",
			RuleName:    "Reverse Shell",
			Category:    runtime.CategoryReverseShell,
			Severity:    "high",
			Description: "Detected reverse shell connection",
			Timestamp:   firstNow.Add(-10 * time.Second),
		},
	}, firstNow)
	if firstResult.EvidenceNodesUpserted != 1 {
		t.Fatalf("first EvidenceNodesUpserted = %d, want 1", firstResult.EvidenceNodesUpserted)
	}
	if got := g.Metadata().BuiltAt; !got.Equal(firstNow) {
		t.Fatalf("after first materialization BuiltAt = %s, want %s", got, firstNow)
	}

	secondResult := MaterializeFindingEvidenceIntoGraph(g, []*runtime.RuntimeFinding{
		{
			ID:          "finding-built-at-2",
			RuleID:      "crypto-mining-process",
			RuleName:    "Cryptocurrency Mining Process",
			Category:    runtime.CategoryCryptoMining,
			Severity:    "high",
			Description: "Detected miner process",
			Timestamp:   secondNow.Add(-10 * time.Second),
		},
	}, secondNow)
	if secondResult.EvidenceNodesUpserted != 1 {
		t.Fatalf("second EvidenceNodesUpserted = %d, want 1", secondResult.EvidenceNodesUpserted)
	}
	if got := g.Metadata().BuiltAt; !got.Equal(secondNow) {
		t.Fatalf("after second materialization BuiltAt = %s, want %s", got, secondNow)
	}
}

func TestMaterializeFindingEvidenceIntoGraphDefersIndexBuildToCaller(t *testing.T) {
	g := graph.New()
	g.BuildIndex()
	if !g.IsIndexBuilt() {
		t.Fatal("expected initial graph index to be built")
	}

	now := time.Date(2026, 3, 16, 20, 25, 0, 0, time.UTC)
	result := MaterializeFindingEvidenceIntoGraph(g, []*runtime.RuntimeFinding{
		{
			ID:          "finding-defer-index",
			RuleID:      "reverse-shell",
			RuleName:    "Reverse Shell",
			Category:    runtime.CategoryReverseShell,
			Severity:    "high",
			Description: "Detected reverse shell connection",
			Timestamp:   now.Add(-10 * time.Second),
		},
	}, now)
	if result.EvidenceNodesUpserted != 1 {
		t.Fatalf("EvidenceNodesUpserted = %d, want 1", result.EvidenceNodesUpserted)
	}
	if g.IsIndexBuilt() {
		t.Fatal("expected index to remain stale until caller finalizes materialized graph")
	}
	if got := g.Metadata().BuiltAt; !got.Equal(now) {
		t.Fatalf("metadata.BuiltAt = %s, want %s", got, now)
	}

	FinalizeMaterializedGraph(g, now.Add(time.Minute))
	if !g.IsIndexBuilt() {
		t.Fatal("expected FinalizeMaterializedGraph to rebuild indexes")
	}
	if got := len(g.GetNodesByKindIndexed(graph.NodeKindEvidence)); got != 1 {
		t.Fatalf("len(GetNodesByKindIndexed(evidence)) = %d, want 1", got)
	}
	if got := g.Metadata().BuiltAt; !got.Equal(now.Add(time.Minute)) {
		t.Fatalf("metadata.BuiltAt after finalize = %s, want %s", got, now.Add(time.Minute))
	}
}
