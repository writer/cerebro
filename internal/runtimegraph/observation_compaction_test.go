package runtimegraph

import (
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func TestNumericPropertyValueBoundsUnsignedOverflow(t *testing.T) {
	got := numericPropertyValue(^uint64(0))
	maxInt := int(^uint(0) >> 1)
	if got != maxInt {
		t.Fatalf("numericPropertyValue(^uint64(0)) = %d, want %d", got, maxInt)
	}
}

func TestCompactHistoricalObservationsRollsUpStaleObservations(t *testing.T) {
	now := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{ID: "workload:prod/api", Kind: graph.NodeKindWorkload, Name: "api"})

	writeCompactionObservation(t, g, "observation:stale-1", "workload:prod/api", "process_exec", now.Add(-8*time.Hour), map[string]any{
		"process_name": "sh",
		"process_path": "/bin/sh",
	})
	writeCompactionObservation(t, g, "observation:stale-2", "workload:prod/api", "process_exec", now.Add(-7*time.Hour), map[string]any{
		"process_name": "bash",
		"process_path": "/bin/bash",
	})
	writeCompactionObservation(t, g, "observation:stale-3", "workload:prod/api", "process_exec", now.Add(-6*time.Hour), map[string]any{
		"process_name": "sh",
		"process_path": "/bin/sh",
	})

	result := CompactHistoricalObservations(g, now, DefaultObservationCompactionPolicy())
	if result.ObservationsCompacted != 3 {
		t.Fatalf("ObservationsCompacted = %d, want 3", result.ObservationsCompacted)
	}
	if result.SummaryNodesCreated != 1 {
		t.Fatalf("SummaryNodesCreated = %d, want 1", result.SummaryNodesCreated)
	}
	if result.SummaryTargetEdgesCreated != 1 {
		t.Fatalf("SummaryTargetEdgesCreated = %d, want 1", result.SummaryTargetEdgesCreated)
	}

	if _, ok := g.GetNode("observation:stale-1"); ok {
		t.Fatal("expected stale observation node to be removed from the active graph")
	}

	summary := mustSingleObservationSummary(t, g)
	if got, _ := summary.PropertyValue("subject_id"); got != "workload:prod/api" {
		t.Fatalf("subject_id = %q, want workload:prod/api", got)
	}
	if got, _ := summary.PropertyValue("observation_type"); got != "process_exec" {
		t.Fatalf("observation_type = %q, want process_exec", got)
	}
	if got := propertyInt(summary.Properties, "compacted_observation_count"); got != 3 {
		t.Fatalf("compacted_observation_count = %d, want 3", got)
	}
	if got := propertyString(summary.Properties, "summary_date"); got != "2026-03-17" {
		t.Fatalf("summary_date = %q, want 2026-03-17", got)
	}
	if got := stringSliceProperty(summary.Properties, "top_process_names"); len(got) != 2 || got[0] != "sh" || got[1] != "bash" {
		t.Fatalf("top_process_names = %#v, want [\"sh\", \"bash\"]", got)
	}
	if got := decodeCounterProperty(summary.Properties, "summary_process_name_counts"); got["sh"] != 2 || got["bash"] != 1 {
		t.Fatalf("summary_process_name_counts = %#v, want sh=2 bash=1", got)
	}
	outEdges := g.GetOutEdges(summary.ID)
	if len(outEdges) != 1 || outEdges[0].Kind != graph.EdgeKindTargets || outEdges[0].Target != "workload:prod/api" {
		t.Fatalf("summary target edges = %#v, want single targets edge to workload", outEdges)
	}
}

func TestCompactHistoricalObservationsPreservesBasedOnLinkedObservations(t *testing.T) {
	now := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{ID: "workload:prod/api", Kind: graph.NodeKindWorkload, Name: "api"})
	g.AddNode(&graph.Node{
		ID:   "evidence:runtime_finding:finding-1",
		Kind: graph.NodeKindEvidence,
		Name: "finding",
		Properties: map[string]any{
			"evidence_type": "runtime_finding",
		},
	})

	writeCompactionObservation(t, g, "observation:stale-linked", "workload:prod/api", "process_exec", now.Add(-8*time.Hour), map[string]any{
		"process_name": "sh",
	})
	g.AddEdge(&graph.Edge{
		ID:     "evidence:runtime_finding:finding-1->observation:stale-linked:based_on",
		Source: "evidence:runtime_finding:finding-1",
		Target: "observation:stale-linked",
		Kind:   graph.EdgeKindBasedOn,
		Effect: graph.EdgeEffectAllow,
	})

	result := CompactHistoricalObservations(g, now, DefaultObservationCompactionPolicy())
	if result.ObservationsCompacted != 0 {
		t.Fatalf("ObservationsCompacted = %d, want 0", result.ObservationsCompacted)
	}
	if result.ObservationsPreservedLinked != 1 {
		t.Fatalf("ObservationsPreservedLinked = %d, want 1", result.ObservationsPreservedLinked)
	}
	if _, ok := g.GetNode("observation:stale-linked"); !ok {
		t.Fatal("expected finding-linked observation to be preserved")
	}
	if got := len(observationSummaryNodes(g)); got != 0 {
		t.Fatalf("len(summary nodes) = %d, want 0", got)
	}
}

func TestCompactHistoricalObservationsPreservesAttackSequenceObservations(t *testing.T) {
	now := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{ID: "workload:prod/api", Kind: graph.NodeKindWorkload, Name: "api"})

	writeCompactionObservation(t, g, "observation:stale-sequenced", "workload:prod/api", "process_exec", now.Add(-8*time.Hour), map[string]any{
		"process_name": "curl",
	})
	sequence := observationSequence{
		WorkloadID:  "workload:prod/api",
		WindowStart: now.Add(-8 * time.Hour),
		WindowEnd:   now.Add(-8 * time.Hour),
		Observations: []observationSequenceCandidate{{
			Node:       mustCompactionNode(t, g, "observation:stale-sequenced"),
			ObservedAt: now.Add(-8 * time.Hour),
			WorkloadID: "workload:prod/api",
		}},
	}
	sequenceID := attackSequenceNodeID(sequence)
	g.AddNode(buildObservationSequenceNode(sequenceID, sequence, now))
	g.AddEdge(buildSequenceContainsEdge(sequenceID, "observation:stale-sequenced", 0, now.Add(-8*time.Hour), now))

	result := CompactHistoricalObservations(g, now, DefaultObservationCompactionPolicy())
	if result.ObservationsCompacted != 0 {
		t.Fatalf("ObservationsCompacted = %d, want 0", result.ObservationsCompacted)
	}
	if result.ObservationsPreservedSequenced != 1 {
		t.Fatalf("ObservationsPreservedSequenced = %d, want 1", result.ObservationsPreservedSequenced)
	}
	if _, ok := g.GetNode("observation:stale-sequenced"); !ok {
		t.Fatal("expected attack-sequence observation to be preserved")
	}
	if got := len(observationSummaryNodes(g)); got != 0 {
		t.Fatalf("len(summary nodes) = %d, want 0", got)
	}
}

func TestCompactHistoricalObservationsPreservesCorroboratedObservations(t *testing.T) {
	now := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{ID: "workload:prod/api", Kind: graph.NodeKindWorkload, Name: "api"})

	writeCompactionObservation(t, g, "observation:primary", "workload:prod/api", "process_exec", now.Add(-8*time.Hour), map[string]any{
		"process_name": "sh",
	})
	writeCompactionObservation(t, g, "observation:secondary", "workload:prod/api", "process_exec", now.Add(-8*time.Hour), map[string]any{
		"process_name": "sh",
	})

	primary := mustCompactionNode(t, g, "observation:primary")
	primaryClone := *primary
	primaryClone.Properties = cloneProperties(primary.Properties)
	primaryClone.Properties["correlation_primary"] = true
	g.AddNode(&primaryClone)

	secondary := mustCompactionNode(t, g, "observation:secondary")
	secondaryClone := *secondary
	secondaryClone.Properties = cloneProperties(secondary.Properties)
	secondaryClone.Properties["correlation_primary"] = false
	secondaryClone.Properties["corroboration_primary_id"] = "observation:primary"
	g.AddNode(&secondaryClone)

	g.AddEdge(&graph.Edge{
		ID:     "observation:secondary->observation:primary:corroborates",
		Source: "observation:secondary",
		Target: "observation:primary",
		Kind:   graph.EdgeKindCorroborates,
		Effect: graph.EdgeEffectAllow,
	})

	result := CompactHistoricalObservations(g, now, DefaultObservationCompactionPolicy())
	if result.ObservationsCompacted != 0 {
		t.Fatalf("ObservationsCompacted = %d, want 0", result.ObservationsCompacted)
	}
	if result.ObservationsPreservedCorrelated != 2 {
		t.Fatalf("ObservationsPreservedCorrelated = %d, want 2", result.ObservationsPreservedCorrelated)
	}
	if _, ok := g.GetNode("observation:primary"); !ok {
		t.Fatal("expected primary corroborated observation to be preserved")
	}
	if _, ok := g.GetNode("observation:secondary"); !ok {
		t.Fatal("expected corroborating observation to be preserved")
	}
	if got := len(observationSummaryNodes(g)); got != 0 {
		t.Fatalf("len(summary nodes) = %d, want 0", got)
	}
}

func TestCompactHistoricalObservationsIgnoresUntrustedCorrelationMetadata(t *testing.T) {
	now := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{ID: "workload:prod/api", Kind: graph.NodeKindWorkload, Name: "api"})

	writeCompactionObservation(t, g, "observation:forged-primary", "workload:prod/api", "process_exec", now.Add(-8*time.Hour), map[string]any{
		"process_name":        "sh",
		"correlation_primary": true,
	})
	writeCompactionObservation(t, g, "observation:forged-secondary", "workload:prod/api", "process_exec", now.Add(-7*time.Hour), map[string]any{
		"process_name":             "bash",
		"corroboration_primary_id": "observation:forged-primary",
	})

	result := CompactHistoricalObservations(g, now, DefaultObservationCompactionPolicy())
	if result.ObservationsPreservedCorrelated != 0 {
		t.Fatalf("ObservationsPreservedCorrelated = %d, want 0", result.ObservationsPreservedCorrelated)
	}
	if result.ObservationsCompacted != 2 {
		t.Fatalf("ObservationsCompacted = %d, want 2", result.ObservationsCompacted)
	}
	if _, ok := g.GetNode("observation:forged-primary"); ok {
		t.Fatal("expected forged correlation_primary observation to be compacted")
	}
	if _, ok := g.GetNode("observation:forged-secondary"); ok {
		t.Fatal("expected forged corroboration_primary_id observation to be compacted")
	}
}

func TestCompactHistoricalObservationsMergesIntoExistingDailySummary(t *testing.T) {
	now := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{ID: "workload:prod/api", Kind: graph.NodeKindWorkload, Name: "api"})

	writeCompactionObservation(t, g, "observation:stale-1", "workload:prod/api", "process_exec", now.Add(-8*time.Hour), map[string]any{
		"process_name": "sh",
	})
	writeCompactionObservation(t, g, "observation:stale-2", "workload:prod/api", "process_exec", now.Add(-7*time.Hour), map[string]any{
		"process_name": "bash",
	})

	first := CompactHistoricalObservations(g, now, DefaultObservationCompactionPolicy())
	if first.ObservationsCompacted != 2 {
		t.Fatalf("first ObservationsCompacted = %d, want 2", first.ObservationsCompacted)
	}
	initialSummary := mustSingleObservationSummary(t, g)

	writeCompactionObservation(t, g, "observation:stale-3", "workload:prod/api", "process_exec", now.Add(-6*time.Hour), map[string]any{
		"process_name": "sh",
	})

	second := CompactHistoricalObservations(g, now, DefaultObservationCompactionPolicy())
	if second.SummaryNodesUpdated != 1 {
		t.Fatalf("SummaryNodesUpdated = %d, want 1", second.SummaryNodesUpdated)
	}
	if second.ObservationsCompacted != 1 {
		t.Fatalf("second ObservationsCompacted = %d, want 1", second.ObservationsCompacted)
	}

	summaries := observationSummaryNodes(g)
	if len(summaries) != 1 {
		t.Fatalf("len(summary nodes) = %d, want 1", len(summaries))
	}
	if summaries[0].ID != initialSummary.ID {
		t.Fatalf("summary ID = %q, want %q", summaries[0].ID, initialSummary.ID)
	}
	if got := propertyInt(summaries[0].Properties, "compacted_observation_count"); got != 3 {
		t.Fatalf("compacted_observation_count = %d, want 3", got)
	}
	if got := decodeCounterProperty(summaries[0].Properties, "summary_process_name_counts"); got["sh"] != 2 || got["bash"] != 1 {
		t.Fatalf("summary_process_name_counts = %#v, want sh=2 bash=1", got)
	}
}

func writeCompactionObservation(t *testing.T, g *graph.Graph, id, subjectID, observationType string, observedAt time.Time, metadata map[string]any) {
	t.Helper()
	if _, err := graph.WriteObservation(g, graph.ObservationWriteRequest{
		ID:              id,
		SubjectID:       subjectID,
		ObservationType: observationType,
		Summary:         observationType,
		SourceSystem:    "runtime",
		SourceEventID:   id,
		ObservedAt:      observedAt,
		ValidFrom:       observedAt,
		RecordedAt:      observedAt,
		TransactionFrom: observedAt,
		Confidence:      1.0,
		Metadata:        metadata,
	}); err != nil {
		t.Fatalf("WriteObservation(%s): %v", id, err)
	}
}

func mustSingleObservationSummary(t *testing.T, g *graph.Graph) *graph.Node {
	t.Helper()
	summaries := observationSummaryNodes(g)
	if len(summaries) != 1 {
		t.Fatalf("len(summary nodes) = %d, want 1", len(summaries))
	}
	return summaries[0]
}

func mustCompactionNode(t *testing.T, g *graph.Graph, id string) *graph.Node {
	t.Helper()
	node, ok := g.GetNode(id)
	if !ok || node == nil {
		t.Fatalf("expected node %q to exist", id)
	}
	return node
}

func observationSummaryNodes(g *graph.Graph) []*graph.Node {
	if g == nil {
		return nil
	}
	var summaries []*graph.Node
	for _, node := range g.GetNodesByKind(graph.NodeKindObservation) {
		if isObservationSummaryNode(node) {
			summaries = append(summaries, node)
		}
	}
	return summaries
}

func stringSliceProperty(properties map[string]any, key string) []string {
	if len(properties) == 0 {
		return nil
	}
	raw, ok := properties[key]
	if !ok {
		return nil
	}
	switch typed := raw.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, value := range typed {
			if text, ok := value.(string); ok && text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}
