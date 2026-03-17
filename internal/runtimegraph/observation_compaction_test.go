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
	if got := propertyString(summary.Properties, "subject_id"); got != "workload:prod/api" {
		t.Fatalf("subject_id = %q, want workload:prod/api", got)
	}
	if got := propertyString(summary.Properties, "observation_type"); got != "process_exec" {
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
