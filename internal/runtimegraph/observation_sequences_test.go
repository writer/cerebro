package runtimegraph

import (
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/runtime"
)

func TestMaterializeObservationSequencesGroupsObservationsWithinWindow(t *testing.T) {
	g := graph.New()
	base := time.Date(2026, 3, 17, 16, 0, 0, 0, time.UTC)
	g.AddNode(&graph.Node{ID: "deployment:prod/api", Kind: graph.NodeKindDeployment, Name: "api"})
	g.AddNode(&graph.Node{
		ID:   "evidence:runtime_finding:finding-seq-1",
		Kind: graph.NodeKindEvidence,
		Name: "finding",
		Properties: map[string]any{
			"evidence_type": "runtime_finding",
			"observed_at":   base.Format(time.RFC3339),
			"valid_from":    base.Format(time.RFC3339),
			"mitre_attack":  []string{"T1059", "T1041"},
		},
	})

	observations := []*runtime.RuntimeObservation{
		{
			ID:          "obs-seq-1",
			Kind:        runtime.ObservationKindProcessExec,
			Source:      "tetragon",
			ObservedAt:  base,
			WorkloadRef: "deployment:prod/api",
			Process:     &runtime.ProcessEvent{Name: "sh", Path: "/bin/sh"},
		},
		{
			ID:          "obs-seq-2",
			Kind:        runtime.ObservationKindFileWrite,
			Source:      "tetragon",
			ObservedAt:  base.Add(20 * time.Second),
			WorkloadRef: "deployment:prod/api",
			File:        &runtime.FileEvent{Operation: "modify", Path: "/etc/crontab"},
		},
		{
			ID:          "obs-seq-3",
			Kind:        runtime.ObservationKindNetworkFlow,
			Source:      "tetragon",
			ObservedAt:  base.Add(45 * time.Second),
			WorkloadRef: "deployment:prod/api",
			Network:     &runtime.NetworkEvent{DstIP: "203.0.113.10", DstPort: 443, Domain: "exfil.example"},
		},
	}
	MaterializeObservationsIntoGraph(g, observations, base.Add(time.Minute))
	g.AddEdge(&graph.Edge{
		ID:     "observation:obs-seq-3->evidence:runtime_finding:finding-seq-1:based_on",
		Source: "observation:obs-seq-3",
		Target: "evidence:runtime_finding:finding-seq-1",
		Kind:   graph.EdgeKindBasedOn,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"source_system": "test",
			"observed_at":   base.Add(45 * time.Second).Format(time.RFC3339),
			"valid_from":    base.Add(45 * time.Second).Format(time.RFC3339),
		},
	})

	summary := MaterializeObservationSequences(g, base.Add(2*time.Minute), DefaultObservationSequencePolicy())
	if summary.SequencesCreated != 1 {
		t.Fatalf("SequencesCreated = %d, want 1", summary.SequencesCreated)
	}
	if summary.ObservationsCorrelated != 3 {
		t.Fatalf("ObservationsCorrelated = %d, want 3", summary.ObservationsCorrelated)
	}

	sequences := g.GetNodesByKind(graph.NodeKindAttackSequence)
	if len(sequences) != 1 {
		t.Fatalf("len(attack_sequence nodes) = %d, want 1", len(sequences))
	}
	sequence := sequences[0]
	sequenceProps := sequence.PropertyMap()
	if got := propertyString(sequenceProps, "workload_ref"); got != "deployment:prod/api" {
		t.Fatalf("workload_ref = %q, want deployment:prod/api", got)
	}
	if got := propertyString(sequenceProps, "severity"); got != "critical" {
		t.Fatalf("severity = %q, want critical", got)
	}
	if got := propertyStringSlice(sequenceProps, "mitre_attack"); len(got) != 2 || got[0] != "T1041" || got[1] != "T1059" {
		t.Fatalf("mitre_attack = %#v, want sorted techniques", got)
	}
	if got := propertyInt(sequenceProps, "observation_count"); got != 3 {
		t.Fatalf("observation_count = %d, want 3", got)
	}

	if !sequenceTestEdgeExists(g.GetOutEdges("deployment:prod/api"), graph.EdgeKindHasSequence, sequence.ID) {
		t.Fatalf("expected workload to have has_sequence edge to %s", sequence.ID)
	}
	for index, observation := range observations {
		contains := false
		for _, edge := range g.GetOutEdges(sequence.ID) {
			if edge == nil || edge.Kind != graph.EdgeKindContains || edge.Target != "observation:"+observation.ID {
				continue
			}
			if got, ok := edge.Properties["sequence_index"].(int); !ok || got != index {
				t.Fatalf("sequence_index = %#v, want %d", edge.Properties["sequence_index"], index)
			}
			contains = true
		}
		if !contains {
			t.Fatalf("expected contains edge for observation %s", observation.ID)
		}
	}
	if !sequenceTestEdgeExists(g.GetOutEdges(sequence.ID), graph.EdgeKindBasedOn, "evidence:runtime_finding:finding-seq-1") {
		t.Fatalf("expected sequence to have based_on edge to correlated evidence")
	}
}

func TestMaterializeObservationSequencesSplitsAcrossWindowBoundary(t *testing.T) {
	g := graph.New()
	base := time.Date(2026, 3, 17, 16, 0, 0, 0, time.UTC)
	g.AddNode(&graph.Node{ID: "deployment:prod/api", Kind: graph.NodeKindDeployment, Name: "api"})

	observations := []*runtime.RuntimeObservation{
		{
			ID:          "obs-window-1",
			Kind:        runtime.ObservationKindProcessExec,
			Source:      "tetragon",
			ObservedAt:  base,
			WorkloadRef: "deployment:prod/api",
			Process:     &runtime.ProcessEvent{Name: "sh", Path: "/bin/sh"},
		},
		{
			ID:          "obs-window-2",
			Kind:        runtime.ObservationKindFileWrite,
			Source:      "tetragon",
			ObservedAt:  base.Add(15 * time.Second),
			WorkloadRef: "deployment:prod/api",
			File:        &runtime.FileEvent{Operation: "modify", Path: "/tmp/a"},
		},
		{
			ID:          "obs-window-3",
			Kind:        runtime.ObservationKindProcessExec,
			Source:      "tetragon",
			ObservedAt:  base.Add(2 * time.Minute),
			WorkloadRef: "deployment:prod/api",
			Process:     &runtime.ProcessEvent{Name: "bash", Path: "/bin/bash"},
		},
		{
			ID:          "obs-window-4",
			Kind:        runtime.ObservationKindNetworkFlow,
			Source:      "tetragon",
			ObservedAt:  base.Add(2*time.Minute + 15*time.Second),
			WorkloadRef: "deployment:prod/api",
			Network:     &runtime.NetworkEvent{DstIP: "198.51.100.5", DstPort: 443},
		},
	}
	MaterializeObservationsIntoGraph(g, observations, base.Add(3*time.Minute))

	summary := MaterializeObservationSequences(g, base.Add(4*time.Minute), DefaultObservationSequencePolicy())
	if summary.SequencesCreated != 2 {
		t.Fatalf("SequencesCreated = %d, want 2", summary.SequencesCreated)
	}
	if got := len(g.GetNodesByKind(graph.NodeKindAttackSequence)); got != 2 {
		t.Fatalf("len(attack_sequence nodes) = %d, want 2", got)
	}
}

func TestFinalizeMaterializedGraphRematerializesObservationSequencesWithoutDuplication(t *testing.T) {
	g := graph.New()
	base := time.Date(2026, 3, 17, 16, 0, 0, 0, time.UTC)
	g.AddNode(&graph.Node{ID: "deployment:prod/api", Kind: graph.NodeKindDeployment, Name: "api"})

	observations := []*runtime.RuntimeObservation{
		{
			ID:          "obs-finalize-1",
			Kind:        runtime.ObservationKindProcessExec,
			Source:      "tetragon",
			ObservedAt:  base,
			WorkloadRef: "deployment:prod/api",
			Process:     &runtime.ProcessEvent{Name: "sh", Path: "/bin/sh"},
		},
		{
			ID:          "obs-finalize-2",
			Kind:        runtime.ObservationKindFileWrite,
			Source:      "tetragon",
			ObservedAt:  base.Add(10 * time.Second),
			WorkloadRef: "deployment:prod/api",
			File:        &runtime.FileEvent{Operation: "modify", Path: "/etc/passwd"},
		},
	}
	MaterializeObservationsIntoGraph(g, observations, base.Add(time.Minute))

	FinalizeMaterializedGraph(g, base.Add(2*time.Minute))
	firstSequences := g.GetNodesByKind(graph.NodeKindAttackSequence)
	if len(firstSequences) != 1 {
		t.Fatalf("len(first attack_sequence nodes) = %d, want 1", len(firstSequences))
	}

	FinalizeMaterializedGraph(g, base.Add(3*time.Minute))
	secondSequences := g.GetNodesByKind(graph.NodeKindAttackSequence)
	if len(secondSequences) != 1 {
		t.Fatalf("len(second attack_sequence nodes) = %d, want 1", len(secondSequences))
	}
	if firstSequences[0].ID != secondSequences[0].ID {
		t.Fatalf("sequence ID changed across rerun: first=%s second=%s", firstSequences[0].ID, secondSequences[0].ID)
	}
	if got := len(g.GetOutEdges(secondSequences[0].ID)); got != 2 {
		t.Fatalf("len(sequence contains edges) = %d, want 2", got)
	}
}

func sequenceTestEdgeExists(edges []*graph.Edge, kind graph.EdgeKind, target string) bool {
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		if edge.Kind == kind && edge.Target == target && edge.DeletedAt == nil {
			return true
		}
	}
	return false
}

func propertyStringSlice(properties map[string]any, key string) []string {
	raw, ok := properties[key]
	if !ok || raw == nil {
		return nil
	}
	values, ok := raw.([]string)
	if !ok {
		return nil
	}
	return values
}
