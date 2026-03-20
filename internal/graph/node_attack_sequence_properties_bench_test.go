package graph

import (
	"testing"
	"time"
)

func BenchmarkNodeAttackSequenceProperties(b *testing.B) {
	sequenceStart := time.Date(2026, 3, 17, 22, 0, 0, 0, time.UTC)
	sequenceEnd := sequenceStart.Add(2 * time.Minute)
	newNode := func() *Node {
		return &Node{
			ID:   "attack_sequence:runtime:bench",
			Kind: NodeKindAttackSequence,
			Name: "Attack sequence bench",
			Properties: map[string]any{
				"sequence_type":           "runtime_observation_window",
				"workload_ref":            "deployment:prod/bench",
				"detail":                  "correlated runtime observations",
				"severity":                "high",
				"observation_count":       3,
				"sequence_start":          sequenceStart.Format(time.RFC3339),
				"sequence_end":            sequenceEnd.Format(time.RFC3339),
				"window_seconds":          int64(120),
				"observation_types":       []string{"process_exec", "network_flow"},
				"ordered_observation_ids": []string{"observation:1", "observation:2"},
				"mitre_attack":            []string{"T1046"},
				"source_system":           "runtime_sequences",
				"source_event_id":         "attack_sequence:runtime:bench",
				"observed_at":             sequenceEnd.Format(time.RFC3339),
				"valid_from":              sequenceStart.Format(time.RFC3339),
				"valid_to":                sequenceEnd.Format(time.RFC3339),
				"recorded_at":             sequenceEnd.Add(5 * time.Second).Format(time.RFC3339),
				"transaction_from":        sequenceEnd.Add(5 * time.Second).Format(time.RFC3339),
				"confidence":              1.0,
			},
		}
	}

	b.Run("typed_cache", func(b *testing.B) {
		node := newNode()
		hydrateNodeTypedProperties(node)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			props, ok := node.AttackSequenceProperties()
			if !ok || props.WorkloadRef == "" {
				b.Fatal("expected typed attack sequence properties")
			}
		}
	})

	b.Run("map_fallback", func(b *testing.B) {
		node := newNode()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			props, ok := node.AttackSequenceProperties()
			if !ok || props.WorkloadRef == "" {
				b.Fatal("expected typed attack sequence properties")
			}
		}
	})
}
