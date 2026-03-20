package graph

import (
	"testing"
	"time"
)

func BenchmarkNodeObservationProperties(b *testing.B) {
	observedAt := time.Date(2026, 3, 17, 11, 0, 0, 0, time.UTC)
	node := &Node{
		ID:   "observation:payments:runtime",
		Kind: NodeKindObservation,
		Name: "runtime_signal",
		Properties: map[string]any{
			"observation_type": "runtime_signal",
			"subject_id":       "service:payments",
			"detail":           "Error rate increased after deploy",
			"source_system":    "agent",
			"source_event_id":  "evt-1",
			"confidence":       0.91,
			"observed_at":      observedAt.Format(time.RFC3339),
			"valid_from":       observedAt.Format(time.RFC3339),
			"recorded_at":      observedAt.Add(30 * time.Second).Format(time.RFC3339),
			"transaction_from": observedAt.Add(30 * time.Second).Format(time.RFC3339),
		},
	}

	b.Run("typed_cache", func(b *testing.B) {
		hydrateNodeTypedProperties(node)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			props, ok := node.ObservationProperties()
			if !ok || props.SubjectID == "" {
				b.Fatal("expected typed observation properties")
			}
		}
	})

	b.Run("map_fallback", func(b *testing.B) {
		node.observationProps = nil
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			props, ok := node.ObservationProperties()
			if !ok || props.SubjectID == "" {
				b.Fatal("expected typed observation properties")
			}
			node.observationProps = nil
		}
	})
}
