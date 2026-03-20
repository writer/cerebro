package graph

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkObservationPropertyStorageBuild(b *testing.B) {
	const nodeCount = 20000
	observedAt := time.Date(2026, 3, 20, 15, 0, 0, 0, time.UTC)

	b.Run("map_backed_nodes", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			nodes := make([]*Node, 0, nodeCount)
			for n := 0; n < nodeCount; n++ {
				nodes = append(nodes, benchmarkObservationNode(fmt.Sprintf("observation:map:%d", n), observedAt))
			}
			if len(nodes) != nodeCount {
				b.Fatalf("built %d nodes, want %d", len(nodes), nodeCount)
			}
		}
	})

	b.Run("columnar_nodes", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			columns := NewPropertyColumns()
			nodes := make([]*Node, 0, nodeCount)
			for n := 0; n < nodeCount; n++ {
				nodes = append(nodes, benchmarkColumnarObservationNode(fmt.Sprintf("observation:column:%d", n), NodeOrdinal(n+1), columns, observedAt))
			}
			if len(nodes) != nodeCount {
				b.Fatalf("built %d nodes, want %d", len(nodes), nodeCount)
			}
		}
	})
}

func BenchmarkObservationPropertyAccess(b *testing.B) {
	observedAt := time.Date(2026, 3, 20, 16, 0, 0, 0, time.UTC)
	mapNode := benchmarkObservationNode("observation:map:access", observedAt)

	columnGraph := New()
	columnGraph.AddNode(benchmarkObservationNode("observation:column:access", observedAt))
	columnNode, ok := columnGraph.GetNode("observation:column:access")
	if !ok {
		b.Fatal("expected column-backed observation node")
	}

	b.Run("map_lookup", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if got := mapNode.Properties["detail"]; got != "Error rate increased after deploy" {
				b.Fatalf("detail = %#v", got)
			}
		}
	})

	b.Run("columnar_lookup", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			props, ok := columnNode.ObservationProperties()
			if !ok || props.Detail != "Error rate increased after deploy" {
				b.Fatalf("ObservationProperties() = %+v, %v", props, ok)
			}
		}
	})
}

func benchmarkObservationNode(id string, observedAt time.Time) *Node {
	return &Node{
		ID:   id,
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
}

func benchmarkColumnarObservationNode(id string, ordinal NodeOrdinal, columns *PropertyColumns, observedAt time.Time) *Node {
	node := &Node{
		ID:              id,
		Kind:            NodeKindObservation,
		Name:            "runtime_signal",
		ordinal:         ordinal,
		propertyColumns: columns,
	}
	columns.SetObservationProperties(ordinal, ObservationProperties{
		ObservationType: "runtime_signal",
		SubjectID:       "service:payments",
		Detail:          "Error rate increased after deploy",
		SourceSystem:    "agent",
		SourceEventID:   "evt-1",
		Confidence:      0.91,
		ObservedAt:      observedAt,
		ValidFrom:       observedAt,
		RecordedAt:      observedAt.Add(30 * time.Second),
		TransactionFrom: observedAt.Add(30 * time.Second),
		present: observationPropertyObservationType |
			observationPropertySubjectID |
			observationPropertyDetail |
			observationPropertySourceSystem |
			observationPropertySourceEventID |
			observationPropertyConfidence |
			observationPropertyObservedAt |
			observationPropertyValidFrom |
			observationPropertyRecordedAt |
			observationPropertyTransactionFrom,
	})
	return node
}
