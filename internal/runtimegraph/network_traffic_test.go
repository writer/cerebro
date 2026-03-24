package runtimegraph

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/runtime"
)

func TestMaterializeObservationsIntoGraphCreatesSyntheticNetworkSubjectForFlowLogs(t *testing.T) {
	g := graph.New()
	observation := &runtime.RuntimeObservation{
		ID:           "runtime:network_flow:eni-1",
		Source:       "aws_vpc_flow_logs",
		Kind:         runtime.ObservationKindNetworkFlow,
		ObservedAt:   time.Date(2026, 3, 21, 18, 0, 0, 0, time.UTC),
		RecordedAt:   time.Date(2026, 3, 21, 18, 0, 5, 0, time.UTC),
		ResourceID:   "eni:eni-0123456789abcdef0",
		ResourceType: "network_interface",
		Network: &runtime.NetworkEvent{
			Protocol: "tcp",
			SrcIP:    "10.0.1.25",
			SrcPort:  44321,
			DstIP:    "10.0.2.44",
			DstPort:  443,
		},
		Metadata: map[string]any{
			"account_id": "123456789012",
		},
	}

	result := MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, observation.ObservedAt.Add(time.Minute))
	if result.ObservationsMaterialized != 1 {
		t.Fatalf("ObservationsMaterialized = %d, want 1", result.ObservationsMaterialized)
	}
	if result.MissingSubjects != 0 {
		t.Fatalf("MissingSubjects = %d, want 0", result.MissingSubjects)
	}

	subject := mustNode(t, g, "eni:eni-0123456789abcdef0")
	if subject.Kind != graph.NodeKindNetwork {
		t.Fatalf("subject.Kind = %q, want %q", subject.Kind, graph.NodeKindNetwork)
	}
	if subject.Provider != "aws" {
		t.Fatalf("subject.Provider = %q, want aws", subject.Provider)
	}
	if got := testMetadataString(subject.Properties, "network_kind"); got != "network_interface" {
		t.Fatalf("network_kind = %q, want network_interface", got)
	}
}

func TestFinalizeMaterializedGraphMarksConnectsToEdgeAsTrafficConfirmed(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:         "eni:eni-0123456789abcdef0",
		Kind:       graph.NodeKindNetwork,
		Name:       "eni-0123456789abcdef0",
		Provider:   "aws",
		Properties: map[string]any{"network_kind": "network_interface"},
	})
	g.AddNode(&graph.Node{
		ID:         "instance:i-api",
		Kind:       graph.NodeKindInstance,
		Name:       "api",
		Provider:   "aws",
		Properties: map[string]any{"private_ip": "10.0.2.44"},
	})
	g.AddEdge(&graph.Edge{
		ID:     "eni:eni-0123456789abcdef0->instance:i-api:connects_to",
		Source: "eni:eni-0123456789abcdef0",
		Target: "instance:i-api",
		Kind:   graph.EdgeKindConnectsTo,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"relationship_type": "CAN_REACH",
		},
	})

	observation := &runtime.RuntimeObservation{
		ID:           "runtime:network_flow:confirmed",
		Source:       "aws_vpc_flow_logs",
		Kind:         runtime.ObservationKindNetworkFlow,
		ObservedAt:   time.Date(2026, 3, 21, 18, 10, 0, 0, time.UTC),
		RecordedAt:   time.Date(2026, 3, 21, 18, 10, 5, 0, time.UTC),
		ResourceID:   "eni:eni-0123456789abcdef0",
		ResourceType: "network_interface",
		Network: &runtime.NetworkEvent{
			Protocol: "tcp",
			SrcIP:    "10.0.1.25",
			SrcPort:  44321,
			DstIP:    "10.0.2.44",
			DstPort:  443,
		},
		Metadata: map[string]any{
			"bytes":   int64(840),
			"packets": int64(10),
		},
	}

	MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, observation.ObservedAt.Add(time.Minute))
	FinalizeMaterializedGraph(g, observation.ObservedAt.Add(2*time.Minute))

	edge := testFindEdge(t, g, "eni:eni-0123456789abcdef0", "instance:i-api", graph.EdgeKindConnectsTo)
	if got := testMetadataString(edge.Properties, "traffic_confirmation"); got != "confirmed" {
		t.Fatalf("traffic_confirmation = %q, want confirmed", got)
	}
	if got := edge.Properties["traffic_volume_bytes"]; got != int64(840) {
		t.Fatalf("traffic_volume_bytes = %#v, want 840", got)
	}
	if got := edge.Properties["packet_count"]; got != int64(10) {
		t.Fatalf("packet_count = %#v, want 10", got)
	}
	if got := edge.Properties["distinct_source_ips"]; got != 1 {
		t.Fatalf("distinct_source_ips = %#v, want 1", got)
	}
	if got := testMetadataString(edge.Properties, "last_seen_traffic"); got != "2026-03-21T18:10:00Z" {
		t.Fatalf("last_seen_traffic = %q, want 2026-03-21T18:10:00Z", got)
	}
}

func TestFinalizeMaterializedGraphCreatesObservedTrafficEdgeForUnmodeledDestination(t *testing.T) {
	g := graph.New()

	observation := &runtime.RuntimeObservation{
		ID:           "runtime:network_flow:unmodeled",
		Source:       "aws_vpc_flow_logs",
		Kind:         runtime.ObservationKindNetworkFlow,
		ObservedAt:   time.Date(2026, 3, 21, 18, 20, 0, 0, time.UTC),
		RecordedAt:   time.Date(2026, 3, 21, 18, 20, 5, 0, time.UTC),
		ResourceID:   "eni:eni-0feedface",
		ResourceType: "network_interface",
		Network: &runtime.NetworkEvent{
			Protocol: "tcp",
			SrcIP:    "10.0.1.25",
			SrcPort:  52314,
			DstIP:    "10.0.9.99",
			DstPort:  8443,
		},
		Metadata: map[string]any{
			"bytes":   int64(2048),
			"packets": int64(4),
		},
	}

	MaterializeObservationsIntoGraph(g, []*runtime.RuntimeObservation{observation}, observation.ObservedAt.Add(time.Minute))
	FinalizeMaterializedGraph(g, observation.ObservedAt.Add(2*time.Minute))

	target := mustNode(t, g, "network:observed_ip:10.0.9.99")
	if target.Kind != graph.NodeKindNetwork {
		t.Fatalf("target.Kind = %q, want %q", target.Kind, graph.NodeKindNetwork)
	}
	if got := testMetadataString(target.Properties, "ip_address"); got != "10.0.9.99" {
		t.Fatalf("ip_address = %q, want 10.0.9.99", got)
	}

	edge := testFindEdge(t, g, "eni:eni-0feedface", "network:observed_ip:10.0.9.99", graph.EdgeKindConnectsTo)
	if got := testMetadataString(edge.Properties, "traffic_confirmation"); got != "observed_only" {
		t.Fatalf("traffic_confirmation = %q, want observed_only", got)
	}
	if got := testMetadataString(edge.Properties, "relationship_type"); got != "OBSERVED_TRAFFIC" {
		t.Fatalf("relationship_type = %q, want OBSERVED_TRAFFIC", got)
	}
}
