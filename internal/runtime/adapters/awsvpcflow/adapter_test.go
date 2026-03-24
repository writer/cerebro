package awsvpcflow

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/runtime"
)

func TestAdapterNormalizeCloudWatchEnvelope(t *testing.T) {
	raw := []byte(`{
		"owner": "123456789012",
		"logGroup": "vpc-flow-logs",
		"logStream": "eni/eni-0123456789abcdef0",
		"messageType": "DATA_MESSAGE",
		"logEvents": [
			{
				"id": "cwl-event-1",
				"timestamp": 1712700060000,
				"message": "2 123456789012 eni-0123456789abcdef0 10.0.1.25 34.235.12.8 44321 443 6 10 840 1712700000 1712700060 ACCEPT OK"
			}
		]
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	observation := observations[0]
	if observation.Source != SourceName {
		t.Fatalf("source = %q, want %q", observation.Source, SourceName)
	}
	if observation.Kind != runtime.ObservationKindNetworkFlow {
		t.Fatalf("kind = %q, want %q", observation.Kind, runtime.ObservationKindNetworkFlow)
	}
	if observation.ID != SourceName+":cwl-event-1" {
		t.Fatalf("id = %q, want %q", observation.ID, SourceName+":cwl-event-1")
	}
	if observation.ResourceID != "eni:eni-0123456789abcdef0" {
		t.Fatalf("resource_id = %q, want eni:eni-0123456789abcdef0", observation.ResourceID)
	}
	if observation.ResourceType != "network_interface" {
		t.Fatalf("resource_type = %q, want network_interface", observation.ResourceType)
	}
	if observation.Network == nil {
		t.Fatal("expected network context")
	}
	if observation.Network.Protocol != "tcp" {
		t.Fatalf("protocol = %q, want tcp", observation.Network.Protocol)
	}
	if observation.Network.SrcIP != "10.0.1.25" || observation.Network.DstIP != "34.235.12.8" {
		t.Fatalf("network IPs = %#v, want 10.0.1.25 -> 34.235.12.8", observation.Network)
	}
	if observation.Network.SrcPort != 44321 || observation.Network.DstPort != 443 {
		t.Fatalf("network ports = %#v, want 44321 -> 443", observation.Network)
	}
	if observation.ObservedAt.UTC().Unix() != 1712700060 {
		t.Fatalf("observed_at = %d, want 1712700060", observation.ObservedAt.UTC().Unix())
	}
	if got := observation.Metadata["account_id"]; got != "123456789012" {
		t.Fatalf("account_id = %#v, want 123456789012", got)
	}
	if got := observation.Metadata["action"]; got != "ACCEPT" {
		t.Fatalf("action = %#v, want ACCEPT", got)
	}
	if got := observation.Metadata["log_status"]; got != "OK" {
		t.Fatalf("log_status = %#v, want OK", got)
	}
	if got := observation.Metadata["cloudwatch_log_group"]; got != "vpc-flow-logs" {
		t.Fatalf("cloudwatch_log_group = %#v, want vpc-flow-logs", got)
	}
}

func TestAdapterNormalizeRejectsMalformedFlowLogLine(t *testing.T) {
	_, err := (Adapter{}).Normalize(context.Background(), []byte("not-a-valid-flow-log"))
	if err == nil {
		t.Fatal("expected malformed flow log payload to fail")
	}
}
