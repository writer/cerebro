package hubble

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/evalops/cerebro/internal/runtime"
)

func TestAdapterNormalizeGoldenPayloads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		fixture           string
		wantKind          runtime.RuntimeObservationKind
		wantResourceID    string
		wantWorkloadRef   string
		wantDirection     string
		wantProtocol      string
		wantDstIP         string
		wantDstPort       int
		wantVerdict       string
		wantPrimaryID     int
		wantPeerID        int
		wantDomain        string
		wantObservationAt string
	}{
		{
			name:              "egress tcp",
			fixture:           "egress_tcp.golden.json",
			wantKind:          runtime.ObservationKindNetworkFlow,
			wantResourceID:    "pod:default/xwing",
			wantWorkloadRef:   "workload:default/xwing",
			wantDirection:     "outbound",
			wantProtocol:      "TCP",
			wantDstIP:         "10.244.1.208",
			wantDstPort:       80,
			wantVerdict:       "DROPPED",
			wantPrimaryID:     56030,
			wantPeerID:        56031,
			wantObservationAt: "2024-07-09T17:55:50.869739112Z",
		},
		{
			name:              "ingress udp",
			fixture:           "ingress_udp.golden.json",
			wantKind:          runtime.ObservationKindNetworkFlow,
			wantResourceID:    "pod:kube-system/coredns-56f8",
			wantWorkloadRef:   "workload:kube-system/coredns",
			wantDirection:     "inbound",
			wantProtocol:      "UDP",
			wantDstIP:         "10.244.2.19",
			wantDstPort:       53,
			wantVerdict:       "FORWARDED",
			wantPrimaryID:     12938,
			wantPeerID:        2,
			wantObservationAt: "2024-07-09T18:01:00Z",
		},
		{
			name:              "dns query",
			fixture:           "dns_query.golden.json",
			wantKind:          runtime.ObservationKindDNSQuery,
			wantResourceID:    "pod:default/xwing",
			wantWorkloadRef:   "workload:default/xwing",
			wantDirection:     "outbound",
			wantProtocol:      "UDP",
			wantDstIP:         "10.96.0.10",
			wantDstPort:       53,
			wantVerdict:       "FORWARDED",
			wantPrimaryID:     1234,
			wantPeerID:        5678,
			wantDomain:        "api.github.com.",
			wantObservationAt: "2024-07-09T18:01:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw := mustReadHubbleFixture(t, tt.fixture)
			observations, err := (Adapter{}).Normalize(context.Background(), raw)
			if err != nil {
				t.Fatalf("Normalize(%s): %v", tt.fixture, err)
			}
			if len(observations) != 1 {
				t.Fatalf("len(observations) = %d, want 1", len(observations))
			}

			observation := observations[0]
			if observation.Kind != tt.wantKind {
				t.Fatalf("kind = %s, want %s", observation.Kind, tt.wantKind)
			}
			if observation.ResourceID != tt.wantResourceID {
				t.Fatalf("resource_id = %q, want %q", observation.ResourceID, tt.wantResourceID)
			}
			if observation.WorkloadRef != tt.wantWorkloadRef {
				t.Fatalf("workload_ref = %q, want %q", observation.WorkloadRef, tt.wantWorkloadRef)
			}
			if got := observation.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"); got != tt.wantObservationAt {
				t.Fatalf("observed_at = %q, want %q", got, tt.wantObservationAt)
			}
			if observation.Network == nil {
				t.Fatal("expected network context")
			}
			if observation.Network.Direction != tt.wantDirection {
				t.Fatalf("network.direction = %q, want %q", observation.Network.Direction, tt.wantDirection)
			}
			if observation.Network.Protocol != tt.wantProtocol {
				t.Fatalf("network.protocol = %q, want %q", observation.Network.Protocol, tt.wantProtocol)
			}
			if observation.Network.DstIP != tt.wantDstIP {
				t.Fatalf("network.dst_ip = %q, want %q", observation.Network.DstIP, tt.wantDstIP)
			}
			if observation.Network.DstPort != tt.wantDstPort {
				t.Fatalf("network.dst_port = %d, want %d", observation.Network.DstPort, tt.wantDstPort)
			}
			if tt.wantDomain != "" && observation.Network.Domain != tt.wantDomain {
				t.Fatalf("network.domain = %q, want %q", observation.Network.Domain, tt.wantDomain)
			}
			if got := observation.Metadata["verdict"]; got != tt.wantVerdict {
				t.Fatalf("metadata.verdict = %#v, want %q", got, tt.wantVerdict)
			}
			if got := observation.Metadata["primary_identity"]; !matchesIntMetadata(got, tt.wantPrimaryID) {
				t.Fatalf("metadata.primary_identity = %#v, want %d", got, tt.wantPrimaryID)
			}
			if got := observation.Metadata["peer_identity"]; !matchesIntMetadata(got, tt.wantPeerID) {
				t.Fatalf("metadata.peer_identity = %#v, want %d", got, tt.wantPeerID)
			}
		})
	}
}

func mustReadHubbleFixture(t *testing.T, name string) []byte {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", name, err)
	}
	return raw
}

func matchesIntMetadata(got any, want int) bool {
	switch value := got.(type) {
	case int:
		return value == want
	case int32:
		return int(value) == want
	case int64:
		return int(value) == want
	case uint32:
		return int(value) == want
	case uint64:
		return int(value) == want
	case float64:
		return int(value) == want
	default:
		return false
	}
}
