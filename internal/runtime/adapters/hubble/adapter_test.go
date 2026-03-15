package hubble

import (
	"context"
	"strings"
	"testing"

	"github.com/evalops/cerebro/internal/runtime"
)

func TestAdapterNormalizeEgressTCPFlow(t *testing.T) {
	raw := []byte(`{
		"flow": {
			"time": "2024-07-09T17:55:50.869739112Z",
			"uuid": "flow-123",
			"verdict": "DROPPED",
			"IP": {
				"source": "10.244.3.187",
				"destination": "10.244.1.208",
				"ipVersion": "IPv4"
			},
			"l4": {
				"TCP": {
					"source_port": 44916,
					"destination_port": 80
				}
			},
			"source": {
				"identity": 56030,
				"namespace": "default",
				"labels": [
					"k8s:app=xwing"
				],
				"pod_name": "xwing",
				"workloads": [
					{
						"name": "xwing",
						"kind": "Deployment"
					}
				]
			},
			"destination": {
				"identity": 56030,
				"namespace": "default",
				"labels": [
					"k8s:app=deathstar"
				],
				"pod_name": "deathstar-6c94dcc57b-ssqjd",
				"workloads": [
					{
						"name": "deathstar",
						"kind": "Deployment"
					}
				]
			},
			"Type": "L3_L4",
			"node_name": "kind-kind/kind-worker",
			"traffic_direction": "EGRESS",
			"drop_reason_desc": "POLICY_DENIED"
		},
		"node_name": "kind-kind/kind-worker",
		"time": "2024-07-09T17:55:50.869739112Z"
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	observation := observations[0]
	if observation.Kind != runtime.ObservationKindNetworkFlow {
		t.Fatalf("kind = %s, want %s", observation.Kind, runtime.ObservationKindNetworkFlow)
	}
	if observation.ID != "hubble:flow-123" {
		t.Fatalf("id = %q, want %q", observation.ID, "hubble:flow-123")
	}
	if observation.ResourceID != "pod:default/xwing" {
		t.Fatalf("resource_id = %q, want pod:default/xwing", observation.ResourceID)
	}
	if observation.WorkloadRef != "workload:default/xwing" {
		t.Fatalf("workload_ref = %q, want workload:default/xwing", observation.WorkloadRef)
	}
	if observation.Network == nil {
		t.Fatal("expected network context")
	}
	if observation.Network.Direction != "outbound" {
		t.Fatalf("direction = %q, want outbound", observation.Network.Direction)
	}
	if observation.Network.Protocol != "TCP" {
		t.Fatalf("protocol = %q, want TCP", observation.Network.Protocol)
	}
	if observation.Network.SrcPort != 44916 || observation.Network.DstPort != 80 {
		t.Fatalf("ports = %#v, want 44916 -> 80", observation.Network)
	}
	if got := observation.Metadata["drop_reason_desc"]; got != "POLICY_DENIED" {
		t.Fatalf("drop_reason_desc = %#v, want POLICY_DENIED", got)
	}
}

func TestAdapterNormalizeIngressUDPFlowAnchorsDestination(t *testing.T) {
	raw := []byte(`{
		"flow": {
			"time": "2024-07-09T18:01:00Z",
			"verdict": "FORWARDED",
			"IP": {
				"source": "1.2.3.4",
				"destination": "10.244.2.19",
				"ipVersion": "IPv4"
			},
			"l4": {
				"UDP": {
					"source_port": 53000,
					"destination_port": 53
				}
			},
			"source": {
				"identity": 2,
				"labels": [
					"reserved:world"
				]
			},
			"destination": {
				"identity": 12938,
				"namespace": "kube-system",
				"pod_name": "coredns-56f8",
				"workloads": [
					{
						"name": "coredns",
						"kind": "Deployment"
					}
				]
			},
			"Type": "L3_L4",
			"traffic_direction": "INGRESS",
			"source_names": [
				"client.example.com"
			],
			"destination_names": [
				"kube-dns.kube-system.svc.cluster.local"
			]
		},
		"node_name": "worker-2",
		"time": "2024-07-09T18:01:00Z"
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	observation := observations[0]
	if observation.ResourceID != "pod:kube-system/coredns-56f8" {
		t.Fatalf("resource_id = %q, want pod:kube-system/coredns-56f8", observation.ResourceID)
	}
	if observation.WorkloadRef != "workload:kube-system/coredns" {
		t.Fatalf("workload_ref = %q, want workload:kube-system/coredns", observation.WorkloadRef)
	}
	if observation.Network == nil || observation.Network.Direction != "inbound" {
		t.Fatalf("network = %#v, want inbound network context", observation.Network)
	}
	if observation.Network.Protocol != "UDP" {
		t.Fatalf("protocol = %q, want UDP", observation.Network.Protocol)
	}
	if got := observation.Metadata["peer_identity"]; got != nil {
		t.Fatalf("peer_identity should stay out of metadata, got %#v", got)
	}
	if got := observation.Metadata["peer_namespace"]; got != "" && got != nil {
		t.Fatalf("peer_namespace = %#v, want empty for world source", got)
	}
	if got := observation.Metadata["source_identity"]; got != float64(2) && got != uint32(2) && got != 2 {
		t.Fatalf("source_identity = %#v, want 2", got)
	}
	if got := observation.Metadata["destination_pod_name"]; got != "coredns-56f8" {
		t.Fatalf("destination_pod_name = %#v, want coredns-56f8", got)
	}
}

func TestAdapterNormalizeRejectsDNSFlowsForDedicatedSlice(t *testing.T) {
	raw := []byte(`{
		"flow": {
			"time": "2024-07-09T18:01:00Z",
			"verdict": "FORWARDED",
			"IP": {
				"source": "10.244.0.10",
				"destination": "10.96.0.10",
				"ipVersion": "IPv4"
			},
			"l4": {
				"UDP": {
					"source_port": 53000,
					"destination_port": 53
				}
			},
			"l7": {
				"type": "REQUEST",
				"dns": {
					"query": "api.github.com"
				}
			}
		}
	}`)

	if _, err := (Adapter{}).Normalize(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "unsupported l7 flow") {
		t.Fatalf("Normalize error = %v, want unsupported l7 flow", err)
	}
}

func TestAdapterNormalizeRejectsHTTPFlowsForDedicatedSlice(t *testing.T) {
	raw := []byte(`{
		"flow": {
			"time": "2024-07-09T18:01:00Z",
			"verdict": "FORWARDED",
			"IP": {
				"source": "10.244.0.10",
				"destination": "10.96.0.10",
				"ipVersion": "IPv4"
			},
			"l4": {
				"TCP": {
					"source_port": 53000,
					"destination_port": 443
				}
			},
			"l7": {
				"type": "REQUEST",
				"http": {
					"method": "GET",
					"url": "https://api.github.com/"
				}
			}
		}
	}`)

	if _, err := (Adapter{}).Normalize(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "unsupported l7 flow") {
		t.Fatalf("Normalize error = %v, want unsupported l7 flow", err)
	}
}

func TestAdapterNormalizeRejectsUnsupportedWrapperEvents(t *testing.T) {
	raw := []byte(`{
		"node_status": {
			"state": "NODE_CONNECTED"
		}
	}`)

	if _, err := (Adapter{}).Normalize(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "unsupported event") {
		t.Fatalf("Normalize error = %v, want unsupported event", err)
	}
}

func TestAdapterNormalizePrefersFlowTimeOverWrapperTime(t *testing.T) {
	raw := []byte(`{
		"flow": {
			"time": "2024-07-09T18:01:00Z",
			"verdict": "FORWARDED",
			"IP": {
				"source": "10.244.0.10",
				"destination": "10.96.0.10",
				"ipVersion": "IPv4"
			},
			"l4": {
				"TCP": {
					"source_port": 53000,
					"destination_port": 443
				}
			}
		},
		"time": "2024-07-09T18:05:00Z"
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	got := observations[0].ObservedAt.UTC().Format("2006-01-02T15:04:05Z")
	if got != "2024-07-09T18:01:00Z" {
		t.Fatalf("observed_at = %q, want 2024-07-09T18:01:00Z", got)
	}
}

func TestAdapterNormalizeFallbackIDIncludesPorts(t *testing.T) {
	rawA := []byte(`{
		"flow": {
			"time": "2024-07-09T18:01:00Z",
			"verdict": "FORWARDED",
			"IP": {
				"source": "10.244.0.10",
				"destination": "10.96.0.10",
				"ipVersion": "IPv4"
			},
			"l4": {
				"TCP": {
					"source_port": 53000,
					"destination_port": 443
				}
			}
		}
	}`)
	rawB := []byte(`{
		"flow": {
			"time": "2024-07-09T18:01:00Z",
			"verdict": "FORWARDED",
			"IP": {
				"source": "10.244.0.10",
				"destination": "10.96.0.10",
				"ipVersion": "IPv4"
			},
			"l4": {
				"TCP": {
					"source_port": 53001,
					"destination_port": 443
				}
			}
		}
	}`)

	observationsA, err := (Adapter{}).Normalize(context.Background(), rawA)
	if err != nil {
		t.Fatalf("Normalize A: %v", err)
	}
	observationsB, err := (Adapter{}).Normalize(context.Background(), rawB)
	if err != nil {
		t.Fatalf("Normalize B: %v", err)
	}

	if observationsA[0].ID == observationsB[0].ID {
		t.Fatalf("ids should differ when ports differ: %q", observationsA[0].ID)
	}
	if !strings.Contains(observationsA[0].ID, ":53000:443:") {
		t.Fatalf("id = %q, want source/destination ports embedded", observationsA[0].ID)
	}
	if !strings.Contains(observationsB[0].ID, ":53001:443:") {
		t.Fatalf("id = %q, want source/destination ports embedded", observationsB[0].ID)
	}
}
