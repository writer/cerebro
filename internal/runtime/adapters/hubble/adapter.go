package hubble

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/runtime"
	"github.com/evalops/cerebro/internal/runtime/adapters"
)

// Adapter normalizes Hubble exporter / observe JSON into runtime observations.
type Adapter struct{}

var _ adapters.Adapter = Adapter{}

type payload struct {
	Flow     *flowEnvelope `json:"flow,omitempty"`
	NodeName string        `json:"node_name,omitempty"`
	Time     time.Time     `json:"time,omitempty"`
}

type flowEnvelope struct {
	Time               time.Time        `json:"time,omitempty"`
	UUID               string           `json:"uuid,omitempty"`
	Verdict            string           `json:"verdict,omitempty"`
	IP                 *ipEnvelope      `json:"IP,omitempty"`
	L4                 *layer4Envelope  `json:"l4,omitempty"`
	Source             *endpoint        `json:"source,omitempty"`
	Destination        *endpoint        `json:"destination,omitempty"`
	Type               string           `json:"Type,omitempty"`
	NodeName           string           `json:"node_name,omitempty"`
	SourceNames        []string         `json:"source_names,omitempty"`
	DestinationNames   []string         `json:"destination_names,omitempty"`
	TrafficDirection   string           `json:"traffic_direction,omitempty"`
	DropReasonDesc     string           `json:"drop_reason_desc,omitempty"`
	TraceObservation   string           `json:"trace_observation_point,omitempty"`
	SourceService      *serviceEnvelope `json:"source_service,omitempty"`
	DestinationService *serviceEnvelope `json:"destination_service,omitempty"`
	L7                 *layer7Envelope  `json:"l7,omitempty"`
}

type ipEnvelope struct {
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	IPVersion   string `json:"ipVersion,omitempty"`
	Encrypted   bool   `json:"encrypted,omitempty"`
}

type layer4Envelope struct {
	TCP    *portEnvelope `json:"TCP,omitempty"`
	UDP    *portEnvelope `json:"UDP,omitempty"`
	SCTP   *portEnvelope `json:"SCTP,omitempty"`
	ICMPv4 *icmpEnvelope `json:"ICMPv4,omitempty"`
	ICMPv6 *icmpEnvelope `json:"ICMPv6,omitempty"`
	VRRP   *vrrpEnvelope `json:"VRRP,omitempty"`
	IGMP   *igmpEnvelope `json:"IGMP,omitempty"`
}

type portEnvelope struct {
	SourcePort      uint32 `json:"source_port,omitempty"`
	DestinationPort uint32 `json:"destination_port,omitempty"`
}

type icmpEnvelope struct {
	Type uint32 `json:"type,omitempty"`
	Code uint32 `json:"code,omitempty"`
}

type vrrpEnvelope struct {
	Type     uint32 `json:"type,omitempty"`
	VRID     uint32 `json:"vrid,omitempty"`
	Priority uint32 `json:"priority,omitempty"`
}

type igmpEnvelope struct {
	Type         uint32 `json:"type,omitempty"`
	GroupAddress string `json:"group_address,omitempty"`
}

type endpoint struct {
	ID          uint32             `json:"ID,omitempty"`
	Identity    uint32             `json:"identity,omitempty"`
	ClusterName string             `json:"cluster_name,omitempty"`
	Namespace   string             `json:"namespace,omitempty"`
	Labels      []string           `json:"labels,omitempty"`
	PodName     string             `json:"pod_name,omitempty"`
	Workloads   []workloadEnvelope `json:"workloads,omitempty"`
}

type workloadEnvelope struct {
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
}

type serviceEnvelope struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type layer7Envelope struct {
	Type string        `json:"type,omitempty"`
	DNS  *dnsEnvelope  `json:"dns,omitempty"`
	HTTP *httpEnvelope `json:"http,omitempty"`
}

type dnsEnvelope struct {
	Query string `json:"query,omitempty"`
}

type httpEnvelope struct {
	Code     uint32 `json:"code,omitempty"`
	Method   string `json:"method,omitempty"`
	URL      string `json:"url,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

func (Adapter) Source() string {
	return "hubble"
}

func (Adapter) Normalize(_ context.Context, raw []byte) ([]*runtime.RuntimeObservation, error) {
	var event payload
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, fmt.Errorf("decode hubble payload: %w", err)
	}
	if event.Flow == nil {
		return nil, fmt.Errorf("decode hubble payload: unsupported event")
	}
	observation, err := observationFromFlow(event)
	if err != nil {
		return nil, err
	}
	return []*runtime.RuntimeObservation{observation}, nil
}

func observationFromFlow(event payload) (*runtime.RuntimeObservation, error) {
	flow := event.Flow
	if flow.IP == nil {
		return nil, fmt.Errorf("decode hubble payload: missing IP context")
	}
	if flow.L7 != nil {
		return nil, fmt.Errorf("decode hubble payload: unsupported l7 flow")
	}

	protocol, srcPort, dstPort := protocolFromL4(flow.L4)
	if protocol == "" {
		return nil, fmt.Errorf("decode hubble payload: missing supported L4 context")
	}

	observedAt := firstNonZeroTime(flow.Time, event.Time)
	nodeName := firstNonEmpty(event.NodeName, flow.NodeName)
	direction, primary, peer := primaryEndpoints(flow)

	metadata := map[string]any{
		"node_name":         nodeName,
		"verdict":           strings.TrimSpace(flow.Verdict),
		"traffic_direction": strings.TrimSpace(flow.TrafficDirection),
		"flow_type":         strings.TrimSpace(flow.Type),
		"ip_version":        strings.TrimSpace(flow.IP.IPVersion),
		"encrypted":         flow.IP.Encrypted,
	}
	if value := strings.TrimSpace(flow.DropReasonDesc); value != "" {
		metadata["drop_reason_desc"] = value
	}
	if value := strings.TrimSpace(flow.TraceObservation); value != "" {
		metadata["trace_observation_point"] = value
	}
	if len(flow.SourceNames) > 0 {
		metadata["source_names"] = append([]string(nil), flow.SourceNames...)
	}
	if len(flow.DestinationNames) > 0 {
		metadata["destination_names"] = append([]string(nil), flow.DestinationNames...)
	}
	addEndpointMetadata(metadata, "source", flow.Source)
	addEndpointMetadata(metadata, "destination", flow.Destination)
	addServiceMetadata(metadata, "source_service", flow.SourceService)
	addServiceMetadata(metadata, "destination_service", flow.DestinationService)
	if peer != nil {
		if value := strings.TrimSpace(peer.Namespace); value != "" {
			metadata["peer_namespace"] = value
		}
		if value := strings.TrimSpace(peer.PodName); value != "" {
			metadata["peer_pod_name"] = value
		}
		if value := primaryWorkloadName(peer); value != "" {
			metadata["peer_workload_name"] = value
		}
	}

	observation := &runtime.RuntimeObservation{
		ID:         hubbleObservationID(flow, protocol, observedAt),
		Kind:       runtime.ObservationKindNetworkFlow,
		Source:     "hubble",
		ObservedAt: observedAt,
		NodeName:   nodeName,
		Cluster:    clusterName(primary, peer),
		Namespace:  namespace(primary, peer),
		Network: &runtime.NetworkEvent{
			Direction: direction,
			Protocol:  protocol,
			SrcIP:     strings.TrimSpace(flow.IP.Source),
			SrcPort:   srcPort,
			DstIP:     strings.TrimSpace(flow.IP.Destination),
			DstPort:   dstPort,
		},
		Metadata: metadata,
		Tags: adapters.CompactTags(
			"hubble",
			"network_flow",
			strings.ToLower(strings.TrimSpace(flow.Verdict)),
			strings.ToLower(strings.TrimSpace(protocol)),
		),
	}

	if primary != nil {
		observation.ResourceID = podResourceID(primary.Namespace, primary.PodName)
		observation.ResourceType = "pod"
		observation.WorkloadRef = workloadRef(primary)
	}

	return observation, nil
}

func protocolFromL4(l4 *layer4Envelope) (string, int, int) {
	if l4 == nil {
		return "", 0, 0
	}
	switch {
	case l4.TCP != nil:
		return "TCP", int(l4.TCP.SourcePort), int(l4.TCP.DestinationPort)
	case l4.UDP != nil:
		return "UDP", int(l4.UDP.SourcePort), int(l4.UDP.DestinationPort)
	case l4.SCTP != nil:
		return "SCTP", int(l4.SCTP.SourcePort), int(l4.SCTP.DestinationPort)
	case l4.ICMPv4 != nil:
		return "ICMPv4", 0, 0
	case l4.ICMPv6 != nil:
		return "ICMPv6", 0, 0
	case l4.VRRP != nil:
		return "VRRP", 0, 0
	case l4.IGMP != nil:
		return "IGMP", 0, 0
	default:
		return "", 0, 0
	}
}

func primaryEndpoints(flow *flowEnvelope) (string, *endpoint, *endpoint) {
	switch strings.TrimSpace(flow.TrafficDirection) {
	case "INGRESS":
		return "inbound", flow.Destination, flow.Source
	case "EGRESS":
		return "outbound", flow.Source, flow.Destination
	default:
		switch {
		case hasPod(flow.Source) && !hasPod(flow.Destination):
			return "outbound", flow.Source, flow.Destination
		case hasPod(flow.Destination) && !hasPod(flow.Source):
			return "inbound", flow.Destination, flow.Source
		case hasPod(flow.Source):
			return "outbound", flow.Source, flow.Destination
		default:
			return "inbound", flow.Destination, flow.Source
		}
	}
}

func hubbleObservationID(flow *flowEnvelope, protocol string, observedAt time.Time) string {
	if value := strings.TrimSpace(flow.UUID); value != "" {
		return "hubble:" + value
	}

	parts := []string{
		"hubble",
		strings.TrimSpace(protocol),
		strings.TrimSpace(flow.IP.Source),
		strings.TrimSpace(flow.IP.Destination),
		strings.TrimSpace(flow.Verdict),
	}
	if _, srcPort, dstPort := protocolFromL4(flow.L4); srcPort != 0 || dstPort != 0 {
		parts = append(parts, fmt.Sprintf("%d", srcPort), fmt.Sprintf("%d", dstPort))
	}
	if observedAt.IsZero() {
		return strings.Join(parts, ":")
	}
	return strings.Join(append(parts, observedAt.UTC().Format(time.RFC3339Nano)), ":")
}

func workloadRef(endpoint *endpoint) string {
	if endpoint == nil {
		return ""
	}
	namespace := strings.TrimSpace(endpoint.Namespace)
	workload := primaryWorkloadName(endpoint)
	if namespace == "" || workload == "" {
		return ""
	}
	return "workload:" + namespace + "/" + workload
}

func primaryWorkloadName(endpoint *endpoint) string {
	if endpoint == nil || len(endpoint.Workloads) == 0 {
		return ""
	}
	return strings.TrimSpace(endpoint.Workloads[0].Name)
}

func podResourceID(namespace, pod string) string {
	namespace = strings.TrimSpace(namespace)
	pod = strings.TrimSpace(pod)
	if namespace == "" || pod == "" {
		return ""
	}
	return "pod:" + namespace + "/" + pod
}

func addEndpointMetadata(metadata map[string]any, prefix string, endpoint *endpoint) {
	if metadata == nil || endpoint == nil {
		return
	}
	if endpoint.Identity != 0 {
		metadata[prefix+"_identity"] = endpoint.Identity
	}
	if value := strings.TrimSpace(endpoint.ClusterName); value != "" {
		metadata[prefix+"_cluster_name"] = value
	}
	if value := strings.TrimSpace(endpoint.Namespace); value != "" {
		metadata[prefix+"_namespace"] = value
	}
	if value := strings.TrimSpace(endpoint.PodName); value != "" {
		metadata[prefix+"_pod_name"] = value
	}
	if value := primaryWorkloadName(endpoint); value != "" {
		metadata[prefix+"_workload_name"] = value
	}
	if len(endpoint.Labels) > 0 {
		metadata[prefix+"_labels"] = append([]string(nil), endpoint.Labels...)
	}
}

func addServiceMetadata(metadata map[string]any, prefix string, service *serviceEnvelope) {
	if metadata == nil || service == nil {
		return
	}
	if value := strings.TrimSpace(service.Name); value != "" {
		metadata[prefix+"_name"] = value
	}
	if value := strings.TrimSpace(service.Namespace); value != "" {
		metadata[prefix+"_namespace"] = value
	}
}

func namespace(primary, peer *endpoint) string {
	if primary != nil && strings.TrimSpace(primary.Namespace) != "" {
		return strings.TrimSpace(primary.Namespace)
	}
	if peer != nil {
		return strings.TrimSpace(peer.Namespace)
	}
	return ""
}

func clusterName(primary, peer *endpoint) string {
	if primary != nil && strings.TrimSpace(primary.ClusterName) != "" {
		return strings.TrimSpace(primary.ClusterName)
	}
	if peer != nil {
		return strings.TrimSpace(peer.ClusterName)
	}
	return ""
}

func hasPod(endpoint *endpoint) bool {
	return endpoint != nil && strings.TrimSpace(endpoint.PodName) != ""
}

func firstNonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
