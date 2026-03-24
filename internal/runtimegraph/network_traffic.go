package runtimegraph

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/runtime"
)

const (
	trafficConfirmationConfirmed    = "confirmed"
	trafficConfirmationObservedOnly = "observed_only"
	trafficConfirmationTopologyOnly = "topology_only"
)

type trafficAggregate struct {
	sourceID  string
	targetID  string
	firstSeen time.Time
	lastSeen  time.Time
	bytes     int64
	packets   int64
	flowCount int64
	sourceIPs map[string]struct{}
}

func ensureObservationSubjectNode(g *graph.Graph, observation *runtime.RuntimeObservation, subjectID string) bool {
	if g == nil {
		return false
	}
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return false
	}
	if _, ok := g.GetNode(subjectID); ok {
		return true
	}
	node := syntheticObservationSubjectNode(observation, subjectID)
	if node == nil {
		return false
	}
	g.AddNode(node)
	return true
}

func syntheticObservationSubjectNode(observation *runtime.RuntimeObservation, subjectID string) *graph.Node {
	if observation == nil || observation.Kind != runtime.ObservationKindNetworkFlow {
		return nil
	}
	resourceType := strings.TrimSpace(observation.ResourceType)
	if resourceType != "network_interface" {
		return nil
	}
	if strings.TrimSpace(observation.ResourceID) != subjectID {
		return nil
	}

	properties := map[string]any{
		"network_kind":             resourceType,
		"runtime_observed_subject": true,
	}
	addMetadataString(properties, "resource_id", observation.ResourceID)
	addMetadataString(properties, "resource_type", resourceType)
	addMetadataString(properties, "private_ip", networkSrcIP(observation))

	node := &graph.Node{
		ID:         subjectID,
		Kind:       graph.NodeKindNetwork,
		Name:       syntheticNetworkSubjectName(subjectID),
		Provider:   runtimeObservationProvider(observation),
		Account:    metadataString(observation.Metadata, "account_id"),
		Properties: properties,
		Risk:       graph.RiskNone,
	}
	return node
}

func syntheticNetworkSubjectName(subjectID string) string {
	if _, name, ok := strings.Cut(strings.TrimSpace(subjectID), ":"); ok && strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	return strings.TrimSpace(subjectID)
}

func runtimeObservationProvider(observation *runtime.RuntimeObservation) string {
	if observation == nil {
		return ""
	}
	source := strings.ToLower(strings.TrimSpace(observation.Source))
	switch {
	case strings.HasPrefix(source, "aws"):
		return "aws"
	case strings.HasPrefix(source, "gcp"):
		return "gcp"
	case strings.HasPrefix(source, "azure"):
		return "azure"
	default:
		for _, tag := range observation.Tags {
			switch strings.ToLower(strings.TrimSpace(tag)) {
			case "aws", "gcp", "azure":
				return strings.ToLower(strings.TrimSpace(tag))
			}
		}
		return ""
	}
}

// MaterializeObservedTrafficIntoGraph projects network-flow observations into
// traffic-backed connects_to edges.
func MaterializeObservedTrafficIntoGraph(g *graph.Graph) {
	if g == nil {
		return
	}

	aggregates := make(map[string]*trafficAggregate)
	for _, node := range g.GetNodesByKind(graph.NodeKindObservation) {
		if node == nil {
			continue
		}
		props, ok := node.ObservationProperties()
		if !ok || props.ObservationType != string(runtime.ObservationKindNetworkFlow) {
			continue
		}
		sourceID := strings.TrimSpace(props.SubjectID)
		if sourceID == "" {
			continue
		}
		if _, ok := g.GetNode(sourceID); !ok {
			continue
		}
		dstIP := nodePropertyString(node, "network_dst_ip")
		if dstIP == "" {
			continue
		}
		targetID := resolveTrafficTargetNodeID(g, dstIP, nodePropertyString(node, "source_system"))
		if targetID == "" {
			synthetic := syntheticObservedTargetNode(dstIP, nodePropertyString(node, "source_system"))
			g.AddNode(synthetic)
			targetID = synthetic.ID
		}
		if targetID == "" || targetID == sourceID {
			continue
		}
		key := sourceID + "->" + targetID
		aggregate := aggregates[key]
		if aggregate == nil {
			aggregate = &trafficAggregate{
				sourceID:  sourceID,
				targetID:  targetID,
				firstSeen: props.ObservedAt,
				lastSeen:  props.ObservedAt,
				sourceIPs: make(map[string]struct{}),
			}
			aggregates[key] = aggregate
		}
		if aggregate.firstSeen.IsZero() || (!props.ObservedAt.IsZero() && props.ObservedAt.Before(aggregate.firstSeen)) {
			aggregate.firstSeen = props.ObservedAt
		}
		if props.ObservedAt.After(aggregate.lastSeen) {
			aggregate.lastSeen = props.ObservedAt
		}
		aggregate.bytes += nodePropertyInt64(node, "bytes")
		aggregate.packets += nodePropertyInt64(node, "packets")
		aggregate.flowCount++
		if srcIP := nodePropertyString(node, "network_src_ip"); srcIP != "" {
			aggregate.sourceIPs[srcIP] = struct{}{}
		}
	}

	for _, aggregate := range aggregates {
		edge := findActiveConnectsToEdge(g, aggregate.sourceID, aggregate.targetID)
		properties := observedTrafficEdgeProperties(aggregate, edge != nil)
		if edge != nil {
			graph.MergeEdgeProperties(g, edge.ID, properties)
			continue
		}
		graph.AddEdgeIfMissing(g, &graph.Edge{
			ID:         fmt.Sprintf("%s->%s:%s", aggregate.sourceID, aggregate.targetID, graph.EdgeKindConnectsTo),
			Source:     aggregate.sourceID,
			Target:     aggregate.targetID,
			Kind:       graph.EdgeKindConnectsTo,
			Effect:     graph.EdgeEffectAllow,
			Properties: properties,
		})
	}

	for _, node := range g.Nodes() {
		for _, edge := range g.GetOutEdges(node.ID) {
			if edge == nil || edge.Kind != graph.EdgeKindConnectsTo {
				continue
			}
			confirmation := strings.TrimSpace(propertyAnyString(edge.Properties, "traffic_confirmation"))
			if confirmation != "" {
				continue
			}
			graph.MergeEdgeProperties(g, edge.ID, map[string]any{
				"traffic_confirmation": trafficConfirmationTopologyOnly,
			})
		}
	}
}

func resolveTrafficTargetNodeID(g *graph.Graph, dstIP, sourceSystem string) string {
	if g == nil {
		return ""
	}
	sourceProvider := runtimeProviderFromSource(strings.TrimSpace(sourceSystem))
	for _, node := range g.Nodes() {
		if node == nil {
			continue
		}
		if sourceProvider != "" && strings.TrimSpace(node.Provider) != "" && !strings.EqualFold(node.Provider, sourceProvider) {
			continue
		}
		for _, candidate := range nodeIPAddresses(node) {
			if candidate == dstIP {
				return node.ID
			}
		}
	}
	for _, node := range g.Nodes() {
		if node == nil {
			continue
		}
		for _, candidate := range nodeIPAddresses(node) {
			if candidate == dstIP {
				return node.ID
			}
		}
	}
	return ""
}

func syntheticObservedTargetNode(dstIP, sourceSystem string) *graph.Node {
	properties := map[string]any{
		"network_kind": "observed_endpoint",
		"ip_address":   dstIP,
	}
	if isPublicIP(dstIP) {
		properties["public_ip"] = dstIP
	} else {
		properties["private_ip"] = dstIP
	}
	return &graph.Node{
		ID:         "network:observed_ip:" + dstIP,
		Kind:       graph.NodeKindNetwork,
		Name:       dstIP,
		Provider:   runtimeProviderFromSource(strings.TrimSpace(sourceSystem)),
		Properties: properties,
		Risk:       graph.RiskNone,
	}
}

func observedTrafficEdgeProperties(aggregate *trafficAggregate, topologyEdge bool) map[string]any {
	if aggregate == nil {
		return nil
	}
	properties := map[string]any{
		"traffic_confirmation": trafficConfirmationObservedOnly,
		"traffic_volume_bytes": aggregate.bytes,
		"packet_count":         aggregate.packets,
		"distinct_source_ips":  len(aggregate.sourceIPs),
		"flow_count":           aggregate.flowCount,
		"observed_traffic":     true,
	}
	if topologyEdge {
		properties["traffic_confirmation"] = trafficConfirmationConfirmed
	} else {
		properties["relationship_type"] = "OBSERVED_TRAFFIC"
	}
	if !aggregate.firstSeen.IsZero() {
		properties["first_seen_traffic"] = aggregate.firstSeen.UTC().Format(time.RFC3339)
	}
	if !aggregate.lastSeen.IsZero() {
		properties["last_seen_traffic"] = aggregate.lastSeen.UTC().Format(time.RFC3339)
	}
	return properties
}

func findActiveConnectsToEdge(g *graph.Graph, sourceID, targetID string) *graph.Edge {
	if g == nil {
		return nil
	}
	for _, edge := range g.GetOutEdges(strings.TrimSpace(sourceID)) {
		if edge == nil || edge.Kind != graph.EdgeKindConnectsTo || edge.Target != strings.TrimSpace(targetID) {
			continue
		}
		return edge
	}
	return nil
}

func nodeIPAddresses(node *graph.Node) []string {
	if node == nil {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, 4)
	for _, key := range []string{"private_ip", "public_ip", "public_ip_address", "ip_address"} {
		if ip := propertyAnyString(node.Properties, key); ip != "" {
			addIPCandidate(out, seen, &out, ip)
		}
	}
	switch typed := node.Properties["ip_addresses"].(type) {
	case []string:
		for _, ip := range typed {
			addIPCandidate(out, seen, &out, ip)
		}
	case []any:
		for _, value := range typed {
			addIPCandidate(out, seen, &out, fmt.Sprintf("%v", value))
		}
	case string:
		for _, candidate := range splitIPCandidates(typed) {
			addIPCandidate(out, seen, &out, candidate)
		}
	}
	sort.Strings(out)
	return out
}

func addIPCandidate(_ []string, seen map[string]struct{}, out *[]string, raw string) {
	raw = strings.TrimSpace(strings.Trim(raw, "[]\""))
	if raw == "" {
		return
	}
	if ip := net.ParseIP(raw); ip == nil {
		return
	}
	if _, ok := seen[raw]; ok {
		return
	}
	seen[raw] = struct{}{}
	*out = append(*out, raw)
}

func splitIPCandidates(raw string) []string {
	cleaned := strings.NewReplacer("[", "", "]", "", "\"", "", ",", " ").Replace(raw)
	return strings.Fields(cleaned)
}

func nodePropertyString(node *graph.Node, key string) string {
	if node == nil {
		return ""
	}
	value, ok := node.PropertyValue(key)
	if !ok {
		return ""
	}
	return propertyAnyString(map[string]any{key: value}, key)
}

func propertyAnyString(properties map[string]any, key string) string {
	if len(properties) == 0 {
		return ""
	}
	value := properties[key]
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		if typed == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

func nodePropertyInt64(node *graph.Node, key string) int64 {
	if node == nil {
		return 0
	}
	value, ok := node.PropertyValue(key)
	if !ok {
		return 0
	}
	if typed, ok := value.(string); ok {
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err == nil {
			return parsed
		}
	}
	return propertyInt64(map[string]any{key: value}, key)
}

func isPublicIP(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	return !ip.IsPrivate()
}

func runtimeProviderFromSource(raw string) string {
	source := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.HasPrefix(source, "aws"):
		return "aws"
	case strings.HasPrefix(source, "gcp"):
		return "gcp"
	case strings.HasPrefix(source, "azure"):
		return "azure"
	default:
		return source
	}
}
