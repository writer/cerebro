package runtimegraph

import (
	"sort"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

type corroboratedObservation struct {
	node           *graph.Node
	properties     graph.ObservationProperties
	correlationKey string
}

func applyObservationCorroboration(g *graph.Graph, observationNodeID string) {
	if g == nil {
		return
	}
	observationNodeID = strings.TrimSpace(observationNodeID)
	if observationNodeID == "" {
		return
	}

	current, ok := g.GetNode(observationNodeID)
	if !ok || current == nil || current.DeletedAt != nil {
		return
	}
	properties, ok := current.ObservationProperties()
	if !ok {
		return
	}
	correlationKey := propertyString(current.Properties, "correlation_key")
	if correlationKey == "" {
		return
	}

	group := correlatedObservations(g, properties.SubjectID, properties.ObservationType, correlationKey)
	if len(group) == 0 {
		return
	}
	primary := selectPrimaryCorroboratedObservation(group)
	memberIDs := make(map[string]struct{}, len(group))
	sourceSet := make(map[string]struct{}, len(group))
	for _, item := range group {
		memberIDs[item.node.ID] = struct{}{}
		if sourceIdentity := trustedCorroborationSourceSystem(item.properties.SourceSystem); sourceIdentity != "" {
			sourceSet[sourceIdentity] = struct{}{}
		}
	}

	sources := sortedStringSet(sourceSet)
	sourceCount := len(sources)
	if sourceCount == 0 {
		sourceCount = 1
	}
	multiplier := corroborationConfidenceMultiplier(sourceCount)

	primaryProperties := cloneObservationPropertiesMap(primary.node.Properties)
	for _, item := range group {
		if item.node.ID == primary.node.ID {
			continue
		}
		mergeCorroboratedObservationProperties(primaryProperties, item.node.Properties)
	}
	primaryProperties["correlation_key"] = correlationKey
	primaryProperties["correlation_primary"] = true
	delete(primaryProperties, "corroboration_primary_id")
	primaryProperties["corroboration_count"] = len(group)
	primaryProperties["corroborating_source_count"] = sourceCount
	primaryProperties["corroboration_multiplier"] = multiplier
	primaryProperties["confidence"] = corroboratedObservationConfidence(multiplier)
	if len(sources) > 0 {
		primaryProperties["corroborating_sources"] = sources
	} else {
		delete(primaryProperties, "corroborating_sources")
	}
	upsertObservationNodeProperties(g, primary.node, primaryProperties)
	rewriteCorroborationEdges(g, primary.node.ID, "", memberIDs)

	for _, item := range group {
		if item.node.ID == primary.node.ID {
			continue
		}

		nodeProperties := cloneObservationPropertiesMap(item.node.Properties)
		nodeProperties["correlation_key"] = correlationKey
		nodeProperties["correlation_primary"] = false
		nodeProperties["corroboration_primary_id"] = primary.node.ID
		delete(nodeProperties, "corroboration_count")
		delete(nodeProperties, "corroborating_source_count")
		delete(nodeProperties, "corroboration_multiplier")
		delete(nodeProperties, "corroborating_sources")
		nodeProperties["confidence"] = runtimeObservationBaseConfidence
		upsertObservationNodeProperties(g, item.node, nodeProperties)
		rewriteCorroborationEdges(g, item.node.ID, primary.node.ID, memberIDs)
		graph.AddEdgeIfMissing(g, buildCorroboratesEdge(item, primary.node.ID))
	}
}

func correlatedObservations(g *graph.Graph, subjectID, observationType, correlationKey string) []corroboratedObservation {
	if g == nil {
		return nil
	}
	subjectID = strings.TrimSpace(subjectID)
	observationType = strings.TrimSpace(observationType)
	correlationKey = strings.TrimSpace(correlationKey)
	if subjectID == "" || observationType == "" || correlationKey == "" {
		return nil
	}

	candidates := g.GetNodesByKindIndexed(graph.NodeKindObservation)
	group := make([]corroboratedObservation, 0, len(candidates))
	for _, node := range candidates {
		if node == nil || node.DeletedAt != nil {
			continue
		}
		properties, ok := node.ObservationProperties()
		if !ok {
			continue
		}
		if strings.TrimSpace(properties.SubjectID) != subjectID || strings.TrimSpace(properties.ObservationType) != observationType {
			continue
		}
		if propertyString(node.Properties, "correlation_key") != correlationKey {
			continue
		}
		group = append(group, corroboratedObservation{
			node:           node,
			properties:     properties,
			correlationKey: correlationKey,
		})
	}
	return group
}

func selectPrimaryCorroboratedObservation(group []corroboratedObservation) corroboratedObservation {
	sorted := append([]corroboratedObservation(nil), group...)
	sort.Slice(sorted, func(i, j int) bool {
		left := corroboratedObservationTime(sorted[i])
		right := corroboratedObservationTime(sorted[j])
		switch {
		case left.IsZero() && right.IsZero():
			return strings.TrimSpace(sorted[i].node.ID) < strings.TrimSpace(sorted[j].node.ID)
		case left.IsZero():
			return false
		case right.IsZero():
			return true
		case !left.Equal(right):
			return left.Before(right)
		default:
			return strings.TrimSpace(sorted[i].node.ID) < strings.TrimSpace(sorted[j].node.ID)
		}
	})
	return sorted[0]
}

func corroboratedObservationTime(item corroboratedObservation) time.Time {
	if !item.properties.ObservedAt.IsZero() {
		return item.properties.ObservedAt.UTC()
	}
	if !item.properties.ValidFrom.IsZero() {
		return item.properties.ValidFrom.UTC()
	}
	if item.node != nil && !item.node.CreatedAt.IsZero() {
		return item.node.CreatedAt.UTC()
	}
	return time.Time{}
}

func buildCorroboratesEdge(item corroboratedObservation, primaryID string) *graph.Edge {
	if item.node == nil {
		return nil
	}
	primaryID = strings.TrimSpace(primaryID)
	if primaryID == "" || strings.TrimSpace(item.node.ID) == "" || strings.TrimSpace(item.node.ID) == primaryID {
		return nil
	}
	properties := map[string]any{
		"correlation_key": item.correlationKey,
	}
	addMetadataString(properties, "source_system", item.properties.SourceSystem)
	addMetadataString(properties, "source_event_id", item.properties.SourceEventID)
	if !item.properties.ObservedAt.IsZero() {
		properties["observed_at"] = item.properties.ObservedAt.UTC().Format(time.RFC3339)
	}
	if !item.properties.ValidFrom.IsZero() {
		properties["valid_from"] = item.properties.ValidFrom.UTC().Format(time.RFC3339)
	}
	return &graph.Edge{
		ID:         item.node.ID + "->" + primaryID + ":" + string(graph.EdgeKindCorroborates),
		Source:     item.node.ID,
		Target:     primaryID,
		Kind:       graph.EdgeKindCorroborates,
		Effect:     graph.EdgeEffectAllow,
		Properties: properties,
	}
}

func rewriteCorroborationEdges(g *graph.Graph, sourceID, desiredTarget string, memberIDs map[string]struct{}) {
	if g == nil {
		return
	}
	sourceID = strings.TrimSpace(sourceID)
	desiredTarget = strings.TrimSpace(desiredTarget)
	if sourceID == "" {
		return
	}
	for _, edge := range g.GetOutEdges(sourceID) {
		if edge == nil || edge.Kind != graph.EdgeKindCorroborates {
			continue
		}
		targetID := strings.TrimSpace(edge.Target)
		if _, ok := memberIDs[targetID]; !ok {
			continue
		}
		if desiredTarget == "" || targetID != desiredTarget {
			g.RemoveEdge(sourceID, targetID, graph.EdgeKindCorroborates)
		}
	}
}

func upsertObservationNodeProperties(g *graph.Graph, existing *graph.Node, properties map[string]any) {
	if g == nil || existing == nil {
		return
	}
	cloned := *existing
	cloned.Properties = properties
	cloned.UpdatedAt = time.Time{}
	g.AddNode(&cloned)
}

func corroborationConfidenceMultiplier(sourceCount int) float64 {
	switch {
	case sourceCount >= 3:
		return 2.0
	case sourceCount == 2:
		return 1.5
	default:
		return 1.0
	}
}

func trustedCorroborationSourceSystem(sourceSystem string) string {
	switch strings.ToLower(strings.TrimSpace(sourceSystem)) {
	case "tetragon", "falco", "hubble", "k8s_audit", "otel", "opentelemetry", "runtime_response":
		return strings.ToLower(strings.TrimSpace(sourceSystem))
	default:
		return ""
	}
}

func corroboratedObservationConfidence(multiplier float64) float64 {
	confidence := runtimeObservationBaseConfidence * multiplier
	if confidence > 1 {
		return 1
	}
	if confidence < 0 {
		return 0
	}
	return confidence
}

func cloneObservationPropertiesMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return make(map[string]any)
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = cloneObservationPropertyValue(value)
	}
	return cloned
}

func cloneObservationPropertyValue(value any) any {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		return append([]any(nil), typed...)
	case map[string]any:
		cloned := make(map[string]any, len(typed))
		for key, nested := range typed {
			cloned[key] = cloneObservationPropertyValue(nested)
		}
		return cloned
	default:
		return value
	}
}

func mergeCorroboratedObservationProperties(dst, src map[string]any) {
	if len(dst) == 0 || len(src) == 0 {
		return
	}
	for key, value := range src {
		key = strings.TrimSpace(key)
		if key == "" || shouldSkipCorroboratedPropertyMerge(key) {
			continue
		}
		if key == "tags" {
			merged := mergeObservationStringLists(dst[key], value)
			if len(merged) > 0 {
				dst[key] = merged
			}
			continue
		}
		if !hasObservationPropertyValue(dst[key]) && hasObservationPropertyValue(value) {
			dst[key] = cloneObservationPropertyValue(value)
		}
	}
}

func shouldSkipCorroboratedPropertyMerge(key string) bool {
	switch key {
	case "confidence",
		"correlation_primary",
		"corroboration_primary_id",
		"corroboration_count",
		"corroborating_source_count",
		"corroboration_multiplier",
		"corroborating_sources":
		return true
	default:
		return false
	}
}

func hasObservationPropertyValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case []string:
		return len(typed) > 0
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}

func mergeObservationStringLists(current, incoming any) []string {
	set := make(map[string]struct{})
	for _, value := range observationStringList(current) {
		set[value] = struct{}{}
	}
	for _, value := range observationStringList(incoming) {
		set[value] = struct{}{}
	}
	return sortedStringSet(set)
}

func observationStringList(value any) []string {
	switch typed := value.(type) {
	case []string:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				continue
			}
			text = strings.TrimSpace(text)
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}
