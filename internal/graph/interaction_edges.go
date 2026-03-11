package graph

import (
	"strings"
	"time"
)

// InteractionEdge represents a single interaction signal between two people.
type InteractionEdge struct {
	SourcePersonID string
	TargetPersonID string
	Channel        string
	Type           string
	Timestamp      time.Time
	Duration       time.Duration
	Weight         float64
}

// UpsertInteractionEdge aggregates interaction events into a canonical undirected edge.
func UpsertInteractionEdge(g *Graph, interaction InteractionEdge) *Edge {
	if g == nil {
		return nil
	}

	source := normalizeInteractionPersonID(interaction.SourcePersonID)
	target := normalizeInteractionPersonID(interaction.TargetPersonID)
	if source == "" || target == "" || source == target {
		return nil
	}
	if source > target {
		source, target = target, source
	}

	channels := make(map[string]struct{})
	types := make(map[string]struct{})

	previousFrequency := 0
	previousWeightedFrequency := 0.0
	previousDurationSeconds := 0.0
	previousStrength := 0.0
	previousLastSeen := time.Time{}

	collect := func(edge *Edge) {
		if edge == nil || edge.Kind != EdgeKindInteractedWith {
			return
		}
		matchedPair := (edge.Source == source && edge.Target == target) ||
			(edge.Source == target && edge.Target == source)
		if !matchedPair {
			return
		}

		frequency := readInt(edge.Properties, "frequency", "interaction_count", "call_count", "co_actions")
		if frequency > previousFrequency {
			previousFrequency = frequency
		}

		weightedFrequency := readFloat(edge.Properties, "weighted_frequency", "weight")
		if weightedFrequency <= 0 {
			weightedFrequency = float64(frequency)
		}
		if weightedFrequency > previousWeightedFrequency {
			previousWeightedFrequency = weightedFrequency
		}

		durationSeconds := readFloat(edge.Properties, "total_duration_seconds", "duration_seconds")
		if durationSeconds > previousDurationSeconds {
			previousDurationSeconds = durationSeconds
		}

		strength := readFloat(edge.Properties, "strength", "relationship_strength")
		if strength > previousStrength {
			previousStrength = strength
		}

		lastSeen := firstTimeFromMap(edge.Properties, "last_seen", "last_interaction", "last_activity", "updated_at", "created_at")
		if lastSeen.After(previousLastSeen) {
			previousLastSeen = lastSeen
		}

		addStringSet(channels, edge.Properties["interaction_channels"])
		addStringSet(channels, edge.Properties["channels"])
		addStringSet(channels, edge.Properties["interaction_source_types"])
		addStringSet(types, edge.Properties["interaction_types"])
		addStringSet(types, edge.Properties["types"])
	}

	for _, edge := range g.GetOutEdges(source) {
		collect(edge)
	}
	for _, edge := range g.GetOutEdges(target) {
		collect(edge)
	}

	if channel := normalizeInteractionLabel(interaction.Channel); channel != "" {
		channels[channel] = struct{}{}
	}
	if interactionType := normalizeInteractionLabel(interaction.Type); interactionType != "" {
		types[interactionType] = struct{}{}
	}

	currentTime := interaction.Timestamp.UTC()
	if currentTime.IsZero() {
		currentTime = time.Now().UTC()
	}

	lastSeen := previousLastSeen
	if lastSeen.IsZero() || currentTime.After(lastSeen) {
		lastSeen = currentTime
	}

	durationSeconds := interaction.Duration.Seconds()
	if durationSeconds < 0 {
		durationSeconds = 0
	}

	frequency := previousFrequency + 1
	totalDurationSeconds := previousDurationSeconds + durationSeconds

	weightIncrement := interaction.Weight
	if weightIncrement <= 0 {
		weightIncrement = 1
	}
	weightedFrequency := previousWeightedFrequency + weightIncrement
	if weightedFrequency < float64(frequency) {
		weightedFrequency = float64(frequency)
	}
	strength := relationshipStrength(lastSeen, weightedFrequency)

	properties := map[string]any{
		"frequency":              frequency,
		"interaction_count":      frequency,
		"last_seen":              lastSeen,
		"last_interaction":       lastSeen,
		"total_duration_seconds": totalDurationSeconds,
		"duration_seconds":       totalDurationSeconds,
		"weighted_frequency":     weightedFrequency,
		"strength":               strength,
		"weight":                 strength,
		"interaction_channels":   sortedKeys(channels),
		"interaction_types":      sortedKeys(types),
	}
	if previousFrequency > 0 {
		properties["previous_frequency"] = previousFrequency
	}
	if previousStrength > 0 {
		properties["previous_strength"] = previousStrength
	}
	if !previousLastSeen.IsZero() {
		properties["previous_last_seen"] = previousLastSeen
	}

	// Remove stale versions to keep one active aggregated edge for this pair.
	g.RemoveEdge(source, target, EdgeKindInteractedWith)
	g.RemoveEdge(target, source, EdgeKindInteractedWith)

	edge := &Edge{
		ID:         interactionEdgeID(source, target),
		Source:     source,
		Target:     target,
		Kind:       EdgeKindInteractedWith,
		Effect:     EdgeEffectAllow,
		Risk:       RiskNone,
		Properties: properties,
	}
	g.AddEdge(edge)
	return edge
}

func normalizeInteractionPersonID(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return ""
	}
	if strings.HasPrefix(normalized, "person:") {
		return normalized
	}
	normalized = strings.TrimPrefix(normalized, "user:")
	if strings.Contains(normalized, ":") {
		return normalized
	}
	return "person:" + normalized
}

func interactionEdgeID(source string, target string) string {
	if source > target {
		source, target = target, source
	}
	return "person_interaction:" + source + "<->" + target
}

func normalizeInteractionLabel(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func addStringSet(set map[string]struct{}, value any) {
	for _, item := range stringSliceFromValue(value) {
		normalized := normalizeInteractionLabel(item)
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
}
