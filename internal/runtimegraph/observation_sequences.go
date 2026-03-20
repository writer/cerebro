package runtimegraph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

const (
	attackSequenceNodePrefix        = "attack_sequence:"
	attackSequenceSourceSystem      = "observation_correlation"
	defaultObservationWindow        = 60 * time.Second
	defaultObservationInactivityGap = 30 * time.Second
	defaultSequenceMinObservations  = 2
)

// ObservationSequencePolicy controls how runtime observation windows collapse
// into derived attack-sequence nodes.
type ObservationSequencePolicy struct {
	WindowDuration  time.Duration `json:"window_duration,omitempty"`
	InactivityGap   time.Duration `json:"inactivity_gap,omitempty"`
	MinObservations int           `json:"min_observations,omitempty"`
}

// ObservationSequenceMaterializationSummary captures one rebuild pass.
type ObservationSequenceMaterializationSummary struct {
	SequencesRemoved       int `json:"sequences_removed"`
	SequencesCreated       int `json:"sequences_created"`
	SequenceEdgesCreated   int `json:"sequence_edges_created"`
	ObservationsCorrelated int `json:"observations_correlated"`
}

type observationSequenceCandidate struct {
	Node            *graph.Node
	ObservedAt      time.Time
	ObservationType string
	WorkloadID      string
	MITRE           []string
}

type observationSequence struct {
	WorkloadID   string
	WindowStart  time.Time
	WindowEnd    time.Time
	Observations []observationSequenceCandidate
}

// DefaultObservationSequencePolicy returns deterministic sequence windows for
// workload-scoped runtime observations.
func DefaultObservationSequencePolicy() ObservationSequencePolicy {
	return ObservationSequencePolicy{
		WindowDuration:  defaultObservationWindow,
		InactivityGap:   defaultObservationInactivityGap,
		MinObservations: defaultSequenceMinObservations,
	}
}

// MaterializeObservationSequences rebuilds workload-scoped attack_sequence
// nodes from active runtime observation nodes.
func MaterializeObservationSequences(g *graph.Graph, now time.Time, policy ObservationSequencePolicy) ObservationSequenceMaterializationSummary {
	summary := ObservationSequenceMaterializationSummary{}
	if g == nil {
		return summary
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	policy = normalizeObservationSequencePolicy(policy)

	summary.SequencesRemoved = purgeObservationSequenceNodes(g)
	candidates := collectObservationSequenceCandidates(g)
	sequences := buildObservationSequences(candidates, policy)

	for _, sequence := range sequences {
		if len(sequence.Observations) < policy.MinObservations {
			continue
		}
		nodeID := attackSequenceNodeID(sequence)
		g.AddNode(buildObservationSequenceNode(nodeID, sequence, now))
		summary.SequencesCreated++
		summary.ObservationsCorrelated += len(sequence.Observations)

		if graph.AddEdgeIfMissing(g, buildWorkloadSequenceEdge(sequence.WorkloadID, nodeID, sequence, now)) {
			summary.SequenceEdgesCreated++
		}
		for idx, observation := range sequence.Observations {
			if graph.AddEdgeIfMissing(g, buildSequenceContainsEdge(nodeID, observation.Node.ID, idx, observation.ObservedAt, now)) {
				summary.SequenceEdgesCreated++
			}
		}
		for _, targetID := range sequenceBasedOnTargets(g, sequence) {
			if graph.AddEdgeIfMissing(g, buildSequenceBasedOnEdge(nodeID, targetID, sequence, now)) {
				summary.SequenceEdgesCreated++
			}
		}
	}

	return summary
}

func normalizeObservationSequencePolicy(policy ObservationSequencePolicy) ObservationSequencePolicy {
	if policy.WindowDuration <= 0 {
		policy.WindowDuration = defaultObservationWindow
	}
	if policy.InactivityGap <= 0 {
		policy.InactivityGap = defaultObservationInactivityGap
	}
	if policy.MinObservations <= 1 {
		policy.MinObservations = defaultSequenceMinObservations
	}
	return policy
}

func purgeObservationSequenceNodes(g *graph.Graph) int {
	if g == nil {
		return 0
	}
	removed := 0
	for _, node := range g.GetNodesByKind(graph.NodeKindAttackSequence) {
		if node == nil {
			continue
		}
		if g.RemoveNode(node.ID) {
			removed++
		}
	}
	if removed > 0 {
		g.CompactDeletedNodes()
	}
	return removed
}

func collectObservationSequenceCandidates(g *graph.Graph) map[string][]observationSequenceCandidate {
	out := make(map[string][]observationSequenceCandidate)
	if g == nil {
		return out
	}
	for _, node := range g.GetNodesByKind(graph.NodeKindObservation) {
		if node == nil {
			continue
		}
		props, ok := node.ObservationProperties()
		if !ok || props.ObservedAt.IsZero() {
			continue
		}
		workloadID := observationSequenceWorkloadID(node, props)
		if workloadID == "" {
			continue
		}
		candidate := observationSequenceCandidate{
			Node:            node,
			ObservedAt:      props.ObservedAt.UTC(),
			ObservationType: strings.TrimSpace(props.ObservationType),
			WorkloadID:      workloadID,
			MITRE:           observationSequenceMITRE(g, node),
		}
		out[workloadID] = append(out[workloadID], candidate)
	}
	for workloadID := range out {
		sort.Slice(out[workloadID], func(i, j int) bool {
			if !out[workloadID][i].ObservedAt.Equal(out[workloadID][j].ObservedAt) {
				return out[workloadID][i].ObservedAt.Before(out[workloadID][j].ObservedAt)
			}
			return out[workloadID][i].Node.ID < out[workloadID][j].Node.ID
		})
	}
	return out
}

func observationSequenceWorkloadID(node *graph.Node, props graph.ObservationProperties) string {
	if node == nil {
		return ""
	}
	if workloadRef := propertyString(node.Properties, "workload_ref"); isWorkloadSequenceSubjectID(workloadRef) {
		return workloadRef
	}
	if isWorkloadSequenceSubjectID(props.SubjectID) {
		return strings.TrimSpace(props.SubjectID)
	}
	return ""
}

func isWorkloadSequenceSubjectID(subjectID string) bool {
	subjectID = strings.TrimSpace(subjectID)
	return strings.HasPrefix(subjectID, "deployment:") ||
		strings.HasPrefix(subjectID, "workload:") ||
		strings.HasPrefix(subjectID, "pod:")
}

func observationSequenceMITRE(g *graph.Graph, node *graph.Node) []string {
	if g == nil || node == nil {
		return nil
	}
	set := make(map[string]struct{})
	for _, edge := range g.GetOutEdges(node.ID) {
		if edge == nil || edge.Kind != graph.EdgeKindBasedOn {
			continue
		}
		target, ok := g.GetNode(edge.Target)
		if !ok || target == nil {
			continue
		}
		for _, technique := range propertyStrings(target.Properties, "mitre_attack") {
			if technique == "" {
				continue
			}
			set[technique] = struct{}{}
		}
	}
	return sortedStringSet(set)
}

func buildObservationSequences(candidatesByWorkload map[string][]observationSequenceCandidate, policy ObservationSequencePolicy) []observationSequence {
	sequences := make([]observationSequence, 0)
	workloads := make([]string, 0, len(candidatesByWorkload))
	for workloadID := range candidatesByWorkload {
		workloads = append(workloads, workloadID)
	}
	sort.Strings(workloads)

	for _, workloadID := range workloads {
		candidates := candidatesByWorkload[workloadID]
		if len(candidates) == 0 {
			continue
		}
		current := observationSequence{
			WorkloadID:   workloadID,
			WindowStart:  candidates[0].ObservedAt,
			WindowEnd:    candidates[0].ObservedAt,
			Observations: []observationSequenceCandidate{candidates[0]},
		}
		for _, candidate := range candidates[1:] {
			gapFromPrevious := candidate.ObservedAt.Sub(current.WindowEnd)
			gapFromWindowStart := candidate.ObservedAt.Sub(current.WindowStart)
			if gapFromPrevious > policy.InactivityGap || gapFromWindowStart > policy.WindowDuration {
				if len(current.Observations) >= policy.MinObservations {
					sequences = append(sequences, current)
				}
				current = observationSequence{
					WorkloadID:   workloadID,
					WindowStart:  candidate.ObservedAt,
					WindowEnd:    candidate.ObservedAt,
					Observations: []observationSequenceCandidate{candidate},
				}
				continue
			}
			current.Observations = append(current.Observations, candidate)
			current.WindowEnd = candidate.ObservedAt
		}
		if len(current.Observations) >= policy.MinObservations {
			sequences = append(sequences, current)
		}
	}
	return sequences
}

func attackSequenceNodeID(sequence observationSequence) string {
	sum := sha256.Sum256([]byte(sequence.WorkloadID + "|" + sequence.WindowStart.UTC().Format(time.RFC3339Nano) + "|" + sequence.WindowEnd.UTC().Format(time.RFC3339Nano) + "|" + strings.Join(sequenceObservationIDs(sequence), "|")))
	return attackSequenceNodePrefix + hex.EncodeToString(sum[:12])
}

func buildObservationSequenceNode(nodeID string, sequence observationSequence, now time.Time) *graph.Node {
	types := sequenceObservationTypes(sequence)
	techniques := sequenceMITRE(sequence)
	severity := observationSequenceSeverity(sequence, techniques)
	detail := fmt.Sprintf("correlated %d runtime observations on %s over %s", len(sequence.Observations), sequence.WorkloadID, sequence.WindowEnd.Sub(sequence.WindowStart).Round(time.Second))

	properties := map[string]any{
		"sequence_type":           "runtime_observation_window",
		"workload_ref":            sequence.WorkloadID,
		"detail":                  detail,
		"severity":                severity,
		"observation_count":       len(sequence.Observations),
		"sequence_start":          sequence.WindowStart.UTC().Format(time.RFC3339),
		"sequence_end":            sequence.WindowEnd.UTC().Format(time.RFC3339),
		"window_seconds":          int64(sequence.WindowEnd.Sub(sequence.WindowStart).Seconds()),
		"observation_types":       types,
		"ordered_observation_ids": sequenceObservationIDs(sequence),
		"source_system":           attackSequenceSourceSystem,
		"source_event_id":         nodeID,
		"observed_at":             sequence.WindowEnd.UTC().Format(time.RFC3339),
		"valid_from":              sequence.WindowStart.UTC().Format(time.RFC3339),
		"valid_to":                sequence.WindowEnd.UTC().Format(time.RFC3339),
		"recorded_at":             now.UTC().Format(time.RFC3339),
		"transaction_from":        now.UTC().Format(time.RFC3339),
		"confidence":              1.0,
	}
	if len(techniques) > 0 {
		properties["mitre_attack"] = techniques
	}

	return &graph.Node{
		ID:         nodeID,
		Kind:       graph.NodeKindAttackSequence,
		Name:       "Attack sequence " + sequence.WorkloadID,
		Properties: properties,
		CreatedAt:  now.UTC(),
		UpdatedAt:  now.UTC(),
	}
}

func buildWorkloadSequenceEdge(workloadID, sequenceNodeID string, sequence observationSequence, now time.Time) *graph.Edge {
	return &graph.Edge{
		ID:     workloadID + "->" + sequenceNodeID + ":" + string(graph.EdgeKindHasSequence),
		Source: workloadID,
		Target: sequenceNodeID,
		Kind:   graph.EdgeKindHasSequence,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"source_system":     attackSequenceSourceSystem,
			"source_event_id":   sequenceNodeID,
			"observed_at":       sequence.WindowEnd.UTC().Format(time.RFC3339),
			"valid_from":        sequence.WindowStart.UTC().Format(time.RFC3339),
			"window_seconds":    int64(sequence.WindowEnd.Sub(sequence.WindowStart).Seconds()),
			"observation_count": len(sequence.Observations),
		},
		CreatedAt: now.UTC(),
	}
}

func buildSequenceContainsEdge(sequenceNodeID, observationNodeID string, index int, observedAt, now time.Time) *graph.Edge {
	return &graph.Edge{
		ID:     fmt.Sprintf("%s->%s:%s:%d", sequenceNodeID, observationNodeID, graph.EdgeKindContains, index),
		Source: sequenceNodeID,
		Target: observationNodeID,
		Kind:   graph.EdgeKindContains,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"source_system":   attackSequenceSourceSystem,
			"source_event_id": sequenceNodeID,
			"observed_at":     observedAt.UTC().Format(time.RFC3339),
			"valid_from":      observedAt.UTC().Format(time.RFC3339),
			"sequence_index":  index,
		},
		CreatedAt: now.UTC(),
	}
}

func sequenceBasedOnTargets(g *graph.Graph, sequence observationSequence) []string {
	if g == nil {
		return nil
	}
	set := make(map[string]struct{})
	for _, observation := range sequence.Observations {
		for _, edge := range g.GetOutEdges(observation.Node.ID) {
			if edge == nil || edge.Kind != graph.EdgeKindBasedOn || edge.DeletedAt != nil {
				continue
			}
			targetID := strings.TrimSpace(edge.Target)
			if targetID == "" {
				continue
			}
			set[targetID] = struct{}{}
		}
	}
	return sortedStringSet(set)
}

func buildSequenceBasedOnEdge(sequenceNodeID, targetID string, sequence observationSequence, now time.Time) *graph.Edge {
	sequenceNodeID = strings.TrimSpace(sequenceNodeID)
	targetID = strings.TrimSpace(targetID)
	if sequenceNodeID == "" || targetID == "" {
		return nil
	}

	properties := map[string]any{
		"source_system":     attackSequenceSourceSystem,
		"source_event_id":   sequenceNodeID,
		"observed_at":       sequence.WindowEnd.UTC().Format(time.RFC3339),
		"valid_from":        sequence.WindowStart.UTC().Format(time.RFC3339),
		"window_seconds":    int64(sequence.WindowEnd.Sub(sequence.WindowStart).Seconds()),
		"observation_count": len(sequence.Observations),
	}

	return &graph.Edge{
		ID:         sequenceNodeID + "->" + targetID + ":" + string(graph.EdgeKindBasedOn),
		Source:     sequenceNodeID,
		Target:     targetID,
		Kind:       graph.EdgeKindBasedOn,
		Effect:     graph.EdgeEffectAllow,
		Properties: properties,
		CreatedAt:  now.UTC(),
	}
}

func sequenceObservationIDs(sequence observationSequence) []string {
	ids := make([]string, 0, len(sequence.Observations))
	for _, observation := range sequence.Observations {
		ids = append(ids, observation.Node.ID)
	}
	return ids
}

func sequenceObservationTypes(sequence observationSequence) []string {
	set := make(map[string]struct{})
	for _, observation := range sequence.Observations {
		if observation.ObservationType == "" {
			continue
		}
		set[observation.ObservationType] = struct{}{}
	}
	return sortedStringSet(set)
}

func sequenceMITRE(sequence observationSequence) []string {
	set := make(map[string]struct{})
	for _, observation := range sequence.Observations {
		for _, technique := range observation.MITRE {
			if technique == "" {
				continue
			}
			set[technique] = struct{}{}
		}
	}
	return sortedStringSet(set)
}

func observationSequenceSeverity(sequence observationSequence, techniques []string) string {
	classes := make(map[string]struct{})
	for _, observation := range sequence.Observations {
		switch strings.TrimSpace(observation.ObservationType) {
		case "process_exec", "process_exit":
			classes["process"] = struct{}{}
		case "file_open", "file_write":
			classes["file"] = struct{}{}
		case "network_flow", "dns_query":
			classes["network"] = struct{}{}
		case "kubernetes_audit":
			classes["control_plane"] = struct{}{}
		}
	}
	switch {
	case len(techniques) >= 2:
		return "critical"
	case len(classes) >= 3:
		return "critical"
	case len(classes) == 2:
		return "high"
	default:
		return "medium"
	}
}

func propertyStrings(properties map[string]any, key string) []string {
	if len(properties) == 0 {
		return nil
	}
	raw, ok := properties[key]
	if !ok || raw == nil {
		return nil
	}
	switch typed := raw.(type) {
	case []string:
		out := make([]string, 0, len(typed))
		for _, value := range typed {
			value = strings.TrimSpace(value)
			if value != "" {
				out = append(out, value)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			value, ok := item.(string)
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			if value != "" {
				out = append(out, value)
			}
		}
		return out
	default:
		return nil
	}
}

func sortedStringSet(set map[string]struct{}) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}
