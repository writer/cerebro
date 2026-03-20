package runtimegraph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/runtime"
)

const observationSummaryNodePrefix = "observation_summary:"
const observationSummaryDateLayout = "2006-01-02"

// ObservationCompactionPolicy controls how stale runtime observations roll up
// into summary observation nodes.
type ObservationCompactionPolicy struct {
	DefaultActiveWindow time.Duration                                    `json:"default_active_window,omitempty"`
	ActiveWindowByKind  map[runtime.RuntimeObservationKind]time.Duration `json:"active_window_by_kind,omitempty"`
	SummaryTopN         int                                              `json:"summary_top_n,omitempty"`
}

// ObservationCompactionResult summarizes one compaction pass.
type ObservationCompactionResult struct {
	ObservationsConsidered          int `json:"observations_considered"`
	ObservationsCompacted           int `json:"observations_compacted"`
	ObservationsPreservedActive     int `json:"observations_preserved_active"`
	ObservationsPreservedLinked     int `json:"observations_preserved_linked"`
	ObservationsPreservedSequenced  int `json:"observations_preserved_sequenced"`
	ObservationsPreservedCorrelated int `json:"observations_preserved_correlated"`
	SummaryNodesCreated             int `json:"summary_nodes_created"`
	SummaryNodesUpdated             int `json:"summary_nodes_updated"`
	SummaryTargetEdgesCreated       int `json:"summary_target_edges_created"`
}

type observationCompactionProtectionReason int

const (
	observationCompactionProtectionNone observationCompactionProtectionReason = iota
	observationCompactionProtectionLinked
	observationCompactionProtectionSequenced
	observationCompactionProtectionCorrelated
)

type observationCompactionGroupKey struct {
	SubjectID       string
	ObservationType string
	Day             string
}

type observationCompactionAccumulator struct {
	Key                 observationCompactionGroupKey
	Count               int
	FirstObservedAt     time.Time
	LastObservedAt      time.Time
	NodeIDs             []string
	ProcessNameCounts   map[string]int
	ProcessPathCounts   map[string]int
	FilePathCounts      map[string]int
	NetworkDomainCounts map[string]int
	AuditResourceCounts map[string]int
	ServiceNameCounts   map[string]int
}

// DefaultObservationCompactionPolicy returns the current runtime compaction
// defaults. High-churn observations get a short active window; response and
// alert artifacts stay hot longer.
func DefaultObservationCompactionPolicy() ObservationCompactionPolicy {
	return ObservationCompactionPolicy{
		DefaultActiveWindow: 4 * time.Hour,
		ActiveWindowByKind: map[runtime.RuntimeObservationKind]time.Duration{
			runtime.ObservationKindRuntimeAlert:    24 * time.Hour,
			runtime.ObservationKindResponseOutcome: 24 * time.Hour,
			runtime.ObservationKindKubernetesAudit: 24 * time.Hour,
		},
		SummaryTopN: 5,
	}
}

// CompactHistoricalObservations rolls stale runtime observation nodes into
// deterministic daily summary observation nodes per subject and observation
// kind. Any observation participating in a finding/evidence chain, an active
// attack sequence, or a corroboration group is preserved.
func CompactHistoricalObservations(g *graph.Graph, now time.Time, policy ObservationCompactionPolicy) ObservationCompactionResult {
	result := ObservationCompactionResult{}
	if g == nil {
		return result
	}

	policy = normalizeObservationCompactionPolicy(policy)
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	groups := make(map[observationCompactionGroupKey]*observationCompactionAccumulator)
	for _, node := range g.GetNodesByKind(graph.NodeKindObservation) {
		if node == nil || isObservationSummaryNode(node) {
			continue
		}
		result.ObservationsConsidered++

		props, ok := node.ObservationProperties()
		if !ok {
			continue
		}
		if props.ObservedAt.IsZero() {
			if ts, ok := propertyTime(node.Properties, "valid_from"); ok {
				props.ObservedAt = ts
			}
		}
		if props.ObservedAt.IsZero() || strings.TrimSpace(props.SubjectID) == "" || strings.TrimSpace(props.ObservationType) == "" {
			continue
		}
		if now.Sub(props.ObservedAt.UTC()) <= policy.activeWindow(props.ObservationType) {
			result.ObservationsPreservedActive++
			continue
		}
		switch observationCompactionProtectionReasonForNode(g, node) {
		case observationCompactionProtectionLinked:
			result.ObservationsPreservedLinked++
			continue
		case observationCompactionProtectionSequenced:
			result.ObservationsPreservedSequenced++
			continue
		case observationCompactionProtectionCorrelated:
			result.ObservationsPreservedCorrelated++
			continue
		}

		key := observationCompactionGroupKey{
			SubjectID:       strings.TrimSpace(props.SubjectID),
			ObservationType: strings.TrimSpace(props.ObservationType),
			Day:             props.ObservedAt.UTC().Format(observationSummaryDateLayout),
		}
		acc := groups[key]
		if acc == nil {
			acc = &observationCompactionAccumulator{
				Key:                 key,
				ProcessNameCounts:   make(map[string]int),
				ProcessPathCounts:   make(map[string]int),
				FilePathCounts:      make(map[string]int),
				NetworkDomainCounts: make(map[string]int),
				AuditResourceCounts: make(map[string]int),
				ServiceNameCounts:   make(map[string]int),
			}
			groups[key] = acc
		}
		acc.addObservation(node, props.ObservedAt.UTC())
	}

	for _, acc := range groups {
		if acc == nil || acc.Count == 0 {
			continue
		}

		summaryID := observationSummaryNodeID(acc.Key.SubjectID, acc.Key.ObservationType, acc.Key.Day)
		if existing, ok := g.GetNode(summaryID); ok && existing != nil {
			acc.mergeExistingSummary(existing)
			result.SummaryNodesUpdated++
		} else {
			result.SummaryNodesCreated++
		}

		g.AddNode(buildObservationSummaryNode(summaryID, acc, policy))
		if graph.AddEdgeIfMissing(g, buildObservationSummaryTargetEdge(summaryID, acc.Key.SubjectID, acc)) {
			result.SummaryTargetEdgesCreated++
		}

		for _, nodeID := range acc.NodeIDs {
			if g.RemoveNode(nodeID) {
				result.ObservationsCompacted++
			}
		}
	}

	return result
}

func normalizeObservationCompactionPolicy(policy ObservationCompactionPolicy) ObservationCompactionPolicy {
	defaults := DefaultObservationCompactionPolicy()
	if policy.DefaultActiveWindow <= 0 {
		policy.DefaultActiveWindow = defaults.DefaultActiveWindow
	}
	if policy.SummaryTopN <= 0 {
		policy.SummaryTopN = defaults.SummaryTopN
	}
	if len(policy.ActiveWindowByKind) == 0 {
		policy.ActiveWindowByKind = defaults.ActiveWindowByKind
		return policy
	}
	normalized := make(map[runtime.RuntimeObservationKind]time.Duration, len(defaults.ActiveWindowByKind)+len(policy.ActiveWindowByKind))
	for kind, window := range defaults.ActiveWindowByKind {
		normalized[kind] = window
	}
	for kind, window := range policy.ActiveWindowByKind {
		if window > 0 {
			normalized[kind] = window
		}
	}
	policy.ActiveWindowByKind = normalized
	return policy
}

func (p ObservationCompactionPolicy) activeWindow(observationType string) time.Duration {
	if window, ok := p.ActiveWindowByKind[runtime.RuntimeObservationKind(strings.TrimSpace(observationType))]; ok && window > 0 {
		return window
	}
	if p.DefaultActiveWindow > 0 {
		return p.DefaultActiveWindow
	}
	return 4 * time.Hour
}

func isObservationSummaryNode(node *graph.Node) bool {
	return node != nil && strings.HasPrefix(strings.TrimSpace(node.ID), observationSummaryNodePrefix)
}

func observationCompactionProtectionReasonForNode(g *graph.Graph, node *graph.Node) observationCompactionProtectionReason {
	if g == nil || node == nil {
		return observationCompactionProtectionNone
	}
	for _, edge := range g.GetOutEdges(node.ID) {
		if edge == nil {
			continue
		}
		switch edge.Kind {
		case graph.EdgeKindBasedOn:
			return observationCompactionProtectionLinked
		case graph.EdgeKindCorroborates:
			return observationCompactionProtectionCorrelated
		}
	}
	for _, edge := range g.GetInEdges(node.ID) {
		if edge == nil {
			continue
		}
		switch edge.Kind {
		case graph.EdgeKindBasedOn:
			return observationCompactionProtectionLinked
		case graph.EdgeKindCorroborates:
			return observationCompactionProtectionCorrelated
		case graph.EdgeKindContains:
			if sequenceNode, ok := g.GetNode(edge.Source); ok && sequenceNode != nil && sequenceNode.Kind == graph.NodeKindAttackSequence {
				return observationCompactionProtectionSequenced
			}
		}
	}
	return observationCompactionProtectionNone
}

func observationSummaryNodeID(subjectID, observationType, day string) string {
	payload := strings.Join([]string{
		strings.TrimSpace(subjectID),
		strings.TrimSpace(observationType),
		strings.TrimSpace(day),
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return observationSummaryNodePrefix + hex.EncodeToString(sum[:12])
}

func buildObservationSummaryNode(summaryID string, acc *observationCompactionAccumulator, policy ObservationCompactionPolicy) *graph.Node {
	metadata := graph.NormalizeWriteMetadata(
		acc.LastObservedAt,
		acc.FirstObservedAt,
		nil,
		"runtime_compactor",
		"observation_compaction:"+summaryID,
		0.95,
		graph.WriteMetadataDefaults{
			SourceSystem:      "runtime_compactor",
			SourceEventPrefix: "observation_compaction",
			DefaultConfidence: 0.95,
			RecordedAt:        acc.LastObservedAt,
			TransactionFrom:   acc.LastObservedAt,
		},
	)

	properties := map[string]any{
		"observation_type":              acc.Key.ObservationType,
		"subject_id":                    acc.Key.SubjectID,
		"detail":                        fmt.Sprintf("compacted %d %s observations", acc.Count, acc.Key.ObservationType),
		"summary_scope":                 "daily_compaction",
		"summary_date":                  acc.Key.Day,
		"compacted_observation_count":   acc.Count,
		"summary_first_observed_at":     acc.FirstObservedAt.UTC().Format(time.RFC3339),
		"summary_last_observed_at":      acc.LastObservedAt.UTC().Format(time.RFC3339),
		"summary_process_name_counts":   encodeCounterProperty(acc.ProcessNameCounts),
		"summary_process_path_counts":   encodeCounterProperty(acc.ProcessPathCounts),
		"summary_file_path_counts":      encodeCounterProperty(acc.FilePathCounts),
		"summary_network_domain_counts": encodeCounterProperty(acc.NetworkDomainCounts),
		"summary_audit_resource_counts": encodeCounterProperty(acc.AuditResourceCounts),
		"summary_service_name_counts":   encodeCounterProperty(acc.ServiceNameCounts),
		"top_process_names":             counterKeysTopN(acc.ProcessNameCounts, policy.SummaryTopN),
		"top_process_paths":             counterKeysTopN(acc.ProcessPathCounts, policy.SummaryTopN),
		"top_file_paths":                counterKeysTopN(acc.FilePathCounts, policy.SummaryTopN),
		"top_network_domains":           counterKeysTopN(acc.NetworkDomainCounts, policy.SummaryTopN),
		"top_audit_resources":           counterKeysTopN(acc.AuditResourceCounts, policy.SummaryTopN),
		"top_service_names":             counterKeysTopN(acc.ServiceNameCounts, policy.SummaryTopN),
	}
	metadata.ApplyTo(properties)

	return &graph.Node{
		ID:         summaryID,
		Kind:       graph.NodeKindObservation,
		Name:       fmt.Sprintf("%s summary", acc.Key.ObservationType),
		Provider:   metadata.SourceSystem,
		Properties: properties,
		Risk:       graph.RiskNone,
	}
}

func buildObservationSummaryTargetEdge(summaryID, subjectID string, acc *observationCompactionAccumulator) *graph.Edge {
	metadata := graph.NormalizeWriteMetadata(
		acc.LastObservedAt,
		acc.FirstObservedAt,
		nil,
		"runtime_compactor",
		"observation_compaction:"+summaryID,
		0.95,
		graph.WriteMetadataDefaults{
			SourceSystem:      "runtime_compactor",
			SourceEventPrefix: "observation_compaction",
			DefaultConfidence: 0.95,
			RecordedAt:        acc.LastObservedAt,
			TransactionFrom:   acc.LastObservedAt,
		},
	)
	properties := metadata.PropertyMap()
	properties["summary_scope"] = "daily_compaction"
	properties["summary_date"] = acc.Key.Day
	properties["compacted_observation_count"] = acc.Count

	return &graph.Edge{
		ID:         fmt.Sprintf("%s->%s:%s", summaryID, subjectID, graph.EdgeKindTargets),
		Source:     summaryID,
		Target:     subjectID,
		Kind:       graph.EdgeKindTargets,
		Effect:     graph.EdgeEffectAllow,
		Properties: properties,
	}
}

func (acc *observationCompactionAccumulator) addObservation(node *graph.Node, observedAt time.Time) {
	if acc == nil || node == nil || observedAt.IsZero() {
		return
	}
	acc.Count++
	if acc.FirstObservedAt.IsZero() || observedAt.Before(acc.FirstObservedAt) {
		acc.FirstObservedAt = observedAt
	}
	if acc.LastObservedAt.IsZero() || observedAt.After(acc.LastObservedAt) {
		acc.LastObservedAt = observedAt
	}
	acc.NodeIDs = append(acc.NodeIDs, strings.TrimSpace(node.ID))
	addCounterValue(acc.ProcessNameCounts, propertyString(node.Properties, "process_name"))
	addCounterValue(acc.ProcessPathCounts, propertyString(node.Properties, "process_path"))
	addCounterValue(acc.FilePathCounts, propertyString(node.Properties, "file_path"))
	addCounterValue(acc.NetworkDomainCounts, propertyString(node.Properties, "network_domain"))
	addCounterValue(acc.AuditResourceCounts, propertyString(node.Properties, "audit_resource"))
	addCounterValue(acc.ServiceNameCounts, propertyString(node.Properties, "service_name"))
}

func (acc *observationCompactionAccumulator) mergeExistingSummary(node *graph.Node) {
	if acc == nil || node == nil {
		return
	}
	acc.Count += propertyInt(node.Properties, "compacted_observation_count")
	if ts, ok := propertyTime(node.Properties, "summary_first_observed_at"); ok && (acc.FirstObservedAt.IsZero() || ts.Before(acc.FirstObservedAt)) {
		acc.FirstObservedAt = ts
	}
	if ts, ok := propertyTime(node.Properties, "summary_last_observed_at"); ok && (acc.LastObservedAt.IsZero() || ts.After(acc.LastObservedAt)) {
		acc.LastObservedAt = ts
	}
	mergeCounterMaps(acc.ProcessNameCounts, decodeCounterProperty(node.Properties, "summary_process_name_counts"))
	mergeCounterMaps(acc.ProcessPathCounts, decodeCounterProperty(node.Properties, "summary_process_path_counts"))
	mergeCounterMaps(acc.FilePathCounts, decodeCounterProperty(node.Properties, "summary_file_path_counts"))
	mergeCounterMaps(acc.NetworkDomainCounts, decodeCounterProperty(node.Properties, "summary_network_domain_counts"))
	mergeCounterMaps(acc.AuditResourceCounts, decodeCounterProperty(node.Properties, "summary_audit_resource_counts"))
	mergeCounterMaps(acc.ServiceNameCounts, decodeCounterProperty(node.Properties, "summary_service_name_counts"))
}

func addCounterValue(counter map[string]int, value string) {
	if counter == nil {
		return
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	counter[value]++
}

func mergeCounterMaps(dst, src map[string]int) {
	if dst == nil || len(src) == 0 {
		return
	}
	for key, value := range src {
		if strings.TrimSpace(key) == "" || value == 0 {
			continue
		}
		dst[key] += value
	}
}

func encodeCounterProperty(counter map[string]int) map[string]any {
	if len(counter) == 0 {
		return nil
	}
	encoded := make(map[string]any, len(counter))
	for key, value := range counter {
		if strings.TrimSpace(key) == "" || value == 0 {
			continue
		}
		encoded[key] = value
	}
	if len(encoded) == 0 {
		return nil
	}
	return encoded
}

func decodeCounterProperty(properties map[string]any, key string) map[string]int {
	if len(properties) == 0 {
		return nil
	}
	raw, ok := properties[key]
	if !ok || raw == nil {
		return nil
	}

	switch typed := raw.(type) {
	case map[string]any:
		out := make(map[string]int, len(typed))
		for entryKey, value := range typed {
			out[strings.TrimSpace(entryKey)] = numericPropertyValue(value)
		}
		return out
	case map[string]int:
		out := make(map[string]int, len(typed))
		for entryKey, value := range typed {
			out[strings.TrimSpace(entryKey)] = value
		}
		return out
	default:
		return nil
	}
}

func counterKeysTopN(counter map[string]int, limit int) []string {
	if len(counter) == 0 || limit <= 0 {
		return nil
	}

	type entry struct {
		Key   string
		Count int
	}
	entries := make([]entry, 0, len(counter))
	for key, count := range counter {
		key = strings.TrimSpace(key)
		if key == "" || count <= 0 {
			continue
		}
		entries = append(entries, entry{Key: key, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Key < entries[j].Key
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Key)
	}
	return out
}

func propertyInt(properties map[string]any, key string) int {
	if len(properties) == 0 {
		return 0
	}
	value, ok := properties[key]
	if !ok {
		return 0
	}
	return numericPropertyValue(value)
}

func numericPropertyValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int8:
		return int(typed)
	case int16:
		return int(typed)
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case uint:
		return boundedIntFromUint64(uint64(typed))
	case uint8:
		return int(typed)
	case uint16:
		return int(typed)
	case uint32:
		return int(typed)
	case uint64:
		return boundedIntFromUint64(typed)
	case float32:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
}

func boundedIntFromUint64(value uint64) int {
	maxInt := uint64(^uint(0) >> 1)
	if value > maxInt {
		return int(maxInt)
	}
	return int(value)
}
