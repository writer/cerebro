package graph

import (
	"math"
	"sort"
	"strings"
	"time"
)

const defaultFreshnessStaleAfter = 30 * 24 * time.Hour

// FreshnessMetrics summarizes recency coverage in the graph.
type FreshnessMetrics struct {
	ObservedAt        time.Time `json:"observed_at"`
	TotalNodes        int       `json:"total_nodes"`
	NodesWithObserved int       `json:"nodes_with_observed"`
	FreshNodes        int       `json:"fresh_nodes"`
	StaleNodes        int       `json:"stale_nodes"`
	FreshnessPercent  float64   `json:"freshness_percent"`
	MedianAgeHours    float64   `json:"median_age_hours"`
	P95AgeHours       float64   `json:"p95_age_hours"`
}

// GetOutEdgesAt returns outgoing edges active at one timestamp.
func (g *Graph) GetOutEdgesAt(nodeID string, at time.Time) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.activeEdgesAtForNodeLocked(g.outEdges[nodeID], at)
}

// GetInEdgesAt returns incoming edges active at one timestamp.
func (g *Graph) GetInEdgesAt(nodeID string, at time.Time) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.activeEdgesAtForNodeLocked(g.inEdges[nodeID], at)
}

// GetAllNodesAt returns nodes active at one timestamp.
func (g *Graph) GetAllNodesAt(at time.Time) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if at.IsZero() {
		at = temporalNowUTC()
	}
	nodes := make([]*Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		if g.nodeActiveAtLocked(node, at) {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetAllNodesBitemporal returns nodes active for both fact time and recorded time.
func (g *Graph) GetAllNodesBitemporal(validAt, recordedAt time.Time) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if validAt.IsZero() {
		validAt = temporalNowUTC()
	}
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}

	nodes := make([]*Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		if g.nodeVisibleAtLocked(node, validAt, recordedAt) {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// SubgraphAt builds one graph view with nodes and edges active at one timestamp.
func (g *Graph) SubgraphAt(at time.Time) *Graph {
	if g == nil {
		return nil
	}
	if at.IsZero() {
		at = temporalNowUTC()
	}
	out := New()
	out.SetSchemaValidationMode(g.SchemaValidationMode())

	for _, node := range g.GetAllNodesAt(at) {
		out.AddNode(cloneNode(node))
	}
	for _, node := range out.GetAllNodes() {
		for _, edge := range g.GetOutEdgesAt(node.ID, at) {
			if edge == nil {
				continue
			}
			if _, ok := out.GetNode(edge.Source); !ok {
				continue
			}
			if _, ok := out.GetNode(edge.Target); !ok {
				continue
			}
			out.AddEdge(cloneEdge(edge))
		}
	}
	return out
}

// SubgraphBitemporal builds one graph view filtered by fact time and recorded time.
func (g *Graph) SubgraphBitemporal(validAt, recordedAt time.Time) *Graph {
	if g == nil {
		return nil
	}
	if validAt.IsZero() {
		validAt = temporalNowUTC()
	}
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}

	out := New()
	out.SetSchemaValidationMode(g.SchemaValidationMode())

	for _, node := range g.GetAllNodesBitemporal(validAt, recordedAt) {
		out.AddNode(cloneNode(node))
	}
	for _, node := range out.GetAllNodes() {
		for _, edge := range g.GetOutEdgesBitemporal(node.ID, validAt, recordedAt) {
			if edge == nil {
				continue
			}
			if _, ok := out.GetNode(edge.Source); !ok {
				continue
			}
			if _, ok := out.GetNode(edge.Target); !ok {
				continue
			}
			out.AddEdge(cloneEdge(edge))
		}
	}
	return out
}

// SubgraphBetween builds one graph view containing entities valid at any time in [from, to].
func (g *Graph) SubgraphBetween(from, to time.Time) *Graph {
	if g == nil {
		return nil
	}
	if from.IsZero() && to.IsZero() {
		return g.SubgraphAt(temporalNowUTC())
	}
	if from.IsZero() {
		from = to
	}
	if to.IsZero() {
		to = from
	}
	if to.Before(from) {
		from, to = to, from
	}
	from = from.UTC()
	to = to.UTC()

	out := New()
	out.SetSchemaValidationMode(g.SchemaValidationMode())

	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, node := range g.nodes {
		if !g.nodeIntersectsWindowLocked(node, from, to) {
			continue
		}
		out.AddNode(cloneNode(node))
	}
	for sourceID := range out.nodes {
		for _, edge := range g.outEdges[sourceID] {
			if !g.edgeIntersectsWindowLocked(edge, from, to) {
				continue
			}
			if _, ok := out.nodes[edge.Target]; !ok {
				continue
			}
			out.AddEdge(cloneEdge(edge))
		}
	}
	return out
}

// Freshness computes observed_at recency metrics for active nodes.
func (g *Graph) Freshness(now time.Time, staleAfter time.Duration) FreshnessMetrics {
	if now.IsZero() {
		now = temporalNowUTC()
	}
	if staleAfter <= 0 {
		staleAfter = defaultFreshnessStaleAfter
	}

	nodes := g.GetAllNodes()
	ages := make([]float64, 0, len(nodes))
	metrics := FreshnessMetrics{
		ObservedAt: now.UTC(),
		TotalNodes: len(nodes),
	}

	for _, node := range nodes {
		if node == nil {
			continue
		}
		observedAt, ok := graphObservedAt(node)
		if !ok {
			continue
		}
		metrics.NodesWithObserved++
		age := now.Sub(observedAt)
		if age < 0 {
			age = 0
		}
		ageHours := age.Hours()
		ages = append(ages, ageHours)
		if age <= staleAfter {
			metrics.FreshNodes++
		} else {
			metrics.StaleNodes++
		}
	}

	if metrics.TotalNodes > 0 {
		metrics.FreshnessPercent = (float64(metrics.FreshNodes) / float64(metrics.TotalNodes)) * 100
	}
	if len(ages) == 0 {
		return metrics
	}

	sort.Float64s(ages)
	metrics.MedianAgeHours = percentile(ages, 0.50)
	metrics.P95AgeHours = percentile(ages, 0.95)
	return metrics
}

// GetOutEdgesBitemporal returns outgoing edges active for both fact time and recorded time.
func (g *Graph) GetOutEdgesBitemporal(nodeID string, validAt, recordedAt time.Time) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.activeEdgesBitemporalForNodeLocked(g.outEdges[nodeID], validAt, recordedAt)
}

// GetInEdgesBitemporal returns incoming edges active for both fact time and recorded time.
func (g *Graph) GetInEdgesBitemporal(nodeID string, validAt, recordedAt time.Time) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.activeEdgesBitemporalForNodeLocked(g.inEdges[nodeID], validAt, recordedAt)
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	position := p * float64(len(sorted)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return sorted[lower]
	}
	weight := position - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}

func (g *Graph) activeEdgesAtForNodeLocked(edges []*Edge, at time.Time) []*Edge {
	if len(edges) == 0 {
		return nil
	}
	if at.IsZero() {
		at = temporalNowUTC()
	}

	active := make([]*Edge, 0, len(edges))
	for _, edge := range edges {
		if !g.edgeActiveAtLocked(edge, at) {
			continue
		}
		active = append(active, edge)
	}
	return active
}

func (g *Graph) activeEdgesBitemporalForNodeLocked(edges []*Edge, validAt, recordedAt time.Time) []*Edge {
	if len(edges) == 0 {
		return nil
	}
	if validAt.IsZero() {
		validAt = temporalNowUTC()
	}
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}

	active := make([]*Edge, 0, len(edges))
	for _, edge := range edges {
		if !g.edgeVisibleAtLocked(edge, validAt, recordedAt) {
			continue
		}
		active = append(active, edge)
	}
	return active
}

func (g *Graph) nodeActiveAtLocked(node *Node, at time.Time) bool {
	if node == nil || node.DeletedAt != nil {
		return false
	}
	start, end := nodeTemporalBounds(node)
	return temporalContains(start, end, at)
}

func (g *Graph) nodeVisibleAtLocked(node *Node, validAt, recordedAt time.Time) bool {
	if node == nil || node.DeletedAt != nil {
		return false
	}
	validStart, validEnd := nodeTemporalBounds(node)
	recordedStart, recordedEnd := nodeRecordedBounds(node)
	return temporalContains(validStart, validEnd, validAt) && temporalContains(recordedStart, recordedEnd, recordedAt)
}

func (g *Graph) edgeActiveAtLocked(edge *Edge, at time.Time) bool {
	if edge == nil || edge.DeletedAt != nil {
		return false
	}
	source, ok := g.nodes[edge.Source]
	if !ok || !g.nodeActiveAtLocked(source, at) {
		return false
	}
	target, ok := g.nodes[edge.Target]
	if !ok || !g.nodeActiveAtLocked(target, at) {
		return false
	}
	start, end := temporalBounds(edge.Properties, edge.CreatedAt, edge.DeletedAt)
	return temporalContains(start, end, at)
}

func (g *Graph) edgeVisibleAtLocked(edge *Edge, validAt, recordedAt time.Time) bool {
	if edge == nil || edge.DeletedAt != nil {
		return false
	}
	source, ok := g.nodes[edge.Source]
	if !ok || !g.nodeVisibleAtLocked(source, validAt, recordedAt) {
		return false
	}
	target, ok := g.nodes[edge.Target]
	if !ok || !g.nodeVisibleAtLocked(target, validAt, recordedAt) {
		return false
	}
	validStart, validEnd := temporalBounds(edge.Properties, edge.CreatedAt, edge.DeletedAt)
	recordedStart, recordedEnd := recordedBounds(edge.Properties, edge.CreatedAt, edge.DeletedAt)
	return temporalContains(validStart, validEnd, validAt) && temporalContains(recordedStart, recordedEnd, recordedAt)
}

func (g *Graph) nodeIntersectsWindowLocked(node *Node, from, to time.Time) bool {
	if node == nil || node.DeletedAt != nil {
		return false
	}
	start, end := nodeTemporalBounds(node)
	return temporalIntersects(start, end, from, to)
}

func nodeTemporalBounds(node *Node) (time.Time, time.Time) {
	if node == nil {
		return time.Time{}, time.Time{}
	}
	var start time.Time
	var end time.Time
	if ts, ok := nodePropertyTime(node, "valid_from"); ok {
		start = ts
	}
	if start.IsZero() {
		if ts, ok := nodePropertyTime(node, "observed_at"); ok {
			start = ts
		}
	}
	if ts, ok := nodePropertyTime(node, "valid_to"); ok {
		end = ts
	}
	if end.IsZero() {
		if ts, ok := temporalPropertyTime(node.Properties, "expires_at"); ok {
			end = ts
		}
	}
	if start.IsZero() {
		start = node.CreatedAt.UTC()
	}
	if node.DeletedAt != nil && !node.DeletedAt.IsZero() {
		if end.IsZero() || node.DeletedAt.UTC().Before(end) {
			end = node.DeletedAt.UTC()
		}
	}
	return start.UTC(), end.UTC()
}

func nodeRecordedBounds(node *Node) (time.Time, time.Time) {
	if node == nil {
		return time.Time{}, time.Time{}
	}
	var start time.Time
	var end time.Time
	if ts, ok := nodePropertyTime(node, "transaction_from"); ok {
		start = ts
	}
	if start.IsZero() {
		if ts, ok := nodePropertyTime(node, "recorded_at"); ok {
			start = ts
		}
	}
	if ts, ok := nodePropertyTime(node, "transaction_to"); ok {
		end = ts
	}
	if start.IsZero() {
		start = node.CreatedAt.UTC()
	}
	if node.DeletedAt != nil && !node.DeletedAt.IsZero() {
		if end.IsZero() || node.DeletedAt.UTC().Before(end) {
			end = node.DeletedAt.UTC()
		}
	}
	return start.UTC(), end.UTC()
}

func (g *Graph) edgeIntersectsWindowLocked(edge *Edge, from, to time.Time) bool {
	if edge == nil || edge.DeletedAt != nil {
		return false
	}
	source, ok := g.nodes[edge.Source]
	if !ok || !g.nodeIntersectsWindowLocked(source, from, to) {
		return false
	}
	target, ok := g.nodes[edge.Target]
	if !ok || !g.nodeIntersectsWindowLocked(target, from, to) {
		return false
	}
	start, end := temporalBounds(edge.Properties, edge.CreatedAt, edge.DeletedAt)
	return temporalIntersects(start, end, from, to)
}

func temporalBounds(properties map[string]any, createdAt time.Time, deletedAt *time.Time) (time.Time, time.Time) {
	var start time.Time
	var end time.Time
	if properties != nil {
		if ts, ok := temporalPropertyTime(properties, "valid_from"); ok {
			start = ts
		}
		if start.IsZero() {
			if ts, ok := temporalPropertyTime(properties, "observed_at"); ok {
				start = ts
			}
		}
		if ts, ok := temporalPropertyTime(properties, "valid_to"); ok {
			end = ts
		}
		if end.IsZero() {
			if ts, ok := temporalPropertyTime(properties, "expires_at"); ok {
				end = ts
			}
		}
	}
	if start.IsZero() {
		start = createdAt.UTC()
	}
	if deletedAt != nil && !deletedAt.IsZero() {
		if end.IsZero() || deletedAt.UTC().Before(end) {
			end = deletedAt.UTC()
		}
	}
	return start.UTC(), end.UTC()
}

func recordedBounds(properties map[string]any, createdAt time.Time, deletedAt *time.Time) (time.Time, time.Time) {
	var start time.Time
	var end time.Time
	if properties != nil {
		if ts, ok := temporalPropertyTime(properties, "transaction_from"); ok {
			start = ts
		}
		if start.IsZero() {
			if ts, ok := temporalPropertyTime(properties, "recorded_at"); ok {
				start = ts
			}
		}
		if ts, ok := temporalPropertyTime(properties, "transaction_to"); ok {
			end = ts
		}
	}
	if start.IsZero() {
		start = createdAt.UTC()
	}
	if deletedAt != nil && !deletedAt.IsZero() {
		if end.IsZero() || deletedAt.UTC().Before(end) {
			end = deletedAt.UTC()
		}
	}
	return start.UTC(), end.UTC()
}

func temporalContains(start, end, at time.Time) bool {
	if at.IsZero() {
		at = temporalNowUTC()
	}
	at = at.UTC()
	if !start.IsZero() && at.Before(start.UTC()) {
		return false
	}
	if !end.IsZero() && at.After(end.UTC()) {
		return false
	}
	return true
}

func temporalIntersects(start, end, from, to time.Time) bool {
	if from.IsZero() || to.IsZero() {
		return temporalContains(start, end, temporalNowUTC())
	}
	from = from.UTC()
	to = to.UTC()
	if to.Before(from) {
		from, to = to, from
	}
	if !end.IsZero() && end.UTC().Before(from) {
		return false
	}
	if !start.IsZero() && start.UTC().After(to) {
		return false
	}
	return true
}

func temporalPropertyTime(properties map[string]any, key string) (time.Time, bool) {
	if len(properties) == 0 {
		return time.Time{}, false
	}
	value, ok := properties[strings.TrimSpace(key)]
	if !ok {
		return time.Time{}, false
	}
	return temporalValueTime(value)
}

func temporalValueTime(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case nil:
		return time.Time{}, false
	case time.Time:
		return typed.UTC(), true
	case string:
		raw := strings.TrimSpace(typed)
		if raw == "" {
			return time.Time{}, false
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
			if parsed, err := time.Parse(layout, raw); err == nil {
				return parsed.UTC(), true
			}
		}
		return time.Time{}, false
	default:
		return time.Time{}, false
	}
}

func graphObservedAt(node *Node) (time.Time, bool) {
	if node == nil {
		return time.Time{}, false
	}
	if props, ok := node.ObservationProperties(); ok && !props.ObservedAt.IsZero() {
		return props.ObservedAt, true
	}
	if props, ok := node.AttackSequenceProperties(); ok && !props.ObservedAt.IsZero() {
		return props.ObservedAt, true
	}
	if ts, ok := temporalPropertyTime(node.Properties, "observed_at"); ok {
		return ts, true
	}
	if !node.UpdatedAt.IsZero() {
		return node.UpdatedAt.UTC(), true
	}
	if !node.CreatedAt.IsZero() {
		return node.CreatedAt.UTC(), true
	}
	return time.Time{}, false
}

func nodePropertyTime(node *Node, key string) (time.Time, bool) {
	if node == nil {
		return time.Time{}, false
	}
	if props, ok := node.ObservationProperties(); ok {
		switch strings.TrimSpace(key) {
		case "observed_at":
			if !props.ObservedAt.IsZero() {
				return props.ObservedAt.UTC(), true
			}
		case "valid_from":
			if !props.ValidFrom.IsZero() {
				return props.ValidFrom.UTC(), true
			}
		case "valid_to":
			if props.ValidTo != nil && !props.ValidTo.IsZero() {
				return props.ValidTo.UTC(), true
			}
		case "recorded_at":
			if !props.RecordedAt.IsZero() {
				return props.RecordedAt.UTC(), true
			}
		case "transaction_from":
			if !props.TransactionFrom.IsZero() {
				return props.TransactionFrom.UTC(), true
			}
		case "transaction_to":
			if props.TransactionTo != nil && !props.TransactionTo.IsZero() {
				return props.TransactionTo.UTC(), true
			}
		}
	}
	if props, ok := node.AttackSequenceProperties(); ok {
		switch strings.TrimSpace(key) {
		case "sequence_start", "valid_from":
			if !props.SequenceStart.IsZero() {
				return props.SequenceStart.UTC(), true
			}
			if !props.ValidFrom.IsZero() {
				return props.ValidFrom.UTC(), true
			}
		case "sequence_end":
			if !props.SequenceEnd.IsZero() {
				return props.SequenceEnd.UTC(), true
			}
		case "observed_at":
			if !props.ObservedAt.IsZero() {
				return props.ObservedAt.UTC(), true
			}
		case "valid_to":
			if props.ValidTo != nil && !props.ValidTo.IsZero() {
				return props.ValidTo.UTC(), true
			}
		case "recorded_at":
			if !props.RecordedAt.IsZero() {
				return props.RecordedAt.UTC(), true
			}
		case "transaction_from":
			if !props.TransactionFrom.IsZero() {
				return props.TransactionFrom.UTC(), true
			}
		}
	}
	return temporalPropertyTime(node.Properties, key)
}
