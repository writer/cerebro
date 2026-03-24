package graph

import (
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/setutil"
)

// GraphDiffFilter narrows diff/changelog results to matching entities.
type GraphDiffFilter struct {
	Kind     NodeKind `json:"kind,omitempty"`
	Provider string   `json:"provider,omitempty"`
	Account  string   `json:"account,omitempty"`
}

// GraphDiffAttribution summarizes the changed slice of the graph for operator-facing changelog views.
type GraphDiffAttribution struct {
	Providers     []string   `json:"providers,omitempty"`
	Accounts      []string   `json:"accounts,omitempty"`
	Kinds         []NodeKind `json:"kinds,omitempty"`
	SourceSystems []string   `json:"source_systems,omitempty"`
}

// GraphSnapshotDiffDetails is the typed response for one filtered diff details read.
type GraphSnapshotDiffDetails struct {
	ID          string                   `json:"id"`
	GeneratedAt time.Time                `json:"generated_at"`
	From        GraphSnapshotReference   `json:"from"`
	To          GraphSnapshotReference   `json:"to"`
	Filter      GraphDiffFilter          `json:"filter"`
	Summary     GraphSnapshotDiffSummary `json:"summary"`
	Attribution GraphDiffAttribution     `json:"attribution"`
	Diff        GraphDiff                `json:"diff"`
}

// GraphChangelogEntry is one adjacent graph-state change.
type GraphChangelogEntry struct {
	DiffID       string                   `json:"diff_id"`
	DiffURL      string                   `json:"diff_url,omitempty"`
	GeneratedAt  time.Time                `json:"generated_at"`
	StoredAt     *time.Time               `json:"stored_at,omitempty"`
	Materialized bool                     `json:"materialized,omitempty"`
	From         GraphSnapshotReference   `json:"from"`
	To           GraphSnapshotReference   `json:"to"`
	Summary      GraphSnapshotDiffSummary `json:"summary"`
	Attribution  GraphDiffAttribution     `json:"attribution"`
}

// GraphChangelog is the typed response for graph changelog reads.
type GraphChangelog struct {
	GeneratedAt time.Time             `json:"generated_at"`
	Since       *time.Time            `json:"since,omitempty"`
	Until       *time.Time            `json:"until,omitempty"`
	Filter      GraphDiffFilter       `json:"filter"`
	Count       int                   `json:"count"`
	Entries     []GraphChangelogEntry `json:"entries,omitempty"`
}

func FilterGraphDiff(diff *GraphDiff, before, after *Snapshot, filter GraphDiffFilter) *GraphDiff {
	if diff == nil {
		return nil
	}
	filter = normalizeGraphDiffFilter(filter)
	if filter.Kind == "" && filter.Provider == "" && filter.Account == "" {
		cloned := *diff
		cloned.NodesAdded = cloneNodes(diff.NodesAdded)
		cloned.NodesRemoved = cloneNodes(diff.NodesRemoved)
		cloned.NodesModified = cloneNodeChanges(diff.NodesModified)
		cloned.EdgesAdded = cloneEdges(diff.EdgesAdded)
		cloned.EdgesRemoved = cloneEdges(diff.EdgesRemoved)
		return &cloned
	}

	beforeNodes := snapshotNodeMap(before)
	afterNodes := snapshotNodeMap(after)
	filtered := &GraphDiff{
		FromVersion:   diff.FromVersion,
		ToVersion:     diff.ToVersion,
		FromTimestamp: diff.FromTimestamp,
		ToTimestamp:   diff.ToTimestamp,
	}
	for _, node := range diff.NodesAdded {
		if nodeMatchesGraphDiffFilter(node, filter) {
			filtered.NodesAdded = append(filtered.NodesAdded, cloneNode(node))
		}
	}
	for _, node := range diff.NodesRemoved {
		if nodeMatchesGraphDiffFilter(node, filter) {
			filtered.NodesRemoved = append(filtered.NodesRemoved, cloneNode(node))
		}
	}
	for _, change := range diff.NodesModified {
		beforeNode := beforeNodes[change.NodeID]
		afterNode := afterNodes[change.NodeID]
		if !nodeMatchesGraphDiffFilter(beforeNode, filter) && !nodeMatchesGraphDiffFilter(afterNode, filter) {
			continue
		}
		filtered.NodesModified = append(filtered.NodesModified, cloneNodeChange(change))
	}
	for _, edge := range diff.EdgesAdded {
		if edgeMatchesGraphDiffFilter(edge, filter, afterNodes) {
			filtered.EdgesAdded = append(filtered.EdgesAdded, cloneEdge(edge))
		}
	}
	for _, edge := range diff.EdgesRemoved {
		if edgeMatchesGraphDiffFilter(edge, filter, beforeNodes) {
			filtered.EdgesRemoved = append(filtered.EdgesRemoved, cloneEdge(edge))
		}
	}
	return filtered
}

func BuildGraphSnapshotDiffDetails(record *GraphSnapshotDiffRecord, before, after *Snapshot, filter GraphDiffFilter) *GraphSnapshotDiffDetails {
	if record == nil {
		return nil
	}
	filtered := FilterGraphDiff(&record.Diff, before, after, filter)
	if filtered == nil {
		return nil
	}
	return &GraphSnapshotDiffDetails{
		ID:          record.ID,
		GeneratedAt: record.GeneratedAt,
		From:        record.From,
		To:          record.To,
		Filter:      normalizeGraphDiffFilter(filter),
		Summary: GraphSnapshotDiffSummary{
			NodesAdded:    len(filtered.NodesAdded),
			NodesRemoved:  len(filtered.NodesRemoved),
			NodesModified: len(filtered.NodesModified),
			EdgesAdded:    len(filtered.EdgesAdded),
			EdgesRemoved:  len(filtered.EdgesRemoved),
		},
		Attribution: SummarizeGraphDiffAttribution(*filtered),
		Diff:        *filtered,
	}
}

func SummarizeGraphDiffAttribution(diff GraphDiff) GraphDiffAttribution {
	providers := make(map[string]struct{})
	accounts := make(map[string]struct{})
	kinds := make(map[NodeKind]struct{})
	sourceSystems := make(map[string]struct{})

	appendNode := func(node *Node) {
		if node == nil {
			return
		}
		if provider := strings.ToLower(strings.TrimSpace(node.Provider)); provider != "" {
			providers[provider] = struct{}{}
		}
		if account := strings.TrimSpace(node.Account); account != "" {
			accounts[account] = struct{}{}
		}
		if node.Kind != "" {
			kinds[node.Kind] = struct{}{}
		}
		if sourceSystem := strings.ToLower(strings.TrimSpace(nodePropertyString(node, "source_system"))); sourceSystem != "" {
			sourceSystems[sourceSystem] = struct{}{}
		}
	}

	for _, node := range diff.NodesAdded {
		appendNode(node)
	}
	for _, node := range diff.NodesRemoved {
		appendNode(node)
	}
	for _, change := range diff.NodesModified {
		appendNode(nodeFromChange("after", change))
		appendNode(nodeFromChange("before", change))
	}

	return GraphDiffAttribution{
		Providers:     setutil.SortedStrings(providers),
		Accounts:      setutil.SortedStrings(accounts),
		Kinds:         sortedNodeKindSet(kinds),
		SourceSystems: setutil.SortedStrings(sourceSystems),
	}
}

func normalizeGraphDiffFilter(filter GraphDiffFilter) GraphDiffFilter {
	filter.Kind = NodeKind(strings.ToLower(strings.TrimSpace(string(filter.Kind))))
	filter.Provider = strings.ToLower(strings.TrimSpace(filter.Provider))
	filter.Account = strings.TrimSpace(filter.Account)
	return filter
}

func nodeMatchesGraphDiffFilter(node *Node, filter GraphDiffFilter) bool {
	if node == nil {
		return false
	}
	if filter.Kind != "" && node.Kind != filter.Kind {
		return false
	}
	if filter.Provider != "" && strings.ToLower(strings.TrimSpace(node.Provider)) != filter.Provider {
		return false
	}
	if filter.Account != "" && strings.TrimSpace(node.Account) != filter.Account {
		return false
	}
	return true
}

func edgeMatchesGraphDiffFilter(edge *Edge, filter GraphDiffFilter, nodes map[string]*Node) bool {
	if edge == nil {
		return false
	}
	if filter.Kind == "" && filter.Provider == "" && filter.Account == "" {
		return true
	}
	return nodeMatchesGraphDiffFilter(nodes[edge.Source], filter) || nodeMatchesGraphDiffFilter(nodes[edge.Target], filter)
}

func snapshotNodeMap(snapshot *Snapshot) map[string]*Node {
	if snapshot == nil {
		return map[string]*Node{}
	}
	out := make(map[string]*Node, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		if node == nil || node.ID == "" {
			continue
		}
		out[node.ID] = node
	}
	return out
}

func nodeFromChange(which string, change NodeChange) *Node {
	source := change.Before
	if which == "after" {
		source = change.After
	}
	if len(source) == 0 {
		return nil
	}
	node := &Node{
		ID:       strings.TrimSpace(change.NodeID),
		Kind:     NodeKind(strings.TrimSpace(readString(source, "kind"))),
		Name:     strings.TrimSpace(readString(source, "name")),
		Provider: strings.TrimSpace(readString(source, "provider")),
		Account:  strings.TrimSpace(readString(source, "account")),
		Region:   strings.TrimSpace(readString(source, "region")),
	}
	if properties, ok := source["properties"].(map[string]any); ok {
		node.Properties = cloneAnyMap(properties)
	}
	return node
}

func sortedNodeKindSet(values map[NodeKind]struct{}) []NodeKind {
	if len(values) == 0 {
		return nil
	}
	out := make([]NodeKind, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func cloneNodeChanges(values []NodeChange) []NodeChange {
	if len(values) == 0 {
		return nil
	}
	out := make([]NodeChange, 0, len(values))
	for _, value := range values {
		out = append(out, cloneNodeChange(value))
	}
	return out
}

func cloneNodeChange(value NodeChange) NodeChange {
	return NodeChange{
		NodeID:      value.NodeID,
		Before:      cloneAnyMap(value.Before),
		After:       cloneAnyMap(value.After),
		ChangedKeys: append([]string(nil), value.ChangedKeys...),
	}
}

func cloneNodes(values []*Node) []*Node {
	if len(values) == 0 {
		return nil
	}
	out := make([]*Node, 0, len(values))
	for _, value := range values {
		out = append(out, cloneNode(value))
	}
	return out
}

func cloneEdges(values []*Edge) []*Edge {
	if len(values) == 0 {
		return nil
	}
	out := make([]*Edge, 0, len(values))
	for _, value := range values {
		out = append(out, cloneEdge(value))
	}
	return out
}
