package graph

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"
)

// GraphDiff captures structural graph changes between two snapshots.
type GraphDiff struct {
	FromVersion   string    `json:"from_version"`
	ToVersion     string    `json:"to_version"`
	FromTimestamp time.Time `json:"from_timestamp"`
	ToTimestamp   time.Time `json:"to_timestamp"`

	NodesAdded    []*Node      `json:"nodes_added"`
	NodesRemoved  []*Node      `json:"nodes_removed"`
	NodesModified []NodeChange `json:"nodes_modified"`

	EdgesAdded   []*Edge `json:"edges_added"`
	EdgesRemoved []*Edge `json:"edges_removed"`
}

// NodeChange captures before/after state for a modified node.
type NodeChange struct {
	NodeID      string         `json:"node_id"`
	Before      map[string]any `json:"before"`
	After       map[string]any `json:"after"`
	ChangedKeys []string       `json:"changed_keys"`
}

// DiffSnapshots compares two snapshots and returns a structural diff.
func DiffSnapshots(before, after *Snapshot) *GraphDiff {
	diff := &GraphDiff{}
	if before != nil {
		diff.FromVersion = before.Version
		diff.FromTimestamp = before.CreatedAt
	}
	if after != nil {
		diff.ToVersion = after.Version
		diff.ToTimestamp = after.CreatedAt
	}
	if before == nil || after == nil {
		return diff
	}

	beforeNodes := make(map[string]*Node, len(before.Nodes))
	for _, node := range before.Nodes {
		if node == nil || node.ID == "" {
			continue
		}
		beforeNodes[node.ID] = node
	}
	afterNodes := make(map[string]*Node, len(after.Nodes))
	for _, node := range after.Nodes {
		if node == nil || node.ID == "" {
			continue
		}
		afterNodes[node.ID] = node
	}

	nodeIDs := unionSortedKeys(beforeNodes, afterNodes)
	for _, nodeID := range nodeIDs {
		beforeNode, hadBefore := beforeNodes[nodeID]
		afterNode, hadAfter := afterNodes[nodeID]
		beforeActive := hadBefore && isSnapshotNodeActive(beforeNode)
		afterActive := hadAfter && isSnapshotNodeActive(afterNode)

		switch {
		case !beforeActive && afterActive:
			diff.NodesAdded = append(diff.NodesAdded, cloneNode(afterNode))
		case beforeActive && !afterActive:
			diff.NodesRemoved = append(diff.NodesRemoved, cloneNode(beforeNode))
		case beforeActive && afterActive:
			if change, ok := diffNode(beforeNode, afterNode); ok {
				diff.NodesModified = append(diff.NodesModified, change)
			}
		}
	}

	beforeEdges := activeSnapshotEdgesByKey(before.Edges)
	afterEdges := activeSnapshotEdgesByKey(after.Edges)
	edgeKeys := unionSortedKeys(beforeEdges, afterEdges)
	for _, key := range edgeKeys {
		beforeEdge, hadBefore := beforeEdges[key]
		afterEdge, hadAfter := afterEdges[key]

		switch {
		case !hadBefore && hadAfter:
			diff.EdgesAdded = append(diff.EdgesAdded, cloneEdge(afterEdge))
		case hadBefore && !hadAfter:
			diff.EdgesRemoved = append(diff.EdgesRemoved, cloneEdge(beforeEdge))
		}
	}

	sort.Slice(diff.NodesAdded, func(i, j int) bool { return diff.NodesAdded[i].ID < diff.NodesAdded[j].ID })
	sort.Slice(diff.NodesRemoved, func(i, j int) bool { return diff.NodesRemoved[i].ID < diff.NodesRemoved[j].ID })
	sort.Slice(diff.NodesModified, func(i, j int) bool { return diff.NodesModified[i].NodeID < diff.NodesModified[j].NodeID })
	sort.Slice(diff.EdgesAdded, func(i, j int) bool {
		if diff.EdgesAdded[i].Source == diff.EdgesAdded[j].Source {
			if diff.EdgesAdded[i].Target == diff.EdgesAdded[j].Target {
				if diff.EdgesAdded[i].Kind == diff.EdgesAdded[j].Kind {
					return diff.EdgesAdded[i].ID < diff.EdgesAdded[j].ID
				}
				return diff.EdgesAdded[i].Kind < diff.EdgesAdded[j].Kind
			}
			return diff.EdgesAdded[i].Target < diff.EdgesAdded[j].Target
		}
		return diff.EdgesAdded[i].Source < diff.EdgesAdded[j].Source
	})
	sort.Slice(diff.EdgesRemoved, func(i, j int) bool {
		if diff.EdgesRemoved[i].Source == diff.EdgesRemoved[j].Source {
			if diff.EdgesRemoved[i].Target == diff.EdgesRemoved[j].Target {
				if diff.EdgesRemoved[i].Kind == diff.EdgesRemoved[j].Kind {
					return diff.EdgesRemoved[i].ID < diff.EdgesRemoved[j].ID
				}
				return diff.EdgesRemoved[i].Kind < diff.EdgesRemoved[j].Kind
			}
			return diff.EdgesRemoved[i].Target < diff.EdgesRemoved[j].Target
		}
		return diff.EdgesRemoved[i].Source < diff.EdgesRemoved[j].Source
	})

	return diff
}

func diffNode(before, after *Node) (NodeChange, bool) {
	beforeProps := cloneAnyMap(before.Properties)
	afterProps := cloneAnyMap(after.Properties)

	changedKeysSet := make(map[string]struct{})
	for key, beforeValue := range beforeProps {
		afterValue, ok := afterProps[key]
		if !ok || !reflect.DeepEqual(beforeValue, afterValue) {
			changedKeysSet[key] = struct{}{}
		}
	}
	for key, afterValue := range afterProps {
		beforeValue, ok := beforeProps[key]
		if !ok || !reflect.DeepEqual(beforeValue, afterValue) {
			changedKeysSet[key] = struct{}{}
		}
	}

	if before.Kind != after.Kind {
		changedKeysSet["kind"] = struct{}{}
	}
	if before.Name != after.Name {
		changedKeysSet["name"] = struct{}{}
	}
	if before.Provider != after.Provider {
		changedKeysSet["provider"] = struct{}{}
	}
	if before.Account != after.Account {
		changedKeysSet["account"] = struct{}{}
	}
	if before.Region != after.Region {
		changedKeysSet["region"] = struct{}{}
	}
	if before.Risk != after.Risk {
		changedKeysSet["risk"] = struct{}{}
	}

	if len(changedKeysSet) == 0 {
		return NodeChange{}, false
	}

	changedKeys := make([]string, 0, len(changedKeysSet))
	for key := range changedKeysSet {
		changedKeys = append(changedKeys, key)
	}
	sort.Strings(changedKeys)

	return NodeChange{
		NodeID: after.ID,
		Before: map[string]any{
			"kind":       before.Kind,
			"name":       before.Name,
			"provider":   before.Provider,
			"account":    before.Account,
			"region":     before.Region,
			"risk":       before.Risk,
			"properties": beforeProps,
		},
		After: map[string]any{
			"kind":       after.Kind,
			"name":       after.Name,
			"provider":   after.Provider,
			"account":    after.Account,
			"region":     after.Region,
			"risk":       after.Risk,
			"properties": afterProps,
		},
		ChangedKeys: changedKeys,
	}, true
}

func activeSnapshotEdgesByKey(edges []*Edge) map[string]*Edge {
	active := make(map[string]*Edge)
	for _, edge := range edges {
		if !isSnapshotEdgeActive(edge) {
			continue
		}
		active[snapshotEdgeKey(edge)] = edge
	}
	return active
}

func snapshotEdgeKey(edge *Edge) string {
	if edge == nil {
		return ""
	}
	props, _ := json.Marshal(edge.Properties)
	return fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s|%s", edge.ID, edge.Source, edge.Target, edge.Kind, edge.Effect, edge.Priority, edge.Risk, string(props))
}

func isSnapshotNodeActive(node *Node) bool {
	return node != nil && node.DeletedAt == nil
}

func isSnapshotEdgeActive(edge *Edge) bool {
	return edge != nil && edge.DeletedAt == nil
}

func unionSortedKeys[T any](left, right map[string]T) []string {
	set := make(map[string]struct{}, len(left)+len(right))
	for key := range left {
		set[key] = struct{}{}
	}
	for key := range right {
		set[key] = struct{}{}
	}
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
