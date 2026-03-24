package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const graphMutationRecordVersion = "1"

type GraphMutationType string

const (
	GraphMutationAddNode         GraphMutationType = "add_node"
	GraphMutationAddEdge         GraphMutationType = "add_edge"
	GraphMutationSetNodeProperty GraphMutationType = "set_node_property"
	GraphMutationRemoveNode      GraphMutationType = "remove_node"
)

type GraphMutationRecord struct {
	Version       string            `json:"version"`
	Sequence      uint64            `json:"sequence"`
	RecordedAt    time.Time         `json:"recorded_at"`
	Type          GraphMutationType `json:"type"`
	Node          *Node             `json:"node,omitempty"`
	Edge          *Edge             `json:"edge,omitempty"`
	NodeID        string            `json:"node_id,omitempty"`
	PropertyKey   string            `json:"property_key,omitempty"`
	PropertyValue any               `json:"property_value,omitempty"`
}

func AppendGraphMutationRecord(w io.Writer, record GraphMutationRecord) error {
	sanitized, err := sanitizeGraphMutationRecord(record)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(w).Encode(sanitized); err != nil {
		return fmt.Errorf("encode graph mutation record: %w", err)
	}
	return nil
}

func LoadGraphMutationRecords(r io.Reader) ([]GraphMutationRecord, error) {
	decoder := json.NewDecoder(r)
	decoder.UseNumber()
	records := make([]GraphMutationRecord, 0, 16)
	for {
		var record GraphMutationRecord
		if err := decoder.Decode(&record); err != nil {
			if err == io.EOF {
				return records, nil
			}
			return nil, fmt.Errorf("decode graph mutation record: %w", err)
		}
		sanitized, err := sanitizeGraphMutationRecord(record)
		if err != nil {
			return nil, err
		}
		records = append(records, sanitized)
	}
}

func ReplayGraphMutationRecords(g *Graph, records []GraphMutationRecord) error {
	if g == nil {
		return fmt.Errorf("graph is required")
	}
	seen := make(map[uint64]GraphMutationType, len(records))
	for _, record := range records {
		sanitized, err := sanitizeGraphMutationRecord(record)
		if err != nil {
			return err
		}
		if previousType, ok := seen[sanitized.Sequence]; ok {
			if previousType == sanitized.Type {
				continue
			}
			return fmt.Errorf("replay graph mutation records: conflicting record types share sequence %d", sanitized.Sequence)
		}
		seen[sanitized.Sequence] = sanitized.Type
		if err := ApplyGraphMutationRecord(g, sanitized); err != nil {
			return err
		}
	}
	return nil
}

func ApplyGraphMutationRecord(g *Graph, record GraphMutationRecord) error {
	if g == nil {
		return fmt.Errorf("graph is required")
	}
	sanitized, err := sanitizeGraphMutationRecord(record)
	if err != nil {
		return err
	}
	switch sanitized.Type {
	case GraphMutationAddNode:
		if existing, ok := g.GetNodeIncludingDeleted(sanitized.Node.ID); ok && shouldSkipReplayedAddNode(existing, sanitized.Node) {
			return nil
		}
		g.AddNode(cloneNode(sanitized.Node))
	case GraphMutationAddEdge:
		if err := applyReplayedAddEdge(g, cloneEdge(sanitized.Edge)); err != nil {
			return err
		}
	case GraphMutationSetNodeProperty:
		if !g.SetNodeProperty(sanitized.NodeID, sanitized.PropertyKey, cloneAny(sanitized.PropertyValue)) {
			if _, ok := g.GetNodeIncludingDeleted(sanitized.NodeID); ok {
				return nil
			}
			return fmt.Errorf("apply graph mutation record: node %q not found for property %q", sanitized.NodeID, sanitized.PropertyKey)
		}
	case GraphMutationRemoveNode:
		if !g.RemoveNode(sanitized.NodeID) {
			if _, ok := g.GetNodeIncludingDeleted(sanitized.NodeID); ok {
				return nil
			}
			return fmt.Errorf("apply graph mutation record: node %q not found for removal", sanitized.NodeID)
		}
	default:
		return fmt.Errorf("apply graph mutation record: unsupported type %q", sanitized.Type)
	}
	return nil
}

func applyReplayedAddEdge(g *Graph, edge *Edge) error {
	if g == nil || edge == nil {
		return fmt.Errorf("apply graph mutation record: edge is required")
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.addEdgeLocked(edge) {
		return fmt.Errorf("apply graph mutation record: edge %q rejected", edge.ID)
	}
	g.markGraphEdgeMutationLocked()
	return nil
}

func shouldSkipReplayedAddNode(existing, incoming *Node) bool {
	if existing == nil || incoming == nil {
		return false
	}
	if incoming.Version > 0 && existing.Version > 0 {
		if incoming.Version > existing.Version {
			return false
		}
		if incoming.Version < existing.Version {
			return true
		}
	}
	if !incoming.UpdatedAt.IsZero() && !existing.UpdatedAt.IsZero() {
		return !incoming.UpdatedAt.After(existing.UpdatedAt)
	}
	if incoming.Version > 0 && existing.Version == 0 {
		return false
	}
	if incoming.Version == 0 && existing.Version > 0 {
		return true
	}
	return true
}

func sanitizeGraphMutationRecord(record GraphMutationRecord) (GraphMutationRecord, error) {
	if record.Sequence == 0 {
		return GraphMutationRecord{}, fmt.Errorf("graph mutation record sequence required")
	}
	if version := strings.TrimSpace(record.Version); version == "" {
		record.Version = graphMutationRecordVersion
	} else if version != graphMutationRecordVersion {
		return GraphMutationRecord{}, fmt.Errorf("unsupported graph mutation record version %q", record.Version)
	}
	record.Type = GraphMutationType(strings.TrimSpace(string(record.Type)))
	switch record.Type {
	case GraphMutationAddNode:
		if record.Node == nil || strings.TrimSpace(record.Node.ID) == "" {
			return GraphMutationRecord{}, fmt.Errorf("graph mutation add_node requires node")
		}
		record.Node = normalizeGraphMutationNode(cloneNode(record.Node))
		record.Edge = nil
		record.NodeID = ""
		record.PropertyKey = ""
		record.PropertyValue = nil
	case GraphMutationAddEdge:
		if record.Edge == nil || strings.TrimSpace(record.Edge.Source) == "" || strings.TrimSpace(record.Edge.Target) == "" {
			return GraphMutationRecord{}, fmt.Errorf("graph mutation add_edge requires edge")
		}
		record.Edge = normalizeGraphMutationEdge(cloneEdge(record.Edge))
		record.Node = nil
		record.NodeID = ""
		record.PropertyKey = ""
		record.PropertyValue = nil
	case GraphMutationSetNodeProperty:
		record.NodeID = strings.TrimSpace(record.NodeID)
		record.PropertyKey = strings.TrimSpace(record.PropertyKey)
		if record.NodeID == "" || record.PropertyKey == "" {
			return GraphMutationRecord{}, fmt.Errorf("graph mutation set_node_property requires node_id and property_key")
		}
		record.Node = nil
		record.Edge = nil
		record.PropertyValue = normalizeGraphMutationValue(record.PropertyValue)
	case GraphMutationRemoveNode:
		record.NodeID = strings.TrimSpace(record.NodeID)
		if record.NodeID == "" {
			return GraphMutationRecord{}, fmt.Errorf("graph mutation remove_node requires node_id")
		}
		record.Node = nil
		record.Edge = nil
		record.PropertyKey = ""
		record.PropertyValue = nil
	default:
		return GraphMutationRecord{}, fmt.Errorf("unsupported graph mutation record type %q", record.Type)
	}
	return record, nil
}

func normalizeGraphMutationNode(node *Node) *Node {
	if node == nil {
		return nil
	}
	node.ordinal = InvalidNodeOrdinal
	node.propertyColumns = nil
	node.commonProps = nil
	node.observationProps = nil
	node.attackSequenceProps = nil
	node.Properties = normalizeGraphMutationMap(node.Properties)
	node.PreviousProperties = normalizeGraphMutationMap(node.PreviousProperties)
	if node.PropertyHistory != nil {
		history := make(map[string][]PropertySnapshot, len(node.PropertyHistory))
		for key, snapshots := range node.PropertyHistory {
			cloned := make([]PropertySnapshot, len(snapshots))
			for i, snapshot := range snapshots {
				cloned[i] = PropertySnapshot{
					Timestamp: snapshot.Timestamp,
					Value:     normalizeGraphMutationValue(snapshot.Value),
				}
			}
			history[key] = cloned
		}
		node.PropertyHistory = history
	}
	return node
}

func normalizeGraphMutationEdge(edge *Edge) *Edge {
	if edge == nil {
		return nil
	}
	edge.Properties = normalizeGraphMutationMap(edge.Properties)
	return edge
}

func normalizeGraphMutationMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	normalized := make(map[string]any, len(values))
	for key, value := range values {
		normalized[key] = normalizeGraphMutationValue(value)
	}
	return normalized
}

func normalizeGraphMutationValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return normalizeGraphMutationMap(typed)
	case []any:
		normalized := make([]any, len(typed))
		for i, item := range typed {
			normalized[i] = normalizeGraphMutationValue(item)
		}
		return normalized
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			maxInt := int64(^uint(0) >> 1)
			minInt := -maxInt - 1
			if parsed >= minInt && parsed <= maxInt {
				return int(parsed)
			}
			return parsed
		}
		if parsed, err := typed.Float64(); err == nil {
			return parsed
		}
		return typed.String()
	default:
		return value
	}
}
