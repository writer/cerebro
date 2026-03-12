package graph

import (
	"reflect"
	"sort"
	"time"
)

// EntityTimeReconstruction describes what portion of an entity was reconstructed from temporal history.
type EntityTimeReconstruction struct {
	AsOf                    time.Time `json:"as_of"`
	RecordedAt              time.Time `json:"recorded_at"`
	PropertyHistoryApplied  bool      `json:"property_history_applied"`
	HistoricalCoreFields    bool      `json:"historical_core_fields"`
	ReconstructedProperties int       `json:"reconstructed_properties"`
}

// EntityTimeRecord is the point-in-time entity read model.
type EntityTimeRecord struct {
	Entity         EntityRecord             `json:"entity"`
	Reconstruction EntityTimeReconstruction `json:"reconstruction"`
}

// EntityPropertyDiff captures one property change between two reconstructed entity states.
type EntityPropertyDiff struct {
	Key    string `json:"key"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}

// EntityTimeDiffRecord captures one entity diff across two timestamps.
type EntityTimeDiffRecord struct {
	EntityID        string               `json:"entity_id"`
	From            time.Time            `json:"from"`
	To              time.Time            `json:"to"`
	RecordedAt      time.Time            `json:"recorded_at"`
	Before          EntityTimeRecord     `json:"before"`
	After           EntityTimeRecord     `json:"after"`
	ChangedKeys     []string             `json:"changed_keys,omitempty"`
	PropertyChanges []EntityPropertyDiff `json:"property_changes,omitempty"`
}

// GetEntityRecordAtTime reconstructs one entity at the requested valid-time slice.
func GetEntityRecordAtTime(g *Graph, id string, asOf, recordedAt time.Time) (EntityTimeRecord, bool) {
	if g == nil {
		return EntityTimeRecord{}, false
	}
	node, reconstruction, ok := g.EntityAtTime(id, asOf, recordedAt)
	if !ok {
		return EntityTimeRecord{}, false
	}
	record := buildEntityRecord(g, node, reconstruction.AsOf, reconstruction.RecordedAt, true)
	return EntityTimeRecord{
		Entity:         record,
		Reconstruction: reconstruction,
	}, true
}

// GetEntityTimeDiff compares one entity across two valid-time points.
func GetEntityTimeDiff(g *Graph, id string, from, to, recordedAt time.Time) (EntityTimeDiffRecord, bool) {
	before, beforeOK := GetEntityRecordAtTime(g, id, from, recordedAt)
	after, afterOK := GetEntityRecordAtTime(g, id, to, recordedAt)
	if !beforeOK && !afterOK {
		return EntityTimeDiffRecord{}, false
	}
	switch {
	case beforeOK:
		recordedAt = before.Reconstruction.RecordedAt
	case afterOK:
		recordedAt = after.Reconstruction.RecordedAt
	case recordedAt.IsZero():
		recordedAt = temporalNowUTC()
	default:
		recordedAt = recordedAt.UTC()
	}
	if !beforeOK {
		before = missingEntityTimeRecord(id, from, recordedAt)
	}
	if !afterOK {
		after = missingEntityTimeRecord(id, to, recordedAt)
	}
	changes := diffEntityProperties(before.Entity.Properties, after.Entity.Properties)
	changedKeys := entityCoreDiffKeys(before.Entity, after.Entity)
	for _, change := range changes {
		changedKeys = append(changedKeys, change.Key)
	}
	sort.Strings(changedKeys)
	return EntityTimeDiffRecord{
		EntityID:        id,
		From:            before.Reconstruction.AsOf,
		To:              after.Reconstruction.AsOf,
		RecordedAt:      before.Reconstruction.RecordedAt,
		Before:          before,
		After:           after,
		ChangedKeys:     changedKeys,
		PropertyChanges: changes,
	}, true
}

func missingEntityTimeRecord(id string, asOf, recordedAt time.Time) EntityTimeRecord {
	if asOf.IsZero() {
		asOf = temporalNowUTC()
	}
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}
	return EntityTimeRecord{
		Entity: EntityRecord{
			ID: id,
		},
		Reconstruction: EntityTimeReconstruction{
			AsOf:       asOf.UTC(),
			RecordedAt: recordedAt.UTC(),
		},
	}
}

func entityCoreDiffKeys(before, after EntityRecord) []string {
	keys := make(map[string]struct{}, 5)
	if before.Kind != after.Kind {
		keys["kind"] = struct{}{}
	}
	if before.Name != after.Name {
		keys["name"] = struct{}{}
	}
	if before.Provider != after.Provider {
		keys["provider"] = struct{}{}
	}
	if before.Account != after.Account {
		keys["account"] = struct{}{}
	}
	if before.Region != after.Region {
		keys["region"] = struct{}{}
	}
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	return out
}

// EntityAtTime reconstructs one node's property state at one valid-time slice.
func (g *Graph) EntityAtTime(id string, asOf, recordedAt time.Time) (*Node, EntityTimeReconstruction, bool) {
	if g == nil {
		return nil, EntityTimeReconstruction{}, false
	}
	if asOf.IsZero() {
		asOf = temporalNowUTC()
	}
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}
	asOf = asOf.UTC()
	recordedAt = recordedAt.UTC()

	g.mu.RLock()
	defer g.mu.RUnlock()

	node, ok := g.nodes[id]
	if !ok || node == nil || !entityQueryAllowedNodeKind(node.Kind) || !entityHistoricalVisibleAtLocked(node, asOf, recordedAt) {
		return nil, EntityTimeReconstruction{}, false
	}

	reconstructed := cloneNode(node)
	reconstructed.Properties = reconstructNodePropertiesAt(node, asOf)
	if len(reconstructed.Properties) == 0 {
		reconstructed.Properties = nil
	}
	return reconstructed, EntityTimeReconstruction{
		AsOf:                    asOf,
		RecordedAt:              recordedAt,
		PropertyHistoryApplied:  len(node.PropertyHistory) > 0,
		HistoricalCoreFields:    false,
		ReconstructedProperties: len(reconstructed.Properties),
	}, true
}

func entityHistoricalVisibleAtLocked(node *Node, validAt, recordedAt time.Time) bool {
	if node == nil {
		return false
	}
	if validAt.IsZero() {
		validAt = temporalNowUTC()
	}
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}
	validAt = validAt.UTC()
	recordedAt = recordedAt.UTC()

	validStart, validEnd := temporalBounds(node.Properties, node.CreatedAt, node.DeletedAt)
	recordedStart, _ := recordedBounds(node.Properties, node.CreatedAt, node.DeletedAt)
	return temporalContains(validStart, validEnd, validAt) && !recordedAt.Before(recordedStart.UTC())
}

func reconstructNodePropertiesAt(node *Node, asOf time.Time) map[string]any {
	if node == nil {
		return nil
	}
	keys := make(map[string]struct{}, len(node.Properties)+len(node.PropertyHistory))
	for key := range node.Properties {
		keys[key] = struct{}{}
	}
	for key := range node.PropertyHistory {
		keys[key] = struct{}{}
	}
	if len(keys) == 0 {
		return nil
	}

	properties := make(map[string]any, len(keys))
	for key := range keys {
		if value, ok := propertyValueAt(node, key, asOf); ok {
			properties[key] = cloneAny(value)
		}
	}
	return properties
}

func propertyValueAt(node *Node, key string, asOf time.Time) (any, bool) {
	if node == nil {
		return nil, false
	}
	if history := node.PropertyHistory[key]; len(history) > 0 {
		for i := len(history) - 1; i >= 0; i-- {
			if !history[i].Timestamp.After(asOf) {
				return history[i].Value, true
			}
		}
		return nil, false
	}
	value, ok := node.Properties[key]
	return value, ok
}

func diffEntityProperties(before, after map[string]any) []EntityPropertyDiff {
	keys := make(map[string]struct{}, len(before)+len(after))
	for key := range before {
		keys[key] = struct{}{}
	}
	for key := range after {
		keys[key] = struct{}{}
	}
	if len(keys) == 0 {
		return nil
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)

	out := make([]EntityPropertyDiff, 0, len(ordered))
	for _, key := range ordered {
		beforeValue, beforeOK := before[key]
		afterValue, afterOK := after[key]
		if beforeOK && afterOK && reflect.DeepEqual(beforeValue, afterValue) {
			continue
		}
		change := EntityPropertyDiff{Key: key}
		if beforeOK {
			change.Before = cloneAny(beforeValue)
		}
		if afterOK {
			change.After = cloneAny(afterValue)
		}
		out = append(out, change)
	}
	return out
}
