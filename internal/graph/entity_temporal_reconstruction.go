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

// EntityTimelineEvent captures one property or lifecycle event across a time window.
type EntityTimelineEvent struct {
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	Key       string    `json:"key,omitempty"`
	Before    any       `json:"before,omitempty"`
	After     any       `json:"after,omitempty"`
}

// EntityTimelineRecord captures one entity timeline across a time window.
type EntityTimelineRecord struct {
	EntityID    string                `json:"entity_id"`
	From        time.Time             `json:"from"`
	To          time.Time             `json:"to"`
	RecordedAt  time.Time             `json:"recorded_at"`
	Before      EntityTimeRecord      `json:"before"`
	After       EntityTimeRecord      `json:"after"`
	ChangedKeys []string              `json:"changed_keys,omitempty"`
	Events      []EntityTimelineEvent `json:"events,omitempty"`
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

// GetEntityTimeline returns one entity timeline across the requested valid-time window.
func GetEntityTimeline(g *Graph, id string, from, to, recordedAt time.Time) (EntityTimelineRecord, bool) {
	before, beforeOK := GetEntityRecordAtTime(g, id, from, recordedAt)
	after, afterOK := GetEntityRecordAtTime(g, id, to, recordedAt)
	events, eventsOK := g.EntityTimeline(id, from, to)
	if !beforeOK && !afterOK && !eventsOK {
		return EntityTimelineRecord{}, false
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

	changedKeysSet := make(map[string]struct{}, len(events))
	for _, event := range events {
		if event.EventType != "property_changed" || event.Key == "" {
			continue
		}
		changedKeysSet[event.Key] = struct{}{}
	}
	changedKeys := make([]string, 0, len(changedKeysSet))
	for key := range changedKeysSet {
		changedKeys = append(changedKeys, key)
	}
	sort.Strings(changedKeys)

	return EntityTimelineRecord{
		EntityID:    id,
		From:        before.Reconstruction.AsOf,
		To:          after.Reconstruction.AsOf,
		RecordedAt:  recordedAt.UTC(),
		Before:      before,
		After:       after,
		ChangedKeys: changedKeys,
		Events:      events,
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
	reconstructed.Properties = reconstructNodePropertiesAt(node, asOf, recordedAt)
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

	validStart, validEnd := nodeTemporalBounds(node)
	recordedStart, recordedEnd := nodeRecordedBounds(node)
	if !temporalContains(validStart, validEnd, validAt) {
		return false
	}
	if node.DeletedAt != nil {
		return !recordedAt.Before(recordedStart.UTC())
	}
	return temporalContains(recordedStart, recordedEnd, recordedAt)
}

func reconstructNodePropertiesAt(node *Node, asOf, recordedAt time.Time) map[string]any {
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
		if value, ok := propertyValueAt(node, key, asOf, recordedAt); ok {
			properties[key] = cloneAny(value)
		}
	}
	return properties
}

// EntityTimeline returns one entity's property and lifecycle events across a valid-time window.
func (g *Graph) EntityTimeline(id string, from, to time.Time) ([]EntityTimelineEvent, bool) {
	if g == nil {
		return nil, false
	}
	if from.IsZero() {
		from = temporalNowUTC()
	}
	if to.IsZero() {
		to = temporalNowUTC()
	}
	from = from.UTC()
	to = to.UTC()
	if to.Before(from) {
		from, to = to, from
	}

	g.mu.RLock()
	node, ok := g.nodes[id]
	if !ok || node == nil || !entityQueryAllowedNodeKind(node.Kind) {
		g.mu.RUnlock()
		return nil, false
	}
	createdAt := node.CreatedAt.UTC()
	var deletedAt time.Time
	if node.DeletedAt != nil {
		deletedAt = node.DeletedAt.UTC()
	}
	history := clonePropertyHistoryMap(node.PropertyHistory)
	g.mu.RUnlock()

	events := make([]EntityTimelineEvent, 0)
	if !createdAt.IsZero() && !createdAt.Before(from) && !createdAt.After(to) {
		events = append(events, EntityTimelineEvent{
			Timestamp: createdAt,
			EventType: "entity_created",
		})
	}
	if !deletedAt.IsZero() && !deletedAt.Before(from) && !deletedAt.After(to) {
		events = append(events, EntityTimelineEvent{
			Timestamp: deletedAt,
			EventType: "entity_deleted",
		})
	}
	for key, snapshots := range history {
		if len(snapshots) == 0 {
			continue
		}
		copied := append([]PropertySnapshot(nil), snapshots...)
		sort.SliceStable(copied, func(i, j int) bool {
			return copied[i].Timestamp.Before(copied[j].Timestamp)
		})
		var previous any
		previousSet := false
		for _, snapshot := range copied {
			ts := snapshot.Timestamp.UTC()
			if !ts.Before(from) && !ts.After(to) {
				event := EntityTimelineEvent{
					Timestamp: ts,
					EventType: "property_changed",
					Key:       key,
					After:     cloneAny(snapshot.Value),
				}
				if previousSet {
					event.Before = cloneAny(previous)
				}
				if previousSet && reflect.DeepEqual(event.Before, event.After) {
					previous = snapshot.Value
					continue
				}
				events = append(events, event)
			}
			previous = snapshot.Value
			previousSet = true
		}
	}
	sort.SliceStable(events, func(i, j int) bool {
		if !events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].Timestamp.Before(events[j].Timestamp)
		}
		left := entityTimelineEventOrder(events[i].EventType)
		right := entityTimelineEventOrder(events[j].EventType)
		if left != right {
			return left < right
		}
		return events[i].Key < events[j].Key
	})
	return events, true
}

func entityTimelineEventOrder(eventType string) int {
	switch eventType {
	case "entity_created":
		return 0
	case "property_changed":
		return 1
	case "entity_deleted":
		return 2
	default:
		return 3
	}
}

func propertyValueAt(node *Node, key string, asOf, recordedAt time.Time) (any, bool) {
	if node == nil {
		return nil, false
	}
	if history := node.PropertyHistory[key]; len(history) > 0 {
		for i := len(history) - 1; i >= 0; i-- {
			snapshot := history[i]
			if snapshot.Timestamp.After(asOf) {
				continue
			}
			if !recordedAt.IsZero() && snapshot.Timestamp.After(recordedAt) {
				continue
			}
			if snapshot.Deleted {
				return nil, false
			}
			return snapshot.Value, true
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
