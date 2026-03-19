package graph

import (
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultTemporalHistoryMaxEntries = 50
	DefaultTemporalHistoryTTL        = 30 * 24 * time.Hour
)

func sanitizeTemporalHistoryConfig(maxEntries int, ttl time.Duration) (int, time.Duration) {
	if maxEntries <= 0 {
		maxEntries = DefaultTemporalHistoryMaxEntries
	}
	if ttl <= 0 {
		ttl = DefaultTemporalHistoryTTL
	}
	return maxEntries, ttl
}

func (g *Graph) SetTemporalHistoryConfig(maxEntries int, ttl time.Duration) {
	if g == nil {
		return
	}
	maxEntries, ttl = sanitizeTemporalHistoryConfig(maxEntries, ttl)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.temporalHistoryMaxEntries = maxEntries
	g.temporalHistoryTTL = ttl
}

func (g *Graph) TemporalHistoryConfig() (int, time.Duration) {
	if g == nil {
		return sanitizeTemporalHistoryConfig(0, 0)
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return sanitizeTemporalHistoryConfig(g.temporalHistoryMaxEntries, g.temporalHistoryTTL)
}

func (g *Graph) temporalHistoryConfigLocked() (int, time.Duration) {
	if g == nil {
		return sanitizeTemporalHistoryConfig(0, 0)
	}
	return sanitizeTemporalHistoryConfig(g.temporalHistoryMaxEntries, g.temporalHistoryTTL)
}

func (g *Graph) trimTemporalHistoryLocked(history []PropertySnapshot, _ time.Time) []PropertySnapshot {
	if len(history) == 0 {
		return nil
	}
	maxEntries, ttl := g.temporalHistoryConfigLocked()

	if ttl > 0 {
		cutoff := temporalNowUTC().UTC().Add(-ttl)
		trimmed := history[:0]
		for _, snapshot := range history {
			if snapshot.Timestamp.Before(cutoff) {
				continue
			}
			trimmed = append(trimmed, snapshot)
		}
		history = trimmed
	}
	if len(history) > maxEntries {
		history = history[len(history)-maxEntries:]
	}
	if len(history) == 0 {
		return nil
	}
	return history
}

// GetNodePropertyHistory returns timestamped values for one node property.
// When window > 0, only snapshots within [now-window, now] are returned.
func (g *Graph) GetNodePropertyHistory(nodeID, property string, window time.Duration) []PropertySnapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()

	node, ok := g.nodes[nodeID]
	if !ok || node == nil {
		return nil
	}
	property = strings.TrimSpace(property)
	if property == "" {
		return nil
	}

	history := node.PropertyHistory[property]
	if len(history) == 0 {
		return nil
	}

	cutoff := time.Time{}
	if window > 0 {
		cutoff = temporalNowUTC().Add(-window)
	}
	out := make([]PropertySnapshot, 0, len(history))
	for _, snapshot := range history {
		if !cutoff.IsZero() && snapshot.Timestamp.Before(cutoff) {
			continue
		}
		out = append(out, PropertySnapshot{
			Timestamp: snapshot.Timestamp,
			Value:     cloneAny(snapshot.Value),
			Deleted:   snapshot.Deleted,
		})
	}
	return out
}

// TemporalDelta computes latest-earliest numeric value for a property over a window.
func (g *Graph) TemporalDelta(nodeID, property string, window time.Duration) (float64, bool) {
	history := g.GetNodePropertyHistory(nodeID, property, window)
	if len(history) < 2 {
		return 0, false
	}

	firstSet := false
	lastSet := false
	var first float64
	var last float64

	for _, snapshot := range history {
		value, ok := temporalFloat(snapshot.Value)
		if !ok {
			continue
		}
		if !firstSet {
			first = value
			firstSet = true
		}
		last = value
		lastSet = true
	}
	if !firstSet || !lastSet {
		return 0, false
	}
	return last - first, true
}

// TemporalTrend returns "increasing", "decreasing", or "stable" over the window.
func (g *Graph) TemporalTrend(nodeID, property string, window time.Duration) (string, bool) {
	delta, ok := g.TemporalDelta(nodeID, property, window)
	if !ok {
		return "", false
	}
	const epsilon = 0.001
	switch {
	case delta > epsilon:
		return "increasing", true
	case delta < -epsilon:
		return "decreasing", true
	default:
		return "stable", true
	}
}

// TemporalStreak counts consecutive snapshots (newest backwards) that satisfy
// one numeric condition in the given window.
func (g *Graph) TemporalStreak(nodeID, property, operator string, threshold float64, window time.Duration) (int, bool) {
	history := g.GetNodePropertyHistory(nodeID, property, window)
	if len(history) == 0 {
		return 0, false
	}

	operator = normalizeTemporalOperator(operator)
	if operator == "" {
		return 0, false
	}

	count := 0
	numericSeen := false
	for i := len(history) - 1; i >= 0; i-- {
		value, ok := temporalFloat(history[i].Value)
		if !ok {
			continue
		}
		numericSeen = true
		if !temporalCompare(value, operator, threshold) {
			break
		}
		count++
	}
	if !numericSeen {
		return 0, false
	}
	return count, true
}

// CompactTemporalHistory rollups old snapshots while preserving recent detail.
// Snapshots older than retention are bucketed by rollup duration, keeping only
// the most recent value in each bucket.
func (g *Graph) CompactTemporalHistory(retention, rollup time.Duration) {
	if retention <= 0 || rollup <= 0 {
		return
	}

	now := temporalNowUTC()
	cutoff := now.Add(-retention)

	g.mu.Lock()
	defer g.mu.Unlock()

	for _, node := range g.nodes {
		if node == nil || len(node.PropertyHistory) == 0 {
			continue
		}
		for property, snapshots := range node.PropertyHistory {
			if len(snapshots) == 0 {
				delete(node.PropertyHistory, property)
				continue
			}
			recent := make([]PropertySnapshot, 0, len(snapshots))
			rolled := make(map[time.Time]PropertySnapshot)
			for _, snapshot := range snapshots {
				if snapshot.Timestamp.Before(cutoff) {
					bucket := snapshot.Timestamp.Truncate(rollup)
					prev, ok := rolled[bucket]
					if !ok || snapshot.Timestamp.After(prev.Timestamp) {
						rolled[bucket] = snapshot
					}
					continue
				}
				recent = append(recent, snapshot)
			}

			combined := make([]PropertySnapshot, 0, len(recent)+len(rolled))
			if len(rolled) > 0 {
				buckets := make([]time.Time, 0, len(rolled))
				for bucket := range rolled {
					buckets = append(buckets, bucket)
				}
				sort.Slice(buckets, func(i, j int) bool { return buckets[i].Before(buckets[j]) })
				for _, bucket := range buckets {
					combined = append(combined, rolled[bucket])
				}
			}
			combined = append(combined, recent...)
			combined = g.trimTemporalHistoryLocked(combined, now)
			if len(combined) == 0 {
				delete(node.PropertyHistory, property)
			} else {
				node.PropertyHistory[property] = combined
			}
		}
	}
}

func temporalFloat(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case time.Time:
		return float64(typed.Unix()), true
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func normalizeTemporalOperator(operator string) string {
	operator = strings.TrimSpace(operator)
	switch operator {
	case ">", ">=", "<", "<=", "=", "==":
		return operator
	default:
		return ""
	}
}

func temporalCompare(value float64, operator string, threshold float64) bool {
	switch operator {
	case ">":
		return value > threshold
	case ">=":
		return value >= threshold
	case "<":
		return value < threshold
	case "<=":
		return value <= threshold
	case "=", "==":
		return value == threshold
	default:
		return false
	}
}

func (g *Graph) appendNodePropertyHistoryLocked(node *Node, property string, value any, at time.Time) {
	if node == nil {
		return
	}
	property = strings.TrimSpace(property)
	if property == "" {
		return
	}
	if at.IsZero() {
		at = temporalNowUTC()
	}
	at = at.UTC()

	if node.PropertyHistory == nil {
		node.PropertyHistory = make(map[string][]PropertySnapshot)
	}
	history := node.PropertyHistory[property]
	if len(history) > 0 {
		history = clonePropertySnapshotsShared(history)
		last := history[len(history)-1]
		if reflect.DeepEqual(last.Value, value) {
			if at.After(last.Timestamp) {
				history[len(history)-1].Timestamp = at
				history = g.trimTemporalHistoryLocked(history, at)
				if len(history) == 0 {
					delete(node.PropertyHistory, property)
				} else {
					node.PropertyHistory[property] = history
				}
			}
			return
		}
	}

	history = append(history, PropertySnapshot{Timestamp: at, Value: cloneAny(value)})
	history = g.trimTemporalHistoryLocked(history, at)
	if len(history) == 0 {
		delete(node.PropertyHistory, property)
		return
	}
	node.PropertyHistory[property] = history
}

func (g *Graph) appendNodePropertyTombstoneLocked(node *Node, property string, at time.Time) {
	if node == nil {
		return
	}
	property = strings.TrimSpace(property)
	if property == "" {
		return
	}
	if at.IsZero() {
		at = temporalNowUTC()
	}
	at = at.UTC()

	if node.PropertyHistory == nil {
		node.PropertyHistory = make(map[string][]PropertySnapshot)
	}
	history := node.PropertyHistory[property]
	if len(history) > 0 {
		history = clonePropertySnapshotsShared(history)
		last := history[len(history)-1]
		if last.Deleted {
			if at.After(last.Timestamp) {
				history[len(history)-1].Timestamp = at
				history = g.trimTemporalHistoryLocked(history, at)
				if len(history) == 0 {
					delete(node.PropertyHistory, property)
				} else {
					node.PropertyHistory[property] = history
				}
			}
			return
		}
	} else {
		history = make([]PropertySnapshot, 0, 1)
	}

	history = append(history, PropertySnapshot{Timestamp: at, Deleted: true})
	history = g.trimTemporalHistoryLocked(history, at)
	if len(history) == 0 {
		delete(node.PropertyHistory, property)
		return
	}
	node.PropertyHistory[property] = history
}

func (g *Graph) appendNodePropertiesHistoryLocked(node *Node, at time.Time) {
	if node == nil {
		return
	}
	for property, value := range node.PropertyMap() {
		g.appendNodePropertyHistoryLocked(node, property, value, at)
	}
}
