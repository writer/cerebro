package graph

import "time"

// Package-split compatibility exports for incremental domain extraction.

func TemporalNowUTC() time.Time {
	return temporalNowUTC()
}

func FirstNonEmpty(values ...string) string {
	return firstNonEmpty(values...)
}

func DefaultEntityFacetDefinitions() []EntityFacetDefinition {
	return append([]EntityFacetDefinition(nil), defaultEntityFacetDefinitions...)
}

func EntityFacetAppliesToNode(def EntityFacetDefinition, kind NodeKind) bool {
	return entityFacetAppliesToNode(def, kind)
}

func SortedSchemaKindCounts(values map[string]int) []SchemaKindCount {
	return sortedSchemaKindCounts(values)
}

func NormalizeNodeMetadataProfile(profile NodeMetadataProfile) NodeMetadataProfile {
	return normalizeNodeMetadataProfile(profile)
}

func HasNodeMetadataProfile(profile NodeMetadataProfile) bool {
	return hasNodeMetadataProfile(profile)
}

func MatchesPropertyType(value any, expectedType string) bool {
	return matchesPropertyType(value, expectedType)
}

func SliceContainsString(values []string, target string) bool {
	return sliceContainsString(values, target)
}

func BuildReportGraphSnapshotID(meta Metadata) string {
	return buildReportGraphSnapshotID(meta)
}

func WriteJSONAtomic(path string, payload any) error {
	return writeJSONAtomic(path, payload)
}

func SanitizeReportFileName(value string) string {
	return sanitizeReportFileName(value)
}

func (g *Graph) GetNodeBitemporal(nodeID string, validAt, recordedAt time.Time) (*Node, bool) {
	if g == nil {
		return nil, false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	node, ok := g.nodes[nodeID]
	if !ok || node == nil || node.DeletedAt != nil {
		return nil, false
	}
	if !g.nodeVisibleAtLocked(node, validAt, recordedAt) {
		return nil, false
	}
	return node, true
}
