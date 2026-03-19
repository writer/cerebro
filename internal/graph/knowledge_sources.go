package graph

import (
	"strings"
	"time"
)

// KnowledgeSourceDerivedState captures graph-aware counts for one source node.
type KnowledgeSourceDerivedState struct {
	ClaimCount       int `json:"claim_count"`
	ArtifactCount    int `json:"artifact_count"`
	ObservationCount int `json:"observation_count"`
	EvidenceCount    int `json:"evidence_count"`
	SubjectCount     int `json:"subject_count"`
}

// KnowledgeSourceRecord is the typed read model for one source node.
type KnowledgeSourceRecord struct {
	ID               string                      `json:"id"`
	SourceType       string                      `json:"source_type,omitempty"`
	CanonicalName    string                      `json:"canonical_name,omitempty"`
	URL              string                      `json:"url,omitempty"`
	TrustTier        string                      `json:"trust_tier,omitempty"`
	ReliabilityScore float64                     `json:"reliability_score,omitempty"`
	SourceSystem     string                      `json:"source_system,omitempty"`
	SourceEventID    string                      `json:"source_event_id,omitempty"`
	ObservedAt       time.Time                   `json:"observed_at,omitempty"`
	ValidFrom        time.Time                   `json:"valid_from,omitempty"`
	ValidTo          *time.Time                  `json:"valid_to,omitempty"`
	RecordedAt       time.Time                   `json:"recorded_at,omitempty"`
	TransactionFrom  time.Time                   `json:"transaction_from,omitempty"`
	TransactionTo    *time.Time                  `json:"transaction_to,omitempty"`
	ClaimIDs         []string                    `json:"claim_ids,omitempty"`
	ArtifactIDs      []string                    `json:"artifact_ids,omitempty"`
	SubjectIDs       []string                    `json:"subject_ids,omitempty"`
	Derived          KnowledgeSourceDerivedState `json:"derived"`
	Metadata         map[string]any              `json:"metadata,omitempty"`
}

// GetSourceRecord returns one typed source record at a specific bitemporal slice.
func GetSourceRecord(g *Graph, sourceID string, validAt, recordedAt time.Time) (KnowledgeSourceRecord, bool) {
	sourceID = strings.TrimSpace(sourceID)
	if g == nil || sourceID == "" {
		return KnowledgeSourceRecord{}, false
	}
	node, ok := visibleNodeByIDAt(g, sourceID, validAt, recordedAt)
	if !ok || node.Kind != NodeKindSource {
		return KnowledgeSourceRecord{}, false
	}
	return buildKnowledgeSourceRecord(g, node, validAt, recordedAt), true
}

func buildKnowledgeSourceRecord(g *Graph, node *Node, validAt, recordedAt time.Time) KnowledgeSourceRecord {
	record := KnowledgeSourceRecord{
		ID:               node.ID,
		SourceType:       strings.ToLower(strings.TrimSpace(readString(node.Properties, "source_type"))),
		CanonicalName:    strings.TrimSpace(readString(node.Properties, "canonical_name")),
		URL:              strings.TrimSpace(readString(node.Properties, "url")),
		TrustTier:        strings.ToLower(strings.TrimSpace(readString(node.Properties, "trust_tier"))),
		ReliabilityScore: readFloat(node.Properties, "reliability_score"),
		SourceSystem:     firstNonEmpty(strings.TrimSpace(readString(node.Properties, "source_system")), strings.TrimSpace(node.Provider)),
		SourceEventID:    strings.TrimSpace(readString(node.Properties, "source_event_id")),
	}
	if ts, ok := graphObservedAt(node); ok {
		record.ObservedAt = ts
	}
	if ts, ok := temporalPropertyTime(node.Properties, "valid_from"); ok {
		record.ValidFrom = ts
	}
	if ts, ok := temporalPropertyTime(node.Properties, "valid_to"); ok {
		record.ValidTo = &ts
	}
	if ts, ok := temporalPropertyTime(node.Properties, "recorded_at"); ok {
		record.RecordedAt = ts
	}
	if ts, ok := temporalPropertyTime(node.Properties, "transaction_from"); ok {
		record.TransactionFrom = ts
	}
	if ts, ok := temporalPropertyTime(node.Properties, "transaction_to"); ok {
		record.TransactionTo = &ts
	}

	claimIDs := make([]string, 0, 4)
	artifactIDs := make([]string, 0, 4)
	subjectIDs := make([]string, 0, 4)
	observationCount := 0
	evidenceCount := 0
	for _, edge := range g.GetInEdgesBitemporal(node.ID, validAt, recordedAt) {
		if edge == nil || edge.Kind != EdgeKindAssertedBy {
			continue
		}
		upstream, ok := g.GetNode(edge.Source)
		if !ok || upstream == nil {
			continue
		}
		switch upstream.Kind {
		case NodeKindClaim:
			claimIDs = append(claimIDs, upstream.ID)
			subjectIDs = append(subjectIDs, strings.TrimSpace(readString(upstream.Properties, "subject_id")))
		case NodeKindObservation:
			artifactIDs = append(artifactIDs, upstream.ID)
			observationCount++
			if props, ok := upstream.ObservationProperties(); ok {
				subjectIDs = append(subjectIDs, strings.TrimSpace(props.SubjectID))
			} else {
				subjectIDs = append(subjectIDs, strings.TrimSpace(readString(upstream.Properties, "subject_id")))
			}
		case NodeKindEvidence:
			artifactIDs = append(artifactIDs, upstream.ID)
			evidenceCount++
		}
	}
	record.ClaimIDs = uniqueSortedStrings(trimNonEmpty(claimIDs))
	record.ArtifactIDs = uniqueSortedStrings(trimNonEmpty(artifactIDs))
	record.SubjectIDs = uniqueSortedStrings(trimNonEmpty(subjectIDs))
	record.Derived = KnowledgeSourceDerivedState{
		ClaimCount:       len(record.ClaimIDs),
		ArtifactCount:    len(record.ArtifactIDs),
		ObservationCount: observationCount,
		EvidenceCount:    evidenceCount,
		SubjectCount:     len(record.SubjectIDs),
	}
	record.Metadata = sourceMetadataProperties(node.Properties)
	return record
}

func sourceMetadataProperties(properties map[string]any) map[string]any {
	if len(properties) == 0 {
		return nil
	}
	out := cloneAnyMap(properties)
	for _, key := range []string{
		"source_type",
		"canonical_name",
		"url",
		"trust_tier",
		"reliability_score",
		"source_system",
		"source_event_id",
		"observed_at",
		"valid_from",
		"valid_to",
		"recorded_at",
		"transaction_from",
		"transaction_to",
	} {
		delete(out, key)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func visibleNodeByIDAt(g *Graph, nodeID string, validAt, recordedAt time.Time) (*Node, bool) {
	if g == nil || strings.TrimSpace(nodeID) == "" {
		return nil, false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	node, ok := g.nodes[nodeID]
	if !ok || !g.nodeVisibleAtLocked(node, validAt, recordedAt) {
		return nil, false
	}
	return node, true
}
