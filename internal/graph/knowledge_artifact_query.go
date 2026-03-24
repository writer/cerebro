package graph

import (
	"sort"
	"strings"
	"time"
)

const (
	defaultKnowledgeArtifactLimit = 100
	maxKnowledgeArtifactLimit     = 500
)

// KnowledgeArtifactQueryOptions tunes typed evidence/observation reads.
type KnowledgeArtifactQueryOptions struct {
	ID         string    `json:"id,omitempty"`
	TargetID   string    `json:"target_id,omitempty"`
	ClaimID    string    `json:"claim_id,omitempty"`
	SourceID   string    `json:"source_id,omitempty"`
	Type       string    `json:"type,omitempty"`
	ValidAt    time.Time `json:"valid_at,omitempty"`
	RecordedAt time.Time `json:"recorded_at,omitempty"`
	Limit      int       `json:"limit,omitempty"`
	Offset     int       `json:"offset,omitempty"`
}

// KnowledgeArtifactQueryFilters echoes the applied artifact filters.
type KnowledgeArtifactQueryFilters struct {
	ID       string `json:"id,omitempty"`
	TargetID string `json:"target_id,omitempty"`
	ClaimID  string `json:"claim_id,omitempty"`
	SourceID string `json:"source_id,omitempty"`
	Type     string `json:"type,omitempty"`
}

// KnowledgeArtifactLinks captures graph links attached to one evidence/observation node.
type KnowledgeArtifactLinks struct {
	TargetIDs       []string `json:"target_ids,omitempty"`
	ClaimIDs        []string `json:"claim_ids,omitempty"`
	ReferencedByIDs []string `json:"referenced_by_ids,omitempty"`
	SourceIDs       []string `json:"source_ids,omitempty"`
}

// KnowledgeArtifactDerivedState captures graph-aware counts for one artifact.
type KnowledgeArtifactDerivedState struct {
	TargetCount       int `json:"target_count"`
	ClaimCount        int `json:"claim_count"`
	ReferencedByCount int `json:"referenced_by_count"`
	SourceCount       int `json:"source_count"`
}

// KnowledgeArtifactRecord is the canonical typed read model for evidence and observations.
type KnowledgeArtifactRecord struct {
	ID              string                        `json:"id"`
	Kind            NodeKind                      `json:"kind"`
	ArtifactType    string                        `json:"artifact_type,omitempty"`
	SubjectID       string                        `json:"subject_id,omitempty"`
	Detail          string                        `json:"detail,omitempty"`
	SourceSystem    string                        `json:"source_system,omitempty"`
	SourceEventID   string                        `json:"source_event_id,omitempty"`
	ObservedAt      time.Time                     `json:"observed_at,omitempty"`
	ValidFrom       time.Time                     `json:"valid_from,omitempty"`
	ValidTo         *time.Time                    `json:"valid_to,omitempty"`
	RecordedAt      time.Time                     `json:"recorded_at,omitempty"`
	TransactionFrom time.Time                     `json:"transaction_from,omitempty"`
	TransactionTo   *time.Time                    `json:"transaction_to,omitempty"`
	Confidence      float64                       `json:"confidence,omitempty"`
	Links           KnowledgeArtifactLinks        `json:"links"`
	Derived         KnowledgeArtifactDerivedState `json:"derived"`
	Metadata        map[string]any                `json:"metadata,omitempty"`
}

// KnowledgeArtifactCollectionSummary captures high-level quality indicators for artifact reads.
type KnowledgeArtifactCollectionSummary struct {
	MatchedArtifacts      int `json:"matched_artifacts"`
	TargetedArtifacts     int `json:"targeted_artifacts"`
	ClaimLinkedArtifacts  int `json:"claim_linked_artifacts"`
	SourceBackedArtifacts int `json:"source_backed_artifacts"`
}

// KnowledgeArtifactCollection is the typed response for evidence/observation reads.
type KnowledgeArtifactCollection struct {
	GeneratedAt time.Time                          `json:"generated_at"`
	Kind        NodeKind                           `json:"kind"`
	ValidAt     time.Time                          `json:"valid_at"`
	RecordedAt  time.Time                          `json:"recorded_at"`
	Filters     KnowledgeArtifactQueryFilters      `json:"filters"`
	Summary     KnowledgeArtifactCollectionSummary `json:"summary"`
	Artifacts   []KnowledgeArtifactRecord          `json:"artifacts,omitempty"`
	Count       int                                `json:"count"`
	Pagination  ClaimCollectionPagination          `json:"pagination"`
}

// QueryEvidence returns typed evidence records at a bitemporal slice.
func QueryEvidence(g *Graph, opts KnowledgeArtifactQueryOptions) KnowledgeArtifactCollection {
	return queryKnowledgeArtifacts(g, NodeKindEvidence, opts)
}

// GetEvidenceRecord returns one typed evidence record at a bitemporal slice.
func GetEvidenceRecord(g *Graph, evidenceID string, validAt, recordedAt time.Time) (KnowledgeArtifactRecord, bool) {
	return getKnowledgeArtifactRecord(g, NodeKindEvidence, evidenceID, validAt, recordedAt)
}

// QueryObservations returns typed observation records at a bitemporal slice.
func QueryObservations(g *Graph, opts KnowledgeArtifactQueryOptions) KnowledgeArtifactCollection {
	return queryKnowledgeArtifacts(g, NodeKindObservation, opts)
}

// GetObservationRecord returns one typed observation record at a bitemporal slice.
func GetObservationRecord(g *Graph, observationID string, validAt, recordedAt time.Time) (KnowledgeArtifactRecord, bool) {
	return getKnowledgeArtifactRecord(g, NodeKindObservation, observationID, validAt, recordedAt)
}

func queryKnowledgeArtifacts(g *Graph, kind NodeKind, opts KnowledgeArtifactQueryOptions) KnowledgeArtifactCollection {
	query := normalizeKnowledgeArtifactQueryOptions(opts)
	result := KnowledgeArtifactCollection{
		GeneratedAt: temporalNowUTC(),
		Kind:        kind,
		ValidAt:     query.ValidAt,
		RecordedAt:  query.RecordedAt,
		Filters: KnowledgeArtifactQueryFilters{
			ID:       query.ID,
			TargetID: query.TargetID,
			ClaimID:  query.ClaimID,
			SourceID: query.SourceID,
			Type:     query.Type,
		},
		Pagination: ClaimCollectionPagination{
			Limit:  query.Limit,
			Offset: query.Offset,
		},
	}
	if g == nil {
		return result
	}

	records := make([]KnowledgeArtifactRecord, 0)
	for _, node := range g.GetAllNodesBitemporal(query.ValidAt, query.RecordedAt) {
		if node == nil || node.Kind != kind {
			continue
		}
		record := buildKnowledgeArtifactRecord(g, node, query.ValidAt, query.RecordedAt)
		if !knowledgeArtifactMatchesQuery(record, query) {
			continue
		}
		records = append(records, record)
		updateKnowledgeArtifactCollectionSummary(&result.Summary, record)
	}

	sort.Slice(records, func(i, j int) bool {
		if !records[i].RecordedAt.Equal(records[j].RecordedAt) {
			return records[i].RecordedAt.After(records[j].RecordedAt)
		}
		if !records[i].ObservedAt.Equal(records[j].ObservedAt) {
			return records[i].ObservedAt.After(records[j].ObservedAt)
		}
		return records[i].ID < records[j].ID
	})

	total := len(records)
	result.Pagination.Total = total
	if query.Offset > total {
		query.Offset = total
		result.Pagination.Offset = total
	}
	end := query.Offset + query.Limit
	if end > total {
		end = total
	}
	if query.Offset < end {
		result.Artifacts = append(result.Artifacts, records[query.Offset:end]...)
	}
	result.Count = len(result.Artifacts)
	result.Pagination.HasMore = end < total
	return result
}

func getKnowledgeArtifactRecord(g *Graph, kind NodeKind, id string, validAt, recordedAt time.Time) (KnowledgeArtifactRecord, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return KnowledgeArtifactRecord{}, false
	}
	result := queryKnowledgeArtifacts(g, kind, KnowledgeArtifactQueryOptions{
		ID:         id,
		ValidAt:    validAt,
		RecordedAt: recordedAt,
		Limit:      1,
	})
	if len(result.Artifacts) == 0 {
		return KnowledgeArtifactRecord{}, false
	}
	return result.Artifacts[0], true
}

func normalizeKnowledgeArtifactQueryOptions(opts KnowledgeArtifactQueryOptions) KnowledgeArtifactQueryOptions {
	if opts.ValidAt.IsZero() {
		opts.ValidAt = temporalNowUTC()
	} else {
		opts.ValidAt = opts.ValidAt.UTC()
	}
	if opts.RecordedAt.IsZero() {
		opts.RecordedAt = temporalNowUTC()
	} else {
		opts.RecordedAt = opts.RecordedAt.UTC()
	}
	opts.ID = strings.TrimSpace(opts.ID)
	opts.TargetID = strings.TrimSpace(opts.TargetID)
	opts.ClaimID = strings.TrimSpace(opts.ClaimID)
	opts.SourceID = strings.TrimSpace(opts.SourceID)
	opts.Type = strings.ToLower(strings.TrimSpace(opts.Type))
	if opts.Limit <= 0 {
		opts.Limit = defaultKnowledgeArtifactLimit
	}
	if opts.Limit > maxKnowledgeArtifactLimit {
		opts.Limit = maxKnowledgeArtifactLimit
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}
	return opts
}

func buildKnowledgeArtifactRecord(g *Graph, node *Node, validAt, recordedAt time.Time) KnowledgeArtifactRecord {
	record := KnowledgeArtifactRecord{
		ID:            node.ID,
		Kind:          node.Kind,
		SubjectID:     strings.TrimSpace(readString(node.Properties, "subject_id")),
		Detail:        strings.TrimSpace(readString(node.Properties, "detail")),
		SourceSystem:  firstNonEmpty(nodePropertyString(node, "source_system"), strings.TrimSpace(node.Provider)),
		SourceEventID: nodePropertyString(node, "source_event_id"),
		Confidence:    nodePropertyFloat(node, "confidence"),
	}
	switch node.Kind {
	case NodeKindObservation:
		if props, ok := node.ObservationProperties(); ok {
			record.SubjectID = strings.TrimSpace(props.SubjectID)
			record.Detail = strings.TrimSpace(props.Detail)
			record.SourceSystem = firstNonEmpty(strings.TrimSpace(props.SourceSystem), strings.TrimSpace(node.Provider))
			record.SourceEventID = strings.TrimSpace(props.SourceEventID)
			record.Confidence = props.Confidence
			record.ArtifactType = strings.ToLower(strings.TrimSpace(props.ObservationType))
			if !props.ValidFrom.IsZero() {
				record.ValidFrom = props.ValidFrom
			}
			if props.ValidTo != nil && !props.ValidTo.IsZero() {
				validTo := props.ValidTo.UTC()
				record.ValidTo = &validTo
			}
			if !props.RecordedAt.IsZero() {
				record.RecordedAt = props.RecordedAt
			}
			if !props.TransactionFrom.IsZero() {
				record.TransactionFrom = props.TransactionFrom
			}
			if props.TransactionTo != nil && !props.TransactionTo.IsZero() {
				transactionTo := props.TransactionTo.UTC()
				record.TransactionTo = &transactionTo
			}
		} else {
			record.ArtifactType = strings.ToLower(strings.TrimSpace(readString(node.Properties, "observation_type")))
		}
	default:
		record.ArtifactType = strings.ToLower(strings.TrimSpace(readString(node.Properties, "evidence_type")))
	}
	if ts, ok := graphObservedAt(node); ok {
		record.ObservedAt = ts
	}
	if record.ValidFrom.IsZero() {
		if ts, ok := nodePropertyTime(node, "valid_from"); ok {
			record.ValidFrom = ts
		}
	}
	if record.ValidTo == nil {
		if ts, ok := nodePropertyTime(node, "valid_to"); ok {
			record.ValidTo = &ts
		}
	}
	if record.RecordedAt.IsZero() {
		if ts, ok := nodePropertyTime(node, "recorded_at"); ok {
			record.RecordedAt = ts
		}
	}
	if record.TransactionFrom.IsZero() {
		if ts, ok := nodePropertyTime(node, "transaction_from"); ok {
			record.TransactionFrom = ts
		}
	}
	if record.TransactionTo == nil {
		if ts, ok := nodePropertyTime(node, "transaction_to"); ok {
			record.TransactionTo = &ts
		}
	}

	record.Links = KnowledgeArtifactLinks{
		TargetIDs:       claimLinkTargetsAt(g, node.ID, EdgeKindTargets, validAt, recordedAt),
		SourceIDs:       claimLinkTargetsAt(g, node.ID, EdgeKindAssertedBy, validAt, recordedAt),
		ReferencedByIDs: artifactReferencedByIDsAt(g, node.ID, validAt, recordedAt),
		ClaimIDs:        artifactClaimIDsAt(g, node.ID, validAt, recordedAt),
	}
	record.Derived = KnowledgeArtifactDerivedState{
		TargetCount:       len(record.Links.TargetIDs),
		ClaimCount:        len(record.Links.ClaimIDs),
		ReferencedByCount: len(record.Links.ReferencedByIDs),
		SourceCount:       len(record.Links.SourceIDs),
	}
	record.Metadata = knowledgeArtifactMetadata(node.Kind, node.Properties)
	return record
}

func artifactReferencedByIDsAt(g *Graph, nodeID string, validAt, recordedAt time.Time) []string {
	if g == nil || strings.TrimSpace(nodeID) == "" {
		return nil
	}
	out := make([]string, 0, 2)
	for _, edge := range g.GetInEdgesBitemporal(nodeID, validAt, recordedAt) {
		if edge == nil || edge.Kind != EdgeKindBasedOn {
			continue
		}
		out = append(out, edge.Source)
	}
	return uniqueSortedStrings(trimNonEmpty(out))
}

func artifactClaimIDsAt(g *Graph, nodeID string, validAt, recordedAt time.Time) []string {
	if g == nil || strings.TrimSpace(nodeID) == "" {
		return nil
	}
	out := make([]string, 0, 2)
	for _, edge := range g.GetInEdgesBitemporal(nodeID, validAt, recordedAt) {
		if edge == nil || edge.Kind != EdgeKindBasedOn {
			continue
		}
		sourceNode, ok := g.GetNode(edge.Source)
		if !ok || sourceNode == nil || sourceNode.Kind != NodeKindClaim {
			continue
		}
		out = append(out, edge.Source)
	}
	return uniqueSortedStrings(trimNonEmpty(out))
}

func knowledgeArtifactMatchesQuery(record KnowledgeArtifactRecord, opts KnowledgeArtifactQueryOptions) bool {
	if opts.ID != "" && record.ID != opts.ID {
		return false
	}
	if opts.TargetID != "" && !containsExactString(record.Links.TargetIDs, opts.TargetID) {
		return false
	}
	if opts.ClaimID != "" && !containsExactString(record.Links.ClaimIDs, opts.ClaimID) {
		return false
	}
	if opts.SourceID != "" && !containsExactString(record.Links.SourceIDs, opts.SourceID) {
		return false
	}
	if opts.Type != "" && !strings.EqualFold(record.ArtifactType, opts.Type) {
		return false
	}
	return true
}

func updateKnowledgeArtifactCollectionSummary(summary *KnowledgeArtifactCollectionSummary, record KnowledgeArtifactRecord) {
	if summary == nil {
		return
	}
	summary.MatchedArtifacts++
	if record.Derived.TargetCount > 0 {
		summary.TargetedArtifacts++
	}
	if record.Derived.ClaimCount > 0 {
		summary.ClaimLinkedArtifacts++
	}
	if record.Derived.SourceCount > 0 {
		summary.SourceBackedArtifacts++
	}
}

func knowledgeArtifactMetadata(kind NodeKind, properties map[string]any) map[string]any {
	if len(properties) == 0 {
		return nil
	}
	out := cloneAnyMap(properties)
	for _, key := range []string{
		"evidence_type",
		"observation_type",
		"subject_id",
		"detail",
		"source_system",
		"source_event_id",
		"observed_at",
		"valid_from",
		"valid_to",
		"recorded_at",
		"transaction_from",
		"transaction_to",
		"confidence",
	} {
		delete(out, key)
	}
	if kind == NodeKindEvidence {
		delete(out, "subject_id")
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
