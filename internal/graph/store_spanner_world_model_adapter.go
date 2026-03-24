package graph

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type SpannerWorldModelEntityRelationshipRecord struct {
	RelationshipID   string
	SourceEntityID   string
	TargetEntityID   string
	RelationshipKind EdgeKind
	Effect           EdgeEffect
	Priority         int
	Properties       map[string]any
	CreatedAt        time.Time
	DeletedAt        *time.Time
	Version          int
	spannerWorldModelTemporalColumns
}

func SpannerWorldModelEntityRelationshipRecordFromEdge(edge *Edge) (SpannerWorldModelEntityRelationshipRecord, error) {
	if edge == nil || strings.TrimSpace(edge.ID) == "" || strings.TrimSpace(edge.Source) == "" || strings.TrimSpace(edge.Target) == "" {
		return SpannerWorldModelEntityRelationshipRecord{}, fmt.Errorf("entity relationship edge is required")
	}
	temporal := spannerWorldModelTemporalFromEdge(edge)
	return SpannerWorldModelEntityRelationshipRecord{
		RelationshipID:                   strings.TrimSpace(edge.ID),
		SourceEntityID:                   strings.TrimSpace(edge.Source),
		TargetEntityID:                   strings.TrimSpace(edge.Target),
		RelationshipKind:                 edge.Kind,
		Effect:                           edge.Effect,
		Priority:                         edge.Priority,
		Properties:                       cloneAnyMap(edge.Properties),
		CreatedAt:                        spannerWorldModelTimestamp(edge.CreatedAt, temporal.ObservedAt),
		DeletedAt:                        spannerWorldModelOptionalTimestamp(edge.DeletedAt),
		Version:                          spannerWorldModelVersion(edge.Version),
		spannerWorldModelTemporalColumns: temporal,
	}, nil
}

func (r SpannerWorldModelEntityRelationshipRecord) ToEdge() *Edge {
	properties := cloneAnyMap(r.Properties)
	if properties == nil {
		properties = make(map[string]any)
	}
	r.writeMetadata().ApplyTo(properties)
	return &Edge{
		ID:         r.RelationshipID,
		Source:     r.SourceEntityID,
		Target:     r.TargetEntityID,
		Kind:       r.RelationshipKind,
		Effect:     r.Effect,
		Priority:   r.Priority,
		Properties: properties,
		CreatedAt:  spannerWorldModelTimestamp(r.CreatedAt, r.ObservedAt),
		DeletedAt:  spannerWorldModelOptionalTimestamp(r.DeletedAt),
		Version:    spannerWorldModelVersion(r.Version),
	}
}

type SpannerWorldModelEvidenceTargetRecord struct {
	EdgeID         string
	EvidenceID     string
	TargetEntityID string
	Properties     map[string]any
	spannerWorldModelTemporalColumns
}

func SpannerWorldModelEvidenceTargetRecordFromEdge(edge *Edge) (SpannerWorldModelEvidenceTargetRecord, error) {
	record, err := spannerWorldModelLinkEdgeRecordFromEdge(edge, EdgeKindTargets, "evidence")
	if err != nil {
		return SpannerWorldModelEvidenceTargetRecord{}, err
	}
	return SpannerWorldModelEvidenceTargetRecord{
		EdgeID:                           record.EdgeID,
		EvidenceID:                       record.SourceID,
		TargetEntityID:                   record.TargetID,
		Properties:                       record.Properties,
		spannerWorldModelTemporalColumns: record.spannerWorldModelTemporalColumns,
	}, nil
}

func (r SpannerWorldModelEvidenceTargetRecord) ToEdge() *Edge {
	return spannerWorldModelLinkRecordToEdge(r.EdgeID, r.EvidenceID, r.TargetEntityID, EdgeKindTargets, r.Properties, r.spannerWorldModelTemporalColumns)
}

type SpannerWorldModelObservationTargetRecord struct {
	EdgeID         string
	ObservationID  string
	TargetEntityID string
	Properties     map[string]any
	spannerWorldModelTemporalColumns
}

func SpannerWorldModelObservationTargetRecordFromEdge(edge *Edge) (SpannerWorldModelObservationTargetRecord, error) {
	record, err := spannerWorldModelLinkEdgeRecordFromEdge(edge, EdgeKindTargets, "observation")
	if err != nil {
		return SpannerWorldModelObservationTargetRecord{}, err
	}
	return SpannerWorldModelObservationTargetRecord{
		EdgeID:                           record.EdgeID,
		ObservationID:                    record.SourceID,
		TargetEntityID:                   record.TargetID,
		Properties:                       record.Properties,
		spannerWorldModelTemporalColumns: record.spannerWorldModelTemporalColumns,
	}, nil
}

func (r SpannerWorldModelObservationTargetRecord) ToEdge() *Edge {
	return spannerWorldModelLinkRecordToEdge(r.EdgeID, r.ObservationID, r.TargetEntityID, EdgeKindTargets, r.Properties, r.spannerWorldModelTemporalColumns)
}

type SpannerWorldModelClaimSourceRecord struct {
	EdgeID     string
	ClaimID    string
	SourceID   string
	Properties map[string]any
	spannerWorldModelTemporalColumns
}

func SpannerWorldModelClaimSourceRecordFromEdge(edge *Edge) (SpannerWorldModelClaimSourceRecord, error) {
	record, err := spannerWorldModelLinkEdgeRecordFromEdge(edge, EdgeKindAssertedBy, "claim source")
	if err != nil {
		return SpannerWorldModelClaimSourceRecord{}, err
	}
	return SpannerWorldModelClaimSourceRecord{
		EdgeID:                           record.EdgeID,
		ClaimID:                          record.SourceID,
		SourceID:                         record.TargetID,
		Properties:                       record.Properties,
		spannerWorldModelTemporalColumns: record.spannerWorldModelTemporalColumns,
	}, nil
}

func (r SpannerWorldModelClaimSourceRecord) ToEdge() *Edge {
	return spannerWorldModelLinkRecordToEdge(r.EdgeID, r.ClaimID, r.SourceID, EdgeKindAssertedBy, r.Properties, r.spannerWorldModelTemporalColumns)
}

type SpannerWorldModelClaimEvidenceRecord struct {
	EdgeID     string
	ClaimID    string
	EvidenceID string
	Properties map[string]any
	spannerWorldModelTemporalColumns
}

func SpannerWorldModelClaimEvidenceRecordFromEdge(edge *Edge) (SpannerWorldModelClaimEvidenceRecord, error) {
	record, err := spannerWorldModelLinkEdgeRecordFromEdge(edge, EdgeKindBasedOn, "claim evidence")
	if err != nil {
		return SpannerWorldModelClaimEvidenceRecord{}, err
	}
	return SpannerWorldModelClaimEvidenceRecord{
		EdgeID:                           record.EdgeID,
		ClaimID:                          record.SourceID,
		EvidenceID:                       record.TargetID,
		Properties:                       record.Properties,
		spannerWorldModelTemporalColumns: record.spannerWorldModelTemporalColumns,
	}, nil
}

func (r SpannerWorldModelClaimEvidenceRecord) ToEdge() *Edge {
	return spannerWorldModelLinkRecordToEdge(r.EdgeID, r.ClaimID, r.EvidenceID, EdgeKindBasedOn, r.Properties, r.spannerWorldModelTemporalColumns)
}

type SpannerWorldModelClaimRelationshipRecord struct {
	EdgeID           string
	ClaimID          string
	RelatedClaimID   string
	RelationshipKind EdgeKind
	Properties       map[string]any
	spannerWorldModelTemporalColumns
}

func SpannerWorldModelClaimRelationshipRecordFromEdge(edge *Edge) (SpannerWorldModelClaimRelationshipRecord, error) {
	record, err := spannerWorldModelLinkEdgeRecordFromEdge(edge, "", "claim relationship")
	if err != nil {
		return SpannerWorldModelClaimRelationshipRecord{}, err
	}
	return SpannerWorldModelClaimRelationshipRecord{
		EdgeID:                           record.EdgeID,
		ClaimID:                          record.SourceID,
		RelatedClaimID:                   record.TargetID,
		RelationshipKind:                 edge.Kind,
		Properties:                       record.Properties,
		spannerWorldModelTemporalColumns: record.spannerWorldModelTemporalColumns,
	}, nil
}

func (r SpannerWorldModelClaimRelationshipRecord) ToEdge() *Edge {
	return spannerWorldModelLinkRecordToEdge(r.EdgeID, r.ClaimID, r.RelatedClaimID, r.RelationshipKind, r.Properties, r.spannerWorldModelTemporalColumns)
}

type spannerWorldModelLinkEdgeRecord struct {
	EdgeID     string
	SourceID   string
	TargetID   string
	Properties map[string]any
	spannerWorldModelTemporalColumns
}

func spannerWorldModelLinkEdgeRecordFromEdge(edge *Edge, wantKind EdgeKind, family string) (spannerWorldModelLinkEdgeRecord, error) {
	if edge == nil || strings.TrimSpace(edge.ID) == "" || strings.TrimSpace(edge.Source) == "" || strings.TrimSpace(edge.Target) == "" {
		return spannerWorldModelLinkEdgeRecord{}, fmt.Errorf("%s edge is required", family)
	}
	if wantKind != "" && edge.Kind != wantKind {
		return spannerWorldModelLinkEdgeRecord{}, fmt.Errorf("%s edge kind %q does not match %q", family, edge.Kind, wantKind)
	}
	return spannerWorldModelLinkEdgeRecord{
		EdgeID:                           strings.TrimSpace(edge.ID),
		SourceID:                         strings.TrimSpace(edge.Source),
		TargetID:                         strings.TrimSpace(edge.Target),
		Properties:                       cloneAnyMap(edge.Properties),
		spannerWorldModelTemporalColumns: spannerWorldModelTemporalFromEdge(edge),
	}, nil
}

func spannerWorldModelLinkRecordToEdge(id, source, target string, kind EdgeKind, properties map[string]any, temporal spannerWorldModelTemporalColumns) *Edge {
	props := cloneAnyMap(properties)
	if props == nil {
		props = make(map[string]any)
	}
	temporal.writeMetadata().ApplyTo(props)
	return &Edge{
		ID:         id,
		Source:     source,
		Target:     target,
		Kind:       kind,
		Effect:     EdgeEffectAllow,
		Properties: props,
		CreatedAt:  spannerWorldModelTimestamp(temporal.ObservedAt),
		Version:    1,
	}
}

func spannerWorldModelTemporalFromEdge(edge *Edge) spannerWorldModelTemporalColumns {
	now := spannerWorldModelTimestamp(edge.CreatedAt)
	if now.IsZero() {
		now = temporalNowUTC()
	}
	observedAt, ok := temporalPropertyTime(edge.Properties, "observed_at")
	if !ok || observedAt.IsZero() {
		observedAt = spannerWorldModelTimestamp(edge.CreatedAt, now)
	}
	validFrom, ok := temporalPropertyTime(edge.Properties, "valid_from")
	if !ok || validFrom.IsZero() {
		validFrom = observedAt
	}
	recordedAt, ok := temporalPropertyTime(edge.Properties, "recorded_at")
	if !ok || recordedAt.IsZero() {
		recordedAt = observedAt
	}
	transactionFrom, ok := temporalPropertyTime(edge.Properties, "transaction_from")
	if !ok || transactionFrom.IsZero() {
		transactionFrom = recordedAt
	}
	validTo, _ := temporalPropertyTime(edge.Properties, "valid_to")
	transactionTo, _ := temporalPropertyTime(edge.Properties, "transaction_to")
	columns := spannerWorldModelTemporalColumns{
		ObservedAt:      observedAt.UTC(),
		ValidFrom:       validFrom.UTC(),
		RecordedAt:      recordedAt.UTC(),
		TransactionFrom: transactionFrom.UTC(),
		SourceSystem:    firstNonEmpty(readString(edge.Properties, "source_system"), "unknown"),
		SourceEventID:   firstNonEmpty(readString(edge.Properties, "source_event_id"), fmt.Sprintf("graph-edge:%s:%d", strings.TrimSpace(edge.ID), recordedAt.UnixNano())),
		Confidence:      readFloat(edge.Properties, "confidence"),
	}
	if !validTo.IsZero() {
		columns.ValidTo = spannerWorldModelTimePtr(validTo.UTC())
	}
	if !transactionTo.IsZero() {
		columns.TransactionTo = spannerWorldModelTimePtr(transactionTo.UTC())
	}
	metadata := columns.writeMetadata()
	return spannerWorldModelTemporalColumns(metadata)
}

type SpannerWorldModelCanonicalAdapter struct {
	mu sync.RWMutex

	entities            map[string]SpannerWorldModelEntityRecord
	sources             map[string]SpannerWorldModelSourceRecord
	claims              map[string]SpannerWorldModelClaimRecord
	evidence            map[string]SpannerWorldModelEvidenceRecord
	observations        map[string]SpannerWorldModelObservationRecord
	entityRelationships map[string]SpannerWorldModelEntityRelationshipRecord
	evidenceTargets     map[string]SpannerWorldModelEvidenceTargetRecord
	observationTargets  map[string]SpannerWorldModelObservationTargetRecord
	claimSources        map[string]SpannerWorldModelClaimSourceRecord
	claimEvidence       map[string]SpannerWorldModelClaimEvidenceRecord
	claimRelationships  map[string]SpannerWorldModelClaimRelationshipRecord
}

func NewMemorySpannerWorldModelCanonicalAdapter() *SpannerWorldModelCanonicalAdapter {
	return &SpannerWorldModelCanonicalAdapter{
		entities:            make(map[string]SpannerWorldModelEntityRecord),
		sources:             make(map[string]SpannerWorldModelSourceRecord),
		claims:              make(map[string]SpannerWorldModelClaimRecord),
		evidence:            make(map[string]SpannerWorldModelEvidenceRecord),
		observations:        make(map[string]SpannerWorldModelObservationRecord),
		entityRelationships: make(map[string]SpannerWorldModelEntityRelationshipRecord),
		evidenceTargets:     make(map[string]SpannerWorldModelEvidenceTargetRecord),
		observationTargets:  make(map[string]SpannerWorldModelObservationTargetRecord),
		claimSources:        make(map[string]SpannerWorldModelClaimSourceRecord),
		claimEvidence:       make(map[string]SpannerWorldModelClaimEvidenceRecord),
		claimRelationships:  make(map[string]SpannerWorldModelClaimRelationshipRecord),
	}
}

func (a *SpannerWorldModelCanonicalAdapter) UpsertNode(ctx context.Context, node *Node) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if a == nil {
		return ErrStoreUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	switch node.Kind {
	case NodeKindSource:
		record, err := SpannerWorldModelSourceRecordFromNode(node)
		if err != nil {
			return err
		}
		a.sources[record.SourceID] = record
	case NodeKindClaim:
		record, err := SpannerWorldModelClaimRecordFromNode(node)
		if err != nil {
			return err
		}
		a.claims[record.ClaimID] = record
	case NodeKindEvidence:
		record, err := SpannerWorldModelEvidenceRecordFromNode(node)
		if err != nil {
			return err
		}
		a.evidence[record.EvidenceID] = record
	case NodeKindObservation:
		record, err := SpannerWorldModelObservationRecordFromNode(node)
		if err != nil {
			return err
		}
		a.observations[record.ObservationID] = record
	default:
		record, err := SpannerWorldModelEntityRecordFromNode(node)
		if err != nil {
			return err
		}
		a.entities[record.EntityID] = record
	}
	return nil
}

func (a *SpannerWorldModelCanonicalAdapter) UpsertEdge(ctx context.Context, edge *Edge) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if a == nil {
		return ErrStoreUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	sourceKind, ok := a.lookupNodeKindLocked(strings.TrimSpace(edge.Source))
	if !ok {
		return fmt.Errorf("source node %q not found in canonical adapter", edge.Source)
	}
	targetKind, ok := a.lookupNodeKindLocked(strings.TrimSpace(edge.Target))
	if !ok {
		return fmt.Errorf("target node %q not found in canonical adapter", edge.Target)
	}

	switch {
	case sourceKind == NodeKindClaim && targetKind == NodeKindSource && edge.Kind == EdgeKindAssertedBy:
		record, err := SpannerWorldModelClaimSourceRecordFromEdge(edge)
		if err != nil {
			return err
		}
		a.claimSources[record.EdgeID] = record
	case sourceKind == NodeKindClaim && targetKind == NodeKindEvidence && edge.Kind == EdgeKindBasedOn:
		record, err := SpannerWorldModelClaimEvidenceRecordFromEdge(edge)
		if err != nil {
			return err
		}
		a.claimEvidence[record.EdgeID] = record
	case sourceKind == NodeKindClaim && targetKind == NodeKindClaim:
		record, err := SpannerWorldModelClaimRelationshipRecordFromEdge(edge)
		if err != nil {
			return err
		}
		a.claimRelationships[record.EdgeID] = record
	case sourceKind == NodeKindEvidence && spannerWorldModelNodeKindIsEntity(targetKind) && edge.Kind == EdgeKindTargets:
		record, err := SpannerWorldModelEvidenceTargetRecordFromEdge(edge)
		if err != nil {
			return err
		}
		a.evidenceTargets[record.EdgeID] = record
	case sourceKind == NodeKindObservation && spannerWorldModelNodeKindIsEntity(targetKind) && edge.Kind == EdgeKindTargets:
		record, err := SpannerWorldModelObservationTargetRecordFromEdge(edge)
		if err != nil {
			return err
		}
		a.observationTargets[record.EdgeID] = record
	case spannerWorldModelNodeKindIsEntity(sourceKind) && spannerWorldModelNodeKindIsEntity(targetKind):
		record, err := SpannerWorldModelEntityRelationshipRecordFromEdge(edge)
		if err != nil {
			return err
		}
		a.entityRelationships[record.RelationshipID] = record
	default:
		return fmt.Errorf("edge %q kind %q is not yet modeled by canonical world-model tables", edge.ID, edge.Kind)
	}
	return nil
}

func (a *SpannerWorldModelCanonicalAdapter) LookupNode(ctx context.Context, id string) (*Node, bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, false, err
	}
	if a == nil {
		return nil, false, ErrStoreUnavailable
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, false, nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if record, ok := a.entities[id]; ok {
		return record.ToNode(), true, nil
	}
	if record, ok := a.sources[id]; ok {
		return record.ToNode(), true, nil
	}
	if record, ok := a.claims[id]; ok {
		return record.ToNode(), true, nil
	}
	if record, ok := a.evidence[id]; ok {
		return record.ToNode(), true, nil
	}
	if record, ok := a.observations[id]; ok {
		return record.ToNode(), true, nil
	}
	return nil, false, nil
}

func (a *SpannerWorldModelCanonicalAdapter) LookupEdge(ctx context.Context, id string) (*Edge, bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, false, err
	}
	if a == nil {
		return nil, false, ErrStoreUnavailable
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, false, nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if record, ok := a.entityRelationships[id]; ok {
		return record.ToEdge(), true, nil
	}
	if record, ok := a.evidenceTargets[id]; ok {
		return record.ToEdge(), true, nil
	}
	if record, ok := a.observationTargets[id]; ok {
		return record.ToEdge(), true, nil
	}
	if record, ok := a.claimSources[id]; ok {
		return record.ToEdge(), true, nil
	}
	if record, ok := a.claimEvidence[id]; ok {
		return record.ToEdge(), true, nil
	}
	if record, ok := a.claimRelationships[id]; ok {
		return record.ToEdge(), true, nil
	}
	return nil, false, nil
}

func (a *SpannerWorldModelCanonicalAdapter) Snapshot(ctx context.Context) (*Snapshot, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if a == nil {
		return nil, ErrStoreUnavailable
	}
	a.mu.RLock()
	defer a.mu.RUnlock()

	nodes := make([]*Node, 0, len(a.entities)+len(a.sources)+len(a.claims)+len(a.evidence)+len(a.observations))
	for _, record := range a.entities {
		nodes = append(nodes, record.ToNode())
	}
	for _, record := range a.sources {
		nodes = append(nodes, record.ToNode())
	}
	for _, record := range a.claims {
		nodes = append(nodes, record.ToNode())
	}
	for _, record := range a.evidence {
		nodes = append(nodes, record.ToNode())
	}
	for _, record := range a.observations {
		nodes = append(nodes, record.ToNode())
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	edges := make([]*Edge, 0, len(a.entityRelationships)+len(a.evidenceTargets)+len(a.observationTargets)+len(a.claimSources)+len(a.claimEvidence)+len(a.claimRelationships))
	for _, record := range a.entityRelationships {
		edges = append(edges, record.ToEdge())
	}
	for _, record := range a.evidenceTargets {
		edges = append(edges, record.ToEdge())
	}
	for _, record := range a.observationTargets {
		edges = append(edges, record.ToEdge())
	}
	for _, record := range a.claimSources {
		edges = append(edges, record.ToEdge())
	}
	for _, record := range a.claimEvidence {
		edges = append(edges, record.ToEdge())
	}
	for _, record := range a.claimRelationships {
		edges = append(edges, record.ToEdge())
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })

	return &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: temporalNowUTC(),
		Nodes:     nodes,
		Edges:     edges,
	}, nil
}

func (a *SpannerWorldModelCanonicalAdapter) lookupNodeKindLocked(id string) (NodeKind, bool) {
	if record, ok := a.entities[id]; ok {
		return record.Kind, true
	}
	if _, ok := a.sources[id]; ok {
		return NodeKindSource, true
	}
	if _, ok := a.claims[id]; ok {
		return NodeKindClaim, true
	}
	if _, ok := a.evidence[id]; ok {
		return NodeKindEvidence, true
	}
	if _, ok := a.observations[id]; ok {
		return NodeKindObservation, true
	}
	return "", false
}

func spannerWorldModelNodeKindIsEntity(kind NodeKind) bool {
	switch kind {
	case "", NodeKindSource, NodeKindClaim, NodeKindEvidence, NodeKindObservation:
		return false
	default:
		return true
	}
}
