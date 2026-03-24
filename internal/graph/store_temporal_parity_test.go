package graph

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestGraphStoreBackendParityTemporalRoundTrip(t *testing.T) {
	t.Parallel()

	for _, backend := range graphStoreBackendFactories() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			t.Parallel()
			runGraphStoreTemporalRoundTripContract(t, backend.new(t))
		})
	}
}

func TestGraphStoreBackendParityTemporalClaimAnalysis(t *testing.T) {
	t.Parallel()

	reference, claimID, validAt, recordedAt := buildTemporalClaimParityGraph(t)
	wantConflict, err := normalizeTemporalParityValue(BuildClaimConflictReport(reference, ClaimConflictReportOptions{
		ValidAt:      validAt,
		RecordedAt:   recordedAt,
		MaxConflicts: 10,
	}))
	if err != nil {
		t.Fatalf("normalize reference conflict report: %v", err)
	}
	wantTimeline, ok := GetClaimTimeline(reference, claimID, ClaimTimelineOptions{
		ValidAt:    validAt,
		RecordedAt: recordedAt,
		Limit:      20,
	})
	if !ok {
		t.Fatalf("expected reference timeline for %q", claimID)
	}
	wantTimelineNormalized, err := normalizeTemporalParityValue(wantTimeline)
	if err != nil {
		t.Fatalf("normalize reference timeline: %v", err)
	}

	for _, backend := range graphStoreBackendFactories() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			t.Parallel()

			store := backend.new(t)
			loadGraphStoreFromReferenceSnapshot(t, store, reference)

			snapshot, err := store.Snapshot(context.Background())
			if err != nil {
				t.Fatalf("Snapshot() error = %v", err)
			}
			restored := GraphViewFromSnapshot(snapshot)

			gotConflict, err := normalizeTemporalParityValue(BuildClaimConflictReport(restored, ClaimConflictReportOptions{
				ValidAt:      validAt,
				RecordedAt:   recordedAt,
				MaxConflicts: 10,
			}))
			if err != nil {
				t.Fatalf("normalize conflict report: %v", err)
			}
			if !reflect.DeepEqual(gotConflict, wantConflict) {
				t.Fatalf("conflict report mismatch = %#v, want %#v", gotConflict, wantConflict)
			}

			gotTimeline, ok := GetClaimTimeline(restored, claimID, ClaimTimelineOptions{
				ValidAt:    validAt,
				RecordedAt: recordedAt,
				Limit:      20,
			})
			if !ok {
				t.Fatalf("expected timeline for %q", claimID)
			}
			gotTimelineNormalized, err := normalizeTemporalParityValue(gotTimeline)
			if err != nil {
				t.Fatalf("normalize timeline: %v", err)
			}
			if !reflect.DeepEqual(gotTimelineNormalized, wantTimelineNormalized) {
				t.Fatalf("timeline mismatch = %#v, want %#v", gotTimelineNormalized, wantTimelineNormalized)
			}
		})
	}
}

func normalizeTemporalParityValue(value any) (map[string]any, error) {
	if value == nil {
		return map[string]any{}, nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized any
	if err := json.Unmarshal(payload, &normalized); err != nil {
		return nil, err
	}
	normalized = stripGeneratedAtFromValue(normalized)
	if asMap, ok := normalized.(map[string]any); ok {
		return asMap, nil
	}
	return map[string]any{"value": normalized}, nil
}

func stripGeneratedAtFromValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		delete(typed, "generated_at")
		for key, child := range typed {
			typed[key] = stripGeneratedAtFromValue(child)
		}
		return typed
	case []any:
		for index, child := range typed {
			typed[index] = stripGeneratedAtFromValue(child)
		}
		return typed
	default:
		return value
	}
}

func runGraphStoreTemporalRoundTripContract(t *testing.T, store GraphStore) {
	t.Helper()

	ctx := context.Background()
	base := time.Date(2026, 3, 23, 15, 0, 0, 0, time.UTC)
	validTo := base.Add(2 * time.Hour)
	transactionTo := base.Add(3 * time.Hour)

	service := contractStoreTemporalNode("service:payments", NodeKindService, "Payments", temporalNodeMetadata{
		ObservedAt:      base,
		ValidFrom:       base,
		ValidTo:         &validTo,
		RecordedAt:      base.Add(5 * time.Minute),
		TransactionFrom: base.Add(5 * time.Minute),
		TransactionTo:   &transactionTo,
		SourceSystem:    "temporal-contract",
		Extra: map[string]any{
			"service_id": "payments",
		},
	})
	observationValidTo := base.Add(90 * time.Minute)
	observationTransactionTo := base.Add(95 * time.Minute)
	observation := contractStoreTemporalNode("observation:payments:latency", NodeKindObservation, "Latency Observation", temporalNodeMetadata{
		ObservedAt:      base.Add(10 * time.Minute),
		ValidFrom:       base.Add(10 * time.Minute),
		ValidTo:         &observationValidTo,
		RecordedAt:      base.Add(11 * time.Minute),
		TransactionFrom: base.Add(11 * time.Minute),
		TransactionTo:   &observationTransactionTo,
		SourceSystem:    "temporal-contract",
		Extra: map[string]any{
			"observation_type": "latency",
			"subject_id":       "service:payments",
		},
	})
	evidenceValidTo := base.Add(150 * time.Minute)
	evidenceTransactionTo := base.Add(155 * time.Minute)
	evidence := contractStoreTemporalNode("evidence:payments:ticket", NodeKindEvidence, "Incident Ticket", temporalNodeMetadata{
		ObservedAt:      base.Add(12 * time.Minute),
		ValidFrom:       base.Add(12 * time.Minute),
		ValidTo:         &evidenceValidTo,
		RecordedAt:      base.Add(13 * time.Minute),
		TransactionFrom: base.Add(13 * time.Minute),
		TransactionTo:   &evidenceTransactionTo,
		SourceSystem:    "temporal-contract",
		Extra: map[string]any{
			"evidence_type": "ticket",
		},
	})
	targetsEdge := contractStoreTemporalEdge("edge:observation:targets", observation.ID, service.ID, EdgeKindTargets, temporalEdgeMetadata{
		ObservedAt:      base.Add(10 * time.Minute),
		ValidFrom:       base.Add(10 * time.Minute),
		RecordedAt:      base.Add(11 * time.Minute),
		TransactionFrom: base.Add(11 * time.Minute),
		SourceSystem:    "temporal-contract",
	})
	basedOnEdgeValidTo := base.Add(2 * time.Hour)
	basedOnEdgeTransactionTo := base.Add(125 * time.Minute)
	basedOnEdge := contractStoreTemporalEdge("edge:observation:based_on", observation.ID, evidence.ID, EdgeKindBasedOn, temporalEdgeMetadata{
		ObservedAt:      base.Add(12 * time.Minute),
		ValidFrom:       base.Add(12 * time.Minute),
		ValidTo:         &basedOnEdgeValidTo,
		RecordedAt:      base.Add(13 * time.Minute),
		TransactionFrom: base.Add(13 * time.Minute),
		TransactionTo:   &basedOnEdgeTransactionTo,
		SourceSystem:    "temporal-contract",
	})

	if err := store.UpsertNodesBatch(ctx, []*Node{service, observation, evidence}); err != nil {
		t.Fatalf("UpsertNodesBatch() error = %v", err)
	}
	if err := store.UpsertEdgesBatch(ctx, []*Edge{targetsEdge, basedOnEdge}); err != nil {
		t.Fatalf("UpsertEdgesBatch() error = %v", err)
	}
	if err := store.DeleteNode(ctx, evidence.ID); err != nil {
		t.Fatalf("DeleteNode() error = %v", err)
	}
	if err := store.DeleteEdge(ctx, basedOnEdge.ID); err != nil {
		t.Fatalf("DeleteEdge() error = %v", err)
	}

	node, ok, err := store.LookupNode(ctx, service.ID)
	if err != nil {
		t.Fatalf("LookupNode() error = %v", err)
	}
	if !ok || node == nil {
		t.Fatalf("expected active service node, got (%#v, %v)", node, ok)
	}
	assertTemporalProperties(t, node, temporalNodeMetadata{
		ObservedAt:      base,
		ValidFrom:       base,
		ValidTo:         &validTo,
		RecordedAt:      base.Add(5 * time.Minute),
		TransactionFrom: base.Add(5 * time.Minute),
		TransactionTo:   &transactionTo,
	})

	observationNode, ok, err := store.LookupNode(ctx, observation.ID)
	if err != nil {
		t.Fatalf("LookupNode(observation) error = %v", err)
	}
	if !ok || observationNode == nil {
		t.Fatalf("expected active observation node, got (%#v, %v)", observationNode, ok)
	}
	assertTemporalProperties(t, observationNode, temporalNodeMetadata{
		ObservedAt:      base.Add(10 * time.Minute),
		ValidFrom:       base.Add(10 * time.Minute),
		ValidTo:         &observationValidTo,
		RecordedAt:      base.Add(11 * time.Minute),
		TransactionFrom: base.Add(11 * time.Minute),
		TransactionTo:   &observationTransactionTo,
	})

	if deletedNode, ok, err := store.LookupNode(ctx, evidence.ID); err != nil {
		t.Fatalf("LookupNode(deleted) error = %v", err)
	} else if ok || deletedNode != nil {
		t.Fatalf("expected deleted node lookup to be absent, got (%#v, %v)", deletedNode, ok)
	}
	if deletedEdge, ok, err := store.LookupEdge(ctx, basedOnEdge.ID); err != nil {
		t.Fatalf("LookupEdge(deleted) error = %v", err)
	} else if ok || deletedEdge != nil {
		t.Fatalf("expected deleted edge lookup to be absent, got (%#v, %v)", deletedEdge, ok)
	}
	targetsStored, ok, err := store.LookupEdge(ctx, targetsEdge.ID)
	if err != nil {
		t.Fatalf("LookupEdge(targets) error = %v", err)
	}
	if !ok || targetsStored == nil {
		t.Fatalf("expected active targets edge, got (%#v, %v)", targetsStored, ok)
	}
	assertTemporalEdgeProperties(t, targetsStored.Properties, temporalEdgeMetadata{
		ObservedAt:      base.Add(10 * time.Minute),
		ValidFrom:       base.Add(10 * time.Minute),
		RecordedAt:      base.Add(11 * time.Minute),
		TransactionFrom: base.Add(11 * time.Minute),
	})

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	assertSnapshotNodeTemporalState(t, snapshot, service.ID, temporalNodeMetadata{
		ObservedAt:      base,
		ValidFrom:       base,
		ValidTo:         &validTo,
		RecordedAt:      base.Add(5 * time.Minute),
		TransactionFrom: base.Add(5 * time.Minute),
		TransactionTo:   &transactionTo,
	})
	assertSnapshotNodeTemporalState(t, snapshot, observation.ID, temporalNodeMetadata{
		ObservedAt:      base.Add(10 * time.Minute),
		ValidFrom:       base.Add(10 * time.Minute),
		ValidTo:         &observationValidTo,
		RecordedAt:      base.Add(11 * time.Minute),
		TransactionFrom: base.Add(11 * time.Minute),
		TransactionTo:   &observationTransactionTo,
	})
	assertSnapshotEdgeTemporalState(t, snapshot, targetsEdge.ID, temporalEdgeMetadata{
		ObservedAt:      base.Add(10 * time.Minute),
		ValidFrom:       base.Add(10 * time.Minute),
		RecordedAt:      base.Add(11 * time.Minute),
		TransactionFrom: base.Add(11 * time.Minute),
	})
}

type temporalNodeMetadata struct {
	ObservedAt      time.Time
	ValidFrom       time.Time
	ValidTo         *time.Time
	RecordedAt      time.Time
	TransactionFrom time.Time
	TransactionTo   *time.Time
	SourceSystem    string
	Extra           map[string]any
}

type temporalEdgeMetadata struct {
	ObservedAt      time.Time
	ValidFrom       time.Time
	ValidTo         *time.Time
	RecordedAt      time.Time
	TransactionFrom time.Time
	TransactionTo   *time.Time
	SourceSystem    string
}

func contractStoreTemporalNode(id string, kind NodeKind, name string, meta temporalNodeMetadata) *Node {
	properties := map[string]any{}
	if meta.ObservedAt.IsZero() {
		meta.ObservedAt = time.Date(2026, 3, 23, 15, 0, 0, 0, time.UTC)
	}
	if meta.ValidFrom.IsZero() {
		meta.ValidFrom = meta.ObservedAt
	}
	if meta.RecordedAt.IsZero() {
		meta.RecordedAt = meta.ObservedAt.Add(2 * time.Minute)
	}
	if meta.TransactionFrom.IsZero() {
		meta.TransactionFrom = meta.RecordedAt
	}
	NormalizeWriteMetadata(meta.ObservedAt, meta.ValidFrom, meta.ValidTo, meta.SourceSystem, "temporal-contract:event", 0.9, WriteMetadataDefaults{
		RecordedAt:      meta.RecordedAt,
		TransactionFrom: meta.TransactionFrom,
		TransactionTo:   meta.TransactionTo,
	}).ApplyTo(properties)
	for key, value := range meta.Extra {
		properties[key] = value
	}
	return &Node{ID: id, Kind: kind, Name: name, Properties: properties}
}

func contractStoreTemporalEdge(id, source, target string, kind EdgeKind, meta temporalEdgeMetadata) *Edge {
	properties := map[string]any{}
	if meta.ObservedAt.IsZero() {
		meta.ObservedAt = time.Date(2026, 3, 23, 15, 0, 0, 0, time.UTC)
	}
	if meta.ValidFrom.IsZero() {
		meta.ValidFrom = meta.ObservedAt
	}
	if meta.RecordedAt.IsZero() {
		meta.RecordedAt = meta.ObservedAt.Add(2 * time.Minute)
	}
	if meta.TransactionFrom.IsZero() {
		meta.TransactionFrom = meta.RecordedAt
	}
	NormalizeWriteMetadata(meta.ObservedAt, meta.ValidFrom, meta.ValidTo, meta.SourceSystem, "temporal-contract:event", 0.9, WriteMetadataDefaults{
		RecordedAt:      meta.RecordedAt,
		TransactionFrom: meta.TransactionFrom,
		TransactionTo:   meta.TransactionTo,
	}).ApplyTo(properties)
	return &Edge{ID: id, Source: source, Target: target, Kind: kind, Properties: properties}
}

func assertTemporalProperties(t *testing.T, node *Node, meta temporalNodeMetadata) {
	t.Helper()
	assertTemporalNodePropertyTime(t, node, "observed_at", meta.ObservedAt)
	assertTemporalNodePropertyTime(t, node, "valid_from", meta.ValidFrom)
	assertTemporalNodePropertyTime(t, node, "recorded_at", meta.RecordedAt)
	assertTemporalNodePropertyTime(t, node, "transaction_from", meta.TransactionFrom)
	assertTemporalNodePropertyTimePtr(t, node, "valid_to", meta.ValidTo)
	assertTemporalNodePropertyTimePtr(t, node, "transaction_to", meta.TransactionTo)
}

func assertSnapshotNodeTemporalState(t *testing.T, snapshot *Snapshot, id string, meta temporalNodeMetadata) {
	t.Helper()
	node := snapshotNodeByID(snapshot, id)
	if node == nil {
		t.Fatalf("expected snapshot node %q", id)
	}
	if node.DeletedAt != nil {
		t.Fatalf("expected active snapshot node %q", id)
	}
	assertTemporalProperties(t, node, meta)
}

func assertSnapshotEdgeTemporalState(t *testing.T, snapshot *Snapshot, id string, meta temporalEdgeMetadata) {
	t.Helper()
	edge := snapshotEdgeByID(snapshot, id)
	if edge == nil {
		t.Fatalf("expected snapshot edge %q", id)
	}
	if edge.DeletedAt != nil {
		t.Fatalf("expected active snapshot edge %q", id)
	}
	assertTemporalEdgeProperties(t, edge.Properties, meta)
}

func assertTemporalEdgeProperties(t *testing.T, properties map[string]any, meta temporalEdgeMetadata) {
	t.Helper()
	assertTemporalPropertyTime(t, properties, "observed_at", meta.ObservedAt)
	assertTemporalPropertyTime(t, properties, "valid_from", meta.ValidFrom)
	assertTemporalPropertyTime(t, properties, "recorded_at", meta.RecordedAt)
	assertTemporalPropertyTime(t, properties, "transaction_from", meta.TransactionFrom)
	assertTemporalPropertyTimePtr(t, properties, "valid_to", meta.ValidTo)
	assertTemporalPropertyTimePtr(t, properties, "transaction_to", meta.TransactionTo)
}

func assertTemporalNodePropertyTime(t *testing.T, node *Node, key string, want time.Time) {
	t.Helper()
	got, ok := nodePropertyTime(node, key)
	if !ok || !got.Equal(want.UTC()) {
		t.Fatalf("%s = (%v, %v), want %v", key, got, ok, want.UTC())
	}
}

func assertTemporalNodePropertyTimePtr(t *testing.T, node *Node, key string, want *time.Time) {
	t.Helper()
	got, ok := nodePropertyTime(node, key)
	if want == nil {
		if ok {
			t.Fatalf("%s = %v, want absent", key, got)
		}
		return
	}
	if !ok || !got.Equal(want.UTC()) {
		t.Fatalf("%s = (%v, %v), want %v", key, got, ok, want.UTC())
	}
}

func assertTemporalPropertyTime(t *testing.T, properties map[string]any, key string, want time.Time) {
	t.Helper()
	got, ok := nodePropertyTime(&Node{Properties: properties}, key)
	if !ok || !got.Equal(want.UTC()) {
		t.Fatalf("%s = (%v, %v), want %v", key, got, ok, want.UTC())
	}
}

func assertTemporalPropertyTimePtr(t *testing.T, properties map[string]any, key string, want *time.Time) {
	t.Helper()
	got, ok := nodePropertyTime(&Node{Properties: properties}, key)
	if want == nil {
		if ok {
			t.Fatalf("%s = %v, want absent", key, got)
		}
		return
	}
	if !ok || !got.Equal(want.UTC()) {
		t.Fatalf("%s = (%v, %v), want %v", key, got, ok, want.UTC())
	}
}

func loadGraphStoreFromReferenceSnapshot(t *testing.T, store GraphStore, reference *Graph) {
	t.Helper()
	snapshot := CreateSnapshot(reference)
	if err := store.UpsertNodesBatch(context.Background(), snapshot.Nodes); err != nil {
		t.Fatalf("UpsertNodesBatch() error = %v", err)
	}
	if err := store.UpsertEdgesBatch(context.Background(), snapshot.Edges); err != nil {
		t.Fatalf("UpsertEdgesBatch() error = %v", err)
	}
}

func buildTemporalClaimParityGraph(t *testing.T) (*Graph, string, time.Time, time.Time) {
	t.Helper()

	g := New()
	base := time.Date(2026, 3, 23, 16, 0, 0, 0, time.UTC)
	recordedAt := base.Add(10 * time.Minute)

	g.AddNode(contractStoreTemporalNode("service:payments", NodeKindService, "Payments", temporalNodeMetadata{
		ObservedAt:      base,
		ValidFrom:       base,
		RecordedAt:      recordedAt,
		TransactionFrom: recordedAt,
		SourceSystem:    "temporal-contract",
		Extra: map[string]any{
			"service_id": "payments",
		},
	}))
	g.AddNode(contractStoreTemporalNode("evidence:ticket:123", NodeKindEvidence, "Ticket 123", temporalNodeMetadata{
		ObservedAt:      base.Add(2 * time.Minute),
		ValidFrom:       base.Add(2 * time.Minute),
		RecordedAt:      recordedAt,
		TransactionFrom: recordedAt,
		SourceSystem:    "temporal-contract",
		Extra: map[string]any{
			"evidence_type": "ticket",
		},
	}))

	if _, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:alice",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectValue:     "alice@example.com",
		SourceID:        "source:cmdb:payments",
		SourceName:      "Payments CMDB",
		SourceType:      "system",
		TrustTier:       "authoritative",
		SourceSystem:    "temporal-contract",
		EvidenceIDs:     []string{"evidence:ticket:123"},
		ObservedAt:      base.Add(3 * time.Minute),
		ValidFrom:       base.Add(3 * time.Minute),
		RecordedAt:      recordedAt.Add(1 * time.Minute),
		TransactionFrom: recordedAt.Add(1 * time.Minute),
	}); err != nil {
		t.Fatalf("WriteClaim(owner alice): %v", err)
	}
	if _, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:bob",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectValue:     "bob@example.com",
		SourceID:        "source:sheet:payments",
		SourceName:      "Payments Sheet",
		SourceType:      "document",
		TrustTier:       "verified",
		SourceSystem:    "temporal-contract",
		ObservedAt:      base.Add(4 * time.Minute),
		ValidFrom:       base.Add(4 * time.Minute),
		RecordedAt:      recordedAt.Add(2 * time.Minute),
		TransactionFrom: recordedAt.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("WriteClaim(owner bob): %v", err)
	}
	if _, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:tier:before",
		SubjectID:       "service:payments",
		Predicate:       "service_tier",
		ObjectValue:     "tier1",
		SourceID:        "source:cmdb:tier",
		SourceName:      "Tier CMDB",
		SourceType:      "system",
		TrustTier:       "authoritative",
		SourceSystem:    "temporal-contract",
		ObservedAt:      base.Add(5 * time.Minute),
		ValidFrom:       base.Add(5 * time.Minute),
		RecordedAt:      recordedAt.Add(3 * time.Minute),
		TransactionFrom: recordedAt.Add(3 * time.Minute),
	}); err != nil {
		t.Fatalf("WriteClaim(tier before): %v", err)
	}
	if _, err := WriteClaim(g, ClaimWriteRequest{
		ID:                "claim:payments:tier:after",
		SubjectID:         "service:payments",
		Predicate:         "service_tier",
		ObjectValue:       "tier0",
		SourceID:          "source:sheet:tier",
		SourceName:        "Tier Sheet",
		SourceType:        "document",
		TrustTier:         "verified",
		SourceSystem:      "temporal-contract",
		SupersedesClaimID: "claim:payments:tier:before",
		ObservedAt:        base.Add(6 * time.Minute),
		ValidFrom:         base.Add(6 * time.Minute),
		RecordedAt:        recordedAt.Add(4 * time.Minute),
		TransactionFrom:   recordedAt.Add(4 * time.Minute),
	}); err != nil {
		t.Fatalf("WriteClaim(tier after): %v", err)
	}
	validAt := base.Add(2 * time.Hour)
	recorded := recordedAt.Add(2 * time.Hour)
	return g, "claim:payments:tier:before", validAt, recorded
}

func snapshotNodeByID(snapshot *Snapshot, id string) *Node {
	if snapshot == nil {
		return nil
	}
	for _, node := range snapshot.Nodes {
		if node != nil && node.ID == id {
			return node
		}
	}
	return nil
}

func snapshotEdgeByID(snapshot *Snapshot, id string) *Edge {
	if snapshot == nil {
		return nil
	}
	for _, edge := range snapshot.Edges {
		if edge != nil && edge.ID == id {
			return edge
		}
	}
	return nil
}
