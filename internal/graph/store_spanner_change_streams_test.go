package graph

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSpannerWorldModelChangeStreamStatements(t *testing.T) {
	statements, err := SpannerWorldModelChangeStreamStatements(DefaultSpannerWorldModelChangeStreamConfig())
	if err != nil {
		t.Fatalf("SpannerWorldModelChangeStreamStatements() error = %v", err)
	}
	if len(statements) != 1 {
		t.Fatalf("expected one DDL statement, got %d", len(statements))
	}
	ddl := statements[0]
	wantFragments := []string{
		"CREATE CHANGE STREAM cerebro_world_model_changes",
		"FOR entities, entity_relationships, sources, evidence, evidence_targets, observations, observation_targets, claims, claim_subjects, claim_objects, claim_sources, claim_evidence, claim_relationships",
		"retention_period = '168h'",
		"value_capture_type = 'NEW_ROW_AND_OLD_VALUES'",
		"exclude_ttl_deletes = false",
		"exclude_insert = false",
		"exclude_update = false",
		"exclude_delete = false",
		"allow_txn_exclusion = true",
	}
	for _, fragment := range wantFragments {
		if !strings.Contains(ddl, fragment) {
			t.Fatalf("expected change-stream DDL to contain %q", fragment)
		}
	}
}

func TestSpannerWorldModelChangeStreamStatementsRejectsInvalidConfig(t *testing.T) {
	_, err := SpannerWorldModelChangeStreamStatements(SpannerChangeStreamConfig{
		Name:             "bad",
		RetentionPeriod:  12 * time.Hour,
		ValueCaptureType: SpannerChangeStreamValueCaptureType("INVALID"),
	})
	if err == nil {
		t.Fatal("expected invalid config error")
	}
	if !strings.Contains(err.Error(), "retention period") {
		t.Fatalf("expected retention period validation error, got %v", err)
	}
}

func TestSpannerWorldModelChangeStreamStatementsRejectsRetentionOverSevenDays(t *testing.T) {
	_, err := SpannerWorldModelChangeStreamStatements(SpannerChangeStreamConfig{
		Name:            "bad",
		RetentionPeriod: 8 * 24 * time.Hour,
	})
	if err == nil {
		t.Fatal("expected retention period validation error")
	}
	if got := err.Error(); !strings.Contains(got, "between 24h and 168h") {
		t.Fatalf("expected seven-day retention validation error, got %v", err)
	}
}
func TestSpannerWorldModelChangeStreamWatchedTablesCoverCanonicalWorldModel(t *testing.T) {
	cfg := DefaultSpannerWorldModelChangeStreamConfig()
	got := make(map[string]struct{}, len(cfg.WatchedTables))
	for _, table := range cfg.WatchedTables {
		got[table.Table] = struct{}{}
	}
	want := []string{
		"entities",
		"entity_relationships",
		"sources",
		"evidence",
		"evidence_targets",
		"observations",
		"observation_targets",
		"claims",
		"claim_subjects",
		"claim_objects",
		"claim_sources",
		"claim_evidence",
		"claim_relationships",
	}
	for _, table := range want {
		if _, ok := got[table]; !ok {
			t.Fatalf("expected watched tables to include %q", table)
		}
	}
}

func TestShapeSpannerWorldModelChangeStreamEnvelopeDeterministic(t *testing.T) {
	commitAt := time.Date(2026, 3, 23, 8, 15, 0, 0, time.UTC)
	records := []SpannerChangeStreamDataRecord{
		{
			Table:            "claim_relationships",
			ModificationType: SpannerChangeStreamModificationUpdate,
			CommitTimestamp:  commitAt,
			TransactionID:    "txn-1",
			RecordSequence:   "0003",
			Keys: map[string]any{
				"claim_id": "claim:1",
				"edge_id":  "edge:claim:supports",
			},
			NewValues: map[string]any{
				"claim_id":          "claim:1",
				"edge_id":           "edge:claim:supports",
				"related_claim_id":  "claim:0",
				"relationship_kind": "supports",
				"source_system":     "platform",
				"source_event_id":   "evt-claim-rel",
				"observed_at":       commitAt.Format(time.RFC3339),
				"valid_from":        commitAt.Format(time.RFC3339),
				"recorded_at":       commitAt.Format(time.RFC3339),
				"transaction_from":  commitAt.Format(time.RFC3339),
				"confidence":        0.9,
				"properties_json":   map[string]any{"explanation": "shared evidence"},
			},
		},
		{
			Table:            "entities",
			ModificationType: SpannerChangeStreamModificationInsert,
			CommitTimestamp:  commitAt,
			TransactionID:    "txn-1",
			RecordSequence:   "0001",
			Keys: map[string]any{
				"entity_id": "service:payments",
			},
			NewValues: map[string]any{
				"entity_id":        "service:payments",
				"kind":             string(NodeKindService),
				"name":             "Payments",
				"source_system":    "platform",
				"source_event_id":  "evt-entity",
				"observed_at":      commitAt.Format(time.RFC3339),
				"valid_from":       commitAt.Format(time.RFC3339),
				"recorded_at":      commitAt.Format(time.RFC3339),
				"transaction_from": commitAt.Format(time.RFC3339),
				"confidence":       0.95,
			},
		},
		{
			Table:            "claim_subjects",
			ModificationType: SpannerChangeStreamModificationDelete,
			CommitTimestamp:  commitAt,
			TransactionID:    "txn-1",
			RecordSequence:   "0002",
			Keys: map[string]any{
				"claim_id":          "claim:1",
				"subject_entity_id": "service:payments",
			},
			OldValues: map[string]any{
				"claim_id":          "claim:1",
				"subject_entity_id": "service:payments",
			},
		},
	}

	envelope, err := ShapeSpannerWorldModelChangeStreamEnvelope(DefaultSpannerWorldModelChangeStreamConfig(), records)
	if err != nil {
		t.Fatalf("ShapeSpannerWorldModelChangeStreamEnvelope() error = %v", err)
	}
	if envelope.StreamName != "cerebro_world_model_changes" {
		t.Fatalf("StreamName = %q, want cerebro_world_model_changes", envelope.StreamName)
	}
	if !envelope.CommitTimestamp.Equal(commitAt) {
		t.Fatalf("CommitTimestamp = %s, want %s", envelope.CommitTimestamp, commitAt)
	}
	if envelope.TransactionID != "txn-1" {
		t.Fatalf("TransactionID = %q, want txn-1", envelope.TransactionID)
	}
	if len(envelope.Mutations) != 3 {
		t.Fatalf("expected 3 mutations, got %d", len(envelope.Mutations))
	}

	if got := envelope.Mutations[0]; got.Identifier != "service:payments" || got.ObjectType != SpannerChangeStreamObjectNode || got.Kind != string(NodeKindService) {
		t.Fatalf("first mutation = %#v", got)
	}
	if got := envelope.Mutations[1]; got.Identifier != "claim_subjects:claim:1:service:payments" || got.Operation != SpannerChangeStreamOperationDelete || got.SourceID != "claim:1" || got.TargetID != "service:payments" || got.Kind != string(EdgeKindRefers) {
		t.Fatalf("second mutation = %#v", got)
	}
	if got := envelope.Mutations[2]; got.Identifier != "edge:claim:supports" || got.ObjectType != SpannerChangeStreamObjectEdge || got.Kind != string(EdgeKindSupports) || got.TargetID != "claim:0" {
		t.Fatalf("third mutation = %#v", got)
	}
}

func TestShapeSpannerWorldModelChangeStreamEnvelopeTrimsMutationSequenceRecordSequence(t *testing.T) {
	commitAt := time.Date(2026, 3, 23, 8, 20, 0, 0, time.UTC)
	envelope, err := ShapeSpannerWorldModelChangeStreamEnvelope(DefaultSpannerWorldModelChangeStreamConfig(), []SpannerChangeStreamDataRecord{
		{
			Table:            "entities",
			ModificationType: SpannerChangeStreamModificationInsert,
			CommitTimestamp:  commitAt,
			TransactionID:    " txn-3 ",
			RecordSequence:   " 0007 ",
			Keys:             map[string]any{"entity_id": "service:billing"},
			NewValues: map[string]any{
				"entity_id": "service:billing",
				"kind":      string(NodeKindService),
			},
		},
	})
	if err != nil {
		t.Fatalf("ShapeSpannerWorldModelChangeStreamEnvelope() error = %v", err)
	}
	if envelope.TransactionID != "txn-3" {
		t.Fatalf("TransactionID = %q, want txn-3", envelope.TransactionID)
	}
	if envelope.MutationSequence != "txn-3:0007" {
		t.Fatalf("MutationSequence = %q, want txn-3:0007", envelope.MutationSequence)
	}
}

func TestShapeSpannerWorldModelMutationRejectsIncompleteCompositeIdentifiers(t *testing.T) {
	tests := []struct {
		name   string
		table  string
		values map[string]any
	}{
		{
			name:   "claim subjects missing ids",
			table:  "claim_subjects",
			values: map[string]any{},
		},
		{
			name:  "claim objects missing object id",
			table: "claim_objects",
			values: map[string]any{
				"claim_id": "claim:1",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := shapeSpannerWorldModelMutation(SpannerChangeStreamDataRecord{
				Table:            tc.table,
				ModificationType: SpannerChangeStreamModificationInsert,
				NewValues:        tc.values,
			})
			if err == nil {
				t.Fatal("expected missing identifier error")
			}
			if !strings.Contains(err.Error(), "missing an identifier") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSpannerChangeStreamConsumersFanOutToPublisherQueueAndReconciler(t *testing.T) {
	envelope := SpannerChangeStreamMutationEnvelope{
		StreamName:       "cerebro_world_model_changes",
		CommitTimestamp:  time.Date(2026, 3, 23, 8, 30, 0, 0, time.UTC),
		TransactionID:    "txn-2",
		MutationSequence: "txn-2:0001",
		Mutations: []SpannerChangeStreamGraphMutation{
			{
				Table:      "entities",
				ObjectType: SpannerChangeStreamObjectNode,
				Operation:  SpannerChangeStreamOperationUpsert,
				Identifier: "service:checkout",
				Kind:       string(NodeKindService),
			},
		},
	}

	publisher := &recordingSpannerChangeStreamPublisher{}
	queue := &recordingSpannerChangeStreamQueue{}
	reconciler := &recordingSpannerChangeStreamReconciler{}

	consumer := NewFanoutSpannerChangeStreamConsumer(
		NewPubSubSpannerChangeStreamConsumer("projects/test/topics/graph", publisher),
		NewQueueSpannerChangeStreamConsumer(queue),
		NewReconcilerSpannerChangeStreamConsumer(reconciler),
	)
	if err := consumer.ConsumeSpannerChangeStream(context.Background(), envelope); err != nil {
		t.Fatalf("ConsumeSpannerChangeStream() error = %v", err)
	}

	if publisher.topic != "projects/test/topics/graph" {
		t.Fatalf("publisher topic = %q, want projects/test/topics/graph", publisher.topic)
	}
	if publisher.attributes["stream_name"] != envelope.StreamName {
		t.Fatalf("publisher stream_name = %q, want %q", publisher.attributes["stream_name"], envelope.StreamName)
	}
	var published SpannerChangeStreamMutationEnvelope
	if err := json.Unmarshal(publisher.data, &published); err != nil {
		t.Fatalf("json.Unmarshal(publisher data) error = %v", err)
	}
	if published.MutationSequence != envelope.MutationSequence {
		t.Fatalf("published MutationSequence = %q, want %q", published.MutationSequence, envelope.MutationSequence)
	}
	if len(queue.envelopes) != 1 || queue.envelopes[0].TransactionID != envelope.TransactionID {
		t.Fatalf("queue envelopes = %#v", queue.envelopes)
	}
	if len(reconciler.envelopes) != 1 || reconciler.envelopes[0].CommitTimestamp != envelope.CommitTimestamp {
		t.Fatalf("reconciler envelopes = %#v", reconciler.envelopes)
	}
}

func TestShapeSpannerWorldModelChangeStreamEnvelopeHonorsTableModificationFilters(t *testing.T) {
	commitAt := time.Date(2026, 3, 23, 9, 0, 0, 0, time.UTC)
	cfg := DefaultSpannerWorldModelChangeStreamConfig()
	cfg.WatchedTables = []SpannerChangeStreamWatchedTable{
		{
			Table:             "entities",
			ModificationTypes: []SpannerChangeStreamModificationType{SpannerChangeStreamModificationUpdate},
		},
	}
	envelope, err := ShapeSpannerWorldModelChangeStreamEnvelope(cfg, []SpannerChangeStreamDataRecord{
		{
			Table:            "entities",
			ModificationType: SpannerChangeStreamModificationInsert,
			CommitTimestamp:  commitAt,
			TransactionID:    "txn-filter",
			RecordSequence:   "0001",
			Keys:             map[string]any{"entity_id": "service:payments"},
			NewValues: map[string]any{
				"entity_id": "service:payments",
				"kind":      string(NodeKindService),
			},
		},
	})
	if err != nil {
		t.Fatalf("ShapeSpannerWorldModelChangeStreamEnvelope() error = %v", err)
	}
	if len(envelope.Mutations) != 0 {
		t.Fatalf("expected insert to be filtered, got %#v", envelope.Mutations)
	}
}

func TestShapeSpannerWorldModelChangeStreamEnvelopeRejectsMixedTransactions(t *testing.T) {
	commitAt := time.Date(2026, 3, 23, 9, 5, 0, 0, time.UTC)
	_, err := ShapeSpannerWorldModelChangeStreamEnvelope(DefaultSpannerWorldModelChangeStreamConfig(), []SpannerChangeStreamDataRecord{
		{
			Table:            "entities",
			ModificationType: SpannerChangeStreamModificationInsert,
			CommitTimestamp:  commitAt,
			TransactionID:    "txn-a",
			RecordSequence:   "0001",
			Keys:             map[string]any{"entity_id": "service:payments"},
			NewValues: map[string]any{
				"entity_id": "service:payments",
				"kind":      string(NodeKindService),
			},
		},
		{
			Table:            "sources",
			ModificationType: SpannerChangeStreamModificationInsert,
			CommitTimestamp:  commitAt,
			TransactionID:    "txn-b",
			RecordSequence:   "0002",
			Keys:             map[string]any{"source_id": "source:doc"},
			NewValues: map[string]any{
				"source_id": "source:doc",
			},
		},
	})
	if err == nil {
		t.Fatal("expected mixed transaction error")
	}
	if !strings.Contains(err.Error(), "does not match envelope transaction") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFanoutSpannerChangeStreamConsumerClonesEnvelopePerSink(t *testing.T) {
	envelope := SpannerChangeStreamMutationEnvelope{
		StreamName:       "cerebro_world_model_changes",
		CommitTimestamp:  time.Date(2026, 3, 23, 9, 10, 0, 0, time.UTC),
		TransactionID:    "txn-clone",
		MutationSequence: "txn-clone:0001",
		Mutations: []SpannerChangeStreamGraphMutation{
			{
				Table:      "entities",
				ObjectType: SpannerChangeStreamObjectNode,
				Operation:  SpannerChangeStreamOperationUpsert,
				Identifier: "service:checkout",
				Kind:       string(NodeKindService),
				NewValues:  map[string]any{"name": "Checkout"},
			},
		},
	}
	mutatingConsumer := SpannerChangeStreamConsumerFunc(func(_ context.Context, envelope SpannerChangeStreamMutationEnvelope) error {
		envelope.Mutations[0].Identifier = "service:mutated"
		envelope.Mutations[0].NewValues["name"] = "Mutated"
		return nil
	})
	queue := &recordingSpannerChangeStreamQueue{}
	consumer := NewFanoutSpannerChangeStreamConsumer(mutatingConsumer, NewQueueSpannerChangeStreamConsumer(queue))
	if err := consumer.ConsumeSpannerChangeStream(context.Background(), envelope); err != nil {
		t.Fatalf("ConsumeSpannerChangeStream() error = %v", err)
	}
	if queue.envelopes[0].Mutations[0].Identifier != "service:checkout" {
		t.Fatalf("queue saw mutated identifier: %#v", queue.envelopes[0].Mutations[0])
	}
	if got := readString(queue.envelopes[0].Mutations[0].NewValues, "name"); got != "Checkout" {
		t.Fatalf("queue saw mutated new values: %#v", queue.envelopes[0].Mutations[0].NewValues)
	}
}

type recordingSpannerChangeStreamPublisher struct {
	topic      string
	data       []byte
	attributes map[string]string
}

func (r *recordingSpannerChangeStreamPublisher) PublishSpannerChangeStream(ctx context.Context, topic string, data []byte, attributes map[string]string) error {
	r.topic = topic
	r.data = append([]byte(nil), data...)
	r.attributes = make(map[string]string, len(attributes))
	for key, value := range attributes {
		r.attributes[key] = value
	}
	return ctx.Err()
}

type recordingSpannerChangeStreamQueue struct {
	envelopes []SpannerChangeStreamMutationEnvelope
}

func (r *recordingSpannerChangeStreamQueue) EnqueueSpannerChangeStream(_ context.Context, envelope SpannerChangeStreamMutationEnvelope) error {
	r.envelopes = append(r.envelopes, envelope)
	return nil
}

type recordingSpannerChangeStreamReconciler struct {
	envelopes []SpannerChangeStreamMutationEnvelope
}

func (r *recordingSpannerChangeStreamReconciler) ReconcileSpannerChangeStream(_ context.Context, envelope SpannerChangeStreamMutationEnvelope) error {
	r.envelopes = append(r.envelopes, envelope)
	return nil
}

type SpannerChangeStreamConsumerFunc func(context.Context, SpannerChangeStreamMutationEnvelope) error

func (f SpannerChangeStreamConsumerFunc) ConsumeSpannerChangeStream(ctx context.Context, envelope SpannerChangeStreamMutationEnvelope) error {
	return f(ctx, envelope)
}
