package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

const defaultSpannerWorldModelChangeStreamName = "cerebro_world_model_changes"

type SpannerChangeStreamValueCaptureType string

const (
	SpannerChangeStreamValueCaptureTypeNewValues          SpannerChangeStreamValueCaptureType = "NEW_VALUES"
	SpannerChangeStreamValueCaptureTypeOldAndNewValues    SpannerChangeStreamValueCaptureType = "OLD_AND_NEW_VALUES"
	SpannerChangeStreamValueCaptureTypeNewRow             SpannerChangeStreamValueCaptureType = "NEW_ROW"
	SpannerChangeStreamValueCaptureTypeNewRowAndOldValues SpannerChangeStreamValueCaptureType = "NEW_ROW_AND_OLD_VALUES"
)

type SpannerChangeStreamModificationType string

const (
	SpannerChangeStreamModificationInsert SpannerChangeStreamModificationType = "INSERT"
	SpannerChangeStreamModificationUpdate SpannerChangeStreamModificationType = "UPDATE"
	SpannerChangeStreamModificationDelete SpannerChangeStreamModificationType = "DELETE"
)

type SpannerChangeStreamOperation string

const (
	SpannerChangeStreamOperationUpsert SpannerChangeStreamOperation = "upsert"
	SpannerChangeStreamOperationDelete SpannerChangeStreamOperation = "delete"
)

type SpannerChangeStreamObjectType string

const (
	SpannerChangeStreamObjectNode SpannerChangeStreamObjectType = "node"
	SpannerChangeStreamObjectEdge SpannerChangeStreamObjectType = "edge"
)

type SpannerChangeStreamWatchedTable struct {
	Table             string
	ModificationTypes []SpannerChangeStreamModificationType
}

type SpannerChangeStreamConfig struct {
	Name              string
	RetentionPeriod   time.Duration
	ValueCaptureType  SpannerChangeStreamValueCaptureType
	ExcludeTTLDeletes bool
	ExcludeInsert     bool
	ExcludeUpdate     bool
	ExcludeDelete     bool
	AllowTxnExclusion bool
	WatchedTables     []SpannerChangeStreamWatchedTable
}

type SpannerChangeStreamDataRecord struct {
	Table            string
	ModificationType SpannerChangeStreamModificationType
	CommitTimestamp  time.Time
	TransactionID    string
	RecordSequence   string
	Keys             map[string]any
	NewValues        map[string]any
	OldValues        map[string]any
}

type SpannerChangeStreamGraphMutation struct {
	Table      string                        `json:"table"`
	ObjectType SpannerChangeStreamObjectType `json:"object_type"`
	Operation  SpannerChangeStreamOperation  `json:"operation"`
	Identifier string                        `json:"identifier"`
	SourceID   string                        `json:"source_id,omitempty"`
	TargetID   string                        `json:"target_id,omitempty"`
	Kind       string                        `json:"kind,omitempty"`
	Keys       map[string]any                `json:"keys,omitempty"`
	NewValues  map[string]any                `json:"new_values,omitempty"`
	OldValues  map[string]any                `json:"old_values,omitempty"`
}

type SpannerChangeStreamMutationEnvelope struct {
	StreamName       string                             `json:"stream_name"`
	CommitTimestamp  time.Time                          `json:"commit_timestamp"`
	TransactionID    string                             `json:"transaction_id"`
	MutationSequence string                             `json:"mutation_sequence"`
	Mutations        []SpannerChangeStreamGraphMutation `json:"mutations"`
}

type SpannerChangeStreamConsumer interface {
	ConsumeSpannerChangeStream(context.Context, SpannerChangeStreamMutationEnvelope) error
}

type SpannerChangeStreamPublisher interface {
	PublishSpannerChangeStream(context.Context, string, []byte, map[string]string) error
}

type SpannerChangeStreamEnvelopeQueue interface {
	EnqueueSpannerChangeStream(context.Context, SpannerChangeStreamMutationEnvelope) error
}

type SpannerChangeStreamEnvelopeReconciler interface {
	ReconcileSpannerChangeStream(context.Context, SpannerChangeStreamMutationEnvelope) error
}

func DefaultSpannerWorldModelChangeStreamConfig() SpannerChangeStreamConfig {
	return SpannerChangeStreamConfig{
		Name:              defaultSpannerWorldModelChangeStreamName,
		RetentionPeriod:   7 * 24 * time.Hour,
		ValueCaptureType:  SpannerChangeStreamValueCaptureTypeNewRowAndOldValues,
		AllowTxnExclusion: true,
		WatchedTables: []SpannerChangeStreamWatchedTable{
			{Table: "entities"},
			{Table: "entity_relationships"},
			{Table: "sources"},
			{Table: "evidence"},
			{Table: "evidence_targets"},
			{Table: "observations"},
			{Table: "observation_targets"},
			{Table: "claims"},
			{Table: "claim_subjects"},
			{Table: "claim_objects"},
			{Table: "claim_sources"},
			{Table: "claim_evidence"},
			{Table: "claim_relationships"},
		},
	}
}

func SpannerWorldModelChangeStreamStatements(cfg SpannerChangeStreamConfig) ([]string, error) {
	cfg, err := normalizeSpannerChangeStreamConfig(cfg)
	if err != nil {
		return nil, err
	}
	tableNames := make([]string, 0, len(cfg.WatchedTables))
	for _, table := range cfg.WatchedTables {
		tableNames = append(tableNames, table.Table)
	}
	statement := fmt.Sprintf(
		"CREATE CHANGE STREAM %s FOR %s OPTIONS (retention_period = '%s', value_capture_type = '%s', exclude_ttl_deletes = %t, exclude_insert = %t, exclude_update = %t, exclude_delete = %t, allow_txn_exclusion = %t)",
		cfg.Name,
		strings.Join(tableNames, ", "),
		formatSpannerChangeStreamRetention(cfg.RetentionPeriod),
		cfg.ValueCaptureType,
		cfg.ExcludeTTLDeletes,
		cfg.ExcludeInsert,
		cfg.ExcludeUpdate,
		cfg.ExcludeDelete,
		cfg.AllowTxnExclusion,
	)
	return []string{statement}, nil
}

func ShapeSpannerWorldModelChangeStreamEnvelope(cfg SpannerChangeStreamConfig, records []SpannerChangeStreamDataRecord) (SpannerChangeStreamMutationEnvelope, error) {
	cfg, err := normalizeSpannerChangeStreamConfig(cfg)
	if err != nil {
		return SpannerChangeStreamMutationEnvelope{}, err
	}
	if len(records) == 0 {
		return SpannerChangeStreamMutationEnvelope{}, fmt.Errorf("at least one change-stream record is required")
	}
	watched := make(map[string]SpannerChangeStreamWatchedTable, len(cfg.WatchedTables))
	for _, table := range cfg.WatchedTables {
		watched[table.Table] = table
	}

	sorted := append([]SpannerChangeStreamDataRecord(nil), records...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].CommitTimestamp.Equal(sorted[j].CommitTimestamp) {
			return sorted[i].CommitTimestamp.Before(sorted[j].CommitTimestamp)
		}
		if sorted[i].TransactionID != sorted[j].TransactionID {
			return sorted[i].TransactionID < sorted[j].TransactionID
		}
		if sorted[i].RecordSequence != sorted[j].RecordSequence {
			return sorted[i].RecordSequence < sorted[j].RecordSequence
		}
		if sorted[i].Table != sorted[j].Table {
			return sorted[i].Table < sorted[j].Table
		}
		return spannerChangeStreamRecordIdentifier(sorted[i]) < spannerChangeStreamRecordIdentifier(sorted[j])
	})

	envelope := SpannerChangeStreamMutationEnvelope{
		StreamName:      cfg.Name,
		CommitTimestamp: sorted[0].CommitTimestamp.UTC(),
		TransactionID:   strings.TrimSpace(sorted[0].TransactionID),
	}
	if envelope.TransactionID == "" {
		envelope.TransactionID = fmt.Sprintf("%s:%d", cfg.Name, envelope.CommitTimestamp.UnixNano())
	}
	lastSequence := strings.TrimSpace(sorted[len(sorted)-1].RecordSequence)
	if lastSequence == "" {
		lastSequence = "0000"
	}
	envelope.MutationSequence = envelope.TransactionID + ":" + lastSequence
	envelope.Mutations = make([]SpannerChangeStreamGraphMutation, 0, len(sorted))

	for _, record := range sorted {
		if !record.CommitTimestamp.UTC().Equal(envelope.CommitTimestamp) {
			return SpannerChangeStreamMutationEnvelope{}, fmt.Errorf("record %q commit timestamp %s does not match envelope commit timestamp %s", record.Table, record.CommitTimestamp, envelope.CommitTimestamp)
		}
		if tx := strings.TrimSpace(record.TransactionID); tx != "" && tx != envelope.TransactionID {
			return SpannerChangeStreamMutationEnvelope{}, fmt.Errorf("record %q transaction %q does not match envelope transaction %q", record.Table, tx, envelope.TransactionID)
		}
		tableCfg, ok := watched[strings.TrimSpace(record.Table)]
		if !ok {
			return SpannerChangeStreamMutationEnvelope{}, fmt.Errorf("table %q is not configured for world-model change streams", record.Table)
		}
		if !spannerChangeStreamModificationAllowed(tableCfg, record.ModificationType) {
			continue
		}
		mutation, err := shapeSpannerWorldModelMutation(record)
		if err != nil {
			return SpannerChangeStreamMutationEnvelope{}, err
		}
		envelope.Mutations = append(envelope.Mutations, mutation)
	}
	return envelope, nil
}

func NewFanoutSpannerChangeStreamConsumer(consumers ...SpannerChangeStreamConsumer) SpannerChangeStreamConsumer {
	filtered := make([]SpannerChangeStreamConsumer, 0, len(consumers))
	for _, consumer := range consumers {
		if consumer != nil {
			filtered = append(filtered, consumer)
		}
	}
	return fanoutSpannerChangeStreamConsumer(filtered)
}

func NewPubSubSpannerChangeStreamConsumer(topic string, publisher SpannerChangeStreamPublisher) SpannerChangeStreamConsumer {
	if strings.TrimSpace(topic) == "" || publisher == nil {
		return nil
	}
	return pubSubSpannerChangeStreamConsumer{
		topic:     strings.TrimSpace(topic),
		publisher: publisher,
	}
}

func NewQueueSpannerChangeStreamConsumer(queue SpannerChangeStreamEnvelopeQueue) SpannerChangeStreamConsumer {
	if queue == nil {
		return nil
	}
	return queueSpannerChangeStreamConsumer{queue: queue}
}

func NewReconcilerSpannerChangeStreamConsumer(reconciler SpannerChangeStreamEnvelopeReconciler) SpannerChangeStreamConsumer {
	if reconciler == nil {
		return nil
	}
	return reconcilerSpannerChangeStreamConsumer{reconciler: reconciler}
}

type fanoutSpannerChangeStreamConsumer []SpannerChangeStreamConsumer

func (c fanoutSpannerChangeStreamConsumer) ConsumeSpannerChangeStream(ctx context.Context, envelope SpannerChangeStreamMutationEnvelope) error {
	for _, consumer := range c {
		if err := consumer.ConsumeSpannerChangeStream(ctx, cloneSpannerChangeStreamEnvelope(envelope)); err != nil {
			return err
		}
	}
	return nil
}

type pubSubSpannerChangeStreamConsumer struct {
	topic     string
	publisher SpannerChangeStreamPublisher
}

func (c pubSubSpannerChangeStreamConsumer) ConsumeSpannerChangeStream(ctx context.Context, envelope SpannerChangeStreamMutationEnvelope) error {
	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal change-stream envelope: %w", err)
	}
	return c.publisher.PublishSpannerChangeStream(ctx, c.topic, data, map[string]string{
		"stream_name":      envelope.StreamName,
		"transaction_id":   envelope.TransactionID,
		"commit_timestamp": envelope.CommitTimestamp.UTC().Format(time.RFC3339Nano),
		"mutation_count":   fmt.Sprintf("%d", len(envelope.Mutations)),
	})
}

type queueSpannerChangeStreamConsumer struct {
	queue SpannerChangeStreamEnvelopeQueue
}

func (c queueSpannerChangeStreamConsumer) ConsumeSpannerChangeStream(ctx context.Context, envelope SpannerChangeStreamMutationEnvelope) error {
	return c.queue.EnqueueSpannerChangeStream(ctx, cloneSpannerChangeStreamEnvelope(envelope))
}

type reconcilerSpannerChangeStreamConsumer struct {
	reconciler SpannerChangeStreamEnvelopeReconciler
}

func (c reconcilerSpannerChangeStreamConsumer) ConsumeSpannerChangeStream(ctx context.Context, envelope SpannerChangeStreamMutationEnvelope) error {
	return c.reconciler.ReconcileSpannerChangeStream(ctx, cloneSpannerChangeStreamEnvelope(envelope))
}

func normalizeSpannerChangeStreamConfig(cfg SpannerChangeStreamConfig) (SpannerChangeStreamConfig, error) {
	if strings.TrimSpace(cfg.Name) == "" {
		cfg.Name = defaultSpannerWorldModelChangeStreamName
	}
	if cfg.RetentionPeriod <= 0 {
		cfg.RetentionPeriod = 7 * 24 * time.Hour
	}
	if cfg.ValueCaptureType == "" {
		cfg.ValueCaptureType = SpannerChangeStreamValueCaptureTypeNewRowAndOldValues
	}
	if len(cfg.WatchedTables) == 0 {
		cfg.WatchedTables = DefaultSpannerWorldModelChangeStreamConfig().WatchedTables
	}
	if cfg.RetentionPeriod < 24*time.Hour || cfg.RetentionPeriod > 7*24*time.Hour {
		return SpannerChangeStreamConfig{}, fmt.Errorf("retention period must be between 24h and 168h")
	}
	switch cfg.ValueCaptureType {
	case SpannerChangeStreamValueCaptureTypeNewValues, SpannerChangeStreamValueCaptureTypeOldAndNewValues, SpannerChangeStreamValueCaptureTypeNewRow, SpannerChangeStreamValueCaptureTypeNewRowAndOldValues:
	default:
		return SpannerChangeStreamConfig{}, fmt.Errorf("unsupported value capture type %q", cfg.ValueCaptureType)
	}
	seenTables := make(map[string]struct{}, len(cfg.WatchedTables))
	for i := range cfg.WatchedTables {
		cfg.WatchedTables[i].Table = strings.TrimSpace(cfg.WatchedTables[i].Table)
		if cfg.WatchedTables[i].Table == "" {
			return SpannerChangeStreamConfig{}, fmt.Errorf("watched table name is required")
		}
		if _, ok := seenTables[cfg.WatchedTables[i].Table]; ok {
			return SpannerChangeStreamConfig{}, fmt.Errorf("duplicate watched table %q", cfg.WatchedTables[i].Table)
		}
		seenTables[cfg.WatchedTables[i].Table] = struct{}{}
		if len(cfg.WatchedTables[i].ModificationTypes) == 0 {
			cfg.WatchedTables[i].ModificationTypes = []SpannerChangeStreamModificationType{
				SpannerChangeStreamModificationInsert,
				SpannerChangeStreamModificationUpdate,
				SpannerChangeStreamModificationDelete,
			}
		}
		for _, mod := range cfg.WatchedTables[i].ModificationTypes {
			switch mod {
			case SpannerChangeStreamModificationInsert, SpannerChangeStreamModificationUpdate, SpannerChangeStreamModificationDelete:
			default:
				return SpannerChangeStreamConfig{}, fmt.Errorf("unsupported watched-table modification type %q", mod)
			}
		}
	}
	return cfg, nil
}

func formatSpannerChangeStreamRetention(duration time.Duration) string {
	return fmt.Sprintf("%dh", int(duration.Hours()))
}

func spannerChangeStreamModificationAllowed(table SpannerChangeStreamWatchedTable, mod SpannerChangeStreamModificationType) bool {
	return slices.Contains(table.ModificationTypes, mod)
}

func shapeSpannerWorldModelMutation(record SpannerChangeStreamDataRecord) (SpannerChangeStreamGraphMutation, error) {
	record.Table = strings.TrimSpace(record.Table)
	if record.Table == "" {
		return SpannerChangeStreamGraphMutation{}, fmt.Errorf("change-stream record table is required")
	}
	operation := SpannerChangeStreamOperationUpsert
	if record.ModificationType == SpannerChangeStreamModificationDelete {
		operation = SpannerChangeStreamOperationDelete
	}
	kind := ""
	objectType := SpannerChangeStreamObjectNode
	identifier := ""
	sourceID := ""
	targetID := ""

	switch record.Table {
	case "entities":
		identifier = spannerChangeStreamField(record, "entity_id")
		kind = spannerChangeStreamField(record, "kind")
	case "sources":
		identifier = spannerChangeStreamField(record, "source_id")
		kind = string(NodeKindSource)
	case "evidence":
		identifier = spannerChangeStreamField(record, "evidence_id")
		kind = string(NodeKindEvidence)
	case "observations":
		identifier = spannerChangeStreamField(record, "observation_id")
		kind = string(NodeKindObservation)
	case "claims":
		identifier = spannerChangeStreamField(record, "claim_id")
		kind = string(NodeKindClaim)
	case "entity_relationships":
		objectType = SpannerChangeStreamObjectEdge
		identifier = spannerChangeStreamField(record, "relationship_id")
		sourceID = spannerChangeStreamField(record, "source_entity_id")
		targetID = spannerChangeStreamField(record, "target_entity_id")
		kind = spannerChangeStreamField(record, "relationship_kind")
	case "evidence_targets":
		objectType = SpannerChangeStreamObjectEdge
		identifier = spannerChangeStreamField(record, "edge_id")
		sourceID = spannerChangeStreamField(record, "evidence_id")
		targetID = spannerChangeStreamField(record, "target_entity_id")
		kind = string(EdgeKindTargets)
	case "observation_targets":
		objectType = SpannerChangeStreamObjectEdge
		identifier = spannerChangeStreamField(record, "edge_id")
		sourceID = spannerChangeStreamField(record, "observation_id")
		targetID = spannerChangeStreamField(record, "target_entity_id")
		kind = string(EdgeKindTargets)
	case "claim_subjects":
		objectType = SpannerChangeStreamObjectEdge
		sourceID = spannerChangeStreamField(record, "claim_id")
		targetID = spannerChangeStreamField(record, "subject_entity_id")
		identifier = spannerChangeStreamCompositeIdentifier("claim_subjects", sourceID, targetID)
		kind = string(EdgeKindRefers)
	case "claim_objects":
		objectType = SpannerChangeStreamObjectEdge
		sourceID = spannerChangeStreamField(record, "claim_id")
		targetID = spannerChangeStreamField(record, "object_entity_id")
		identifier = spannerChangeStreamCompositeIdentifier("claim_objects", sourceID, targetID)
		kind = string(EdgeKindRefers)
	case "claim_sources":
		objectType = SpannerChangeStreamObjectEdge
		identifier = spannerChangeStreamField(record, "edge_id")
		sourceID = spannerChangeStreamField(record, "claim_id")
		targetID = spannerChangeStreamField(record, "source_id")
		kind = string(EdgeKindAssertedBy)
	case "claim_evidence":
		objectType = SpannerChangeStreamObjectEdge
		identifier = spannerChangeStreamField(record, "edge_id")
		sourceID = spannerChangeStreamField(record, "claim_id")
		targetID = spannerChangeStreamField(record, "evidence_id")
		kind = string(EdgeKindBasedOn)
	case "claim_relationships":
		objectType = SpannerChangeStreamObjectEdge
		identifier = spannerChangeStreamField(record, "edge_id")
		sourceID = spannerChangeStreamField(record, "claim_id")
		targetID = spannerChangeStreamField(record, "related_claim_id")
		kind = spannerChangeStreamField(record, "relationship_kind")
	default:
		return SpannerChangeStreamGraphMutation{}, fmt.Errorf("unsupported world-model change-stream table %q", record.Table)
	}

	if strings.TrimSpace(identifier) == "" {
		return SpannerChangeStreamGraphMutation{}, fmt.Errorf("change-stream record for table %q is missing an identifier", record.Table)
	}

	return SpannerChangeStreamGraphMutation{
		Table:      record.Table,
		ObjectType: objectType,
		Operation:  operation,
		Identifier: identifier,
		SourceID:   sourceID,
		TargetID:   targetID,
		Kind:       kind,
		Keys:       cloneAnyMap(record.Keys),
		NewValues:  cloneAnyMap(record.NewValues),
		OldValues:  cloneAnyMap(record.OldValues),
	}, nil
}

func spannerChangeStreamField(record SpannerChangeStreamDataRecord, key string) string {
	key = strings.TrimSpace(key)
	for _, source := range []map[string]any{record.NewValues, record.OldValues, record.Keys} {
		if source == nil {
			continue
		}
		if value := readString(source, key); strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func spannerChangeStreamRecordIdentifier(record SpannerChangeStreamDataRecord) string {
	switch strings.TrimSpace(record.Table) {
	case "entities":
		return spannerChangeStreamField(record, "entity_id")
	case "sources":
		return spannerChangeStreamField(record, "source_id")
	case "evidence":
		return spannerChangeStreamField(record, "evidence_id")
	case "observations":
		return spannerChangeStreamField(record, "observation_id")
	case "claims":
		return spannerChangeStreamField(record, "claim_id")
	case "entity_relationships":
		return spannerChangeStreamField(record, "relationship_id")
	case "evidence_targets", "observation_targets", "claim_sources", "claim_evidence", "claim_relationships":
		return spannerChangeStreamField(record, "edge_id")
	case "claim_subjects":
		return spannerChangeStreamCompositeIdentifier("claim_subjects", spannerChangeStreamField(record, "claim_id"), spannerChangeStreamField(record, "subject_entity_id"))
	case "claim_objects":
		return spannerChangeStreamCompositeIdentifier("claim_objects", spannerChangeStreamField(record, "claim_id"), spannerChangeStreamField(record, "object_entity_id"))
	default:
		return strings.TrimSpace(record.Table)
	}
}

func spannerChangeStreamCompositeIdentifier(prefix, sourceID, targetID string) string {
	if sourceID == "" || targetID == "" {
		return ""
	}
	return prefix + ":" + sourceID + ":" + targetID
}

func cloneSpannerChangeStreamEnvelope(envelope SpannerChangeStreamMutationEnvelope) SpannerChangeStreamMutationEnvelope {
	cloned := envelope
	cloned.Mutations = make([]SpannerChangeStreamGraphMutation, len(envelope.Mutations))
	for i, mutation := range envelope.Mutations {
		cloned.Mutations[i] = mutation
		cloned.Mutations[i].Keys = cloneAnyMap(mutation.Keys)
		cloned.Mutations[i].NewValues = cloneAnyMap(mutation.NewValues)
		cloned.Mutations[i].OldValues = cloneAnyMap(mutation.OldValues)
	}
	return cloned
}
