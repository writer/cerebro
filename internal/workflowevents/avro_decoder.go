package workflowevents

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// IsSharedEnvelopeEvent reports whether the workflow event payload carries the
// shared event-registry writer.contracts.EventEnvelopeV1 Avro envelope.
func IsSharedEnvelopeEvent(event *cerebrov1.EventEnvelope) bool {
	if event == nil || len(event.GetPayload()) == 0 {
		return false
	}
	attrs := event.GetAttributes()
	return strings.HasPrefix(strings.TrimSpace(event.GetKind()), "workflow.v1.") &&
		strings.TrimSpace(attrs["envelope_version"]) == "1"
}

// DecodeSharedEnvelopeEvent rebuilds the local protobuf envelope used by the
// projector/replay API from a raw event-registry Avro envelope and JetStream headers.
func DecodeSharedEnvelopeEvent(data []byte, attributes map[string]string) (*cerebrov1.EventEnvelope, error) {
	envelope, err := readSharedEnvelope(data, "")
	if err != nil {
		return nil, err
	}
	attrs := make(map[string]string, len(attributes)+5)
	for key, value := range attributes {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		attrs[key] = value
	}
	setDefaultAttribute(attrs, "event_type", envelope.eventType)
	setDefaultAttribute(attrs, "event_version", fmt.Sprintf("%d", envelope.version))
	setDefaultAttribute(attrs, "event_id", envelope.eventID)
	setDefaultAttribute(attrs, "envelope_version", "1")
	event := &cerebrov1.EventEnvelope{
		Id:         envelope.eventID,
		TenantId:   strings.TrimSpace(attrs[EventAttributeTenantID]),
		SourceId:   strings.TrimSpace(attrs[EventAttributeSourceSystem]),
		Kind:       envelope.eventType,
		OccurredAt: timestamppb.New(time.UnixMilli(envelope.emittedAtMS).UTC()),
		SchemaRef:  schemaForKind(envelope.eventType),
		Payload:    data,
		Attributes: attrs,
	}
	return event, nil
}

func decodeWorkflowPayload(event *cerebrov1.EventEnvelope, kind string, payload any) error {
	data := event.GetPayload()
	if len(data) == 0 {
		return fmt.Errorf("workflow event %q payload is required", event.GetId())
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		if err := json.Unmarshal(data, payload); err != nil {
			return fmt.Errorf("decode workflow event %q JSON payload: %w", event.GetId(), err)
		}
		return nil
	}
	envelope, err := readSharedEnvelope(data, kind)
	if err != nil {
		if !IsSharedEnvelopeEvent(event) {
			if jsonErr := json.Unmarshal(data, payload); jsonErr == nil {
				return nil
			}
		}
		return fmt.Errorf("decode workflow event %q shared envelope: %w", event.GetId(), err)
	}
	if err := decodeAvroPayload(kind, envelope.payload, payload); err != nil {
		return fmt.Errorf("decode workflow event %q Avro payload: %w", event.GetId(), err)
	}
	return nil
}

func decodeAvroPayload(kind string, data []byte, payload any) error {
	reader := newAvroReader(data)
	var err error
	switch target := payload.(type) {
	case *DecisionRecorded:
		err = decodeDecisionRecorded(reader, target)
	case *ActionRecorded:
		err = decodeActionRecorded(reader, target)
	case *OutcomeRecorded:
		err = decodeOutcomeRecorded(reader, target)
	case *FindingRecorded:
		err = decodeFindingRecorded(reader, target)
	case *FindingNoteAdded:
		err = decodeFindingNoteAdded(reader, target)
	case *FindingTicketLinked:
		err = decodeFindingTicketLinked(reader, target)
	case *FindingExternalRefLinked:
		err = decodeFindingExternalRefLinked(reader, target)
	case *FindingStatusChanged:
		err = decodeFindingStatusChanged(reader, target)
	case *FindingTombstoned:
		err = decodeFindingTombstoned(reader, target)
	case *ComplianceAggregateRecorded:
		err = decodeComplianceAggregateRecorded(reader, target)
	default:
		return fmt.Errorf("unsupported workflow payload target %T for %s", payload, kind)
	}
	if err != nil {
		return err
	}
	if reader.remaining() != 0 {
		return fmt.Errorf("payload has %d trailing bytes", reader.remaining())
	}
	return nil
}

func decodeComplianceAggregateRecorded(reader *avroReader, payload *ComplianceAggregateRecorded) error {
	var err error
	if payload.TenantID, err = reader.string(); err != nil {
		return err
	}
	if payload.AggregateType, err = reader.string(); err != nil {
		return err
	}
	if payload.AggregateID, err = reader.string(); err != nil {
		return err
	}
	if payload.RevisionID, err = reader.string(); err != nil {
		return err
	}
	if payload.AggregateVersion, err = reader.long(); err != nil {
		return err
	}
	if payload.Operation, err = reader.string(); err != nil {
		return err
	}
	if payload.ContentDigest, err = reader.string(); err != nil {
		return err
	}
	if payload.PayloadJSON, err = reader.string(); err != nil {
		return err
	}
	if payload.ActorID, err = reader.string(); err != nil {
		return err
	}
	payload.RecordedAt, err = reader.string()
	return err
}

func decodeDecisionRecorded(reader *avroReader, payload *DecisionRecorded) error {
	var err error
	if payload.TenantID, err = reader.string(); err != nil {
		return err
	}
	if payload.DecisionID, err = reader.string(); err != nil {
		return err
	}
	if payload.DecisionType, err = reader.string(); err != nil {
		return err
	}
	if payload.Status, err = reader.string(); err != nil {
		return err
	}
	if payload.MadeBy, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.Rationale, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.TargetIDs, err = reader.stringArray(); err != nil {
		return err
	}
	if payload.EvidenceIDs, err = reader.stringArray(); err != nil {
		return err
	}
	if payload.ActionIDs, err = reader.stringArray(); err != nil {
		return err
	}
	if payload.SourceSystem, err = reader.string(); err != nil {
		return err
	}
	if payload.SourceEventID, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.ObservedAt, err = reader.string(); err != nil {
		return err
	}
	if payload.ValidFrom, err = reader.string(); err != nil {
		return err
	}
	if payload.ValidTo, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.Confidence, err = reader.nullableDouble(); err != nil {
		return err
	}
	payload.Metadata, err = reader.metadataMap()
	return err
}

func decodeActionRecorded(reader *avroReader, payload *ActionRecorded) error {
	var err error
	if payload.TenantID, err = reader.string(); err != nil {
		return err
	}
	if payload.ActionID, err = reader.string(); err != nil {
		return err
	}
	if payload.ActionType, err = reader.string(); err != nil {
		return err
	}
	if payload.Status, err = reader.string(); err != nil {
		return err
	}
	if payload.RecommendationID, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.InsightType, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.Title, err = reader.string(); err != nil {
		return err
	}
	if payload.Summary, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.DecisionID, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.TargetIDs, err = reader.stringArray(); err != nil {
		return err
	}
	if payload.SourceSystem, err = reader.string(); err != nil {
		return err
	}
	if payload.SourceEventID, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.ObservedAt, err = reader.string(); err != nil {
		return err
	}
	if payload.ValidFrom, err = reader.string(); err != nil {
		return err
	}
	if payload.ValidTo, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.Confidence, err = reader.nullableDouble(); err != nil {
		return err
	}
	if payload.AutoGenerated, err = reader.boolean(); err != nil {
		return err
	}
	payload.Metadata, err = reader.metadataMap()
	return err
}

func decodeOutcomeRecorded(reader *avroReader, payload *OutcomeRecorded) error {
	var err error
	if payload.TenantID, err = reader.string(); err != nil {
		return err
	}
	if payload.OutcomeID, err = reader.string(); err != nil {
		return err
	}
	if payload.DecisionID, err = reader.string(); err != nil {
		return err
	}
	if payload.OutcomeType, err = reader.string(); err != nil {
		return err
	}
	if payload.Verdict, err = reader.string(); err != nil {
		return err
	}
	if payload.ImpactScore, err = reader.nullableDouble(); err != nil {
		return err
	}
	if payload.TargetIDs, err = reader.stringArray(); err != nil {
		return err
	}
	if payload.SourceSystem, err = reader.string(); err != nil {
		return err
	}
	if payload.SourceEventID, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.ObservedAt, err = reader.string(); err != nil {
		return err
	}
	if payload.ValidFrom, err = reader.string(); err != nil {
		return err
	}
	if payload.ValidTo, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.Confidence, err = reader.nullableDouble(); err != nil {
		return err
	}
	payload.Metadata, err = reader.metadataMap()
	return err
}

func decodeFindingRecorded(reader *avroReader, payload *FindingRecorded) error {
	var err error
	if payload.Finding, err = reader.findingSnapshot(); err != nil {
		return err
	}
	payload.RecordedAt, err = reader.string()
	return err
}

func decodeFindingNoteAdded(reader *avroReader, payload *FindingNoteAdded) error {
	var err error
	if payload.Finding, err = reader.findingSnapshot(); err != nil {
		return err
	}
	if payload.NoteID, err = reader.string(); err != nil {
		return err
	}
	if payload.Body, err = reader.string(); err != nil {
		return err
	}
	payload.CreatedAt, err = reader.string()
	return err
}

func decodeFindingTicketLinked(reader *avroReader, payload *FindingTicketLinked) error {
	var err error
	if payload.Finding, err = reader.findingSnapshot(); err != nil {
		return err
	}
	if payload.URL, err = reader.string(); err != nil {
		return err
	}
	if payload.Name, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.ExternalID, err = reader.nullableString(); err != nil {
		return err
	}
	payload.LinkedAt, err = reader.string()
	return err
}

func decodeFindingExternalRefLinked(reader *avroReader, payload *FindingExternalRefLinked) error {
	var err error
	if payload.Finding, err = reader.findingSnapshot(); err != nil {
		return err
	}
	if payload.System, err = reader.string(); err != nil {
		return err
	}
	if payload.Kind, err = reader.string(); err != nil {
		return err
	}
	if payload.ExternalID, err = reader.string(); err != nil {
		return err
	}
	if payload.URL, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.ExternalStatus, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.ExternalStatusReason, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.LifecycleOwner, err = reader.nullableString(); err != nil {
		return err
	}
	payload.LinkedAt, err = reader.string()
	return err
}

func decodeFindingStatusChanged(reader *avroReader, payload *FindingStatusChanged) error {
	var err error
	if payload.Finding, err = reader.findingSnapshot(); err != nil {
		return err
	}
	if payload.Status, err = reader.string(); err != nil {
		return err
	}
	if payload.Reason, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.Source, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.UpdatedAt, err = reader.string(); err != nil {
		return err
	}
	if payload.DecisionID, err = reader.nullableString(); err != nil {
		return err
	}
	if payload.OutcomeID, err = reader.nullableString(); err != nil {
		return err
	}
	payload.OutcomeType, err = reader.nullableString()
	return err
}

func decodeFindingTombstoned(reader *avroReader, payload *FindingTombstoned) error {
	var err error
	if payload.Finding, err = reader.findingSnapshot(); err != nil {
		return err
	}
	if payload.PriorStatus, err = reader.string(); err != nil {
		return err
	}
	if payload.Reason, err = reader.string(); err != nil {
		return err
	}
	if payload.Actor, err = reader.string(); err != nil {
		return err
	}
	if payload.RunID, err = reader.string(); err != nil {
		return err
	}
	payload.TombstonedAt, err = reader.string()
	return err
}

func (r *avroReader) findingSnapshot() (FindingSnapshot, error) {
	var finding FindingSnapshot
	var err error
	if finding.TenantID, err = r.string(); err != nil {
		return finding, err
	}
	if finding.SourceSystem, err = r.string(); err != nil {
		return finding, err
	}
	if finding.FindingID, err = r.string(); err != nil {
		return finding, err
	}
	if finding.Fingerprint, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.Title, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.Summary, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.RuleID, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.Severity, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.Status, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.RuntimeID, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.PolicyID, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.CheckID, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.PrimaryResourceURN, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.ResourceURNs, err = r.stringArray(); err != nil {
		return finding, err
	}
	if finding.EventIDs, err = r.stringArray(); err != nil {
		return finding, err
	}
	if finding.FirstObservedAt, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.LastObservedAt, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.ResourceCount, err = r.integer(); err != nil {
		return finding, err
	}
	if finding.EventCount, err = r.integer(); err != nil {
		return finding, err
	}
	if finding.ControlRefs, err = r.findingControlRefArray(); err != nil {
		return finding, err
	}
	if finding.RiskScore, err = r.integer(); err != nil {
		return finding, err
	}
	if finding.EffectiveSeverity, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.LikelihoodScore, err = r.integer(); err != nil {
		return finding, err
	}
	if finding.ImpactScore, err = r.integer(); err != nil {
		return finding, err
	}
	if finding.ConfidenceScore, err = r.integer(); err != nil {
		return finding, err
	}
	if finding.LikelihoodLevel, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.ImpactLevel, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.RiskModelVersion, err = r.nullableString(); err != nil {
		return finding, err
	}
	if finding.RiskReasons, err = r.stringArray(); err != nil {
		return finding, err
	}
	finding.Metadata, err = r.stringMap()
	return finding, err
}

type sharedEnvelope struct {
	eventType   string
	version     int
	eventID     string
	emittedAtMS int64
	payload     []byte
}

func readSharedEnvelope(data []byte, expectedKind string) (sharedEnvelope, error) {
	reader := newAvroReader(data)
	eventType, err := reader.string()
	if err != nil {
		return sharedEnvelope{}, err
	}
	version, err := reader.integer()
	if err != nil {
		return sharedEnvelope{}, err
	}
	eventID, err := reader.string()
	if err != nil {
		return sharedEnvelope{}, err
	}
	emittedAtMS, err := reader.long()
	if err != nil {
		return sharedEnvelope{}, err
	}
	for i := 0; i < 13; i++ {
		if _, err := reader.nullableString(); err != nil {
			return sharedEnvelope{}, err
		}
	}
	payload, err := reader.bytesValue()
	if err != nil {
		return sharedEnvelope{}, err
	}
	if reader.remaining() != 0 {
		return sharedEnvelope{}, fmt.Errorf("shared envelope has %d trailing bytes", reader.remaining())
	}
	if expectedKind != "" && eventType != expectedKind {
		return sharedEnvelope{}, fmt.Errorf("shared envelope event_type = %q, want %q", eventType, expectedKind)
	}
	return sharedEnvelope{
		eventType:   eventType,
		version:     version,
		eventID:     eventID,
		emittedAtMS: emittedAtMS,
		payload:     payload,
	}, nil
}

type avroReader struct {
	data []byte
	pos  int
}

func newAvroReader(data []byte) *avroReader {
	return &avroReader{data: data}
}

func (r *avroReader) remaining() int {
	return len(r.data) - r.pos
}

func (r *avroReader) boolean() (bool, error) {
	if r.remaining() < 1 {
		return false, fmt.Errorf("unexpected EOF reading boolean")
	}
	value := r.data[r.pos]
	r.pos++
	switch value {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("invalid Avro boolean value %d", value)
	}
}

func (r *avroReader) integer() (int, error) {
	value, err := r.long()
	if err != nil {
		return 0, err
	}
	if value < math.MinInt32 || value > math.MaxInt32 {
		return 0, fmt.Errorf("avro int out of range: %d", value)
	}
	return int(value), nil
}

func (r *avroReader) long() (int64, error) {
	var value uint64
	for shift := 0; shift < 64; shift += 7 {
		if r.remaining() < 1 {
			return 0, fmt.Errorf("unexpected EOF reading long")
		}
		b := r.data[r.pos]
		r.pos++
		value |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return int64(value>>1) ^ -int64(value&1), nil
		}
	}
	return 0, fmt.Errorf("avro long varint exceeds 64 bits")
}

func (r *avroReader) double() (float64, error) {
	if r.remaining() < 8 {
		return 0, fmt.Errorf("unexpected EOF reading double")
	}
	value := binary.LittleEndian.Uint64(r.data[r.pos : r.pos+8])
	r.pos += 8
	return math.Float64frombits(value), nil
}

func (r *avroReader) string() (string, error) {
	data, err := r.bytesValue()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (r *avroReader) bytesValue() ([]byte, error) {
	length, err := r.long()
	if err != nil {
		return nil, err
	}
	if length < 0 {
		return nil, fmt.Errorf("negative byte/string length %d", length)
	}
	if length > int64(r.remaining()) {
		return nil, fmt.Errorf("byte/string length %d exceeds remaining %d", length, r.remaining())
	}
	start := r.pos
	r.pos += int(length)
	return r.data[start:r.pos], nil
}

func (r *avroReader) nullableString() (string, error) {
	index, err := r.long()
	if err != nil {
		return "", err
	}
	switch index {
	case 0:
		return "", nil
	case 1:
		return r.string()
	default:
		return "", fmt.Errorf("invalid nullable string union index %d", index)
	}
}

func (r *avroReader) nullableDouble() (float64, error) {
	index, err := r.long()
	if err != nil {
		return 0, err
	}
	switch index {
	case 0:
		return 0, nil
	case 1:
		return r.double()
	default:
		return 0, fmt.Errorf("invalid nullable double union index %d", index)
	}
}

func (r *avroReader) stringArray() ([]string, error) {
	values := make([]string, 0)
	if err := r.readArray(func() error {
		value, err := r.string()
		if err != nil {
			return err
		}
		values = append(values, value)
		return nil
	}); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, nil
	}
	return values, nil
}

func (r *avroReader) findingControlRefArray() ([]FindingControlRefSnapshot, error) {
	values := make([]FindingControlRefSnapshot, 0)
	if err := r.readArray(func() error {
		frameworkName, err := r.string()
		if err != nil {
			return err
		}
		controlID, err := r.string()
		if err != nil {
			return err
		}
		values = append(values, FindingControlRefSnapshot{FrameworkName: frameworkName, ControlID: controlID})
		return nil
	}); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, nil
	}
	return values, nil
}

func (r *avroReader) stringMap() (map[string]string, error) {
	values := make(map[string]string)
	if err := r.readMap(func(key string) error {
		value, err := r.string()
		if err != nil {
			return err
		}
		values[key] = value
		return nil
	}); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, nil
	}
	return values, nil
}

func (r *avroReader) metadataMap() (map[string]any, error) {
	values := make(map[string]any)
	if err := r.readMap(func(key string) error {
		value, err := r.metadataValue()
		if err != nil {
			return err
		}
		if value != nil {
			values[key] = value
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, nil
	}
	return values, nil
}

func (r *avroReader) metadataValue() (any, error) {
	index, err := r.long()
	if err != nil {
		return nil, err
	}
	switch index {
	case 0:
		return nil, nil
	case 1:
		return r.string()
	case 2:
		return r.long()
	case 3:
		return r.double()
	case 4:
		return r.boolean()
	default:
		return nil, fmt.Errorf("invalid metadata union index %d", index)
	}
}

func (r *avroReader) readArray(readItem func() error) error {
	for {
		count, err := r.long()
		if err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
		if count < 0 {
			count = -count
			if _, err := r.long(); err != nil {
				return err
			}
		}
		for i := int64(0); i < count; i++ {
			if err := readItem(); err != nil {
				return err
			}
		}
	}
}

func (r *avroReader) readMap(readItem func(key string) error) error {
	for {
		count, err := r.long()
		if err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
		if count < 0 {
			count = -count
			if _, err := r.long(); err != nil {
				return err
			}
		}
		for i := int64(0); i < count; i++ {
			key, err := r.string()
			if err != nil {
				return err
			}
			if err := readItem(key); err != nil {
				return err
			}
		}
	}
}

func setDefaultAttribute(attrs map[string]string, key string, value string) {
	if strings.TrimSpace(attrs[key]) == "" && strings.TrimSpace(value) != "" {
		attrs[key] = strings.TrimSpace(value)
	}
}

func schemaForKind(kind string) string {
	switch strings.TrimSpace(kind) {
	case EventKindKnowledgeDecisionRecorded:
		return SchemaKnowledgeDecisionRecorded
	case EventKindKnowledgeActionRecorded:
		return SchemaKnowledgeActionRecorded
	case EventKindKnowledgeOutcomeRecorded:
		return SchemaKnowledgeOutcomeRecorded
	case EventKindFindingRecorded:
		return SchemaFindingRecorded
	case EventKindFindingNoteAdded:
		return SchemaFindingNoteAdded
	case EventKindFindingTicketLinked:
		return SchemaFindingTicketLinked
	case EventKindFindingExternalRefLinked:
		return SchemaFindingExternalRefLinked
	case EventKindFindingStatusChanged:
		return SchemaFindingStatusChanged
	case EventKindFindingTombstoned:
		return SchemaFindingTombstoned
	default:
		return ""
	}
}
