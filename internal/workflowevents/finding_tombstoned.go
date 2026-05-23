package workflowevents

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// Sentinel errors returned when a FindingTombstoned payload omits a required field.
var (
	ErrFindingTombstonedFindingIDRequired   = errors.New("finding tombstoned finding_id is required")
	ErrFindingTombstonedRunIDRequired       = errors.New("finding tombstoned run_id is required")
	ErrFindingTombstonedPriorStatusRequired = errors.New("finding tombstoned prior_status is required")
	ErrFindingTombstonedActorRequired       = errors.New("finding tombstoned actor is required")
	ErrFindingTombstonedReasonRequired      = errors.New("finding tombstoned reason is required")
	ErrFindingTombstonedTimestampRequired   = errors.New("finding tombstoned tombstoned_at is required")
)

const (
	EventKindFindingTombstoned = "workflow.v1.finding.tombstoned"
	SchemaFindingTombstoned    = "urn:cerebro:events/workflow.finding.tombstoned/v1"
)

func init() {
	registerKind(EventKindFindingTombstoned, SchemaFindingTombstoned)
}

// FindingTombstoned captures one durable finding tombstone event payload.
type FindingTombstoned struct {
	Finding      FindingSnapshot `json:"finding"`
	PriorStatus  string          `json:"prior_status"`
	Reason       string          `json:"reason"`
	Actor        string          `json:"actor"`
	RunID        string          `json:"run_id"`
	TombstonedAt string          `json:"tombstoned_at"`
}

// NewFindingTombstonedEvent builds the durable event envelope for one finding tombstone.
func NewFindingTombstonedEvent(payload FindingTombstoned) (*cerebrov1.EventEnvelope, error) {
	if err := validateFindingTombstoned(&payload); err != nil {
		return nil, err
	}
	tenantID := strings.TrimSpace(payload.Finding.TenantID)
	sourceSystem := strings.TrimSpace(payload.Finding.SourceSystem)
	if tenantID == "" {
		return nil, fmt.Errorf("workflow event tenant id is required")
	}
	if sourceSystem == "" {
		return nil, fmt.Errorf("workflow event source system is required")
	}
	occurredAt, err := parseEventTime(payload.TombstonedAt)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode finding tombstoned payload: %w", err)
	}
	primaryID := payload.Finding.FindingID + "|" + payload.RunID
	attributes := map[string]string{
		EventAttributeTenantID:     tenantID,
		EventAttributeSourceSystem: sourceSystem,
		EventAttributeWorkflowKind: "finding_tombstoned",
		EventAttributeFindingID:    payload.Finding.FindingID,
		"event_type":               EventKindFindingTombstoned,
	}
	return &cerebrov1.EventEnvelope{
		Id:         eventID(tenantID, EventKindFindingTombstoned, primaryID),
		TenantId:   tenantID,
		SourceId:   sourceSystem,
		Kind:       EventKindFindingTombstoned,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  SchemaFindingTombstoned,
		Payload:    body,
		Attributes: attributes,
	}, nil
}

// DecodeFindingTombstoned decodes a finding tombstone event payload and enforces required fields.
func DecodeFindingTombstoned(event *cerebrov1.EventEnvelope) (*FindingTombstoned, error) {
	payload := &FindingTombstoned{}
	if err := decodePayload(event, EventKindFindingTombstoned, payload); err != nil {
		return nil, err
	}
	if err := validateFindingTombstoned(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func validateFindingTombstoned(payload *FindingTombstoned) error {
	if payload == nil {
		return fmt.Errorf("finding tombstoned payload is required")
	}
	if strings.TrimSpace(payload.Finding.FindingID) == "" {
		return ErrFindingTombstonedFindingIDRequired
	}
	if strings.TrimSpace(payload.RunID) == "" {
		return ErrFindingTombstonedRunIDRequired
	}
	if strings.TrimSpace(payload.PriorStatus) == "" {
		return ErrFindingTombstonedPriorStatusRequired
	}
	if strings.TrimSpace(payload.Actor) == "" {
		return ErrFindingTombstonedActorRequired
	}
	if strings.TrimSpace(payload.Reason) == "" {
		return ErrFindingTombstonedReasonRequired
	}
	if strings.TrimSpace(payload.TombstonedAt) == "" {
		return ErrFindingTombstonedTimestampRequired
	}
	return nil
}
