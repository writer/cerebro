package workflowevents

import (
	"errors"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// Sentinel errors returned when a FindingExternalRefLinked payload omits a required field.
var (
	ErrFindingExternalRefFindingIDRequired  = errors.New("finding external ref finding_id is required")
	ErrFindingExternalRefSystemRequired     = errors.New("finding external ref system is required")
	ErrFindingExternalRefKindRequired       = errors.New("finding external ref kind is required")
	ErrFindingExternalRefExternalIDRequired = errors.New("finding external ref external_id is required")
	ErrFindingExternalRefLinkedAtRequired   = errors.New("finding external ref linked_at is required")
)

const (
	EventKindFindingExternalRefLinked = "workflow.v1.finding.external_ref_linked"
	SchemaFindingExternalRefLinked    = "urn:cerebro:events/workflow.finding.external_ref_linked/v1"
)

func init() {
	registerKind(EventKindFindingExternalRefLinked, SchemaFindingExternalRefLinked)
}

// FindingExternalRefLinked captures one durable source-native lifecycle reference attached to a finding.
type FindingExternalRefLinked struct {
	Finding              FindingSnapshot `json:"finding"`
	System               string          `json:"system"`
	Kind                 string          `json:"kind"`
	ExternalID           string          `json:"external_id"`
	URL                  string          `json:"url,omitempty"`
	ExternalStatus       string          `json:"external_status,omitempty"`
	ExternalStatusReason string          `json:"external_status_reason,omitempty"`
	LifecycleOwner       string          `json:"lifecycle_owner,omitempty"`
	LinkedAt             string          `json:"linked_at"`
}

// NewFindingExternalRefLinkedEvent builds the durable event envelope for one finding external reference.
func NewFindingExternalRefLinkedEvent(payload FindingExternalRefLinked) (*cerebrov1.EventEnvelope, error) {
	if err := validateFindingExternalRefLinked(&payload); err != nil {
		return nil, err
	}
	primaryID := strings.Join([]string{
		payload.Finding.FindingID,
		payload.System,
		payload.Kind,
		payload.ExternalID,
	}, "|")
	return newEvent(registryFindingExternalRefLinked(payload), SchemaFindingExternalRefLinked, payload.Finding.TenantID, payload.Finding.SourceSystem, primaryID, payload.LinkedAt, map[string]string{
		EventAttributeWorkflowKind: "finding_external_ref",
		EventAttributeFindingID:    payload.Finding.FindingID,
		"external_system":          payload.System,
		"external_kind":            payload.Kind,
		"external_id":              payload.ExternalID,
		"lifecycle_owner":          payload.LifecycleOwner,
	})
}

// DecodeFindingExternalRefLinked decodes a finding external reference event payload and enforces required fields.
func DecodeFindingExternalRefLinked(event *cerebrov1.EventEnvelope) (*FindingExternalRefLinked, error) {
	payload := &FindingExternalRefLinked{}
	if err := decodePayload(event, EventKindFindingExternalRefLinked, payload); err != nil {
		return nil, err
	}
	if err := validateFindingExternalRefLinked(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func validateFindingExternalRefLinked(payload *FindingExternalRefLinked) error {
	if payload == nil {
		return fmt.Errorf("finding external ref payload is required")
	}
	if strings.TrimSpace(payload.Finding.FindingID) == "" {
		return ErrFindingExternalRefFindingIDRequired
	}
	if strings.TrimSpace(payload.System) == "" {
		return ErrFindingExternalRefSystemRequired
	}
	if strings.TrimSpace(payload.Kind) == "" {
		return ErrFindingExternalRefKindRequired
	}
	if strings.TrimSpace(payload.ExternalID) == "" {
		return ErrFindingExternalRefExternalIDRequired
	}
	if strings.TrimSpace(payload.LinkedAt) == "" {
		return ErrFindingExternalRefLinkedAtRequired
	}
	return nil
}
