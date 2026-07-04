package sourcecdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

var ErrInvalidEventEnvelope = errors.New("invalid event envelope")

// EventContract captures per-kind schema expectations declared by source catalogs.
type EventContract struct {
	Kind                  string   `json:"kind" yaml:"kind"`
	SchemaRef             string   `json:"schema_ref" yaml:"schema_ref"`
	RequiredAttributes    []string `json:"required_attributes" yaml:"required_attributes"`
	RequiredPayloadFields []string `json:"required_payload_fields" yaml:"required_payload_fields"`
}

const (
	AttributeActorUser     = "actor_user"
	AttributeActorID       = "actor_id"
	AttributeEventType     = "event_type"
	AttributeOutcomeResult = "outcome_result"
	AttributeResourceID    = "resource_id"
	AttributeResourceType  = "resource_type"
	AttributeSourceIP      = "source_ip"
	AttributeUserAgent     = "user_agent"
)

// RecommendedUDMAttributes are the Panther-inspired normalized attributes that
// source events should prefer when mapping provider-specific fields.
var RecommendedUDMAttributes = []string{
	AttributeActorUser,
	AttributeActorID,
	AttributeEventType,
	AttributeOutcomeResult,
	AttributeResourceID,
	AttributeResourceType,
	AttributeSourceIP,
	AttributeUserAgent,
}

// ValidateEventEnvelope enforces the public normalized append-log contract used
// by source fixtures and runtime sync before events enter durable stores.
func ValidateEventEnvelope(event *cerebrov1.EventEnvelope) error {
	if event == nil {
		return fmt.Errorf("%w: event is required", ErrInvalidEventEnvelope)
	}
	for field, value := range map[string]string{
		"id":         event.GetId(),
		"tenant_id":  event.GetTenantId(),
		"source_id":  event.GetSourceId(),
		"kind":       event.GetKind(),
		"schema_ref": event.GetSchemaRef(),
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidEventEnvelope, field)
		}
		if strings.TrimSpace(value) != value {
			return fmt.Errorf("%w: %s must not have leading or trailing whitespace", ErrInvalidEventEnvelope, field)
		}
		if !utf8.ValidString(value) {
			return fmt.Errorf("%w: %s must be valid UTF-8", ErrInvalidEventEnvelope, field)
		}
	}
	if !validEventKind(event.GetKind()) {
		return fmt.Errorf("%w: kind %q must use dot-separated lowercase identifiers", ErrInvalidEventEnvelope, event.GetKind())
	}
	if !validSchemaRef(event.GetSchemaRef()) {
		return fmt.Errorf("%w: schema_ref %q must use source/family/vN format", ErrInvalidEventEnvelope, event.GetSchemaRef())
	}
	if event.GetOccurredAt() == nil {
		return fmt.Errorf("%w: occurred_at is required", ErrInvalidEventEnvelope)
	}
	if err := event.GetOccurredAt().CheckValid(); err != nil {
		return fmt.Errorf("%w: occurred_at is invalid: %w", ErrInvalidEventEnvelope, err)
	}
	if len(event.GetPayload()) == 0 {
		return fmt.Errorf("%w: payload is required", ErrInvalidEventEnvelope)
	}
	if !json.Valid(event.GetPayload()) {
		return fmt.Errorf("%w: payload must be valid JSON", ErrInvalidEventEnvelope)
	}
	for key, value := range event.GetAttributes() {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("%w: attributes must not contain empty keys", ErrInvalidEventEnvelope)
		}
		if strings.TrimSpace(key) != key {
			return fmt.Errorf("%w: attribute key %q must not have leading or trailing whitespace", ErrInvalidEventEnvelope, key)
		}
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			return fmt.Errorf("%w: attributes must be valid UTF-8", ErrInvalidEventEnvelope)
		}
	}
	return nil
}

// ValidateEventEnvelopeWithContracts enforces the generic envelope contract and
// the matching source catalog contract when one is provided for the event kind.
func ValidateEventEnvelopeWithContracts(event *cerebrov1.EventEnvelope, contracts []EventContract) error {
	if err := ValidateEventEnvelope(event); err != nil {
		return err
	}
	for _, contract := range contracts {
		normalized, err := NormalizeEventContract(contract)
		if err != nil {
			return err
		}
		if normalized.Kind != event.GetKind() {
			continue
		}
		if normalized.SchemaRef != "" && normalized.SchemaRef != event.GetSchemaRef() {
			return fmt.Errorf("%w: kind %q schema_ref %q does not match contract %q", ErrInvalidEventEnvelope, event.GetKind(), event.GetSchemaRef(), normalized.SchemaRef)
		}
		for _, key := range normalized.RequiredAttributes {
			if strings.TrimSpace(event.GetAttributes()[key]) == "" {
				return fmt.Errorf("%w: kind %q missing required attribute %q", ErrInvalidEventEnvelope, event.GetKind(), key)
			}
		}
		var payload any
		if len(normalized.RequiredPayloadFields) != 0 {
			if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
				return fmt.Errorf("%w: payload must be an object for contract validation: %w", ErrInvalidEventEnvelope, err)
			}
		}
		for _, field := range normalized.RequiredPayloadFields {
			if !payloadHasField(payload, field) {
				return fmt.Errorf("%w: kind %q missing required payload field %q", ErrInvalidEventEnvelope, event.GetKind(), field)
			}
		}
		return nil
	}
	if len(contracts) != 0 {
		return fmt.Errorf("%w: kind %q has no matching event contract", ErrInvalidEventEnvelope, event.GetKind())
	}
	return nil
}

func NormalizeEventContract(contract EventContract) (EventContract, error) {
	normalized := EventContract{
		Kind:                  strings.TrimSpace(contract.Kind),
		SchemaRef:             strings.TrimSpace(contract.SchemaRef),
		RequiredAttributes:    uniqueTrimmedStrings(contract.RequiredAttributes),
		RequiredPayloadFields: uniqueTrimmedStrings(contract.RequiredPayloadFields),
	}
	if normalized.Kind == "" {
		return EventContract{}, fmt.Errorf("event_contract kind is required")
	}
	if !validEventKind(normalized.Kind) {
		return EventContract{}, fmt.Errorf("event_contract kind %q must use dot-separated lowercase identifiers", normalized.Kind)
	}
	if normalized.SchemaRef != "" && !validSchemaRef(normalized.SchemaRef) {
		return EventContract{}, fmt.Errorf("event_contract kind %q schema_ref %q must use source/family/vN format", normalized.Kind, normalized.SchemaRef)
	}
	if len(normalized.RequiredAttributes) == 0 && len(normalized.RequiredPayloadFields) == 0 {
		return EventContract{}, fmt.Errorf("event_contract kind %q must require attributes or payload fields", normalized.Kind)
	}
	return normalized, nil
}

func ValidateEventContracts(contracts []EventContract) ([]EventContract, error) {
	normalized := make([]EventContract, 0, len(contracts))
	seen := map[string]struct{}{}
	for _, contract := range contracts {
		next, err := NormalizeEventContract(contract)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[next.Kind]; ok {
			return nil, fmt.Errorf("duplicate event_contract kind %q", next.Kind)
		}
		seen[next.Kind] = struct{}{}
		normalized = append(normalized, next)
	}
	sort.Slice(normalized, func(i int, j int) bool {
		return normalized[i].Kind < normalized[j].Kind
	})
	return normalized, nil
}

func validEventKind(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if !validIdentifierPart(part) {
			return false
		}
	}
	return true
}

func uniqueTrimmedStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func payloadHasField(payload any, path string) bool {
	for _, alternative := range strings.Split(strings.TrimSpace(path), "|") {
		if payloadHasFieldPath(payload, strings.TrimSpace(alternative)) {
			return true
		}
	}
	return false
}

func payloadHasFieldPath(payload any, path string) bool {
	parts := strings.Split(strings.TrimSpace(path), ".")
	if len(parts) == 0 {
		return false
	}
	current := payload
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return false
		}
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		value, ok := object[part]
		if !ok || value == nil {
			return false
		}
		if text, ok := value.(string); ok && strings.TrimSpace(text) == "" {
			return false
		}
		current = value
	}
	return true
}

func validSchemaRef(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) < 3 {
		return false
	}
	for idx, part := range parts {
		if idx == len(parts)-1 {
			if len(part) < 2 || part[0] != 'v' {
				return false
			}
			for _, r := range part[1:] {
				if !unicode.IsDigit(r) {
					return false
				}
			}
			continue
		}
		if !validIdentifierPart(part) {
			return false
		}
	}
	return true
}

func validIdentifierPart(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
