package auditevents

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/ports"
)

const (
	MaxIdentifierCharacters = 200
	MaxSummaryCharacters    = 500
	MaxQueryCharacters      = 200
	MaxCursorCharacters     = 2048
	DefaultLimit            = 100
	MaxLimit                = 500
	DefaultMinutes          = 60
	MinMinutes              = 5
	MaxMinutes              = 24 * 60
)

// Normalize validates and copies one event into the fixed public allowlist.
func Normalize(input *ports.AuditEventV1) (*ports.AuditEventV1, error) {
	if input == nil {
		return nil, fmt.Errorf("%w: record is required", ports.ErrAuditEventInvalid)
	}
	event := *input
	var err error
	if event.ID, err = requiredIdentifierText("id", event.ID); err != nil {
		return nil, err
	}
	if event.TenantID, err = requiredIdentifierText("tenant_id", event.TenantID); err != nil {
		return nil, err
	}
	if event.Action, err = requiredIdentifierText("action", event.Action); err != nil {
		return nil, err
	}
	if event.Category, err = optionalText("category", event.Category, MaxIdentifierCharacters); err != nil {
		return nil, err
	}
	if event.RequestID, err = optionalText("request_id", event.RequestID, MaxIdentifierCharacters); err != nil {
		return nil, err
	}
	if event.Service, err = optionalText("service", event.Service, MaxIdentifierCharacters); err != nil {
		return nil, err
	}
	if event.Summary, err = optionalText("summary", event.Summary, MaxSummaryCharacters); err != nil {
		return nil, err
	}
	if event.TraceID, err = optionalText("trace_id", event.TraceID, MaxIdentifierCharacters); err != nil {
		return nil, err
	}
	event.Outcome = strings.ToLower(strings.TrimSpace(event.Outcome))
	if !ValidOutcome(event.Outcome) {
		return nil, fmt.Errorf("%w: outcome must be success, failure, denied, or unknown", ports.ErrAuditEventInvalid)
	}
	if event.OccurredAt.IsZero() {
		return nil, fmt.Errorf("%w: occurred_at is required", ports.ErrAuditEventInvalid)
	}
	event.OccurredAt = event.OccurredAt.UTC()
	if event.DurationMS != nil {
		if *event.DurationMS < 0 {
			return nil, fmt.Errorf("%w: duration_ms must be non-negative", ports.ErrAuditEventInvalid)
		}
		duration := *event.DurationMS
		event.DurationMS = &duration
	}
	event.Actor, err = normalizeActor(event.Actor)
	if err != nil {
		return nil, err
	}
	event.Resource, err = normalizeResource(event.Resource)
	if err != nil {
		return nil, err
	}
	return &event, nil
}

// ValidateQuery enforces the tenant, time-window, keyset, and limit invariants
// expected by every reader implementation.
func ValidateQuery(query ports.AuditEventQueryV1) error {
	if strings.TrimSpace(query.TenantID) == "" {
		return fmt.Errorf("%w: tenant_id is required", ports.ErrAuditEventInvalid)
	}
	if _, err := requiredIdentifierText("tenant_id", query.TenantID); err != nil {
		return err
	}
	if query.After.IsZero() || query.Before.IsZero() || !query.After.Before(query.Before) {
		return fmt.Errorf("%w: valid after and before times are required", ports.ErrAuditEventInvalid)
	}
	if query.Before.Sub(query.After) > time.Duration(MaxMinutes)*time.Minute {
		return fmt.Errorf("%w: time window must not exceed %d minutes", ports.ErrAuditEventInvalid, MaxMinutes)
	}
	if query.Limit == 0 || query.Limit > MaxLimit {
		return fmt.Errorf("%w: limit must be between 1 and %d", ports.ErrAuditEventInvalid, MaxLimit)
	}
	if !query.PageBeforeOccurredAt.IsZero() && strings.TrimSpace(query.PageBeforeID) == "" {
		return fmt.Errorf("%w: page boundary id is required", ports.ErrAuditEventInvalid)
	}
	if query.PageBeforeOccurredAt.IsZero() && strings.TrimSpace(query.PageBeforeID) != "" {
		return fmt.Errorf("%w: page boundary time is required", ports.ErrAuditEventInvalid)
	}
	if _, err := optionalText("page boundary id", query.PageBeforeID, MaxIdentifierCharacters); err != nil {
		return err
	}
	if !query.PageBeforeOccurredAt.IsZero() &&
		(query.PageBeforeOccurredAt.Before(query.After) || query.PageBeforeOccurredAt.After(query.Before)) {
		return fmt.Errorf("%w: page boundary is outside the query window", ports.ErrAuditEventInvalid)
	}
	if query.Outcome != "" && !ValidOutcome(query.Outcome) {
		return fmt.Errorf("%w: invalid outcome filter", ports.ErrAuditEventInvalid)
	}
	for field, value := range map[string]string{
		"action": query.Action, "actor": query.Actor, "q": query.Query,
		"resource_type": query.ResourceType, "service": query.Service, "trace_id": query.TraceID,
	} {
		if _, err := optionalText(field, value, MaxQueryCharacters); err != nil {
			return err
		}
	}
	return nil
}

func ValidOutcome(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ports.AuditEventOutcomeSuccess, ports.AuditEventOutcomeFailure, ports.AuditEventOutcomeDenied, ports.AuditEventOutcomeUnknown:
		return true
	default:
		return false
	}
}

// Digest binds an event identity to the complete normalized persistence
// allowlist, making projection idempotency checks stable without permitting
// rewrites.
func Digest(event *ports.AuditEventV1) (string, error) {
	normalized, err := Normalize(event)
	if err != nil {
		return "", err
	}
	parts := []string{
		normalized.ID, normalized.TenantID, normalized.Action, normalized.Category,
		normalized.OccurredAt.Format(time.RFC3339Nano), normalized.Outcome,
		normalized.RequestID, normalized.Service, normalized.Summary, normalized.TraceID,
	}
	if normalized.Actor != nil {
		parts = append(parts, normalized.Actor.ID, normalized.Actor.Kind, normalized.Actor.Label)
	} else {
		parts = append(parts, "", "", "")
	}
	if normalized.Resource != nil {
		parts = append(parts, normalized.Resource.ID, normalized.Resource.Type, normalized.Resource.Label)
	} else {
		parts = append(parts, "", "", "")
	}
	if normalized.DurationMS == nil {
		parts = append(parts, "")
	} else {
		parts = append(parts, fmt.Sprintf("%d", *normalized.DurationMS))
	}
	hash := sha256.New()
	for _, part := range parts {
		_, _ = fmt.Fprintf(hash, "%d:", len(part))
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func normalizeActor(actor *ports.AuditEventActorV1) (*ports.AuditEventActorV1, error) {
	if actor == nil {
		return nil, nil
	}
	copy := *actor
	var err error
	if copy.ID, err = optionalText("actor.id", copy.ID, MaxIdentifierCharacters); err != nil {
		return nil, err
	}
	if copy.Kind, err = optionalText("actor.kind", copy.Kind, MaxIdentifierCharacters); err != nil {
		return nil, err
	}
	if copy.Label, err = optionalText("actor.label", copy.Label, MaxIdentifierCharacters); err != nil {
		return nil, err
	}
	if copy.ID == "" && copy.Kind == "" && copy.Label == "" {
		return nil, nil
	}
	return &copy, nil
}

func normalizeResource(resource *ports.AuditEventResourceV1) (*ports.AuditEventResourceV1, error) {
	if resource == nil {
		return nil, nil
	}
	copy := *resource
	var err error
	if copy.ID, err = optionalText("resource.id", copy.ID, MaxIdentifierCharacters); err != nil {
		return nil, err
	}
	if copy.Type, err = optionalText("resource.type", copy.Type, MaxIdentifierCharacters); err != nil {
		return nil, err
	}
	if copy.Label, err = optionalText("resource.label", copy.Label, MaxIdentifierCharacters); err != nil {
		return nil, err
	}
	if copy.ID == "" && copy.Type == "" && copy.Label == "" {
		return nil, nil
	}
	return &copy, nil
}

func requiredIdentifierText(field string, value string) (string, error) {
	value, err := optionalText(field, value, MaxIdentifierCharacters)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", fmt.Errorf("%w: %s is required", ports.ErrAuditEventInvalid, field)
	}
	return value, nil
}

func optionalText(field string, value string, maxCharacters int) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%w: %s must be valid UTF-8", ports.ErrAuditEventInvalid, field)
	}
	if utf8.RuneCountInString(value) > maxCharacters {
		return "", fmt.Errorf("%w: %s must be at most %d characters", ports.ErrAuditEventInvalid, field, maxCharacters)
	}
	return value, nil
}

func IsInvalid(err error) bool {
	return errors.Is(err, ports.ErrAuditEventInvalid)
}
