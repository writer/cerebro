package auditevents

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestAuditEventV1FieldAllowlist(t *testing.T) {
	typeOfEvent := reflect.TypeOf(ports.AuditEventV1{})
	want := []string{
		"ID", "TenantID", "Action", "Actor", "Category", "DurationMS", "OccurredAt",
		"Outcome", "RequestID", "Resource", "Service", "Summary", "TraceID",
	}
	if typeOfEvent.NumField() != len(want) {
		t.Fatalf("AuditEventV1 field count = %d, want %d", typeOfEvent.NumField(), len(want))
	}
	for index, field := range want {
		if got := typeOfEvent.Field(index).Name; got != field {
			t.Fatalf("AuditEventV1 field[%d] = %q, want %q", index, got, field)
		}
	}
}

func TestNormalizeRejectsFieldsOutsideBounds(t *testing.T) {
	event := validEvent()
	event.Summary = strings.Repeat("界", MaxSummaryCharacters+1)
	if _, err := Normalize(event); !errors.Is(err, ports.ErrAuditEventInvalid) {
		t.Fatalf("Normalize() error = %v, want ErrAuditEventInvalid", err)
	}
}

func TestNormalizeCountsUnicodeCodePoints(t *testing.T) {
	event := validEvent()
	event.ID = strings.Repeat("🧠", MaxIdentifierCharacters)
	event.Summary = strings.Repeat("界", MaxSummaryCharacters)
	if _, err := Normalize(event); err != nil {
		t.Fatalf("Normalize(multibyte max) error = %v", err)
	}
	event.ID += "🧠"
	if _, err := Normalize(event); !errors.Is(err, ports.ErrAuditEventInvalid) {
		t.Fatalf("Normalize(multibyte over max) error = %v", err)
	}
	event = validEvent()
	event.Summary = string([]byte{0xff})
	if _, err := Normalize(event); !errors.Is(err, ports.ErrAuditEventInvalid) {
		t.Fatalf("Normalize(invalid UTF-8) error = %v", err)
	}
}

func TestNormalizeCopiesAndCanonicalizesAllowlistedFields(t *testing.T) {
	duration := int64(42)
	event := validEvent()
	event.Outcome = " SUCCESS "
	event.DurationMS = &duration
	event.Actor = &ports.AuditEventActorV1{ID: " actor-1 ", Label: " Operator "}
	normalized, err := Normalize(event)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if normalized.Outcome != ports.AuditEventOutcomeSuccess || normalized.Actor.ID != "actor-1" {
		t.Fatalf("Normalize() = %+v", normalized)
	}
	event.Actor.ID = "mutated"
	duration = 99
	if normalized.Actor.ID != "actor-1" || *normalized.DurationMS != 42 {
		t.Fatal("Normalize() retained mutable input references")
	}
}

func TestDigestIsStableAndCoversAllowlist(t *testing.T) {
	first, err := Digest(validEvent())
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	again, err := Digest(validEvent())
	if err != nil || again != first {
		t.Fatalf("Digest() = %q, %v; want %q", again, err, first)
	}
	changed := validEvent()
	changed.TraceID = "trace-2"
	other, err := Digest(changed)
	if err != nil {
		t.Fatalf("Digest(changed) error = %v", err)
	}
	if other == first {
		t.Fatal("Digest() ignored an allowlisted field")
	}
}

func TestValidateQueryRequiresStableWindowAndBoundary(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	query := ports.AuditEventQueryV1{TenantID: "tenant-a", After: now.Add(-time.Hour), Before: now, Limit: 100}
	if err := ValidateQuery(query); err != nil {
		t.Fatalf("ValidateQuery() error = %v", err)
	}
	query.PageBeforeID = "event-1"
	if err := ValidateQuery(query); !errors.Is(err, ports.ErrAuditEventInvalid) {
		t.Fatalf("ValidateQuery() error = %v, want invalid boundary", err)
	}
}

func validEvent() *ports.AuditEventV1 {
	return &ports.AuditEventV1{
		ID: "event-1", TenantID: "tenant-a", Action: "policy.read",
		OccurredAt: time.Date(2026, 7, 18, 11, 30, 0, 0, time.UTC),
		Outcome:    ports.AuditEventOutcomeSuccess, TraceID: "trace-1",
	}
}
