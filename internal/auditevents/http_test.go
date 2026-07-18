package auditevents

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestHTTPQueryCursorPreservesWindowAndFilters(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	values := url.Values{"minutes": {"30"}, "action": {"record.read"}, "limit": {"1"}}
	query, err := ParseHTTPQuery(values, "tenant-a", now)
	if err != nil {
		t.Fatalf("ParseHTTPQuery() error = %v", err)
	}
	event := validEvent()
	event.Action = "record.read"
	event.OccurredAt = now.Add(-time.Minute)
	page, err := NewHTTPPage(query, ports.AuditEventPageV1{Events: []*ports.AuditEventV1{event}, HasMore: true})
	if err != nil {
		t.Fatalf("NewHTTPPage() error = %v", err)
	}
	values.Set("cursor", page.NextCursor)
	next, err := ParseHTTPQuery(values, "tenant-a", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ParseHTTPQuery(cursor) error = %v", err)
	}
	if !next.After.Equal(query.After) || !next.Before.Equal(query.Before) || next.PageBeforeID != event.ID {
		t.Fatalf("cursor query = %+v; first = %+v", next, query)
	}
	values.Set("action", "record.write")
	if _, err := ParseHTTPQuery(values, "tenant-a", now.Add(time.Minute)); !errors.Is(err, ports.ErrAuditEventInvalid) {
		t.Fatalf("changed-filter cursor error = %v", err)
	}
}

func TestHTTPQueryRejectsExpiredCursor(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	query, err := ParseHTTPQuery(url.Values{}, "tenant-a", now)
	if err != nil {
		t.Fatalf("ParseHTTPQuery() error = %v", err)
	}
	event := validEvent()
	event.OccurredAt = now.Add(-time.Minute)
	page, err := NewHTTPPage(query, ports.AuditEventPageV1{Events: []*ports.AuditEventV1{event}, HasMore: true})
	if err != nil {
		t.Fatalf("NewHTTPPage() error = %v", err)
	}
	values := url.Values{"cursor": {page.NextCursor}}
	if _, err := ParseHTTPQuery(values, "tenant-a", now.Add(auditEventCursorMaxAge+time.Second)); !errors.Is(err, ports.ErrAuditEventInvalid) {
		t.Fatalf("expired cursor error = %v", err)
	}
}

func TestNewHTTPPageRejectsInvalidReaderResults(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	query := ports.AuditEventQueryV1{TenantID: "tenant-a", After: now.Add(-time.Hour), Before: now, Limit: 10}
	wrongTenant := validEvent()
	wrongTenant.TenantID = "tenant-b"
	if _, err := NewHTTPPage(query, ports.AuditEventPageV1{Events: []*ports.AuditEventV1{wrongTenant}}); err == nil {
		t.Fatal("NewHTTPPage(wrong tenant) error = nil")
	}
	if _, err := NewHTTPPage(query, ports.AuditEventPageV1{HasMore: true}); err == nil {
		t.Fatal("NewHTTPPage(empty nonterminal page) error = nil")
	}
	newer := validEvent()
	newer.ID = "event-2"
	newer.OccurredAt = now.Add(-time.Minute)
	older := validEvent()
	older.OccurredAt = now.Add(-30 * time.Minute)
	if _, err := NewHTTPPage(query, ports.AuditEventPageV1{Events: []*ports.AuditEventV1{older, newer}}); err == nil {
		t.Fatal("NewHTTPPage(out of order) error = nil")
	}
	outside := validEvent()
	outside.OccurredAt = now.Add(time.Second)
	if _, err := NewHTTPPage(query, ports.AuditEventPageV1{Events: []*ports.AuditEventV1{outside}}); err == nil {
		t.Fatal("NewHTTPPage(outside window) error = nil")
	}
}
