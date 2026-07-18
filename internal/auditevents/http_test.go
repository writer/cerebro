package auditevents

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
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

func TestHTTPQueryCursorChecksumCoversKeysetBoundary(t *testing.T) {
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
	cursor, err := decodeCursor(page.NextCursor)
	if err != nil {
		t.Fatalf("decodeCursor() error = %v", err)
	}
	cursor.LastID = "different-boundary"
	payload, err := json.Marshal(cursor)
	if err != nil {
		t.Fatalf("json.Marshal(cursor) error = %v", err)
	}
	values := url.Values{"cursor": {base64.RawURLEncoding.EncodeToString(payload)}}
	if _, err := ParseHTTPQuery(values, "tenant-a", now); !errors.Is(err, ports.ErrAuditEventInvalid) {
		t.Fatalf("modified boundary error = %v", err)
	}
}

func TestHTTPQueryAndCursorAcceptMaximumMultibyteText(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	queryText := strings.Repeat("界", MaxQueryCharacters)
	query, err := ParseHTTPQuery(url.Values{"q": {queryText}}, "tenant-a", now)
	if err != nil {
		t.Fatalf("ParseHTTPQuery(multibyte max) error = %v", err)
	}
	event := validEvent()
	event.ID = strings.Repeat("🧠", MaxIdentifierCharacters)
	event.OccurredAt = now.Add(-time.Minute)
	page, err := NewHTTPPage(query, ports.AuditEventPageV1{Events: []*ports.AuditEventV1{event}, HasMore: true})
	if err != nil {
		t.Fatalf("NewHTTPPage(multibyte boundary) error = %v", err)
	}
	if len(page.NextCursor) <= 1024 || len(page.NextCursor) > MaxCursorCharacters {
		t.Fatalf("next_cursor length = %d", len(page.NextCursor))
	}
	values := url.Values{"q": {queryText}, "cursor": {page.NextCursor}}
	if _, err := ParseHTTPQuery(values, "tenant-a", now); err != nil {
		t.Fatalf("ParseHTTPQuery(multibyte cursor) error = %v", err)
	}
	if _, err := ParseHTTPQuery(url.Values{"q": {queryText + "界"}}, "tenant-a", now); !errors.Is(err, ports.ErrAuditEventInvalid) {
		t.Fatalf("ParseHTTPQuery(multibyte over max) error = %v", err)
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

func TestNewHTTPPageRequiresEventsStrictlyOlderThanResumeBoundary(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	boundaryTime := now.Add(-10 * time.Minute)
	query := ports.AuditEventQueryV1{
		TenantID: "tenant-a", After: now.Add(-time.Hour), Before: now, Limit: 10,
		PageBeforeOccurredAt: boundaryTime, PageBeforeID: "event-5",
	}
	for _, tc := range []struct {
		name       string
		occurredAt time.Time
		id         string
		wantError  bool
	}{
		{name: "same event", occurredAt: boundaryTime, id: "event-5", wantError: true},
		{name: "same time greater id", occurredAt: boundaryTime, id: "event-6", wantError: true},
		{name: "newer time", occurredAt: boundaryTime.Add(time.Second), id: "event-1", wantError: true},
		{name: "same time smaller id", occurredAt: boundaryTime, id: "event-4"},
		{name: "older time", occurredAt: boundaryTime.Add(-time.Second), id: "event-9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := validEvent()
			event.ID = tc.id
			event.OccurredAt = tc.occurredAt
			_, err := NewHTTPPage(query, ports.AuditEventPageV1{Events: []*ports.AuditEventV1{event}})
			if (err != nil) != tc.wantError {
				t.Fatalf("NewHTTPPage() error = %v, wantError = %v", err, tc.wantError)
			}
		})
	}
}
