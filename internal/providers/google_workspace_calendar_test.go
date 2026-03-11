package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGoogleWorkspaceProviderListCalendarActivity_NormalizesAndDedupes(t *testing.T) {
	t.Parallel()

	since := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	calendarCalls := 0

	provider := NewGoogleWorkspaceProvider()
	provider.domain = "example.com"
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.URL.Path == "/admin/directory/v1/users":
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"users": []map[string]interface{}{
					{"id": "u-1", "primaryEmail": "user-1@example.com", "suspended": false},
					{"id": "u-2", "primaryEmail": "user-2@example.com", "suspended": false},
				},
			})
		case strings.HasPrefix(req.URL.Path, "/calendar/v3/calendars/") && strings.HasSuffix(req.URL.Path, "/events"):
			calendarCalls++
			if got := req.URL.Query().Get("timeMin"); got != since.Format(time.RFC3339) {
				t.Fatalf("expected timeMin=%q, got %q", since.Format(time.RFC3339), got)
			}

			calendarID := strings.TrimPrefix(req.URL.Path, "/calendar/v3/calendars/")
			calendarID = strings.TrimSuffix(calendarID, "/events")
			if decoded, err := url.PathUnescape(calendarID); err == nil {
				calendarID = decoded
			}

			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"items": []map[string]interface{}{
					{
						"id":      "event-1-" + calendarID,
						"iCalUID": "evt-1@example.com",
						"summary": "Platform Weekly",
						"start":   map[string]interface{}{"dateTime": "2026-02-02T10:00:00Z"},
						"end":     map[string]interface{}{"dateTime": "2026-02-02T11:00:00Z"},
						"organizer": map[string]interface{}{
							"email": "manager@example.com",
						},
						"attendees": []map[string]interface{}{
							{"email": "user-1@example.com", "responseStatus": "accepted", "self": true},
							{"email": "manager@example.com", "responseStatus": "accepted", "organizer": true},
						},
						"recurrence": []string{"RRULE:FREQ=WEEKLY;BYDAY=MO"},
						"created":    "2026-01-20T00:00:00Z",
						"updated":    "2026-01-30T00:00:00Z",
					},
				},
			})
		default:
			t.Fatalf("unexpected request path: %s", req.URL.Path)
			return nil, nil
		}
	})}

	eventRows, attendeeRows, err := provider.listCalendarActivity(context.Background(), since)
	if err != nil {
		t.Fatalf("listCalendarActivity failed: %v", err)
	}
	if calendarCalls != 2 {
		t.Fatalf("expected 2 calendar calls (one per user), got %d", calendarCalls)
	}
	if len(eventRows) != 1 {
		t.Fatalf("expected deduped 1 event row, got %d", len(eventRows))
	}
	if len(attendeeRows) != 2 {
		t.Fatalf("expected deduped 2 attendee rows, got %d", len(attendeeRows))
	}

	event := eventRows[0]
	if got := asString(event["id"]); got != "evt-1@example.com" {
		t.Fatalf("expected canonical iCalUID event id, got %q", got)
	}
	if got := asString(event["calendar_id"]); got != "user-1@example.com" {
		t.Fatalf("expected first calendar owner to seed calendar_id, got %q", got)
	}
	if got := asString(event["organizer_email"]); got != "manager@example.com" {
		t.Fatalf("expected organizer_email manager@example.com, got %q", got)
	}

	expectedHashBytes := sha256.Sum256([]byte("Platform Weekly"))
	expectedHash := hex.EncodeToString(expectedHashBytes[:])
	if got := asString(event["title_hash"]); got != expectedHash {
		t.Fatalf("expected title_hash %q, got %q", expectedHash, got)
	}
	if got := asString(event["start_time"]); got != "2026-02-02T10:00:00Z" {
		t.Fatalf("unexpected start_time: %q", got)
	}
	if got, ok := asInt(event["duration_minutes"]); !ok || got != 60 {
		t.Fatalf("expected duration_minutes=60, got %v (ok=%v)", event["duration_minutes"], ok)
	}
	if got := asString(event["recurrence_pattern"]); got != "RRULE:FREQ=WEEKLY;BYDAY=MO" {
		t.Fatalf("unexpected recurrence_pattern: %q", got)
	}
	if got, ok := event["is_recurring"].(bool); !ok || !got {
		t.Fatalf("expected is_recurring=true, got %v (ok=%v)", event["is_recurring"], ok)
	}
	if got := asString(event["response_status"]); got != "accepted" {
		t.Fatalf("expected response_status accepted, got %q", got)
	}
	if got, ok := asInt(event["attendee_count"]); !ok || got != 2 {
		t.Fatalf("expected attendee_count=2, got %v (ok=%v)", event["attendee_count"], ok)
	}
	if _, exists := event["summary"]; exists {
		t.Fatal("event row should not include summary field")
	}
	if _, exists := event["description"]; exists {
		t.Fatal("event row should not include description field")
	}
}

func TestGoogleWorkspaceProviderListCalendarActivity_IgnoresPermissionErrors(t *testing.T) {
	t.Parallel()

	provider := NewGoogleWorkspaceProvider()
	provider.domain = "example.com"
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.URL.Path == "/admin/directory/v1/users":
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"users": []map[string]interface{}{
					{"id": "u-1", "primaryEmail": "locked@example.com", "suspended": false},
					{"id": "u-2", "primaryEmail": "ok@example.com", "suspended": false},
				},
			})
		case strings.Contains(req.URL.Path, "locked@example.com") || strings.Contains(req.URL.Path, "locked%40example.com"):
			return jsonHTTPResponse(http.StatusForbidden, map[string]interface{}{"error": "forbidden"})
		case strings.Contains(req.URL.Path, "ok@example.com") || strings.Contains(req.URL.Path, "ok%40example.com"):
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"items": []map[string]interface{}{
					{
						"id":      "ok-event",
						"iCalUID": "ok-event@example.com",
						"summary": "Security standup",
						"start":   map[string]interface{}{"dateTime": "2026-02-10T09:00:00Z"},
						"end":     map[string]interface{}{"dateTime": "2026-02-10T09:30:00Z"},
						"attendees": []map[string]interface{}{
							{"email": "ok@example.com", "responseStatus": "accepted", "self": true},
						},
					},
				},
			})
		default:
			t.Fatalf("unexpected request path: %s", req.URL.Path)
			return nil, nil
		}
	})}

	eventRows, attendeeRows, err := provider.listCalendarActivity(context.Background(), time.Now().AddDate(0, 0, -30))
	if err != nil {
		t.Fatalf("expected permission-denied calendars to be ignored, got %v", err)
	}
	if len(eventRows) != 1 {
		t.Fatalf("expected 1 event row from accessible calendar, got %d", len(eventRows))
	}
	if len(attendeeRows) != 1 {
		t.Fatalf("expected 1 attendee row from accessible calendar, got %d", len(attendeeRows))
	}
}
