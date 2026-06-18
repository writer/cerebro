package cosmo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestParseSettingsRejectsUnsafeBaseURL(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  "http://169.254.169.254",
		"token":     "token",
	}), false)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want non-nil")
	}
}

func TestParseSettingsRejectsBaseURLWithPath(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  "https://cosmo.example.com/workspace",
		"token":     "token",
	}), false)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want non-nil")
	}
}

func TestParseSettingsMessageRequiresScopedExportConfig(t *testing.T) {
	base := map[string]string{
		"tenant_id":     "writer",
		"base_url":      "https://cosmo.example.com",
		"token":         "token",
		"family":        "message",
		"client_id":     "cerebro-runtime",
		"export_secret": "secret",
		"since":         "2026-05-01T00:00:00Z",
	}
	for _, tc := range []struct {
		name string
		key  string
	}{
		{name: "client id", key: "client_id"},
		{name: "export secret", key: "export_secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cloneMap(base)
			delete(cfg, tc.key)
			_, err := parseSettings(sourcecdk.NewConfig(cfg), false)
			if err == nil {
				t.Fatal("parseSettings() error = nil, want non-nil")
			}
		})
	}
}

func TestParseSettingsMessageRejectsUnscopedOrUnboundedConfig(t *testing.T) {
	base := map[string]string{
		"tenant_id":     "writer",
		"base_url":      "https://cosmo.example.com",
		"token":         "token",
		"family":        "message",
		"client_id":     "cerebro-runtime",
		"export_secret": "secret",
		"since":         "2026-05-01T00:00:00Z",
	}
	for _, tc := range []struct {
		name string
		key  string
		val  string
	}{
		{name: "ticket id", key: "ticket_id", val: "COSMO-1"},
		{name: "page size", key: "per_page", val: "101"},
		{name: "window", key: "max_window_hours", val: "25"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cloneMap(base)
			cfg[tc.key] = tc.val
			_, err := parseSettings(sourcecdk.NewConfig(cfg), false)
			if err == nil {
				t.Fatal("parseSettings() error = nil, want non-nil")
			}
		})
	}
	cfg := cloneMap(base)
	cfg["per_page"] = "100"
	if _, err := parseSettings(sourcecdk.NewConfig(cfg), false); err != nil {
		t.Fatalf("parseSettings(per_page=100) error = %v", err)
	}
}

func TestReadSessionsPaginatesAndMapsAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ui/memory/sessions" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer gh-token" {
			t.Fatalf("Authorization = %q, want bearer token", got)
		}
		if got := r.URL.Query().Get("q"); got != "deploy" {
			t.Fatalf("q = %q, want deploy", got)
		}
		if got := r.URL.Query().Get("user"); got != "U123" {
			t.Fatalf("user = %q, want U123", got)
		}
		if got := r.URL.Query().Get("status"); got != "success" {
			t.Fatalf("status = %q, want success", got)
		}
		sessions := []map[string]any{
			{
				"id":           1,
				"ticket_id":    "COSMO-1",
				"thread_key":   "C123:1710000000.000100",
				"date":         "2026-05-12",
				"user":         "U123",
				"agent_type":   "engineers",
				"task":         "deploy service",
				"outcome":      "fixed",
				"status":       "success",
				"services":     []string{"api"},
				"environments": []string{"prod"},
				"source":       "memory",
			},
			{
				"id":         2,
				"ticket_id":  "COSMO-2",
				"thread_key": "C123:1710000000.000200",
				"date":       "2026-05-13",
				"user":       "U123",
				"task":       "check pod",
				"outcome":    "healthy",
				"status":     "success",
			},
		}
		offset := r.URL.Query().Get("offset")
		if offset == "1" {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": 1, "sessions": sessions[1:]})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": 1, "sessions": sessions[:1]})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "gh-token",
		"family":    "session",
		"q":         "deploy",
		"user":      "U123",
		"status":    "success",
		"per_page":  "1",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if got := first.NextCursor.GetOpaque(); got != "1" {
		t.Fatalf("NextCursor = %q, want 1", got)
	}
	event := first.Events[0]
	if got, want := event.Kind, "cosmo.session"; got != want {
		t.Fatalf("event.Kind = %q, want %q", got, want)
	}
	if got, want := event.Attributes["ticket_id"], "COSMO-1"; got != want {
		t.Fatalf("ticket_id = %q, want %q", got, want)
	}
	if got, want := event.Attributes["thread_key"], "C123:1710000000.000100"; got != want {
		t.Fatalf("thread_key = %q, want %q", got, want)
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
}

func TestReadMessagesUsesScopedExportContractAndPaginatesEventTypes(t *testing.T) {
	var requestCount int
	var windowSince string
	var windowUntil string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cerebro/messages" {
			http.NotFound(w, r)
			return
		}
		requestCount++
		if got := r.Header.Get("Authorization"); got != "Bearer gh-token" {
			t.Fatalf("Authorization = %q, want bearer token", got)
		}
		if got := r.Header.Get("X-Cosmo-Client"); got != "cerebro-runtime" {
			t.Fatalf("X-Cosmo-Client = %q, want approved client", got)
		}
		if got := r.Header.Get("X-Cerebro-Export-Secret"); got != "export-secret" {
			t.Fatalf("X-Cerebro-Export-Secret set = %t, want true", got != "")
		}
		if got := r.URL.Query().Get("ticket_id"); got != "" {
			t.Fatalf("ticket_id = %q, want empty", got)
		}
		if got := r.URL.Query().Get("limit"); got != "1" {
			t.Fatalf("limit = %q, want 1", got)
		}
		since := r.URL.Query().Get("since")
		until := r.URL.Query().Get("until")
		if since == "" || until == "" {
			t.Fatalf("since=%q until=%q, want bounded export window", since, until)
		}
		parsedSince, err := time.Parse(time.RFC3339Nano, since)
		if err != nil {
			t.Fatalf("parse since: %v", err)
		}
		parsedUntil, err := time.Parse(time.RFC3339Nano, until)
		if err != nil {
			t.Fatalf("parse until: %v", err)
		}
		if !parsedUntil.After(parsedSince) || parsedUntil.Sub(parsedSince) > time.Hour {
			t.Fatalf("window = %s..%s, want positive <= 1h", parsedSince, parsedUntil)
		}
		if windowSince == "" {
			windowSince = since
			windowUntil = until
		} else if since != windowSince || until != windowUntil {
			t.Fatalf("window changed: %s..%s, want %s..%s", since, until, windowSince, windowUntil)
		}
		eventType := r.URL.Query().Get("event_type")
		offset := r.URL.Query().Get("offset")
		switch requestCount {
		case 1:
			if eventType != "message" || offset != "0" {
				t.Fatalf("request 1 event_type=%q offset=%q, want message/0", eventType, offset)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": 1, "messages": []map[string]any{
				{
					"id":         10,
					"ticket_id":  "COSMO-1",
					"event_type": "message",
					"role":       "assistant",
					"summary":    "Investigated issue",
					"created_at": "2026-05-12T12:00:00Z",
				},
			}})
		case 2:
			if eventType != "message" || offset != "1" {
				t.Fatalf("request 2 event_type=%q offset=%q, want message/1", eventType, offset)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": 0, "messages": []map[string]any{}})
		case 3:
			if eventType != "completion" || offset != "0" {
				t.Fatalf("request 3 event_type=%q offset=%q, want completion/0", eventType, offset)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": 1, "messages": []map[string]any{
				{
					"id":         11,
					"ticket_id":  "COSMO-2",
					"event_type": "completion",
					"role":       "assistant",
					"summary":    "Completed issue",
					"created_at": "2026-05-12T12:01:00Z",
				},
			}})
		case 4:
			if eventType != "completion" || offset != "1" {
				t.Fatalf("request 4 event_type=%q offset=%q, want completion/1", eventType, offset)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": 0, "messages": []map[string]any{}})
		default:
			t.Fatalf("unexpected request %d", requestCount)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":        "writer",
		"base_url":         server.URL,
		"token":            "gh-token",
		"family":           "message",
		"client_id":        "cerebro-runtime",
		"export_secret":    "export-secret",
		"event_types":      "message,completion",
		"max_window_hours": "1",
		"per_page":         "1",
		"since":            "2026-05-01T00:00:00Z",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	firstCursor := decodeMessageCursor(t, first.NextCursor.GetOpaque())
	if firstCursor.EventTypeIndex != 0 || firstCursor.Offset != 1 || firstCursor.Until == "" {
		t.Fatalf("first cursor = %#v, want message offset 1 with fixed window", firstCursor)
	}
	if got := first.Events[0].Attributes["role"]; got != "assistant" {
		t.Fatalf("role = %q, want assistant", got)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 0 {
		t.Fatalf("len(second.Events) = %d, want 0", len(second.Events))
	}
	secondCursor := decodeMessageCursor(t, second.NextCursor.GetOpaque())
	if secondCursor.EventTypeIndex != 1 || secondCursor.Offset != 0 || secondCursor.Since != windowSince || secondCursor.Until != windowUntil {
		t.Fatalf("second cursor = %#v, want completion offset 0 in same window", secondCursor)
	}
	third, err := source.Read(context.Background(), cfg, second.NextCursor)
	if err != nil {
		t.Fatalf("Read(third) error = %v", err)
	}
	if len(third.Events) != 1 {
		t.Fatalf("len(third.Events) = %d, want 1", len(third.Events))
	}
	if got := third.Events[0].Attributes["event_type"]; got != "completion" {
		t.Fatalf("third event_type = %q, want completion", got)
	}
	fourth, err := source.Read(context.Background(), cfg, third.NextCursor)
	if err != nil {
		t.Fatalf("Read(fourth) error = %v", err)
	}
	if len(fourth.Events) != 0 {
		t.Fatalf("len(fourth.Events) = %d, want 0", len(fourth.Events))
	}
	if fourth.NextCursor != nil {
		t.Fatalf("fourth.NextCursor = %#v, want nil", fourth.NextCursor)
	}
	checkpoint := decodeMessageCursor(t, fourth.Checkpoint.GetCursorOpaque())
	if !checkpoint.ResumableCheckpoint || checkpoint.Until != "" || checkpoint.EventTypeIndex != 0 || checkpoint.Offset != 0 {
		t.Fatalf("checkpoint cursor = %#v, want resumable next-window cursor", checkpoint)
	}
	if checkpoint.Since != windowUntil {
		t.Fatalf("checkpoint since = %q, want previous until %q", checkpoint.Since, windowUntil)
	}
}

func TestReadMessagesStartsFirstWindowAtConfiguredSince(t *testing.T) {
	configuredSince := "2026-05-01T00:00:00Z"
	wantUntil := "2026-05-01T01:00:00Z"
	var sawRequest bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cerebro/messages" {
			http.NotFound(w, r)
			return
		}
		sawRequest = true
		if got := r.URL.Query().Get("since"); got != configuredSince {
			t.Fatalf("since = %q, want %q", got, configuredSince)
		}
		if got := r.URL.Query().Get("until"); got != wantUntil {
			t.Fatalf("until = %q, want %q", got, wantUntil)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": 0, "messages": []map[string]any{}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":        "writer",
		"base_url":         server.URL,
		"token":            "gh-token",
		"family":           "message",
		"client_id":        "cerebro-runtime",
		"export_secret":    "export-secret",
		"event_types":      "message",
		"max_window_hours": "1",
		"per_page":         "10",
		"since":            configuredSince,
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if !sawRequest {
		t.Fatal("server saw no message export request")
	}
	checkpoint := decodeMessageCursor(t, pull.Checkpoint.GetCursorOpaque())
	if checkpoint.Since != wantUntil {
		t.Fatalf("checkpoint since = %q, want %q", checkpoint.Since, wantUntil)
	}
}

func TestReadMessagesWithoutSinceUsesStableCompatibilityWindow(t *testing.T) {
	parsed, ok := parseMessageCursorTime(defaultMessageExportInitialSince)
	if !ok {
		t.Fatalf("parse default since %q failed", defaultMessageExportInitialSince)
	}
	settings, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id":        "writer",
		"base_url":         "https://cosmo.example.com",
		"token":            "gh-token",
		"family":           "message",
		"client_id":        "cerebro-runtime",
		"export_secret":    "export-secret",
		"event_types":      "message",
		"max_window_hours": "1",
		"per_page":         "10",
	}), false)
	if err != nil {
		t.Fatalf("parseSettings() error = %v", err)
	}
	var first messageWindow
	for _, now := range []time.Time{
		time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 5, 18, 13, 0, 0, 0, time.UTC),
	} {
		window, ok, err := readMessageCursor(settings, nil, now)
		if err != nil {
			t.Fatalf("readMessageCursor(%s) error = %v", now, err)
		}
		if !ok {
			t.Fatalf("readMessageCursor(%s) ok = false, want true", now)
		}
		if !window.since.Equal(parsed) {
			t.Fatalf("window since = %s, want %s", window.since, parsed)
		}
		if !window.until.Equal(parsed.Add(time.Hour)) {
			t.Fatalf("window until = %s, want %s", window.until, parsed.Add(time.Hour))
		}
		if first.since.IsZero() {
			first = window
			continue
		}
		if !window.since.Equal(first.since) || !window.until.Equal(first.until) {
			t.Fatalf("window changed across retries: %s..%s then %s..%s", first.since, first.until, window.since, window.until)
		}
	}
}

func TestFactAttributesExposeCoordinationRiskContract(t *testing.T) {
	attrs := attributesFor(familyFact, map[string]any{
		"key":         "coordination:risk:thread-1",
		"category":    "coordination_risk",
		"source":      "session:thread-1",
		"risk_reason": "agent coordinated a privileged change across sessions",
	})
	for _, key := range []string{"key", "category", "source"} {
		if attrs[key] == "" {
			t.Fatalf("fact attribute %q = empty, want populated coordination-risk contract field", key)
		}
	}
	if got, want := attrs["category"], "coordination_risk"; got != want {
		t.Fatalf("category = %q, want %q", got, want)
	}
	if got, want := attrs["source"], "session:thread-1"; got != want {
		t.Fatalf("source = %q, want %q so downstream projection/finding can resolve session context", got, want)
	}
}

func TestMessageAttributesIncludeUserContext(t *testing.T) {
	attrs := attributesFor(familyMessage, map[string]any{
		"ticket_id":  "COSMO-1",
		"event_type": "message",
		"role":       "user",
		"userId":     "user-1",
		"userEmail":  "alice@example.com",
	})

	if got := attrs["user_id"]; got != "user-1" {
		t.Fatalf("user_id = %q, want user-1", got)
	}
	if got := attrs["email"]; got != "alice@example.com" {
		t.Fatalf("email = %q, want alice@example.com", got)
	}
}

func TestDiscoverMessagesIteratesConfiguredEventTypes(t *testing.T) {
	var eventTypes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cerebro/messages" {
			http.NotFound(w, r)
			return
		}
		eventType := r.URL.Query().Get("event_type")
		eventTypes = append(eventTypes, eventType)
		if eventType == "completion" {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": 1, "messages": []map[string]any{
				{
					"id":         20,
					"ticket_id":  "COSMO-2",
					"event_type": "completion",
					"role":       "assistant",
					"summary":    "Completed issue",
					"created_at": "2026-05-12T12:01:00Z",
				},
			}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": 0, "messages": []map[string]any{}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	urns, err := source.Discover(context.Background(), messageTestConfig(server.URL))
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got, want := eventTypes, []string{"message", "completion"}; !slicesEqual(got, want) {
		t.Fatalf("event types queried = %#v, want %#v", got, want)
	}
	if len(urns) != 1 {
		t.Fatalf("len(urns) = %d, want 1", len(urns))
	}
}

func TestReadMessagesReturnsHardScopedExportFailures(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/cerebro/messages" {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "scoped export rejected"})
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackBaseURL = true
			_, err = source.Read(context.Background(), messageTestConfig(server.URL), nil)
			if err == nil {
				t.Fatal("Read() error = nil, want non-nil")
			}
			var responseErr *responseError
			if !errors.As(err, &responseErr) {
				t.Fatalf("Read() error = %T %v, want responseError", err, err)
			}
			if responseErr.StatusCode() != status {
				t.Fatalf("StatusCode() = %d, want %d", responseErr.StatusCode(), status)
			}
		})
	}
}

func TestNextMessageCursorRespectsScopedExportOffsetLimit(t *testing.T) {
	settings := settings{eventTypes: []string{"message", "completion"}}
	window := messageWindow{
		since:          time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		until:          time.Date(2026, 5, 1, 1, 0, 0, 0, time.UTC),
		eventTypeIndex: 0,
		offset:         messageExportMaxOffset - messageExportMaxPageSize,
	}

	next, checkpoint := nextMessageCursor(settings, window, messageExportMaxPageSize, messageExportMaxPageSize)
	if next == "" || checkpoint != next {
		t.Fatalf("next=%q checkpoint=%q, want next event cursor", next, checkpoint)
	}
	cursor := decodeMessageCursor(t, next)
	if cursor.EventTypeIndex != 1 || cursor.Offset != 0 {
		t.Fatalf("cursor = %#v, want next event type at offset 0", cursor)
	}

	settings.eventTypes = []string{"message"}
	next, checkpoint = nextMessageCursor(settings, window, messageExportMaxPageSize, messageExportMaxPageSize)
	if next != "" {
		t.Fatalf("next = %q, want empty after final event type", next)
	}
	cursor = decodeMessageCursor(t, checkpoint)
	if cursor.Since != window.until.Format(time.RFC3339Nano) || cursor.Until != "" || cursor.Offset != 0 {
		t.Fatalf("checkpoint = %#v, want next window checkpoint", cursor)
	}
}

func TestReadMessagesRejectsInvalidScopedCursor(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := messageTestConfig("https://cosmo.example.com")
	for _, cursor := range []*cerebrov1.SourceCursor{
		{Opaque: "1"},
		{Opaque: `{"source":"cosmo.message","resumable_checkpoint":true,"since":"2026-05-14T00:00:00Z","until":"2026-05-14T01:00:00Z","offset":-1}`},
		{Opaque: `{"source":"other","resumable_checkpoint":true,"since":"2026-05-14T00:00:00Z","until":"2026-05-14T01:00:00Z"}`},
	} {
		if _, err := source.Read(context.Background(), cfg, cursor); err == nil {
			t.Fatalf("Read(cursor=%q) error = nil, want non-nil", cursor.GetOpaque())
		}
	}
}

func TestReadSurveyFeedbackUsesWebhookSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/survey-results" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("X-Webhook-Secret"); got != "secret" {
			t.Fatalf("X-Webhook-Secret = %q, want secret", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": 2, "feedback": []map[string]any{
			{
				"key":            "feedback:C1:1",
				"ticketId":       "COSMO-1",
				"channel":        "C1",
				"messageTs":      "1710000000.000100",
				"userId":         "U1",
				"reaction":       "+1",
				"sentiment":      "positive",
				"workflowRunUrl": "https://github.com/example/cosmo/actions/runs/1",
				"feedbackAt":     "2026-05-12T12:00:00Z",
			},
			{
				"key":        "feedback:C1:2",
				"ticketId":   "COSMO-2",
				"channel":    "C1",
				"messageTs":  "1710000000.000200",
				"userId":     "U2",
				"reaction":   "-1",
				"sentiment":  "negative",
				"feedbackAt": "2026-05-12T12:01:00Z",
			},
		}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":      "writer",
		"base_url":       server.URL,
		"family":         "survey_feedback",
		"webhook_secret": "secret",
		"per_page":       "1",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if got, want := first.Events[0].Kind, "cosmo.survey_feedback"; got != want {
		t.Fatalf("event.Kind = %q, want %q", got, want)
	}
	if got, want := first.Events[0].Attributes["sentiment"], "positive"; got != want {
		t.Fatalf("sentiment = %q, want %q", got, want)
	}
	if got := first.NextCursor.GetOpaque(); got != "1" {
		t.Fatalf("NextCursor = %q, want 1", got)
	}
}

func TestReadSurveyFeedbackCanUseGitHubToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ui/memory/survey-results" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer gh-token" {
			t.Fatalf("Authorization = %q, want bearer token", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": 1, "feedback": []map[string]any{
			{
				"key":        "feedback:C1:1",
				"ticketId":   "COSMO-1",
				"sentiment":  "positive",
				"feedbackAt": "2026-05-12T12:00:00Z",
			},
		}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
		"family":    "survey_feedback",
		"token":     "gh-token",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if got, want := pull.Events[0].Attributes["ticket_id"], "COSMO-1"; got != want {
		t.Fatalf("ticket_id = %q, want %q", got, want)
	}
}

func messageTestConfig(baseURL string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"tenant_id":        "writer",
		"base_url":         baseURL,
		"token":            "gh-token",
		"family":           "message",
		"client_id":        "cerebro-runtime",
		"export_secret":    "export-secret",
		"event_types":      "message,completion",
		"max_window_hours": "1",
		"per_page":         "1",
		"since":            "2026-05-01T00:00:00Z",
	})
}

func decodeMessageCursor(t *testing.T, opaque string) messageCursor {
	t.Helper()
	var cursor messageCursor
	if err := json.Unmarshal([]byte(opaque), &cursor); err != nil {
		t.Fatalf("decode message cursor %q: %v", opaque, err)
	}
	return cursor
}

func cloneMap(input map[string]string) map[string]string {
	clone := make(map[string]string, len(input))
	for key, value := range input {
		clone[key] = value
	}
	return clone
}

func slicesEqual(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
