package cosmo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestReadMessagesPaginatesWithOptionalTicketID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ui/memory/messages" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("ticket_id"); got != "" {
			t.Fatalf("ticket_id = %q, want empty", got)
		}
		if got := r.URL.Query().Get("event_type"); got != "message" {
			t.Fatalf("event_type = %q, want message", got)
		}
		if got := r.URL.Query().Get("limit"); got != "1" {
			t.Fatalf("limit = %q, want 1", got)
		}
		switch offset := r.URL.Query().Get("offset"); offset {
		case "0":
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
		case "1":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": 0, "messages": []map[string]any{}})
		default:
			t.Fatalf("offset = %q, want 0 or 1", offset)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":  "writer",
		"base_url":   server.URL,
		"token":      "gh-token",
		"family":     "message",
		"event_type": "message",
		"per_page":   "1",
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
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
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
