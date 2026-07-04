package gitguardian

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndReadFamilies(t *testing.T) {
	tests := []struct {
		family        string
		path          string
		kind          string
		records       []map[string]any
		wantAttribute string
		wantValue     string
		wantCursor    string
	}{
		{
			family: familyIncidents,
			path:   "/v1/incidents/secrets",
			kind:   "gitguardian.incidents",
			records: []map[string]any{{
				"id":            3759,
				"date":          "2026-06-25T10:00:00Z",
				"incident_name": "Stripe Token",
				"secret_id":     1,
				"severity":      "high",
				"status":        "TRIGGERED",
				"validity":      "valid",
			}},
			wantAttribute: "title",
			wantValue:     "Stripe Token",
			wantCursor:    "cursor-2",
		},
		{
			family: familyMembers,
			path:   "/v1/members",
			kind:   "gitguardian.members",
			records: []map[string]any{{
				"id":           3252,
				"name":         "John Smith",
				"email":        "john.smith@example.com",
				"access_level": "owner",
				"active":       true,
				"created_at":   "2026-06-24T09:00:00Z",
				"last_login":   "2026-06-25T09:00:00Z",
			}},
			wantAttribute: "user_id",
			wantValue:     "3252",
		},
		{
			family: familyAuditEvents,
			path:   "/v1/audit_logs",
			kind:   "gitguardian.audit_events",
			records: []map[string]any{{
				"id":           91234,
				"date":         "2026-06-25T08:00:00Z",
				"member_email": "security@example.com",
				"member_name":  "Security Team",
				"member_id":    1243,
				"event_name":   "user.logged_in",
				"action_type":  "READ",
				"target_ids":   []string{"1243"},
			}},
			wantAttribute: "actor_id",
			wantValue:     "1243",
		},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()

			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Token test-token" {
					t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
				}
				if r.URL.RequestURI() == "/v1/health" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
				}
				if got := r.URL.Query().Get("limit"); got != "" {
					t.Fatalf("limit query = %q, want GitGuardian per_page", got)
				}
				if got := r.URL.Query().Get("per_page"); got == "" {
					t.Fatalf("per_page query is empty")
				}
				if tt.wantCursor != "" && r.URL.Query().Get("per_page") == "2" && r.URL.Query().Get("cursor") == "" {
					w.Header().Set("Link", "<"+server.URL+tt.path+"?cursor="+tt.wantCursor+"&per_page=2>; rel=\"next\"")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"data": tt.records})
			}))
			defer server.Close()

			cfg := sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant",
				"base_url":  server.URL,
				"family":    tt.family,
				"api_token": "test-token",
				"per_page":  "2",
			})
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("kind = %q, want %q", event.Kind, tt.kind)
			}
			if strings.TrimSpace(event.Id) == "" {
				t.Fatalf("event id is empty: %#v", event)
			}
			if got := event.Attributes[tt.wantAttribute]; got != tt.wantValue {
				t.Fatalf("attribute %s = %q, want %q", tt.wantAttribute, got, tt.wantValue)
			}
			if tt.wantCursor != "" {
				if got := sourcecdk.CursorToken(pull.NextCursor); got != tt.wantCursor {
					t.Fatalf("NextCursor = %q, want %q", got, tt.wantCursor)
				}
			}
		})
	}
}

func TestSourceCheckReportsProviderUnavailable(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    familyIncidents,
		"api_token": "test-token",
	})
	err = source.Check(context.Background(), cfg)
	if err == nil {
		t.Fatal("Check() error = nil, want provider unavailable failure")
	}
	var statusErr interface{ StatusCode() int }
	if !errors.As(err, &statusErr) || statusErr.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("Check() error = %v, want provider unavailable status", err)
	}
}
