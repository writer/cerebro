package box

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/boxapi"
)

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() == "/users/me" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/users" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": []map[string]string{{"id": "record-1", "resource_urn": "urn:cerebro:tenant:runtime_asset:record-1", "resource_type": "asset", "resource_id": "record-1", "name": "Record One", "updated_at": "2026-06-01T00:00:00Z"}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token"}
	cfg := sourcecdk.NewConfig(cfgValues)
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
	if event.Kind != "box.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestRuntimeUsesBoxAPIPathsAndCursors(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/users":
			if got := r.URL.Query().Get("usemarker"); got != "true" {
				t.Fatalf("users usemarker = %q, want true", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"entries":     []map[string]string{{"id": "user-1", "name": "User One", "login": "user@example.test"}},
				"next_marker": "marker-2",
			})
		case "/folders/0/items":
			if got := r.URL.Query().Get("usemarker"); got != "true" {
				t.Fatalf("content usemarker = %q, want true", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"entries": []map[string]string{{"id": "file-1", "type": "file", "name": "Security Evidence.pdf"}}})
		case "/groups":
			if got := r.URL.Query().Get("offset"); got != "0" {
				t.Fatalf("groups offset = %q, want 0", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"entries":     []map[string]string{{"id": "group-1", "type": "group", "name": "Engineering"}},
				"offset":      0,
				"limit":       100,
				"total_count": 1,
			})
		case "/groups/group-1/memberships":
			if got := r.URL.Query().Get("offset"); got != "0" {
				t.Fatalf("memberships offset = %q, want 0", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"entries": []map[string]any{{
					"id":          "membership-1",
					"type":        "group_membership",
					"role":        "member",
					"modified_at": "2026-06-02T03:04:05Z",
					"group":       map[string]string{"id": "group-1", "type": "group", "name": "Engineering"},
					"user":        map[string]string{"id": "user-1", "type": "user", "login": "user@example.test", "name": "User One"},
				}},
				"offset":      0,
				"limit":       100,
				"total_count": 1,
			})
		case "/events":
			if got := r.URL.Query().Get("stream_type"); got != "admin_logs_streaming" {
				t.Fatalf("events stream_type = %q, want admin_logs_streaming", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"entries": []map[string]any{{
					"event_id":   "event-1",
					"event_type": "ITEM_UPLOAD",
					"created_by": map[string]string{"id": "user-1", "login": "user@example.test", "name": "User One"},
					"source":     map[string]string{"id": "file-1", "type": "file", "name": "Security Evidence.pdf"},
				}},
				"next_stream_position": "stream-2",
			})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	baseCfg := map[string]string{
		"base_url":  server.URL,
		"tenant_id": "tenant",
		"token":     "test-token",
	}
	for _, tt := range []struct {
		family string
		kind   string
		cursor string
		extra  map[string]string
	}{
		{family: familyUsers, kind: "box.users", cursor: "marker-2"},
		{family: familyContentAssets, kind: "box.content_assets"},
		{family: familyGroups, kind: "box.groups"},
		{family: familyGroupMemberships, kind: "box.group_memberships", extra: map[string]string{"group_ids": "group-1"}},
		{family: familyAuditEvents, kind: "box.audit_events", cursor: "stream-2"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			cfgValues := map[string]string{}
			for key, value := range baseCfg {
				cfgValues[key] = value
			}
			cfgValues["family"] = tt.family
			for key, value := range tt.extra {
				cfgValues[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(cfgValues), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("event kind = %q, want %q", got, tt.kind)
			}
			if tt.family == familyGroupMemberships {
				wantOccurredAt := time.Date(2026, time.June, 2, 3, 4, 5, 0, time.UTC)
				if got := pull.Events[0].GetOccurredAt().AsTime(); !got.Equal(wantOccurredAt) {
					t.Fatalf("OccurredAt = %s, want %s", got.Format(time.RFC3339), wantOccurredAt.Format(time.RFC3339))
				}
			}
			if tt.cursor != "" && (pull.NextCursor == nil || pull.NextCursor.GetOpaque() != tt.cursor) {
				t.Fatalf("NextCursor = %#v, want %s", pull.NextCursor, tt.cursor)
			}
		})
	}
	if got := strings.Join(requests, "\n"); !strings.Contains(got, "/users?") || !strings.Contains(got, "/folders/0/items?") || !strings.Contains(got, "/events?") {
		t.Fatalf("requests = %s, want Box collection paths", got)
	}
}

func TestGroupMembershipsRequireConfiguredGroupIDs(t *testing.T) {
	param, values := boxapi.PathParamValues(sourcecdk.NewConfig(map[string]string{
		"family": familyGroupMemberships,
	}))
	if param != "" || len(values) != 0 {
		t.Fatalf("boxPathParamValues() = %q, %v; want no path params without group_ids", param, values)
	}

	param, values = boxapi.PathParamValues(sourcecdk.NewConfig(map[string]string{
		"family":    familyGroupMemberships,
		"group_ids": "group-1, group-2",
	}))
	if param != "group_id" || strings.Join(values, ",") != "group-1,group-2" {
		t.Fatalf("boxPathParamValues() = %q, %v; want configured group_ids", param, values)
	}
}

func TestRuntimeUsesBoxClientCredentialsTokenExchange(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			tokenRequests++
			if r.Method != http.MethodPost {
				t.Fatalf("token method = %s", r.Method)
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error = %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "client_credentials" {
				t.Fatalf("grant_type = %q, want client_credentials", got)
			}
			if got := r.Form.Get("client_id"); got != "client-id" {
				t.Fatalf("client_id = %q, want client-id", got)
			}
			if got := r.Form.Get("client_secret"); got != "client-secret" {
				t.Fatalf("client_secret = %q, want client-secret", got)
			}
			if got := r.Form.Get("box_subject_type"); got != "enterprise" {
				t.Fatalf("box_subject_type = %q, want enterprise", got)
			}
			if got := r.Form.Get("box_subject_id"); got != "enterprise-1" {
				t.Fatalf("box_subject_id = %q, want enterprise-1", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 600})
		case "/users":
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Fatalf("Authorization = %q, want Bearer test-token", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"entries": []map[string]string{{"id": "user-1", "name": "User One", "login": "user@example.test"}}})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":      server.URL,
		"token_url":     server.URL + "/oauth2/token",
		"tenant_id":     "tenant",
		"client_id":     "client-id",
		"client_secret": "client-secret",
		"enterprise_id": "enterprise-1",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d, want 1", tokenRequests)
	}
}

func TestNewFixtureReplaysBoxFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyUsers, familyContentAssets, familyGroups, familyGroupMemberships, familyAuditEvents} {
		values := map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		}
		if family == familyGroupMemberships {
			values["group_ids"] = "group-1"
		}
		familyConfigs[family] = sourcecdk.NewConfig(values)
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
	for _, tt := range []struct {
		family          string
		kind            string
		wantResourceURN string
	}{
		{family: familyUsers, kind: "box.users", wantResourceURN: "urn:cerebro:tenant:runtime_users:user-1"},
		{family: familyContentAssets, kind: "box.content_assets", wantResourceURN: "urn:cerebro:tenant:runtime_content_assets:file-1"},
		{family: familyGroups, kind: "box.groups", wantResourceURN: "urn:cerebro:tenant:box_groups:group-1"},
		{family: familyGroupMemberships, kind: "box.group_memberships", wantResourceURN: "urn:cerebro:tenant:runtime_users:user-1"},
		{family: familyAuditEvents, kind: "box.audit_events", wantResourceURN: "urn:cerebro:tenant:runtime_content_assets:file-1"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), familyConfigs[tt.family], nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("event kind = %q, want %q", got, tt.kind)
			}
			if got := pull.Events[0].Attributes["resource_urn"]; got != tt.wantResourceURN {
				t.Fatalf("resource_urn = %q, want %q", got, tt.wantResourceURN)
			}
		})
	}
}
