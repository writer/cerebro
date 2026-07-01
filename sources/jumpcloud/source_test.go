package jumpcloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndReadUsers(t *testing.T) {
	source := newTestSource(t)
	requests := []*http.Request{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		requireJumpCloudHeaders(t, r)
		if r.URL.Path != "/systemusers" {
			t.Fatalf("path = %q, want /systemusers", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{{
				"_id":         "user-1",
				"email":       "user@example.test",
				"username":    "user.one",
				"displayname": "User One",
				"created":     "2026-06-01T00:00:00Z",
			}},
			"skip":       0,
			"limit":      1,
			"totalCount": 1,
		})
	}))
	defer server.Close()

	cfg := jumpCloudConfig(server.URL, map[string]string{"family": defaultFamily, "per_page": "2"})
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
	if event.Kind != "jumpcloud.users" {
		t.Fatalf("kind = %q, want jumpcloud.users", event.Kind)
	}
	if event.Attributes["user_id"] != "user-1" || event.Attributes["email"] != "user@example.test" || event.Attributes["tenant_id"] != "tenant" {
		t.Fatalf("attributes = %#v, want user identity attributes", event.Attributes)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if len(requests) < 3 {
		t.Fatalf("requests = %d, want health, check, and read", len(requests))
	}
}

func TestSourceReadsProviderFamilies(t *testing.T) {
	tests := []struct {
		name      string
		family    string
		path      string
		response  any
		kind      string
		attrKey   string
		attrValue string
	}{
		{
			name:   "users",
			family: familyUsers,
			path:   "/systemusers",
			response: map[string]any{
				"results":    []map[string]any{{"_id": "user-1", "email": "user@example.test", "username": "user.one"}},
				"skip":       0,
				"limit":      2,
				"totalCount": 1,
			},
			kind:      "jumpcloud.users",
			attrKey:   "user_id",
			attrValue: "user-1",
		},
		{
			name:      "groups",
			family:    familyGroups,
			path:      "/v2/usergroups",
			response:  []map[string]any{{"id": "group-1", "name": "Engineering", "type": "user_group"}},
			kind:      "jumpcloud.groups",
			attrKey:   "group_id",
			attrValue: "group-1",
		},
		{
			name:   "systems",
			family: familySystems,
			path:   "/systems",
			response: map[string]any{
				"results":    []map[string]any{{"_id": "system-1", "displayName": "mac-1", "hostname": "mac-1.local", "os": "macOS"}},
				"skip":       0,
				"limit":      2,
				"totalCount": 1,
			},
			kind:      "jumpcloud.systems",
			attrKey:   "system_id",
			attrValue: "system-1",
		},
		{
			name:   "applications",
			family: familyApplications,
			path:   "/applications",
			response: map[string]any{
				"results":    []map[string]any{{"_id": "app-1", "displayName": "SAML App", "ssoUrl": "https://example.test/sso"}},
				"skip":       0,
				"limit":      2,
				"totalCount": 1,
			},
			kind:      "jumpcloud.applications",
			attrKey:   "app_id",
			attrValue: "app-1",
		},
		{
			name:      "system groups",
			family:    familySystemGroups,
			path:      "/v2/systemgroups",
			response:  []map[string]any{{"id": "system-group-1", "name": "Mac laptops", "type": "system"}},
			kind:      "jumpcloud.system_groups",
			attrKey:   "group_id",
			attrValue: "system-group-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := newTestSource(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requireJumpCloudHeaders(t, r)
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %s", r.URL.Path, tt.path)
				}
				if got := r.URL.Query().Get("skip"); got != "0" {
					t.Fatalf("skip = %q, want 0", got)
				}
				if got := r.URL.Query().Get("limit"); got != "2" {
					t.Fatalf("limit = %q, want 2", got)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			pull, err := source.Read(context.Background(), jumpCloudConfig(server.URL, map[string]string{"family": tt.family, "per_page": "2"}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("kind = %q, want %s", event.Kind, tt.kind)
			}
			if event.Attributes[tt.attrKey] != tt.attrValue {
				t.Fatalf("%s = %q, want %q in %#v", tt.attrKey, event.Attributes[tt.attrKey], tt.attrValue, event.Attributes)
			}
			if event.Attributes["tenant_id"] != "tenant" {
				t.Fatalf("tenant_id = %q, want tenant", event.Attributes["tenant_id"])
			}
		})
	}
}

func TestSourceReadsGroupMembersWithFanout(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireJumpCloudHeaders(t, r)
		if r.URL.Path != "/v2/usergroups/group-a/members" {
			t.Fatalf("path = %q, want /v2/usergroups/group-a/members", r.URL.Path)
		}
		if got := r.URL.Query().Get("skip"); got != "0" {
			t.Fatalf("skip = %q, want 0", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{"to": map[string]any{"id": "user-1", "type": "user"}}})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), jumpCloudConfig(server.URL, map[string]string{
		"family":    familyGroupMembers,
		"per_page":  "2",
		"group_ids": "group-a",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if attrs["group_id"] != "group-a" || attrs["member_user_id"] != "user-1" || attrs["member_type"] != "user" {
		t.Fatalf("attributes = %#v, want group membership", attrs)
	}
}

func TestSourceDiscoversGroupMembersAsScopedMemberships(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireJumpCloudHeaders(t, r)
		if r.URL.Path != "/v2/usergroups/group-1/members" {
			t.Fatalf("path = %q, want /v2/usergroups/group-1/members", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{"to": map[string]any{"id": "user-1", "type": "user"}}})
	}))
	defer server.Close()

	urns, err := source.Discover(context.Background(), jumpCloudConfig(server.URL, map[string]string{
		"family":    familyGroupMembers,
		"per_page":  "2",
		"group_ids": "group-1",
	}))
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	want := "urn:cerebro:tenant:jumpcloud_group_members:id-3136bc9e0fb2e9df9ed3b7b56fd78448"
	if len(urns) != 1 || urns[0].String() != want {
		t.Fatalf("urns = %v, want [%s]", urns, want)
	}
}

func TestSourceReadsDirectoryInsightsAuditEvents(t *testing.T) {
	source := newTestSource(t)
	requests := []map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" {
			t.Fatalf("path = %q, want /events", r.URL.Path)
		}
		requireJumpCloudHeaders(t, r)
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		requests = append(requests, body)
		w.Header().Set("Content-Type", "application/json")
		switch len(requests) {
		case 1:
			w.Header().Set("X-Result-Count", "2")
			w.Header().Set("X-Limit", "2")
			w.Header().Set("X-Search_after", `[1719849600000,"event-2"]`)
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": "event-1", "event_type": "admin_login_attempt", "resource": map[string]any{"id": "admin-1", "type": "admin", "email": "admin@example.test"}, "success": true, "timestamp": "2026-06-01T00:00:00Z"},
				{"id": "event-2", "event_type": "sso_login_success", "initiated_by": map[string]any{"id": "user-1", "email": "user@example.test"}, "resource": map[string]any{"id": "app-1", "type": "application"}, "timestamp": "2026-06-01T00:01:00Z"},
			})
		case 2:
			w.Header().Set("X-Result-Count", "1")
			w.Header().Set("X-Limit", "2")
			w.Header().Set("X-Search_after", `[1719849660000,"event-3"]`)
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": "event-3", "event_type": "directory_user_update", "initiated_by": map[string]any{"id": "admin-1"}, "resource": map[string]any{"id": "user-2", "type": "user"}, "timestamp": "2026-06-01T00:02:00Z"},
			})
		default:
			t.Fatalf("unexpected request count %d", len(requests))
		}
	}))
	defer server.Close()

	cfg := jumpCloudConfig("https://console.jumpcloud.com/api", map[string]string{
		"family":            familyAuditEvents,
		"insights_base_url": server.URL,
		"audit_start_time":  "2026-06-01T00:00:00Z",
		"per_page":          "2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 2 {
		t.Fatalf("first events = %d, want 2", len(first.Events))
	}
	if first.NextCursor.GetOpaque() != `[1719849600000,"event-2"]` {
		t.Fatalf("first cursor = %q, want search_after token", first.NextCursor.GetOpaque())
	}
	attrs := first.Events[1].Attributes
	if attrs["event_type"] != "sso_login_success" || attrs["actor_id"] != "user-1" || attrs["resource_id"] != "app-1" {
		t.Fatalf("audit attributes = %#v, want normalized actor/resource fields", attrs)
	}
	second, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: first.NextCursor.GetOpaque()})
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second cursor = %#v, want nil", second.NextCursor)
	}
	if len(second.Events) != 1 {
		t.Fatalf("second events = %d, want 1", len(second.Events))
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(requests))
	}
	if got := requests[0]["start_time"]; got != "2026-06-01T00:00:00Z" {
		t.Fatalf("start_time = %#v, want configured start", got)
	}
	if _, ok := requests[0]["search_after"]; ok {
		t.Fatalf("first request search_after = %#v, want omitted", requests[0]["search_after"])
	}
	if got := requests[1]["search_after"]; got == nil {
		t.Fatalf("second request search_after missing: %#v", requests[1])
	}
}

func newTestSource(t *testing.T) *Source {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	return source
}

func jumpCloudConfig(baseURL string, values map[string]string) sourcecdk.Config {
	config := map[string]string{
		"tenant_id": "tenant",
		"base_url":  baseURL,
		"api_key":   "test-key",
		"org_id":    "org-1",
	}
	for key, value := range values {
		config[key] = value
	}
	return sourcecdk.NewConfig(config)
}

func requireJumpCloudHeaders(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("x-api-key"); got != "test-key" {
		t.Fatalf("x-api-key = %q, want test-key", got)
	}
	if got := r.Header.Get("x-org-id"); got != "org-1" {
		t.Fatalf("x-org-id = %q, want org-1", got)
	}
	if got := r.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want empty", got)
	}
}
