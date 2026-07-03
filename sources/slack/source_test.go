package slack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "slack" {
		t.Fatalf("Spec().Id = %q, want slack", got)
	}
}

func TestReadSlackIdentityWorkspacePostureKinds(t *testing.T) {
	for _, tt := range []struct {
		name     string
		family   string
		kind     string
		path     string
		method   string
		query    map[string]string
		noQuery  []string
		response map[string]any
		want     map[string]string
	}{
		{
			name:   "team",
			family: familyTeam,
			kind:   "slack.team",
			path:   "/auth.teams.list",
			method: http.MethodPost,
			query:  map[string]string{"limit": "100"},
			response: map[string]any{"ok": true, "teams": []map[string]any{{
				"id": "T1", "name": "Writer", "domain": "writer",
			}}},
			want: map[string]string{"team_id": "T1", "name": "Writer", "domain": "writer"},
		},
		{
			name:   "user_privileged_no_mfa",
			family: familyUser,
			kind:   "slack.user",
			path:   "/users.list",
			method: http.MethodGet,
			query:  map[string]string{"limit": "100"},
			response: map[string]any{"ok": true, "members": []map[string]any{{
				"id": "U1", "team_id": "T1", "name": "alice", "real_name": "Alice Admin",
				"profile":  map[string]any{"email": "alice@writer.com"},
				"is_admin": true, "is_owner": false, "is_primary_owner": false,
				"is_bot": false, "has_2fa": false, "deleted": false,
			}}},
			want: map[string]string{
				"user_id": "U1", "team_id": "T1", "name": "alice", "email": "alice@writer.com",
				"is_admin": "true", "has_2fa": "false", "has_mfa": "false", "is_bot": "false", "deleted": "false",
			},
		},
		{
			name:   "user_privileged_with_mfa",
			family: familyUser,
			kind:   "slack.user",
			path:   "/users.list",
			method: http.MethodGet,
			query:  map[string]string{"limit": "100"},
			response: map[string]any{"ok": true, "members": []map[string]any{{
				"id": "U2", "team_id": "T1", "name": "bob",
				"profile":  map[string]any{"email": "bob@writer.com"},
				"is_owner": true, "has_2fa": true, "two_factor_type": "app",
			}}},
			want: map[string]string{
				"user_id": "U2", "is_owner": "true", "has_2fa": "true", "has_mfa": "true", "two_factor_type": "app",
			},
		},
		{
			name:   "channel",
			family: familyChannel,
			kind:   "slack.channel",
			path:   "/conversations.list",
			method: http.MethodGet,
			query: map[string]string{
				"exclude_archived": "false",
				"limit":            "100",
				"types":            "public_channel,private_channel",
			},
			response: map[string]any{"ok": true, "channels": []map[string]any{{
				"id": "C1", "name": "general", "context_team_id": "T1",
				"is_private": false, "is_archived": false, "creator": "U1", "num_members": 12,
			}}},
			want: map[string]string{"channel_id": "C1", "name": "general", "team_id": "T1", "is_private": "false", "creator": "U1"},
		},
		{
			name:   "shared_channel",
			family: familyChannel,
			kind:   "slack.channel",
			path:   "/conversations.list",
			method: http.MethodGet,
			query: map[string]string{
				"exclude_archived": "false",
				"limit":            "100",
				"types":            "public_channel,private_channel",
			},
			response: map[string]any{"ok": true, "channels": []map[string]any{{
				"id": "C9", "name": "connect", "shared_team_ids": []string{"T1", "T2"},
				"is_private": false, "creator": "U1",
			}}},
			want: map[string]string{"channel_id": "C9", "name": "connect", "shared_team_ids": "T1,T2", "team_id": ""},
		},
		{
			name:   "user_group",
			family: familyUserGroup,
			kind:   "slack.user_group",
			path:   "/usergroups.list",
			method: http.MethodGet,
			noQuery: []string{
				"cursor",
				"limit",
				"per_page",
			},
			response: map[string]any{"ok": true, "usergroups": []map[string]any{{
				"id": "S1", "team_id": "T1", "handle": "eng", "name": "Engineering",
				"description": "Eng team", "is_disabled": false,
			}}},
			want: map[string]string{"group_id": "S1", "team_id": "T1", "handle": "eng", "name": "Engineering"},
		},
		{
			name:   "access_log",
			family: familyAccessLog,
			kind:   "slack.access_log",
			path:   "/team.accessLogs",
			method: http.MethodGet,
			query:  map[string]string{"count": "100", "page": "1"},
			response: map[string]any{"ok": true, "logins": []map[string]any{{
				"user_id": "U1", "username": "alice", "ip": "203.0.113.10", "user_agent": "Mozilla/5.0",
				"count": 3, "date_first": 1780271000, "date_last": 1780272000,
			}}},
			want: map[string]string{"actor_id": "U1", "actor_name": "alice", "event_type": "team_access", "ip_address": "203.0.113.10", "login_count": "3"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("request path = %q, want %s", got, tt.path)
				}
				if got := r.Method; got != tt.method {
					t.Fatalf("request method = %q, want %q", got, tt.method)
				}
				for key, want := range tt.query {
					if got := r.URL.Query().Get(key); got != want {
						t.Fatalf("query %q = %q, want %q", key, got, want)
					}
				}
				if got := r.URL.Query().Get("per_page"); got != "" {
					t.Fatalf("query per_page = %q, want empty", got)
				}
				for _, key := range tt.noQuery {
					if got := r.URL.Query().Get(key); got != "" {
						t.Fatalf("query %q = %q, want empty", key, got)
					}
				}
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			config := map[string]string{"base_url": server.URL, "family": tt.family, "tenant_id": "writer", "token": "slack-token"}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %q", event.Kind, tt.kind)
			}
			for key, value := range tt.want {
				if got := event.Attributes[key]; got != value {
					t.Fatalf("attribute %q = %q, want %q", key, got, value)
				}
			}
		})
	}
}

func TestReadSlackAccessLogUsesStableUserID(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/team.accessLogs" {
			t.Fatalf("request path = %q, want /team.accessLogs", got)
		}
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "logins": []map[string]any{{
			"user_id":    "U1",
			"username":   "alice",
			"ip":         "203.0.113.10",
			"user_agent": "Mozilla/5.0",
			"count":      requests,
			"date_first": 1780271000,
			"date_last":  1780272000 + requests,
		}}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	config := sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyAccessLog,
		"tenant_id": "writer",
		"token":     "slack-token",
	})
	first, err := source.Read(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	second, err := source.Read(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if len(first.Events) != 1 || len(second.Events) != 1 {
		t.Fatalf("events = %d/%d, want 1/1", len(first.Events), len(second.Events))
	}
	if first.Events[0].Id != second.Events[0].Id {
		t.Fatalf("access-log event IDs changed across mutable fields: %q then %q", first.Events[0].Id, second.Events[0].Id)
	}
	if got := second.Events[0].Attributes["login_count"]; got != "2" {
		t.Fatalf("second login_count = %q, want 2", got)
	}
}

func TestReadSlackAccessLogKeepsDistinctIPsForSameUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/team.accessLogs" {
			t.Fatalf("request path = %q, want /team.accessLogs", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "logins": []map[string]any{
			{
				"user_id":    "U1",
				"username":   "alice",
				"ip":         "203.0.113.10",
				"user_agent": "Mozilla/5.0",
				"count":      3,
				"date_first": 1780271000,
				"date_last":  1780272000,
			},
			{
				"user_id":    "U1",
				"username":   "alice",
				"ip":         "198.51.100.25",
				"user_agent": "Mobile Safari",
				"count":      1,
				"date_first": 1780273000,
				"date_last":  1780273100,
			},
		}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyAccessLog,
		"tenant_id": "writer",
		"token":     "slack-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2 access-log rows", len(pull.Events))
	}
	if pull.Events[0].Id == pull.Events[1].Id {
		t.Fatalf("access-log event IDs collapsed for same user on different IPs: %q", pull.Events[0].Id)
	}
	if pull.Events[0].Attributes["external_id"] != "U1" || pull.Events[1].Attributes["external_id"] != "U1" {
		t.Fatalf("external IDs = %q/%q, want U1/U1", pull.Events[0].Attributes["external_id"], pull.Events[1].Attributes["external_id"])
	}
	if pull.Events[0].Attributes["ip_address"] != "203.0.113.10" || pull.Events[1].Attributes["ip_address"] != "198.51.100.25" {
		t.Fatalf("ip addresses = %q/%q, want distinct access locations", pull.Events[0].Attributes["ip_address"], pull.Events[1].Attributes["ip_address"])
	}
}

func TestReadSlackScalarMembershipFamilies(t *testing.T) {
	for _, tt := range []struct {
		name      string
		family    string
		path      string
		configKey string
		configVal string
		queryKey  string
		listKey   string
		kind      string
		want      map[string]string
	}{
		{
			name:      "channel_member",
			family:    familyChannelMember,
			path:      "/conversations.members",
			configKey: "channel_id",
			configVal: "C1",
			queryKey:  "channel",
			listKey:   "members",
			kind:      "slack.channel_member",
			want:      map[string]string{"channel_id": "C1", "user_id": "U1", "membership_type": "channel"},
		},
		{
			name:      "user_group_member",
			family:    familyUserGroupMember,
			path:      "/usergroups.users.list",
			configKey: "usergroup_id",
			configVal: "S1",
			queryKey:  "usergroup",
			listKey:   "users",
			kind:      "slack.user_group_member",
			want:      map[string]string{"usergroup_id": "S1", "user_id": "U1", "membership_type": "user_group"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("request path = %q, want %s", got, tt.path)
				}
				if got := r.URL.Query().Get(tt.queryKey); got != tt.configVal {
					t.Fatalf("query %q = %q, want %q", tt.queryKey, got, tt.configVal)
				}
				if got := r.URL.Query().Get("limit"); got != "2" {
					t.Fatalf("limit = %q, want 2", got)
				}
				if tt.family == familyUserGroupMember {
					if got := r.URL.Query().Get("include_disabled"); got != "true" {
						t.Fatalf("include_disabled = %q, want true", got)
					}
				}
				if got := r.Header.Get("Authorization"); got != "Bearer slack-token" {
					t.Fatalf("Authorization = %q, want bearer token", got)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"ok":                true,
					tt.listKey:          []string{"U1"},
					"response_metadata": map[string]any{"next_cursor": "cursor-2"},
				})
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			config := sourcecdk.NewConfig(map[string]string{
				"base_url":   server.URL,
				"family":     tt.family,
				"per_page":   "2",
				"tenant_id":  "writer",
				"token":      "slack-token",
				tt.configKey: tt.configVal,
			})
			pull, err := source.Read(context.Background(), config, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			if pull.NextCursor == nil || pull.NextCursor.GetOpaque() != "cursor-2" {
				t.Fatalf("NextCursor = %#v, want cursor-2", pull.NextCursor)
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %q", event.Kind, tt.kind)
			}
			for key, want := range tt.want {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("attribute %q = %q, want %q", key, got, want)
				}
			}
			urns, err := source.Discover(context.Background(), config)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(urns) != 1 {
				t.Fatalf("Discover URNs = %d, want 1", len(urns))
			}
			if requests != 2 {
				t.Fatalf("requests = %d, want Read and Discover", requests)
			}
		})
	}
}

func TestReadSlackAuditLogsUsesAuditBaseURL(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.URL.EscapedPath(); got != "/logs" {
			t.Fatalf("request path = %q, want /logs", got)
		}
		for key, want := range map[string]string{
			"action": "user_login",
			"cursor": "cursor-1",
			"latest": "1780273000",
			"limit":  "3",
			"oldest": "1780270000",
		} {
			if got := r.URL.Query().Get(key); got != want {
				t.Fatalf("query %q = %q, want %q", key, got, want)
			}
		}
		if got := r.Header.Get("Authorization"); got != "Bearer slack-token" {
			t.Fatalf("Authorization = %q, want bearer token", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": []map[string]any{{
				"id":          "Ev1",
				"date_create": 1780272000,
				"action":      "user_login",
				"actor": map[string]any{"type": "user", "user": map[string]any{
					"id": "U1", "name": "alice", "email": "alice@example.test", "team": "T1",
				}},
				"entity": map[string]any{"type": "user", "user": map[string]any{
					"id": "U2", "name": "bob", "team": "T1",
				}},
				"context": map[string]any{"ip_address": "203.0.113.10", "ua": "Mozilla/5.0"},
			}},
			"response_metadata": map[string]any{"next_cursor": "cursor-2"},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	config := sourcecdk.NewConfig(map[string]string{
		"action":             "user_login",
		"audit_log_base_url": server.URL,
		"family":             familyAuditLog,
		"latest":             "1780273000",
		"oldest":             "1780270000",
		"per_page":           "3",
		"tenant_id":          "writer",
		"token":              "slack-token",
	})
	pull, err := source.Read(context.Background(), config, &cerebrov1.SourceCursor{Opaque: "cursor-1"})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if pull.NextCursor == nil || pull.NextCursor.GetOpaque() != "cursor-2" {
		t.Fatalf("NextCursor = %#v, want cursor-2", pull.NextCursor)
	}
	event := pull.Events[0]
	if event.Kind != "slack.audit_log" {
		t.Fatalf("Kind = %q, want slack.audit_log", event.Kind)
	}
	for key, want := range map[string]string{
		"actor_email":   "alice@example.test",
		"actor_id":      "U1",
		"actor_name":    "alice",
		"event_type":    "user_login",
		"ip_address":    "203.0.113.10",
		"resource_id":   "U2",
		"resource_name": "bob",
		"resource_type": "user",
		"team_id":       "T1",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("attribute %q = %q, want %q", key, got, want)
		}
	}
}

func TestReadSlackAuditLogsUsesRollingLookback(t *testing.T) {
	requests := 0
	var firstOldest string
	var firstLatest string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/logs" {
			t.Fatalf("request path = %q, want /logs", got)
		}
		oldestValue := r.URL.Query().Get("oldest")
		latestValue := r.URL.Query().Get("latest")
		oldest, err := strconv.ParseInt(oldestValue, 10, 64)
		if err != nil {
			t.Fatalf("oldest query = %q, want unix seconds", oldestValue)
		}
		latest, err := strconv.ParseInt(latestValue, 10, 64)
		if err != nil {
			t.Fatalf("latest query = %q, want unix seconds", latestValue)
		}
		if got := latest - oldest; got != 90000 {
			t.Fatalf("lookback window = %d, want 90000", got)
		}
		responseMetadata := map[string]any{}
		entries := []map[string]any{{
			"id":          "Ev1",
			"date_create": 1780272000,
			"action":      "user_login",
		}}
		switch requests {
		case 0:
			firstOldest = oldestValue
			firstLatest = latestValue
			responseMetadata["next_cursor"] = "cursor-2"
		case 1:
			entries[0]["id"] = "Ev2"
			entries[0]["date_create"] = 1780275600
			if got := r.URL.Query().Get("cursor"); got != "cursor-2" {
				t.Fatalf("cursor = %q, want cursor-2", got)
			}
			if oldestValue != firstOldest || latestValue != firstLatest {
				t.Fatalf("window = %s..%s, want first page window %s..%s", oldestValue, latestValue, firstOldest, firstLatest)
			}
		default:
			t.Fatalf("unexpected request %d", requests+1)
		}
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries":           entries,
			"response_metadata": responseMetadata,
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	config := sourcecdk.NewConfig(map[string]string{
		"audit_log_base_url": server.URL,
		"family":             familyAuditLog,
		"lookback_seconds":   "90000",
		"tenant_id":          "writer",
		"token":              "slack-token",
	})
	first, err := source.Read(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if first.NextCursor == nil {
		t.Fatal("first NextCursor = nil, want rolling-window cursor")
	}
	if len(first.Events) != 1 {
		t.Fatalf("first Events = %d, want 1", len(first.Events))
	}
	if first.Checkpoint == nil {
		t.Fatal("first Checkpoint = nil, want checkpoint with rolling-window cursor")
	}
	if first.Checkpoint.GetCursorOpaque() != first.NextCursor.GetOpaque() {
		t.Fatalf("first checkpoint cursor = %q, want next cursor %q", first.Checkpoint.GetCursorOpaque(), first.NextCursor.GetOpaque())
	}
	envelope, ok := sourcecdk.DecodeCursorEnvelope(first.NextCursor.GetOpaque())
	if !ok {
		t.Fatalf("first NextCursor = %q, want cursor envelope", first.NextCursor.GetOpaque())
	}
	if envelope.Source != sourceID || envelope.Family != familyAuditLog || envelope.Token != "cursor-2" {
		t.Fatalf("first NextCursor envelope = %#v, want Slack audit cursor-2", envelope)
	}
	second, err := source.Read(context.Background(), config, first.NextCursor)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestReadSlackAuditLogsPreservesLegacyPlainCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/logs" {
			t.Fatalf("request path = %q, want /logs", got)
		}
		if got := r.URL.Query().Get("cursor"); got != "legacy-cursor" {
			t.Fatalf("cursor = %q, want legacy-cursor", got)
		}
		for _, key := range []string{"oldest", "latest"} {
			if got := r.URL.Query().Get(key); got != "" {
				t.Fatalf("%s = %q, want empty for legacy cursor continuation", key, got)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries":           []map[string]any{},
			"response_metadata": map[string]any{},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	config := sourcecdk.NewConfig(map[string]string{
		"audit_log_base_url": server.URL,
		"family":             familyAuditLog,
		"lookback_seconds":   "90000",
		"tenant_id":          "writer",
		"token":              "slack-token",
	})
	if _, err := source.Read(context.Background(), config, &cerebrov1.SourceCursor{Opaque: "legacy-cursor"}); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
}

func TestReadReturnsSlackEnvelopeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/users.list" {
			t.Fatalf("request path = %q, want /users.list", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":       false,
			"error":    "missing_scope",
			"needed":   "users:read",
			"provided": "team:read",
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	config := sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyUser,
		"tenant_id": "writer",
		"token":     "slack-token",
	})
	_, err = source.Read(context.Background(), config, nil)
	if err == nil {
		t.Fatal("Read() error = nil, want Slack envelope error")
	}
	message := err.Error()
	for _, want := range []string{
		"slack API returned ok=false: missing_scope",
		"needed=users:read",
		"provided=team:read",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("Read() error = %q, want to contain %q", message, want)
		}
	}
	if strings.Contains(message, "response did not contain a record list") {
		t.Fatalf("Read() error = %q, want provider envelope error before record-list parsing", message)
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/users.list" {
			t.Fatalf("request path = %q, want /users.list", got)
		}
		http.Error(w, `{"ok":false,"error":"service_unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	config := sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyUser,
		"tenant_id": "writer",
		"token":     "slack-token",
	})
	_, err = source.Read(context.Background(), config, nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "slack API returned 503: service_unavailable") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func TestReadUsesSlackCursorAndLimit(t *testing.T) {
	expectedRequests := []struct {
		cursor string
	}{
		{},
		{cursor: "cursor-2"},
	}
	requestIndex := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestIndex >= len(expectedRequests) {
			t.Fatalf("unexpected request %d: %s", requestIndex+1, r.URL.RequestURI())
		}
		if got := r.URL.EscapedPath(); got != "/users.list" {
			t.Fatalf("request path = %q, want /users.list", got)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		if got := r.URL.Query().Get("per_page"); got != "" {
			t.Fatalf("per_page = %q, want empty", got)
		}
		expected := expectedRequests[requestIndex]
		if expected.cursor != r.URL.Query().Get("cursor") {
			t.Fatalf("cursor = %q, want %q", r.URL.Query().Get("cursor"), expected.cursor)
		}
		response := map[string]any{
			"ok": true,
			"members": []map[string]any{{
				"id":      "U1",
				"team_id": "T1",
				"name":    "alice",
			}},
			"response_metadata": map[string]any{},
		}
		if expected.cursor == "" {
			response["response_metadata"] = map[string]any{"next_cursor": "cursor-2"}
		}
		requestIndex++
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	config := sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyUser,
		"per_page":  "2",
		"tenant_id": "writer",
		"token":     "slack-token",
	})
	first, err := source.Read(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "cursor-2" {
		t.Fatalf("first NextCursor = %#v, want cursor-2", first.NextCursor)
	}
	second, err := source.Read(context.Background(), config, &cerebrov1.SourceCursor{Opaque: "cursor-2"})
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if requestIndex != len(expectedRequests) {
		t.Fatalf("requests = %d, want %d", requestIndex, len(expectedRequests))
	}
}

func TestNewFixtureReplaysSlackFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyTeam, familyUser, familyChannel, familyUserGroup, familyAccessLog, familyChannelMember, familyUserGroupMember, familyAuditLog} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"audit_log_base_url": "https://audit.example.test",
			"channel_id":         "C1",
			"family":             family,
			"tenant_id":          "tenant",
			"usergroup_id":       "S1",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
	for _, tt := range []struct {
		family string
		kind   string
		want   map[string]string
	}{
		{family: familyTeam, kind: "slack.team", want: map[string]string{"team_id": "T1", "domain": "writer"}},
		{family: familyUser, kind: "slack.user", want: map[string]string{"user_id": "U1", "team_id": "T1", "email": "alice@example.test", "has_2fa": "false"}},
		{family: familyChannel, kind: "slack.channel", want: map[string]string{"channel_id": "C1", "team_id": "T1", "creator": "U1"}},
		{family: familyUserGroup, kind: "slack.user_group", want: map[string]string{"group_id": "S1", "team_id": "T1", "handle": "eng"}},
		{family: familyAccessLog, kind: "slack.access_log", want: map[string]string{"actor_id": "U1", "event_type": "team_access", "ip_address": "203.0.113.10"}},
		{family: familyChannelMember, kind: "slack.channel_member", want: map[string]string{"channel_id": "C1", "user_id": "U1", "membership_type": "channel"}},
		{family: familyUserGroupMember, kind: "slack.user_group_member", want: map[string]string{"usergroup_id": "S1", "user_id": "U1", "membership_type": "user_group"}},
		{family: familyAuditLog, kind: "slack.audit_log", want: map[string]string{"actor_id": "U1", "event_type": "user_login", "resource_id": "U2"}},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), familyConfigs[tt.family], nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if got := event.Kind; got != tt.kind {
				t.Fatalf("event kind = %q, want %q", got, tt.kind)
			}
			for key, want := range tt.want {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("attribute %q = %q, want %q", key, got, want)
				}
			}
		})
	}
}
