package slack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
		response map[string]any
		want     map[string]string
	}{
		{
			name:   "team",
			family: "team",
			kind:   "slack.team",
			path:   "/auth.teams.list",
			response: map[string]any{"ok": true, "teams": []map[string]any{{
				"id": "T1", "name": "Writer", "domain": "writer",
			}}},
			want: map[string]string{"team_id": "T1", "name": "Writer", "domain": "writer"},
		},
		{
			name:   "user_privileged_no_mfa",
			family: "user",
			kind:   "slack.user",
			path:   "/users.list",
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
			family: "user",
			kind:   "slack.user",
			path:   "/users.list",
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
			family: "channel",
			kind:   "slack.channel",
			path:   "/conversations.list",
			response: map[string]any{"ok": true, "channels": []map[string]any{{
				"id": "C1", "name": "general", "context_team_id": "T1",
				"is_private": false, "is_archived": false, "creator": "U1", "num_members": 12,
			}}},
			want: map[string]string{"channel_id": "C1", "name": "general", "team_id": "T1", "is_private": "false", "creator": "U1"},
		},
		{
			name:   "shared_channel",
			family: "channel",
			kind:   "slack.channel",
			path:   "/conversations.list",
			response: map[string]any{"ok": true, "channels": []map[string]any{{
				"id": "C9", "name": "connect", "shared_team_ids": []string{"T1", "T2"},
				"is_private": false, "creator": "U1",
			}}},
			want: map[string]string{"channel_id": "C9", "name": "connect", "shared_team_ids": "T1,T2", "team_id": ""},
		},
		{
			name:   "user_group",
			family: "user_group",
			kind:   "slack.user_group",
			path:   "/usergroups.list",
			response: map[string]any{"ok": true, "usergroups": []map[string]any{{
				"id": "S1", "team_id": "T1", "handle": "eng", "name": "Engineering",
				"description": "Eng team", "is_disabled": false,
			}}},
			want: map[string]string{"group_id": "S1", "team_id": "T1", "handle": "eng", "name": "Engineering"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("request path = %q, want %s", got, tt.path)
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
