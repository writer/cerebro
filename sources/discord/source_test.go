package discord

import (
	"bytes"
	"context"
	"embed"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed testdata/*.json
var testFiles embed.FS

// These fixtures are normalized provider-contract vectors. They are not live
// response captures and carry no provider provenance claim.

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bot test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/guilds/test-guild_id/audit-logs" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("after") != "0" {
			t.Fatalf("after = %q, want 0", r.URL.Query().Get("after"))
		}
		if limit := r.URL.Query().Get("limit"); limit != "1" && limit != "2" {
			t.Fatalf("limit = %q, want Check=1 or Read=2", limit)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readFixture(t, "testdata/read_audit_log.json"))
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "api_token": "test-token", "application_id": "test-application_id", "guild_id": "test-guild_id", "per_page": "2"}
	cfg := sourcecdk.NewConfig(cfgValues)
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("events = %d, want 2", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "discord.audit_log" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if event.Attributes["event_type"] != "10" {
		t.Fatalf("event_type = %q, want action_type 10", event.Attributes["event_type"])
	}
	if got := sourcecdk.CursorToken(pull.NextCursor); got != "100000000000000002" {
		t.Fatalf("cursor = %q, want highest audit entry id", got)
	}
	if got := pull.Events[1].Attributes["actor_id"]; got != "" {
		t.Fatalf("actorless audit actor_id = %q, want empty", got)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want one selected-family Check and one Read", requests)
	}
}

func TestSourceCheckUsesSelectedFamily(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/guilds/100000000000000000/members" {
			t.Fatalf("Check path = %q, want selected member family", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readFixture(t, "testdata/read_member.json"))
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant", "base_url": server.URL, "family": familyMember,
		"api_token": "test-token", "application_id": "200000000000000000",
		"guild_id": "100000000000000000",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestMemberReadUsesRawArrayAndHighestUserIDCursor(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bot test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/guilds/100000000000000000/members" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "2" {
			t.Fatalf("limit = %q, want 2", r.URL.Query().Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch after := r.URL.Query().Get("after"); after {
		case "0":
			_, _ = w.Write(readFixture(t, "testdata/read_member.json"))
		case "100000000000000002":
			_, _ = w.Write([]byte(`[{"avatar":null,"joined_at":"2026-06-03T00:00:00Z","deaf":false,"mute":false,"roles":[],"user":{"id":"100000000000000003","username":"member-three"}}]`))
		default:
			t.Fatalf("after = %q", after)
		}
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":      "tenant",
		"base_url":       server.URL,
		"family":         familyMember,
		"api_token":      "test-token",
		"application_id": "200000000000000000",
		"guild_id":       "100000000000000000",
		"per_page":       "2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if len(first.Events) != 2 || sourcecdk.CursorToken(first.NextCursor) != "100000000000000002" {
		t.Fatalf("first events/cursor = %d/%q", len(first.Events), sourcecdk.CursorToken(first.NextCursor))
	}
	if got := first.Events[0].Attributes["user_id"]; got != "100000000000000001" {
		t.Fatalf("first user_id = %q", got)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if len(second.Events) != 1 || second.NextCursor != nil {
		t.Fatalf("second events/cursor = %d/%#v", len(second.Events), second.NextCursor)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestFullMemberPageWithoutHighestUserIDFails(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"avatar":null,"joined_at":"2026-06-01T00:00:00Z","deaf":false,"mute":false,"roles":[],"user":{"id":"100000000000000001","username":"member-one"}},
			{"avatar":null,"joined_at":"2026-06-02T00:00:00Z","deaf":false,"mute":false,"roles":[],"user":{"username":"missing-id"}}
		]`))
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant", "base_url": server.URL, "family": familyMember,
		"api_token": "test-token", "application_id": "200000000000000000",
		"guild_id": "100000000000000000", "per_page": "2",
	})
	_, err = source.Read(context.Background(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "member id is required") {
		t.Fatalf("Read() error = %v, want required highest user id", err)
	}
}

func TestResumedCursorMustBePositiveSnowflake(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant", "family": familyMember, "api_token": "test-token",
		"application_id": "200000000000000000", "guild_id": "100000000000000000",
	})
	for _, cursor := range []string{"0", "not-a-snowflake"} {
		_, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: cursor})
		if err == nil || !strings.Contains(err.Error(), "positive string snowflake") {
			t.Fatalf("Read(cursor=%q) error = %v, want positive snowflake rejection", cursor, err)
		}
	}
}

func TestUnsortedMemberPageUsesNumericMaximumUserIDCursor(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"joined_at":"2026-06-09T00:00:00Z","deaf":false,"mute":false,"roles":[],"user":{"id":"100000000000000009","username":"later"}},
			{"joined_at":"2026-06-03T00:00:00Z","deaf":false,"mute":false,"roles":[],"user":{"id":"100000000000000003","username":"earlier"}}
		]`))
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant", "base_url": server.URL, "family": familyMember,
		"api_token": "test-token", "application_id": "200000000000000000",
		"guild_id": "100000000000000000", "per_page": "2",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got := sourcecdk.CursorToken(pull.NextCursor); got != "100000000000000009" {
		t.Fatalf("cursor = %q, want numeric maximum nested user.id", got)
	}
}

func TestNonpagedFamiliesSendNoPaginationQuery(t *testing.T) {
	tests := []struct {
		family string
		path   string
		body   string
	}{
		{family: familyRole, path: "/guilds/100000000000000000/roles", body: `[{"id":"500000000000000001","name":"operator","permissions":"8"}]`},
		{family: familyPermission, path: "/applications/200000000000000000/guilds/100000000000000000/commands/permissions", body: `[{"id":"600000000000000001","application_id":"200000000000000000","guild_id":"100000000000000000","permissions":[]}]`},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != test.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, test.path)
				}
				if r.URL.RawQuery != "" {
					t.Fatalf("query = %q, want no pagination query", r.URL.RawQuery)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			cfg := sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant", "base_url": server.URL, "family": test.family,
				"api_token": "test-token", "application_id": "200000000000000000",
				"guild_id": "100000000000000000", "per_page": "100",
			})
			if _, err := source.Read(context.Background(), cfg, nil); err != nil {
				t.Fatalf("Read() error = %v", err)
			}
		})
	}
}

func TestPermissionReadBindsResponseScopeToRequest(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "application", body: `[{"id":"600000000000000001","application_id":"200000000000000009","guild_id":"100000000000000000","permissions":[]}]`, want: "application_id does not match request scope"},
		{name: "guild", body: `[{"id":"600000000000000001","application_id":"200000000000000000","guild_id":"100000000000000009","permissions":[]}]`, want: "guild_id does not match request scope"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			cfg := sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant", "base_url": server.URL, "family": familyPermission,
				"api_token": "test-token", "application_id": "200000000000000000",
				"guild_id": "100000000000000000",
			})
			_, err = source.Read(context.Background(), cfg, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Read() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestFamiliesRejectWrongResponseEnvelopes(t *testing.T) {
	tests := []struct {
		family string
		body   string
		want   string
	}{
		{family: familyAuditLog, body: `{"items":[]}`, want: "audit_log_entries"},
		{family: familyMember, body: `{"items":[]}`, want: "bare array"},
		{family: familyRole, body: `{"items":[]}`, want: "bare array"},
		{family: familyPermission, body: `{"items":[]}`, want: "bare array"},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			cfg := sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant", "base_url": server.URL, "family": test.family,
				"api_token": "test-token", "application_id": "200000000000000000",
				"guild_id": "100000000000000000", "per_page": "2",
			})
			_, err = source.Read(context.Background(), cfg, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Read() error = %v, want %q", err, test.want)
			}
		})
	}
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := testFiles.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return bytes.TrimSpace(contents)
}
