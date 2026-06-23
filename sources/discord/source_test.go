package discord

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/guilds/test-guild_id/audit-logs" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"id": "record-1", "resource_urn": "urn:cerebro:tenant:runtime_asset:record-1", "resource_type": "asset", "resource_id": "record-1", "name": "Record One", "updated_at": "2026-06-01T00:00:00Z"}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "api_token": "test-token", "application_id": "test-application_id", "guild_id": "test-guild_id"}
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
	if event.Kind != "discord.audit_log" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestAuditLogReadsAuditLogEntries(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/guilds/test-guild_id/audit-logs" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"application_commands": []map[string]string{{"id": "command-1", "name": "wrong-list"}},
			"audit_log_entries":    []map[string]string{{"id": "audit-1", "user_id": "user-1", "action_type": "MEMBER_BAN_ADD", "target_id": "member-1"}},
		})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyAuditLog, "api_token": "test-token", "application_id": "test-application_id", "guild_id": "test-guild_id"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if !strings.Contains(event.Id, "audit-1") || strings.Contains(event.Id, "command-1") {
		t.Fatalf("event id = %q, want audit entry id", event.Id)
	}
	if got := event.Attributes["actor_id"]; got != "user-1" {
		t.Fatalf("actor_id = %q, want user-1", got)
	}
	if got := event.Attributes["event_type"]; got != "MEMBER_BAN_ADD" {
		t.Fatalf("event_type = %q, want MEMBER_BAN_ADD", got)
	}
}

func TestMemberUsesUserIDInsteadOfAvatar(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/guilds/test-guild_id/members" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"avatar": "avatar-hash", "user": map[string]string{"id": "user-1", "username": "User One"}, "nick": "Member Nick"}}})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyMember, "api_token": "test-token", "application_id": "test-application_id", "guild_id": "test-guild_id"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if !strings.Contains(event.Id, "user-1") || strings.Contains(event.Id, "avatar-hash") {
		t.Fatalf("event id = %q, want user id without avatar hash", event.Id)
	}
	if got := event.Attributes["id"]; got != "user-1" {
		t.Fatalf("id attribute = %q, want user-1", got)
	}
	if got := event.Attributes["provider_id"]; got != "user-1" {
		t.Fatalf("provider_id = %q, want user-1", got)
	}
	if got := event.Attributes["source_event_id"]; got != "user-1" {
		t.Fatalf("source_event_id = %q, want user-1", got)
	}
	if got := event.Attributes["name"]; got != "User One" {
		t.Fatalf("name = %q, want User One", got)
	}
}
