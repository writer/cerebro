package files_com

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

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/external_events" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"id":         1001,
				"event_type": "webhook.delivery",
				"status":     "success",
				"body":       `{"action":"file.uploaded","path":"/Finance/q2.csv"}`,
				"created_at": "2026-06-01T00:00:00Z",
				"body_url":   "https://example.files.com/external_events/1001/body",
			},
		})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "api_token": "test-token"}
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
	if event.Kind != "files_com.external_event" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if got := event.Attributes["event_type"]; got != "webhook.delivery" {
		t.Fatalf("event_type = %q, want webhook.delivery", got)
	}
	if got := event.Attributes["outcome_result"]; got != "success" {
		t.Fatalf("outcome_result = %q, want success", got)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{
		familyActionNotificationExportResult,
		familyApiKey,
		familyExavaultReserved,
		familyExternalEvent,
		familyGroup,
		familyGroupUser,
		familyLogin,
		familyPermission,
		familySiteApiKey,
		familyUser,
		familyUserApiKey,
		familyUserGroup,
	} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":    family,
			"tenant_id": "tenant",
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
		{family: familyExternalEvent, kind: "files_com.external_event", want: map[string]string{"source_event_id": "1001", "event_type": "webhook.delivery"}},
		{family: familyApiKey, kind: "files_com.api_key", want: map[string]string{"secret_id": "2001", "secret_name": "prod automation key"}},
		{family: familyGroup, kind: "files_com.group", want: map[string]string{"group_id": "3001", "group_name": "Operations"}},
		{family: familyGroupUser, kind: "files_com.group_user", want: map[string]string{"user_id": "501", "group_id": "3001"}},
		{family: familyActionNotificationExportResult, kind: "files_com.action_notification_export_result", want: map[string]string{"alert_id": "4001", "alert_status": "200"}},
		{family: familyPermission, kind: "files_com.permission", want: map[string]string{"resource_id": "5001", "resource_type": "permission"}},
		{family: familyLogin, kind: "files_com.login", want: map[string]string{"actor_id": "501", "source_ip": "203.0.113.10"}},
		{family: familySiteApiKey, kind: "files_com.site_api_key", want: map[string]string{"secret_id": "2002", "secret_name": "site ingest key"}},
		{family: familyUserApiKey, kind: "files_com.user_api_key", want: map[string]string{"secret_id": "2003", "secret_name": "ada cli key"}},
		{family: familyExavaultReserved, kind: "files_com.exavault_reserved", want: map[string]string{"resource_id": "exavault-sftp-us-east", "resource_type": "ip_address_range"}},
		{family: familyUserGroup, kind: "files_com.user_group", want: map[string]string{"group_id": "3002", "group_name": "Finance"}},
		{family: familyUser, kind: "files_com.user", want: map[string]string{"user_id": "501", "login": "ada"}},
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
			for key, value := range tt.want {
				if got := event.Attributes[key]; got != value {
					t.Fatalf("attribute %q = %q, want %q", key, got, value)
				}
			}
		})
	}
}

func TestProviderUnavailableResponseReturnsError(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "maintenance"})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    defaultFamily,
		"api_token": "test-token",
	})
	err = source.Check(context.Background(), cfg)
	if err == nil {
		t.Fatal("Check() error = nil, want provider unavailable error")
	}
	var statusErr interface{ StatusCode() int }
	if !errors.As(err, &statusErr) || statusErr.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("Check() error = %v, want provider unavailable status", err)
	}
}
