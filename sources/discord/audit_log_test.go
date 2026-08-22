package discord

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestAuditLogStableIdentityTimestampAndDuplicateParity(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/guilds/100000000000000000/audit-logs" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("after") != "0" || r.URL.Query().Get("limit") != "3" {
			t.Fatalf("query = %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readFixture(t, "testdata/read_audit_log_duplicates.json"))
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant", "base_url": server.URL, "family": familyAuditLog,
		"api_token": "test-token", "guild_id": "100000000000000000", "per_page": "3",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("events = %d, want identical duplicate collapsed", len(pull.Events))
	}
	first := pull.Events[0]
	wantID := auditEventID("tenant", server.URL, "/guilds/100000000000000000/audit-logs", "100000000000000001")
	if first.Id != wantID || first.TenantId != "tenant" {
		t.Fatalf("identity = %q/%q, want %q/tenant", first.Id, first.TenantId, wantID)
	}
	if first.SourceId != "discord" || first.Kind != "discord.audit_log" || first.SchemaRef != "discord/audit_log/v1" {
		t.Fatalf("event contract = %q/%q/%q", first.SourceId, first.Kind, first.SchemaRef)
	}
	for key, want := range map[string]string{
		"external_id": "100000000000000001", "family": familyAuditLog,
		"guild_id": "100000000000000000", "provider": "discord",
		"provider_id": "100000000000000001", "record_class": "audit_event",
		"schema": "audit_log", "source_event_id": "100000000000000001",
		"source_provider": "discord", "source_system": "discord",
	} {
		if got := first.Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
	if _, exists := first.Attributes["reason"]; exists {
		t.Fatalf("reason must remain payload-only: %#v", first.Attributes)
	}
	if got := first.OccurredAt.AsTime().UnixMilli(); got != 1_443_912_257_910 {
		t.Fatalf("OccurredAt millis = %d, want snowflake-derived time", got)
	}
	if got := sourcecdk.CursorToken(pull.NextCursor); got != "100000000000000002" {
		t.Fatalf("cursor = %q, want raw full-page high watermark", got)
	}
	if pull.Checkpoint == nil || pull.Checkpoint.Watermark.AsTime().UnixMilli() != 1_443_912_257_910 {
		t.Fatalf("checkpoint watermark = %#v, want last accepted snowflake time", pull.Checkpoint)
	}
}

func TestAuditLogDefaultPagePlanMatchesRust(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatal(err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") != "0" || r.URL.Query().Get("limit") != "50" {
			t.Fatalf("query = %q, want deterministic after=0 limit=50", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readFixture(t, "testdata/read_audit_log.json"))
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant", "base_url": server.URL, "family": familyAuditLog,
		"api_token": "test-token", "guild_id": "100000000000000000",
	})
	if _, err := source.Read(context.Background(), cfg, nil); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
}

func TestAuditLogConflictingDuplicateFailsClosed(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"audit_log_entries":[
			{"id":"100000000000000001","user_id":null,"action_type":10,"target_id":null},
			{"id":"100000000000000001","user_id":null,"action_type":20,"target_id":null}
		]}`))
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant", "base_url": server.URL, "family": familyAuditLog,
		"api_token": "test-token", "guild_id": "100000000000000000", "per_page": "2",
	})
	_, err = source.Read(context.Background(), cfg, nil)
	if !errors.Is(err, errConflictingDuplicate) {
		t.Fatalf("Read() error = %v, want conflicting duplicate", err)
	}
}

func TestAuditLogProviderFailuresRetainTypedStatuses(t *testing.T) {
	tests := []struct {
		status int
	}{
		{status: http.StatusUnauthorized},
		{status: http.StatusForbidden},
		{status: http.StatusTooManyRequests},
	}
	for _, test := range tests {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatal(err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(`{"message":"provider rejected request"}`))
			}))
			defer server.Close()
			cfg := sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant", "base_url": server.URL, "family": familyAuditLog,
				"api_token": "test-token", "guild_id": "100000000000000000", "per_page": "2",
			})
			_, err = source.Read(context.Background(), cfg, nil)
			var statusErr interface{ StatusCode() int }
			if !errors.As(err, &statusErr) {
				t.Fatalf("Read() error = %T %v, want typed status error", err, err)
			}
			if statusErr.StatusCode() != test.status {
				t.Fatalf("status = %d, want %d", statusErr.StatusCode(), test.status)
			}
		})
	}
}

func TestAuditLogCursorRequiresPositiveSnowflake(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatal(err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant", "family": familyAuditLog,
		"api_token": "test-token", "guild_id": "100000000000000000",
	})
	_, err = source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: "0"})
	if !errors.Is(err, errInvalidCursor) {
		t.Fatalf("Read() error = %v, want typed cursor failure", err)
	}
}

func TestAuditLogResponseBytesAreProviderBounded(t *testing.T) {
	body := make([]byte, maxAuditResponseBytes+1)
	if err := validateResponseEnvelope(familyAuditLog, body); !errors.Is(err, errAuditResponseTooLarge) {
		t.Fatalf("validateResponseEnvelope() error = %v, want response bound", err)
	}
}

func TestAuditLogProviderTenantIsRejected(t *testing.T) {
	body := []byte(`{"audit_log_entries":[{"id":"100000000000000001","user_id":null,"action_type":10,"target_id":null,"tenant_id":"attacker"}]}`)
	if err := validateResponseEnvelope(familyAuditLog, body); !errors.Is(err, errInvalidAuditRecord) {
		t.Fatalf("validateResponseEnvelope() error = %v, want runtime-owned tenant rejection", err)
	}
}

func auditEventID(tenantID, baseURL, path, providerID string) string {
	scope := sha256.Sum256([]byte(strings.TrimRight(baseURL, "/") + "\x00" + path))
	return strings.Join([]string{"discord", tenantID, hex.EncodeToString(scope[:])[:12], familyAuditLog, providerID}, "-")
}
