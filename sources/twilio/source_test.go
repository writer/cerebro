package twilio

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/2010-04-01/Accounts.json" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"id": "record-1", "resource_urn": "urn:cerebro:tenant:runtime_asset:record-1", "resource_type": "asset", "resource_id": "record-1", "name": "Record One", "updated_at": "2026-06-01T00:00:00Z"}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token", "account_sid": "test-account_sid"}
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
	if event.Kind != "twilio.accounts" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestAccountsSourceWorkerFixtureParity(t *testing.T) {
	fixture, err := os.ReadFile("testdata/source_worker_accounts_page.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Basic test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.URL.Path; got != "/2010-04-01/Accounts.json" {
			t.Fatalf("path = %q", got)
		}
		if got := r.URL.Query().Get("limit"); got != "100" {
			t.Fatalf("limit = %q", got)
		}
		if got := r.URL.Query().Get("cursor"); got != "accounts-page-1" {
			t.Fatalf("cursor = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyAccounts,
		"tenant_id": "tenant",
		"token":     "test-token",
	})
	pull, err := source.Read(
		context.Background(),
		cfg,
		&cerebrov1.SourceCursor{Opaque: "accounts-page-1"},
	)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want one deduplicated event", len(pull.Events))
	}
	if pull.NextCursor == nil || pull.NextCursor.GetOpaque() != "accounts-page-2" {
		t.Fatalf("next cursor = %#v", pull.NextCursor)
	}

	event := pull.Events[0]
	scope := sha256.Sum256([]byte(server.URL + "\x00/2010-04-01/Accounts.json"))
	wantEventID := "twilio-tenant-" + hex.EncodeToString(scope[:])[:12] + "-accounts-record-1"
	if event.GetId() != wantEventID {
		t.Fatalf("event id = %q, want %q", event.GetId(), wantEventID)
	}
	if event.GetTenantId() != "tenant" || event.GetKind() != "twilio.accounts" || event.GetSchemaRef() != "twilio/accounts/v1" {
		t.Fatalf("event scope = %#v", event)
	}
	if got, want := event.GetOccurredAt().AsTime(), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("occurred_at = %s, want %s", got, want)
	}
	for name, want := range map[string]string{
		"source_event_id": "provider-event-1",
		"tenant_id":       "tenant",
		"user_id":         "record-1",
	} {
		if got := event.GetAttributes()[name]; got != want {
			t.Fatalf("attribute %s = %q, want %q", name, got, want)
		}
	}
	var payload map[string]any
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		t.Fatalf("decode event payload: %v", err)
	}
	if payload["id"] != "record-1" || payload["name"] != "Record One" {
		t.Fatalf("payload = %#v", payload)
	}
}
