package cloudflare_zero_trust

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
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/accounts/test-account_id/access/users" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"id":         "user-1",
				"email":      "alice@example.com",
				"name":       "Alice Example",
				"last_seen":  "2026-06-01T00:00:00Z",
				"created_at": "2026-05-01T00:00:00Z",
			}},
			"success": true,
		})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "account_id": "test-account_id", "base_url": server.URL, "family": defaultFamily, "token": "test-token"}
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
	if event.Kind != "cloudflare_zero_trust.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}

	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyApplications, familyAuditEvents, familyGroups, familyRoles, familyUsers} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"account_id": "account-1",
			"family":     family,
			"tenant_id":  "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"errors":[{"message":"service unavailable"}]}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id": "account-1",
		"base_url":   server.URL,
		"family":     familyUsers,
		"tenant_id":  "writer",
		"token":      "token-1",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "cloudflare_zero_trust API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}
