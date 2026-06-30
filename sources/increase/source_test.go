package increase

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

func TestSourceCheckAndReadFamilies(t *testing.T) {
	tests := []struct {
		family         string
		path           string
		kind           string
		wantPayloadKey string
		wantAttr       string
	}{
		{family: familyAccount, path: "/accounts", kind: "increase.account", wantPayloadKey: "program_id", wantAttr: "resource_urn"},
		{family: familyAccountNumber, path: "/account_numbers", kind: "increase.account_number", wantPayloadKey: "inbound_ach", wantAttr: "resource_urn"},
		{family: familyAccountStatement, path: "/account_statements", kind: "increase.account_statement", wantPayloadKey: "statement_period_end", wantAttr: "resource_urn"},
		{family: familyAccountTransfer, path: "/account_transfers", kind: "increase.account_transfer", wantPayloadKey: "destination_account_id", wantAttr: "resource_urn"},
		{family: familyAchPrenotification, path: "/ach_prenotifications", kind: "increase.ach_prenotification", wantPayloadKey: "standard_entry_class_code", wantAttr: "alert_status"},
		{family: familyAchTransfer, path: "/ach_transfers", kind: "increase.ach_transfer", wantPayloadKey: "submission", wantAttr: "resource_urn"},
		{family: familyCard, path: "/cards", kind: "increase.card", wantPayloadKey: "authorization_controls", wantAttr: "resource_urn"},
		{family: familyDigitalWalletToken, path: "/digital_wallet_tokens", kind: "increase.digital_wallet_token", wantPayloadKey: "token_requestor", wantAttr: "secret_id"},
		{family: familyEvent, path: "/events", kind: "increase.event", wantPayloadKey: "associated_object_id", wantAttr: "event_type"},
		{family: familyEventSubscription, path: "/event_subscriptions", kind: "increase.event_subscription", wantPayloadKey: "selected_event_categories", wantAttr: "resource_urn"},
		{family: familyExternalAccount, path: "/external_accounts", kind: "increase.external_account", wantPayloadKey: "account_holder", wantAttr: "resource_urn"},
		{family: familyOauthConnection, path: "/oauth_connections", kind: "increase.oauth_connection", wantPayloadKey: "oauth_application_id", wantAttr: "resource_urn"},
	}

	for _, tc := range tests {
		t.Run(tc.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			payload := fixturePayload(t, tc.family)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
					t.Fatalf("Authorization = %q, want Bearer test-token", got)
				}
				if got := r.Header.Get("Accept"); got != "application/json" {
					t.Fatalf("Accept = %q, want application/json", got)
				}
				if r.URL.Path != tc.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tc.path)
				}
				if r.URL.Query().Get("per_page") != "" {
					t.Fatalf("per_page query = %q, want empty", r.URL.Query().Get("per_page"))
				}
				if limit := r.URL.Query().Get("limit"); limit != "" && limit != "1" {
					t.Fatalf("limit query = %q, want empty or 1", limit)
				}
				writeJSON(t, w, map[string]any{"data": []map[string]any{payload}, "next_cursor": "cursor-" + tc.family})
			}))
			defer server.Close()

			cfg := sourcecdk.NewConfig(map[string]string{
				"tenant_id":   "tenant",
				"base_url":    server.URL,
				"family":      tc.family,
				"health_path": tc.path,
				"token":       "test-token",
				"per_page":    "1",
			})
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
			if event.Kind != tc.kind {
				t.Fatalf("kind = %q, want %q", event.Kind, tc.kind)
			}
			if strings.TrimSpace(event.Id) == "" {
				t.Fatalf("event id is empty: %#v", event)
			}
			if got := event.Attributes["source_event_id"]; strings.TrimSpace(got) == "" {
				t.Fatalf("source_event_id is empty: %#v", event.Attributes)
			}
			if got := event.Attributes[tc.wantAttr]; strings.TrimSpace(got) == "" {
				t.Fatalf("%s is empty: %#v", tc.wantAttr, event.Attributes)
			}
			var gotPayload map[string]any
			if err := json.Unmarshal(event.Payload, &gotPayload); err != nil {
				t.Fatalf("unmarshal event payload: %v", err)
			}
			if _, ok := gotPayload[tc.wantPayloadKey]; !ok {
				t.Fatalf("payload missing %q: %#v", tc.wantPayloadKey, gotPayload)
			}
			if pull.NextCursor == nil || pull.NextCursor.Opaque != "cursor-"+tc.family {
				t.Fatalf("NextCursor = %#v, want provider cursor", pull.NextCursor)
			}
		})
	}
}

func TestSourceRequiresToken(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		writeJSON(t, w, map[string]any{"data": []map[string]any{fixturePayload(t, familyEvent)}})
	}))
	defer server.Close()

	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    familyEvent,
	}))
	if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("Check() error = %v, want ErrInvalidConfig", err)
	}
	if called {
		t.Fatalf("server was called without a token")
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" {
			t.Fatalf("path = %q, want /events", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
	}))
	defer server.Close()

	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    familyEvent,
		"token":     "test-token",
	}), nil)
	if got := sourcecdk.SourceErrorKind(err); got != sourcecdk.ErrorKindProvider {
		t.Fatalf("Read() error kind = %q, want provider; err=%v", got, err)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range increaseFamilies() {
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
	for _, family := range increaseFamilies() {
		t.Run(family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), familyConfigs[family], nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			payload := map[string]any{}
			if err := json.Unmarshal(pull.Events[0].Payload, &payload); err != nil {
				t.Fatalf("unmarshal fixture payload: %v", err)
			}
			rawPayload, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal fixture payload: %v", err)
			}
			if strings.Contains(string(rawPayload), "Record One") || strings.Contains(string(rawPayload), "source-increase") {
				t.Fatalf("fixture payload still contains generated placeholder values: %s", rawPayload)
			}
		})
	}
}

func fixturePayload(t *testing.T, family string) map[string]any {
	t.Helper()
	payload, err := fixtureFS.ReadFile("testdata/read_" + family + ".json")
	if err != nil {
		t.Fatalf("read fixture payload for %s: %v", family, err)
	}
	var events []struct {
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal(payload, &events); err != nil {
		t.Fatalf("unmarshal fixture payload for %s: %v", family, err)
	}
	if len(events) != 1 {
		t.Fatalf("fixture events for %s = %d, want 1", family, len(events))
	}
	return events[0].Payload
}

func increaseFamilies() []string {
	return []string{
		familyAccount,
		familyAccountNumber,
		familyAccountStatement,
		familyAccountTransfer,
		familyAchPrenotification,
		familyAchTransfer,
		familyCard,
		familyDigitalWalletToken,
		familyEvent,
		familyEventSubscription,
		familyExternalAccount,
		familyOauthConnection,
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, body map[string]any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
