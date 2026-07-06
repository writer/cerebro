package apollo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndReadFamilies(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "test-key" {
			t.Fatalf("x-api-key = %q", r.Header.Get("x-api-key"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/users/api_profile":
			if r.Method != http.MethodGet {
				t.Fatalf("health method = %q", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "user-current", "email": "owner@example.test"})
		case "/users/search":
			assertApolloPageRequest(t, r, http.MethodGet)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pagination": map[string]any{"page": 1, "per_page": 100, "total_entries": 1, "total_pages": 1},
				"users":      []map[string]any{{"id": "user-1", "email": "user@example.test", "name": "Apollo User", "created_at": "2026-06-01T00:00:00Z", "deleted": false}},
			})
		case "/accounts/search":
			assertApolloPageRequest(t, r, http.MethodPost)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pagination": map[string]any{"page": 1, "per_page": 100, "total_entries": 1, "total_pages": 1},
				"accounts":   []map[string]any{{"id": "account-1", "name": "Apollo Account", "domain": "example.test", "organization_id": "org-1", "created_at": "2026-06-01T00:00:00Z"}},
			})
		case "/contacts/search":
			assertApolloPageRequest(t, r, http.MethodPost)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pagination": map[string]any{"page": 1, "per_page": 100, "total_entries": 1, "total_pages": 1},
				"contacts":   []map[string]any{{"id": "contact-1", "person_id": "person-1", "email": "contact@example.test", "name": "Apollo Contact", "title": "Buyer", "created_at": "2026-06-01T00:00:00Z"}},
			})
		default:
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	baseCfg := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "api_key": "test-key"}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(baseCfg)); err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	for _, tc := range []struct {
		family string
		kind   string
	}{
		{family: familyUsers, kind: "apollo.users"},
		{family: familyAccounts, kind: "apollo.accounts"},
		{family: familyContacts, kind: "apollo.contacts"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			cfgValues := map[string]string{}
			for key, value := range baseCfg {
				cfgValues[key] = value
			}
			cfgValues["family"] = tc.family
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(cfgValues), nil)
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
		})
	}
}

func assertApolloPageRequest(t *testing.T, r *http.Request, method string) {
	t.Helper()
	if r.Method != method {
		t.Fatalf("method for %s = %q, want %q", r.URL.Path, r.Method, method)
	}
	if got := r.URL.Query().Get("page"); got != "1" {
		t.Fatalf("page for %s = %q, want 1", r.URL.Path, got)
	}
	if got := r.URL.Query().Get("per_page"); got != "1" && got != "100" {
		t.Fatalf("per_page for %s = %q, want 1 or 100", r.URL.Path, got)
	}
}
