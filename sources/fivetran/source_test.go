package fivetran

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/fivetranapi"
)

func TestSourceCheckAndReadUsesFivetranRESTAPI(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("key-1:secret-1"))
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Fatalf("Authorization = %q, want %q", got, wantAuth)
		}
		if got := r.Header.Get("Accept"); got != "application/json;version=2" {
			t.Fatalf("Accept = %q", got)
		}
		requests = append(requests, r.URL.RequestURI())
		switch r.URL.Path {
		case "/v1/account/info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": "Success",
				"data": map[string]any{"account_id": "acct_1", "account_name": "Acme"},
			})
		case "/v1/users":
			if got := r.URL.Query().Get("limit"); got != "1" && got != "100" {
				t.Fatalf("limit = %q, want 1 or 100", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": "Success",
				"data": map[string]any{
					"items": []map[string]any{{
						"id":         "user_1",
						"email":      "user@example.test",
						"given_name": "User",
						"role":       "Account Administrator",
						"active":     true,
						"created_at": "2026-06-01T00:00:00Z",
					}},
					"next_cursor": "cursor-2",
				},
			})
		default:
			t.Fatalf("unexpected path %q", r.URL.RequestURI())
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":  "tenant",
		"base_url":   server.URL,
		"family":     fivetranapi.FamilyUsers,
		"api_key":    "key-1",
		"api_secret": "secret-1",
		"per_page":   "100",
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
	if event.Kind != "fivetran.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if got := event.Attributes["user_id"]; got != "user_1" {
		t.Fatalf("user_id = %q", got)
	}
	if got := event.Attributes["email"]; got != "user@example.test" {
		t.Fatalf("email = %q", got)
	}
	if sourcecdk.CursorToken(pull.NextCursor) != "cursor-2" {
		t.Fatalf("next cursor = %#v", pull.NextCursor)
	}
	if len(requests) < 3 || requests[0] != "/v1/account/info" || !strings.HasPrefix(requests[1], "/v1/users") || !strings.HasPrefix(requests[2], "/v1/users") {
		t.Fatalf("requests = %#v", requests)
	}
}

func TestSourceReadFansOutScopedGroupUsers(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/groups/group_1/users" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": "Success",
			"data": map[string]any{
				"items": []map[string]any{{
					"id":    "user_1",
					"email": "user@example.test",
				}},
			},
		})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    fivetranapi.FamilyGroupUsers,
		"group_ids": "group_1",
		"username":  "key-1",
		"password":  "secret-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Attributes["group_id"]; got != "group_1" {
		t.Fatalf("group_id = %q", got)
	}
	if got := event.Attributes["user_id"]; got != "user_1" {
		t.Fatalf("user_id = %q", got)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range fivetranapi.FamilyNames() {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"tenant_id": "tenant",
			"family":    family,
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func TestFivetranProviderUnavailableReturnsError(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"provider unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":   "tenant",
		"base_url":    server.URL,
		"family":      fivetranapi.FamilyUsers,
		"username":    "key-1",
		"password":    "secret-1",
		"health_path": "/v1/account/info",
	})
	if err := source.Check(context.Background(), cfg); err == nil {
		t.Fatal("Check() error = nil, want provider unavailable error")
	}
	if _, err := source.Discover(context.Background(), cfg); err == nil {
		t.Fatal("Discover() error = nil, want provider unavailable error")
	}
	if _, err := source.Read(context.Background(), cfg, nil); err == nil {
		t.Fatal("Read() error = nil, want provider unavailable error")
	}
}
