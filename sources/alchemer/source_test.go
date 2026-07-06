package alchemer

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
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want empty query-parameter auth", got)
		}
		if got := r.URL.Query().Get("api_token"); got != "test-token" {
			t.Fatalf("api_token = %q, want test-token", got)
		}
		if got := r.URL.Query().Get("api_token_secret"); got != "test-secret" {
			t.Fatalf("api_token_secret = %q, want test-secret", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v5/account":
			_ = json.NewEncoder(w).Encode(map[string]any{"result_ok": true, "data": map[string]any{"id": "acct-1", "organization": "Writer"}})
		case "/v5/accountuser":
			if got := r.URL.Query().Get("page"); got != "1" {
				t.Fatalf("page = %q, want 1", got)
			}
			if got := r.URL.Query().Get("resultsperpage"); got != "1" && got != "100" {
				t.Fatalf("resultsperpage = %q, want source check or read page size", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"result_ok": true, "total_count": 1, "page": 1, "total_pages": 1, "results_per_page": 100, "data": []map[string]any{{"id": "user-1", "username": "Ada", "email": "ada@example.test", "status": "Active"}}})
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "api_token": "test-token", "api_token_secret": "test-secret"}
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
	if event.Kind != "alchemer.account_users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestSourceReadSSOIntegrationsFromKeyedObjectMap(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v5/sso" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("page"); got != "1" {
			t.Fatalf("page = %q, want 1", got)
		}
		if got := r.URL.Query().Get("resultsperpage"); got != "100" {
			t.Fatalf("resultsperpage = %q, want 100", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result_ok":        true,
			"total_count":      1,
			"page":             1,
			"total_pages":      1,
			"results_per_page": 100,
			"data": map[string]any{
				"sso-1": map[string]any{
					"id":              "sso-1",
					"name":            "Corporate SSO",
					"entity_id":       "https://idp.example.test",
					"status":          "Active",
					"type":            "Account",
					"created":         "2017-02-06 15:51:04",
					"dModified":       "2017-06-22 17:23:43",
					"sp_metadata":     "app.alchemer.com/login/getsamlxml/idp/sso-1",
					"sp_login":        "app.alchemer.com/ssologin.php?idp=sso-1",
					"creatusers":      "false",
					"force_sso_login": "0",
				},
			},
		})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familySSOIntegrations, "api_token": "test-token", "api_token_secret": "test-secret"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "alchemer.sso_integrations" {
		t.Fatalf("kind = %q", event.Kind)
	}
	attrs := event.Attributes
	if attrs["policy_id"] != "sso-1" || attrs["policy_name"] != "Corporate SSO" || attrs["policy_status"] != "Active" {
		t.Fatalf("policy attributes = %#v, want nested SSO object fields", attrs)
	}
	if attrs["resource_name"] != "Corporate SSO" {
		t.Fatalf("resource_name = %q, want Corporate SSO", attrs["resource_name"])
	}
	var payload map[string]any
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	record, ok := payload["sso_integration"].(map[string]any)
	if !ok || record["name"] != "Corporate SSO" {
		t.Fatalf("payload = %#v, want keyed map record under sso_integration", payload)
	}
}

func TestSourceReadUsesAlchemerPagePagination(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if r.URL.Path != "/v5/accountuser" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("resultsperpage"); got != "2" {
			t.Fatalf("resultsperpage = %q, want 2", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "1":
			_ = json.NewEncoder(w).Encode(map[string]any{"result_ok": true, "total_count": 3, "page": 1, "total_pages": 2, "results_per_page": 2, "data": []map[string]any{{"id": "user-1", "username": "Ada"}, {"id": "user-2", "username": "Grace"}}})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{"result_ok": true, "total_count": 3, "page": 2, "total_pages": 2, "results_per_page": 2, "data": []map[string]any{{"id": "user-3", "username": "Katherine"}}})
		default:
			t.Fatalf("unexpected page %q", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "api_token": "test-token", "api_token_secret": "test-secret", "per_page": "2"})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first cursor = %#v, want page 2", first.NextCursor)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second cursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 || requests[0].URL.Query().Get("page") != "1" || requests[1].URL.Query().Get("page") != "2" {
		t.Fatalf("pagination requests = %#v", requests)
	}
}
