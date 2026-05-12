package vulnview

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestParseSettingsRejectsUnsafeBaseURL(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      "http://169.254.169.254/api",
		"okta_issuer":   "https://example.okta.com/oauth2/default",
		"client_id":     "client",
		"client_secret": "secret",
	}), false)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want non-nil")
	}
}

func TestParseSettingsRejectsTokenURLOutsideOktaIssuer(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      "https://vulnview.writer-security.com/api",
		"okta_issuer":   "https://writer.okta.com/oauth2/default",
		"token_url":     "https://attacker.example/token",
		"client_id":     "client",
		"client_secret": "secret",
	}), false)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want non-nil")
	}
}

func TestReadVulnerabilitiesPaginatesAndMapsAttributes(t *testing.T) {
	var tokenRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenRequests++
			if got := r.FormValue("grant_type"); got != "client_credentials" {
				t.Fatalf("grant_type = %q, want client_credentials", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
		case "/vulnerabilities":
			if got := r.Header.Get("Authorization"); got != "Bearer access" {
				t.Fatalf("Authorization = %q, want bearer token", got)
			}
			if got := r.URL.Query().Get("siteId"); got != "site-1" {
				t.Fatalf("siteId query = %q, want site-1", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
				{
					"type":        "vulnerability",
					"templateId":  "cve-2026-1234",
					"name":        "Test CVE",
					"severity":    "high",
					"host":        "app.writer.com",
					"matchedAt":   "https://app.writer.com/login",
					"scanId":      "scan-1",
					"scanName":    "prod-web",
					"siteId":      "site-1",
					"siteName":    "prod",
					"description": "test finding",
					"timestamp":   "2026-05-12T00:00:00Z",
				},
				{
					"type":       "vulnerability",
					"templateId": "exposed-panel",
					"name":       "Exposed Panel",
					"severity":   "medium",
					"host":       "admin.writer.com",
					"scanId":     "scan-2",
				},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      server.URL,
		"token_url":     server.URL + "/token",
		"client_id":     "client",
		"client_secret": "secret",
		"family":        "vulnerability",
		"site_id":       "site-1",
		"per_page":      "1",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor.GetOpaque() != "1" {
		t.Fatalf("first.NextCursor = %q, want 1", first.NextCursor.GetOpaque())
	}
	event := first.Events[0]
	if got, want := event.Kind, "vulnview.vulnerability"; got != want {
		t.Fatalf("event.Kind = %q, want %q", got, want)
	}
	if got, want := event.Attributes["template_id"], "cve-2026-1234"; got != want {
		t.Fatalf("template_id = %q, want %q", got, want)
	}
	if got, want := event.Attributes["target_id"], "app.writer.com"; got != want {
		t.Fatalf("target_id = %q, want %q", got, want)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %v, want nil", second.NextCursor)
	}
	if tokenRequests != 1 {
		t.Fatalf("tokenRequests = %d, want cached token reuse", tokenRequests)
	}
}

func TestAccessTokenCacheScopesByClientSecret(t *testing.T) {
	tokenRequests := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			secret := r.FormValue("client_secret")
			tokenRequests[secret]++
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-" + secret, "token_type": "Bearer", "expires_in": 3600})
		case "/vulnerabilities":
			want := "Bearer access-" + r.URL.Query().Get("search")
			if got := r.Header.Get("Authorization"); got != want {
				t.Fatalf("Authorization = %q, want %q", got, want)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"templateId": "cve-2026-1234",
				"name":       "Test CVE",
				"severity":   "high",
				"host":       "app.writer.com",
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	for _, secret := range []string{"one", "two"} {
		cfg := sourcecdk.NewConfig(map[string]string{
			"tenant_id":     "writer",
			"base_url":      server.URL,
			"token_url":     server.URL + "/token",
			"client_id":     "client",
			"client_secret": secret,
			"family":        "vulnerability",
			"search":        secret,
		})
		if _, err := source.Read(context.Background(), cfg, nil); err != nil {
			t.Fatalf("Read(%s) error = %v", secret, err)
		}
	}
	if tokenRequests["one"] != 1 || tokenRequests["two"] != 1 {
		t.Fatalf("tokenRequests = %#v, want one request per secret", tokenRequests)
	}
}

func TestReadDNSAlertsPaginatesWithinAsset(t *testing.T) {
	var assetRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
		case "/assets":
			assetRequests++
			if got := r.URL.Query().Get("limit"); got != "1" {
				t.Fatalf("limit = %q, want 1", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"asset": "staging.writer.com",
				"dnsAlerts": []map[string]any{
					{"alert": "dangling-cname", "severity": "high"},
					{"alert": "stale-a-record", "severity": "medium"},
				},
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      server.URL,
		"token_url":     server.URL + "/token",
		"client_id":     "client",
		"client_secret": "secret",
		"family":        "dns_alert",
		"per_page":      "1",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil {
		t.Fatal("first.NextCursor = nil, want cursor for second alert")
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if first.Events[0].Attributes["alert"] == second.Events[0].Attributes["alert"] {
		t.Fatalf("alerts were not paginated distinctly: %q", first.Events[0].Attributes["alert"])
	}
	if assetRequests != 2 {
		t.Fatalf("assetRequests = %d, want 2", assetRequests)
	}
}
