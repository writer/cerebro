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
