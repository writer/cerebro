package vulnview

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
)

func TestParseSettingsUsesRuntimeTenantFallback(t *testing.T) {
	settings, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- config fixture uses placeholder secret text.
		"base_url":                      "http://127.0.0.1/api",
		"client_id":                     "client",
		"client_secret":                 "secret",
		"family":                        "asset",
		"okta_issuer":                   "http://127.0.0.1/oauth2/default",
		sourceconfig.RuntimeTenantIDKey: "writer",
	}), true)
	if err != nil {
		t.Fatalf("parseSettings() error = %v", err)
	}
	if settings.tenantID != "writer" {
		t.Fatalf("tenantID = %q, want writer", settings.tenantID)
	}
}

func TestParseSettingsRejectsUnsafeBaseURL(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- invalid config fixture uses placeholder secret text.
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
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- invalid config fixture uses placeholder secret text.
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

func TestParseSettingsRejectsUntrustedBaseURL(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      "https://attacker.example/api",
		"okta_issuer":   "https://writer.okta.com/oauth2/default",
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
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm: %v", err)
			}
			tokenRequests++
			if got := r.Form.Get("grant_type"); got != "client_credentials" {
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

func TestReadVulnerabilitiesMapsFindingStateAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
		case "/vulnerabilities":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"type":       "vulnerability",
				"templateId": "cve-2026-1234",
				"name":       "Test CVE",
				"severity":   "high",
				"host":       "app.writer.com",
				"status":     "resolved",
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
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      server.URL,
		"token_url":     server.URL + "/token",
		"client_id":     "client",
		"client_secret": "secret",
		"family":        "vulnerability",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if got := attrs["vulnview_status"]; got != "resolved" {
		t.Fatalf("vulnview_status = %q, want resolved", got)
	}
	if got := attrs["vulnview_finding_state"]; got != "resolved" {
		t.Fatalf("vulnview_finding_state = %q, want resolved", got)
	}
	if _, ok := attrs["status"]; ok {
		t.Fatalf("generic status attribute = %q, want status to stay namespaced for vulnerability records", attrs["status"])
	}
}

func TestAccessTokenCacheScopesByClientSecret(t *testing.T) {
	tokenRequests := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm: %v", err)
			}
			secret := r.Form.Get("client_secret")
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

func TestReadDNSAlertsMapsFindingStateAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
		case "/assets":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"asset": "staging.writer.com",
				"dnsAlerts": []map[string]any{{
					"alert":    "dangling-cname",
					"severity": "high",
					"state":    "closed",
				}},
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
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      server.URL,
		"token_url":     server.URL + "/token",
		"client_id":     "client",
		"client_secret": "secret",
		"family":        "dns_alert",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if got := attrs["vulnview_state"]; got != "closed" {
		t.Fatalf("vulnview_state = %q, want closed", got)
	}
	if got := attrs["vulnview_finding_state"]; got != "closed" {
		t.Fatalf("vulnview_finding_state = %q, want closed", got)
	}
	if _, ok := attrs["state"]; ok {
		t.Fatalf("generic state attribute = %q, want state to stay namespaced for DNS alert records", attrs["state"])
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

func TestReadDNSAlertsBatchesAssetPages(t *testing.T) {
	var assetRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
		case "/assets":
			assetRequests++
			if got := r.URL.Query().Get("limit"); got != "3" {
				t.Fatalf("limit = %q, want 3", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
				{"asset": "empty.writer.com", "dnsAlerts": []map[string]any{}},
				{
					"asset":     "staging.writer.com",
					"dnsAlerts": []map[string]any{{"alert": "dangling-cname", "severity": "high"}},
				},
				{
					"asset":     "prod.writer.com",
					"dnsAlerts": []map[string]any{{"alert": "stale-a-record", "severity": "medium"}},
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
		"family":        "dns_alert",
		"per_page":      "3",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(pull.Events) = %d, want 2", len(pull.Events))
	}
	if assetRequests != 1 {
		t.Fatalf("assetRequests = %d, want 1", assetRequests)
	}
}

func TestReadDNSAlertsReturnsCursorForEmptyAssetBatch(t *testing.T) {
	var assetRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
		case "/assets":
			assetRequests++
			cursor := r.URL.Query().Get("cursor")
			if cursor == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"items":      []map[string]any{{"asset": "empty.writer.com", "dnsAlerts": []map[string]any{}}},
					"nextCursor": "1",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"asset":     "staging.writer.com",
				"dnsAlerts": []map[string]any{{"alert": "dangling-cname", "severity": "high"}},
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
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(pull.Events) = %d, want 0", len(pull.Events))
	}
	if pull.NextCursor == nil {
		t.Fatal("NextCursor = nil, want cursor for next asset page")
	}
	next, err := source.Read(context.Background(), cfg, pull.NextCursor)
	if err != nil {
		t.Fatalf("Read(next) error = %v", err)
	}
	if len(next.Events) != 1 {
		t.Fatalf("len(next.Events) = %d, want 1", len(next.Events))
	}
	if got := next.Events[0].Attributes["asset_id"]; got != "staging.writer.com" {
		t.Fatalf("asset_id = %q, want staging.writer.com", got)
	}
	if assetRequests != 2 {
		t.Fatalf("assetRequests = %d, want 2", assetRequests)
	}
}

func TestDiscoverDNSAlertsAdvancesPastEmptyAssetBatch(t *testing.T) {
	var assetRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
		case "/assets":
			assetRequests++
			cursor := r.URL.Query().Get("cursor")
			if cursor == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"items":      []map[string]any{{"asset": "empty.writer.com", "dnsAlerts": []map[string]any{}}},
					"nextCursor": "1",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"asset":     "staging.writer.com",
				"dnsAlerts": []map[string]any{{"alert": "dangling-cname", "severity": "high"}},
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
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 1 {
		t.Fatalf("len(urns) = %d, want 1", len(urns))
	}
	if assetRequests != 2 {
		t.Fatalf("assetRequests = %d, want 2", assetRequests)
	}
}
