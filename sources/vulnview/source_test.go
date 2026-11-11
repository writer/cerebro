package vulnview

import (
	"context"
	"encoding/json"
	"errors"
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

func TestParseSettingsRejectsMissingBaseURL(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- invalid config fixture uses placeholder secret text.
		"tenant_id":     "writer",
		"okta_issuer":   "https://example.okta.com/oauth2/default",
		"client_id":     "client",
		"client_secret": "secret",
	}), false)
	if !errors.Is(err, errMissingBaseURL) {
		t.Fatalf("error = %v, want errMissingBaseURL", err)
	}
}

func TestParseSettingsRejectsTokenURLOutsideOktaIssuer(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- invalid config fixture uses placeholder secret text.
		"tenant_id":                          "writer",
		"base_url":                           "https://vulnview.example.test/api",
		"okta_issuer":                        "https://writer.okta.com/oauth2/default",
		"token_url":                          "https://attacker.example/token",
		"client_id":                          "client",
		"client_secret":                      "secret",
		sourceconfig.SourceTrustedOriginsKey: "vulnview=https://vulnview.example.test",
	}), false)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want non-nil")
	}
}

func TestParseSettingsAcceptsNonWriterOriginWhenTrusted(t *testing.T) {
	resolved, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- config fixture uses placeholder secret text.
		"tenant_id":                          "writer",
		"base_url":                           "https://vulnview.example.test/api",
		"okta_issuer":                        "https://writer.okta.com/oauth2/default",
		"client_id":                          "client",
		"client_secret":                      "secret",
		sourceconfig.SourceTrustedOriginsKey: "vulnview=https://vulnview.example.test",
	}), false)
	if err != nil {
		t.Fatalf("parseSettings() error = %v", err)
	}
	if resolved.baseURL != "https://vulnview.example.test/api" {
		t.Fatalf("baseURL = %q, want https://vulnview.example.test/api", resolved.baseURL)
	}
}

func TestParseSettingsRejectsUntrustedBaseURL(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id":                          "writer",
		"base_url":                           "https://attacker.example/api",
		"okta_issuer":                        "https://writer.okta.com/oauth2/default",
		"client_id":                          "client",
		"client_secret":                      "secret",
		sourceconfig.SourceTrustedOriginsKey: "vulnview=https://vulnview.example.test",
	}), false)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want non-nil")
	}
}

// Same configuration as TestParseSettingsAcceptsNonWriterOriginWhenTrusted
// without the deployment allowlist, so the rejection comes from the missing
// trusted origin.
func TestParseSettingsRejectsBaseURLWithNoTrustedOriginConfigured(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      "https://vulnview.example.test/api",
		"okta_issuer":   "https://writer.okta.com/oauth2/default",
		"client_id":     "client",
		"client_secret": "secret",
	}), false)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want missing trusted origin rejected")
	}
}

func TestReadAssetsPaginatesAndMapsAttributes(t *testing.T) {
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
		case "/assets":
			if got := r.Header.Get("Authorization"); got != "Bearer access" {
				t.Fatalf("Authorization = %q, want bearer token", got)
			}
			if got := r.URL.Query().Get("siteId"); got != "site-1" {
				t.Fatalf("siteId query = %q, want site-1", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
				{
					"asset":           "app.writer.com",
					"highestSeverity": "high",
					"findingsCount":   3,
					"sites":           "prod",
				},
				{
					"asset": "admin.writer.com",
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
		"family":        "asset",
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
	if got, want := event.Kind, "vulnview.asset"; got != want {
		t.Fatalf("event.Kind = %q, want %q", got, want)
	}
	if got, want := event.Attributes["asset_id"], "app.writer.com"; got != want {
		t.Fatalf("asset_id = %q, want %q", got, want)
	}
	if got, want := event.Attributes["highest_severity"], "high"; got != want {
		t.Fatalf("highest_severity = %q, want %q", got, want)
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

func TestReadScansLinksSiteAndCloudAccountContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
		case "/scans":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"scanId":         "scan-1",
				"siteId":         "site-1",
				"name":           "prod-web",
				"scanType":       "dns",
				"status":         "complete",
				"cloudAccountId": "123456789012",
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
		"family":        "scan",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if got := attrs["scan_id"]; got != "scan-1" {
		t.Fatalf("scan_id = %q, want scan-1", got)
	}
	if got := attrs["cloud_account_id"]; got != "123456789012" {
		t.Fatalf("cloud_account_id = %q, want 123456789012", got)
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
		case "/assets":
			want := "Bearer access-" + r.URL.Query().Get("search")
			if got := r.Header.Get("Authorization"); got != want {
				t.Fatalf("Authorization = %q, want %q", got, want)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"asset": "app.writer.com",
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
			"family":        "asset",
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

func TestParseSettingsRejectsMissingTenantID(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- config fixture uses placeholder secret text.
		"base_url":      "http://127.0.0.1/api",
		"client_id":     "client",
		"client_secret": "secret",
		"family":        "asset",
	}), true)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want tenant_id required")
	}
	if !errors.Is(err, errMissingTenantID) {
		t.Fatalf("error = %v, want errMissingTenantID", err)
	}
}

func TestParseSettingsRejectsMissingClientID(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- config fixture uses placeholder secret text.
		"tenant_id":     "writer",
		"base_url":      "http://127.0.0.1/api",
		"client_secret": "secret",
		"family":        "asset",
	}), true)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want client_id required")
	}
	if !errors.Is(err, errMissingClientID) {
		t.Fatalf("error = %v, want errMissingClientID", err)
	}
}

func TestParseSettingsRejectsMissingClientSecret(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  "http://127.0.0.1/api",
		"client_id": "client",
		"family":    "asset",
	}), true)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want client_secret required")
	}
	if !errors.Is(err, errMissingClientSecret) {
		t.Fatalf("error = %v, want errMissingClientSecret", err)
	}
}

func TestParseSettingsRejectsBaseURLWithFragment(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- config fixture uses placeholder secret text.
		"tenant_id":     "writer",
		"base_url":      "https://vulnview.example.test/api#section",
		"okta_issuer":   "https://writer.okta.com/oauth2/default",
		"client_id":     "client",
		"client_secret": "secret",
	}), false)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want fragment rejection")
	}
	if !errors.Is(err, errInvalidBaseComponents) {
		t.Fatalf("error = %v, want errInvalidBaseComponents", err)
	}
}

func TestParseSettingsRejectsUnsupportedFamily(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- config fixture uses placeholder secret text.
		"tenant_id":     "writer",
		"base_url":      "http://127.0.0.1/api",
		"client_id":     "client",
		"client_secret": "secret",
		"family":        "not_a_family",
	}), true)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want unsupported family")
	}
	if !errors.Is(err, errUnsupportedFamily) {
		t.Fatalf("error = %v, want errUnsupportedFamily", err)
	}
}

func TestParseSettingsRejectsInvalidPerPage(t *testing.T) {
	for _, perPage := range []string{"abc", "0", "501"} {
		_, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- config fixture uses placeholder secret text.
			"tenant_id":     "writer",
			"base_url":      "http://127.0.0.1/api",
			"client_id":     "client",
			"client_secret": "secret",
			"family":        "asset",
			"per_page":      perPage,
		}), true)
		if err == nil {
			t.Fatalf("parseSettings(per_page=%q) error = nil, want error", perPage)
		}
	}
}

func TestParseSettingsRequiresSourceForFindingFamily(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- config fixture uses placeholder secret text.
		"tenant_id":     "writer",
		"base_url":      "http://127.0.0.1/api",
		"client_id":     "client",
		"client_secret": "secret",
		"okta_issuer":   "http://127.0.0.1/oauth2/default",
		"family":        "finding",
	}), true)
	if !errors.Is(err, errMissingSource) {
		t.Fatalf("error = %v, want errMissingSource", err)
	}
}

func TestParseSettingsRejectsUnsupportedSource(t *testing.T) {
	_, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- config fixture uses placeholder secret text.
		"tenant_id":     "writer",
		"base_url":      "http://127.0.0.1/api",
		"client_id":     "client",
		"client_secret": "secret",
		"okta_issuer":   "http://127.0.0.1/oauth2/default",
		"family":        "finding",
		"source":        "not_a_source",
	}), true)
	if !errors.Is(err, errUnsupportedSource) {
		t.Fatalf("error = %v, want errUnsupportedSource", err)
	}
}

func TestParseSettingsAcceptsEachFindingSource(t *testing.T) {
	for _, source := range vulnViewFindingSources {
		resolved, err := parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- config fixture uses placeholder secret text.
			"tenant_id":     "writer",
			"base_url":      "http://127.0.0.1/api",
			"client_id":     "client",
			"client_secret": "secret",
			"okta_issuer":   "http://127.0.0.1/oauth2/default",
			"family":        "finding",
			"source":        source,
		}), true)
		if err != nil {
			t.Fatalf("parseSettings(source=%q) error = %v", source, err)
		}
		if resolved.source != source {
			t.Fatalf("resolved.source = %q, want %q", resolved.source, source)
		}
	}
}

func TestReadReturnsErrorOnHTTP404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "resource not found"})
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      server.URL,
		"token_url":     server.URL + "/token",
		"client_id":     "client",
		"client_secret": "secret",
		"family":        "asset",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want HTTP 404 error")
	}
	var respErr *sourcecdk.HTTPStatusError
	if !errors.As(err, &respErr) {
		t.Fatalf("error type = %T, want *sourcecdk.HTTPStatusError", err)
	}
	if respErr.StatusCode() != http.StatusNotFound {
		t.Fatalf("statusCode = %d, want %d", respErr.StatusCode(), http.StatusNotFound)
	}
}

func TestReadReturnsErrorOnHTTP500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "internal server error"})
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      server.URL,
		"token_url":     server.URL + "/token",
		"client_id":     "client",
		"client_secret": "secret",
		"family":        "asset",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want HTTP 500 error")
	}
	var respErr *sourcecdk.HTTPStatusError
	if !errors.As(err, &respErr) {
		t.Fatalf("error type = %T, want *sourcecdk.HTTPStatusError", err)
	}
	if respErr.StatusCode() != http.StatusInternalServerError {
		t.Fatalf("statusCode = %d, want %d", respErr.StatusCode(), http.StatusInternalServerError)
	}
}

func TestReadReturnsErrorOnHTTP429RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
		default:
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "rate limit exceeded"})
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      server.URL,
		"token_url":     server.URL + "/token",
		"client_id":     "client",
		"client_secret": "secret",
		"family":        "asset",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want HTTP 429 error")
	}
	var respErr *sourcecdk.HTTPStatusError
	if !errors.As(err, &respErr) {
		t.Fatalf("error type = %T, want *sourcecdk.HTTPStatusError", err)
	}
	if respErr.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("statusCode = %d, want %d", respErr.StatusCode(), http.StatusTooManyRequests)
	}
}

func TestTokenEndpointHTTP500ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "token service unavailable"})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      server.URL,
		"token_url":     server.URL + "/token",
		"client_id":     "client",
		"client_secret": "secret2",
		"family":        "asset",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want token endpoint error")
	}
	var respErr *sourcecdk.HTTPStatusError
	if !errors.As(err, &respErr) {
		t.Fatalf("error type = %T, want *sourcecdk.HTTPStatusError", err)
	}
	if respErr.StatusCode() != http.StatusInternalServerError {
		t.Fatalf("statusCode = %d, want %d", respErr.StatusCode(), http.StatusInternalServerError)
	}
}
