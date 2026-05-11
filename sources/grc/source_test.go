package grc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	testClientID     = "test-client"
	testClientSecret = "test-secret"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "grc" {
		t.Fatalf("Spec().Id = %q, want grc", source.Spec().Id)
	}
	if source.Spec().Name != "GRC" {
		t.Fatalf("Spec().Name = %q, want GRC", source.Spec().Name)
	}
}

func TestParseSettingsRequiresTenant(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"client_id":     testClientID,
		"client_secret": testClientSecret,
		"family":        familyVendor,
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want tenant_id error")
	}
}

func TestParseSettingsRejectsUnknownProvider(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"client_id":     testClientID,
		"client_secret": testClientSecret,
		"family":        familyVendor,
		"provider":      "drata",
		"tenant_id":     "writer",
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want unknown provider error")
	}
}

func TestReadVantaVendorPagesAsCanonicalGRCEvents(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := testConfig(server.URL, familyVendor)

	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	discover, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(discover) != 1 {
		t.Fatalf("len(Discover()) = %d, want 1", len(discover))
	}
	if got := discover[0].String(); !strings.Contains(got, "grc_vendor:vanta:vendor-1") {
		t.Fatalf("Discover()[0] = %q, want vendor-1 grc urn", got)
	}

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(first).Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "cursor-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-2", first.NextCursor)
	}
	event := first.Events[0]
	if event.Kind != "grc.vendor" {
		t.Fatalf("event.Kind = %q, want grc.vendor", event.Kind)
	}
	if event.SourceId != "grc" {
		t.Fatalf("event.SourceId = %q, want grc", event.SourceId)
	}
	if got := event.Attributes["provider"]; got != "vanta" {
		t.Fatalf("event provider = %q, want vanta", got)
	}
	if got := event.Attributes["inherent_risk_level"]; got != "HIGH" {
		t.Fatalf("event inherent_risk_level = %q, want HIGH", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("unmarshal event payload: %v", err)
	}
	if got := payload["name"]; got != "Acme SaaS" {
		t.Fatalf("payload name = %#v, want Acme SaaS", got)
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(second).Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
	if got := second.Events[0].Attributes["vendor_id"]; got != "vendor-2" {
		t.Fatalf("second vendor_id = %q, want vendor-2", got)
	}
}

func TestReadVantaVulnerabilityNormalizesFields(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := testConfig(server.URL, familyVulnerability)

	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(vulnerability) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(vulnerability).Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if got := attrs["name"]; got != "CVE-2026-4242" {
		t.Fatalf("vulnerability name = %q, want CVE-2026-4242", got)
	}
	if got := attrs["package"]; got != "pkg:golang/example/module@1.2.3" {
		t.Fatalf("package = %q, want purl", got)
	}
	if got := attrs["remediate_by_date"]; got != "2026-05-30T00:00:00Z" {
		t.Fatalf("remediate_by_date = %q, want deadline", got)
	}
}

func testConfig(baseURL string, family string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"base_url":      baseURL,
		"client_id":     testClientID,
		"client_secret": testClientSecret,
		"family":        family,
		"per_page":      "1",
		"provider":      "vanta",
		"tenant_id":     "writer",
	})
}

func newTestAPIHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			if r.Method != http.MethodPost {
				t.Fatalf("token method = %s, want POST", r.Method)
			}
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode token request: %v", err)
			}
			if payload["client_id"] != testClientID || payload["client_secret"] != testClientSecret {
				t.Fatalf("unexpected token credentials: %#v", payload)
			}
			writeJSON(t, w, map[string]any{
				"access_token": "test-token",
				"expires_in":   3599,
				"token_type":   "Bearer",
			})
		case "/v1/vendors":
			requireBearer(t, r)
			if r.URL.Query().Get("pageCursor") == "cursor-2" {
				writePage(t, w, false, "", []map[string]any{{
					"id":                               "vendor-2",
					"name":                             "Beta SaaS",
					"status":                           "APPROVED",
					"residualRiskLevel":                "LOW",
					"lastSecurityReviewCompletionDate": "2026-02-01T00:00:00Z",
				}})
				return
			}
			writePage(t, w, true, "cursor-2", []map[string]any{{
				"id":                               "vendor-1",
				"name":                             "Acme SaaS",
				"websiteUrl":                       "https://acme.example",
				"securityOwnerUserId":              "user-1",
				"status":                           "IN_REVIEW",
				"inherentRiskLevel":                "HIGH",
				"residualRiskLevel":                "MEDIUM",
				"nextSecurityReviewDueDate":        "2026-06-01T00:00:00Z",
				"lastSecurityReviewCompletionDate": "2025-06-01T00:00:00Z",
				"category":                         map[string]any{"displayName": "ai"},
			}})
		case "/v1/vulnerabilities":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":                "vuln-1",
				"name":              "CVE-2026-4242",
				"packageIdentifier": "pkg:golang/example/module@1.2.3",
				"severity":          "HIGH",
				"cvssSeverityScore": 8.7,
				"isFixable":         true,
				"remediateByDate":   "2026-05-30T00:00:00Z",
				"lastDetectedDate":  "2026-05-10T00:00:00Z",
			}})
		default:
			http.NotFound(w, r)
		}
	})
}

func requireBearer(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want bearer token", got)
	}
}

func writePage(t *testing.T, w http.ResponseWriter, hasNext bool, endCursor string, data []map[string]any) {
	t.Helper()
	writeJSON(t, w, map[string]any{
		"results": map[string]any{
			"pageInfo": map[string]any{
				"endCursor":   endCursor,
				"hasNextPage": hasNext,
			},
			"data": data,
		},
	})
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
