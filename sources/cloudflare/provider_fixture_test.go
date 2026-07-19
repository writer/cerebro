package cloudflare

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceReplaysCapturedCloudflareFamilies(t *testing.T) {
	tests := []struct {
		family         string
		fixtureCase    string
		detailCase     string
		configKey      string
		captureTime    bool
		minimumRecords int
	}{
		{family: "account", fixtureCase: "list_accounts", captureTime: true, minimumRecords: 3},
		{family: "member", fixtureCase: "list_members", configKey: "account_id", captureTime: true, minimumRecords: 1},
		{family: "account_ruleset", fixtureCase: "list_account_rulesets", detailCase: "get_account_ruleset", configKey: "account_id", minimumRecords: 1},
		{family: "zone", fixtureCase: "list_zones", minimumRecords: 3},
		{family: "dns_record", fixtureCase: "list_dns_records", configKey: "zone_id", minimumRecords: 4},
		{family: "zone_ruleset", fixtureCase: "list_zone_rulesets", detailCase: "get_zone_ruleset", configKey: "zone_id", minimumRecords: 8},
		{family: "load_balancer", fixtureCase: "list_load_balancers", configKey: "zone_id", minimumRecords: 2},
		{family: "load_balancer_pool", fixtureCase: "list_load_balancer_pools", configKey: "account_id", minimumRecords: 2},
		{family: "access_application", fixtureCase: "list_access_applications", configKey: "account_id", minimumRecords: 1},
		{family: "access_group", fixtureCase: "list_access_groups", configKey: "account_id", minimumRecords: 1},
		{family: "zone_access_group", fixtureCase: "list_zone_access_groups", configKey: "zone_id", minimumRecords: 1},
		{family: "gateway_rule", fixtureCase: "list_gateway_rules", configKey: "account_id", minimumRecords: 2},
	}

	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := capturedCloudflareBundle(t, test.family, test.fixtureCase)
			requestPath := capturedCloudflareRequestPath(t, bundle)
			details := map[string]sourcefixture.Bundle{}
			if test.detailCase != "" {
				detail := capturedCloudflareBundle(t, test.family, test.detailCase)
				details[capturedCloudflareRequestPath(t, detail)] = detail
			}
			server := capturedCloudflareServer(t, requestPath, bundle, details)
			defer server.Close()

			source := capturedCloudflareSource(t)
			config := map[string]string{}
			if test.configKey != "" {
				config[test.configKey] = capturedCloudflarePathSegment(t, requestPath, 3)
			}
			cfg := capturedCloudflareConfig(server.URL, test.family, config)
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) < test.minimumRecords {
				t.Fatalf("Read() events = %d, want at least %d", len(pull.Events), test.minimumRecords)
			}
			for _, event := range pull.Events {
				if event.Kind != "cloudflare."+test.family {
					t.Fatalf("event kind = %q, want cloudflare.%s", event.Kind, test.family)
				}
				if strings.TrimSpace(event.Attributes["resource_id"]) == "" {
					t.Fatalf("resource_id is empty for event %q", event.Id)
				}
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(urns) != len(pull.Events) {
				t.Fatalf("Discover() URNs = %d, want %d read records", len(urns), len(pull.Events))
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, test.captureTime); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, updateCapturedCloudflareFixtures()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSourceReplaysCapturedCloudflareMemberPagination(t *testing.T) {
	pages := map[string]sourcefixture.Bundle{
		"":  capturedCloudflareBundle(t, "member", "list_members"),
		"2": capturedCloudflareBundle(t, "member", "list_members_page_2"),
		"3": capturedCloudflareBundle(t, "member", "list_members_page_3"),
	}
	requestPath := capturedCloudflareRequestPath(t, pages[""])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer replay-token" {
			t.Fatalf("Authorization = %q, want replay token", got)
		}
		if r.Method != http.MethodGet || r.URL.EscapedPath() != requestPath {
			t.Fatalf("unexpected Cloudflare replay request %s %s", r.Method, r.URL.RequestURI())
		}
		page := strings.TrimSpace(r.URL.Query().Get("page"))
		bundle, ok := pages[page]
		if !ok {
			t.Fatalf("request page = %q, want first, second, or third captured page", page)
		}
		writeCapturedCloudflareResponse(w, bundle)
	}))
	defer server.Close()

	source := capturedCloudflareSource(t)
	cfg := capturedCloudflareConfig(server.URL, "member", map[string]string{
		"account_id": capturedCloudflarePathSegment(t, requestPath, 3),
		"per_page":   "15",
	})
	var (
		cursor *cerebrov1.SourceCursor
		count  int
	)
	for page := 1; page <= 3; page++ {
		pull, err := source.Read(context.Background(), cfg, cursor)
		if err != nil {
			t.Fatalf("Read(page %d) error = %v", page, err)
		}
		if len(pull.Events) != 1 {
			t.Fatalf("Read(page %d) events = %d, want 1 captured record", page, len(pull.Events))
		}
		count += len(pull.Events)
		if page < 3 {
			want := string(rune('1' + page))
			if pull.NextCursor.GetOpaque() != want {
				t.Fatalf("Read(page %d) cursor = %q, want %q", page, pull.NextCursor.GetOpaque(), want)
			}
		} else if pull.NextCursor != nil {
			t.Fatalf("Read(page 3) cursor = %#v, want terminal page", pull.NextCursor)
		}
		cursor = pull.NextCursor
	}
	if count != 3 {
		t.Fatalf("pagination records = %d, want 3 captured pages", count)
	}
}

func capturedCloudflareBundle(t *testing.T, family, fixtureCase string) sourcefixture.Bundle {
	t.Helper()
	bundle, err := sourcefixture.FindBundle("../..", sourceID, family, fixtureCase)
	if err != nil {
		t.Fatalf("FindBundle(%s/%s) error = %v", family, fixtureCase, err)
	}
	return bundle
}

func capturedCloudflareRequestPath(t *testing.T, bundle sourcefixture.Bundle) string {
	t.Helper()
	parsed, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatalf("parse captured request URL: %v", err)
	}
	return parsed.EscapedPath()
}

func capturedCloudflarePathSegment(t *testing.T, requestPath string, index int) string {
	t.Helper()
	segments := strings.Split(strings.Trim(requestPath, "/"), "/")
	if index < 0 || index >= len(segments) {
		t.Fatalf("request path %q has no segment %d", requestPath, index)
	}
	return segments[index]
}

func capturedCloudflareSource(t *testing.T) *Source {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	return source
}

func capturedCloudflareConfig(baseURL, family string, extra map[string]string) sourcecdk.Config {
	values := map[string]string{
		"base_url":  baseURL + "/client/v4",
		"family":    family,
		"tenant_id": "tenant",
		"token":     "replay-token",
	}
	for key, value := range extra {
		values[key] = value
	}
	return sourcecdk.NewConfig(values)
}

func capturedCloudflareServer(t *testing.T, requestPath string, bundle sourcefixture.Bundle, details map[string]sourcefixture.Bundle) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer replay-token" {
			t.Fatalf("Authorization = %q, want replay token", got)
		}
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected Cloudflare replay request %s %s", r.Method, r.URL.RequestURI())
		}
		if r.URL.EscapedPath() == requestPath {
			writeCapturedCloudflareResponse(w, bundle)
			return
		}
		if detail, ok := details[r.URL.EscapedPath()]; ok {
			writeCapturedCloudflareResponse(w, detail)
			return
		}
		if strings.HasPrefix(r.URL.EscapedPath(), strings.TrimSuffix(requestPath, "/")+"/") {
			http.NotFound(w, r)
			return
		}
		t.Fatalf("unexpected Cloudflare replay request %s %s", r.Method, r.URL.RequestURI())
	}))
}

func writeCapturedCloudflareResponse(w http.ResponseWriter, bundle sourcefixture.Bundle) {
	w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
	for key, value := range bundle.Manifest.Response.Headers {
		w.Header().Set(key, value)
	}
	w.WriteHeader(bundle.Manifest.Response.Status)
	_, _ = w.Write(bundle.Payload)
}

func updateCapturedCloudflareFixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}
