package fastly

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceReplaysCapturedFastlyFamilies(t *testing.T) {
	tests := []struct {
		family         string
		fixtureCase    string
		minimumRecords int
		config         func(*testing.T, string) map[string]string
	}{
		{family: familyServices, fixtureCase: "list_services_page_1", minimumRecords: 100},
		{
			family: familyAclEntries, fixtureCase: "list_acl_entries", minimumRecords: 1,
			config: func(t *testing.T, requestPath string) map[string]string {
				return map[string]string{
					"service_id": capturedFastlyPathSegment(t, requestPath, 1),
					"acl_id":     capturedFastlyPathSegment(t, requestPath, 3),
				}
			},
		},
		{family: familyAuditEvents, fixtureCase: "list_audit_events", minimumRecords: 1},
	}

	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := capturedFastlyBundle(t, test.family, test.fixtureCase)
			requestURL := capturedFastlyRequestURL(t, bundle)
			server := capturedFastlyServer(t, map[string]sourcefixture.Bundle{"": bundle})
			defer server.Close()

			extra := map[string]string{}
			if test.config != nil {
				extra = test.config(t, requestURL.EscapedPath())
			}
			extra["per_page"] = requestURL.Query().Get(capturedFastlyPageSizeParam(test.family))
			source := capturedFastlySource(t)
			cfg := capturedFastlyConfig(server.URL, test.family, extra)
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) < test.minimumRecords {
				t.Fatalf("Read() events = %d, want at least %d", len(pull.Events), test.minimumRecords)
			}
			for _, event := range pull.Events {
				if event.Kind != "fastly."+test.family {
					t.Fatalf("event kind = %q, want fastly.%s", event.Kind, test.family)
				}
				if strings.TrimSpace(event.Attributes["resource_id"]) == "" {
					t.Fatalf("resource_id is empty for event %q", event.Id)
				}
			}
			if test.family == familyAuditEvents {
				if strings.TrimSpace(pull.Events[0].Attributes["actor_id"]) == "" || strings.TrimSpace(pull.Events[0].Attributes["event_type"]) == "" {
					t.Fatalf("audit attributes = %#v, want actor and event type", pull.Events[0].Attributes)
				}
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(urns) != len(pull.Events) {
				t.Fatalf("Discover() URNs = %d, want %d read records", len(urns), len(pull.Events))
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, updateCapturedFastlyFixtures()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSourceReplaysCapturedFastlyServicePagination(t *testing.T) {
	pages := map[string]sourcefixture.Bundle{
		"1": capturedFastlyBundle(t, familyServices, "list_services_page_1"),
		"2": capturedFastlyBundle(t, familyServices, "list_services_page_2"),
		"3": capturedFastlyBundle(t, familyServices, "list_services_page_3"),
	}
	server := capturedFastlyServer(t, pages)
	defer server.Close()

	source := capturedFastlySource(t)
	cfg := capturedFastlyConfig(server.URL, familyServices, map[string]string{"per_page": "100"})
	var (
		cursor *cerebrov1.SourceCursor
		count  int
		ids    = map[string]struct{}{}
	)
	for page, wantRecords := range []int{100, 100, 58} {
		pull, err := source.Read(context.Background(), cfg, cursor)
		if err != nil {
			t.Fatalf("Read(page %d) error = %v", page+1, err)
		}
		if len(pull.Events) != wantRecords {
			t.Fatalf("Read(page %d) events = %d, want %d", page+1, len(pull.Events), wantRecords)
		}
		for _, event := range pull.Events {
			ids[event.Attributes["resource_id"]] = struct{}{}
		}
		count += len(pull.Events)
		if page < 2 {
			want := string(rune('2' + page))
			if pull.NextCursor.GetOpaque() != want {
				t.Fatalf("Read(page %d) cursor = %q, want %q", page+1, pull.NextCursor.GetOpaque(), want)
			}
		} else if pull.NextCursor != nil {
			t.Fatalf("Read(page 3) cursor = %#v, want terminal page", pull.NextCursor)
		}
		cursor = pull.NextCursor
	}
	// The captured third page contains two representations of the same service
	// ID, so preserve the provider response instead of manufacturing uniqueness.
	if count != 258 || len(ids) != 257 {
		t.Fatalf("pagination records = %d with %d unique IDs, want 258 records and 257 provider IDs", count, len(ids))
	}
}

func capturedFastlyBundle(t *testing.T, family, fixtureCase string) sourcefixture.Bundle {
	t.Helper()
	bundle, err := sourcefixture.FindBundle("../..", sourceID, family, fixtureCase)
	if err != nil {
		t.Fatalf("FindBundle(%s/%s) error = %v", family, fixtureCase, err)
	}
	return bundle
}

func capturedFastlyRequestURL(t *testing.T, bundle sourcefixture.Bundle) *url.URL {
	t.Helper()
	parsed, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatalf("parse captured request URL: %v", err)
	}
	return parsed
}

func capturedFastlyPathSegment(t *testing.T, requestPath string, index int) string {
	t.Helper()
	segments := strings.Split(strings.Trim(requestPath, "/"), "/")
	if index < 0 || index >= len(segments) {
		t.Fatalf("request path %q has no segment %d", requestPath, index)
	}
	return segments[index]
}

func capturedFastlyPageSizeParam(family string) string {
	if family == familyAuditEvents {
		return "page[size]"
	}
	return "per_page"
}

func capturedFastlySource(t *testing.T) *Source {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	return source
}

func capturedFastlyConfig(baseURL, family string, extra map[string]string) sourcecdk.Config {
	values := map[string]string{
		"base_url":  baseURL,
		"family":    family,
		"tenant_id": "tenant",
		"token":     "replay-token",
	}
	for key, value := range extra {
		if strings.TrimSpace(value) != "" {
			values[key] = value
		}
	}
	return sourcecdk.NewConfig(values)
}

func capturedFastlyServer(t *testing.T, pages map[string]sourcefixture.Bundle) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Fastly-Key"); got != "replay-token" {
			t.Fatalf("Fastly-Key = %q, want replay token", got)
		}
		page := strings.TrimSpace(r.URL.Query().Get("page"))
		if page == "" {
			page = strings.TrimSpace(r.URL.Query().Get("page[number]"))
		}
		bundle, ok := pages[page]
		if !ok {
			bundle, ok = pages[""]
		}
		if !ok {
			t.Fatalf("request page = %q, want a captured Fastly page", page)
		}
		captured := capturedFastlyRequestURL(t, bundle)
		if r.Method != http.MethodGet || r.URL.EscapedPath() != captured.EscapedPath() || !reflect.DeepEqual(r.URL.Query(), captured.Query()) {
			t.Fatalf("unexpected Fastly replay request %s %s; want %s", r.Method, r.URL.RequestURI(), captured.RequestURI())
		}
		writeCapturedFastlyResponse(w, bundle)
	}))
}

func writeCapturedFastlyResponse(w http.ResponseWriter, bundle sourcefixture.Bundle) {
	w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
	for key, value := range bundle.Manifest.Response.Headers {
		w.Header().Set(key, value)
	}
	w.WriteHeader(bundle.Manifest.Response.Status)
	_, _ = w.Write(bundle.Payload)
}

func updateCapturedFastlyFixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}
