package twitter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceReplaysCapturedTwitterFamilies(t *testing.T) {
	tests := []struct {
		family      string
		fixtureCase string
		id          string
		wantRecords int
		wantCursor  string
		captureTime bool
		assert      func(*testing.T, map[string]string)
	}{
		{
			family:      familyListMembership,
			fixtureCase: "list_memberships",
			id:          "783214",
			wantRecords: 93,
			wantCursor:  "1731271766573010389",
			captureTime: true,
			assert: func(t *testing.T, attributes map[string]string) {
				if attributes["group_id"] != "70971664" || attributes["member_id"] != "783214" {
					t.Fatalf("list membership attributes = %#v, want captured list and configured user", attributes)
				}
			},
		},
		{
			family:      familyMember,
			fixtureCase: "list_members",
			id:          "84839422",
			wantRecords: 100,
			wantCursor:  "4611686018799963893",
			captureTime: true,
			assert: func(t *testing.T, attributes map[string]string) {
				if attributes["user_id"] != "1319036828964454402" || !strings.HasPrefix(attributes["login"], "example-") {
					t.Fatalf("member attributes = %#v, want captured sanitized user", attributes)
				}
			},
		},
		{
			family:      familyJob,
			fixtureCase: "compliance_jobs",
			id:          "unused",
			wantRecords: 1,
			assert: func(t *testing.T, attributes map[string]string) {
				if attributes["policy_id"] != "1522929458495242241" || attributes["policy_type"] != "tweets" || attributes["policy_status"] != "created" {
					t.Fatalf("compliance job attributes = %#v, want captured job", attributes)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := capturedTwitterBundle(t, test.family, test.fixtureCase)
			server := capturedTwitterServer(t, bundle)
			defer server.Close()

			source := capturedTwitterSource(t)
			cfg := capturedTwitterConfig(server.URL, test.family, test.id)
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != test.wantRecords {
				t.Fatalf("Read() events = %d, want %d", len(pull.Events), test.wantRecords)
			}
			seenSourceIDs := make(map[string]struct{}, len(pull.Events))
			for _, event := range pull.Events {
				if event.Kind != "twitter."+test.family {
					t.Fatalf("event kind = %q, want twitter.%s", event.Kind, test.family)
				}
				if event.Attributes["tenant_id"] != "tenant" {
					t.Fatalf("tenant_id = %q, want tenant", event.Attributes["tenant_id"])
				}
				sourceEventID := strings.TrimSpace(event.Attributes["source_event_id"])
				if sourceEventID == "" {
					t.Fatalf("source_event_id is empty: %#v", event.Attributes)
				}
				if _, exists := seenSourceIDs[sourceEventID]; exists {
					t.Fatalf("duplicate source_event_id %q", sourceEventID)
				}
				seenSourceIDs[sourceEventID] = struct{}{}
			}
			test.assert(t, pull.Events[0].Attributes)
			if test.wantCursor == "" {
				if pull.NextCursor != nil {
					t.Fatalf("next cursor = %#v, want nil", pull.NextCursor)
				}
			} else if pull.NextCursor == nil || pull.NextCursor.Opaque != test.wantCursor {
				t.Fatalf("next cursor = %#v, want %q", pull.NextCursor, test.wantCursor)
			}

			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(urns) != len(pull.Events) {
				t.Fatalf("Discover() URNs = %d, want %d", len(urns), len(pull.Events))
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, test.captureTime); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, updateCapturedTwitterFixtures()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func capturedTwitterBundle(t *testing.T, family, fixtureCase string) sourcefixture.Bundle {
	t.Helper()
	bundle, err := sourcefixture.FindBundle("../..", sourceID, family, fixtureCase)
	if err != nil {
		t.Fatalf("FindBundle(%s/%s) error = %v", family, fixtureCase, err)
	}
	return bundle
}

func capturedTwitterSource(t *testing.T) *Source {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	return source
}

func capturedTwitterConfig(baseURL, family, id string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"base_url":  baseURL,
		"family":    family,
		"id":        id,
		"tenant_id": "tenant",
		"token":     "replay-token",
	})
}

func capturedTwitterServer(t *testing.T, bundle sourcefixture.Bundle) *httptest.Server {
	t.Helper()
	captured := capturedTwitterRequestURL(t, bundle)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer replay-token" {
			t.Fatalf("Authorization = %q, want replay token", got)
		}
		if r.Method != http.MethodGet || r.URL.EscapedPath() != captured.EscapedPath() {
			t.Fatalf("unexpected Twitter replay request %s %s; want GET %s", r.Method, r.URL.RequestURI(), captured.EscapedPath())
		}
		for key, values := range captured.Query() {
			if got := r.URL.Query()[key]; strings.Join(got, "\x00") != strings.Join(values, "\x00") {
				t.Fatalf("query %q = %#v, want captured %#v", key, got, values)
			}
		}
		for key := range r.URL.Query() {
			if key != "max_results" && captured.Query().Get(key) == "" {
				t.Fatalf("unexpected Twitter replay query %q in %s", key, r.URL.RawQuery)
			}
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		for key, value := range bundle.Manifest.Response.Headers {
			w.Header().Set(key, value)
		}
		w.WriteHeader(bundle.Manifest.Response.Status)
		_, _ = w.Write(bundle.Payload)
	}))
}

func capturedTwitterRequestURL(t *testing.T, bundle sourcefixture.Bundle) *url.URL {
	t.Helper()
	parsed, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatalf("parse captured request URL: %v", err)
	}
	return parsed
}

func updateCapturedTwitterFixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}
