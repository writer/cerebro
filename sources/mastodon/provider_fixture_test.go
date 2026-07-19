package mastodon

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

func TestSourceReplaysCapturedMastodonFamilies(t *testing.T) {
	tests := []struct {
		family      string
		fixtureCase string
		wantRecords int
		assert      func(*testing.T, map[string]string)
	}{
		{
			family:      familyAccount,
			fixtureCase: "list_accounts",
			wantRecords: 1,
			assert: func(t *testing.T, attributes map[string]string) {
				if attributes["user_id"] != "116387030920493064" || attributes["login"] != "admin" {
					t.Fatalf("account attributes = %#v, want captured account identity", attributes)
				}
			},
		},
		{
			family:      familyActivity,
			fixtureCase: "instance_activity",
			wantRecords: 12,
			assert: func(t *testing.T, attributes map[string]string) {
				if attributes["source_event_id"] != "1775949325" || attributes["statuses"] != "96" || attributes["event_type"] != "instance_activity" {
					t.Fatalf("activity attributes = %#v, want captured weekly aggregate", attributes)
				}
			},
		},
		{
			family:      familyVerifyCredential,
			fixtureCase: "verify_credentials",
			wantRecords: 1,
			assert: func(t *testing.T, attributes map[string]string) {
				if attributes["user_id"] != "116387031229467654" || attributes["login"] != "mastodonpy_test" {
					t.Fatalf("verified account attributes = %#v, want captured account identity", attributes)
				}
			},
		},
		{
			family:      familyNotification,
			fixtureCase: "notifications",
			wantRecords: 1,
			assert: func(t *testing.T, attributes map[string]string) {
				if attributes["alert_id"] != "24" || attributes["alert_type"] != "mention" || attributes["resource_id"] != "116388617698080047" {
					t.Fatalf("notification attributes = %#v, want captured mention", attributes)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := capturedMastodonBundle(t, test.family, test.fixtureCase)
			server := capturedMastodonServer(t, bundle)
			defer server.Close()

			source := capturedMastodonSource(t)
			cfg := capturedMastodonConfig(server.URL, test.family)
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != test.wantRecords {
				t.Fatalf("Read() events = %d, want %d", len(pull.Events), test.wantRecords)
			}
			seenSourceIDs := make(map[string]struct{}, len(pull.Events))
			for _, event := range pull.Events {
				if event.Kind != "mastodon."+test.family {
					t.Fatalf("event kind = %q, want mastodon.%s", event.Kind, test.family)
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
			if test.family == familyNotification {
				if pull.NextCursor == nil || pull.NextCursor.Opaque != "24" {
					t.Fatalf("notification next cursor = %#v, want max_id 24", pull.NextCursor)
				}
			}

			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(urns) != len(pull.Events) {
				t.Fatalf("Discover() URNs = %d, want %d", len(urns), len(pull.Events))
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, updateCapturedMastodonFixtures()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func capturedMastodonBundle(t *testing.T, family, fixtureCase string) sourcefixture.Bundle {
	t.Helper()
	bundle, err := sourcefixture.FindBundle("../..", sourceID, family, fixtureCase)
	if err != nil {
		t.Fatalf("FindBundle(%s/%s) error = %v", family, fixtureCase, err)
	}
	return bundle
}

func capturedMastodonSource(t *testing.T) *Source {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	return source
}

func capturedMastodonConfig(baseURL, family string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"base_url":  baseURL,
		"family":    family,
		"id":        "3",
		"tenant_id": "tenant",
		"token":     "replay-token",
	})
}

func capturedMastodonServer(t *testing.T, bundle sourcefixture.Bundle) *httptest.Server {
	t.Helper()
	captured := capturedMastodonRequestURL(t, bundle)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer replay-token" {
			t.Fatalf("Authorization = %q, want replay token", got)
		}
		if r.Method != http.MethodGet || r.URL.EscapedPath() != captured.EscapedPath() {
			t.Fatalf("unexpected Mastodon replay request %s %s; want GET %s", r.Method, r.URL.RequestURI(), captured.EscapedPath())
		}
		for key := range r.URL.Query() {
			if key != "limit" {
				t.Fatalf("unexpected Mastodon replay query %q in %s", key, r.URL.RawQuery)
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

func capturedMastodonRequestURL(t *testing.T, bundle sourcefixture.Bundle) *url.URL {
	t.Helper()
	parsed, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatalf("parse captured request URL: %v", err)
	}
	return parsed
}

func updateCapturedMastodonFixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}
