package zendesk

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

func TestSourceReplaysCapturedZendeskFamilies(t *testing.T) {
	tests := []struct {
		family      string
		fixtureCase string
	}{
		{family: familyUsers, fixtureCase: "list_users"},
		{family: familyTickets, fixtureCase: "list_tickets"},
		{family: familyAuditEvents, fixtureCase: "list_ticket_audits"},
	}

	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := capturedZendeskBundle(t, test.family, test.fixtureCase)
			requestPath := capturedZendeskRequestPath(t, bundle)
			server := capturedZendeskServer(t, requestPath, bundle)
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			cfg := sourcecdk.NewConfig(map[string]string{
				"base_url":  server.URL + "/api",
				"family":    test.family,
				"page_size": "1",
				"subdomain": "replay",
				"tenant_id": "tenant",
				"token":     "replay-token",
			})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 || pull.Events[0].Kind != "zendesk."+test.family {
				t.Fatalf("Read() events = %#v, want one zendesk.%s", pull.Events, test.family)
			}
			if pull.NextCursor == nil || strings.TrimSpace(pull.NextCursor.Opaque) == "" {
				t.Fatalf("Read() next cursor = %#v, want Zendesk after_cursor", pull.NextCursor)
			}
			if test.family == familyAuditEvents {
				if got := pull.Events[0].Attributes["event_type"]; got != "ticket_audit" {
					t.Fatalf("event_type = %q, want ticket_audit", got)
				}
				if strings.TrimSpace(pull.Events[0].Attributes["actor_id"]) == "" {
					t.Fatal("actor_id is empty")
				}
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, updateCapturedZendeskFixtures()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func capturedZendeskBundle(t *testing.T, family, fixtureCase string) sourcefixture.Bundle {
	t.Helper()
	bundle, err := sourcefixture.FindBundle("../..", sourceID, family, fixtureCase)
	if err != nil {
		t.Fatalf("FindBundle(%s/%s) error = %v", family, fixtureCase, err)
	}
	return bundle
}

func capturedZendeskRequestPath(t *testing.T, bundle sourcefixture.Bundle) string {
	t.Helper()
	parsed, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatalf("parse captured request URL: %v", err)
	}
	return parsed.EscapedPath()
}

func capturedZendeskServer(t *testing.T, requestPath string, bundle sourcefixture.Bundle) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Basic replay-token" {
			t.Fatalf("Authorization = %q, want replay token", got)
		}
		if r.Method != http.MethodGet || r.URL.EscapedPath() != requestPath {
			t.Fatalf("unexpected Zendesk replay request %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		w.WriteHeader(bundle.Manifest.Response.Status)
		_, _ = w.Write(bundle.Payload)
	}))
}

func updateCapturedZendeskFixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}
