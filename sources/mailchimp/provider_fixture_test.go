package mailchimp

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

func TestSourceReplaysCapturedMailchimpFamilies(t *testing.T) {
	tests := []struct {
		family      string
		fixtureCase string
		listID      string
	}{
		{family: familyLists, fixtureCase: "list_lists"},
		{family: familyMembers, fixtureCase: "list_members", listID: "example-2e767a40"},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := capturedMailchimpBundle(t, test.family, test.fixtureCase)
			server := capturedMailchimpServer(t, bundle)
			defer server.Close()
			source, err := New()
			if err != nil {
				t.Fatal(err)
			}
			source.allowLoopbackForTest()
			cfg := sourcecdk.NewConfig(map[string]string{"api_key": "replay-token", "base_url": server.URL + "/3.0", "dc": "example", "family": test.family, "list_id": test.listID, "tenant_id": "tenant"})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) < 1 {
				t.Fatal("Read() returned no captured events")
			}
			for _, event := range pull.Events {
				if event.Kind != "mailchimp."+test.family || strings.TrimSpace(event.Id) == "" {
					t.Fatalf("captured event = %#v", event)
				}
			}
			if test.family == familyMembers && !strings.HasSuffix(pull.Events[0].Attributes["email"], "@example.test") {
				t.Fatalf("email = %q, want sanitized example address", pull.Events[0].Attributes["email"])
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, true); err != nil {
				t.Fatal(err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, updateCapturedMailchimpFixtures()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func capturedMailchimpBundle(t *testing.T, family, fixtureCase string) sourcefixture.Bundle {
	t.Helper()
	bundle, err := sourcefixture.FindBundle("../..", sourceID, family, fixtureCase)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func capturedMailchimpServer(t *testing.T, bundle sourcefixture.Bundle) *httptest.Server {
	t.Helper()
	captured, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic Y2VyZWJybzpyZXBsYXktdG9rZW4=" || r.Method != http.MethodGet || r.URL.EscapedPath() != captured.EscapedPath() {
			t.Fatalf("unexpected Mailchimp replay request %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		w.WriteHeader(bundle.Manifest.Response.Status)
		_, _ = w.Write(bundle.Payload)
	}))
}

func updateCapturedMailchimpFixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}
