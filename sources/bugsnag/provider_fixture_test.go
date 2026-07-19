package bugsnag

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

func TestSourceReplaysCapturedBugsnagFamilies(t *testing.T) {
	tests := []struct {
		family      string
		fixtureCase string
		config      map[string]string
		wantEvents  int
		wantAttr    string
	}{
		{family: familyProjects, fixtureCase: "organization_projects", config: map[string]string{"organization_id": "example-organization"}, wantEvents: 30, wantAttr: "resource_name"},
		{family: familyErrors, fixtureCase: "project_errors", config: map[string]string{"project_id": "example-project"}, wantEvents: 1, wantAttr: "severity"},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle, err := sourcefixture.FindBundle("../..", sourceID, test.family, test.fixtureCase)
			if err != nil {
				t.Fatal(err)
			}
			captured, err := url.Parse(bundle.Manifest.Request.URL)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Token replay-token" || r.Header.Get("X-Version") != "2" || r.Header.Get("X-Bugsnag-Api") != "true" || r.Method != http.MethodGet || r.URL.EscapedPath() != captured.EscapedPath() {
					t.Fatalf("unexpected Bugsnag replay request %s %s", r.Method, r.URL.RequestURI())
				}
				w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
				w.WriteHeader(bundle.Manifest.Response.Status)
				_, _ = w.Write(bundle.Payload)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatal(err)
			}
			source.allowLoopbackForTest()
			values := map[string]string{"api_token": "replay-token", "base_url": server.URL, "family": test.family, "tenant_id": "tenant"}
			for key, value := range test.config {
				values[key] = value
			}
			cfg := sourcecdk.NewConfig(values)
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != test.wantEvents {
				t.Fatalf("Read() events = %d, want %d", len(pull.Events), test.wantEvents)
			}
			for _, event := range pull.Events {
				if event.Kind != "bugsnag."+test.family || strings.TrimSpace(event.Attributes[test.wantAttr]) == "" {
					t.Fatalf("captured event = %#v", event)
				}
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			for index, event := range pull.Events {
				resourceURN := event.Attributes["resource_urn"]
				if test.family == familyProjects && (index >= len(urns) || resourceURN != urns[index].String()) {
					t.Fatalf("project resource_urn = %q, discover URN = %#v", resourceURN, urns)
				}
				if test.family == familyErrors && !strings.HasPrefix(resourceURN, "urn:cerebro:tenant:bugsnag_projects:") {
					t.Fatalf("error resource_urn = %q, want affected project URN", resourceURN)
				}
				if test.family == familyErrors && (event.Attributes["resource_type"] != "bugsnag_project" || event.Attributes["resource_name"] != event.Attributes["resource_id"]) {
					t.Fatalf("error affected resource = %#v, want Bugsnag project", event.Attributes)
				}
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
				t.Fatal(err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
