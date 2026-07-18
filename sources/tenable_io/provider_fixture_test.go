package tenable_io

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

func TestSourceReplaysCapturedTenableFamilies(t *testing.T) {
	tests := []struct {
		family           string
		fixtureCase      string
		wantEvents       int
		useCaptureTime   bool
		wantResourceType string
	}{
		{family: familyAssets, fixtureCase: "list_assets", wantEvents: 13, wantResourceType: "asset"},
		{family: familyVulnerabilities, fixtureCase: "list_workbench_vulnerabilities", wantEvents: 2, useCaptureTime: true, wantResourceType: "vulnerability"},
	}

	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := capturedTenableBundle(t, test.family, test.fixtureCase)
			requestPath := capturedTenableRequestPath(t, bundle)
			server := capturedTenableServer(t, requestPath, bundle)
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			cfg := sourcecdk.NewConfig(map[string]string{
				"api_token": "accessKey=example;secretKey=example",
				"base_url":  server.URL,
				"family":    test.family,
				"tenant_id": "tenant",
			})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != test.wantEvents {
				t.Fatalf("Read() events = %d, want %d", len(pull.Events), test.wantEvents)
			}
			if pull.NextCursor != nil {
				t.Fatalf("Read() next cursor = %#v, want nil", pull.NextCursor)
			}
			for _, event := range pull.Events {
				if event.Kind != "tenable_io."+test.family {
					t.Fatalf("event kind = %q, want tenable_io.%s", event.Kind, test.family)
				}
				if got := event.Attributes["resource_type"]; got != test.wantResourceType {
					t.Fatalf("resource_type = %q, want %q", got, test.wantResourceType)
				}
			}
			if test.family == familyVulnerabilities {
				if got := pull.Events[0].Attributes["finding_id"]; strings.TrimSpace(got) == "" {
					t.Fatal("finding_id is empty")
				}
				if got := pull.Events[0].Attributes["status"]; got != "New" {
					t.Fatalf("status = %q, want New", got)
				}
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, test.useCaptureTime); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, updateCapturedTenableFixtures()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func capturedTenableBundle(t *testing.T, family, fixtureCase string) sourcefixture.Bundle {
	t.Helper()
	bundle, err := sourcefixture.FindBundle("../..", sourceID, family, fixtureCase)
	if err != nil {
		t.Fatalf("FindBundle(%s/%s) error = %v", family, fixtureCase, err)
	}
	return bundle
}

func capturedTenableRequestPath(t *testing.T, bundle sourcefixture.Bundle) string {
	t.Helper()
	parsed, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatalf("parse captured request URL: %v", err)
	}
	return parsed.EscapedPath()
}

func capturedTenableServer(t *testing.T, requestPath string, bundle sourcefixture.Bundle) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-ApiKeys"); got != "accessKey=example;secretKey=example" {
			t.Fatalf("X-ApiKeys = %q, want replay credential", got)
		}
		if r.Method != http.MethodGet || r.URL.EscapedPath() != requestPath {
			t.Fatalf("unexpected Tenable replay request %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		w.WriteHeader(bundle.Manifest.Response.Status)
		_, _ = w.Write(bundle.Payload)
	}))
}

func updateCapturedTenableFixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}
