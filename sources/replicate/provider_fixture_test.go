package replicate

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

func TestSourceReplaysCapturedReplicateFamilies(t *testing.T) {
	tests := []struct {
		family         string
		fixtureCase    string
		minimumRecords int
	}{
		{family: familyModels, fixtureCase: "list_models", minimumRecords: 25},
		{family: familyCollections, fixtureCase: "list_collections", minimumRecords: 19},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := capturedReplicateBundle(t, test.family, test.fixtureCase)
			server := capturedReplicateServer(t, bundle)
			defer server.Close()
			source, err := New()
			if err != nil {
				t.Fatal(err)
			}
			source.allowLoopbackForTest()
			cfg := sourcecdk.NewConfig(map[string]string{"base_url": server.URL, "family": test.family, "tenant_id": "tenant", "token": "replay-token"})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) < test.minimumRecords {
				t.Fatalf("Read() events = %d, want at least %d", len(pull.Events), test.minimumRecords)
			}
			for _, event := range pull.Events {
				if event.Kind != "replicate."+test.family || strings.TrimSpace(event.Attributes["resource_id"]) == "" {
					t.Fatalf("captured event = %#v", event)
				}
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(urns) != len(pull.Events) {
				t.Fatalf("Discover() URNs = %d, want %d", len(urns), len(pull.Events))
			}
			for index, event := range pull.Events {
				if event.Attributes["resource_urn"] != urns[index].String() {
					t.Fatalf("%s resource_urn = %q, discover URN = %q", test.family, event.Attributes["resource_urn"], urns[index].String())
				}
				if test.family == familyModels && (event.Attributes["owner"] == "" || !strings.Contains(event.Attributes["resource_id"], "/")) {
					t.Fatalf("model identity = %#v, want owner/name", event.Attributes)
				}
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, true); err != nil {
				t.Fatal(err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, updateCapturedReplicateFixtures()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func capturedReplicateBundle(t *testing.T, family, fixtureCase string) sourcefixture.Bundle {
	t.Helper()
	bundle, err := sourcefixture.FindBundle("../..", sourceID, family, fixtureCase)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func capturedReplicateServer(t *testing.T, bundle sourcefixture.Bundle) *httptest.Server {
	t.Helper()
	captured, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer replay-token" || r.Method != http.MethodGet || r.URL.EscapedPath() != captured.EscapedPath() {
			t.Fatalf("unexpected Replicate replay request %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		w.WriteHeader(bundle.Manifest.Response.Status)
		_, _ = w.Write(bundle.Payload)
	}))
}

func updateCapturedReplicateFixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}
