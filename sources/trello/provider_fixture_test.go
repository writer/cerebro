package trello

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

func TestSourceReplaysCapturedTrelloFamilies(t *testing.T) {
	tests := []struct {
		family      string
		fixtureCase string
		minimum     int
		config      map[string]string
		captureTime bool
	}{
		{family: familyUsers, fixtureCase: "authenticated_member", minimum: 1, captureTime: true},
		{family: familyGroups, fixtureCase: "member_organizations", minimum: 1, captureTime: true},
		{family: familyWorkspaces, fixtureCase: "member_boards", minimum: 10},
		{family: familyDocuments, fixtureCase: "board_cards", minimum: 4, config: map[string]string{"board_id": "example-board"}},
		{family: familyAuditEvents, fixtureCase: "member_actions", minimum: 50, config: map[string]string{"member_id": "example-member"}},
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
				if r.Method != http.MethodGet || r.URL.EscapedPath() != captured.EscapedPath() || r.URL.Query().Get("key") != "replay-key" || r.URL.Query().Get("token") != "replay-token" {
					t.Fatalf("unexpected Trello replay request %s %s", r.Method, r.URL.RequestURI())
				}
				for key, values := range captured.Query() {
					if len(values) != 0 && r.URL.Query().Get(key) != values[0] {
						t.Fatalf("Trello replay query %s = %q, want %q", key, r.URL.Query().Get(key), values[0])
					}
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
			values := map[string]string{"api_key": "replay-key", "base_url": server.URL, "family": test.family, "tenant_id": "tenant", "token": "replay-token"}
			for key, value := range test.config {
				values[key] = value
			}
			cfg := sourcecdk.NewConfig(values)
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) < test.minimum {
				t.Fatalf("Read() events = %d, want at least %d", len(pull.Events), test.minimum)
			}
			for _, event := range pull.Events {
				if event.Kind != "trello."+test.family || strings.TrimSpace(event.Id) == "" {
					t.Fatalf("captured event = %#v", event)
				}
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if test.family == familyWorkspaces || test.family == familyDocuments {
				for index, event := range pull.Events {
					if index >= len(urns) || event.Attributes["resource_urn"] != urns[index].String() {
						t.Fatalf("%s resource_urn = %q, discover URN = %#v", test.family, event.Attributes["resource_urn"], urns)
					}
				}
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, test.captureTime); err != nil {
				t.Fatal(err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
