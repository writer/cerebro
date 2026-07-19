package gitguardian_secrets

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

func TestSourceReplaysCapturedGitGuardianSecretsFamilies(t *testing.T) {
	tests := []struct {
		family         string
		fixtureCase    string
		useCaptureTime bool
	}{
		{family: familySources, fixtureCase: "list_sources", useCaptureTime: true},
		{family: familyAuditEvents, fixtureCase: "list_audit_logs"},
	}

	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle, err := sourcefixture.FindBundle("../..", sourceID, test.family, test.fixtureCase)
			if err != nil {
				t.Fatalf("FindBundle() error = %v", err)
			}
			parsed, err := url.Parse(bundle.Manifest.Request.URL)
			if err != nil {
				t.Fatalf("parse captured request URL: %v", err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Token replay-token" {
					t.Fatalf("Authorization = %q, want replay token", got)
				}
				if r.Method != http.MethodGet || r.URL.EscapedPath() != parsed.EscapedPath() || r.URL.Query().Get("per_page") != "5" {
					t.Fatalf("unexpected GitGuardian Secrets replay request %s %s", r.Method, r.URL.RequestURI())
				}
				w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
				for key, value := range bundle.Manifest.Response.Headers {
					w.Header().Set(key, value)
				}
				w.WriteHeader(bundle.Manifest.Response.Status)
				_, _ = w.Write(bundle.Payload)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			cfg := sourcecdk.NewConfig(map[string]string{
				"api_token": "replay-token",
				"base_url":  server.URL,
				"family":    test.family,
				"per_page":  "5",
				"tenant_id": "tenant",
			})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 5 {
				t.Fatalf("Read() events = %d, want 5", len(pull.Events))
			}
			if pull.NextCursor == nil || strings.TrimSpace(pull.NextCursor.Opaque) == "" {
				t.Fatalf("Read() next cursor = %#v, want Link cursor", pull.NextCursor)
			}
			for _, event := range pull.Events {
				if event.Kind != "gitguardian_secrets."+test.family {
					t.Fatalf("event kind = %q, want gitguardian_secrets.%s", event.Kind, test.family)
				}
			}
			if test.family == familySources {
				if strings.TrimSpace(pull.Events[0].Attributes["resource_id"]) == "" || strings.TrimSpace(pull.Events[0].Attributes["resource_type"]) == "" {
					t.Fatalf("source attributes = %#v, want resource identity and type", pull.Events[0].Attributes)
				}
			} else if strings.TrimSpace(pull.Events[0].Attributes["actor_id"]) == "" || strings.TrimSpace(pull.Events[0].Attributes["event_type"]) == "" {
				t.Fatalf("audit attributes = %#v, want actor and event type", pull.Events[0].Attributes)
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, test.useCaptureTime); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			update := strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, update); err != nil {
				t.Fatal(err)
			}
		})
	}
}
