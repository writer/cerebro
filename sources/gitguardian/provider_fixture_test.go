package gitguardian

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

func TestSourceReplaysCapturedGitGuardianFamilies(t *testing.T) {
	tests := []struct {
		family      string
		fixtureCase string
	}{
		{family: familyIncidents, fixtureCase: "list_incidents"},
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
					t.Fatalf("unexpected GitGuardian replay request %s %s", r.Method, r.URL.RequestURI())
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
				if event.Kind != "gitguardian."+test.family {
					t.Fatalf("event kind = %q, want gitguardian.%s", event.Kind, test.family)
				}
			}
			if test.family == familyIncidents {
				if strings.TrimSpace(pull.Events[0].Attributes["finding_id"]) == "" || strings.TrimSpace(pull.Events[0].Attributes["severity"]) == "" {
					t.Fatalf("incident attributes = %#v, want finding identity and severity", pull.Events[0].Attributes)
				}
			} else if strings.TrimSpace(pull.Events[0].Attributes["actor_id"]) == "" || strings.TrimSpace(pull.Events[0].Attributes["event_type"]) == "" {
				t.Fatalf("audit attributes = %#v, want actor and event type", pull.Events[0].Attributes)
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			update := strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, update); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSourceReplaysCapturedGitGuardianMembers(t *testing.T) {
	bundle, err := sourcefixture.FindBundle("../..", sourceID, familyMembers, "list_members")
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
		if r.Method != http.MethodGet || r.URL.EscapedPath() != parsed.EscapedPath() {
			t.Fatalf("unexpected GitGuardian replay request %s %s", r.Method, r.URL.RequestURI())
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
		"family":    familyMembers,
		"tenant_id": "tenant",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("Read() events = %d, want 2", len(pull.Events))
	}
	if pull.NextCursor != nil {
		t.Fatalf("Read() next cursor = %#v, want nil", pull.NextCursor)
	}
	for _, event := range pull.Events {
		if event.Kind != "gitguardian.members" {
			t.Fatalf("event kind = %q, want gitguardian.members", event.Kind)
		}
		if strings.TrimSpace(event.Attributes["user_id"]) == "" {
			t.Fatal("user_id is empty")
		}
		if !strings.HasSuffix(event.Attributes["primary_email"], "@example.test") {
			t.Fatalf("primary_email = %q, want sanitized example address", event.Attributes["primary_email"])
		}
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
		t.Fatalf("StabilizeEvents() error = %v", err)
	}
	update := strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", familyMembers, pull.Events, urns, update); err != nil {
		t.Fatal(err)
	}
}
