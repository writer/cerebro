package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceReplaysCapturedPublicFamilies(t *testing.T) {
	tests := []struct {
		name           string
		family         string
		fixtureCase    string
		providerPath   string
		config         map[string]string
		useCaptureTime bool
		assertEvent    func(*testing.T, map[string]string)
	}{
		{
			name:         "repositories",
			family:       familyRepositories,
			fixtureCase:  "projects",
			providerPath: "/api/v4/projects",
			config:       map[string]string{"order_by": "id", "search": "gitlab", "simple": "true"},
			assertEvent: func(t *testing.T, attributes map[string]string) {
				if attributes["resource_id"] != "84581023" || attributes["resource_type"] != "repository" {
					t.Fatalf("repository attributes = %#v", attributes)
				}
			},
		},
		{
			name:           "users",
			family:         familyUsers,
			fixtureCase:    "users",
			providerPath:   "/api/v4/users",
			config:         map[string]string{"username": "gitlab-bot"},
			useCaptureTime: true,
			assertEvent: func(t *testing.T, attributes map[string]string) {
				if attributes["user_id"] != "1786152" || attributes["login"] != "gitlab-bot" {
					t.Fatalf("user attributes = %#v", attributes)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle, err := sourcefixture.FindBundle("../..", sourceID, test.family, test.fixtureCase)
			if err != nil {
				t.Fatalf("FindBundle() error = %v", err)
			}
			if !strings.Contains(bundle.Manifest.Request.URL, test.providerPath) {
				t.Fatalf("capture URL = %q, want path %q", bundle.Manifest.Request.URL, test.providerPath)
			}
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			sawCapturedQuery := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "" {
					t.Fatalf("Authorization = %q, want empty for public GitLab endpoint", got)
				}
				if r.URL.Path != test.providerPath {
					t.Fatalf("path = %q, want %q", r.URL.Path, test.providerPath)
				}
				matched := true
				for key, value := range test.config {
					if r.URL.Query().Get(key) != value {
						matched = false
					}
				}
				if matched {
					sawCapturedQuery = true
				}
				w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
				for name, value := range bundle.Manifest.Response.Headers {
					w.Header().Set(name, value)
				}
				w.WriteHeader(bundle.Manifest.Response.Status)
				_, _ = w.Write(bundle.Payload)
			}))
			defer server.Close()
			cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": test.family, "health_path": test.providerPath, "per_page": "1"}
			for key, value := range test.config {
				cfgValues[key] = value
			}
			cfg := sourcecdk.NewConfig(cfgValues)
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if !sawCapturedQuery {
				t.Fatal("captured query was not replayed")
			}
			test.assertEvent(t, pull.Events[0].Attributes)
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, test.useCaptureTime); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES") == "1"); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := NewFixture(); err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
}

func TestSourceReadAuditEventsDoesNotInventResourceURN(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/api/v4/audit_events" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"id":          9001,
			"created_at":  "2026-06-01T00:00:00Z",
			"author_id":   7,
			"entity_id":   101,
			"entity_type": "Project",
			"entity_path": "writer/cerebro",
			"details": map[string]any{
				"custom_message": "Changed project visibility",
			},
		}})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyAuditEvents, "token": "test-token"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	assertNoResourceURN(t, pull.Events[0].Attributes)
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/api/v4/projects" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "maintenance"})
	}))
	defer server.Close()
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"auth_model": "bearer_token",
		"base_url":   server.URL,
		"family":     familyRepositories,
		"tenant_id":  "tenant",
		"token":      "test-token",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "gitlab API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func TestNewFixtureReplaysGitLabFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyRepositories, familyUsers, familyAuditEvents} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
	for _, tt := range []struct {
		family          string
		kind            string
		wantResourceURN string
	}{
		{family: familyRepositories, kind: "gitlab.repositories", wantResourceURN: "urn:cerebro:tenant:runtime_repositories:84581023"},
		{family: familyUsers, kind: "gitlab.users", wantResourceURN: "urn:cerebro:tenant:runtime_users:1786152"},
		{family: familyAuditEvents, kind: "gitlab.audit_events"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), familyConfigs[tt.family], nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("event kind = %q, want %q", got, tt.kind)
			}
			if tt.wantResourceURN == "" {
				assertNoResourceURN(t, pull.Events[0].Attributes)
				return
			}
			if got := pull.Events[0].Attributes["resource_urn"]; got != tt.wantResourceURN {
				t.Fatalf("resource_urn = %q, want %q", got, tt.wantResourceURN)
			}
		})
	}
}

func assertNoResourceURN(t *testing.T, attributes map[string]string) {
	t.Helper()
	if got := attributes["resource_urn"]; got != "" {
		t.Fatalf("resource_urn = %q, want empty because audit event target kind is not statically known", got)
	}
}
