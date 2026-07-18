package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceReplaysCapturedPullRequest(t *testing.T) {
	pullBundle := capturedGitHubBundle(t, familyPullRequest, "pull_requests")
	repoBundle := capturedGitHubBundle(t, familyRepository, "repository")
	server := capturedGitHubServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v3/repos/octocat/Hello-World":
			writeCapturedGitHubResponse(w, repoBundle)
			return true
		case "/api/v3/repos/octocat/Hello-World/pulls":
			if r.URL.Query().Get("state") != "all" || r.URL.Query().Get("sort") != "updated" || r.URL.Query().Get("direction") != "desc" || r.URL.Query().Get("per_page") != "1" {
				t.Fatalf("pull request query = %q", r.URL.RawQuery)
			}
			writeCapturedGitHubResponse(w, pullBundle)
			return true
		default:
			return false
		}
	})
	defer server.Close()

	source := capturedGitHubSource(t)
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyPullRequest,
		"owner":    "octocat",
		"per_page": "1",
		"repo":     "Hello-World",
		"state":    "all",
		"token":    "test-token",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Attributes["pull_number"] != "1" || pull.Events[0].Attributes["repository"] != "octocat/Hello-World" {
		t.Fatalf("pull request events = %#v", pull.Events)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if err := sourcefixture.StabilizeEvents(pullBundle, pull.Events, false); err != nil {
		t.Fatalf("StabilizeEvents() error = %v", err)
	}
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", familyPullRequest, pull.Events, urns, updateCapturedSourceFixtures()); err != nil {
		t.Fatal(err)
	}
}

func TestSourceReplaysCapturedRepositoryShapes(t *testing.T) {
	tests := []struct {
		name         string
		fixtureCase  string
		owner        string
		repo         string
		manifestPath string
		apiPath      string
		fallbackPath string
		wantFullName string
	}{
		{name: "repository", fixtureCase: "repository", owner: "octocat", repo: "Hello-World", apiPath: "/api/v3/repos/octocat/Hello-World", wantFullName: "octocat/Hello-World"},
		{name: "organization repositories", fixtureCase: "org_repositories", owner: "github", apiPath: "/api/v3/orgs/github/repos", wantFullName: "github/copilot-sdk"},
		{name: "user repositories", fixtureCase: "user_repositories", owner: "octocat", apiPath: "/api/v3/users/octocat/repos", fallbackPath: "/api/v3/orgs/octocat/repos", wantFullName: "octocat/Spoon-Knife"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := capturedGitHubBundle(t, familyRepository, test.fixtureCase)
			server := capturedGitHubServer(t, func(w http.ResponseWriter, r *http.Request) bool {
				if test.fallbackPath != "" && r.URL.Path == test.fallbackPath {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"message":"Not Found"}`))
					return true
				}
				if r.URL.Path != test.apiPath {
					return false
				}
				if test.repo == "" && (r.URL.Query().Get("sort") != "updated" || r.URL.Query().Get("direction") != "desc" || r.URL.Query().Get("per_page") != "1") {
					t.Fatalf("repository list query = %q", r.URL.RawQuery)
				}
				writeCapturedGitHubResponse(w, bundle)
				return true
			})
			defer server.Close()

			source := capturedGitHubSource(t)
			values := map[string]string{"base_url": server.URL, "family": familyRepository, "owner": test.owner, "per_page": "1", "token": "test-token"}
			if test.repo != "" {
				values["repo"] = test.repo
			}
			cfg := sourcecdk.NewConfig(values)
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 || pull.Events[0].Attributes["full_name"] != test.wantFullName {
				t.Fatalf("repository events = %#v", pull.Events)
			}
			if test.fixtureCase != "repository" {
				return
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", familyRepository, pull.Events, urns, updateCapturedSourceFixtures()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSourceReplaysCapturedOrganizationMembers(t *testing.T) {
	bundle := capturedGitHubBundle(t, familyOrgInventory, "members")
	server := capturedGitHubServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v3/orgs/github/members":
			if r.URL.Query().Get("per_page") != "1" {
				t.Fatalf("members query = %q", r.URL.RawQuery)
			}
			writeCapturedGitHubResponse(w, bundle)
			return true
		case "/api/v3/orgs/github/outside_collaborators", "/api/v3/orgs/github/installations":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
			return true
		default:
			return false
		}
	})
	defer server.Close()

	source := capturedGitHubSource(t)
	cfg := sourcecdk.NewConfig(map[string]string{"base_url": server.URL, "family": familyOrgInventory, "owner": "github", "per_page": "1", "token": "test-token"})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Kind != "github.org_member" || pull.Events[0].Attributes["login"] != "aashah" {
		t.Fatalf("organization inventory events = %#v", pull.Events)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if err := sourcefixture.StabilizeEvents(bundle, pull.Events, true); err != nil {
		t.Fatalf("StabilizeEvents() error = %v", err)
	}
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", familyOrgInventory, pull.Events, urns, updateCapturedSourceFixtures()); err != nil {
		t.Fatal(err)
	}
}

func capturedGitHubBundle(t *testing.T, family, fixtureCase string) sourcefixture.Bundle {
	t.Helper()
	bundle, err := sourcefixture.FindBundle("../..", "github", family, fixtureCase)
	if err != nil {
		t.Fatalf("FindBundle(%s/%s) error = %v", family, fixtureCase, err)
	}
	return bundle
}

func capturedGitHubSource(t *testing.T) *Source {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	return source
}

func capturedGitHubServer(t *testing.T, handler func(http.ResponseWriter, *http.Request) bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q, want replay token", got)
		}
		if handler(w, r) {
			return
		}
		t.Fatalf("unexpected GitHub replay request %s %s", r.Method, r.URL.RequestURI())
	}))
}

func writeCapturedGitHubResponse(w http.ResponseWriter, bundle sourcefixture.Bundle) {
	w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
	for name, value := range bundle.Manifest.Response.Headers {
		w.Header().Set(name, value)
	}
	w.WriteHeader(bundle.Manifest.Response.Status)
	_, _ = w.Write(bundle.Payload)
}

func updateCapturedSourceFixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}
