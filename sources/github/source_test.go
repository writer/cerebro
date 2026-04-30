package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	gogithub "github.com/google/go-github/v66/github"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "github" {
		t.Fatalf("Spec().Id = %q, want %q", source.Spec().Id, "github")
	}
}

func TestCheckRequiresOwner(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(nil)); err == nil {
		t.Fatal("Check() error = nil, want non-nil")
	}
}

func TestReadRequiresRepo(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"owner": "writer"}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want non-nil")
	}
}

func TestAuditRequiresToken(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"family": "audit",
		"owner":  "writer",
	})); err == nil {
		t.Fatal("Check(audit) error = nil, want non-nil")
	}
}

func TestNewFixtureReturnsFixtureURNs(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(map[string]string{"token": "test"}))
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 2 {
		t.Fatalf("len(Discover()) = %d, want 2", len(urns))
	}
}

func TestNewFixtureReplaysFixturePages(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{"token": "test"})

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil {
		t.Fatal("first.NextCursor = nil, want non-nil")
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatal("second.NextCursor != nil, want nil")
	}

	final, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: "2"})
	if err != nil {
		t.Fatalf("Read(final) error = %v", err)
	}
	if len(final.Events) != 0 {
		t.Fatalf("len(final.Events) = %d, want 0", len(final.Events))
	}
}

func TestReadRejectsNegativeCursor(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{"owner": "writer", "repo": "cerebro"})

	if _, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: "-1"}); err == nil {
		t.Fatal("Read() error = nil, want non-nil")
	}
}

func TestReadTrimsCursor(t *testing.T) {
	server := httptest.NewServer(newGitHubAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"owner":    "writer",
		"per_page": "1",
		"repo":     "cerebro",
		"state":    "all",
	})

	pull, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: " 1 "})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
}

func TestCheckDiscoverAndReadLiveGitHubPullRequestPreview(t *testing.T) {
	server := httptest.NewServer(newGitHubAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	checkCfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"owner":    "writer",
	})
	if err := source.Check(context.Background(), checkCfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	discoverCfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"owner":    "writer",
	})
	discover, err := source.Discover(context.Background(), discoverCfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(discover) != 1 {
		t.Fatalf("len(Discover()) = %d, want 1", len(discover))
	}
	if discover[0] != "urn:cerebro:writer:repo:writer/cerebro" {
		t.Fatalf("Discover()[0] = %q, want repo urn", discover[0])
	}

	readCfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"owner":    "writer",
		"per_page": "1",
		"repo":     "cerebro",
		"state":    "all",
	})
	first, err := source.Read(context.Background(), readCfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "2" {
		t.Fatalf("first.NextCursor = %#v, want page 2", first.NextCursor)
	}
	if first.Checkpoint == nil || first.Checkpoint.CursorOpaque != "2" {
		t.Fatalf("first.Checkpoint = %#v, want cursor 2", first.Checkpoint)
	}

	second, err := source.Read(context.Background(), readCfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
	if second.Checkpoint == nil || second.Checkpoint.CursorOpaque != "3" {
		t.Fatalf("second.Checkpoint = %#v, want cursor 3", second.Checkpoint)
	}

	final, err := source.Read(context.Background(), readCfg, &cerebrov1.SourceCursor{Opaque: "3"})
	if err != nil {
		t.Fatalf("Read(final) error = %v", err)
	}
	if len(final.Events) != 0 {
		t.Fatalf("len(final.Events) = %d, want 0", len(final.Events))
	}
}

func TestCheckDiscoverAndReadLiveGitHubAuditPreview(t *testing.T) {
	server := httptest.NewServer(newGitHubAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   "audit",
		"include":  "all",
		"owner":    "writer",
		"token":    "test-token",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(audit) error = %v", err)
	}

	discover, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(audit) error = %v", err)
	}
	if len(discover) != 1 {
		t.Fatalf("len(Discover(audit)) = %d, want 1", len(discover))
	}
	if discover[0] != "urn:cerebro:writer:org:writer" {
		t.Fatalf("Discover(audit)[0] = %q, want org urn", discover[0])
	}

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(audit first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(audit first).Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "cursor-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-2", first.NextCursor)
	}
	if got := first.Events[0].Kind; got != "github.audit" {
		t.Fatalf("first.Events[0].Kind = %q, want github.audit", got)
	}
	if got := first.Events[0].Attributes["permission"]; got != "admin" {
		t.Fatalf("first.Events[0].Attributes[permission] = %q, want admin", got)
	}
	if got := first.Events[0].Attributes["previous_visibility"]; got != "private" {
		t.Fatalf("first.Events[0].Attributes[previous_visibility] = %q, want private", got)
	}
	if got := first.Events[0].Attributes["external_identity_nameid"]; got != "dependabot@writer.com" {
		t.Fatalf("first.Events[0].Attributes[external_identity_nameid] = %q, want dependabot@writer.com", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(first.Events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal audit payload: %v", err)
	}
	if got := payload["resource_type"]; got != "repository_vulnerability_alert" {
		t.Fatalf("audit payload resource_type = %#v, want repository_vulnerability_alert", got)
	}
	if got := payload["resource_id"]; got != "writer/cerebro" {
		t.Fatalf("audit payload resource_id = %#v, want writer/cerebro", got)
	}
	raw, ok := payload["raw"].(map[string]any)
	if !ok {
		t.Fatalf("audit payload raw = %#v, want object", payload["raw"])
	}
	if got := raw["action"]; got != "repository_vulnerability_alert.create" {
		t.Fatalf("audit raw action = %#v, want repository_vulnerability_alert.create", got)
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(audit second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(audit second).Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
	if second.Checkpoint == nil || second.Checkpoint.CursorOpaque != "audit-doc-2" {
		t.Fatalf("second.Checkpoint = %#v, want audit-doc-2", second.Checkpoint)
	}
}

func TestNextAuditCursorIgnoresBefore(t *testing.T) {
	if got := nextAuditCursor(&gogithub.Response{Before: "cursor-1"}); got != "" {
		t.Fatalf("nextAuditCursor() = %q, want empty cursor", got)
	}
}

func TestCheckDiscoverAndReadLiveGitHubDependabotAlertPreview(t *testing.T) {
	server := httptest.NewServer(newGitHubAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   "dependabot_alert",
		"owner":    "writer",
		"per_page": "1",
		"repo":     "cerebro",
		"token":    "test-token",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(dependabot_alert) error = %v", err)
	}

	discover, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(dependabot_alert) error = %v", err)
	}
	if len(discover) != 1 {
		t.Fatalf("len(Discover(dependabot_alert)) = %d, want 1", len(discover))
	}
	if discover[0] != "urn:cerebro:writer:repo:writer/cerebro" {
		t.Fatalf("Discover(dependabot_alert)[0] = %q, want repo urn", discover[0])
	}

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(dependabot_alert first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(dependabot_alert first).Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "cursor-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-2", first.NextCursor)
	}
	if got := first.Events[0].Kind; got != "github.dependabot_alert" {
		t.Fatalf("first.Events[0].Kind = %q, want github.dependabot_alert", got)
	}
	if got := first.Events[0].Attributes["severity"]; got != "high" {
		t.Fatalf("first.Events[0].Attributes[severity] = %q, want high", got)
	}
	if got := first.Events[0].Attributes["package"]; got != "golang.org/x/crypto" {
		t.Fatalf("first.Events[0].Attributes[package] = %q, want golang.org/x/crypto", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(first.Events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal dependabot payload: %v", err)
	}
	if got := payload["ghsa_id"]; got != "GHSA-xxxx-yyyy-zzzz" {
		t.Fatalf("dependabot payload ghsa_id = %#v, want GHSA", got)
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(dependabot_alert second) error = %v", err)
	}
	if len(second.Events) != 0 {
		t.Fatalf("len(Read(dependabot_alert second).Events) = %d, want 0", len(second.Events))
	}
}

func newGitHubAPIHandler(t *testing.T) http.Handler {
	t.Helper()

	repo := map[string]any{
		"id":        1,
		"name":      "cerebro",
		"full_name": "writer/cerebro",
		"html_url":  "https://github.com/writer/cerebro",
	}
	pulls := []map[string]any{
		{
			"number":     443,
			"title":      "feat(source): add source preview surfaces",
			"state":      "open",
			"html_url":   "https://github.com/writer/cerebro/pull/443",
			"created_at": "2026-04-23T01:00:00Z",
			"updated_at": "2026-04-23T02:00:00Z",
			"user": map[string]any{
				"login": "jonathan",
			},
			"draft": false,
			"head": map[string]any{
				"label": "writer:feat/cerebro-next-source-preview-20260423",
			},
			"base": map[string]any{
				"label": "writer:feat/cerebro-next-source-registry-20260423",
			},
		},
		{
			"number":     442,
			"title":      "feat(bootstrap): expose the source registry",
			"state":      "closed",
			"html_url":   "https://github.com/writer/cerebro/pull/442",
			"created_at": "2026-04-22T23:00:00Z",
			"updated_at": "2026-04-23T00:00:00Z",
			"closed_at":  "2026-04-23T00:30:00Z",
			"user": map[string]any{
				"login": "jonathan",
			},
			"draft": false,
			"head": map[string]any{
				"label": "writer:feat/cerebro-next-source-registry-20260423",
			},
			"base": map[string]any{
				"label": "writer:feat/cerebro-next-source-cdk-20260423",
			},
		},
	}
	auditEntries := []map[string]any{
		{
			"@timestamp":                  1776916397852,
			"_document_id":                "audit-doc-1",
			"action":                      "repository_vulnerability_alert.create",
			"actor":                       "dependabot[bot]",
			"actor_id":                    49699333,
			"actor_is_bot":                true,
			"business":                    "writer",
			"business_id":                 10550,
			"created_at":                  1776916397852,
			"external_identity_nameid":    "dependabot@writer.com",
			"operation_type":              "create",
			"org":                         "writer",
			"org_id":                      1,
			"permission":                  "admin",
			"previous_visibility":         "private",
			"programmatic_access_type":    "GitHub App server-to-server token",
			"public_repo":                 false,
			"repo":                        "writer/cerebro",
			"repo_id":                     1,
			"visibility":                  "internal",
			"request_id":                  "audit-1",
			"repository_vulnerability_id": 99,
		},
		{
			"@timestamp":     1776916385929,
			"_document_id":   "audit-doc-2",
			"action":         "org_credential_authorization.deauthorize",
			"actor":          "octocat",
			"actor_id":       1,
			"created_at":     1776916385929,
			"operation_type": "modify",
			"org":            "writer",
			"org_id":         1,
			"user":           "octocat",
			"user_id":        1,
			"actor_is_agent": false,
			"actor_is_bot":   false,
			"request_id":     "audit-2",
			"visibility":     "internal",
		},
	}
	dependabotAlerts := []map[string]any{
		{
			"number":     7,
			"state":      "open",
			"url":        "https://api.github.com/repos/writer/cerebro/dependabot/alerts/7",
			"html_url":   "https://github.com/writer/cerebro/security/dependabot/7",
			"created_at": "2026-04-23T00:00:00Z",
			"updated_at": "2026-04-24T00:00:00Z",
			"dependency": map[string]any{
				"package": map[string]any{
					"ecosystem": "go",
					"name":      "golang.org/x/crypto",
				},
				"manifest_path": "go.mod",
				"scope":         "runtime",
			},
			"security_advisory": map[string]any{
				"ghsa_id":  "GHSA-xxxx-yyyy-zzzz",
				"cve_id":   "CVE-2026-0001",
				"summary":  "High severity issue in golang.org/x/crypto",
				"severity": "high",
			},
			"security_vulnerability": map[string]any{
				"package": map[string]any{
					"ecosystem": "go",
					"name":      "golang.org/x/crypto",
				},
				"severity":                 "high",
				"vulnerable_version_range": "< 0.31.0",
				"first_patched_version": map[string]any{
					"identifier": "0.31.0",
				},
			},
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v3/orgs/writer/repos":
			if err := json.NewEncoder(w).Encode([]map[string]any{repo}); err != nil {
				t.Fatalf("encode repos response: %v", err)
			}
		case "/api/v3/repos/writer/cerebro":
			if err := json.NewEncoder(w).Encode(repo); err != nil {
				t.Fatalf("encode repo response: %v", err)
			}
		case "/api/v3/repos/writer/cerebro/pulls":
			page := r.URL.Query().Get("page")
			if page == "" || page == "1" {
				w.Header().Set("Link", "</api/v3/repos/writer/cerebro/pulls?page=2>; rel=\"next\", </api/v3/repos/writer/cerebro/pulls?page=2>; rel=\"last\"")
				if err := json.NewEncoder(w).Encode(pulls[:1]); err != nil {
					t.Fatalf("encode pulls page 1: %v", err)
				}
				return
			}
			if page == "2" {
				if err := json.NewEncoder(w).Encode(pulls[1:2]); err != nil {
					t.Fatalf("encode pulls page 2: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode empty pulls page: %v", err)
			}
		case "/api/v3/orgs/writer/audit-log":
			after := r.URL.Query().Get("after")
			if after == "" {
				w.Header().Set("Link", "</api/v3/orgs/writer/audit-log?after=cursor-2&before=>; rel=\"next\"")
				if err := json.NewEncoder(w).Encode(auditEntries[:1]); err != nil {
					t.Fatalf("encode audit page 1: %v", err)
				}
				return
			}
			if after == "cursor-2" {
				if err := json.NewEncoder(w).Encode(auditEntries[1:2]); err != nil {
					t.Fatalf("encode audit page 2: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode empty audit page: %v", err)
			}
		case "/api/v3/repos/writer/cerebro/dependabot/alerts":
			after := r.URL.Query().Get("after")
			if after == "" {
				w.Header().Set("Link", "</api/v3/repos/writer/cerebro/dependabot/alerts?after=cursor-2&before=>; rel=\"next\"")
				if err := json.NewEncoder(w).Encode(dependabotAlerts); err != nil {
					t.Fatalf("encode dependabot alerts page 1: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode empty dependabot alerts page: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	})
}
