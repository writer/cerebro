package okta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type rewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = t.target.Scheme
	cloned.URL.Host = t.target.Host
	cloned.Host = t.target.Host
	return t.base.RoundTrip(cloned)
}

func newTestSource(t *testing.T, handler http.Handler) (*Source, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	target, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		t.Fatalf("parse test server URL: %v", err)
	}
	source, err := New()
	if err != nil {
		server.Close()
		t.Fatalf("New() error = %v", err)
	}
	source.client = &http.Client{
		Transport: rewriteTransport{
			target: target,
			base:   http.DefaultTransport,
		},
	}
	return source, server.Close
}

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "okta" {
		t.Fatalf("Spec().Id = %q, want %q", source.Spec().Id, "okta")
	}
}

func TestCheckRequiresDomain(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"token": "test-token"})); err == nil {
		t.Fatal("Check() error = nil, want non-nil")
	}
}

func TestAuditRequiresToken(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"domain": "writer.okta.com",
		"family": "audit",
	})); err == nil {
		t.Fatal("Check(audit) error = nil, want non-nil")
	}
}

func TestUserRejectsSince(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"domain": "writer.okta.com",
		"family": "user",
		"since":  "2026-04-23T00:00:00Z",
		"token":  "test-token",
	}), nil)
	if err == nil {
		t.Fatal("Read(user) error = nil, want non-nil")
	}
}

func TestParseSettingsRejectsUnsafeBaseURL(t *testing.T) {
	for name, baseURL := range map[string]string{
		"http":       "http://writer.okta.com",
		"other-host": "https://attacker.example.com",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
				"base_url": baseURL,
				"domain":   "writer.okta.com",
				"family":   "audit",
				"token":    "test-token",
			}))
			if err == nil {
				t.Fatalf("parseSettings() error = nil, want non-nil")
			}
		})
	}
}

func TestNewFixtureReturnsFixtureURNs(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(map[string]string{
		"domain": "writer.okta.com",
		"family": "user",
		"token":  "test-token",
	}))
	if err != nil {
		t.Fatalf("Discover(user) error = %v", err)
	}
	if len(urns) != 2 {
		t.Fatalf("len(Discover(user)) = %d, want 2", len(urns))
	}
}

func TestNewFixtureReplaysFixturePages(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"domain": "writer.okta.com",
		"family": "audit",
		"token":  "test-token",
	})

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

func TestNewFixtureRejectsNegativeCursor(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"domain": "writer.okta.com",
		"family": "audit",
		"token":  "test-token",
	})

	_, err = source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: "-1"})
	if err == nil {
		t.Fatal("Read() error = nil, want non-nil")
	}
}

func TestCheckDiscoverAndReadLiveOktaAuditPreview(t *testing.T) {
	source, cleanup := newTestSource(t, newOktaAPIHandler(t))
	defer cleanup()
	cfg := sourcecdk.NewConfig(map[string]string{
		"domain":   "writer.okta.com",
		"family":   "audit",
		"per_page": "1",
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
	if discover[0] != "urn:cerebro:writer.okta.com:org:writer.okta.com" {
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
	if got := first.Events[0].Kind; got != "okta.audit" {
		t.Fatalf("first.Events[0].Kind = %q, want okta.audit", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(first.Events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal audit payload: %v", err)
	}
	if got := payload["resource_type"]; got != "User" {
		t.Fatalf("audit payload resource_type = %#v, want User", got)
	}
	if got := payload["resource_id"]; got != "00u1" {
		t.Fatalf("audit payload resource_id = %#v, want 00u1", got)
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
	if second.Checkpoint == nil || second.Checkpoint.CursorOpaque != "evt-2" {
		t.Fatalf("second.Checkpoint = %#v, want evt-2", second.Checkpoint)
	}
}

func TestCheckDiscoverAndReadLiveOktaUserPreview(t *testing.T) {
	source, cleanup := newTestSource(t, newOktaAPIHandler(t))
	defer cleanup()
	discoverCfg := sourcecdk.NewConfig(map[string]string{
		"domain":   "writer.okta.com",
		"family":   "user",
		"per_page": "2",
		"token":    "test-token",
	})
	if err := source.Check(context.Background(), discoverCfg); err != nil {
		t.Fatalf("Check(user) error = %v", err)
	}

	discover, err := source.Discover(context.Background(), discoverCfg)
	if err != nil {
		t.Fatalf("Discover(user) error = %v", err)
	}
	if len(discover) != 2 {
		t.Fatalf("len(Discover(user)) = %d, want 2", len(discover))
	}
	if discover[0] != "urn:cerebro:writer.okta.com:user:00u1" {
		t.Fatalf("Discover(user)[0] = %q, want first user urn", discover[0])
	}

	readCfg := sourcecdk.NewConfig(map[string]string{
		"domain":   "writer.okta.com",
		"family":   "user",
		"per_page": "1",
		"token":    "test-token",
	})
	first, err := source.Read(context.Background(), readCfg, nil)
	if err != nil {
		t.Fatalf("Read(user first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(user first).Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "cursor-user-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-user-2", first.NextCursor)
	}
	if got := first.Events[0].Kind; got != "okta.user" {
		t.Fatalf("first.Events[0].Kind = %q, want okta.user", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(first.Events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal user payload: %v", err)
	}
	profile, ok := payload["profile"].(map[string]any)
	if !ok {
		t.Fatalf("user payload profile = %#v, want object", payload["profile"])
	}
	if got := profile["login"]; got != "alice@writer.com" {
		t.Fatalf("user payload profile.login = %#v, want alice@writer.com", got)
	}

	second, err := source.Read(context.Background(), readCfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(user second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(user second).Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
	if second.Checkpoint == nil || second.Checkpoint.CursorOpaque != "00u2" {
		t.Fatalf("second.Checkpoint = %#v, want 00u2", second.Checkpoint)
	}
}

func newOktaAPIHandler(t *testing.T) http.Handler {
	t.Helper()

	auditRecords := []map[string]any{
		{
			"uuid":           "evt-1",
			"published":      "2026-04-23T01:00:00Z",
			"eventType":      "user.session.start",
			"displayMessage": "User login to Okta",
			"severity":       "INFO",
			"actor": map[string]any{
				"id":          "00u1",
				"type":        "User",
				"alternateId": "alice@writer.com",
				"displayName": "Alice Example",
			},
			"client": map[string]any{
				"ipAddress": "1.2.3.4",
				"zone":      "null",
				"userAgent": map[string]any{
					"rawUserAgent": "Mozilla/5.0",
				},
			},
			"outcome": map[string]any{
				"result": "SUCCESS",
			},
			"transaction": map[string]any{
				"id": "txn-1",
			},
			"target": []map[string]any{
				{
					"id":          "00u1",
					"type":        "User",
					"alternateId": "alice@writer.com",
					"displayName": "Alice Example",
				},
			},
		},
		{
			"uuid":           "evt-2",
			"published":      "2026-04-23T00:00:00Z",
			"eventType":      "policy.rule.update",
			"displayMessage": "Policy updated",
			"severity":       "WARN",
			"actor": map[string]any{
				"id":          "00u2",
				"type":        "User",
				"alternateId": "admin@writer.com",
				"displayName": "Admin Example",
			},
			"outcome": map[string]any{
				"result": "SUCCESS",
			},
			"target": []map[string]any{
				{
					"id":          "pol-1",
					"type":        "PolicyRule",
					"displayName": "Require MFA",
				},
			},
		},
	}
	userRecords := []map[string]any{
		{
			"id":          "00u1",
			"status":      "ACTIVE",
			"created":     "2026-04-20T00:00:00Z",
			"activated":   "2026-04-20T00:01:00Z",
			"lastUpdated": "2026-04-23T01:00:00Z",
			"lastLogin":   "2026-04-23T01:00:00Z",
			"profile": map[string]any{
				"login":        "alice@writer.com",
				"email":        "alice@writer.com",
				"displayName":  "Alice Example",
				"firstName":    "Alice",
				"lastName":     "Example",
				"department":   "Security",
				"title":        "Engineer",
				"organization": "Writer",
				"userType":     "employee",
			},
			"type": map[string]any{
				"id":   "oty1",
				"name": "default",
			},
		},
		{
			"id":            "00u2",
			"status":        "SUSPENDED",
			"created":       "2026-04-20T02:00:00Z",
			"lastUpdated":   "2026-04-23T00:30:00Z",
			"statusChanged": "2026-04-23T00:30:00Z",
			"profile": map[string]any{
				"login":       "admin@writer.com",
				"email":       "admin@writer.com",
				"displayName": "Admin Example",
				"firstName":   "Admin",
				"lastName":    "Example",
			},
			"type": map[string]any{
				"id":   "oty1",
				"name": "default",
			},
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if got := r.Header.Get("Authorization"); got != "SSWS test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			if err := json.NewEncoder(w).Encode(map[string]any{"errorSummary": "invalid token"}); err != nil {
				t.Fatalf("encode auth error: %v", err)
			}
			return
		}
		switch r.URL.Path {
		case "/api/v1/logs":
			after := r.URL.Query().Get("after")
			if after == "" {
				w.Header().Set("Link", "</api/v1/logs?after=cursor-2&limit=1>; rel=\"next\"")
				if err := json.NewEncoder(w).Encode(auditRecords[:1]); err != nil {
					t.Fatalf("encode audit page 1: %v", err)
				}
				return
			}
			if after == "cursor-2" {
				if err := json.NewEncoder(w).Encode(auditRecords[1:2]); err != nil {
					t.Fatalf("encode audit page 2: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode empty audit page: %v", err)
			}
		case "/api/v1/users":
			after := r.URL.Query().Get("after")
			if after == "" {
				limit := r.URL.Query().Get("limit")
				if limit == "2" {
					if err := json.NewEncoder(w).Encode(userRecords); err != nil {
						t.Fatalf("encode user discover page: %v", err)
					}
					return
				}
				w.Header().Set("Link", "</api/v1/users?after=cursor-user-2&limit=1>; rel=\"next\"")
				if err := json.NewEncoder(w).Encode(userRecords[:1]); err != nil {
					t.Fatalf("encode users page 1: %v", err)
				}
				return
			}
			if after == "cursor-user-2" {
				if err := json.NewEncoder(w).Encode(userRecords[1:2]); err != nil {
					t.Fatalf("encode users page 2: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode empty users page: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	})
}
