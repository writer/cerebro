package okta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

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

func TestNewFixtureReplaysOktaIdentityFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
	}{
		{family: "admin_role", config: map[string]string{"user_id": "00u1", "user_email": "admin@writer.com"}, kind: "okta.admin_role"},
		{family: "app_assignment", config: map[string]string{"app_id": "app-prod"}, kind: "okta.app_assignment"},
		{family: "application", kind: "okta.application"},
		{family: "group", kind: "okta.group"},
		{family: "group_membership", config: map[string]string{"group_id": "grp-security"}, kind: "okta.group_membership"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{
				"domain": "writer.okta.com",
				"family": tt.family,
				"token":  "test-token",
			}
			for key, value := range tt.config {
				config[key] = value
			}
			urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(config))
			if err != nil {
				t.Fatalf("Discover(%s) error = %v", tt.family, err)
			}
			if len(urns) != 1 {
				t.Fatalf("len(Discover(%s)) = %d, want 1", tt.family, len(urns))
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tt.family, len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("Read(%s).Events[0].Kind = %q, want %q", tt.family, got, tt.kind)
			}
		})
	}
}

func TestCheckDiscoverAndReadLiveOktaAuditPreview(t *testing.T) {
	server := httptest.NewServer(newOktaAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
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
	server := httptest.NewServer(newOktaAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	discoverCfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
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
		"base_url": server.URL,
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

func TestReadLiveOktaIdentityJoinFamilies(t *testing.T) {
	server := httptest.NewServer(newOktaAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
		attr   string
		want   string
	}{
		{
			family: "group",
			kind:   "okta.group",
			attr:   "group_id",
			want:   "grp-security",
		},
		{
			family: "group_membership",
			config: map[string]string{"group_id": "grp-security"},
			kind:   "okta.group_membership",
			attr:   "member_email",
			want:   "admin@writer.com",
		},
		{
			family: "application",
			kind:   "okta.application",
			attr:   "app_id",
			want:   "app-prod",
		},
		{
			family: "app_assignment",
			config: map[string]string{"app_id": "app-prod"},
			kind:   "okta.app_assignment",
			attr:   "subject_email",
			want:   "admin@writer.com",
		},
		{
			family: "admin_role",
			config: map[string]string{"user_id": "00u1", "user_email": "admin@writer.com"},
			kind:   "okta.admin_role",
			attr:   "role_id",
			want:   "super_admin",
		},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{
				"base_url": server.URL,
				"domain":   "writer.okta.com",
				"family":   tt.family,
				"per_page": "1",
				"token":    "test-token",
			}
			for key, value := range tt.config {
				config[key] = value
			}
			if err := source.Check(context.Background(), sourcecdk.NewConfig(config)); err != nil {
				t.Fatalf("Check(%s) error = %v", tt.family, err)
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tt.family, len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("Read(%s).Events[0].Kind = %q, want %q", tt.family, got, tt.kind)
			}
			if got := pull.Events[0].Attributes[tt.attr]; got != tt.want {
				t.Fatalf("Read(%s).Events[0].Attributes[%q] = %q, want %q", tt.family, tt.attr, got, tt.want)
			}
		})
	}
}

func TestRejectsUnsafeBaseURL(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, baseURL := range []string{
		"http://writer.okta.com",
		"https://evil.okta.com",
		"https://writer.okta.com:8443",
		"https://writer.okta.com/path",
		"https://user@writer.okta.com",
		"https://localhost.",
	} {
		t.Run(baseURL, func(t *testing.T) {
			err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
				"base_url": baseURL,
				"domain":   "writer.okta.com",
				"family":   "audit",
				"token":    "test-token",
			}))
			if err == nil {
				t.Fatal("Check() error = nil, want non-nil")
			}
		})
	}
}

func TestRejectsUnsafeDomain(t *testing.T) {
	for _, domain := range []string{
		"localhost",
		"localhost.",
		"127.0.0.1",
		"127.0.0.1.",
		"[::1]",
	} {
		t.Run(domain, func(t *testing.T) {
			_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
				"domain": domain,
				"family": "audit",
				"token":  "test-token",
			}), false)
			if err == nil {
				t.Fatal("parseSettings() error = nil, want non-nil")
			}
		})
	}
}

func TestGetJSONRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[" + strings.Repeat(" ", maxOktaBodyBytes) + "]"))
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var target []map[string]any
	_, err = source.getJSON(context.Background(), settings{
		baseURL: server.URL,
		token:   "test-token",
	}, "/api/v1/logs", nil, &target)
	if err == nil {
		t.Fatal("getJSON() error = nil, want non-nil")
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
	groupRecords := []map[string]any{
		{
			"id":                    "grp-security",
			"type":                  "OKTA_GROUP",
			"created":               "2026-04-20T00:00:00Z",
			"lastUpdated":           "2026-04-23T00:00:00Z",
			"lastMembershipUpdated": "2026-04-23T01:00:00Z",
			"profile": map[string]any{
				"name":        "Security",
				"description": "Security team",
			},
		},
	}
	appRecords := []map[string]any{
		{
			"id":          "app-prod",
			"name":        "oidc_client",
			"label":       "Production Console",
			"status":      "ACTIVE",
			"signOnMode":  "OPENID_CONNECT",
			"created":     "2026-04-20T00:00:00Z",
			"lastUpdated": "2026-04-23T00:00:00Z",
		},
	}
	appAssignmentRecords := []map[string]any{
		{
			"id":          "00u1",
			"status":      "ACTIVE",
			"created":     "2026-04-20T00:00:00Z",
			"lastUpdated": "2026-04-23T00:00:00Z",
			"profile": map[string]any{
				"email": "admin@writer.com",
				"login": "admin@writer.com",
			},
		},
	}
	roleRecords := []map[string]any{
		{
			"id":             "super_admin",
			"label":          "Super Administrator",
			"type":           "SUPER_ADMIN",
			"assignmentType": "USER",
			"status":         "ACTIVE",
			"created":        "2026-04-20T00:00:00Z",
			"lastUpdated":    "2026-04-23T00:00:00Z",
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
		case "/api/v1/groups":
			if err := json.NewEncoder(w).Encode(groupRecords); err != nil {
				t.Fatalf("encode groups: %v", err)
			}
		case "/api/v1/groups/grp-security/users":
			if err := json.NewEncoder(w).Encode(userRecords[1:2]); err != nil {
				t.Fatalf("encode group members: %v", err)
			}
		case "/api/v1/apps":
			if err := json.NewEncoder(w).Encode(appRecords); err != nil {
				t.Fatalf("encode apps: %v", err)
			}
		case "/api/v1/apps/app-prod/users":
			if err := json.NewEncoder(w).Encode(appAssignmentRecords); err != nil {
				t.Fatalf("encode app assignments: %v", err)
			}
		case "/api/v1/users/00u1/roles":
			if err := json.NewEncoder(w).Encode(roleRecords); err != nil {
				t.Fatalf("encode admin roles: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	})
}
