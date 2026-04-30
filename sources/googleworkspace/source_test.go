package googleworkspace

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "google_workspace" {
		t.Fatalf("Spec().Id = %q, want google_workspace", source.Spec().Id)
	}
}

func TestCheckRequiresDomainAndToken(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"token": "test-token"})); err == nil {
		t.Fatal("Check() error = nil, want missing domain error")
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"domain": "writer.com"})); err == nil {
		t.Fatal("Check() error = nil, want missing token error")
	}
}

func TestNewFixtureReplaysGoogleWorkspaceFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		kind   string
	}{
		{family: "user", kind: "google_workspace.user"},
		{family: "group", kind: "google_workspace.group"},
		{family: "group_member", kind: "google_workspace.group_member"},
		{family: "role_assignment", kind: "google_workspace.role_assignment"},
		{family: "audit", kind: "google_workspace.audit"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			cfg := sourcecdk.NewConfig(map[string]string{
				"domain":    "writer.com",
				"family":    tt.family,
				"group_key": "security@writer.com",
				"token":     "test-token",
			})
			pull, err := source.Read(context.Background(), cfg, nil)
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

func TestReadLiveGoogleWorkspaceUserPreview(t *testing.T) {
	server := httptest.NewServer(newGoogleWorkspaceAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"domain":   "writer.com",
		"family":   "user",
		"per_page": "1",
		"token":    "test-token",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(user) error = %v", err)
	}
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(user first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(user first).Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "page-2" {
		t.Fatalf("first.NextCursor = %#v, want page-2", first.NextCursor)
	}
	if got := first.Events[0].Attributes["email"]; got != "admin@writer.com" {
		t.Fatalf("first event email = %q, want admin@writer.com", got)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(user second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(user second).Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
}

func TestReadLiveGoogleWorkspaceRoleAndAuditPreview(t *testing.T) {
	server := httptest.NewServer(newGoogleWorkspaceAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		kind   string
	}{
		{family: "role_assignment", kind: "google_workspace.role_assignment"},
		{family: "audit", kind: "google_workspace.audit"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
				"base_url": server.URL,
				"domain":   "writer.com",
				"family":   tt.family,
				"token":    "test-token",
			}), nil)
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

func newGoogleWorkspaceAPIHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			if _, err := w.Write([]byte(`{"error":"invalid token"}`)); err != nil {
				t.Fatalf("write auth error: %v", err)
			}
			return
		}
		switch r.URL.Path {
		case "/admin/directory/v1/users":
			if r.URL.Query().Get("pageToken") == "" {
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]any{
					"nextPageToken": "page-2",
					"users": []map[string]any{{
						"id": "1001", "primaryEmail": "admin@writer.com", "name": map[string]any{"fullName": "Admin Writer"},
						"isAdmin": true, "isDelegatedAdmin": true, "isEnrolledIn2Sv": false, "isEnforcedIn2Sv": false,
						"creationTime": "2025-01-01T00:00:00.000Z", "lastLoginTime": "2025-01-15T00:00:00.000Z",
					}},
				}); err != nil {
					t.Fatalf("encode users page 1: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{{
					"id": "1002", "primaryEmail": "alice@writer.com", "name": map[string]any{"fullName": "Alice Writer"},
					"isAdmin": false, "isEnrolledIn2Sv": true, "isEnforcedIn2Sv": true,
					"creationTime": "2026-04-20T00:00:00.000Z", "lastLoginTime": "2026-04-23T00:00:00.000Z",
				}},
			}); err != nil {
				t.Fatalf("encode users page 2: %v", err)
			}
		case "/admin/directory/v1/customer/my_customer/roleassignments":
			if err := json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{"roleAssignmentId": "ra-1", "roleId": "super-admin", "assignedTo": "1001", "assigneeType": "USER", "scopeType": "CUSTOMER"}},
			}); err != nil {
				t.Fatalf("encode role assignments: %v", err)
			}
		case "/admin/reports/v1/activity/users/all/applications/admin":
			if err := json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{
					"id":     map[string]any{"time": "2026-04-23T00:00:00.000Z", "uniqueQualifier": "audit-1", "applicationName": "admin", "customerId": "C01"},
					"actor":  map[string]any{"email": "admin@writer.com", "profileId": "1001"},
					"events": []map[string]any{{"name": "CHANGE_TWO_STEP_VERIFICATION_ENFORCEMENT", "type": "SECURITY_SETTINGS"}},
				}},
			}); err != nil {
				t.Fatalf("encode audit: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	})
}
