package googleworkspace

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"gopkg.in/yaml.v3"
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

func TestCatalogDeclaresVerifiedGoogleWorkspaceProviderAPI(t *testing.T) {
	payload, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	var catalog struct {
		Description     string   `yaml:"description"`
		RuntimeFamilies []string `yaml:"runtime_families"`
		ProviderAPI     struct {
			Status     string   `yaml:"status"`
			Transport  string   `yaml:"transport"`
			Auth       string   `yaml:"auth"`
			BaseURL    string   `yaml:"base_url"`
			References []string `yaml:"references"`
			Families   []struct {
				ID     string `yaml:"id"`
				Method string `yaml:"method"`
				Path   string `yaml:"path"`
			} `yaml:"families"`
		} `yaml:"provider_api"`
	}
	if err := yaml.Unmarshal(payload, &catalog); err != nil {
		t.Fatalf("unmarshal catalog: %v", err)
	}
	for _, text := range []string{"Directory users", "group memberships", "admin role assignments", "Reports API admin activity"} {
		if !strings.Contains(catalog.Description, text) {
			t.Fatalf("description = %q, want source-specific text %q", catalog.Description, text)
		}
	}
	assertStringSet(t, catalog.RuntimeFamilies, []string{familyAudit, familyGroup, familyGroupMember, familyRoleAssign, familyUser})
	if catalog.ProviderAPI.Status != "verified" || catalog.ProviderAPI.Transport != "rest" || catalog.ProviderAPI.Auth != "bearer_token" || catalog.ProviderAPI.BaseURL != defaultBaseURL {
		t.Fatalf("provider_api = %#v, want verified REST bearer-token API at %s", catalog.ProviderAPI, defaultBaseURL)
	}
	for _, ref := range []string{
		"https://raw.githubusercontent.com/googleapis/google-api-go-client/main/admin/directory/v1/admin-api.json",
		"https://raw.githubusercontent.com/googleapis/google-api-go-client/main/admin/reports/v1/admin-api.json",
		"https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list",
		"https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list",
	} {
		if !hasString(catalog.ProviderAPI.References, ref) {
			t.Fatalf("provider references = %v, want %s", catalog.ProviderAPI.References, ref)
		}
	}
	wantPaths := map[string]string{
		familyAudit:       "/admin/reports/v1/activity/users/{userKey}/applications/{applicationName}",
		familyGroup:       "/admin/directory/v1/groups",
		familyGroupMember: "/admin/directory/v1/groups/{groupKey}/members",
		familyRoleAssign:  "/admin/directory/v1/customer/{customer}/roleassignments",
		familyUser:        "/admin/directory/v1/users",
	}
	gotPaths := map[string]string{}
	for _, family := range catalog.ProviderAPI.Families {
		if family.Method != http.MethodGet {
			t.Fatalf("provider family %s method = %q, want GET", family.ID, family.Method)
		}
		gotPaths[family.ID] = family.Path
	}
	for family, want := range wantPaths {
		if got := gotPaths[family]; got != want {
			t.Fatalf("provider path for %s = %q, want %q", family, got, want)
		}
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
		t.Fatal("Check() error = nil, want missing auth error")
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
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover(%s) error = %v", tt.family, err)
			}
			if len(urns) == 0 {
				t.Fatalf("Discover(%s) returned no URNs", tt.family)
			}
		})
	}
}

func TestReadLiveGoogleWorkspaceUserPreview(t *testing.T) {
	server := httptest.NewServer(newGoogleWorkspaceAPIHandler(t))
	defer server.Close()

	source, err := newLiveTestSource()
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
	if first.NextCursor == nil || sourcecdk.CursorToken(first.NextCursor) != "page-2" {
		t.Fatalf("first.NextCursor = %#v, want page-2", first.NextCursor)
	}
	if !sourcecdk.ResumableCursorOpaque(first.NextCursor.GetOpaque()) {
		t.Fatalf("first.NextCursor.Opaque = %q, want resumable envelope", first.NextCursor.GetOpaque())
	}
	if got := first.Events[0].Attributes["email"]; got != "admin@writer.com" {
		t.Fatalf("first event email = %q, want admin@writer.com", got)
	}
	second, err := source.ReadWithCheckpoint(context.Background(), cfg, first.NextCursor, first.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(user second) error = %v", err)
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

	source, err := newLiveTestSource()
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

func TestGoogleWorkspaceRoleAssignmentResolvesAssignedUserEmail(t *testing.T) {
	server := httptest.NewServer(newGoogleWorkspaceAPIHandler(t))
	defer server.Close()

	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"domain":   "writer.com",
		"family":   familyRoleAssign,
		"token":    "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", familyRoleAssign, err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["subject_email"]; got != "admin@writer.com" {
		t.Fatalf("subject_email = %q, want admin@writer.com", got)
	}
	if got := pull.Events[0].Attributes["subject_name"]; got != "Admin Writer" {
		t.Fatalf("subject_name = %q, want Admin Writer", got)
	}
}

func TestGoogleWorkspaceRoleAssignmentCachesUserLookupsPerPage(t *testing.T) {
	var userLookups int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/admin/directory/v1/customer/my_customer/roleassignments":
			if err := json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{"roleAssignmentId": "ra-1", "roleId": "super-admin", "assignedTo": "1001", "assigneeType": "USER", "scopeType": "CUSTOMER"},
					{"roleAssignmentId": "ra-2", "roleId": "groups-admin", "assignedTo": "1001", "assigneeType": "USER", "scopeType": "CUSTOMER"},
				},
			}); err != nil {
				t.Fatalf("encode role assignments: %v", err)
			}
		case "/admin/directory/v1/users/1001":
			userLookups++
			if err := json.NewEncoder(w).Encode(map[string]any{
				"id": "1001", "primaryEmail": "admin@writer.com", "name": map[string]any{"fullName": "Admin Writer"},
			}); err != nil {
				t.Fatalf("encode user lookup: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"domain":   "writer.com",
		"family":   familyRoleAssign,
		"per_page": "2",
		"token":    "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", familyRoleAssign, err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(pull.Events))
	}
	if userLookups != 1 {
		t.Fatalf("user lookups = %d, want 1", userLookups)
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/directory/v1/users" {
			t.Fatalf("path = %q, want /admin/directory/v1/users", r.URL.Path)
		}
		http.Error(w, `{"error":"service unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"domain":   "writer.com",
		"family":   familyUser,
		"token":    "test-token",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "google_workspace API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func newLiveTestSource() (*Source, error) {
	source, err := New()
	if err != nil {
		return nil, err
	}
	source.allowLoopbackBaseURL = true
	source.client = source.safeClient()
	return source, nil
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
		case "/admin/directory/v1/users/1001":
			if err := json.NewEncoder(w).Encode(map[string]any{
				"id": "1001", "primaryEmail": "admin@writer.com", "name": map[string]any{"fullName": "Admin Writer"},
			}); err != nil {
				t.Fatalf("encode user lookup: %v", err)
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

func assertStringSet(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("strings = %v, want %v", got, want)
	}
	for _, value := range want {
		if !hasString(got, value) {
			t.Fatalf("strings = %v, want %q", got, value)
		}
	}
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
