package identitydirectory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

type stubDirectoryStore struct {
	orgs  []*ports.IdentityOrganization
	users []*ports.IdentityUser
}

func (s *stubDirectoryStore) Ping(context.Context) error { return nil }

func (s *stubDirectoryStore) UpsertIdentityOrganization(_ context.Context, org *ports.IdentityOrganization) error {
	copied := *org
	s.orgs = append(s.orgs, &copied)
	return nil
}

func (s *stubDirectoryStore) UpsertIdentityUser(_ context.Context, user *ports.IdentityUser) error {
	copied := *user
	copied.Roles = append([]string(nil), user.Roles...)
	copied.Groups = append([]string(nil), user.Groups...)
	s.users = append(s.users, &copied)
	return nil
}

func (s *stubDirectoryStore) ListIdentityOrganizations(_ context.Context, filter ports.IdentityOrganizationFilter) ([]*ports.IdentityOrganization, error) {
	var out []*ports.IdentityOrganization
	for _, org := range s.orgs {
		if filter.TenantID != "" && org.TenantID != filter.TenantID {
			continue
		}
		if filter.OrgID != "" && org.OrgID != filter.OrgID {
			continue
		}
		if !matchesExact(filter.Provider, org.Provider) || !matchesExact(filter.Source, identityDirectorySource(org.Source)) {
			continue
		}
		if !matchesQuery(filter.Query, org.OrgID, org.Name, org.Domain, identityDirectorySource(org.Source)) {
			continue
		}
		copied := *org
		out = append(out, &copied)
	}
	return out, nil
}

func (s *stubDirectoryStore) ListIdentityUsers(_ context.Context, filter ports.IdentityUserFilter) ([]*ports.IdentityUser, error) {
	var out []*ports.IdentityUser
	for _, user := range s.users {
		if filter.TenantID != "" && user.TenantID != filter.TenantID {
			continue
		}
		if filter.OrgID != "" && user.OrgID != filter.OrgID {
			continue
		}
		if !matchesExact(filter.Provider, user.Provider) || !matchesExact(filter.Source, identityDirectorySource(user.Source)) || !matchesExact(filter.Status, firstNonEmpty(user.Status, "active")) {
			continue
		}
		if !matchesQuery(filter.Query, user.UserID, user.Email, user.DisplayName, identityDirectorySource(user.Source)) {
			continue
		}
		copied := *user
		copied.Roles = append([]string(nil), user.Roles...)
		copied.Groups = append([]string(nil), user.Groups...)
		out = append(out, &copied)
	}
	return out, nil
}

func testHandler(store ports.StateStore) Handler {
	return NewHandler(store, config.AuthConfig{
		APIKeys: []config.APIKey{{
			Key:      "opaque-api-key-value",
			TenantID: "tenant-a",
		}},
		MCPOAuth: config.MCPOAuthConfig{
			TenantID: "tenant-a",
			Upstream: config.MCPOAuthUpstreamConfig{
				Issuer: "https://example.okta.com",
			},
			Clients: []config.MCPOAuthClient{{
				ClientID:   "automation",
				Name:       "Automation",
				GrantTypes: []string{"client_credentials"},
				TenantID:   "tenant-a",
				Roles:      []string{"cerebro.viewer"},
			}},
		},
	}, func(context.Context, string) (string, error) {
		return "tenant-a", nil
	}, nil)
}

func TestListOrganizationsIncludesOAuthTenant(t *testing.T) {
	handler := testHandler(&stubDirectoryStore{})
	recorder := httptest.NewRecorder()

	handler.ListOrganizations(recorder, httptest.NewRequest(http.MethodGet, "/identity/orgs", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response listOrganizationsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Organizations) != 1 {
		t.Fatalf("organizations = %+v, want one oauth tenant", response.Organizations)
	}
	org := response.Organizations[0]
	if org.OrgID != "tenant-a" || org.TenantID != "tenant-a" || org.Provider != "okta" || !strings.HasPrefix(org.Source, "mcp_oauth") {
		t.Fatalf("oauth organization = %+v", org)
	}
}

func TestListUsersMergesPersistedOAuthUsersAndConfiguredServiceUsers(t *testing.T) {
	store := &stubDirectoryStore{
		users: []*ports.IdentityUser{{
			TenantID:    "tenant-a",
			OrgID:       "tenant-a",
			UserID:      "00u123",
			Subject:     "00u123",
			Email:       "person@example.com",
			DisplayName: "Person Example",
			Status:      "active",
			Provider:    "okta",
			Source:      "mcp_oauth",
			Groups:      []string{"security-team"},
			LastSeenAt:  time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		}},
	}
	handler := testHandler(store)
	recorder := httptest.NewRecorder()

	handler.ListUsers(recorder, httptest.NewRequest(http.MethodGet, "/identity/users?q=person", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response listUsersResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Users) != 1 || response.Users[0].Email != "person@example.com" {
		t.Fatalf("filtered users = %+v, want persisted OAuth user", response.Users)
	}

	allRecorder := httptest.NewRecorder()
	handler.ListUsers(allRecorder, httptest.NewRequest(http.MethodGet, "/identity/users", nil))
	if !strings.Contains(allRecorder.Body.String(), "service:automation") {
		t.Fatalf("all users response missing configured service principal: %s", allRecorder.Body.String())
	}
	if strings.Contains(allRecorder.Body.String(), "opaque-api-key-value") {
		t.Fatalf("all users response leaked API key material: %s", allRecorder.Body.String())
	}
	if !strings.Contains(allRecorder.Body.String(), "api-key:1") {
		t.Fatalf("all users response missing non-secret API key placeholder: %s", allRecorder.Body.String())
	}
}

func TestListUsersKeepsConfiguredUsersInsideLimit(t *testing.T) {
	store := &stubDirectoryStore{
		users: []*ports.IdentityUser{
			{
				TenantID:    "tenant-a",
				OrgID:       "tenant-a",
				UserID:      "persisted-1",
				DisplayName: "Persisted 1",
				LastSeenAt:  time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC),
			},
			{
				TenantID:    "tenant-a",
				OrgID:       "tenant-a",
				UserID:      "persisted-2",
				DisplayName: "Persisted 2",
				LastSeenAt:  time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
			},
		},
	}
	handler := testHandler(store)
	recorder := httptest.NewRecorder()

	handler.ListUsers(recorder, httptest.NewRequest(http.MethodGet, "/identity/users?limit=2", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response listUsersResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Users) != 2 {
		t.Fatalf("users = %+v, want two configured users", response.Users)
	}
	for _, want := range []string{"api-key:1", "service:automation"} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Fatalf("limited users response missing configured user %q: %s", want, recorder.Body.String())
		}
	}
}

func TestListOrganizationsFiltersProviderAndSource(t *testing.T) {
	store := &stubDirectoryStore{
		orgs: []*ports.IdentityOrganization{{
			TenantID:  "tenant-a",
			OrgID:     "manual",
			Name:      "Manual",
			Provider:  "oidc",
			Source:    "identity_directory",
			UserCount: 2,
			UpdatedAt: time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC),
		}},
	}
	handler := testHandler(store)
	recorder := httptest.NewRecorder()

	handler.ListOrganizations(recorder, httptest.NewRequest(http.MethodGet, "/identity/orgs?provider=okta&source=mcp_oauth_client", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response listOrganizationsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Organizations) != 1 || response.Organizations[0].OrgID != "tenant-a" {
		t.Fatalf("organizations = %+v, want configured Okta OAuth tenant", response.Organizations)
	}
}

func TestListOrganizationsFiltersDefaultIdentityDirectorySource(t *testing.T) {
	store := &stubDirectoryStore{
		orgs: []*ports.IdentityOrganization{{
			TenantID: "tenant-a",
			OrgID:    "manual",
			Name:     "Manual",
			Provider: "oidc",
		}},
	}
	handler := testHandler(store)
	recorder := httptest.NewRecorder()

	handler.ListOrganizations(recorder, httptest.NewRequest(http.MethodGet, "/identity/orgs?provider=oidc&source=identity_directory", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response listOrganizationsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Organizations) != 1 || response.Organizations[0].OrgID != "manual" || response.Organizations[0].Source != "identity_directory" {
		t.Fatalf("organizations = %+v, want persisted org with default identity directory source", response.Organizations)
	}
}

func TestListUsersFiltersStatusProviderAndSource(t *testing.T) {
	store := &stubDirectoryStore{
		users: []*ports.IdentityUser{
			{
				TenantID:    "tenant-a",
				OrgID:       "tenant-a",
				UserID:      "00u123",
				DisplayName: "Suspended User",
				Status:      "suspended",
				Provider:    "okta",
				Source:      "mcp_oauth",
				LastSeenAt:  time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC),
			},
			{
				TenantID:    "tenant-a",
				OrgID:       "tenant-a",
				UserID:      "active-user",
				DisplayName: "Active User",
				Status:      "active",
				Provider:    "okta",
				Source:      "mcp_oauth",
			},
		},
	}
	handler := testHandler(store)
	recorder := httptest.NewRecorder()

	handler.ListUsers(recorder, httptest.NewRequest(http.MethodGet, "/identity/users?provider=okta&source=mcp_oauth&status=suspended", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response listUsersResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Users) != 1 || response.Users[0].UserID != "00u123" || response.Users[0].Status != "suspended" {
		t.Fatalf("users = %+v, want suspended Okta OAuth user", response.Users)
	}
}

func TestListUsersFiltersDefaultIdentityDirectorySource(t *testing.T) {
	store := &stubDirectoryStore{
		users: []*ports.IdentityUser{{
			TenantID:    "tenant-a",
			OrgID:       "tenant-a",
			UserID:      "manual-user",
			DisplayName: "Manual User",
			Provider:    "oidc",
		}},
	}
	handler := testHandler(store)
	recorder := httptest.NewRecorder()

	handler.ListUsers(recorder, httptest.NewRequest(http.MethodGet, "/identity/users?provider=oidc&source=identity_directory&status=active", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response listUsersResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Users) != 1 || response.Users[0].UserID != "manual-user" || response.Users[0].Source != "identity_directory" {
		t.Fatalf("users = %+v, want persisted user with default identity directory source", response.Users)
	}
}

func TestConfiguredEntitlementUserIDPrefersSubject(t *testing.T) {
	users := configuredUsers(config.AuthConfig{
		MCPOAuth: config.MCPOAuthConfig{
			Upstream: config.MCPOAuthUpstreamConfig{Issuer: "https://example.okta.com"},
			Entitlements: []config.MCPOAuthEntitlement{{
				TenantID: "tenant-a",
				Subject:  "00u123",
				Email:    "person@example.com",
			}},
		},
	}, "tenant-a", "")

	if len(users) != 1 || users[0].UserID != "00u123" {
		t.Fatalf("configured users = %+v, want subject-derived user id", users)
	}
}

func TestMergeUsersPreservesConfiguredGrantsOnPersistedCollision(t *testing.T) {
	configured := []*ports.IdentityUser{{
		TenantID:    "tenant-a",
		UserID:      "00u123",
		DisplayName: "Configured User",
		Roles:       []string{"cerebro.viewer"},
		Groups:      []string{"security-team"},
	}}
	persisted := []*ports.IdentityUser{{
		TenantID:    "tenant-a",
		UserID:      "00u123",
		Subject:     "00u123",
		Email:       "person@example.com",
		DisplayName: "Persisted User",
		LastSeenAt:  time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
	}}

	users := mergeUsers(configured, persisted, "tenant-a", "", "", "", "", "", 10)
	if len(users) != 1 {
		t.Fatalf("users = %+v, want one merged user", users)
	}
	if users[0].Email != "person@example.com" || users[0].DisplayName != "Persisted User" {
		t.Fatalf("merged user did not keep persisted profile fields: %+v", users[0])
	}
	if len(users[0].Roles) != 1 || users[0].Roles[0] != "cerebro.viewer" {
		t.Fatalf("merged roles = %#v, want configured role", users[0].Roles)
	}
	if len(users[0].Groups) != 1 || users[0].Groups[0] != "security-team" {
		t.Fatalf("merged groups = %#v, want configured group", users[0].Groups)
	}
}

func TestOAuthProviderUsesIssuerHost(t *testing.T) {
	if got := oauthProvider("https://tenant.okta.com/oauth2/default"); got != "okta" {
		t.Fatalf("oauthProvider(okta issuer) = %q, want okta", got)
	}
	if got := oauthProvider("https://booktaku.example.com/oauth2/default"); got != "oidc" {
		t.Fatalf("oauthProvider(non-okta issuer) = %q, want oidc", got)
	}
}
