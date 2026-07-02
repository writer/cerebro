package mcpoauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func identityForTest(subject string, groups []string) Identity {
	return NewIdentity(subject, VerifiedEmail{}, "", groups)
}

func verifiedIdentityForTest(t *testing.T, subject string, email string, name string, groups []string) Identity {
	t.Helper()
	verifiedEmail, ok := NewVerifiedEmail(email, true)
	if !ok {
		t.Fatalf("NewVerifiedEmail(%q, true) rejected test email", email)
	}
	return NewIdentity(subject, verifiedEmail, name, groups)
}

func TestTokenRefreshReplayRevokesFamily(t *testing.T) {
	store := &replayRefreshStore{
		consumeRecord: RefreshToken{FamilyID: "family-1"},
		consumeErr:    ErrReplay,
	}
	service, err := NewService(config.MCPOAuthConfig{
		Resource:   "https://cerebro.example/api/v1/mcp",
		AccessTTL:  time.Minute,
		RefreshTTL: time.Hour,
		Clients: []config.MCPOAuthClient{{
			ClientID: "droid",
			Public:   true,
		}},
	}, store, func(context.Context, AccessGrant, time.Duration, time.Time) (string, error) {
		return "access-token", nil
	}, WithOIDCProvider(stubOIDCProvider{}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	_, err = service.Token(context.Background(), "", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"droid"},
		"resource":      {"https://cerebro.example/api/v1/mcp"},
		"refresh_token": {"stolen-refresh-token"},
	})
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != "invalid_grant" {
		t.Fatalf("Token replay error = %v, want invalid_grant OAuthError", err)
	}
	if len(store.revokedFamilies) != 1 || store.revokedFamilies[0] != "family-1" {
		t.Fatalf("revokedFamilies = %#v, want [family-1]", store.revokedFamilies)
	}
}

func TestTokenDoesNotBypassClientSecretWhenPublicFlagIsSet(t *testing.T) {
	service, err := NewService(config.MCPOAuthConfig{
		Resource:   "https://cerebro.example/api/v1/mcp",
		AccessTTL:  time.Minute,
		RefreshTTL: time.Hour,
		Clients: []config.MCPOAuthClient{{
			ClientID:     "droid",
			ClientSecret: "secret",
			Public:       true,
		}},
	}, &replayRefreshStore{}, func(context.Context, AccessGrant, time.Duration, time.Time) (string, error) {
		return "access-token", nil
	}, WithOIDCProvider(stubOIDCProvider{}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	_, err = service.Token(context.Background(), "", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"droid"},
		"resource":      {"https://cerebro.example/api/v1/mcp"},
		"refresh_token": {"refresh-token"},
	})
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != "invalid_client" {
		t.Fatalf("Token without client secret error = %v, want invalid_client OAuthError", err)
	}
}

func TestClientCredentialsAcceptsHashedClientSecret(t *testing.T) {
	sum := sha256.Sum256([]byte("client-secret"))
	service, err := NewService(config.MCPOAuthConfig{
		Resource:  "https://cerebro.example/api/v1/mcp",
		AccessTTL: time.Minute,
		Clients: []config.MCPOAuthClient{{
			ClientID:           "panopticon",
			ClientSecretSHA256: base16Lower(sum[:]),
			GrantTypes:         []string{"client_credentials"},
			AllowedTenants:     []string{"writer"},
			Scopes:             []string{ScopeSecurityRead},
		}},
	}, &replayRefreshStore{}, func(_ context.Context, grant AccessGrant, _ time.Duration, _ time.Time) (string, error) {
		if grant.ClientID != "panopticon" || len(grant.AllowedTenants) != 1 || grant.AllowedTenants[0] != "writer" {
			t.Fatalf("grant = %#v", grant)
		}
		return "access-token", nil
	}, WithOIDCProvider(stubOIDCProvider{}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	response, err := service.Token(context.Background(), "Basic "+base64.StdEncoding.EncodeToString([]byte("panopticon:client-secret")), url.Values{
		"grant_type": {"client_credentials"},
		"resource":   {"https://cerebro.example/api/v1/mcp"},
	})
	if err != nil {
		t.Fatalf("Token error = %v", err)
	}
	if response.AccessToken != "access-token" || response.RefreshToken != "" {
		t.Fatalf("response = %#v", response)
	}
}

func TestClientCredentialsDropsRolesWhenExplicitScopeRequested(t *testing.T) {
	var issuedGrant AccessGrant
	service, err := NewService(config.MCPOAuthConfig{
		Resource:  "https://cerebro.example/api/v1/mcp",
		AccessTTL: time.Minute,
		Clients: []config.MCPOAuthClient{{
			ClientID:       "panopticon",
			ClientSecret:   "client-secret",
			GrantTypes:     []string{"client_credentials"},
			AllowedTenants: []string{"writer"},
			Roles:          []string{"cerebro.connector_manager"},
		}},
	}, &replayRefreshStore{}, func(_ context.Context, grant AccessGrant, _ time.Duration, _ time.Time) (string, error) {
		issuedGrant = grant
		return "access-token", nil
	}, WithOIDCProvider(stubOIDCProvider{}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	_, err = service.Token(context.Background(), "Basic "+base64.StdEncoding.EncodeToString([]byte("panopticon:client-secret")), url.Values{
		"grant_type": {"client_credentials"},
		"resource":   {"https://cerebro.example/api/v1/mcp"},
		"scope":      {ScopeSecurityRead},
	})
	if err != nil {
		t.Fatalf("Token error = %v", err)
	}
	if len(issuedGrant.Roles) != 0 {
		t.Fatalf("explicit-scope token roles = %#v, want none so scope request narrows grant", issuedGrant.Roles)
	}
}

func TestClientCredentialsKeepsRolesWhenScopeDefaults(t *testing.T) {
	var issuedGrant AccessGrant
	service, err := NewService(config.MCPOAuthConfig{
		Resource:  "https://cerebro.example/api/v1/mcp",
		AccessTTL: time.Minute,
		Clients: []config.MCPOAuthClient{{
			ClientID:       "panopticon",
			ClientSecret:   "client-secret",
			GrantTypes:     []string{"client_credentials"},
			AllowedTenants: []string{"writer"},
			Roles:          []string{"cerebro.connector_manager"},
		}},
	}, &replayRefreshStore{}, func(_ context.Context, grant AccessGrant, _ time.Duration, _ time.Time) (string, error) {
		issuedGrant = grant
		return "access-token", nil
	}, WithOIDCProvider(stubOIDCProvider{}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	_, err = service.Token(context.Background(), "Basic "+base64.StdEncoding.EncodeToString([]byte("panopticon:client-secret")), url.Values{
		"grant_type": {"client_credentials"},
		"resource":   {"https://cerebro.example/api/v1/mcp"},
	})
	if err != nil {
		t.Fatalf("Token error = %v", err)
	}
	if len(issuedGrant.Roles) != 1 || issuedGrant.Roles[0] != "cerebro.connector_manager" {
		t.Fatalf("default-scope token roles = %#v, want connector manager role", issuedGrant.Roles)
	}
}

func TestRegisterClientEnforcesDynamicClientLimit(t *testing.T) {
	store := &limitedClientStore{err: ErrOAuthClientLimitExceeded}
	service, err := NewService(config.MCPOAuthConfig{
		Resource:                  "https://cerebro.example/api/v1/mcp",
		DynamicClientRegistration: true,
	}, store, func(context.Context, AccessGrant, time.Duration, time.Time) (string, error) {
		return "access-token", nil
	}, WithOIDCProvider(stubOIDCProvider{}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	_, err = service.RegisterClient(context.Background(), ClientRegistrationRequest{
		RedirectURIs: []string{"http://127.0.0.1:9876/callback"},
	})
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != "too_many_clients" || oauthErr.Status != statusTooManyRequests {
		t.Fatalf("RegisterClient limit error = %v, want too_many_clients 429", err)
	}
	if store.maxClients != maxDynamicOAuthClients {
		t.Fatalf("maxClients = %d, want %d", store.maxClients, maxDynamicOAuthClients)
	}
}

func TestEntitlementForIdentityScopesTenantGrant(t *testing.T) {
	service := &Service{cfg: config.MCPOAuthConfig{
		Entitlements: []config.MCPOAuthEntitlement{{
			Groups:         []string{"secops"},
			AllowedTenants: []string{"writer"},
			Scopes:         []string{ScopeSecurityRead},
		}},
	}}
	entitlement, err := service.entitlementForIdentity(identityForTest("user-1", []string{"secops"}), "droid", []string{ScopeSecurityRead}, false)
	if err != nil {
		t.Fatalf("entitlementForIdentity error = %v", err)
	}
	if got := entitlement.AllowedTenants; len(got) != 1 || got[0] != "writer" {
		t.Fatalf("AllowedTenants = %#v, want [writer]", got)
	}

	_, err = service.entitlementForIdentity(identityForTest("user-2", []string{"engineering"}), "droid", []string{ScopeSecurityRead}, false)
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != "access_denied" {
		t.Fatalf("missing entitlement error = %v, want access_denied", err)
	}
}

func TestEntitlementForIdentityRequiresVerifiedEmailClaim(t *testing.T) {
	service := &Service{cfg: config.MCPOAuthConfig{
		Entitlements: []config.MCPOAuthEntitlement{{
			Email:          "user@example.com",
			AllowedTenants: []string{"writer"},
			Scopes:         []string{ScopeSecurityRead},
		}},
	}}
	unverifiedEmail, ok := NewVerifiedEmail("user@example.com", false)
	if ok {
		t.Fatal("NewVerifiedEmail accepted an unverified email")
	}
	_, err := service.entitlementForIdentity(NewIdentity("user-1", unverifiedEmail, "", []string{"secops"}), "droid", []string{ScopeSecurityRead}, false)
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != "access_denied" {
		t.Fatalf("unverified email entitlement error = %v, want access_denied", err)
	}

	entitlement, err := service.entitlementForIdentity(verifiedIdentityForTest(t, "user-1", "user@example.com", "", []string{"secops"}), "droid", []string{ScopeSecurityRead}, false)
	if err != nil {
		t.Fatalf("verified email entitlement error = %v", err)
	}
	if got := entitlement.AllowedTenants; len(got) != 1 || got[0] != "writer" {
		t.Fatalf("AllowedTenants = %#v, want [writer]", got)
	}
}

func TestEntitlementForIdentitySubjectGrantDoesNotRequireVerifiedEmail(t *testing.T) {
	service := &Service{cfg: config.MCPOAuthConfig{
		Entitlements: []config.MCPOAuthEntitlement{{
			Subject:        "user-1",
			AllowedTenants: []string{"writer"},
			Scopes:         []string{ScopeSecurityRead},
		}},
	}}
	entitlement, err := service.entitlementForIdentity(identityForTest("user-1", []string{"secops"}), "droid", []string{ScopeSecurityRead}, false)
	if err != nil {
		t.Fatalf("subject entitlement error = %v", err)
	}
	if got := entitlement.AllowedTenants; len(got) != 1 || got[0] != "writer" {
		t.Fatalf("AllowedTenants = %#v, want [writer]", got)
	}
}

func TestAuthorizationCodeSubjectRequiresVerifiedEmail(t *testing.T) {
	cases := []struct {
		name     string
		identity Identity
		want     string
	}{
		{
			name:     "verified email keeps legacy email subject",
			identity: verifiedIdentityForTest(t, "user-1", "user@example.com", "", nil),
			want:     "user@example.com",
		},
		{
			name:     "unverified email uses oidc subject",
			identity: NewIdentity("user-1", VerifiedEmail{}, "", nil),
			want:     "user-1",
		},
		{
			name:     "missing email uses oidc subject",
			identity: identityForTest("user-1", nil),
			want:     "user-1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorizationCodeSubject(tc.identity); got != tc.want {
				t.Fatalf("authorizationCodeSubject() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuthorizationCodeFromLoginUsesVerifiedEmailBoundary(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	login := LoginState{
		ClientID:      "droid",
		RedirectURI:   "http://127.0.0.1/callback",
		Resource:      "https://cerebro.example/api/v1/mcp",
		CodeChallenge: "challenge",
	}
	entitlement := grantEntitlement{
		TenantID:       "writer",
		AllowedTenants: []string{"writer"},
		Scopes:         []string{ScopeSecurityRead},
		Roles:          []string{"cerebro.viewer"},
	}

	verifiedCode := authorizationCodeFromLogin(login, verifiedIdentityForTest(t, "user-1", "user@example.com", "", nil), entitlement, "code-token", now, time.Minute)
	if verifiedCode.Subject != "user@example.com" || verifiedCode.Email != "user@example.com" {
		t.Fatalf("verified authorization code subject/email = %q/%q, want verified email", verifiedCode.Subject, verifiedCode.Email)
	}

	unverifiedCode := authorizationCodeFromLogin(login, identityForTest("user-1", nil), entitlement, "code-token", now, time.Minute)
	if unverifiedCode.Subject != "user-1" || unverifiedCode.Email != "" {
		t.Fatalf("unverified authorization code subject/email = %q/%q, want subject only", unverifiedCode.Subject, unverifiedCode.Email)
	}
}

func TestEntitlementForIdentityDropsRolesWhenExplicitScopeRequested(t *testing.T) {
	service := &Service{cfg: config.MCPOAuthConfig{
		Entitlements: []config.MCPOAuthEntitlement{{
			Groups:         []string{"secops"},
			AllowedTenants: []string{"writer"},
			Scopes:         []string{ScopeSecurityRead},
			Roles:          []string{"cerebro.connector_manager"},
		}},
	}}

	narrowed, err := service.entitlementForIdentity(identityForTest("user-1", []string{"secops"}), "droid", []string{ScopeSecurityRead}, true)
	if err != nil {
		t.Fatalf("entitlementForIdentity explicit scope error = %v", err)
	}
	if len(narrowed.Roles) != 0 {
		t.Fatalf("explicit-scope entitlement roles = %#v, want none so scope request narrows grant", narrowed.Roles)
	}

	defaulted, err := service.entitlementForIdentity(identityForTest("user-1", []string{"secops"}), "droid", []string{ScopeSecurityRead}, false)
	if err != nil {
		t.Fatalf("entitlementForIdentity default scope error = %v", err)
	}
	if len(defaulted.Roles) != 1 || defaulted.Roles[0] != "cerebro.connector_manager" {
		t.Fatalf("default-scope entitlement roles = %#v, want connector manager role", defaulted.Roles)
	}
}

func TestCallbackRecordsOAuthIdentityDirectory(t *testing.T) {
	stateToken := "state-token"
	store := &directoryOAuthStore{
		login: LoginState{
			StateHash:     HashToken(stateToken),
			ClientID:      "droid",
			RedirectURI:   "http://127.0.0.1/callback",
			ClientState:   "client-state",
			Resource:      "https://cerebro.example/api/v1/mcp",
			Scopes:        []string{ScopeSecurityRead},
			CodeChallenge: "challenge",
			Nonce:         "nonce",
			ExpiresAt:     time.Now().Add(time.Minute),
		},
	}
	service, err := NewService(config.MCPOAuthConfig{
		Resource: "https://cerebro.example/api/v1/mcp",
		CodeTTL:  time.Minute,
		Upstream: config.MCPOAuthUpstreamConfig{
			Issuer:         "https://example.okta.com",
			SecurityGroups: []string{"security-team"},
		},
		Entitlements: []config.MCPOAuthEntitlement{{
			Groups:         []string{"security-team"},
			AllowedTenants: []string{"tenant-a"},
			Roles:          []string{"cerebro.viewer"},
			Scopes:         []string{ScopeSecurityRead},
		}},
	}, store, func(context.Context, AccessGrant, time.Duration, time.Time) (string, error) {
		return "access-token", nil
	}, WithOIDCProvider(staticOIDCProvider{identity: verifiedIdentityForTest(t, "00u123", "person@example.com", "Person Example", []string{"security-team"})}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	redirect, err := service.Callback(context.Background(), url.Values{"state": {stateToken}, "code": {"upstream-code"}})
	if err != nil {
		t.Fatalf("Callback error = %v", err)
	}
	if !strings.HasPrefix(redirect, "http://127.0.0.1/callback?") {
		t.Fatalf("redirect = %q", redirect)
	}
	if len(store.orgs) != 1 || store.orgs[0].TenantID != "tenant-a" || store.orgs[0].Provider != "okta" {
		t.Fatalf("recorded orgs = %+v", store.orgs)
	}
	if len(store.users) != 1 {
		t.Fatalf("recorded users = %+v", store.users)
	}
	user := store.users[0]
	if user.UserID != "00u123" || user.DisplayName != "Person Example" || user.Provider != "okta" || user.Source != "mcp_oauth" {
		t.Fatalf("recorded user = %+v", user)
	}
	if len(user.Roles) != 1 || user.Roles[0] != "cerebro.viewer" || len(user.Groups) != 1 || user.Groups[0] != "security-team" {
		t.Fatalf("recorded grants = roles %#v groups %#v", user.Roles, user.Groups)
	}
}

func TestCallbackContinuesWhenIdentityDirectoryRecordFails(t *testing.T) {
	stateToken := "state-token"
	store := &directoryOAuthStore{
		login: LoginState{
			StateHash:     HashToken(stateToken),
			ClientID:      "droid",
			RedirectURI:   "http://127.0.0.1/callback",
			ClientState:   "client-state",
			Resource:      "https://cerebro.example/api/v1/mcp",
			Scopes:        []string{ScopeSecurityRead},
			CodeChallenge: "challenge",
			Nonce:         "nonce",
			ExpiresAt:     time.Now().Add(time.Minute),
		},
		recordErr: errors.New("directory unavailable"),
	}
	service, err := NewService(config.MCPOAuthConfig{
		Resource: "https://cerebro.example/api/v1/mcp",
		CodeTTL:  time.Minute,
		Upstream: config.MCPOAuthUpstreamConfig{
			SecurityGroups: []string{"security-team"},
		},
		Entitlements: []config.MCPOAuthEntitlement{{
			Groups:         []string{"security-team"},
			AllowedTenants: []string{"tenant-a"},
			Roles:          []string{"cerebro.viewer"},
			Scopes:         []string{ScopeSecurityRead},
		}},
	}, store, func(context.Context, AccessGrant, time.Duration, time.Time) (string, error) {
		return "access-token", nil
	}, WithOIDCProvider(staticOIDCProvider{identity: verifiedIdentityForTest(t, "00u123", "person@example.com", "Person Example", []string{"security-team"})}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	redirect, err := service.Callback(context.Background(), url.Values{"state": {stateToken}, "code": {"upstream-code"}})
	if err != nil {
		t.Fatalf("Callback error = %v", err)
	}
	if !strings.HasPrefix(redirect, "http://127.0.0.1/callback?") {
		t.Fatalf("redirect = %q", redirect)
	}
	if store.code.CodeHash == ([32]byte{}) {
		t.Fatalf("authorization code was not saved")
	}
}

func TestOAuthProviderFromIssuerUsesHost(t *testing.T) {
	if got := oauthProviderFromIssuer("https://tenant.okta.com/oauth2/default"); got != "okta" {
		t.Fatalf("oauthProviderFromIssuer(okta issuer) = %q, want okta", got)
	}
	if got := oauthProviderFromIssuer("https://booktaku.example.com/oauth2/default"); got != "oidc" {
		t.Fatalf("oauthProviderFromIssuer(non-okta issuer) = %q, want oidc", got)
	}
}

func base16Lower(raw []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, b := range raw {
		out[i*2] = alphabet[b>>4]
		out[i*2+1] = alphabet[b&0x0f]
	}
	return string(out)
}

type replayRefreshStore struct {
	Store
	consumeRecord   RefreshToken
	consumeErr      error
	revokedFamilies []string
}

func (s *replayRefreshStore) ConsumeOAuthRefreshToken(context.Context, [32]byte, time.Time) (RefreshToken, error) {
	return s.consumeRecord, s.consumeErr
}

func (s *replayRefreshStore) RevokeOAuthRefreshFamily(_ context.Context, familyID string) error {
	s.revokedFamilies = append(s.revokedFamilies, familyID)
	return nil
}

type limitedClientStore struct {
	Store
	err        error
	maxClients int
}

func (s *limitedClientStore) SaveOAuthClientWithLimit(_ context.Context, _ OAuthClient, maxClients int) error {
	s.maxClients = maxClients
	return s.err
}

type directoryOAuthStore struct {
	Store
	login     LoginState
	code      AuthorizationCode
	orgs      []*ports.IdentityOrganization
	users     []*ports.IdentityUser
	recordErr error
}

func (s *directoryOAuthStore) ConsumeLoginState(_ context.Context, stateHash [32]byte, _ time.Time) (LoginState, error) {
	if stateHash != s.login.StateHash {
		return LoginState{}, ErrNotFound
	}
	return s.login, nil
}

func (s *directoryOAuthStore) SaveAuthorizationCode(_ context.Context, code AuthorizationCode) error {
	s.code = code
	return nil
}

func (s *directoryOAuthStore) UpsertIdentityOrganization(_ context.Context, org *ports.IdentityOrganization) error {
	if s.recordErr != nil {
		return s.recordErr
	}
	copied := *org
	s.orgs = append(s.orgs, &copied)
	return nil
}

func (s *directoryOAuthStore) UpsertIdentityUser(_ context.Context, user *ports.IdentityUser) error {
	if s.recordErr != nil {
		return s.recordErr
	}
	copied := *user
	copied.Roles = cloneStrings(user.Roles)
	copied.Groups = cloneStrings(user.Groups)
	s.users = append(s.users, &copied)
	return nil
}

type stubOIDCProvider struct{}

func (stubOIDCProvider) AuthorizationEndpoint(context.Context) (string, error) {
	return "https://sso.example/authorize", nil
}

func (stubOIDCProvider) ExchangeCode(context.Context, string, string) (Identity, error) {
	return Identity{}, nil
}

type staticOIDCProvider struct {
	identity Identity
}

func (staticOIDCProvider) AuthorizationEndpoint(context.Context) (string, error) {
	return "https://sso.example/authorize", nil
}

func (p staticOIDCProvider) ExchangeCode(context.Context, string, string) (Identity, error) {
	return p.identity, nil
}
