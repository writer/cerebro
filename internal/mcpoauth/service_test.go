package mcpoauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
)

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
	entitlement, err := service.entitlementForIdentity(Identity{
		Subject: "user-1",
		Email:   "user@example.com",
		Groups:  []string{"secops"},
	}, "droid", []string{ScopeSecurityRead})
	if err != nil {
		t.Fatalf("entitlementForIdentity error = %v", err)
	}
	if got := entitlement.AllowedTenants; len(got) != 1 || got[0] != "writer" {
		t.Fatalf("AllowedTenants = %#v, want [writer]", got)
	}

	_, err = service.entitlementForIdentity(Identity{
		Subject: "user-2",
		Groups:  []string{"engineering"},
	}, "droid", []string{ScopeSecurityRead})
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != "access_denied" {
		t.Fatalf("missing entitlement error = %v, want access_denied", err)
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

type stubOIDCProvider struct{}

func (stubOIDCProvider) AuthorizationEndpoint(context.Context) (string, error) {
	return "https://sso.example/authorize", nil
}

func (stubOIDCProvider) ExchangeCode(context.Context, string, string) (Identity, error) {
	return Identity{}, nil
}
