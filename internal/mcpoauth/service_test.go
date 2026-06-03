package mcpoauth

import (
	"context"
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

type stubOIDCProvider struct{}

func (stubOIDCProvider) AuthorizationEndpoint(context.Context) (string, error) {
	return "https://sso.example/authorize", nil
}

func (stubOIDCProvider) ExchangeCode(context.Context, string, string) (Identity, error) {
	return Identity{}, nil
}
