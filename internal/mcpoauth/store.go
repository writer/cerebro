package mcpoauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"
)

const ScopeSecurityRead = "cerebro.cosmo.security.read"

// Store persists OAuth state. Implementations must consume states, codes, and
// refresh tokens atomically to prevent replay.
type Store interface {
	SaveOAuthClient(ctx context.Context, client OAuthClient) error
	GetOAuthClient(ctx context.Context, clientID string) (OAuthClient, error)
	SaveLoginState(ctx context.Context, state LoginState) error
	ConsumeLoginState(ctx context.Context, stateHash [32]byte, now time.Time) (LoginState, error)
	SaveAuthorizationCode(ctx context.Context, code AuthorizationCode) error
	ConsumeAuthorizationCode(ctx context.Context, codeHash [32]byte, now time.Time) (AuthorizationCode, error)
	SaveOAuthRefreshToken(ctx context.Context, token RefreshToken) error
	ConsumeOAuthRefreshToken(ctx context.Context, tokenHash [32]byte, now time.Time) (RefreshToken, error)
	RevokeOAuthRefreshFamily(ctx context.Context, familyID string) error
	RevokeOAuthRefreshToken(ctx context.Context, tokenHash [32]byte, clientID string) error
}

// OAuthClient is a dynamically registered MCP OAuth client.
type OAuthClient struct {
	ClientID     string
	ClientSecret string
	Name         string
	RedirectURIs []string
	Public       bool
	CreatedAt    time.Time
}

// LoginState tracks Cerebro's upstream OIDC redirect state for one pending
// downstream OAuth authorization request.
type LoginState struct {
	StateHash      [32]byte
	ClientID       string
	RedirectURI    string
	ClientState    string
	Resource       string
	Scopes         []string
	ScopesExplicit bool
	CodeChallenge  string
	Nonce          string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// AuthorizationCode is a single-use code issued by Cerebro to the MCP client
// after upstream OIDC login succeeds.
type AuthorizationCode struct {
	CodeHash       [32]byte
	ClientID       string
	RedirectURI    string
	Resource       string
	Subject        string
	Email          string
	TenantID       string
	AllowedTenants []string
	Scopes         []string
	Roles          []string
	Groups         []string
	CodeChallenge  string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// RefreshToken tracks a single-use refresh token lineage.
type RefreshToken struct {
	TokenHash      [32]byte
	ClientID       string
	Resource       string
	Subject        string
	Email          string
	TenantID       string
	AllowedTenants []string
	Scopes         []string
	Roles          []string
	Groups         []string
	FamilyID       string
	Generation     int
	CreatedAt      time.Time
	ExpiresAt      time.Time
	FamilyRevoked  bool
}

var (
	ErrNotFound                 = errors.New("mcpoauth: token not found")
	ErrExpired                  = errors.New("mcpoauth: token expired")
	ErrConsumed                 = errors.New("mcpoauth: token already consumed")
	ErrReplay                   = errors.New("mcpoauth: refresh token replay detected")
	ErrOAuthClientLimitExceeded = errors.New("mcpoauth: oauth client registration limit exceeded")
)

func HashToken(token string) [32]byte {
	return sha256.Sum256([]byte(strings.TrimSpace(token)))
}
