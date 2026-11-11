package sourcecdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuthToken is a bearer access token together with its absolute expiry.
type OAuthToken struct {
	Value     string
	ExpiresAt time.Time
}

// OAuthTokenFetcher exchanges credentials for a fresh bearer token. A source
// implements this by sending an OAuth2 client_credentials POST through the
// Source CDK's HTTP boundary (internal/sourcehttp) and decoding the response
// with DecodeOAuthTokenResponse; OAuthTokenCache owns only the caching,
// leeway, and invalidation around that call, not the request itself, so the
// CDK stays free of a net/http dependency.
type OAuthTokenFetcher func(ctx context.Context) (OAuthToken, error)

// OAuthTokenCache caches one bearer token per cache key until shortly before
// expiry, calling a source-supplied OAuthTokenFetcher to obtain or refresh
// it. It generalizes the client-credentials caching, locking, expiry leeway,
// and 401-triggered invalidation that a Standard-tier source would otherwise
// hand-roll per provider.
type OAuthTokenCache struct {
	leeway time.Duration

	mu      sync.Mutex
	entries map[string]OAuthToken
}

// NewOAuthTokenCache constructs a cache that treats a token as due for
// refresh leeway before its advertised expiry, so a request built with a
// cached token does not race the provider's own clock skew.
func NewOAuthTokenCache(leeway time.Duration) *OAuthTokenCache {
	return &OAuthTokenCache{leeway: leeway}
}

// Token returns the cached bearer token for key, calling fetch to obtain and
// cache a new one when no cached entry exists or the cached entry is within
// leeway of expiry.
func (c *OAuthTokenCache) Token(ctx context.Context, key string, fetch OAuthTokenFetcher) (string, error) {
	if c == nil {
		return "", fmt.Errorf("oauth token cache is required")
	}
	now := time.Now().UTC()
	c.mu.Lock()
	if cached, ok := c.entries[key]; ok && cached.Value != "" && now.Add(c.leeway).Before(cached.ExpiresAt) {
		token := cached.Value
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()
	token, err := fetch(ctx)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	if c.entries == nil {
		c.entries = make(map[string]OAuthToken)
	}
	c.entries[key] = token
	c.mu.Unlock()
	return token.Value, nil
}

// Invalidate discards the cached token for key, if any, so the next Token
// call fetches a fresh one. Sources call this after a bearer-authenticated
// request is rejected as unauthorized, so a revoked or rotated token is
// retried exactly once rather than reused until its advertised expiry.
func (c *OAuthTokenCache) Invalidate(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// DecodeOAuthTokenResponse parses a standard OAuth2 client-credentials token
// response body (access_token, expires_in, token_type) into a bearer token
// and its absolute expiry. label names the provider in returned errors
// (e.g. "VulnView"). defaultTTL is used when expires_in is absent or
// non-positive. A token_type other than "Bearer" (case-insensitive) is
// rejected, matching providers that otherwise issue non-bearer credentials
// through the same endpoint shape.
func DecodeOAuthTokenResponse(label string, body []byte, now time.Time, defaultTTL time.Duration) (OAuthToken, error) {
	var decoded struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return OAuthToken{}, fmt.Errorf("decode %s token response: %w", label, err)
	}
	if strings.TrimSpace(decoded.AccessToken) == "" {
		return OAuthToken{}, fmt.Errorf("%s token endpoint returned empty access_token", label)
	}
	if decoded.TokenType != "" && !strings.EqualFold(decoded.TokenType, "Bearer") {
		return OAuthToken{}, fmt.Errorf("%s token endpoint returned unsupported token_type %q", label, decoded.TokenType)
	}
	expiresIn := decoded.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = int(defaultTTL.Seconds())
	}
	return OAuthToken{Value: decoded.AccessToken, ExpiresAt: now.Add(time.Duration(expiresIn) * time.Second)}, nil
}

// ClientCredentialsForm builds the url.Values body for an OAuth2
// client_credentials grant.
func ClientCredentialsForm(clientID, clientSecret, scope string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	if strings.TrimSpace(scope) != "" {
		form.Set("scope", scope)
	}
	return form
}

// HashSecret returns a hex-encoded SHA-256 digest of value, for use as one
// component of a token cache key so a credential secret is never retained in
// plain text in an in-memory cache key.
func HashSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
