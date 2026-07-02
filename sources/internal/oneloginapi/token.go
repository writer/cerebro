package oneloginapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const tokenRefreshSkew = time.Minute

var runtimeTemplateKeys = []string{"subdomain", "client_id", "client_secret"}

// TokenCache caches OneLogin resource API access tokens until shortly before
// expiry. OneLogin's token endpoint uses Basic auth and a JSON grant body.
type TokenCache struct {
	mu      sync.Mutex
	entries map[string]tokenCacheEntry
}

type tokenCacheEntry struct {
	value     string
	expiresAt time.Time
}

// ResolveRuntimeConfig renders OneLogin runtime URLs and injects the documented
// resource Authorization header value into config for jsonapi.
func ResolveRuntimeConfig(ctx context.Context, cfg sourcecdk.Config, cache *TokenCache, allowLoopback bool) (sourcecdk.Config, error) {
	runtimeCfg, err := sourcecdk.ResolveBaseURLConfig(SourceID, DefaultBaseURLTemplate, cfg, runtimeTemplateKeys)
	if err != nil {
		return sourcecdk.Config{}, err
	}
	token, err := cache.Token(ctx, runtimeCfg, allowLoopback)
	if err != nil {
		return sourcecdk.Config{}, err
	}
	values := runtimeCfg.Values()
	values["token"] = token
	return sourcecdk.NewConfig(values), nil
}

// Token returns a cached OneLogin access token or exchanges the configured
// client credential pair for a new resource API token.
func (c *TokenCache) Token(ctx context.Context, cfg sourcecdk.Config, allowLoopback bool) (string, error) {
	if c == nil {
		return "", fmt.Errorf("%s token cache is required", SourceID)
	}
	tokenURL, err := tokenURLForConfig(cfg, allowLoopback)
	if err != nil {
		return "", err
	}
	clientID, err := sourcecdk.RequiredConfigValue(SourceID, cfg, "client_id")
	if err != nil {
		return "", err
	}
	clientSecret, err := sourcecdk.RequiredConfigValue(SourceID, cfg, "client_secret")
	if err != nil {
		return "", err
	}
	cacheKey := tokenCacheKey(tokenURL, clientID, clientSecret)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if cached, ok := c.entries[cacheKey]; ok && cached.value != "" && now.Before(cached.expiresAt) {
		return cached.value, nil
	}
	token, expiresAt, err := exchangeToken(ctx, tokenURL, clientID, clientSecret, allowLoopback)
	if err != nil {
		return "", err
	}
	if c.entries == nil {
		c.entries = map[string]tokenCacheEntry{}
	}
	c.entries[cacheKey] = tokenCacheEntry{value: token, expiresAt: expiresAt}
	return token, nil
}

func tokenURLForConfig(cfg sourcecdk.Config, allowLoopback bool) (string, error) {
	configured := sourcecdk.ConfigValue(cfg, "token_url")
	if configured != "" {
		if !providerManagedTokenURLOverrideAllowed(configured, allowLoopback) {
			return "", fmt.Errorf("%w: %s token_url is provider-managed and cannot be overridden", sourcecdk.ErrInvalidConfig, SourceID)
		}
		return normalizeTokenURL(configured, allowLoopback)
	}
	if subdomain := sourcecdk.ConfigValue(cfg, "subdomain"); subdomain != "" {
		rendered, err := sourcecdk.RenderConfigTemplate(SourceID, OAuthTokenURLTemplate, cfg, runtimeTemplateKeys)
		if err != nil {
			return "", err
		}
		return normalizeTokenURL(rendered, allowLoopback)
	}
	baseURL := sourcecdk.ConfigValue(cfg, "base_url")
	if baseURL == "" {
		return "", fmt.Errorf("%w: %s subdomain or base_url is required", sourcecdk.ErrInvalidConfig, SourceID)
	}
	base, _, err := sourcehttp.NormalizeBaseURLWithOptions(SourceID, baseURL, sourcehttp.URLValidationOptions{AllowLoopback: allowLoopback})
	if err != nil {
		return "", err
	}
	return normalizeTokenURL(base+"/auth/oauth2/v2/token", allowLoopback)
}

func normalizeTokenURL(raw string, allowLoopback bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse %s token_url: %w", SourceID, err)
	}
	if parsed == nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("%s token_url must include a host", SourceID)
	}
	loopbackHTTP := allowLoopback && parsed.Scheme == "http" && sourcehttp.IsLoopbackHost(parsed.Hostname())
	if parsed.Scheme != "https" && !loopbackHTTP {
		return "", fmt.Errorf("%s token_url must use https", SourceID)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("%s token_url must not include user info, query, or fragment", SourceID)
	}
	return parsed.String(), nil
}

func providerManagedTokenURLOverrideAllowed(raw string, allowLoopback bool) bool {
	if !allowLoopback {
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || strings.TrimSpace(parsed.Host) == "" {
		return false
	}
	return sourcehttp.IsLoopbackHost(parsed.Hostname())
}

func exchangeToken(ctx context.Context, tokenURL string, clientID string, clientSecret string, allowLoopback bool) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(`{"grant_type":"client_credentials"}`))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build %s token request: %w", SourceID, err)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := sourcehttp.DoWithRetry(ctx, sourcehttp.NewClient(sourcehttp.ClientOptions{
		SourceID:      SourceID,
		AllowLoopback: allowLoopback,
		Timeout:       10 * time.Second,
	}), req, sourcehttp.RetryOptions{})
	if err != nil {
		return "", time.Time{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", time.Time{}, &sourcecdk.HTTPStatusError{
			Code:    resp.StatusCode,
			Message: fmt.Sprintf("%s token endpoint returned HTTP %d", SourceID, resp.StatusCode),
		}
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		return "", time.Time{}, fmt.Errorf("decode %s token response: %w", SourceID, err)
	}
	token := strings.TrimSpace(payload.AccessToken)
	if token == "" {
		return "", time.Time{}, fmt.Errorf("%s token response missing access_token", SourceID)
	}
	expiresIn := payload.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 300
	}
	expiresAt := time.Now().Add(time.Duration(expiresIn)*time.Second - tokenRefreshSkew)
	if !expiresAt.After(time.Now()) {
		expiresAt = time.Now().Add(time.Minute)
	}
	return token, expiresAt, nil
}

func tokenCacheKey(tokenURL string, clientID string, clientSecret string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{SourceID, tokenURL, clientID, clientSecret}, "\x00")))
	return hex.EncodeToString(sum[:])
}
