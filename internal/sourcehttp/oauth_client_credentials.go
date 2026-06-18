package sourcehttp

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
)

// ClientCredentialsOptions describes a generic OAuth 2.0 client-credentials exchange.
type ClientCredentialsOptions struct {
	SourceID         string
	TokenURLTemplate string
	TemplateKeys     []string
	Scopes           []string
	ScopeSeparator   string
	TokenParams      map[string]string
	ExpirationBuffer time.Duration
	AllowLoopback    bool
	Timeout          time.Duration
}

// ClientCredentialsCache caches access tokens until shortly before expiry.
type ClientCredentialsCache struct {
	mu      sync.Mutex
	entries map[string]clientCredentialsCacheEntry
}

type clientCredentialsCacheEntry struct {
	value     string
	expiresAt time.Time
}

// Token returns a cached bearer token or exchanges client_id/client_secret for a new one.
func (c *ClientCredentialsCache) Token(ctx context.Context, cfg sourcecdk.Config, options ClientCredentialsOptions) (string, error) {
	if c == nil {
		return "", fmt.Errorf("%s oauth token cache is required", sourceID(options.SourceID))
	}
	configuredTokenURL := configValue(cfg, "token_url")
	if strings.TrimSpace(configuredTokenURL) != "" && strings.TrimSpace(options.TokenURLTemplate) != "" && !providerManagedTokenURLOverrideAllowed(configuredTokenURL, options.AllowLoopback) {
		return "", fmt.Errorf("%w: %s token_url is provider-managed and cannot be overridden", sourcecdk.ErrInvalidConfig, sourceID(options.SourceID))
	}
	tokenURL, err := renderTemplate(firstNonEmpty(configuredTokenURL, options.TokenURLTemplate), cfg, options)
	if err != nil {
		return "", err
	}
	tokenURL, err = normalizeOAuthURL(tokenURL, options)
	if err != nil {
		return "", err
	}
	clientID, err := requiredConfigValue(cfg, "client_id", options)
	if err != nil {
		return "", err
	}
	clientSecret, err := requiredConfigValue(cfg, "client_secret", options)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {clientSecret}}
	if scope := strings.Join(options.Scopes, firstNonEmpty(options.ScopeSeparator, " ")); strings.TrimSpace(scope) != "" {
		form.Set("scope", scope)
	}
	for key, template := range options.TokenParams {
		value, err := renderTemplate(template, cfg, options)
		if err != nil {
			return "", err
		}
		form.Set(key, value)
	}
	cacheKey := clientCredentialsCacheKey(sourceID(options.SourceID), tokenURL, form)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if cached, ok := c.entries[cacheKey]; ok && cached.value != "" && now.Before(cached.expiresAt) {
		return cached.value, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build %s token request: %w", sourceID(options.SourceID), err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := DoWithRetry(ctx, NewClient(ClientOptions{
		SourceID:      sourceID(options.SourceID),
		AllowLoopback: options.AllowLoopback,
		Timeout:       firstNonZeroDuration(options.Timeout, 10*time.Second),
	}), req, RetryOptions{})
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s token endpoint returned HTTP %d", sourceID(options.SourceID), resp.StatusCode)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		return "", fmt.Errorf("decode %s token response: %w", sourceID(options.SourceID), err)
	}
	token := strings.TrimSpace(payload.AccessToken)
	if token == "" {
		return "", fmt.Errorf("%s token response missing access_token", sourceID(options.SourceID))
	}
	expiresIn := payload.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 300
	}
	entry := clientCredentialsCacheEntry{
		value:     token,
		expiresAt: now.Add(time.Duration(expiresIn)*time.Second - firstNonZeroDuration(options.ExpirationBuffer, time.Minute)),
	}
	if !entry.expiresAt.After(now) {
		entry.expiresAt = now.Add(time.Minute)
	}
	if c.entries == nil {
		c.entries = make(map[string]clientCredentialsCacheEntry)
	}
	c.entries[cacheKey] = entry
	return entry.value, nil
}

func providerManagedTokenURLOverrideAllowed(raw string, allowLoopback bool) bool {
	if !allowLoopback {
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || strings.TrimSpace(parsed.Host) == "" {
		return false
	}
	return IsLoopbackHost(parsed.Hostname())
}

func clientCredentialsCacheKey(sourceID string, tokenURL string, form url.Values) string {
	material := strings.Join([]string{sourceID, tokenURL, form.Encode()}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func renderTemplate(template string, cfg sourcecdk.Config, options ClientCredentialsOptions) (string, error) {
	rendered := strings.TrimSpace(template)
	for _, key := range options.TemplateKeys {
		for _, prefix := range []string{"config", "credential", "connection"} {
			placeholder := "${" + prefix + "." + key + "}"
			if !strings.Contains(rendered, placeholder) {
				continue
			}
			value, err := requiredConfigValue(cfg, key, options)
			if err != nil {
				return "", err
			}
			rendered = strings.ReplaceAll(rendered, placeholder, value)
		}
	}
	if strings.Contains(rendered, "${") {
		return "", fmt.Errorf("%w: %s template %q contains unresolved variable", sourcecdk.ErrInvalidConfig, sourceID(options.SourceID), template)
	}
	return rendered, nil
}

func normalizeOAuthURL(raw string, options ClientCredentialsOptions) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse %s token_url: %w", sourceID(options.SourceID), err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("%w: %s token_url must be absolute", sourcecdk.ErrInvalidConfig, sourceID(options.SourceID))
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: %s token_url must not include user info, query, or fragment", sourcecdk.ErrInvalidConfig, sourceID(options.SourceID))
	}
	baseURL, _, err := NormalizeBaseURL(sourceID(options.SourceID), parsed.Scheme+"://"+parsed.Host, options.AllowLoopback)
	if err != nil {
		return "", err
	}
	path := parsed.EscapedPath()
	if strings.TrimSpace(path) == "" {
		path = "/"
	}
	return baseURL + path, nil
}

func requiredConfigValue(cfg sourcecdk.Config, key string, options ClientCredentialsOptions) (string, error) {
	value := strings.TrimSpace(configValue(cfg, key))
	if value == "" {
		return "", fmt.Errorf("%w: %s %s is required", sourcecdk.ErrInvalidConfig, sourceID(options.SourceID), key)
	}
	return value, nil
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return value
}

func sourceID(value string) string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return trimmed
	}
	return "source"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstNonZeroDuration(values ...time.Duration) time.Duration {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
