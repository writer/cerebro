package sourcehttp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const githubAppTokenRefreshSkew = time.Minute

type GitHubAppAuthConfig struct {
	AppID            string
	InstallationID   string
	PrivateKey       string
	PrivateKeyBase64 string
	BaseURL          string
}

type githubAppTokenTransport struct {
	base           http.RoundTripper
	appID          string
	installationID string
	privateKey     *rsa.PrivateKey
	tokenURL       string

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

type githubAppInstallationTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type GitHubAppInstallationTokenHTTPError struct {
	StatusCode int
}

func (err *GitHubAppInstallationTokenHTTPError) Error() string {
	return fmt.Sprintf("github app installation token request returned HTTP %d", err.StatusCode)
}

func (err *GitHubAppInstallationTokenHTTPError) HTTPStatus() int {
	if err == nil {
		return 0
	}
	return err.StatusCode
}

func (cfg GitHubAppAuthConfig) Configured() bool {
	return cfg.AppID != "" && cfg.InstallationID != "" && (cfg.PrivateKey != "" || cfg.PrivateKeyBase64 != "")
}

func (cfg GitHubAppAuthConfig) Validate() error {
	appFields := 0
	for _, value := range []string{cfg.AppID, cfg.InstallationID, cfg.PrivateKey, cfg.PrivateKeyBase64} {
		if strings.TrimSpace(value) != "" {
			appFields++
		}
	}
	if appFields == 0 {
		return nil
	}
	if cfg.PrivateKey != "" && cfg.PrivateKeyBase64 != "" {
		return fmt.Errorf("github app private_key and private_key_base64 are mutually exclusive")
	}
	if cfg.AppID == "" || cfg.InstallationID == "" || (cfg.PrivateKey == "" && cfg.PrivateKeyBase64 == "") {
		return fmt.Errorf("github app auth requires app_id, installation_id, and private_key")
	}
	if _, err := strconv.ParseInt(cfg.AppID, 10, 64); err != nil {
		return fmt.Errorf("parse github app_id: %w", err)
	}
	if _, err := strconv.ParseInt(cfg.InstallationID, 10, 64); err != nil {
		return fmt.Errorf("parse github installation_id: %w", err)
	}
	return nil
}

func WithGitHubAppAuth(client *http.Client, cfg GitHubAppAuthConfig) (*http.Client, error) {
	key, err := parseGitHubAppPrivateKey(cfg)
	if err != nil {
		return nil, err
	}
	cloned := *client
	base := cloned.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	cloned.Transport = &githubAppTokenTransport{
		base:           base,
		appID:          cfg.AppID,
		installationID: cfg.InstallationID,
		privateKey:     key,
		tokenURL:       githubAppInstallationTokenURL(cfg.BaseURL, cfg.InstallationID),
	}
	return &cloned, nil
}

func (rt *githubAppTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := rt.installationToken(req.Context())
	if err != nil {
		return nil, err
	}
	cloned := req.Clone(req.Context())
	cloned.Header = req.Header.Clone()
	cloned.Header.Set("Authorization", "Bearer "+token)
	return rt.base.RoundTrip(cloned)
}

func (rt *githubAppTokenTransport) installationToken(ctx context.Context) (string, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.token != "" && time.Until(rt.expiresAt) > githubAppTokenRefreshSkew {
		return rt.token, nil
	}
	jwt, err := signGitHubAppJWT(rt.appID, rt.privateKey, time.Now)
	if err != nil {
		return "", err
	}
	// #nosec G704 -- tokenURL is derived from NormalizeGitHubBaseURL output plus GitHub's fixed app-token path.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rt.tokenURL, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return "", fmt.Errorf("build github app installation token request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		return "", fmt.Errorf("github app installation token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &GitHubAppInstallationTokenHTTPError{StatusCode: resp.StatusCode}
	}
	if readErr != nil {
		return "", fmt.Errorf("read github app installation token response: %w", readErr)
	}
	var parsed githubAppInstallationTokenResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("decode github app installation token response: %w", err)
	}
	if strings.TrimSpace(parsed.Token) == "" {
		return "", fmt.Errorf("github app installation token response did not include token")
	}
	rt.token = parsed.Token
	rt.expiresAt = parsed.ExpiresAt
	if rt.expiresAt.IsZero() {
		rt.expiresAt = time.Now().Add(time.Hour)
	}
	return rt.token, nil
}

func githubAppInstallationTokenURL(baseURL string, installationID string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = "https://api.github.com"
	} else if parsed, err := url.Parse(base); err == nil && strings.TrimRight(parsed.EscapedPath(), "/") == "" && !IsGitHubAPIHost(parsed.Hostname()) {
		base += "/api/v3"
	}
	return fmt.Sprintf("%s/app/installations/%s/access_tokens", base, installationID)
}

func signGitHubAppJWT(appID string, privateKey *rsa.PrivateKey, now func() time.Time) (string, error) {
	if now == nil {
		now = time.Now
	}
	issuedAt := now().Add(-time.Minute).Unix()
	expiresAt := now().Add(9 * time.Minute).Unix()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iat": issuedAt,
		"exp": expiresAt,
		"iss": appID,
	})
	if err != nil {
		return "", fmt.Errorf("marshal github app jwt claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(claims)
	unsigned := header + "." + payload
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign github app jwt: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func parseGitHubAppPrivateKey(cfg GitHubAppAuthConfig) (*rsa.PrivateKey, error) {
	raw := strings.TrimSpace(cfg.PrivateKey)
	if raw == "" && strings.TrimSpace(cfg.PrivateKeyBase64) != "" {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.PrivateKeyBase64))
		if err != nil {
			return nil, fmt.Errorf("decode github app private_key_base64: %w", err)
		}
		raw = string(decoded)
	}
	raw = strings.ReplaceAll(raw, `\n`, "\n")
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("github app private key must be PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse github app private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("github app private key must be RSA")
	}
	return key, nil
}
