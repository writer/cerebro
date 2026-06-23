package vulnview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	httpTimeout        = 30 * time.Second
	maxBodyBytes       = 8 << 20
	tokenRefreshLeeway = time.Minute
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func isSupportedFamily(family string) bool {
	switch family {
	case familySite, familyScan, familyVulnerability, familyAsset, familyDNSAlert:
		return true
	default:
		return false
	}
}

func supportedFamilies() []string {
	return []string{familySite, familyScan, familyVulnerability, familyAsset, familyDNSAlert}
}

func (s *Source) getJSON(ctx context.Context, settings settings, requestPath string, query url.Values, target any) error {
	token, err := s.token(ctx, settings)
	if err != nil {
		return err
	}
	err = s.getJSONWithToken(ctx, settings, requestPath, query, token, target)
	if err != nil && isUnauthorizedResponse(err) {
		s.invalidateToken(settings)
		token, tokenErr := s.token(ctx, settings)
		if tokenErr != nil {
			return tokenErr
		}
		err = s.getJSONWithToken(ctx, settings, requestPath, query, token, target)
	}
	return err
}

func (s *Source) getJSONWithToken(ctx context.Context, settings settings, requestPath string, query url.Values, token string, target any) error {
	endpoint := settings.baseURL + requestPath
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build request %s: %w", requestPath, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := s.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", requestPath, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxBodyBytes)
	if err != nil {
		return fmt.Errorf("read %s response: %w", requestPath, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return decodeResponseError("VulnView API", resp.StatusCode, body)
	}
	if target == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return nil
}

func (s *Source) token(ctx context.Context, settings settings) (string, error) {
	key := tokenCacheKey(settings)
	now := time.Now().UTC()
	s.mu.Lock()
	if key == s.tokenKey && s.accessToken != "" && now.Add(tokenRefreshLeeway).Before(s.tokenExpiresAt) {
		token := s.accessToken
		s.mu.Unlock()
		return token, nil
	}
	s.mu.Unlock()
	token, expiresAt, err := s.fetchToken(ctx, settings)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.tokenKey = key
	s.accessToken = token
	s.tokenExpiresAt = expiresAt
	s.mu.Unlock()
	return token, nil
}

func (s *Source) invalidateToken(settings settings) {
	key := tokenCacheKey(settings)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenKey == key {
		s.tokenKey = ""
		s.accessToken = ""
		s.tokenExpiresAt = time.Time{}
	}
}

func tokenCacheKey(settings settings) string {
	return strings.Join([]string{
		settings.baseURL,
		settings.tokenURL,
		settings.clientID,
		settings.scope,
		hashValue(settings.clientSecret),
	}, "\x00")
}

func hashValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *Source) fetchToken(ctx context.Context, settings settings) (string, time.Time, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", settings.scope)
	form.Set("client_id", settings.clientID)
	form.Set("client_secret", settings.clientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build VulnView token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := s.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("request VulnView token: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxBodyBytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read VulnView token response: %w", err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return "", time.Time{}, decodeResponseError("VulnView token endpoint", resp.StatusCode, body)
	}
	var decoded tokenResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", time.Time{}, fmt.Errorf("decode VulnView token response: %w", err)
	}
	if decoded.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("VulnView token endpoint returned empty access_token")
	}
	if decoded.TokenType != "" && !strings.EqualFold(decoded.TokenType, "Bearer") {
		return "", time.Time{}, fmt.Errorf("VulnView token endpoint returned unsupported token_type %q", decoded.TokenType)
	}
	expiresIn := decoded.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	return decoded.AccessToken, time.Now().UTC().Add(time.Duration(expiresIn) * time.Second), nil
}

func (s *Source) httpClient() *http.Client {
	var client *http.Client
	allowLoopback := false
	if s != nil {
		client = s.client
		allowLoopback = s.allowLoopbackBaseURL
	}
	return sourcehttp.HardenClient(client, sourcehttp.ClientOptions{
		SourceID:      "vulnview",
		Timeout:       httpTimeout,
		AllowLoopback: allowLoopback,
		LookupIPAddrs: lookupIPAddrs(s),
	})
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

func decodeResponseError(service string, statusCode int, body []byte) error {
	message := strings.TrimSpace(string(body))
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		for _, key := range []string{"message", "error_description", "error", "detail"} {
			if value := valueString(payload[key]); value != "" {
				message = value
				break
			}
		}
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	return &responseError{statusCode: statusCode, message: fmt.Sprintf("%s returned %d: %s", service, statusCode, message)}
}

func isUnauthorizedResponse(err error) bool {
	var responseErr *responseError
	return errors.As(err, &responseErr) && responseErr.statusCode == http.StatusUnauthorized
}
