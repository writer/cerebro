package grc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
)

var defaultTokenRetryBackoffs = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (s *Source) token(ctx context.Context, settings settings) (string, error) {
	cacheKey := tokenCacheKey(settings)
	now := time.Now()
	s.mu.Lock()
	if s.tokenKey == cacheKey && s.accessToken != "" && now.Add(tokenRefreshLeeway).Before(s.tokenExpiresAt) {
		token := s.accessToken
		s.mu.Unlock()
		return token, nil
	}
	s.mu.Unlock()

	body, err := json.Marshal(map[string]string{
		"client_id":     settings.clientID,
		"client_secret": settings.clientSecret,
		"scope":         settings.scope,
		"grant_type":    "client_credentials",
	})
	if err != nil {
		return "", fmt.Errorf("marshal grc token request: %w", err)
	}

	var response tokenResponse
	backoffs := s.tokenBackoffs()
	for attempt := 0; ; attempt++ {
		response, err = s.requestToken(ctx, settings, body)
		if err == nil {
			break
		}
		if !sourcecdk.IsRetryableHTTPStatus(err) || attempt >= len(backoffs) {
			return "", fmt.Errorf("request grc token: %w", err)
		}
		if sleepErr := sourcecdk.SleepContext(ctx, backoffs[attempt]); sleepErr != nil {
			return "", fmt.Errorf("request grc token retry: %w", sleepErr)
		}
	}
	if strings.TrimSpace(response.AccessToken) == "" {
		return "", fmt.Errorf("grc token response missing access_token")
	}
	expiresIn := response.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	s.mu.Lock()
	s.tokenKey = cacheKey
	s.accessToken = response.AccessToken
	s.tokenExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	s.mu.Unlock()
	return response.AccessToken, nil
}

func (s *Source) requestToken(ctx context.Context, settings settings, body []byte) (tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.tokenURL, bytes.NewReader(body))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("build grc token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	var response tokenResponse
	if err := s.doJSON(req, &response); err != nil {
		return tokenResponse{}, err
	}
	return response, nil
}

func (s *Source) tokenBackoffs() []time.Duration {
	if s != nil && s.tokenRetryBackoffs != nil {
		return s.tokenRetryBackoffs
	}
	return defaultTokenRetryBackoffs
}

func (s *Source) invalidateToken(settings settings) {
	if s == nil {
		return
	}
	cacheKey := tokenCacheKey(settings)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenKey != cacheKey {
		return
	}
	s.accessToken = ""
	s.tokenExpiresAt = time.Time{}
}

func tokenCacheKey(settings settings) string {
	secretHash := sha256.Sum256([]byte(settings.clientSecret))
	return strings.Join([]string{
		settings.provider,
		settings.tenantID,
		settings.baseURL,
		settings.tokenURL,
		settings.clientID,
		settings.scope,
		hex.EncodeToString(secretHash[:]),
	}, "\x00")
}
