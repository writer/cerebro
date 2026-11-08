package vulnview

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	httpTimeout           = 30 * time.Second
	maxBodyBytes          = 8 << 20
	tokenExpirationLeeway = time.Minute
	defaultTokenTTL       = time.Hour
)

// responseMessageKeys lists the JSON object keys, in priority order, that
// VulnView's API and token endpoints use to carry a human-readable error
// message.
var responseMessageKeys = []string{"message", "error_description", "error", "detail"}

func isSupportedFamily(family string) bool {
	switch family {
	case familySite, familyScan, familyVulnerability, familyAsset, familyDNSAlert, familyCloudIdentityFinding, familyCloudIdentityAssessment:
		return true
	default:
		return false
	}
}

func supportedFamilies() []string {
	return []string{familySite, familyScan, familyVulnerability, familyAsset, familyDNSAlert, familyCloudIdentityFinding, familyCloudIdentityAssessment}
}

func (s *Source) getJSON(ctx context.Context, settings settings, requestPath string, query url.Values, target any) error {
	token, err := s.token(ctx, settings)
	if err != nil {
		return err
	}
	err = s.getJSONWithToken(ctx, settings, requestPath, query, token, target)
	if err != nil && sourcecdk.IsHTTPStatus(err, http.StatusUnauthorized) {
		s.tokenCache.Invalidate(tokenCacheKey(settings))
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
	resp, err := s.httpClient().Do(req)
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
		return sourcecdk.DecodeAPIError("VulnView API", resp.StatusCode, body, http.StatusText(resp.StatusCode), responseMessageKeys...)
	}
	if target == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return nil
}

// token returns a cached bearer token for settings, fetching a new one
// through fetchToken when absent or near expiry.
func (s *Source) token(ctx context.Context, settings settings) (string, error) {
	token, err := s.tokenCache.Token(ctx, tokenCacheKey(settings), func(ctx context.Context) (sourcecdk.OAuthToken, error) {
		return s.fetchToken(ctx, settings)
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func tokenCacheKey(settings settings) string {
	return strings.Join([]string{
		settings.baseURL,
		settings.tokenURL,
		settings.clientID,
		settings.scope,
		sourcecdk.HashSecret(settings.clientSecret),
	}, "\x00")
}

func (s *Source) fetchToken(ctx context.Context, settings settings) (sourcecdk.OAuthToken, error) {
	form := sourcecdk.ClientCredentialsForm(settings.clientID, settings.clientSecret, settings.scope)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return sourcecdk.OAuthToken{}, fmt.Errorf("build VulnView token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return sourcecdk.OAuthToken{}, fmt.Errorf("request VulnView token: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxBodyBytes)
	if err != nil {
		return sourcecdk.OAuthToken{}, fmt.Errorf("read VulnView token response: %w", err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return sourcecdk.OAuthToken{}, sourcecdk.DecodeAPIError("VulnView token endpoint", resp.StatusCode, body, http.StatusText(resp.StatusCode), responseMessageKeys...)
	}
	return sourcecdk.DecodeOAuthTokenResponse("VulnView", body, time.Now().UTC(), defaultTokenTTL)
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
