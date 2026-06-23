package jsonapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- Duo Admin API HMAC auth requires HMAC-SHA1.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcehttp"
)

type cachedOAuthToken struct {
	accessToken string
	tokenType   string
	expiresAt   time.Time
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

func (s *Source) authorizeRequest(ctx context.Context, settings settings, req *http.Request) error {
	authModel := settings.authModel
	if authModel == "" {
		authModel = "legacy_token"
	}
	switch authModel {
	case "none":
		return nil
	case "legacy_token":
		return setTokenHeader(req, firstNonEmpty(s.options.TokenHeader, "Authorization"), firstNonEmpty(s.options.TokenScheme, "Bearer"), settings.token, s.options.SourceID)
	case "bearer_token":
		return setTokenHeader(req, "Authorization", "Bearer", settings.token, s.options.SourceID)
	case "api_key", "api_token":
		return setTokenHeader(req, firstNonEmpty(s.options.TokenHeader, "Authorization"), firstNonEmpty(s.options.TokenScheme, "Token"), settings.token, s.options.SourceID)
	case "basic":
		if settings.username != "" || settings.password != "" {
			if settings.username == "" || settings.password == "" {
				return fmt.Errorf("%s username and password are required for basic auth", s.options.SourceID)
			}
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(settings.username+":"+settings.password)))
			return nil
		}
		return setTokenHeader(req, "Authorization", "Basic", settings.token, s.options.SourceID)
	case "duo_hmac":
		return setDuoHMACAuth(req, settings, s.options.SourceID)
	case "oauth_client_credentials":
		token := settings.token
		if token == "" {
			var err error
			token, err = s.oauthAccessToken(ctx, settings, "client_credentials")
			if err != nil {
				return err
			}
		}
		return setTokenHeader(req, "Authorization", "Bearer", token, s.options.SourceID)
	case "oauth_authorization_code":
		token := settings.token
		if token == "" && settings.refreshToken != "" {
			var err error
			token, err = s.oauthAccessToken(ctx, settings, "refresh_token")
			if err != nil {
				return err
			}
		}
		return setTokenHeader(req, "Authorization", "Bearer", token, s.options.SourceID)
	case "jwt":
		return setTokenHeader(req, "Authorization", "Bearer", settings.token, s.options.SourceID)
	case "signature":
		return setTokenHeader(req, "Authorization", firstNonEmpty(s.options.TokenScheme, "Signature"), settings.token, s.options.SourceID)
	case "aws_sigv4":
		return s.setAWSSigV4Auth(ctx, req, settings)
	case "two_step":
		token, err := s.twoStepAccessToken(ctx, settings)
		if err != nil {
			return err
		}
		return setTokenHeader(req, "Authorization", "Bearer", token, s.options.SourceID)
	default:
		return fmt.Errorf("%s auth model %q is not supported by jsonapi", s.options.SourceID, authModel)
	}
}

func setDuoHMACAuth(req *http.Request, settings settings, sourceID string) error {
	integrationKey := firstNonEmpty(settings.clientID, settings.username)
	secretKey := firstNonEmpty(settings.clientSecret, settings.password)
	if integrationKey == "" || secretKey == "" {
		return fmt.Errorf("%s client_id and client_secret are required for Duo HMAC auth", sourceID)
	}
	date := time.Now().UTC().Format(time.RFC1123Z)
	req.Header.Set("Date", date)
	canonical := strings.Join([]string{
		date,
		strings.ToUpper(req.Method),
		strings.ToLower(req.URL.Host),
		req.URL.EscapedPath(),
		req.URL.Query().Encode(),
	}, "\n")
	mac := hmac.New(sha1.New, []byte(secretKey))
	_, _ = mac.Write([]byte(canonical))
	signature := hex.EncodeToString(mac.Sum(nil))
	req.SetBasicAuth(integrationKey, signature)
	return nil
}

// setAWSSigV4Auth signs the request with AWS Signature Version 4.
// It uses access_key/secret_key from config (mapped to clientID/clientSecret)
// and derives region and service from the request URL host or config values.
func (s *Source) setAWSSigV4Auth(_ context.Context, req *http.Request, settings settings) error {
	accessKey := firstNonEmpty(settings.clientID, settings.username)
	secretKey := firstNonEmpty(settings.clientSecret, settings.password)
	if accessKey == "" || secretKey == "" {
		return fmt.Errorf("%s access_key and secret_key are required for aws_sigv4 auth", s.options.SourceID)
	}
	region := firstNonEmpty(settings.region, "us-east-1")
	service := firstNonEmpty(settings.service, "execute-api")

	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)

	// Build canonical request.
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	sortedQuery := make([]string, 0, len(req.URL.Query()))
	for k, vs := range req.URL.Query() {
		for _, v := range vs {
			sortedQuery = append(sortedQuery, rfc3986Escape(k)+"="+rfc3986Escape(v))
		}
	}
	sort.Strings(sortedQuery)
	canonicalQuery := strings.Join(sortedQuery, "&")

	payloadHash := "UNSIGNED-PAYLOAD"
	if req.Body == nil {
		payloadHash = sha256Hex([]byte(""))
	}

	canonicalHeaders := "host:" + req.URL.Host + "\n" + "x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-date"

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	// Build string to sign.
	credentialScope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// Calculate signing key.
	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")

	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
	return nil
}

// twoStepAccessToken exchanges an API key for a session token via a two-step
// flow. It POSTs the api_key to the token_url and caches the result.
func (s *Source) twoStepAccessToken(ctx context.Context, settings settings) (string, error) {
	apiKey := settings.apiKey
	if apiKey == "" {
		return "", fmt.Errorf("%s api_key is required for two_step auth", s.options.SourceID)
	}
	tokenURL := settings.tokenURL
	if tokenURL == "" {
		return "", fmt.Errorf("%s token_url is required for two_step auth", s.options.SourceID)
	}

	cacheKey := "two_step:" + tokenURL
	s.oauthTokenMu.Lock()
	defer s.oauthTokenMu.Unlock()

	now := time.Now()
	if cached, ok := s.oauthTokens[cacheKey]; ok && cached.accessToken != "" && cached.expiresAt.After(now.Add(time.Minute)) {
		return cached.accessToken, nil
	}

	body := url.Values{"api_key": {apiKey}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return "", fmt.Errorf("%s two_step token request: %w", s.options.SourceID, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := s.client
	if client == nil {
		client = sourcehttp.NewClient(sourcehttp.ClientOptions{
			SourceID:                 s.options.SourceID,
			AllowLoopback:            s.AllowLoopbackBaseURL,
			PrivateEndpointAllowlist: settings.privateEndpointAllowlist,
			LookupIPAddrs:            lookupIPAddrs(s),
		})
	}
	resp, err := sourcehttp.DoWithRetry(ctx, client, req, sourcehttp.RetryOptions{})
	if err != nil {
		return "", fmt.Errorf("%s two_step token exchange: %w", s.options.SourceID, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s two_step token exchange returned status %d", s.options.SourceID, resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Token       string `json:"token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(resp.Body, &tokenResp); err != nil {
		return "", fmt.Errorf("%s two_step token decode: %w", s.options.SourceID, err)
	}
	token := firstNonEmpty(tokenResp.AccessToken, tokenResp.Token)
	if token == "" {
		return "", fmt.Errorf("%s two_step token exchange returned empty token", s.options.SourceID)
	}

	expiresAt := now.Add(time.Hour)
	if tokenResp.ExpiresIn > 0 {
		expiresAt = now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}
	s.oauthTokens[cacheKey] = cachedOAuthToken{accessToken: token, expiresAt: expiresAt}
	return token, nil
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}

// rfc3986Escape encodes a string per RFC 3986, which AWS SigV4 requires.
// Unlike url.QueryEscape, it encodes spaces as %20 (not +) and does not
// encode tilde (~).
func rfc3986Escape(s string) string {
	escaped := url.QueryEscape(s)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	return escaped
}

func setTokenHeader(req *http.Request, header string, scheme string, token string, sourceID string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("%s token is required", sourceID)
	}
	header = strings.TrimSpace(header)
	if header == "" {
		header = "Authorization"
	}
	scheme = strings.TrimSpace(scheme)
	if strings.EqualFold(header, "Authorization") {
		if scheme == "" {
			req.Header.Set(header, token)
			return nil
		}
		separator := " "
		if strings.HasSuffix(scheme, "=") {
			separator = ""
		}
		req.Header.Set(header, scheme+separator+token)
		return nil
	}
	req.Header.Set(header, token)
	return nil
}

func (s *Source) oauthAccessToken(ctx context.Context, settings settings, grantType string) (string, error) {
	cacheKey := oauthCacheKey(settings, grantType)
	now := time.Now().UTC()
	s.oauthTokenMu.Lock()
	if cached, ok := s.oauthTokens[cacheKey]; ok && cached.accessToken != "" && cached.expiresAt.After(now.Add(time.Minute)) {
		token := cached.accessToken
		s.oauthTokenMu.Unlock()
		return token, nil
	}
	s.oauthTokenMu.Unlock()

	token, tokenType, expiresAt, err := s.exchangeOAuthToken(ctx, settings, grantType)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(tokenType, "bearer") && tokenType != "" {
		return "", fmt.Errorf("%s OAuth token response returned unsupported token_type %q", s.options.SourceID, tokenType)
	}
	s.oauthTokenMu.Lock()
	s.oauthTokens[cacheKey] = cachedOAuthToken{accessToken: token, tokenType: tokenType, expiresAt: expiresAt}
	s.oauthTokenMu.Unlock()
	return token, nil
}

func (s *Source) exchangeOAuthToken(ctx context.Context, settings settings, grantType string) (string, string, time.Time, error) {
	tokenURL, err := s.normalizeTokenURL(settings)
	if err != nil {
		return "", "", time.Time{}, err
	}
	form := url.Values{}
	form.Set("grant_type", grantType)
	for key, value := range settings.oauthTokenParams {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			form.Set(strings.TrimSpace(key), strings.TrimSpace(value))
		}
	}
	if len(settings.oauthScopes) != 0 {
		form.Set("scope", strings.Join(nonEmpty(settings.oauthScopes), " "))
	}
	switch grantType {
	case "client_credentials":
		if settings.clientID == "" || settings.clientSecret == "" {
			return "", "", time.Time{}, fmt.Errorf("%s client_id and client_secret are required for OAuth client credentials", s.options.SourceID)
		}
	case "refresh_token":
		if settings.refreshToken == "" {
			return "", "", time.Time{}, fmt.Errorf("%s refresh_token is required for OAuth refresh", s.options.SourceID)
		}
		form.Set("refresh_token", settings.refreshToken)
	default:
		return "", "", time.Time{}, fmt.Errorf("%s OAuth grant_type %q is not supported", s.options.SourceID, grantType)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("build %s OAuth token request: %w", s.options.SourceID, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	switch strings.ToLower(strings.TrimSpace(settings.oauthTokenRequestMethod)) {
	case "", "client_secret_post":
		form.Set("client_id", settings.clientID)
		form.Set("client_secret", settings.clientSecret)
		setFormRequestBody(req, form.Encode())
	case "client_secret_basic", "basic":
		req.SetBasicAuth(settings.clientID, settings.clientSecret)
		if settings.clientID != "" {
			form.Set("client_id", settings.clientID)
			setFormRequestBody(req, form.Encode())
		}
	default:
		return "", "", time.Time{}, fmt.Errorf("%s token_request_auth_method %q is not supported", s.options.SourceID, settings.oauthTokenRequestMethod)
	}
	client := s.client
	if client == nil {
		client = sourcehttp.NewClient(sourcehttp.ClientOptions{
			SourceID:                 s.options.SourceID,
			AllowLoopback:            s.AllowLoopbackBaseURL,
			PrivateEndpointAllowlist: settings.privateEndpointAllowlist,
			LookupIPAddrs:            lookupIPAddrs(s),
		})
	}
	resp, err := sourcehttp.DoWithRetry(ctx, client, req, sourcehttp.RetryOptions{})
	if err != nil {
		return "", "", time.Time{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", time.Time{}, decodeResponseError(s.options.SourceID, resp.StatusCode, resp.Body)
	}
	var payload map[string]any
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		return "", "", time.Time{}, fmt.Errorf("decode %s OAuth token response: %w", s.options.SourceID, err)
	}
	token := valueString(payload["access_token"])
	if token == "" {
		return "", "", time.Time{}, fmt.Errorf("%s OAuth token response did not include access_token", s.options.SourceID)
	}
	tokenType := firstNonEmpty(valueString(payload["token_type"]), "Bearer")
	expiresAt := time.Now().UTC().Add(time.Hour)
	if expiresIn, ok := intValue(payload["expires_in"]); ok && expiresIn > 0 {
		expiresAt = time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)
	}
	return token, tokenType, expiresAt, nil
}

func setFormRequestBody(req *http.Request, encoded string) {
	req.Body = io.NopCloser(strings.NewReader(encoded))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(encoded)), nil }
	req.ContentLength = int64(len(encoded))
}

func (s *Source) normalizeTokenURL(settings settings) (string, error) {
	raw := strings.TrimSpace(settings.tokenURL)
	if raw == "" {
		return "", fmt.Errorf("%s token_url is required for OAuth auth", s.options.SourceID)
	}
	if strings.HasPrefix(raw, "/") {
		path, err := sourcehttp.NormalizeRequestPath(s.options.SourceID, raw)
		if err != nil {
			return "", err
		}
		return settings.baseURL + path, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse %s token_url: %w", s.options.SourceID, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("%s token_url must be absolute or start with /", s.options.SourceID)
	}
	origin, _, err := sourcehttp.NormalizeBaseURLWithOptions(s.options.SourceID, parsed.Scheme+"://"+parsed.Host, sourcehttp.URLValidationOptions{
		AllowLoopback:            s.AllowLoopbackBaseURL,
		PrivateEndpointAllowlist: settings.privateEndpointAllowlist,
	})
	if err != nil {
		return "", err
	}
	return origin + parsed.RequestURI(), nil
}

func normalizedAuthModel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	switch value {
	case "", "token":
		return ""
	case "legacy", "legacy_token":
		return "legacy_token"
	case "bearer", "bearer_token":
		return "bearer_token"
	case "api_key", "api_token":
		return "api_key"
	case "basic", "duo_hmac", "oauth_client_credentials", "oauth_authorization_code", "jwt", "signature", "none", "aws_sigv4", "two_step":
		return value
	default:
		return value
	}
}

func authModelAllowed(authModel string, allowed []string) bool {
	for _, candidate := range allowed {
		if normalizedAuthModel(candidate) == authModel {
			return true
		}
	}
	return false
}

func oauthCacheKey(settings settings, grantType string) string {
	return strings.Join([]string{
		grantType,
		settings.tenantID,
		settings.tokenURL,
		settings.clientID,
		stableID(settings.clientSecret),
		settings.refreshToken,
		strings.Join(nonEmpty(settings.oauthScopes), " "),
	}, "\x00")
}
