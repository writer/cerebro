package bootstrap

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/mcpoauth"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	maxOAuthOIDCResponseBytes  = 2 << 20
	oauthOIDCDiscoveryCacheTTL = time.Hour
	oauthOIDCJWKSCacheTTL      = 5 * time.Minute
)

type mcpOAuthOIDCClient struct {
	cfg        config.MCPOAuthUpstreamConfig
	httpClient *http.Client

	mu                 sync.Mutex
	discovery          *oauthOIDCDiscovery
	discoveryExpiresAt time.Time
	jwks               *oauthJWKSet
	jwksExpiresAt      time.Time
}

func newMCPOAuthOIDCClient(cfg config.MCPOAuthUpstreamConfig) *mcpOAuthOIDCClient {
	return &mcpOAuthOIDCClient{
		cfg:        cfg,
		httpClient: newMCPOAuthOIDCHTTPClient(cfg),
	}
}

func newMCPOAuthOIDCHTTPClient(cfg config.MCPOAuthUpstreamConfig) *http.Client {
	return sourcehttp.NewClient(sourcehttp.ClientOptions{
		SourceID:      "mcp-oauth-oidc",
		Timeout:       15 * time.Second,
		AllowLoopback: mcpOAuthOIDCAllowsLoopback(cfg),
	})
}

func mcpOAuthOIDCAllowsLoopback(cfg config.MCPOAuthUpstreamConfig) bool {
	for _, raw := range []string{cfg.Issuer, cfg.TokenEndpoint, cfg.JWKSURI} {
		if mcpOAuthOIDCURLUsesLoopback(raw) {
			return true
		}
	}
	return false
}

func mcpOAuthOIDCURLUsesLoopback(raw string) bool {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil {
		return false
	}
	return sourcehttp.IsLoopbackHost(parsed.Hostname())
}

func (c *mcpOAuthOIDCClient) AuthorizationEndpoint(ctx context.Context) (string, error) {
	if endpoint := strings.TrimSpace(c.cfg.AuthorizationEndpoint); endpoint != "" {
		return endpoint, nil
	}
	discovery, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	if discovery.AuthorizationEndpoint == "" {
		return "", fmt.Errorf("mcpoauth: upstream discovery missing authorization_endpoint")
	}
	return discovery.AuthorizationEndpoint, nil
}

func (c *mcpOAuthOIDCClient) tokenEndpoint(ctx context.Context) (string, error) {
	if endpoint := strings.TrimSpace(c.cfg.TokenEndpoint); endpoint != "" {
		return endpoint, nil
	}
	discovery, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	if discovery.TokenEndpoint == "" {
		return "", fmt.Errorf("mcpoauth: upstream discovery missing token_endpoint")
	}
	return discovery.TokenEndpoint, nil
}

func (c *mcpOAuthOIDCClient) jwksURI(ctx context.Context) (string, error) {
	if uri := strings.TrimSpace(c.cfg.JWKSURI); uri != "" {
		return uri, nil
	}
	discovery, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	if discovery.JWKSURI == "" {
		return "", fmt.Errorf("mcpoauth: upstream discovery missing jwks_uri")
	}
	return discovery.JWKSURI, nil
}

func (c *mcpOAuthOIDCClient) ExchangeCode(ctx context.Context, code string, nonce string) (mcpoauth.Identity, error) {
	tokenEndpoint, err := c.tokenEndpoint(ctx)
	if err != nil {
		return mcpoauth.Identity{}, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", strings.TrimSpace(code))
	form.Set("redirect_uri", c.cfg.RedirectURI)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return mcpoauth.Identity{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return mcpoauth.Identity{}, fmt.Errorf("mcpoauth: upstream token exchange failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readOAuthOIDCLimited(resp.Body, maxOAuthOIDCResponseBytes)
	if err != nil {
		return mcpoauth.Identity{}, fmt.Errorf("mcpoauth: read upstream token response: %w", err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return mcpoauth.Identity{}, mcpoauthOAuthError("access_denied", "upstream token exchange failed", http.StatusBadGateway)
	}
	var decoded struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return mcpoauth.Identity{}, fmt.Errorf("mcpoauth: decode upstream token response: %w", err)
	}
	if decoded.Error != "" {
		return mcpoauth.Identity{}, mcpoauthOAuthError("access_denied", decoded.Error, http.StatusBadGateway)
	}
	if decoded.IDToken == "" {
		return mcpoauth.Identity{}, fmt.Errorf("mcpoauth: upstream token response missing id_token")
	}
	return c.verifyIDToken(ctx, decoded.IDToken, nonce)
}

func (c *mcpOAuthOIDCClient) verifyIDToken(ctx context.Context, token string, nonce string) (mcpoauth.Identity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return mcpoauth.Identity{}, mcpoauthOAuthError("invalid_grant", "upstream id_token is malformed", http.StatusBadGateway)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return mcpoauth.Identity{}, mcpoauthOAuthError("invalid_grant", "upstream id_token header is malformed", http.StatusBadGateway)
	}
	var header struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return mcpoauth.Identity{}, mcpoauthOAuthError("invalid_grant", "upstream id_token header is malformed", http.StatusBadGateway)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return mcpoauth.Identity{}, mcpoauthOAuthError("invalid_grant", "upstream id_token payload is malformed", http.StatusBadGateway)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return mcpoauth.Identity{}, mcpoauthOAuthError("invalid_grant", "upstream id_token payload is malformed", http.StatusBadGateway)
	}
	keySet, err := c.loadJWKS(ctx)
	if err != nil {
		return mcpoauth.Identity{}, err
	}
	if err := verifyOAuthJWTSignature(parts[0]+"."+parts[1], parts[2], header, keySet); err != nil {
		if !isOAuthSigningKeyUnknown(err) {
			return mcpoauth.Identity{}, err
		}
		keySet, err = c.refreshJWKS(ctx)
		if err != nil {
			return mcpoauth.Identity{}, err
		}
		if err := verifyOAuthJWTSignature(parts[0]+"."+parts[1], parts[2], header, keySet); err != nil {
			return mcpoauth.Identity{}, err
		}
	}
	if got := oauthStringClaim(claims, "iss"); got != c.cfg.Issuer {
		return mcpoauth.Identity{}, mcpoauthOAuthError("invalid_grant", "upstream id_token issuer mismatch", http.StatusBadGateway)
	}
	if !oauthAudienceContains(claims["aud"], c.cfg.ClientID) {
		return mcpoauth.Identity{}, mcpoauthOAuthError("invalid_grant", "upstream id_token audience mismatch", http.StatusBadGateway)
	}
	now := time.Now().UTC()
	if exp := oauthInt64Claim(claims, "exp"); exp <= 0 || now.After(time.Unix(exp, 0).Add(time.Minute)) {
		return mcpoauth.Identity{}, mcpoauthOAuthError("invalid_grant", "upstream id_token expired", http.StatusBadGateway)
	}
	if nbf := oauthInt64Claim(claims, "nbf"); nbf > 0 && now.Add(time.Minute).Before(time.Unix(nbf, 0)) {
		return mcpoauth.Identity{}, mcpoauthOAuthError("invalid_grant", "upstream id_token not yet valid", http.StatusBadGateway)
	}
	if expectedNonce := strings.TrimSpace(nonce); expectedNonce != "" && oauthStringClaim(claims, "nonce") != expectedNonce {
		return mcpoauth.Identity{}, mcpoauthOAuthError("invalid_grant", "upstream id_token nonce mismatch", http.StatusBadGateway)
	}
	subject := oauthStringClaim(claims, "sub")
	if subject == "" {
		return mcpoauth.Identity{}, mcpoauthOAuthError("invalid_grant", "upstream id_token missing subject", http.StatusBadGateway)
	}
	email := firstNonEmpty(oauthStringClaim(claims, "email"), oauthStringClaim(claims, "preferred_username"), subject)
	return mcpoauth.Identity{
		Subject: subject,
		Email:   email,
		Groups:  oauthStringListClaim(claims, c.cfg.GroupsClaim),
	}, nil
}

type oauthOIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func (c *mcpOAuthOIDCClient) discover(ctx context.Context) (oauthOIDCDiscovery, error) {
	now := time.Now()
	c.mu.Lock()
	if c.discovery != nil && now.Before(c.discoveryExpiresAt) {
		discovery := *c.discovery
		c.mu.Unlock()
		return discovery, nil
	}
	c.mu.Unlock()

	issuer := strings.TrimRight(c.cfg.Issuer, "/")
	discoveryURL := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return oauthOIDCDiscovery{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return oauthOIDCDiscovery{}, fmt.Errorf("mcpoauth: upstream OIDC discovery failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readOAuthOIDCLimited(resp.Body, maxOAuthOIDCResponseBytes)
	if err != nil {
		return oauthOIDCDiscovery{}, err
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return oauthOIDCDiscovery{}, fmt.Errorf("mcpoauth: upstream OIDC discovery status %d", resp.StatusCode)
	}
	var discovery oauthOIDCDiscovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		return oauthOIDCDiscovery{}, fmt.Errorf("mcpoauth: decode upstream OIDC discovery: %w", err)
	}
	if discovery.Issuer != c.cfg.Issuer {
		return oauthOIDCDiscovery{}, fmt.Errorf("mcpoauth: upstream discovery issuer mismatch")
	}
	c.mu.Lock()
	c.discovery = &discovery
	c.discoveryExpiresAt = time.Now().Add(oauthOIDCDiscoveryCacheTTL)
	c.mu.Unlock()
	return discovery, nil
}

type oauthJWKSet struct {
	Keys []oauthJWK `json:"keys"`
}

type oauthJWK struct {
	KTY string `json:"kty"`
	KID string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (c *mcpOAuthOIDCClient) loadJWKS(ctx context.Context) (oauthJWKSet, error) {
	return c.loadJWKSWithForce(ctx, false)
}

func (c *mcpOAuthOIDCClient) refreshJWKS(ctx context.Context) (oauthJWKSet, error) {
	return c.loadJWKSWithForce(ctx, true)
}

func (c *mcpOAuthOIDCClient) loadJWKSWithForce(ctx context.Context, force bool) (oauthJWKSet, error) {
	now := time.Now()
	c.mu.Lock()
	if !force && c.jwks != nil && now.Before(c.jwksExpiresAt) {
		keys := *c.jwks
		c.mu.Unlock()
		return keys, nil
	}
	c.mu.Unlock()

	jwksURI, err := c.jwksURI(ctx)
	if err != nil {
		return oauthJWKSet{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return oauthJWKSet{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return oauthJWKSet{}, fmt.Errorf("mcpoauth: fetch upstream JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readOAuthOIDCLimited(resp.Body, maxOAuthOIDCResponseBytes)
	if err != nil {
		return oauthJWKSet{}, err
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return oauthJWKSet{}, fmt.Errorf("mcpoauth: upstream JWKS status %d", resp.StatusCode)
	}
	var keys oauthJWKSet
	if err := json.Unmarshal(body, &keys); err != nil {
		return oauthJWKSet{}, fmt.Errorf("mcpoauth: decode upstream JWKS: %w", err)
	}
	c.mu.Lock()
	c.jwks = &keys
	c.jwksExpiresAt = time.Now().Add(oauthOIDCJWKSCacheTTL)
	c.mu.Unlock()
	return keys, nil
}

func isOAuthSigningKeyUnknown(err error) bool {
	var oauthErr *mcpoauth.OAuthError
	return errors.As(err, &oauthErr) && oauthErr.Code == "invalid_grant" && strings.Contains(oauthErr.Description, "signing key is unknown")
}

func verifyOAuthJWTSignature(signingInput string, signatureSegment string, header struct {
	Alg string `json:"alg"`
	KID string `json:"kid"`
	Typ string `json:"typ"`
}, keys oauthJWKSet) error {
	signature, err := base64.RawURLEncoding.DecodeString(signatureSegment)
	if err != nil {
		return mcpoauthOAuthError("invalid_grant", "upstream id_token signature is malformed", http.StatusBadGateway)
	}
	key, ok := findOAuthJWK(keys, header.KID, header.Alg)
	if !ok {
		return mcpoauthOAuthError("invalid_grant", "upstream id_token signing key is unknown", http.StatusBadGateway)
	}
	digest := sha256.Sum256([]byte(signingInput))
	switch header.Alg {
	case "RS256":
		pub, err := oauthRSAPublicKey(key)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
			return mcpoauthOAuthError("invalid_grant", "upstream id_token signature is invalid", http.StatusBadGateway)
		}
		return nil
	case "ES256":
		pub, err := oauthECDSAPublicKey(key)
		if err != nil {
			return err
		}
		if len(signature) != 64 {
			return mcpoauthOAuthError("invalid_grant", "upstream id_token ECDSA signature is malformed", http.StatusBadGateway)
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return mcpoauthOAuthError("invalid_grant", "upstream id_token signature is invalid", http.StatusBadGateway)
		}
		return nil
	default:
		return mcpoauthOAuthError("invalid_grant", "upstream id_token algorithm is unsupported", http.StatusBadGateway)
	}
}

func findOAuthJWK(keys oauthJWKSet, kid string, alg string) (oauthJWK, bool) {
	var fallback oauthJWK
	for _, key := range keys.Keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if key.Alg != "" && alg != "" && key.Alg != alg {
			continue
		}
		if kid != "" && key.KID == kid {
			return key, true
		}
		if kid == "" && fallback.KTY == "" {
			fallback = key
		}
	}
	if kid == "" && fallback.KTY != "" {
		return fallback, true
	}
	return oauthJWK{}, false
}

func oauthRSAPublicKey(key oauthJWK) (*rsa.PublicKey, error) {
	if key.KTY != "RSA" {
		return nil, mcpoauthOAuthError("invalid_grant", "upstream signing key is not RSA", http.StatusBadGateway)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, mcpoauthOAuthError("invalid_grant", "upstream RSA key modulus is invalid", http.StatusBadGateway)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, mcpoauthOAuthError("invalid_grant", "upstream RSA key exponent is invalid", http.StatusBadGateway)
	}
	e := new(big.Int).SetBytes(eBytes).Int64()
	if e <= 1 {
		return nil, mcpoauthOAuthError("invalid_grant", "upstream RSA key exponent is invalid", http.StatusBadGateway)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e)}, nil
}

func oauthECDSAPublicKey(key oauthJWK) (*ecdsa.PublicKey, error) {
	if key.KTY != "EC" || key.CRV != "P-256" {
		return nil, mcpoauthOAuthError("invalid_grant", "upstream signing key is not ES256", http.StatusBadGateway)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, mcpoauthOAuthError("invalid_grant", "upstream EC key x coordinate is invalid", http.StatusBadGateway)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, mcpoauthOAuthError("invalid_grant", "upstream EC key y coordinate is invalid", http.StatusBadGateway)
	}
	if len(xBytes) != 32 || len(yBytes) != 32 {
		return nil, mcpoauthOAuthError("invalid_grant", "upstream EC key coordinate length is invalid", http.StatusBadGateway)
	}
	encoded := make([]byte, 65)
	encoded[0] = 4
	copy(encoded[1:33], xBytes)
	copy(encoded[33:], yBytes)
	if _, err := ecdh.P256().NewPublicKey(encoded); err != nil {
		return nil, mcpoauthOAuthError("invalid_grant", "upstream EC key is not on P-256", http.StatusBadGateway)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}, nil
}

func oauthAudienceContains(value any, expected string) bool {
	switch typed := value.(type) {
	case string:
		return typed == expected
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok && text == expected {
				return true
			}
		}
	}
	return false
}

func oauthStringClaim(claims map[string]any, key string) string {
	value, ok := claims[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func oauthInt64Claim(claims map[string]any, key string) int64 {
	value, ok := claims[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	default:
		return 0
	}
}

func oauthStringListClaim(claims map[string]any, key string) []string {
	value, ok := claims[key]
	if !ok {
		return nil
	}
	var out []string
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
	case []string:
		for _, text := range typed {
			if strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
	case string:
		split := strings.FieldsFunc(typed, func(r rune) bool { return r == ',' || r == ' ' })
		for _, text := range split {
			if strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
	}
	return out
}

func readOAuthOIDCLimited(r io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(r, limit+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response body exceeds %d bytes", limit)
	}
	return body, nil
}
