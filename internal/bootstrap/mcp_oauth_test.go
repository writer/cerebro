package bootstrap

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/mcpoauth"
)

func TestMCPOAuthFlowIssuesCapabilityTokenForMCP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var upstreamNonce string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			upstreamNonce = r.URL.Query().Get("nonce")
			redirectURI := r.URL.Query().Get("redirect_uri")
			values := url.Values{}
			values.Set("code", "upstream-code")
			values.Set("state", r.URL.Query().Get("state"))
			http.Redirect(w, r, redirectURI+"?"+values.Encode(), http.StatusFound)
		case "/token":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			clientID, secret, ok := r.BasicAuth()
			if !ok || clientID != "writer-client" || secret != "writer-secret" {
				t.Fatalf("upstream token BasicAuth = (%q,%q,%v)", clientID, secret, ok)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("upstream ParseForm: %v", err)
			}
			if got := r.Form.Get("code"); got != "upstream-code" {
				t.Fatalf("upstream code = %q, want upstream-code", got)
			}
			idToken := signOIDCIDToken(t, key, map[string]any{
				"iss":    "https://writer-sso.example",
				"aud":    "writer-client",
				"sub":    "user-1",
				"email":  "user@example.com",
				"groups": []string{"secops"},
				"nonce":  upstreamNonce,
				"iat":    time.Now().Unix(),
				"exp":    time.Now().Add(time.Hour).Unix(),
			})
			_ = json.NewEncoder(w).Encode(map[string]any{"id_token": idToken, "token_type": "Bearer"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK("test-kid", &key.PublicKey)}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	store := newMemoryMCPOAuthStore()
	clientRedirect := "http://127.0.0.1/callback"
	cfg := testMCPOAuthConfig(clientRedirect, upstream.URL)
	app, err := NewWithError(cfg, Dependencies{StateStore: store}, nil)
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	metadataResp, err := server.Client().Get(server.URL + oauthProtectedResourceMetadataMCPPath)
	if err != nil {
		t.Fatalf("GET protected resource metadata: %v", err)
	}
	var metadata map[string]any
	if err := json.NewDecoder(metadataResp.Body).Decode(&metadata); err != nil {
		t.Fatalf("Decode metadata: %v", err)
	}
	_ = metadataResp.Body.Close()
	if metadata["resource"] != "https://cerebro.example/api/v1/mcp" {
		t.Fatalf("resource metadata = %#v", metadata)
	}

	unauthReq, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("NewRequest unauth MCP: %v", err)
	}
	unauthResp, err := server.Client().Do(unauthReq)
	if err != nil {
		t.Fatalf("POST unauth MCP: %v", err)
	}
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized || !strings.Contains(unauthResp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("unauth MCP status/header = %d %q", unauthResp.StatusCode, unauthResp.Header.Get("WWW-Authenticate"))
	}
	if !strings.Contains(unauthResp.Header.Get("WWW-Authenticate"), `scope="`+scopeCosmoSecurityRead+`"`) {
		t.Fatalf("unauth MCP missing scope challenge: %q", unauthResp.Header.Get("WWW-Authenticate"))
	}

	codeVerifier := strings.Repeat("a", 64)
	codeChallenge := pkceChallenge(codeVerifier)
	authURL := server.URL + oauthAuthorizePath + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"droid"},
		"redirect_uri":          {clientRedirect},
		"state":                 {"client-state"},
		"scope":                 {scopeCosmoSecurityRead},
		"resource":              {"https://cerebro.example/api/v1/mcp"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	noRedirect := noRedirectClient(server)
	authResp, err := noRedirect.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	_ = authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound || !strings.HasPrefix(authResp.Header.Get("Location"), upstream.URL+"/authorize") {
		t.Fatalf("authorize status/location = %d %q", authResp.StatusCode, authResp.Header.Get("Location"))
	}
	upstreamResp, err := noRedirect.Get(authResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("GET upstream authorize: %v", err)
	}
	_ = upstreamResp.Body.Close()
	callbackLocation := strings.Replace(upstreamResp.Header.Get("Location"), "https://cerebro.example", server.URL, 1)
	if upstreamResp.StatusCode != http.StatusFound || !strings.HasPrefix(callbackLocation, server.URL+oauthCallbackPath) {
		t.Fatalf("upstream status/location = %d %q", upstreamResp.StatusCode, upstreamResp.Header.Get("Location"))
	}
	callbackResp, err := noRedirect.Get(callbackLocation)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	_ = callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusFound || !strings.HasPrefix(callbackResp.Header.Get("Location"), clientRedirect) {
		t.Fatalf("callback status/location = %d %q", callbackResp.StatusCode, callbackResp.Header.Get("Location"))
	}
	clientCallback, err := url.Parse(callbackResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse client callback: %v", err)
	}
	if got := clientCallback.Query().Get("state"); got != "client-state" {
		t.Fatalf("client callback state = %q, want client-state", got)
	}
	code := clientCallback.Query().Get("code")
	if code == "" {
		t.Fatalf("client callback missing code: %s", clientCallback.String())
	}

	missingResource := exchangeMCPOAuthTokenRaw(t, server, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"droid"},
		"redirect_uri":  {clientRedirect},
		"code":          {code},
		"code_verifier": {codeVerifier},
	})
	_ = missingResource.Body.Close()
	if missingResource.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing resource token status = %d, want 400", missingResource.StatusCode)
	}

	tokenResp := exchangeMCPOAuthToken(t, server, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"droid"},
		"redirect_uri":  {clientRedirect},
		"resource":      {"https://cerebro.example/api/v1/mcp"},
		"code":          {code},
		"code_verifier": {codeVerifier},
	})
	if tokenResp.AccessToken == "" || tokenResp.RefreshToken == "" || tokenResp.TokenType != "Bearer" {
		t.Fatalf("token response = %#v", tokenResp)
	}
	store.mu.Lock()
	originalRefreshRecord := store.refresh[hashKey(mcpoauth.HashToken(tokenResp.RefreshToken))].value
	store.mu.Unlock()
	replay := exchangeMCPOAuthTokenRaw(t, server, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"droid"},
		"redirect_uri":  {clientRedirect},
		"resource":      {"https://cerebro.example/api/v1/mcp"},
		"code":          {code},
		"code_verifier": {codeVerifier},
	})
	_ = replay.Body.Close()
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed authorization code status = %d, want 400", replay.StatusCode)
	}

	mcpReq, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatalf("NewRequest MCP: %v", err)
	}
	mcpReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	mcpReq.Header.Set("Content-Type", "application/json")
	mcpReq.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	mcpResp, err := server.Client().Do(mcpReq)
	if err != nil {
		t.Fatalf("POST MCP with OAuth token: %v", err)
	}
	defer func() { _ = mcpResp.Body.Close() }()
	if mcpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(mcpResp.Body)
		t.Fatalf("MCP status = %d body=%s", mcpResp.StatusCode, body)
	}
	if got := mcpResp.Header.Get("Mcp-Session-Id"); got != "" {
		t.Fatalf("MCP OAuth Mcp-Session-Id = %q, want empty for stateless MCP", got)
	}
	var mcpPayload map[string]any
	if err := json.NewDecoder(mcpResp.Body).Decode(&mcpPayload); err != nil {
		t.Fatalf("decode MCP payload: %v", err)
	}
	if mcpPayload["error"] != nil {
		t.Fatalf("MCP returned error: %#v", mcpPayload)
	}

	nonMCPReq, err := http.NewRequest(http.MethodGet, server.URL+"/reports", nil)
	if err != nil {
		t.Fatalf("NewRequest non-MCP: %v", err)
	}
	nonMCPReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	nonMCPResp, err := server.Client().Do(nonMCPReq)
	if err != nil {
		t.Fatalf("GET reports with MCP OAuth token: %v", err)
	}
	_ = nonMCPResp.Body.Close()
	if nonMCPResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-MCP status with MCP OAuth token = %d, want 401", nonMCPResp.StatusCode)
	}

	refreshed := exchangeMCPOAuthToken(t, server, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"droid"},
		"resource":      {"https://cerebro.example/api/v1/mcp"},
		"refresh_token": {tokenResp.RefreshToken},
	})
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" || refreshed.RefreshToken == tokenResp.RefreshToken {
		t.Fatalf("refresh response = %#v", refreshed)
	}
	store.mu.Lock()
	rotatedRefreshRecord := store.refresh[hashKey(mcpoauth.HashToken(refreshed.RefreshToken))].value
	store.mu.Unlock()
	if !rotatedRefreshRecord.ExpiresAt.Equal(originalRefreshRecord.ExpiresAt) {
		t.Fatalf("rotated refresh expiration = %v, want family expiration %v", rotatedRefreshRecord.ExpiresAt, originalRefreshRecord.ExpiresAt)
	}
	revokeResp := revokeMCPOAuthTokenRaw(t, server, url.Values{
		"client_id": {"droid"},
		"token":     {refreshed.RefreshToken},
	})
	_ = revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", revokeResp.StatusCode)
	}
	revokedRefresh := exchangeMCPOAuthTokenRaw(t, server, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"droid"},
		"resource":      {"https://cerebro.example/api/v1/mcp"},
		"refresh_token": {refreshed.RefreshToken},
	})
	_ = revokedRefresh.Body.Close()
	if revokedRefresh.StatusCode != http.StatusBadRequest {
		t.Fatalf("revoked refresh status = %d, want 400", revokedRefresh.StatusCode)
	}
}

func TestMCPOAuthClientCredentialsIssuesMCPOnlyToken(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	cfg := testMCPOAuthConfig("http://127.0.0.1/callback", upstream.URL)
	cfg.Auth.MCPOAuth.Clients = []config.MCPOAuthClient{{
		ClientID:       "panopticon",
		ClientSecret:   "client-secret",
		GrantTypes:     []string{"client_credentials"},
		AllowedTenants: []string{"writer"},
		Scopes:         []string{scopeCosmoSecurityRead},
		Groups:         []string{"security"},
	}}
	app, err := NewWithError(cfg, Dependencies{StateStore: newMemoryMCPOAuthStore()}, nil)
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	form := url.Values{
		"grant_type": {"client_credentials"},
		"resource":   {"https://cerebro.example/api/v1/mcp"},
		"scope":      {scopeCosmoSecurityRead},
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+oauthTokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest token: %v", err)
	}
	req.SetBasicAuth("panopticon", "client-secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("client_credentials status = %d body=%s", resp.StatusCode, body)
	}
	var tokenResp mcpoauth.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenResp.AccessToken == "" || tokenResp.RefreshToken != "" {
		t.Fatalf("client_credentials token response = %#v", tokenResp)
	}

	mcpReq, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatalf("NewRequest MCP: %v", err)
	}
	mcpReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	mcpReq.Header.Set("Content-Type", "application/json")
	mcpReq.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	mcpResp, err := server.Client().Do(mcpReq)
	if err != nil {
		t.Fatalf("POST MCP with M2M token: %v", err)
	}
	_ = mcpResp.Body.Close()
	if mcpResp.StatusCode != http.StatusOK {
		t.Fatalf("MCP status with M2M token = %d, want 200", mcpResp.StatusCode)
	}

	nonMCPReq, err := http.NewRequest(http.MethodGet, server.URL+"/reports", nil)
	if err != nil {
		t.Fatalf("NewRequest non-MCP: %v", err)
	}
	nonMCPReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	nonMCPResp, err := server.Client().Do(nonMCPReq)
	if err != nil {
		t.Fatalf("GET reports with M2M token: %v", err)
	}
	_ = nonMCPResp.Body.Close()
	if nonMCPResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-MCP status with M2M token = %d, want 401", nonMCPResp.StatusCode)
	}
}

func TestMCPOAuthOIDCDiscoveryDoesNotFollowRedirects(t *testing.T) {
	redirectTargetHit := false
	var redirectTarget *httptest.Server
	redirectTarget = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "placeholder",
			"authorization_endpoint": redirectTarget.URL + "/authorize",
			"token_endpoint":         redirectTarget.URL + "/token",
			"jwks_uri":               redirectTarget.URL + "/jwks",
		})
	}))
	defer redirectTarget.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, redirectTarget.URL+"/openid-configuration", http.StatusFound)
	}))
	defer upstream.Close()

	client := newMCPOAuthOIDCClient(config.MCPOAuthUpstreamConfig{
		Issuer:       upstream.URL,
		ClientID:     "writer-client",
		ClientSecret: "writer-secret",
		RedirectURI:  "https://cerebro.example/oauth/callback",
	})
	endpoint, err := client.AuthorizationEndpoint(context.Background())
	if err == nil {
		t.Fatalf("AuthorizationEndpoint = %q, want upstream discovery redirect rejection", endpoint)
	}
	if redirectTargetHit {
		t.Fatal("OIDC discovery followed a server-side redirect target")
	}
}

func TestMCPOAuthOIDCTokenExchangeDoesNotFollowRedirects(t *testing.T) {
	redirectTargetHit := false
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit = true
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": "redirected"})
	}))
	defer redirectTarget.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, redirectTarget.URL+"/capture", http.StatusFound)
	}))
	defer upstream.Close()

	client := newMCPOAuthOIDCClient(config.MCPOAuthUpstreamConfig{
		Issuer:        "https://writer-sso.example",
		TokenEndpoint: upstream.URL + "/token",
		ClientID:      "writer-client",
		ClientSecret:  "writer-secret",
		RedirectURI:   "https://cerebro.example/oauth/callback",
	})
	_, err := client.ExchangeCode(context.Background(), "upstream-code", "nonce")
	if err == nil {
		t.Fatal("ExchangeCode succeeded through an upstream token redirect")
	}
	if redirectTargetHit {
		t.Fatal("OIDC token exchange followed a server-side redirect target")
	}
}

func TestMCPOAuthCallbackRejectsMissingSecurityGroup(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var upstreamNonce string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			upstreamNonce = r.URL.Query().Get("nonce")
			redirectURI := r.URL.Query().Get("redirect_uri")
			values := url.Values{"code": {"upstream-code"}, "state": {r.URL.Query().Get("state")}}
			http.Redirect(w, r, redirectURI+"?"+values.Encode(), http.StatusFound)
		case "/token":
			idToken := signOIDCIDToken(t, key, map[string]any{
				"iss":    "https://writer-sso.example",
				"aud":    "writer-client",
				"sub":    "user-1",
				"groups": []string{"not-security"},
				"nonce":  upstreamNonce,
				"iat":    time.Now().Unix(),
				"exp":    time.Now().Add(time.Hour).Unix(),
			})
			_ = json.NewEncoder(w).Encode(map[string]any{"id_token": idToken, "token_type": "Bearer"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK("test-kid", &key.PublicKey)}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	clientRedirect := "http://127.0.0.1/callback"
	app, err := NewWithError(testMCPOAuthConfig(clientRedirect, upstream.URL), Dependencies{StateStore: newMemoryMCPOAuthStore()}, nil)
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	noRedirect := noRedirectClient(server)

	authResp, err := noRedirect.Get(server.URL + oauthAuthorizePath + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"droid"},
		"redirect_uri":          {clientRedirect},
		"state":                 {"client-state"},
		"code_challenge":        {pkceChallenge(strings.Repeat("a", 64))},
		"code_challenge_method": {"S256"},
	}.Encode())
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	_ = authResp.Body.Close()
	upstreamResp, err := noRedirect.Get(authResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("GET upstream authorize: %v", err)
	}
	_ = upstreamResp.Body.Close()
	callbackLocation := strings.Replace(upstreamResp.Header.Get("Location"), "https://cerebro.example", server.URL, 1)
	callbackResp, err := noRedirect.Get(callbackLocation)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	_ = callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusForbidden {
		t.Fatalf("callback status = %d, want 403", callbackResp.StatusCode)
	}
}

func TestMCPOAuthOIDCRefreshesJWKSOnUnknownKID(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey old: %v", err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey new: %v", err)
	}
	var jwksMu sync.Mutex
	useNewKey := false
	jwksRequests := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		jwksMu.Lock()
		jwksRequests++
		serveNewKey := useNewKey
		jwksMu.Unlock()
		if serveNewKey {
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK("new-kid", &newKey.PublicKey)}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK("old-kid", &oldKey.PublicKey)}})
	}))
	defer upstream.Close()

	client := newMCPOAuthOIDCClient(config.MCPOAuthUpstreamConfig{
		Issuer:      "https://writer-sso.example",
		JWKSURI:     upstream.URL + "/jwks",
		ClientID:    "writer-client",
		GroupsClaim: "groups",
	})
	oldToken := signOIDCIDTokenWithKID(t, oldKey, "old-kid", map[string]any{
		"iss":    "https://writer-sso.example",
		"aud":    "writer-client",
		"sub":    "user-1",
		"groups": []string{"secops"},
		"nonce":  "nonce-1",
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	if _, err := client.verifyIDToken(context.Background(), oldToken, "nonce-1"); err != nil {
		t.Fatalf("verify old token: %v", err)
	}

	jwksMu.Lock()
	useNewKey = true
	jwksMu.Unlock()
	newToken := signOIDCIDTokenWithKID(t, newKey, "new-kid", map[string]any{
		"iss":    "https://writer-sso.example",
		"aud":    "writer-client",
		"sub":    "user-1",
		"groups": []string{"secops"},
		"nonce":  "nonce-2",
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	if _, err := client.verifyIDToken(context.Background(), newToken, "nonce-2"); err != nil {
		t.Fatalf("verify token after JWKS rotation: %v", err)
	}
	jwksMu.Lock()
	requests := jwksRequests
	jwksMu.Unlock()
	if requests < 2 {
		t.Fatalf("JWKS requests = %d, want at least 2 after unknown kid refresh", requests)
	}
}

func TestMCPOAuthDynamicClientRegistration(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authorize" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	clientRedirect := "http://127.0.0.1:39123/callback"
	cfg := testMCPOAuthConfig(clientRedirect, upstream.URL)
	cfg.Auth.MCPOAuth.Clients = nil
	store := newMemoryMCPOAuthStore()
	app, err := NewWithError(cfg, Dependencies{StateStore: store}, nil)
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	metadataResp, err := server.Client().Get(server.URL + oauthAuthorizationServerMetadataPath)
	if err != nil {
		t.Fatalf("GET authorization server metadata: %v", err)
	}
	var metadata map[string]any
	if err := json.NewDecoder(metadataResp.Body).Decode(&metadata); err != nil {
		t.Fatalf("Decode metadata: %v", err)
	}
	_ = metadataResp.Body.Close()
	if metadata["registration_endpoint"] != "https://cerebro.example/oauth/register" {
		t.Fatalf("registration_endpoint = %#v", metadata["registration_endpoint"])
	}
	authMethods, ok := metadata["token_endpoint_auth_methods_supported"].([]any)
	if !ok || len(authMethods) == 0 || authMethods[0] != "none" {
		t.Fatalf("token_endpoint_auth_methods_supported = %#v, want none first for public MCP clients", metadata["token_endpoint_auth_methods_supported"])
	}

	registerBody := strings.NewReader(`{"client_name":"Droid","redirect_uris":["` + clientRedirect + `"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"]}`)
	registerResp, err := server.Client().Post(server.URL+oauthRegisterPath, "application/json", registerBody)
	if err != nil {
		t.Fatalf("POST register: %v", err)
	}
	defer func() { _ = registerResp.Body.Close() }()
	if registerResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(registerResp.Body)
		t.Fatalf("register status = %d body=%s", registerResp.StatusCode, body)
	}
	var registered mcpoauth.ClientRegistrationResponse
	if err := json.NewDecoder(registerResp.Body).Decode(&registered); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if registered.ClientID == "" || registered.TokenEndpointAuthMethod != "none" {
		t.Fatalf("registered client = %#v", registered)
	}

	noRedirect := noRedirectClient(server)
	authResp, err := noRedirect.Get(server.URL + oauthAuthorizePath + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {registered.ClientID},
		"redirect_uri":          {clientRedirect},
		"state":                 {"client-state"},
		"resource":              {"https://cerebro.example/api/v1/mcp"},
		"code_challenge":        {pkceChallenge(strings.Repeat("a", 64))},
		"code_challenge_method": {"S256"},
	}.Encode())
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	_ = authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound || !strings.HasPrefix(authResp.Header.Get("Location"), upstream.URL+"/authorize") {
		t.Fatalf("authorize status/location = %d %q", authResp.StatusCode, authResp.Header.Get("Location"))
	}

	badRegisterResp, err := server.Client().Post(server.URL+oauthRegisterPath, "application/json", strings.NewReader(`{"redirect_uris":["https://evil.example/callback"]}`))
	if err != nil {
		t.Fatalf("POST bad register: %v", err)
	}
	_ = badRegisterResp.Body.Close()
	if badRegisterResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad register status = %d, want 400", badRegisterResp.StatusCode)
	}

	confidentialRegisterResp, err := server.Client().Post(server.URL+oauthRegisterPath, "application/json", strings.NewReader(`{"client_name":"Droid confidential","redirect_uris":["`+clientRedirect+`"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_basic"}`))
	if err != nil {
		t.Fatalf("POST confidential register: %v", err)
	}
	defer func() { _ = confidentialRegisterResp.Body.Close() }()
	if confidentialRegisterResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(confidentialRegisterResp.Body)
		t.Fatalf("confidential register status = %d body=%s", confidentialRegisterResp.StatusCode, body)
	}
	var confidential mcpoauth.ClientRegistrationResponse
	if err := json.NewDecoder(confidentialRegisterResp.Body).Decode(&confidential); err != nil {
		t.Fatalf("decode confidential register response: %v", err)
	}
	if confidential.ClientID == "" || confidential.ClientSecret == "" || confidential.TokenEndpointAuthMethod != "client_secret_basic" || confidential.ClientSecretExpiresAt == nil || *confidential.ClientSecretExpiresAt != 0 {
		t.Fatalf("confidential client = %#v", confidential)
	}
	store.mu.Lock()
	storedConfidential := store.clients[confidential.ClientID]
	store.mu.Unlock()
	if storedConfidential.Public || storedConfidential.ClientSecret == "" || storedConfidential.ClientSecret == confidential.ClientSecret {
		t.Fatalf("stored confidential client = %#v", storedConfidential)
	}
	wrongSecretResp := exchangeMCPOAuthTokenRaw(t, server, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {confidential.ClientID},
		"client_secret": {"wrong-secret"},
		"resource":      {"https://cerebro.example/api/v1/mcp"},
		"refresh_token": {"refresh_dummy"},
	})
	_ = wrongSecretResp.Body.Close()
	if wrongSecretResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong confidential secret token status = %d, want 401", wrongSecretResp.StatusCode)
	}
	correctSecretReq, err := http.NewRequest(http.MethodPost, server.URL+oauthTokenPath, strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"resource":      {"https://cerebro.example/api/v1/mcp"},
		"refresh_token": {"refresh_dummy"},
	}.Encode()))
	if err != nil {
		t.Fatalf("NewRequest confidential token: %v", err)
	}
	correctSecretReq.SetBasicAuth(confidential.ClientID, confidential.ClientSecret)
	correctSecretReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	correctSecretResp, err := server.Client().Do(correctSecretReq)
	if err != nil {
		t.Fatalf("POST confidential token: %v", err)
	}
	_ = correctSecretResp.Body.Close()
	if correctSecretResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("correct confidential secret token status = %d, want 400 invalid_grant", correctSecretResp.StatusCode)
	}

	postRegisterResp, err := server.Client().Post(server.URL+oauthRegisterPath, "application/json", strings.NewReader(`{"client_name":"Droid post","redirect_uris":["`+clientRedirect+`"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_post"}`))
	if err != nil {
		t.Fatalf("POST client_secret_post register: %v", err)
	}
	defer func() { _ = postRegisterResp.Body.Close() }()
	if postRegisterResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(postRegisterResp.Body)
		t.Fatalf("client_secret_post register status = %d body=%s", postRegisterResp.StatusCode, body)
	}
	var postClient mcpoauth.ClientRegistrationResponse
	if err := json.NewDecoder(postRegisterResp.Body).Decode(&postClient); err != nil {
		t.Fatalf("decode client_secret_post response: %v", err)
	}
	if postClient.ClientID == "" || postClient.ClientSecret == "" || postClient.TokenEndpointAuthMethod != "client_secret_post" {
		t.Fatalf("client_secret_post client = %#v", postClient)
	}
	postSecretResp := exchangeMCPOAuthTokenRaw(t, server, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {postClient.ClientID},
		"client_secret": {postClient.ClientSecret},
		"resource":      {"https://cerebro.example/api/v1/mcp"},
		"refresh_token": {"refresh_dummy"},
	})
	_ = postSecretResp.Body.Close()
	if postSecretResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("client_secret_post token status = %d, want 400 invalid_grant", postSecretResp.StatusCode)
	}
}

func TestMCPOAuthDynamicClientRegistrationRateLimitsByClientIP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	cfg := testMCPOAuthConfig("http://127.0.0.1:39123/callback", upstream.URL)
	cfg.Auth.MCPOAuth.Clients = nil
	app, err := NewWithError(cfg, Dependencies{StateStore: newMemoryMCPOAuthStore()}, nil)
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	handler := app.Handler()
	body := `{"client_name":"Droid","redirect_uris":["http://127.0.0.1:39123/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}`
	for i := 0; i < oauthRegisterBurst; i++ {
		req := httptest.NewRequest(http.MethodPost, oauthRegisterPath, strings.NewReader(body))
		req.RemoteAddr = "198.51.100.10:12345"
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusCreated {
			t.Fatalf("registration %d status = %d body=%s, want 201", i+1, resp.Code, resp.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, oauthRegisterPath, strings.NewReader(body))
	req.RemoteAddr = "198.51.100.10:12345"
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited registration status = %d body=%s, want 429", resp.Code, resp.Body.String())
	}
}

func TestMCPOAuthAuditTelemetryIncludesSafeTokenShape(t *testing.T) {
	cfg := testMCPOAuthConfig("http://127.0.0.1:39123/callback", "https://writer-sso.example")
	app := &App{cfg: cfg}
	form := url.Values{
		"grant_type": {"authorization_code"},
		"client_id":  {"droid"},
		"resource":   {"https://cerebro.example/api/v1/mcp"},
		"scope":      {scopeCosmoSecurityRead},
		"code":       {"test-code"},
	}
	req := httptest.NewRequest(http.MethodPost, oauthTokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("droid:test-client-credential")))
	req.Header.Set("X-Request-ID", "oauth-req-1")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	stderr := captureBootstrapStderr(t, func() {
		app.emitOAuthAuditEvent(req, "token", http.StatusBadRequest, "rejected", "invalid_target", "droid", time.Now())
	})
	payload := decodeBootstrapTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"name":                       "cerebro.oauth.mcp",
		"operation":                  "token",
		"outcome":                    "rejected",
		"status_code":                float64(http.StatusBadRequest),
		"reason":                     "invalid_target",
		"request_id":                 "oauth-req-1",
		"oauth.grant_type":           "authorization_code",
		"oauth.client_auth_method":   "client_secret_basic",
		"oauth.resource_present":     true,
		"oauth.resource_matches_mcp": true,
		"oauth.scope_count":          float64(1),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	for _, key := range []string{"resource", "code", "client_secret", "access_token", "refresh_token"} {
		if _, exists := payload[key]; exists {
			t.Fatalf("telemetry recorded sensitive OAuth field %q: %#v", key, payload)
		}
	}
}

func TestMCPOAuthAuditTelemetryIncludesSafeRegistrationShape(t *testing.T) {
	app := &App{cfg: testMCPOAuthConfig("http://127.0.0.1:39123/callback", "https://writer-sso.example")}
	request := mcpoauth.ClientRegistrationRequest{
		ClientName:              "Droid",
		RedirectURIs:            []string{"http://127.0.0.1:39123/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}
	req := httptest.NewRequest(http.MethodPost, oauthRegisterPath, nil)

	stderr := captureBootstrapStderr(t, func() {
		app.emitOAuthAuditEvent(req, "register", http.StatusCreated, "success", "", "mcp_client_redacted", time.Now(), oauthAuditRegistrationFields(request)...)
	})
	payload := decodeBootstrapTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"name":                      "cerebro.oauth.mcp",
		"operation":                 "register",
		"outcome":                   "success",
		"status_code":               float64(http.StatusCreated),
		"oauth.redirect_uri_count":  float64(1),
		"oauth.grant_type_count":    float64(2),
		"oauth.response_type_count": float64(1),
		"oauth.client_auth_method":  "none",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	for _, key := range []string{"redirect_uris", "client_name", "client_secret"} {
		if _, exists := payload[key]; exists {
			t.Fatalf("telemetry recorded raw registration field %q: %#v", key, payload)
		}
	}
}

func TestMCPOAuthAuditTelemetryIncludesSafeRevocationShape(t *testing.T) {
	app := &App{cfg: testMCPOAuthConfig("http://127.0.0.1:39123/callback", "https://writer-sso.example")}
	form := url.Values{
		"client_id":       {"droid"},
		"token":           {"test-token"},
		"token_type_hint": {"refresh_token"},
	}
	req := httptest.NewRequest(http.MethodPost, oauthRevokePath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	stderr := captureBootstrapStderr(t, func() {
		app.emitOAuthAuditEvent(req, "revoke", http.StatusOK, "success", "", "droid", time.Now())
	})
	payload := decodeBootstrapTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"name":                          "cerebro.oauth.mcp",
		"operation":                     "revoke",
		"outcome":                       "success",
		"status_code":                   float64(http.StatusOK),
		"oauth.client_auth_method":      "none",
		"oauth.token_type_hint_present": true,
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	for _, key := range []string{"token", "token_type_hint", "client_secret", "access_token", "refresh_token"} {
		if _, exists := payload[key]; exists {
			t.Fatalf("telemetry recorded sensitive revocation field %q: %#v", key, payload)
		}
	}
}

func testMCPOAuthConfig(clientRedirect string, upstreamBase string) config.Config {
	return config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled:                 true,
			CapabilityTokenSecrets:  []string{"capability-secret"},
			CapabilityTokenAudience: "cerebro-api",
			RequestOrigin: config.RequestOriginConfig{
				PublicOrigin: "https://cerebro.example",
			},
			MCPOAuth: config.MCPOAuthConfig{
				Enabled:                   true,
				Issuer:                    "https://cerebro.example",
				Resource:                  "https://cerebro.example/api/v1/mcp",
				AccessTTL:                 time.Hour,
				RefreshTTL:                24 * time.Hour,
				CodeTTL:                   5 * time.Minute,
				StateTTL:                  5 * time.Minute,
				TenantID:                  "writer",
				DynamicClientRegistration: true,
				Clients: []config.MCPOAuthClient{{
					ClientID:     "droid",
					RedirectURIs: []string{clientRedirect},
					Public:       true,
				}},
				Upstream: config.MCPOAuthUpstreamConfig{
					Issuer:                "https://writer-sso.example",
					AuthorizationEndpoint: upstreamBase + "/authorize",
					TokenEndpoint:         upstreamBase + "/token",
					JWKSURI:               upstreamBase + "/jwks",
					ClientID:              "writer-client",
					ClientSecret:          "writer-secret",
					RedirectURI:           "https://cerebro.example/oauth/callback",
					Scopes:                []string{"openid", "email", "profile", "groups"},
					GroupsClaim:           "groups",
					SecurityGroups:        []string{"secops"},
				},
			},
		},
	}
}

func exchangeMCPOAuthToken(t *testing.T, server *httptest.Server, form url.Values) mcpoauth.TokenResponse {
	t.Helper()
	resp := exchangeMCPOAuthTokenRaw(t, server, form)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token status = %d body=%s", resp.StatusCode, body)
	}
	var decoded mcpoauth.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return decoded
}

func exchangeMCPOAuthTokenRaw(t *testing.T, server *httptest.Server, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server.URL+oauthTokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest token: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	return resp
}

func revokeMCPOAuthTokenRaw(t *testing.T, server *httptest.Server, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server.URL+oauthRevokePath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest revoke: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST revoke: %v", err)
	}
	return resp
}

func noRedirectClient(server *httptest.Server) *http.Client {
	base := server.Client()
	return &http.Client{
		Transport:     base.Transport,
		Timeout:       base.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type memoryMCPOAuthStore struct {
	mu       sync.Mutex
	clients  map[string]mcpoauth.OAuthClient
	states   map[string]memoryState
	codes    map[string]memoryCode
	refresh  map[string]memoryRefresh
	families map[string]bool
}

type memoryState struct {
	value    mcpoauth.LoginState
	consumed bool
}

type memoryCode struct {
	value    mcpoauth.AuthorizationCode
	consumed bool
}

type memoryRefresh struct {
	value    mcpoauth.RefreshToken
	consumed bool
}

func newMemoryMCPOAuthStore() *memoryMCPOAuthStore {
	return &memoryMCPOAuthStore{
		clients:  map[string]mcpoauth.OAuthClient{},
		states:   map[string]memoryState{},
		codes:    map[string]memoryCode{},
		refresh:  map[string]memoryRefresh{},
		families: map[string]bool{},
	}
}

func (s *memoryMCPOAuthStore) Ping(context.Context) error { return nil }

func (s *memoryMCPOAuthStore) SaveOAuthClient(_ context.Context, client mcpoauth.OAuthClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[client.ClientID] = client
	return nil
}

func (s *memoryMCPOAuthStore) GetOAuthClient(_ context.Context, clientID string) (mcpoauth.OAuthClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.clients[clientID]
	if !ok {
		return mcpoauth.OAuthClient{}, mcpoauth.ErrNotFound
	}
	return client, nil
}

func (s *memoryMCPOAuthStore) SaveLoginState(_ context.Context, state mcpoauth.LoginState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[hashKey(state.StateHash)] = memoryState{value: state}
	return nil
}

func (s *memoryMCPOAuthStore) ConsumeLoginState(_ context.Context, stateHash [32]byte, now time.Time) (mcpoauth.LoginState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(stateHash)
	record, ok := s.states[key]
	if !ok {
		return mcpoauth.LoginState{}, mcpoauth.ErrNotFound
	}
	if record.consumed {
		return mcpoauth.LoginState{}, mcpoauth.ErrConsumed
	}
	if !now.Before(record.value.ExpiresAt) {
		return mcpoauth.LoginState{}, mcpoauth.ErrExpired
	}
	record.consumed = true
	s.states[key] = record
	return record.value, nil
}

func (s *memoryMCPOAuthStore) SaveAuthorizationCode(_ context.Context, code mcpoauth.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[hashKey(code.CodeHash)] = memoryCode{value: code}
	return nil
}

func (s *memoryMCPOAuthStore) ConsumeAuthorizationCode(_ context.Context, codeHash [32]byte, now time.Time) (mcpoauth.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(codeHash)
	record, ok := s.codes[key]
	if !ok {
		return mcpoauth.AuthorizationCode{}, mcpoauth.ErrNotFound
	}
	if record.consumed {
		return mcpoauth.AuthorizationCode{}, mcpoauth.ErrConsumed
	}
	if !now.Before(record.value.ExpiresAt) {
		return mcpoauth.AuthorizationCode{}, mcpoauth.ErrExpired
	}
	record.consumed = true
	s.codes[key] = record
	return record.value, nil
}

func (s *memoryMCPOAuthStore) SaveOAuthRefreshToken(_ context.Context, token mcpoauth.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[hashKey(token.TokenHash)] = memoryRefresh{value: token}
	return nil
}

func (s *memoryMCPOAuthStore) ConsumeOAuthRefreshToken(_ context.Context, tokenHash [32]byte, now time.Time) (mcpoauth.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(tokenHash)
	record, ok := s.refresh[key]
	if !ok {
		return mcpoauth.RefreshToken{}, mcpoauth.ErrNotFound
	}
	if s.families[record.value.FamilyID] || record.consumed {
		s.families[record.value.FamilyID] = true
		return mcpoauth.RefreshToken{}, mcpoauth.ErrReplay
	}
	if !now.Before(record.value.ExpiresAt) {
		return mcpoauth.RefreshToken{}, mcpoauth.ErrExpired
	}
	record.consumed = true
	s.refresh[key] = record
	return record.value, nil
}

func (s *memoryMCPOAuthStore) RevokeOAuthRefreshFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.families[familyID] = true
	return nil
}

func (s *memoryMCPOAuthStore) RevokeOAuthRefreshToken(_ context.Context, tokenHash [32]byte, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.refresh[hashKey(tokenHash)]
	if !ok || record.value.ClientID != clientID {
		return nil
	}
	s.families[record.value.FamilyID] = true
	return nil
}

func hashKey(hash [32]byte) string {
	return hex.EncodeToString(hash[:])
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func signOIDCIDToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	return signOIDCIDTokenWithKID(t, key, "test-kid", claims)
}

func signOIDCIDTokenWithKID(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func rsaJWK(kid string, key *rsa.PublicKey) map[string]string {
	exponent := big.NewInt(int64(key.E)).Bytes()
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(exponent),
	}
}

func TestMCPOAuthTokenEndpointRejectsPKCEMismatch(t *testing.T) {
	store := newMemoryMCPOAuthStore()
	code, err := mcpoauth.NewOpaqueToken("code")
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}
	store.codes[hashKey(mcpoauth.HashToken(code))] = memoryCode{value: mcpoauth.AuthorizationCode{
		CodeHash:      mcpoauth.HashToken(code),
		ClientID:      "droid",
		RedirectURI:   "http://127.0.0.1/callback",
		Resource:      "https://cerebro.example/api/v1/mcp",
		Subject:       "user@example.com",
		TenantID:      "writer",
		Scopes:        []string{scopeCosmoSecurityRead},
		Groups:        []string{"security"},
		CodeChallenge: pkceChallenge(strings.Repeat("a", 64)),
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Minute),
	}}
	app, err := NewWithError(testMCPOAuthConfig("http://127.0.0.1/callback", "http://127.0.0.1"), Dependencies{StateStore: store}, nil)
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	resp := exchangeMCPOAuthTokenRaw(t, server, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"droid"},
		"redirect_uri":  {"http://127.0.0.1/callback"},
		"resource":      {"https://cerebro.example/api/v1/mcp"},
		"code":          {code},
		"code_verifier": {strings.Repeat("b", 64)},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PKCE mismatch status = %d body=%s", resp.StatusCode, body)
	}
}
