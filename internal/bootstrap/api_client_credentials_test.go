package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/mcpoauth"
)

func TestAPIClientCredentialsIssuesAPIResourceBoundCapabilityToken(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	cfg := apiClientCredentialsTestConfig()
	app, err := NewWithError(cfg, Dependencies{}, registry)
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	tokenResp := exchangeAPIClientCredentialsToken(t, server, "ci-client", "client-secret", url.Values{
		"grant_type": {"client_credentials"},
		"resource":   {"https://cerebro.example"},
		"scope":      {scopeCosmoSecurityRead},
	})
	if tokenResp.AccessToken == "" || tokenResp.RefreshToken != "" || tokenResp.TokenType != "Bearer" {
		t.Fatalf("token response = %#v", tokenResp)
	}

	staticSecretReq, err := http.NewRequest(http.MethodGet, server.URL+"/sources?tenant_id=writer", nil)
	if err != nil {
		t.Fatalf("NewRequest static secret sources: %v", err)
	}
	staticSecretReq.Header.Set("Authorization", "Bearer client-secret")
	staticSecretResp, err := server.Client().Do(staticSecretReq)
	if err != nil {
		t.Fatalf("GET /sources with static client secret: %v", err)
	}
	_ = staticSecretResp.Body.Close()
	if staticSecretResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /sources with static client secret status = %d, want 401", staticSecretResp.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, server.URL+"/sources?tenant_id=writer", nil)
	if err != nil {
		t.Fatalf("NewRequest sources: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /sources with API capability token: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /sources status = %d, want 200", resp.StatusCode)
	}

	mcpReq, err := http.NewRequest(http.MethodPost, server.URL+mcpEndpointPath, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatalf("NewRequest MCP: %v", err)
	}
	mcpReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	mcpReq.Header.Set("Content-Type", "application/json")
	mcpResp, err := server.Client().Do(mcpReq)
	if err != nil {
		t.Fatalf("POST MCP with API capability token: %v", err)
	}
	_ = mcpResp.Body.Close()
	if mcpResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("MCP status with API capability token = %d, want 401", mcpResp.StatusCode)
	}
}

func TestAPIClientCredentialsRejectsWrongSecret(t *testing.T) {
	app, err := NewWithError(apiClientCredentialsTestConfig(), Dependencies{}, nil)
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp := exchangeAPIClientCredentialsTokenRaw(t, server, "ci-client", "wrong-secret", url.Values{
		"grant_type": {"client_credentials"},
		"resource":   {"https://cerebro.example"},
		"scope":      {scopeCosmoSecurityRead},
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-secret token status = %d, want 401", resp.StatusCode)
	}
}

func TestResourceBoundCapabilityTokenCannotCrossSurfaces(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	cfg := apiClientCredentialsTestConfig()
	app, err := NewWithError(cfg, Dependencies{}, registry)
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	token, err := issueCapabilityToken(cfg.Auth, capabilityClaims{
		Audience:     cfg.Auth.CapabilityTokenAudience,
		Subject:      "service:mcp-client",
		Resource:     mcpCapabilityTokenResource,
		TenantID:     "writer",
		Scopes:       []string{scopeCosmoSecurityRead},
		Groups:       []string{"security"},
		CredentialID: "test-mcp-client",
		ClientID:     "mcp-client",
	}, time.Minute, time.Now())
	if err != nil {
		t.Fatalf("issueCapabilityToken: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, server.URL+"/sources?tenant_id=writer", nil)
	if err != nil {
		t.Fatalf("NewRequest sources: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /sources with MCP-bound token: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("API status with MCP-bound token = %d, want 401", resp.StatusCode)
	}
}

func apiClientCredentialsTestConfig() config.Config {
	return config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled:                 true,
			CapabilityTokenSecrets:  []string{"capability-secret"},
			CapabilityTokenAudience: "cerebro-api",
			APICredentials: []config.APICredential{{
				ID:        "ci-credential",
				ClientID:  "ci-client",
				Kind:      "oauth_client",
				KeySHA256: sha256Hex("client-secret"),
				Principal: "ci",
				TenantID:  "writer",
				Scopes:    []string{scopeCosmoSecurityRead},
			}},
			RequestOrigin: config.RequestOriginConfig{PublicOrigin: "https://cerebro.example"},
		},
	}
}

func exchangeAPIClientCredentialsToken(t *testing.T, server *httptest.Server, clientID string, secret string, form url.Values) mcpoauth.TokenResponse {
	t.Helper()
	resp := exchangeAPIClientCredentialsTokenRaw(t, server, clientID, secret, form)
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

func exchangeAPIClientCredentialsTokenRaw(t *testing.T, server *httptest.Server, clientID string, secret string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server.URL+oauthTokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest token: %v", err)
	}
	req.SetBasicAuth(clientID, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	return resp
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
