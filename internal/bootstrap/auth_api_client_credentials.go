package bootstrap

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/mcpoauth"
)

const defaultAPICapabilityTokenTTL = 10 * time.Minute

func (app *App) shouldHandleAPIClientCredentialsToken(r *http.Request) bool {
	if r == nil || r.Form == nil || strings.TrimSpace(r.Form.Get("grant_type")) != "client_credentials" {
		return false
	}
	resource := strings.TrimSpace(r.Form.Get("resource"))
	if tokenResourceMatchesAny(resource, apiCapabilityTokenResources(app.cfg.Auth, r)) {
		return true
	}
	return app.mcpOAuthService == nil
}

func (app *App) exchangeAPIClientCredentialsToken(_ context.Context, r *http.Request) (mcpoauth.TokenResponse, error) {
	if !app.cfg.Auth.Enabled || len(app.cfg.Auth.APICredentials) == 0 || len(app.cfg.Auth.CapabilityTokenSecrets) == 0 {
		return mcpoauth.TokenResponse{}, mcpoauthOAuthError("server_error", "Cerebro API client credentials are not configured", http.StatusServiceUnavailable)
	}
	resource := strings.TrimSpace(r.Form.Get("resource"))
	if resource == "" {
		return mcpoauth.TokenResponse{}, mcpoauthOAuthError("invalid_target", "resource is required", http.StatusBadRequest)
	}
	if !tokenResourceMatchesAny(resource, apiCapabilityTokenResources(app.cfg.Auth, r)) {
		return mcpoauth.TokenResponse{}, mcpoauthOAuthError("invalid_target", "resource is not this Cerebro API", http.StatusBadRequest)
	}
	clientID, secret, ok := oauthClientSecret(r)
	if !ok {
		return mcpoauth.TokenResponse{}, mcpoauthOAuthError("invalid_client", "confidential client authentication is required", http.StatusUnauthorized)
	}
	credential, ok := app.apiClientCredential(clientID, secret)
	if !ok {
		return mcpoauth.TokenResponse{}, mcpoauthOAuthError("invalid_client", "client authentication failed", http.StatusUnauthorized)
	}
	scopes, err := requestedAPICredentialScopes(r.Form, credential)
	if err != nil {
		return mcpoauth.TokenResponse{}, err
	}
	if strings.TrimSpace(credential.TenantID) == "" && len(credential.AllowedTenants) == 0 {
		return mcpoauth.TokenResponse{}, mcpoauthOAuthError("invalid_client", "client_credentials credential has no tenant grant", http.StatusUnauthorized)
	}
	now := time.Now().UTC()
	ttl := defaultAPICapabilityTokenTTL
	if app.cfg.Auth.MCPOAuth.AccessTTL > 0 {
		ttl = app.cfg.Auth.MCPOAuth.AccessTTL
	}
	access, err := issueCapabilityToken(app.cfg.Auth, capabilityClaims{
		Audience:       app.cfg.Auth.CapabilityTokenAudience,
		Subject:        "service:" + clientID,
		IssuedAt:       now.Unix(),
		CredentialID:   apiCredentialIdentifier(credential),
		ClientID:       clientID,
		Resource:       resource,
		TenantID:       credential.TenantID,
		AllowedTenants: cloneAuthValues(credential.AllowedTenants),
		Scopes:         scopes,
		Groups:         []string{"security"},
	}, ttl, now)
	if err != nil {
		return mcpoauth.TokenResponse{}, err
	}
	return mcpoauth.TokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int64(ttl.Seconds()),
		Scope:       strings.Join(scopes, " "),
	}, nil
}

func oauthClientSecret(r *http.Request) (string, string, bool) {
	if r == nil {
		return "", "", false
	}
	if clientID, secret, ok := r.BasicAuth(); ok {
		return strings.TrimSpace(clientID), strings.TrimSpace(secret), strings.TrimSpace(clientID) != "" && strings.TrimSpace(secret) != ""
	}
	if r.Form == nil {
		return "", "", false
	}
	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	secret := strings.TrimSpace(r.Form.Get("client_secret"))
	return clientID, secret, clientID != "" && secret != ""
}

func (app *App) apiClientCredential(clientID string, secret string) (config.APICredential, bool) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" || strings.TrimSpace(secret) == "" {
		return config.APICredential{}, false
	}
	for _, credential := range app.cfg.Auth.APICredentials {
		if strings.TrimSpace(credential.ClientID) != clientID {
			continue
		}
		if apiCredentialMatches(secret, credential) {
			return credential, true
		}
	}
	return config.APICredential{}, false
}

func requestedAPICredentialScopes(form url.Values, credential config.APICredential) ([]string, error) {
	allowed := normalizeAuthList(credential.Scopes)
	if len(allowed) == 0 {
		return nil, mcpoauthOAuthError("invalid_client", "client_credentials credential has no scopes", http.StatusUnauthorized)
	}
	requested := normalizeAuthList(strings.Fields(form.Get("scope")))
	if len(requested) == 0 {
		return cloneAuthValues(allowed), nil
	}
	for _, scope := range requested {
		if !containsAuthValue(allowed, scope) {
			return nil, mcpoauthOAuthError("invalid_scope", "requested scope is not allowed for client", http.StatusBadRequest)
		}
	}
	return requested, nil
}

func tokenResourceMatchesAny(resource string, allowed []string) bool {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return false
	}
	for _, candidate := range allowed {
		if resource == strings.TrimSpace(candidate) {
			return true
		}
	}
	return false
}

func apiCredentialIdentifier(credential config.APICredential) string {
	return firstNonEmpty(credential.ID, credential.ClientID, credential.Name, credential.Principal)
}

func cloneAuthValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}
