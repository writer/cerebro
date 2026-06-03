package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/mcpoauth"
)

const (
	oauthProtectedResourceMetadataPath          = "/.well-known/oauth-protected-resource"
	oauthProtectedResourceMetadataMCPPath       = "/.well-known/oauth-protected-resource/api/v1/mcp"
	oauthAuthorizationServerMetadataPath        = "/.well-known/oauth-authorization-server"
	oauthAuthorizePath                          = "/oauth/authorize"
	oauthCallbackPath                           = "/oauth/callback"
	oauthTokenPath                              = "/oauth/token"
	oauthRegisterPath                           = "/oauth/register"
	oauthMaxFormBytes                     int64 = 1 << 20
	oauthRegisterRatePerSecond                  = 0.2
	oauthRegisterBurst                          = 5
)

func (app *App) handleOAuthProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	cfg := app.cfg.Auth.MCPOAuth
	resource := strings.TrimSpace(cfg.Resource)
	if resource == "" {
		resource = externalOrigin(r, app.cfg.Auth.RequestOrigin) + mcpEndpointPath
	}
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		issuer = externalOrigin(r, app.cfg.Auth.RequestOrigin)
	}
	writeOAuthJSON(w, http.StatusOK, map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{issuer},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{scopeCosmoSecurityRead},
	})
}

func (app *App) handleOAuthAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	cfg := app.cfg.Auth.MCPOAuth
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		issuer = externalOrigin(r, app.cfg.Auth.RequestOrigin)
	}
	metadata := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + oauthAuthorizePath,
		"token_endpoint":                        issuer + oauthTokenPath,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"scopes_supported":                      []string{scopeCosmoSecurityRead},
		"resource_indicators_supported":         true,
	}
	if cfg.DynamicClientRegistration {
		metadata["registration_endpoint"] = issuer + oauthRegisterPath
	}
	writeOAuthJSON(w, http.StatusOK, metadata)
}

func (app *App) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if app.mcpOAuthService == nil {
		writeOAuthError(w, mcpoauthOAuthError("server_error", "MCP OAuth is not configured", http.StatusServiceUnavailable))
		return
	}
	redirectURL, err := app.mcpOAuthService.Authorize(r.Context(), r.URL.Query())
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (app *App) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if app.mcpOAuthService == nil {
		writeOAuthError(w, mcpoauthOAuthError("server_error", "MCP OAuth is not configured", http.StatusServiceUnavailable))
		return
	}
	redirectURL, err := app.mcpOAuthService.Callback(r.Context(), r.URL.Query())
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (app *App) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if app.mcpOAuthService == nil {
		writeOAuthError(w, mcpoauthOAuthError("server_error", "MCP OAuth is not configured", http.StatusServiceUnavailable))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, oauthMaxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, mcpoauthOAuthError("invalid_request", "invalid form body", http.StatusBadRequest))
		return
	}
	response, err := app.mcpOAuthService.Token(r.Context(), r.Header.Get("Authorization"), r.PostForm)
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeOAuthJSON(w, http.StatusOK, response)
}

func (app *App) handleOAuthRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if app.mcpOAuthService == nil {
		writeOAuthError(w, mcpoauthOAuthError("server_error", "MCP OAuth is not configured", http.StatusServiceUnavailable))
		return
	}
	if app.mcpOAuthRegisterLimit != nil {
		origin := resolveRequestOrigin(r, app.cfg.Auth.RequestOrigin)
		clientIP := firstNonEmpty(origin.ClientIP, "unknown")
		if !app.mcpOAuthRegisterLimit.Allow(clientIP) {
			writeOAuthError(w, mcpoauthOAuthError("rate_limited", "too many dynamic client registration attempts", http.StatusTooManyRequests))
			return
		}
	}
	defer func() { _ = r.Body.Close() }()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, oauthMaxFormBytes))
	var request mcpoauth.ClientRegistrationRequest
	if err := decoder.Decode(&request); err != nil {
		writeOAuthError(w, mcpoauthOAuthError("invalid_client_metadata", "invalid JSON body", http.StatusBadRequest))
		return
	}
	response, err := app.mcpOAuthService.RegisterClient(r.Context(), request)
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeOAuthJSON(w, http.StatusCreated, response)
}

func writeOAuthJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeOAuthError(w http.ResponseWriter, err error) {
	var oauthErr *mcpoauth.OAuthError
	if !errors.As(err, &oauthErr) {
		oauthErr = mcpoauthOAuthError("server_error", "OAuth request failed", http.StatusInternalServerError)
	}
	if oauthErr.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="cerebro-oauth"`)
	}
	writeOAuthJSON(w, oauthErr.Status, map[string]string{
		"error":             oauthErr.Code,
		"error_description": oauthErr.Description,
	})
}

func mcpoauthOAuthError(code string, description string, status int) *mcpoauth.OAuthError {
	return &mcpoauth.OAuthError{Code: code, Description: description, Status: status}
}

func externalOrigin(r *http.Request, cfg config.RequestOriginConfig) string {
	origin := resolveRequestOrigin(r, cfg)
	return origin.Scheme + "://" + origin.Host
}

func mcpOAuthResourceMetadataURL(r *http.Request, cfg config.AuthConfig) string {
	return externalOrigin(r, cfg.RequestOrigin) + oauthProtectedResourceMetadataMCPPath
}
