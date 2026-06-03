package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/mcpoauth"
	"github.com/writer/cerebro/internal/telemetry"
)

const (
	oauthProtectedResourceMetadataPath          = "/.well-known/oauth-protected-resource"
	oauthProtectedResourceMetadataMCPPath       = "/.well-known/oauth-protected-resource/api/v1/mcp"
	oauthAuthorizationServerMetadataPath        = "/.well-known/oauth-authorization-server"
	oauthAuthorizePath                          = "/oauth/authorize"
	oauthCallbackPath                           = "/oauth/callback"
	oauthTokenPath                              = "/oauth/token"
	oauthRevokePath                             = "/oauth/revoke"
	oauthRegisterPath                           = "/oauth/register"
	oauthMaxFormBytes                     int64 = 1 << 20
	oauthRegisterRatePerSecond                  = 0.2
	oauthRegisterBurst                          = 5
	oauthEndpointRatePerSecond                  = 2.0
	oauthEndpointBurst                          = 20
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
		"revocation_endpoint":                   issuer + oauthRevokePath,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
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
	started := time.Now()
	clientID := r.URL.Query().Get("client_id")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		app.emitOAuthAuditEvent(r, "authorize", http.StatusMethodNotAllowed, "rejected", "method_not_allowed", clientID, started)
		return
	}
	if app.mcpOAuthService == nil {
		writeOAuthError(w, mcpoauthOAuthError("server_error", "MCP OAuth is not configured", http.StatusServiceUnavailable))
		app.emitOAuthAuditEvent(r, "authorize", http.StatusServiceUnavailable, "error", "not_configured", clientID, started)
		return
	}
	if !app.allowOAuthEndpoint(w, r, "authorize", clientID, started) {
		return
	}
	redirectURL, err := app.mcpOAuthService.Authorize(r.Context(), r.URL.Query())
	if err != nil {
		writeOAuthError(w, err)
		app.emitOAuthAuditEvent(r, "authorize", oauthErrorStatus(err), oauthAuditOutcome(err), oauthErrorCode(err), clientID, started)
		return
	}
	app.emitOAuthAuditEvent(r, "authorize", http.StatusFound, "success", "", clientID, started)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (app *App) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		app.emitOAuthAuditEvent(r, "callback", http.StatusMethodNotAllowed, "rejected", "method_not_allowed", "", started)
		return
	}
	if app.mcpOAuthService == nil {
		writeOAuthError(w, mcpoauthOAuthError("server_error", "MCP OAuth is not configured", http.StatusServiceUnavailable))
		app.emitOAuthAuditEvent(r, "callback", http.StatusServiceUnavailable, "error", "not_configured", "", started)
		return
	}
	if !app.allowOAuthEndpoint(w, r, "callback", "", started) {
		return
	}
	redirectURL, err := app.mcpOAuthService.Callback(r.Context(), r.URL.Query())
	if err != nil {
		writeOAuthError(w, err)
		app.emitOAuthAuditEvent(r, "callback", oauthErrorStatus(err), oauthAuditOutcome(err), oauthErrorCode(err), "", started)
		return
	}
	app.emitOAuthAuditEvent(r, "callback", http.StatusFound, "success", "", "", started)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (app *App) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		app.emitOAuthAuditEvent(r, "token", http.StatusMethodNotAllowed, "rejected", "method_not_allowed", "", started)
		return
	}
	if app.mcpOAuthService == nil {
		writeOAuthError(w, mcpoauthOAuthError("server_error", "MCP OAuth is not configured", http.StatusServiceUnavailable))
		app.emitOAuthAuditEvent(r, "token", http.StatusServiceUnavailable, "error", "not_configured", "", started)
		return
	}
	if !app.allowOAuthEndpoint(w, r, "token", "", started) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, oauthMaxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, mcpoauthOAuthError("invalid_request", "invalid form body", http.StatusBadRequest))
		app.emitOAuthAuditEvent(r, "token", http.StatusBadRequest, "rejected", "invalid_request", "", started)
		return
	}
	clientID := r.Form.Get("client_id")
	response, err := app.mcpOAuthService.Token(r.Context(), r.Header.Get("Authorization"), r.Form)
	if err != nil {
		writeOAuthError(w, err)
		app.emitOAuthAuditEvent(r, "token", oauthErrorStatus(err), oauthAuditOutcome(err), oauthErrorCode(err), clientID, started)
		return
	}
	app.emitOAuthAuditEvent(r, "token", http.StatusOK, "success", "", clientID, started)
	writeOAuthJSON(w, http.StatusOK, response)
}

func (app *App) handleOAuthRevoke(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		app.emitOAuthAuditEvent(r, "revoke", http.StatusMethodNotAllowed, "rejected", "method_not_allowed", "", started)
		return
	}
	if app.mcpOAuthService == nil {
		writeOAuthError(w, mcpoauthOAuthError("server_error", "MCP OAuth is not configured", http.StatusServiceUnavailable))
		app.emitOAuthAuditEvent(r, "revoke", http.StatusServiceUnavailable, "error", "not_configured", "", started)
		return
	}
	if !app.allowOAuthEndpoint(w, r, "revoke", "", started) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, oauthMaxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, mcpoauthOAuthError("invalid_request", "invalid form body", http.StatusBadRequest))
		app.emitOAuthAuditEvent(r, "revoke", http.StatusBadRequest, "rejected", "invalid_request", "", started)
		return
	}
	clientID := r.Form.Get("client_id")
	if _, err := app.mcpOAuthService.Revoke(r.Context(), r.Header.Get("Authorization"), r.Form); err != nil {
		writeOAuthError(w, err)
		app.emitOAuthAuditEvent(r, "revoke", oauthErrorStatus(err), oauthAuditOutcome(err), oauthErrorCode(err), clientID, started)
		return
	}
	app.emitOAuthAuditEvent(r, "revoke", http.StatusOK, "success", "", clientID, started)
	w.WriteHeader(http.StatusOK)
}

func (app *App) handleOAuthRegister(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		app.emitOAuthAuditEvent(r, "register", http.StatusMethodNotAllowed, "rejected", "method_not_allowed", "", started)
		return
	}
	if app.mcpOAuthService == nil {
		writeOAuthError(w, mcpoauthOAuthError("server_error", "MCP OAuth is not configured", http.StatusServiceUnavailable))
		app.emitOAuthAuditEvent(r, "register", http.StatusServiceUnavailable, "error", "not_configured", "", started)
		return
	}
	if app.mcpOAuthRegisterLimit != nil {
		origin := resolveRequestOrigin(r, app.cfg.Auth.RequestOrigin)
		clientIP := firstNonEmpty(origin.ClientIP, "unknown")
		if !app.mcpOAuthRegisterLimit.Allow(clientIP) {
			writeOAuthError(w, mcpoauthOAuthError("rate_limited", "too many dynamic client registration attempts", http.StatusTooManyRequests))
			app.emitOAuthAuditEvent(r, "register", http.StatusTooManyRequests, "rejected", "rate_limited", "", started)
			return
		}
	}
	defer func() { _ = r.Body.Close() }()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, oauthMaxFormBytes))
	var request mcpoauth.ClientRegistrationRequest
	if err := decoder.Decode(&request); err != nil {
		app.emitOAuthAuditEvent(r, "register", http.StatusBadRequest, "rejected", "invalid_request", "", started)
		writeOAuthError(w, mcpoauthOAuthError("invalid_client_metadata", "invalid JSON body", http.StatusBadRequest))
		return
	}
	response, err := app.mcpOAuthService.RegisterClient(r.Context(), request)
	if err != nil {
		app.emitOAuthAuditEvent(r, "register", oauthErrorStatus(err), oauthAuditOutcome(err), oauthErrorCode(err), "", started)
		writeOAuthError(w, err)
		return
	}
	app.emitOAuthAuditEvent(r, "register", http.StatusCreated, "success", "", response.ClientID, started)
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

func (app *App) allowOAuthEndpoint(w http.ResponseWriter, r *http.Request, operation string, clientID string, started time.Time) bool {
	if app.mcpOAuthEndpointLimit == nil {
		return true
	}
	origin := resolveRequestOrigin(r, app.cfg.Auth.RequestOrigin)
	key := operation + ":" + firstNonEmpty(origin.ClientIP, "unknown")
	if !app.mcpOAuthEndpointLimit.Allow(key) {
		writeOAuthError(w, mcpoauthOAuthError("rate_limited", "too many OAuth requests", http.StatusTooManyRequests))
		app.emitOAuthAuditEvent(r, operation, http.StatusTooManyRequests, "rejected", "rate_limited", clientID, started)
		return false
	}
	return true
}

func (app *App) emitOAuthAuditEvent(r *http.Request, operation string, status int, outcome string, reason string, clientID string, started time.Time) {
	if r == nil {
		return
	}
	origin := resolveRequestOrigin(r, app.cfg.Auth.RequestOrigin)
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "operation", Value: strings.TrimSpace(operation)},
		telemetry.Field{Key: "outcome", Value: strings.TrimSpace(outcome)},
		telemetry.Field{Key: "status", Value: status},
		telemetry.Field{Key: "status_code", Value: status},
		telemetry.Field{Key: "method", Value: r.Method},
		telemetry.Field{Key: "route", Value: accessAuditRoute(r)},
		telemetry.Field{Key: "duration_ms", Value: time.Since(started).Milliseconds()},
	)
	if clientIP := strings.TrimSpace(origin.ClientIP); clientIP != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "client_ip", Value: clientIP})
	}
	if remoteIP := strings.TrimSpace(origin.RemoteIP); remoteIP != "" && remoteIP != strings.TrimSpace(origin.ClientIP) {
		attrs = attrs.WithField(telemetry.Field{Key: "remote_ip", Value: remoteIP})
	}
	if clientID = strings.TrimSpace(clientID); clientID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "client_id", Value: clientID})
	}
	if reason = strings.TrimSpace(reason); reason != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "reason", Value: reason})
	}
	telemetry.Event(r.Context(), "cerebro.oauth.mcp", attrs)
}

func oauthErrorStatus(err error) int {
	var oauthErr *mcpoauth.OAuthError
	if errors.As(err, &oauthErr) && oauthErr.Status != 0 {
		return oauthErr.Status
	}
	return http.StatusInternalServerError
}

func oauthErrorCode(err error) string {
	var oauthErr *mcpoauth.OAuthError
	if errors.As(err, &oauthErr) {
		return oauthErr.Code
	}
	return "server_error"
}

func oauthAuditOutcome(err error) string {
	status := oauthErrorStatus(err)
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return "denied"
	}
	if status >= 500 {
		return "error"
	}
	return "rejected"
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
