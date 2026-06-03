package mcpoauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/config"
)

// AccessGrant is the claim set Cerebro places into an MCP capability token.
type AccessGrant struct {
	Subject        string
	Email          string
	ClientID       string
	Resource       string
	TenantID       string
	AllowedTenants []string
	Scopes         []string
	Groups         []string
}

// AccessTokenIssuer mints a signed bearer access token for an OAuth grant.
type AccessTokenIssuer func(context.Context, AccessGrant, time.Duration, time.Time) (string, error)

type Service struct {
	cfg        config.MCPOAuthConfig
	store      Store
	oidc       OIDCProvider
	issueToken AccessTokenIssuer
	now        func() time.Time
}

type ServiceOption func(*Service)

func WithOIDCProvider(provider OIDCProvider) ServiceOption {
	return func(s *Service) {
		if provider != nil {
			s.oidc = provider
		}
	}
}

func WithNow(now func() time.Time) ServiceOption {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

func NewService(cfg config.MCPOAuthConfig, store Store, issueToken AccessTokenIssuer, opts ...ServiceOption) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("mcpoauth: store is required")
	}
	if issueToken == nil {
		return nil, fmt.Errorf("mcpoauth: access token issuer is required")
	}
	s := &Service{
		cfg:        cfg,
		store:      store,
		issueToken: issueToken,
		now:        time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.oidc == nil {
		return nil, fmt.Errorf("mcpoauth: OIDC provider is required")
	}
	return s, nil
}

const (
	statusBadRequest          = 400
	statusUnauthorized        = 401
	statusForbidden           = 403
	statusInternalServerError = 500
	statusBadGateway          = 502
)

type OAuthError struct {
	Code        string
	Description string
	Status      int
}

func (e *OAuthError) Error() string {
	if e == nil {
		return ""
	}
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

func oauthError(code string, description string, status int) *OAuthError {
	if status == 0 {
		status = statusBadRequest
	}
	return &OAuthError{Code: code, Description: description, Status: status}
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type ClientRegistrationRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

func (s *Service) RegisterClient(ctx context.Context, request ClientRegistrationRequest) (ClientRegistrationResponse, error) {
	if !s.cfg.DynamicClientRegistration {
		return ClientRegistrationResponse{}, oauthError("invalid_request", "dynamic client registration is disabled", statusBadRequest)
	}
	redirectURIs := normalizeStrings(request.RedirectURIs)
	if len(redirectURIs) == 0 {
		return ClientRegistrationResponse{}, oauthError("invalid_client_metadata", "redirect_uris is required", statusBadRequest)
	}
	for _, redirectURI := range redirectURIs {
		if !validDynamicRedirectURI(redirectURI) {
			return ClientRegistrationResponse{}, oauthError("invalid_redirect_uri", "dynamic clients may only register loopback redirect URIs", statusBadRequest)
		}
	}
	if !grantTypesAllowed(request.GrantTypes) {
		return ClientRegistrationResponse{}, oauthError("invalid_client_metadata", "grant_types must be authorization_code and optional refresh_token", statusBadRequest)
	}
	if !responseTypesAllowed(request.ResponseTypes) {
		return ClientRegistrationResponse{}, oauthError("invalid_client_metadata", "response_types must be code", statusBadRequest)
	}
	method := strings.TrimSpace(request.TokenEndpointAuthMethod)
	if method == "" {
		method = "none"
	}
	if method != "none" {
		return ClientRegistrationResponse{}, oauthError("invalid_client_metadata", "only public clients with token_endpoint_auth_method=none are supported", statusBadRequest)
	}
	clientID, err := NewOpaqueToken("mcp_client")
	if err != nil {
		return ClientRegistrationResponse{}, fmt.Errorf("mcpoauth: generate dynamic client id: %w", err)
	}
	client := OAuthClient{
		ClientID:     clientID,
		Name:         strings.TrimSpace(request.ClientName),
		RedirectURIs: redirectURIs,
		Public:       true,
		CreatedAt:    s.now().UTC(),
	}
	if err := s.store.SaveOAuthClient(ctx, client); err != nil {
		return ClientRegistrationResponse{}, fmt.Errorf("mcpoauth: save dynamic client: %w", err)
	}
	return ClientRegistrationResponse{
		ClientID:                clientID,
		ClientName:              client.Name,
		RedirectURIs:            cloneStrings(client.RedirectURIs),
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}, nil
}

func (s *Service) Authorize(ctx context.Context, query url.Values) (string, error) {
	if query.Get("response_type") != "code" {
		return "", oauthError("unsupported_response_type", "response_type must be code", statusBadRequest)
	}
	client, ok := s.client(ctx, query.Get("client_id"))
	if !ok {
		return "", oauthError("unauthorized_client", "unknown OAuth client", statusBadRequest)
	}
	redirectURI := strings.TrimSpace(query.Get("redirect_uri"))
	if !redirectURIAllowed(client, redirectURI) {
		return "", oauthError("invalid_request", "redirect_uri is not registered for client", statusBadRequest)
	}
	clientState := strings.TrimSpace(query.Get("state"))
	if clientState == "" {
		return "", oauthError("invalid_request", "state is required", statusBadRequest)
	}
	resource := strings.TrimSpace(query.Get("resource"))
	if resource == "" {
		resource = s.cfg.Resource
	}
	if resource != s.cfg.Resource {
		return "", oauthError("invalid_target", "resource is not this MCP server", statusBadRequest)
	}
	scopes, err := normalizeRequestedScopes(query.Get("scope"))
	if err != nil {
		return "", err
	}
	codeChallenge := strings.TrimSpace(query.Get("code_challenge"))
	if codeChallenge == "" || query.Get("code_challenge_method") != "S256" {
		return "", oauthError("invalid_request", "PKCE S256 code_challenge is required", statusBadRequest)
	}
	stateToken, err := NewOpaqueToken("state")
	if err != nil {
		return "", fmt.Errorf("mcpoauth: generate state: %w", err)
	}
	nonce, err := NewOpaqueToken("nonce")
	if err != nil {
		return "", fmt.Errorf("mcpoauth: generate nonce: %w", err)
	}
	now := s.now().UTC()
	if err := s.store.SaveLoginState(ctx, LoginState{
		StateHash:     HashToken(stateToken),
		ClientID:      client.ClientID,
		RedirectURI:   redirectURI,
		ClientState:   clientState,
		Resource:      resource,
		Scopes:        scopes,
		CodeChallenge: codeChallenge,
		Nonce:         nonce,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.cfg.StateTTL),
	}); err != nil {
		return "", fmt.Errorf("mcpoauth: save login state: %w", err)
	}
	authEndpoint, err := s.oidc.AuthorizationEndpoint(ctx)
	if err != nil {
		return "", err
	}
	upstream := url.Values{}
	upstream.Set("response_type", "code")
	upstream.Set("client_id", s.cfg.Upstream.ClientID)
	upstream.Set("redirect_uri", s.cfg.Upstream.RedirectURI)
	upstream.Set("scope", strings.Join(s.cfg.Upstream.Scopes, " "))
	upstream.Set("state", stateToken)
	upstream.Set("nonce", nonce)
	return appendQuery(authEndpoint, upstream), nil
}

func (s *Service) Callback(ctx context.Context, query url.Values) (string, error) {
	if upstreamErr := strings.TrimSpace(query.Get("error")); upstreamErr != "" {
		return "", oauthError("access_denied", upstreamErr, statusBadRequest)
	}
	stateToken, err := NormalizeOpaqueToken(query.Get("state"))
	if err != nil {
		return "", oauthError("invalid_request", "state is required", statusBadRequest)
	}
	upstreamCode := strings.TrimSpace(query.Get("code"))
	if upstreamCode == "" {
		return "", oauthError("invalid_request", "code is required", statusBadRequest)
	}
	login, err := s.store.ConsumeLoginState(ctx, HashToken(stateToken), s.now().UTC())
	if err != nil {
		return "", tokenStoreError("invalid_request", "login state is invalid", err)
	}
	identity, err := s.oidc.ExchangeCode(ctx, upstreamCode, login.Nonce)
	if err != nil {
		return "", err
	}
	if !containsAny(identity.Groups, s.cfg.Upstream.SecurityGroups) {
		return "", oauthError("access_denied", "authenticated user is not in an authorized security group", statusForbidden)
	}
	codeToken, err := NewOpaqueToken("code")
	if err != nil {
		return "", fmt.Errorf("mcpoauth: generate code: %w", err)
	}
	now := s.now().UTC()
	if err := s.store.SaveAuthorizationCode(ctx, AuthorizationCode{
		CodeHash:       HashToken(codeToken),
		ClientID:       login.ClientID,
		RedirectURI:    login.RedirectURI,
		Resource:       login.Resource,
		Subject:        firstNonEmpty(identity.Email, identity.Subject),
		Email:          identity.Email,
		TenantID:       strings.TrimSpace(s.cfg.TenantID),
		AllowedTenants: cloneStrings(s.cfg.AllowedTenants),
		Scopes:         cloneStrings(login.Scopes),
		Groups:         []string{"security"},
		CodeChallenge:  login.CodeChallenge,
		CreatedAt:      now,
		ExpiresAt:      now.Add(s.cfg.CodeTTL),
	}); err != nil {
		return "", fmt.Errorf("mcpoauth: save authorization code: %w", err)
	}
	redirect, err := url.Parse(login.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("mcpoauth: parse client redirect uri: %w", err)
	}
	values := redirect.Query()
	values.Set("code", codeToken)
	values.Set("state", login.ClientState)
	redirect.RawQuery = values.Encode()
	return redirect.String(), nil
}

func (s *Service) Token(ctx context.Context, authorizationHeader string, form url.Values) (TokenResponse, error) {
	client, err := s.authenticateClient(ctx, authorizationHeader, form)
	if err != nil {
		return TokenResponse{}, err
	}
	resource, err := s.tokenRequestResource(form)
	if err != nil {
		return TokenResponse{}, err
	}
	switch form.Get("grant_type") {
	case "authorization_code":
		return s.exchangeAuthorizationCode(ctx, client, resource, form)
	case "refresh_token":
		return s.exchangeRefreshToken(ctx, client, resource, form)
	default:
		return TokenResponse{}, oauthError("unsupported_grant_type", "grant_type must be authorization_code or refresh_token", statusBadRequest)
	}
}

func (s *Service) tokenRequestResource(form url.Values) (string, error) {
	resource := strings.TrimSpace(form.Get("resource"))
	if resource == "" {
		return "", oauthError("invalid_target", "resource is required", statusBadRequest)
	}
	if resource != s.cfg.Resource {
		return "", oauthError("invalid_target", "resource is not this MCP server", statusBadRequest)
	}
	return resource, nil
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, client config.MCPOAuthClient, resource string, form url.Values) (TokenResponse, error) {
	code, err := NormalizeOpaqueToken(form.Get("code"))
	if err != nil {
		return TokenResponse{}, oauthError("invalid_grant", "code is required", statusBadRequest)
	}
	redirectURI := strings.TrimSpace(form.Get("redirect_uri"))
	if !redirectURIAllowed(client, redirectURI) {
		return TokenResponse{}, oauthError("invalid_grant", "redirect_uri is invalid", statusBadRequest)
	}
	codeVerifier := strings.TrimSpace(form.Get("code_verifier"))
	if !validCodeVerifier(codeVerifier) {
		return TokenResponse{}, oauthError("invalid_grant", "code_verifier is invalid", statusBadRequest)
	}
	record, err := s.store.ConsumeAuthorizationCode(ctx, HashToken(code), s.now().UTC())
	if err != nil {
		return TokenResponse{}, tokenStoreError("invalid_grant", "authorization code is invalid", err)
	}
	if record.ClientID != client.ClientID || record.RedirectURI != redirectURI {
		return TokenResponse{}, oauthError("invalid_grant", "authorization code was issued to a different client", statusBadRequest)
	}
	if record.Resource != resource {
		return TokenResponse{}, oauthError("invalid_target", "authorization code was issued for a different resource", statusBadRequest)
	}
	if !verifyPKCES256(codeVerifier, record.CodeChallenge) {
		return TokenResponse{}, oauthError("invalid_grant", "PKCE verification failed", statusBadRequest)
	}
	return s.issueTokenPair(ctx, refreshGrantFromCode(record, ""), 0)
}

func (s *Service) exchangeRefreshToken(ctx context.Context, client config.MCPOAuthClient, resource string, form url.Values) (TokenResponse, error) {
	refreshToken, err := NormalizeOpaqueToken(form.Get("refresh_token"))
	if err != nil {
		return TokenResponse{}, oauthError("invalid_grant", "refresh_token is required", statusBadRequest)
	}
	record, err := s.store.ConsumeOAuthRefreshToken(ctx, HashToken(refreshToken), s.now().UTC())
	if err != nil {
		if errors.Is(err, ErrReplay) && strings.TrimSpace(record.FamilyID) != "" {
			_ = s.store.RevokeOAuthRefreshFamily(ctx, record.FamilyID)
		}
		return TokenResponse{}, tokenStoreError("invalid_grant", "refresh token is invalid", err)
	}
	if record.ClientID != client.ClientID {
		_ = s.store.RevokeOAuthRefreshFamily(ctx, record.FamilyID)
		return TokenResponse{}, oauthError("invalid_grant", "refresh token was issued to a different client", statusBadRequest)
	}
	if record.Resource != resource {
		_ = s.store.RevokeOAuthRefreshFamily(ctx, record.FamilyID)
		return TokenResponse{}, oauthError("invalid_target", "refresh token was issued for a different resource", statusBadRequest)
	}
	return s.issueTokenPair(ctx, refreshGrantFromRefresh(record), record.Generation+1)
}

func (s *Service) issueTokenPair(ctx context.Context, grant RefreshToken, generation int) (TokenResponse, error) {
	now := s.now().UTC()
	access, err := s.issueToken(ctx, AccessGrant{
		Subject:        grant.Subject,
		Email:          grant.Email,
		ClientID:       grant.ClientID,
		Resource:       grant.Resource,
		TenantID:       grant.TenantID,
		AllowedTenants: cloneStrings(grant.AllowedTenants),
		Scopes:         cloneStrings(grant.Scopes),
		Groups:         cloneStrings(grant.Groups),
	}, s.cfg.AccessTTL, now)
	if err != nil {
		return TokenResponse{}, err
	}
	refreshPlain, err := NewOpaqueToken("refresh")
	if err != nil {
		return TokenResponse{}, fmt.Errorf("mcpoauth: generate refresh token: %w", err)
	}
	familyID := strings.TrimSpace(grant.FamilyID)
	if familyID == "" {
		familyID, err = NewFamilyID()
		if err != nil {
			return TokenResponse{}, fmt.Errorf("mcpoauth: generate refresh family: %w", err)
		}
	}
	if err := s.store.SaveOAuthRefreshToken(ctx, RefreshToken{
		TokenHash:      HashToken(refreshPlain),
		ClientID:       grant.ClientID,
		Resource:       grant.Resource,
		Subject:        grant.Subject,
		Email:          grant.Email,
		TenantID:       grant.TenantID,
		AllowedTenants: cloneStrings(grant.AllowedTenants),
		Scopes:         cloneStrings(grant.Scopes),
		Groups:         cloneStrings(grant.Groups),
		FamilyID:       familyID,
		Generation:     generation,
		CreatedAt:      now,
		ExpiresAt:      refreshExpiresAt(grant, now, s.cfg.RefreshTTL),
	}); err != nil {
		return TokenResponse{}, fmt.Errorf("mcpoauth: issue refresh token: %w", err)
	}
	return TokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.cfg.AccessTTL.Seconds()),
		RefreshToken: refreshPlain,
		Scope:        strings.Join(grant.Scopes, " "),
	}, nil
}

func refreshGrantFromCode(code AuthorizationCode, familyID string) RefreshToken {
	return RefreshToken{
		ClientID:       code.ClientID,
		Resource:       code.Resource,
		Subject:        code.Subject,
		Email:          code.Email,
		TenantID:       code.TenantID,
		AllowedTenants: cloneStrings(code.AllowedTenants),
		Scopes:         cloneStrings(code.Scopes),
		Groups:         cloneStrings(code.Groups),
		FamilyID:       familyID,
	}
}

func refreshGrantFromRefresh(token RefreshToken) RefreshToken {
	return RefreshToken{
		ClientID:       token.ClientID,
		Resource:       token.Resource,
		Subject:        token.Subject,
		Email:          token.Email,
		TenantID:       token.TenantID,
		AllowedTenants: cloneStrings(token.AllowedTenants),
		Scopes:         cloneStrings(token.Scopes),
		Groups:         cloneStrings(token.Groups),
		FamilyID:       token.FamilyID,
		ExpiresAt:      token.ExpiresAt,
	}
}

func refreshExpiresAt(grant RefreshToken, now time.Time, ttl time.Duration) time.Time {
	if !grant.ExpiresAt.IsZero() {
		return grant.ExpiresAt
	}
	return now.Add(ttl)
}

func (s *Service) authenticateClient(ctx context.Context, authorizationHeader string, form url.Values) (config.MCPOAuthClient, error) {
	clientID, secret, hasSecret := basicClientCredentials(authorizationHeader)
	if clientID == "" {
		clientID = strings.TrimSpace(form.Get("client_id"))
		secret = strings.TrimSpace(form.Get("client_secret"))
		hasSecret = secret != ""
	}
	client, ok := s.client(ctx, clientID)
	if !ok {
		return config.MCPOAuthClient{}, oauthError("invalid_client", "unknown OAuth client", statusUnauthorized)
	}
	if client.ClientSecret == "" {
		return client, nil
	}
	if !hasSecret || !constantTimeEqual(secret, client.ClientSecret) {
		return config.MCPOAuthClient{}, oauthError("invalid_client", "client authentication failed", statusUnauthorized)
	}
	return client, nil
}

func (s *Service) client(ctx context.Context, clientID string) (config.MCPOAuthClient, bool) {
	clientID = strings.TrimSpace(clientID)
	for _, client := range s.cfg.Clients {
		if client.ClientID == clientID {
			return client, true
		}
	}
	client, err := s.store.GetOAuthClient(ctx, clientID)
	if err == nil {
		return config.MCPOAuthClient{
			ClientID:     client.ClientID,
			ClientSecret: client.ClientSecret,
			Name:         client.Name,
			RedirectURIs: cloneStrings(client.RedirectURIs),
			Public:       client.Public,
		}, true
	}
	return config.MCPOAuthClient{}, false
}

func redirectURIAllowed(client config.MCPOAuthClient, redirectURI string) bool {
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		return false
	}
	for _, allowed := range client.RedirectURIs {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

func validDynamicRedirectURI(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func grantTypesAllowed(values []string) bool {
	values = normalizeStrings(values)
	if len(values) == 0 {
		return true
	}
	seenAuthCode := false
	for _, value := range values {
		switch value {
		case "authorization_code":
			seenAuthCode = true
		case "refresh_token":
		default:
			return false
		}
	}
	return seenAuthCode
}

func responseTypesAllowed(values []string) bool {
	values = normalizeStrings(values)
	if len(values) == 0 {
		return true
	}
	return len(values) == 1 && values[0] == "code"
}

func normalizeRequestedScopes(raw string) ([]string, error) {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 0 {
		return []string{ScopeSecurityRead}, nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(fields))
	for _, scope := range fields {
		if scope != ScopeSecurityRead {
			return nil, oauthError("invalid_scope", "requested scope is not supported", statusBadRequest)
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	if len(out) == 0 {
		return nil, oauthError("invalid_scope", "requested scope is not supported", statusBadRequest)
	}
	return out, nil
}

func validCodeVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, r := range verifier {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_' || r == '~':
		default:
			return false
		}
	}
	return true
}

func verifyPKCES256(verifier string, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	return constantTimeEqual(expected, strings.TrimSpace(challenge))
}

func basicClientCredentials(header string) (string, string, bool) {
	parts := strings.Fields(strings.TrimSpace(header))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", false
	}
	clientID, secret, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(clientID), secret, true
}

func tokenStoreError(code string, description string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrExpired), errors.Is(err, ErrConsumed), errors.Is(err, ErrReplay):
		return oauthError(code, description, statusBadRequest)
	default:
		return err
	}
}

func appendQuery(raw string, values url.Values) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	query := parsed.Query()
	for key, vals := range values {
		for _, value := range vals {
			query.Add(key, value)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func containsAny(values []string, allowed []string) bool {
	for _, value := range values {
		for _, allow := range allowed {
			if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(allow)) {
				return true
			}
		}
	}
	return false
}

func normalizeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func constantTimeEqual(a string, b string) bool {
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
