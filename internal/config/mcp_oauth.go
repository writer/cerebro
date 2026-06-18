package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultMCPOAuthAccessTTL  = 10 * time.Minute
	defaultMCPOAuthRefreshTTL = 24 * time.Hour
	defaultMCPOAuthCodeTTL    = 5 * time.Minute
	defaultMCPOAuthStateTTL   = 10 * time.Minute
)

func loadMCPOAuthConfig(publicOrigin string) (MCPOAuthConfig, error) {
	enabled, err := parseBoolEnv("CEREBRO_MCP_OAUTH_ENABLED")
	if err != nil {
		return MCPOAuthConfig{}, err
	}
	cfg := MCPOAuthConfig{
		Enabled:        enabled,
		Issuer:         strings.TrimRight(strings.TrimSpace(os.Getenv("CEREBRO_MCP_OAUTH_ISSUER")), "/"),
		Resource:       strings.TrimSpace(os.Getenv("CEREBRO_MCP_OAUTH_RESOURCE")),
		TenantID:       strings.TrimSpace(os.Getenv("CEREBRO_MCP_OAUTH_TENANT_ID")),
		AllowedTenants: parseCSV(os.Getenv("CEREBRO_MCP_OAUTH_ALLOWED_TENANTS")),
		Upstream: MCPOAuthUpstreamConfig{
			Issuer:                strings.TrimRight(strings.TrimSpace(os.Getenv("CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER")), "/"),
			AuthorizationEndpoint: strings.TrimSpace(os.Getenv("CEREBRO_MCP_OAUTH_UPSTREAM_AUTHORIZATION_ENDPOINT")),
			TokenEndpoint:         strings.TrimSpace(os.Getenv("CEREBRO_MCP_OAUTH_UPSTREAM_TOKEN_ENDPOINT")),
			JWKSURI:               strings.TrimSpace(os.Getenv("CEREBRO_MCP_OAUTH_UPSTREAM_JWKS_URI")),
			ClientID:              strings.TrimSpace(os.Getenv("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID")),
			ClientSecret:          strings.TrimSpace(os.Getenv("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET")),
			RedirectURI:           strings.TrimSpace(os.Getenv("CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI")),
			Scopes:                parseCSV(os.Getenv("CEREBRO_MCP_OAUTH_UPSTREAM_SCOPES")),
			GroupsClaim:           strings.TrimSpace(os.Getenv("CEREBRO_MCP_OAUTH_UPSTREAM_GROUPS_CLAIM")),
			SecurityGroups:        parseCSV(os.Getenv("CEREBRO_MCP_OAUTH_SECURITY_GROUPS")),
		},
	}
	if cfg.Issuer == "" {
		cfg.Issuer = strings.TrimRight(strings.TrimSpace(publicOrigin), "/")
	}
	if cfg.Resource == "" && strings.TrimSpace(publicOrigin) != "" {
		cfg.Resource = strings.TrimRight(strings.TrimSpace(publicOrigin), "/") + "/api/v1/mcp"
	}
	if cfg.Upstream.GroupsClaim == "" {
		cfg.Upstream.GroupsClaim = "groups"
	}
	if len(cfg.Upstream.Scopes) == 0 {
		cfg.Upstream.Scopes = []string{"openid", "email", "profile", "groups"}
	}
	if cfg.AccessTTL, err = parseDurationEnv("CEREBRO_MCP_OAUTH_ACCESS_TTL", defaultMCPOAuthAccessTTL); err != nil {
		return MCPOAuthConfig{}, err
	}
	if cfg.RefreshTTL, err = parseDurationEnv("CEREBRO_MCP_OAUTH_REFRESH_TTL", defaultMCPOAuthRefreshTTL); err != nil {
		return MCPOAuthConfig{}, err
	}
	if cfg.CodeTTL, err = parseDurationEnv("CEREBRO_MCP_OAUTH_CODE_TTL", defaultMCPOAuthCodeTTL); err != nil {
		return MCPOAuthConfig{}, err
	}
	if cfg.StateTTL, err = parseDurationEnv("CEREBRO_MCP_OAUTH_STATE_TTL", defaultMCPOAuthStateTTL); err != nil {
		return MCPOAuthConfig{}, err
	}
	if cfg.DynamicClientRegistration, err = parseBoolEnv("CEREBRO_MCP_OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED"); err != nil {
		return MCPOAuthConfig{}, err
	}
	clientsRaw, err := readConfigValue("CEREBRO_MCP_OAUTH_CLIENTS_JSON")
	if err != nil {
		return MCPOAuthConfig{}, err
	}
	clients, err := parseMCPOAuthClients(clientsRaw)
	if err != nil {
		return MCPOAuthConfig{}, err
	}
	cfg.Clients = clients
	entitlementsRaw, err := readConfigValue("CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON")
	if err != nil {
		return MCPOAuthConfig{}, err
	}
	entitlements, err := parseMCPOAuthEntitlements(entitlementsRaw)
	if err != nil {
		return MCPOAuthConfig{}, err
	}
	cfg.Entitlements = entitlements
	if cfg.Enabled {
		if err := validateMCPOAuthConfig(cfg); err != nil {
			return MCPOAuthConfig{}, err
		}
	}
	return cfg, nil
}

func parseMCPOAuthClients(raw string) ([]MCPOAuthClient, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var clients []MCPOAuthClient
	if err := json.Unmarshal([]byte(raw), &clients); err != nil {
		return nil, fmt.Errorf("parse CEREBRO_MCP_OAUTH_CLIENTS_JSON: %w", err)
	}
	for index := range clients {
		clients[index].ClientID = strings.TrimSpace(clients[index].ClientID)
		clients[index].ClientSecret = strings.TrimSpace(clients[index].ClientSecret)
		clients[index].ClientSecretSHA256 = strings.ToLower(strings.TrimSpace(clients[index].ClientSecretSHA256))
		clients[index].Name = strings.TrimSpace(clients[index].Name)
		clients[index].RedirectURIs = normalizeStringSlice(clients[index].RedirectURIs)
		var err error
		clients[index].GrantTypes, err = normalizeOAuthGrantTypes(clients[index].GrantTypes)
		if err != nil {
			return nil, fmt.Errorf("CEREBRO_MCP_OAUTH_CLIENTS_JSON[%d]: %w", index, err)
		}
		clients[index].TenantID = strings.TrimSpace(clients[index].TenantID)
		clients[index].AllowedTenants = normalizeStringSlice(clients[index].AllowedTenants)
		clients[index].Scopes = normalizeStringSlice(clients[index].Scopes)
		clients[index].Roles = normalizeStringSlice(clients[index].Roles)
		clients[index].Groups = normalizeStringSlice(clients[index].Groups)
		if clients[index].ClientID == "" {
			return nil, fmt.Errorf("CEREBRO_MCP_OAUTH_CLIENTS_JSON[%d] requires client_id", index)
		}
		if clients[index].Public && (clients[index].ClientSecret != "" || clients[index].ClientSecretSHA256 != "") {
			return nil, fmt.Errorf("CEREBRO_MCP_OAUTH_CLIENTS_JSON[%d] must not set client_secret or client_secret_sha256 when public=true", index)
		}
		if clients[index].ClientSecret == "" && clients[index].ClientSecretSHA256 == "" {
			clients[index].Public = true
		}
		if containsString(clients[index].GrantTypes, "client_credentials") && clients[index].Public {
			return nil, fmt.Errorf("CEREBRO_MCP_OAUTH_CLIENTS_JSON[%d] must set client_secret or client_secret_sha256 for client_credentials", index)
		}
		if clients[index].ClientSecretSHA256 != "" && !validSHA256Hex(clients[index].ClientSecretSHA256) {
			return nil, fmt.Errorf("CEREBRO_MCP_OAUTH_CLIENTS_JSON[%d] client_secret_sha256 must be a SHA-256 hex digest", index)
		}
		if err := validateKnownRBACRoles(fmt.Sprintf("CEREBRO_MCP_OAUTH_CLIENTS_JSON[%d].roles", index), clients[index].Roles); err != nil {
			return nil, err
		}
		if containsString(clients[index].GrantTypes, "client_credentials") && clients[index].TenantID == "" && len(clients[index].AllowedTenants) == 0 {
			return nil, fmt.Errorf("CEREBRO_MCP_OAUTH_CLIENTS_JSON[%d] requires tenant_id or allowed_tenants for client_credentials", index)
		}
		if containsString(clients[index].GrantTypes, "authorization_code") && len(clients[index].RedirectURIs) == 0 {
			return nil, fmt.Errorf("CEREBRO_MCP_OAUTH_CLIENTS_JSON[%d] requires at least one redirect_uri", index)
		}
		for _, redirectURI := range clients[index].RedirectURIs {
			if err := validateAbsoluteHTTPURL("redirect_uri", redirectURI); err != nil {
				return nil, fmt.Errorf("CEREBRO_MCP_OAUTH_CLIENTS_JSON[%d]: %w", index, err)
			}
		}
	}
	return clients, nil
}

func parseMCPOAuthEntitlements(raw string) ([]MCPOAuthEntitlement, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var entitlements []MCPOAuthEntitlement
	if err := json.Unmarshal([]byte(raw), &entitlements); err != nil {
		return nil, fmt.Errorf("parse CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON: %w", err)
	}
	for index := range entitlements {
		entitlements[index].Subject = strings.TrimSpace(entitlements[index].Subject)
		entitlements[index].Email = strings.TrimSpace(entitlements[index].Email)
		entitlements[index].ClientID = strings.TrimSpace(entitlements[index].ClientID)
		entitlements[index].Groups = normalizeStringSlice(entitlements[index].Groups)
		entitlements[index].TenantID = strings.TrimSpace(entitlements[index].TenantID)
		entitlements[index].AllowedTenants = normalizeStringSlice(entitlements[index].AllowedTenants)
		entitlements[index].Scopes = normalizeStringSlice(entitlements[index].Scopes)
		entitlements[index].Roles = normalizeStringSlice(entitlements[index].Roles)
		if entitlements[index].Subject == "" && entitlements[index].Email == "" && entitlements[index].ClientID == "" && len(entitlements[index].Groups) == 0 {
			return nil, fmt.Errorf("CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON[%d] requires subject, email, client_id, or groups", index)
		}
		if entitlements[index].TenantID == "" && len(entitlements[index].AllowedTenants) == 0 {
			return nil, fmt.Errorf("CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON[%d] requires tenant_id or allowed_tenants", index)
		}
		if err := validateKnownRBACRoles(fmt.Sprintf("CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON[%d].roles", index), entitlements[index].Roles); err != nil {
			return nil, err
		}
	}
	return entitlements, nil
}

func normalizeOAuthGrantTypes(values []string) ([]string, error) {
	values = normalizeStringSlice(values)
	if len(values) == 0 {
		return []string{"authorization_code", "refresh_token"}, nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		switch value {
		case "authorization_code", "refresh_token", "client_credentials":
		default:
			return nil, fmt.Errorf("unsupported grant_type %q", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return []string{"authorization_code", "refresh_token"}, nil
	}
	return out, nil
}

func validateMCPOAuthConfig(cfg MCPOAuthConfig) error {
	if cfg.Issuer == "" {
		return fmt.Errorf("CEREBRO_MCP_OAUTH_ISSUER or CEREBRO_PUBLIC_ORIGIN is required when CEREBRO_MCP_OAUTH_ENABLED=true")
	}
	if err := validateAbsoluteHTTPOrigin("CEREBRO_MCP_OAUTH_ISSUER", cfg.Issuer); err != nil {
		return err
	}
	if cfg.Resource == "" {
		return fmt.Errorf("CEREBRO_MCP_OAUTH_RESOURCE or CEREBRO_PUBLIC_ORIGIN is required when CEREBRO_MCP_OAUTH_ENABLED=true")
	}
	if err := validateAbsoluteHTTPURL("CEREBRO_MCP_OAUTH_RESOURCE", cfg.Resource); err != nil {
		return err
	}
	if len(cfg.Clients) == 0 && !cfg.DynamicClientRegistration {
		return fmt.Errorf("CEREBRO_MCP_OAUTH_CLIENTS_JSON or CEREBRO_MCP_OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED=true is required when CEREBRO_MCP_OAUTH_ENABLED=true")
	}
	if requiresInteractiveEntitlement(cfg) && cfg.TenantID == "" && len(cfg.AllowedTenants) == 0 && len(cfg.Entitlements) == 0 {
		return fmt.Errorf("CEREBRO_MCP_OAUTH_TENANT_ID, CEREBRO_MCP_OAUTH_ALLOWED_TENANTS, or CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON is required for authorization_code when CEREBRO_MCP_OAUTH_ENABLED=true")
	}
	if !requiresInteractiveEntitlement(cfg) && !hasClientCredentialsTenantGrant(cfg.Clients) {
		return fmt.Errorf("client_credentials clients require tenant_id or allowed_tenants when CEREBRO_MCP_OAUTH_ENABLED=true")
	}
	if cfg.Upstream.Issuer == "" {
		return fmt.Errorf("CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER is required when CEREBRO_MCP_OAUTH_ENABLED=true")
	}
	if err := validateAbsoluteHTTPOrigin("CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER", cfg.Upstream.Issuer); err != nil {
		return err
	}
	if cfg.Upstream.ClientID == "" {
		return fmt.Errorf("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID is required when CEREBRO_MCP_OAUTH_ENABLED=true")
	}
	if cfg.Upstream.ClientSecret == "" {
		return fmt.Errorf("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET is required when CEREBRO_MCP_OAUTH_ENABLED=true")
	}
	if cfg.Upstream.RedirectURI == "" {
		return fmt.Errorf("CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI is required when CEREBRO_MCP_OAUTH_ENABLED=true")
	}
	if err := validateAbsoluteHTTPURL("CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI", cfg.Upstream.RedirectURI); err != nil {
		return err
	}
	if len(cfg.Upstream.SecurityGroups) == 0 {
		return fmt.Errorf("CEREBRO_MCP_OAUTH_SECURITY_GROUPS is required when CEREBRO_MCP_OAUTH_ENABLED=true")
	}
	if cfg.Upstream.AuthorizationEndpoint != "" {
		if err := validateAbsoluteHTTPURL("CEREBRO_MCP_OAUTH_UPSTREAM_AUTHORIZATION_ENDPOINT", cfg.Upstream.AuthorizationEndpoint); err != nil {
			return err
		}
	}
	if cfg.Upstream.TokenEndpoint != "" {
		if err := validateAbsoluteHTTPURL("CEREBRO_MCP_OAUTH_UPSTREAM_TOKEN_ENDPOINT", cfg.Upstream.TokenEndpoint); err != nil {
			return err
		}
	}
	if cfg.Upstream.JWKSURI != "" {
		if err := validateAbsoluteHTTPURL("CEREBRO_MCP_OAUTH_UPSTREAM_JWKS_URI", cfg.Upstream.JWKSURI); err != nil {
			return err
		}
	}
	return nil
}

func hasClientCredentialsTenantGrant(clients []MCPOAuthClient) bool {
	for _, client := range clients {
		if containsString(client.GrantTypes, "client_credentials") && (client.TenantID != "" || len(client.AllowedTenants) > 0) {
			return true
		}
	}
	return false
}

func requiresInteractiveEntitlement(cfg MCPOAuthConfig) bool {
	if cfg.DynamicClientRegistration {
		return true
	}
	for _, client := range cfg.Clients {
		if containsString(client.GrantTypes, "authorization_code") {
			return true
		}
	}
	return false
}

func validateAbsoluteHTTPOrigin(name string, raw string) error {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%s must be an http(s) origin", name)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("%s must use http or https", name)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Trim(parsed.Path, "/") != "" {
		return fmt.Errorf("%s must not include user info, path, query, or fragment", name)
	}
	if parsed.Scheme != "https" && !isLoopbackOAuthHost(parsed.Hostname()) {
		return fmt.Errorf("%s must use https unless it targets loopback", name)
	}
	return nil
}

func validateAbsoluteHTTPURL(name string, raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%s must be an absolute http(s) URL", name)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("%s must use http or https", name)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%s must not include user info or fragment", name)
	}
	if parsed.Scheme != "https" && !isLoopbackOAuthHost(parsed.Hostname()) {
		return fmt.Errorf("%s must use https unless it targets loopback", name)
	}
	return nil
}

func isLoopbackOAuthHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
