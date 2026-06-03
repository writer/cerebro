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
	enabled, err := parseBoolEnv("CEREBRO_MCP_OAUTH_ENABLED", false)
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
	if cfg.DynamicClientRegistration, err = parseBoolEnv("CEREBRO_MCP_OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED", true); err != nil {
		return MCPOAuthConfig{}, err
	}
	clients, err := parseMCPOAuthClients(os.Getenv("CEREBRO_MCP_OAUTH_CLIENTS_JSON"))
	if err != nil {
		return MCPOAuthConfig{}, err
	}
	cfg.Clients = clients
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
		clients[index].Name = strings.TrimSpace(clients[index].Name)
		clients[index].RedirectURIs = normalizeStringSlice(clients[index].RedirectURIs)
		if clients[index].ClientID == "" {
			return nil, fmt.Errorf("CEREBRO_MCP_OAUTH_CLIENTS_JSON[%d] requires client_id", index)
		}
		if clients[index].Public && clients[index].ClientSecret != "" {
			return nil, fmt.Errorf("CEREBRO_MCP_OAUTH_CLIENTS_JSON[%d] must not set client_secret when public=true", index)
		}
		if clients[index].ClientSecret == "" {
			clients[index].Public = true
		}
		if len(clients[index].RedirectURIs) == 0 {
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
	if cfg.TenantID == "" && len(cfg.AllowedTenants) == 0 {
		return fmt.Errorf("CEREBRO_MCP_OAUTH_TENANT_ID or CEREBRO_MCP_OAUTH_ALLOWED_TENANTS is required when CEREBRO_MCP_OAUTH_ENABLED=true")
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
