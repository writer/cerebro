package vulnview

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func (settings settings) query() url.Values {
	query := url.Values{}
	sourcecdk.AddQueryParam(query, "siteId", settings.siteID)
	sourcecdk.AddQueryParam(query, "scanName", settings.scanName)
	sourcecdk.AddQueryParam(query, "name", settings.scanName)
	sourcecdk.AddQueryParam(query, "severity", settings.severity)
	sourcecdk.AddQueryParam(query, "search", settings.search)
	return query
}

const (
	defaultBaseURL  = "https://vulnview.writer-security.com/api"
	defaultScope    = "vulnview"
	defaultFamily   = familyVulnerability
	defaultPageSize = 100
	maxPageSize     = 500
)

type settings struct {
	tenantID     string
	family       string
	baseURL      string
	tokenURL     string
	clientID     string
	clientSecret string
	scope        string
	siteID       string
	scanName     string
	severity     string
	search       string
	perPage      int
}

type responseError struct {
	statusCode int
	message    string
}

func (e *responseError) Error() string {
	return e.message
}

func (e *responseError) StatusCode() int {
	return e.statusCode
}

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettings(cfg, s != nil && s.allowLoopbackBaseURL)
}

func parseSettings(cfg sourcecdk.Config, allowLoopback bool) (settings, error) {
	resolved := settings{
		tenantID:     firstNonEmpty(sourcecdk.ConfigValue(cfg, "tenant_id"), sourcecdk.ConfigValue(cfg, "__cerebro_runtime_tenant_id")),
		family:       sourcecdk.ConfigValue(cfg, "family"),
		baseURL:      sourcecdk.ConfigValue(cfg, "base_url"),
		tokenURL:     sourcecdk.ConfigValue(cfg, "token_url"),
		clientID:     sourcecdk.ConfigValue(cfg, "client_id"),
		clientSecret: sourcecdk.ConfigValue(cfg, "client_secret"),
		scope:        sourcecdk.ConfigValue(cfg, "scope"),
		siteID:       sourcecdk.ConfigValue(cfg, "site_id"),
		scanName:     sourcecdk.ConfigValue(cfg, "scan_name"),
		severity:     strings.ToLower(sourcecdk.ConfigValue(cfg, "severity")),
		search:       sourcecdk.ConfigValue(cfg, "search"),
		perPage:      defaultPageSize,
	}
	if resolved.tenantID == "" {
		return resolved, fmt.Errorf("vulnview tenant_id is required")
	}
	if resolved.family == "" {
		resolved.family = defaultFamily
	}
	if !isSupportedFamily(resolved.family) {
		return resolved, fmt.Errorf("vulnview family must be one of %s", strings.Join(supportedFamilies(), ", "))
	}
	if resolved.baseURL == "" {
		resolved.baseURL = defaultBaseURL
	}
	normalizedBase, err := normalizeBaseURL(resolved.baseURL, allowLoopback)
	if err != nil {
		return resolved, err
	}
	resolved.baseURL = normalizedBase
	if err := validateBaseURL(resolved.baseURL, allowLoopback); err != nil {
		return resolved, err
	}
	if resolved.scope == "" {
		resolved.scope = defaultScope
	}
	if resolved.clientID == "" {
		return resolved, fmt.Errorf("vulnview client_id is required")
	}
	if resolved.clientSecret == "" {
		return resolved, fmt.Errorf("vulnview client_secret is required")
	}
	issuer := strings.TrimRight(sourcecdk.ConfigValue(cfg, "okta_issuer"), "/")
	if issuer == "" && !allowLoopback {
		return resolved, fmt.Errorf("vulnview okta_issuer is required")
	}
	if resolved.tokenURL == "" {
		if issuer == "" {
			return resolved, fmt.Errorf("vulnview okta_issuer or token_url is required")
		}
		resolved.tokenURL = issuer + "/v1/token"
	}
	normalizedTokenURL, err := normalizeAbsoluteURL(resolved.tokenURL, allowLoopback)
	if err != nil {
		return resolved, err
	}
	resolved.tokenURL = normalizedTokenURL
	if err := validateTokenURL(cfg, resolved.tokenURL, allowLoopback); err != nil {
		return resolved, err
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return resolved, fmt.Errorf("parse vulnview per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return resolved, fmt.Errorf("vulnview per_page must be between 1 and %d", maxPageSize)
		}
		resolved.perPage = perPage
	}
	return resolved, nil
}

func validateBaseURL(baseURL string, allowLoopback bool) error {
	if allowLoopback {
		return nil
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse vulnview base_url: %w", err)
	}
	trusted, err := url.Parse(defaultBaseURL)
	if err != nil {
		return fmt.Errorf("parse default VulnView base_url: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, trusted.Scheme) || !strings.EqualFold(parsed.Host, trusted.Host) {
		return fmt.Errorf("vulnview base_url must use the trusted VulnView origin")
	}
	return nil
}

func validateTokenURL(cfg sourcecdk.Config, tokenURL string, allowLoopback bool) error {
	issuer := strings.TrimRight(sourcecdk.ConfigValue(cfg, "okta_issuer"), "/")
	if issuer == "" {
		if allowLoopback {
			return nil
		}
		return fmt.Errorf("vulnview okta_issuer is required")
	}
	expected, err := normalizeAbsoluteURL(issuer+"/v1/token", allowLoopback)
	if err != nil {
		return err
	}
	if tokenURL != expected {
		return fmt.Errorf("vulnview token_url must match okta_issuer token endpoint")
	}
	return nil
}

func normalizeBaseURL(raw string, allowLoopback bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse vulnview base_url: %w", err)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.User != nil {
		return "", fmt.Errorf("vulnview base_url must not include user info, query, or fragment")
	}
	normalized, err := normalizeParsedURL(parsed, allowLoopback)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(normalized, "/"), nil
}

func normalizeAbsoluteURL(raw string, allowLoopback bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse vulnview url: %w", err)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.User != nil {
		return "", fmt.Errorf("vulnview url must not include user info, query, or fragment")
	}
	return normalizeParsedURL(parsed, allowLoopback)
}

func normalizeParsedURL(parsed *url.URL, allowLoopback bool) (string, error) {
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	allowInsecureLoopback := allowLoopback && parsed.Scheme == "http" && sourcecdk.IsLoopbackHost(host)
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", fmt.Errorf("vulnview url must use https")
	}
	if host == "" {
		return "", fmt.Errorf("vulnview url must include a host")
	}
	allowCustomPort := allowLoopback && sourcecdk.IsLoopbackHost(host)
	if strings.TrimSpace(parsed.Port()) != "" && parsed.Port() != "443" && !allowCustomPort {
		return "", fmt.Errorf("vulnview url must not include a custom port")
	}
	if sourcecdk.IsUnsafeHost(host) && (!allowLoopback || !sourcecdk.IsLoopbackHost(host)) {
		return "", fmt.Errorf("vulnview url must not target loopback, private, or link-local hosts")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}
