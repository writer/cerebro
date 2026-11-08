package vulnview

import (
	"errors"
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
	defaultScope    = "vulnview"
	defaultFamily   = familyVulnerability
	defaultPageSize = 100
	maxPageSize     = 500
)

var (
	errMissingTenantID       = errors.New("missing vulnview tenant_id")
	errUnsupportedFamily     = errors.New("unsupported vulnview family")
	errMissingBaseURL        = errors.New("missing vulnview base_url")
	errMissingClientID       = errors.New("missing vulnview client_id")
	errMissingClientSecret   = errors.New("missing vulnview client_secret")
	errInvalidURLComponents  = errors.New("invalid vulnview url components")
	errInvalidBaseComponents = errors.New("invalid vulnview base_url components")
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
		return resolved, fmt.Errorf("%w: vulnview tenant_id is required", errMissingTenantID)
	}
	if resolved.family == "" {
		resolved.family = defaultFamily
	}
	if !isSupportedFamily(resolved.family) {
		return resolved, fmt.Errorf("%w: vulnview family must be one of %s", errUnsupportedFamily, strings.Join(supportedFamilies(), ", "))
	}
	if resolved.baseURL == "" {
		return resolved, fmt.Errorf("%w: vulnview base_url is required", errMissingBaseURL)
	}
	normalizedBase, err := sourcecdk.NormalizeTrustedURL("vulnview", "base_url", resolved.baseURL, allowLoopback, errInvalidBaseComponents)
	if err != nil {
		return resolved, err
	}
	resolved.baseURL = normalizedBase
	if err := validateBaseURL(cfg, resolved.baseURL, allowLoopback); err != nil {
		return resolved, err
	}
	if resolved.scope == "" {
		resolved.scope = defaultScope
	}
	if resolved.clientID == "" {
		return resolved, fmt.Errorf("%w: vulnview client_id is required", errMissingClientID)
	}
	if resolved.clientSecret == "" {
		return resolved, fmt.Errorf("%w: vulnview client_secret is required", errMissingClientSecret)
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
	normalizedTokenURL, err := sourcecdk.NormalizeTrustedURL("vulnview", "url", resolved.tokenURL, allowLoopback, errInvalidURLComponents)
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

func validateBaseURL(cfg sourcecdk.Config, baseURL string, allowLoopback bool) error {
	if allowLoopback {
		return nil
	}
	return sourcecdk.RequireTrustedOriginFromDeploymentAllowlist(cfg, sourceID, "base_url", "VulnView", baseURL)
}

func validateTokenURL(cfg sourcecdk.Config, tokenURL string, allowLoopback bool) error {
	issuer := strings.TrimRight(sourcecdk.ConfigValue(cfg, "okta_issuer"), "/")
	if issuer == "" {
		if allowLoopback {
			return nil
		}
		return fmt.Errorf("vulnview okta_issuer is required")
	}
	return sourcecdk.RequireIssuerTokenURL("vulnview", "okta_issuer", issuer, "/v1/token", tokenURL, allowLoopback)
}
