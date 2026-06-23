package grc

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
)

type settings struct {
	provider     string
	tenantID     string
	family       string
	baseURL      string
	tokenURL     string
	clientID     string
	clientSecret string
	scope        string
	perPage      int
}

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettings(cfg, s != nil && s.allowLoopbackBaseURL)
}

func parseSettings(cfg sourcecdk.Config, allowLoopbackBaseURL bool) (settings, error) {
	resolved := settings{
		provider:     sourcecdk.ConfigValue(cfg, "provider"),
		tenantID:     firstNonEmptyString(sourcecdk.ConfigValue(cfg, "tenant_id"), sourcecdk.ConfigValue(cfg, "__cerebro_runtime_tenant_id")),
		family:       sourcecdk.ConfigValue(cfg, "family"),
		baseURL:      sourcecdk.ConfigValue(cfg, "base_url"),
		tokenURL:     sourcecdk.ConfigValue(cfg, "token_url"),
		clientID:     sourcecdk.ConfigValue(cfg, "client_id"),
		clientSecret: sourcecdk.ConfigValue(cfg, "client_secret"),
		scope:        sourcecdk.ConfigValue(cfg, "scope"),
		perPage:      defaultPageSize,
	}
	if resolved.provider == "" {
		resolved.provider = defaultProvider
	}
	if resolved.family == "" {
		resolved.family = defaultFamily
	}
	if resolved.baseURL == "" {
		resolved.baseURL = defaultBaseURL
	}
	if resolved.scope == "" {
		resolved.scope = defaultReadScope
	}
	if resolved.tenantID == "" {
		return resolved, fmt.Errorf("grc tenant_id is required")
	}
	if resolved.provider != defaultProvider {
		return resolved, fmt.Errorf("grc provider %q is not supported", resolved.provider)
	}
	if !isSupportedFamily(resolved.family) {
		return resolved, fmt.Errorf("grc family must be one of %s", strings.Join(supportedFamilies(), ", "))
	}
	normalizedBase, err := normalizeBaseURL(resolved.baseURL, allowLoopbackBaseURL)
	if err != nil {
		return resolved, err
	}
	if err := validateTrustedVantaOrigin(normalizedBase, allowLoopbackBaseURL); err != nil {
		return resolved, err
	}
	resolved.baseURL = normalizedBase
	if resolved.tokenURL == "" {
		resolved.tokenURL = normalizedBase + "/oauth/token"
	} else {
		normalizedTokenURL, err := normalizeAbsoluteURL(resolved.tokenURL, allowLoopbackBaseURL)
		if err != nil {
			return resolved, err
		}
		if err := validateTrustedVantaOrigin(normalizedTokenURL, allowLoopbackBaseURL); err != nil {
			return resolved, err
		}
		resolved.tokenURL = normalizedTokenURL
	}
	if resolved.clientID == "" {
		return resolved, fmt.Errorf("grc client_id is required")
	}
	if resolved.clientSecret == "" {
		return resolved, fmt.Errorf("grc client_secret is required")
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return resolved, fmt.Errorf("parse grc per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return resolved, fmt.Errorf("grc per_page must be between 1 and %d", maxPageSize)
		}
		resolved.perPage = perPage
	}
	return resolved, nil
}

func supportedFamilies() []string {
	return []string{
		familyFramework,
		familyControl,
		familyControlTest,
		familyPolicy,
		familyDocument,
		familyVendor,
		familyVulnerability,
		familyVulnerableAsset,
		familyRiskScenario,
		familyPerson,
		familyUser,
		familyIntegration,
	}
}

func isSupportedFamily(family string) bool {
	for _, candidate := range supportedFamilies() {
		if family == candidate {
			return true
		}
	}
	return false
}

func normalizeBaseURL(raw string, allowLoopback bool) (string, error) {
	normalized, err := normalizeAbsoluteURL(raw, allowLoopback)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(normalized, "/"), nil
}

func normalizeAbsoluteURL(raw string, allowLoopback bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse grc url: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	allowInsecureLoopback := allowLoopback && parsed.Scheme == "http" && sourcecdk.IsLoopbackHost(host)
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", fmt.Errorf("grc url must use https")
	}
	if host == "" {
		return "", fmt.Errorf("grc url must include a host")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func validateTrustedVantaOrigin(raw string, allowLoopback bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("parse grc url: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if allowLoopback && sourcecdk.IsLoopbackHost(host) {
		return nil
	}
	if host == "api.vanta.com" || host == "api.eu.vanta.com" {
		return nil
	}
	return fmt.Errorf("grc Vanta host %q is not trusted", host)
}
