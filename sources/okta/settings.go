package okta

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	defaultPageSize     = 10
	maxPageSize         = 200
	defaultFamily       = familyAudit
	defaultAuditOrder   = "ASCENDING"
	defaultUserOrder    = "asc"
	familyAudit         = "audit"
	familyApplication   = "application"
	familyAppAssign     = "app_assignment"
	familyAdminRole     = "admin_role"
	familyAuthenticator = "authenticator"
	familyGroup         = "group"
	familyGroupMember   = "group_membership"
	familyIDP           = "identity_provider"
	familyNetworkZone   = "network_zone"
	familyPolicyRule    = "policy_rule"
	familyTrustedOrigin = "trusted_origin"
	familyUser          = "user"
)

type settings struct {
	family    string
	domain    string
	baseURL   string
	token     string
	filter    string
	q         string
	search    string
	sortBy    string
	sortOrder string
	since     string
	until     string
	groupID   string
	appID     string
	userID    string
	userEmail string
	perPage   int
}

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettings(cfg, s != nil && s.allowLoopbackBaseURL)
}

func parseSettings(cfg sourcecdk.Config, allowLoopbackBaseURL bool) (settings, error) {
	settings := settings{
		family:    sourcecdk.ConfigValue(cfg, "family"),
		domain:    sourcecdk.ConfigValue(cfg, "domain"),
		baseURL:   sourcecdk.ConfigValue(cfg, "base_url"),
		token:     sourcecdk.ConfigValue(cfg, "token"),
		filter:    sourcecdk.ConfigValue(cfg, "filter"),
		q:         sourcecdk.ConfigValue(cfg, "q"),
		search:    sourcecdk.ConfigValue(cfg, "search"),
		sortBy:    sourcecdk.ConfigValue(cfg, "sort_by"),
		sortOrder: sourcecdk.ConfigValue(cfg, "sort_order"),
		since:     sourcecdk.ConfigValue(cfg, "since"),
		until:     sourcecdk.ConfigValue(cfg, "until"),
		groupID:   sourcecdk.ConfigValue(cfg, "group_id"),
		appID:     sourcecdk.ConfigValue(cfg, "app_id"),
		userID:    sourcecdk.ConfigValue(cfg, "user_id"),
		userEmail: sourcecdk.ConfigValue(cfg, "user_email"),
		perPage:   defaultPageSize,
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	switch settings.family {
	case "api_token", "authorization_server", "brand", "device_assurance", "event_hook", "inline_hook", "log_stream", familyAdminRole, familyAppAssign, familyApplication, familyAudit, familyAuthenticator, familyGroup, familyGroupMember, familyIDP, familyNetworkZone, familyPolicyRule, familyThreatInsight, familyTrustedOrigin, familyUser:
	default:
		return settings, fmt.Errorf("unsupported okta family")
	}
	if settings.domain == "" {
		return settings, fmt.Errorf("okta domain is required")
	}
	domain, err := normalizeDomain(settings.domain, allowLoopbackBaseURL)
	if err != nil {
		return settings, err
	}
	settings.domain = domain
	if settings.baseURL == "" {
		settings.baseURL, err = normalizeBaseURL("https://"+settings.domain, settings.domain, allowLoopbackBaseURL)
		if err != nil {
			return settings, err
		}
	} else {
		settings.baseURL, err = normalizeBaseURL(settings.baseURL, settings.domain, allowLoopbackBaseURL)
		if err != nil {
			return settings, err
		}
	}
	if settings.token == "" {
		return settings, fmt.Errorf("okta token is required")
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse okta per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("okta per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	switch settings.family {
	case familyAudit:
		if settings.search != "" || settings.sortBy != "" {
			return settings, fmt.Errorf("okta search and sort_by are only supported when family=%q", familyUser)
		}
		settings.sortOrder, err = normalizeAuditSortOrder(settings.sortOrder)
		if err != nil {
			return settings, err
		}
	case familyAdminRole:
		if settings.userID == "" {
			return settings, fmt.Errorf("okta user_id is required when family=%q", familyAdminRole)
		}
	case familyAppAssign:
		if settings.appID == "" {
			return settings, fmt.Errorf("okta app_id is required when family=%q", familyAppAssign)
		}
	case "api_token", "authorization_server", "brand", "device_assurance", "event_hook", "inline_hook", "log_stream", familyApplication, familyAuthenticator, familyGroup, familyIDP, familyNetworkZone, familyPolicyRule, familyThreatInsight, familyTrustedOrigin:
		if settings.since != "" || settings.until != "" {
			return settings, fmt.Errorf("okta since and until are only supported when family=%q", familyAudit)
		}
	case familyGroupMember:
		if settings.groupID == "" {
			return settings, fmt.Errorf("okta group_id is required when family=%q", familyGroupMember)
		}
	case familyUser:
		if settings.since != "" || settings.until != "" {
			return settings, fmt.Errorf("okta since and until are only supported when family=%q", familyAudit)
		}
		settings.sortOrder, err = normalizeUserSortOrder(settings.sortOrder)
		if err != nil {
			return settings, err
		}
	}
	return settings, nil
}

func normalizeDomain(raw string, allowLoopback bool) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("okta domain is required")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse okta domain: %w", err)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("okta domain must not include user info, query, or fragment")
	}
	if strings.TrimSpace(parsed.Port()) != "" {
		return "", fmt.Errorf("okta domain must not include a port")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return "", fmt.Errorf("okta domain must be a host")
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("okta domain must be a valid host")
	}
	host = strings.TrimRight(strings.ToLower(host), ".")
	if sourcecdk.IsUnsafeHost(host) && (!allowLoopback || !sourcecdk.IsLoopbackHost(host)) {
		return "", fmt.Errorf("okta domain must not target loopback, private, or link-local hosts")
	}
	return host, nil
}

func normalizeBaseURL(raw string, domain string, allowLoopback bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse okta base_url: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	allowInsecureLoopback := allowLoopback && parsed.Scheme == "http" && sourcecdk.IsLoopbackHost(host)
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", fmt.Errorf("okta base_url must use https")
	}
	if host == "" {
		return "", fmt.Errorf("okta base_url must include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("okta base_url must not include user info, query, or fragment")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return "", fmt.Errorf("okta base_url must be an origin URL")
	}
	allowCustomLoopbackPort := allowLoopback && sourcecdk.IsLoopbackHost(host)
	if strings.TrimSpace(parsed.Port()) != "" && parsed.Port() != "443" && !allowCustomLoopbackPort {
		return "", fmt.Errorf("okta base_url must not include a custom port")
	}
	allowLoopbackHost := allowLoopback && sourcecdk.IsLoopbackHost(host)
	if sourcecdk.IsUnsafeHost(host) && !allowLoopbackHost {
		return "", fmt.Errorf("okta base_url must not target loopback, private, or link-local hosts")
	}
	if host != strings.ToLower(strings.TrimSpace(domain)) && !allowLoopbackHost {
		return "", fmt.Errorf("okta base_url host must match okta domain")
	}
	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func normalizeAuditSortOrder(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "asc", "ascending":
		return defaultAuditOrder, nil
	case "desc", "descending":
		return "DESCENDING", nil
	default:
		return "", fmt.Errorf("okta sort_order must be one of asc, desc, ascending, or descending when family=%q", familyAudit)
	}
}

func normalizeUserSortOrder(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "asc", "ascending":
		return defaultUserOrder, nil
	case "desc", "descending":
		return "desc", nil
	default:
		return "", fmt.Errorf("okta sort_order must be one of asc, desc, ascending, or descending when family=%q", familyUser)
	}
}
