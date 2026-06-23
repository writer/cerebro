package sentinelone

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	defaultPageSize = 10
	maxPageSize     = 200
	defaultFamily   = familyThreat

	familyActivity    = "activity"
	familyAgent       = "agent"
	familyApplication = "application"
	familyExclusion   = "exclusion"
	familyGroup       = "group"
	familySite        = "site"
	familyThreat      = "threat"
)

type settings struct {
	family   string
	baseURL  string
	host     string
	token    string
	siteID   string
	groupID  string
	agentID  string
	since    string
	until    string
	activity string
	perPage  int
}

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettings(cfg, s != nil && s.allowLoopbackBaseURL)
}

func parseSettings(cfg sourcecdk.Config, allowLoopbackBaseURL bool) (settings, error) {
	resolved := settings{
		family:   sourcecdk.ConfigValue(cfg, "family"),
		baseURL:  sourcecdk.ConfigValue(cfg, "base_url"),
		token:    sourcecdk.ConfigValue(cfg, "token"),
		siteID:   sourcecdk.ConfigValue(cfg, "site_id"),
		groupID:  sourcecdk.ConfigValue(cfg, "group_id"),
		agentID:  sourcecdk.ConfigValue(cfg, "agent_id"),
		since:    sourcecdk.ConfigValue(cfg, "since"),
		until:    sourcecdk.ConfigValue(cfg, "until"),
		activity: sourcecdk.ConfigValue(cfg, "activity_type"),
		perPage:  defaultPageSize,
	}
	if resolved.family == "" {
		resolved.family = defaultFamily
	}
	switch resolved.family {
	case familyActivity, familyAgent, familyApplication, familyExclusion, familyGroup, familySite, familyThreat:
	default:
		return resolved, fmt.Errorf("sentinelone family must be one of activity, agent, application, exclusion, group, site, or threat")
	}
	if resolved.baseURL == "" {
		return resolved, fmt.Errorf("sentinelone base_url is required")
	}
	normalizedBase, host, err := normalizeBaseURL(resolved.baseURL, allowLoopbackBaseURL)
	if err != nil {
		return resolved, err
	}
	resolved.baseURL = normalizedBase
	resolved.host = host
	if resolved.token == "" {
		return resolved, fmt.Errorf("sentinelone token is required")
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return resolved, fmt.Errorf("parse sentinelone per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return resolved, fmt.Errorf("sentinelone per_page must be between 1 and %d", maxPageSize)
		}
		resolved.perPage = perPage
	}
	switch resolved.family {
	case familyActivity, familyThreat:
	default:
		if resolved.since != "" || resolved.until != "" {
			return resolved, fmt.Errorf("sentinelone since/until are only supported when family is %q or %q", familyActivity, familyThreat)
		}
	}
	return resolved, nil
}

func normalizeBaseURL(raw string, allowLoopback bool) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("parse sentinelone base_url: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	allowInsecureLoopback := allowLoopback && parsed.Scheme == "http" && sourcecdk.IsLoopbackHost(host)
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", "", fmt.Errorf("sentinelone base_url must use https")
	}
	if host == "" {
		return "", "", fmt.Errorf("sentinelone base_url must include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", "", fmt.Errorf("sentinelone base_url must not include user info, query, or fragment")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return "", "", fmt.Errorf("sentinelone base_url must be an origin URL")
	}
	allowCustomPort := allowLoopback && sourcecdk.IsLoopbackHost(host)
	if strings.TrimSpace(parsed.Port()) != "" && parsed.Port() != "443" && !allowCustomPort {
		return "", "", fmt.Errorf("sentinelone base_url must not include a custom port")
	}
	allowLoopbackHost := allowLoopback && sourcecdk.IsLoopbackHost(host)
	if sourcecdk.IsUnsafeHost(host) && !allowLoopbackHost {
		return "", "", fmt.Errorf("sentinelone base_url must not target loopback, private, or link-local hosts")
	}
	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), host, nil
}
