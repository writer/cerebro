package googleworkspace

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/googleworkspaceauth"
)

type settings struct {
	family      string
	domain      string
	customerID  string
	token       string
	baseURL     string
	groupKey    string
	application string
	perPage     int
	auth        googleworkspaceauth.Settings
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	settings := settings{
		family:      sourcecdk.ConfigValue(cfg, "family"),
		domain:      sourcecdk.ConfigValue(cfg, "domain"),
		customerID:  sourcecdk.ConfigValue(cfg, "customer_id"),
		token:       sourcecdk.ConfigValue(cfg, "token"),
		baseURL:     sourcecdk.ConfigValue(cfg, "base_url"),
		groupKey:    sourcecdk.ConfigValue(cfg, "group_key"),
		application: sourcecdk.ConfigValue(cfg, "application"),
		perPage:     defaultPageSize,
		auth:        googleworkspaceauth.FromConfig(cfg),
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	switch settings.family {
	case familyAudit, familyGroup, familyGroupMember, familyRoleAssign, familyUser:
	default:
		return settings, fmt.Errorf("google_workspace family must be one of audit, group, group_member, role_assignment, or user")
	}
	if settings.domain == "" {
		return settings, fmt.Errorf("google_workspace domain is required")
	}
	if settings.customerID == "" {
		settings.customerID = defaultCustomerID
	}
	if err := googleworkspaceauth.Validate(settings.auth); err != nil {
		return settings, err
	}
	if settings.baseURL == "" {
		settings.baseURL = defaultBaseURL
	}
	if settings.family == familyGroupMember && settings.groupKey == "" {
		return settings, fmt.Errorf("google_workspace group_key is required when family=%q", familyGroupMember)
	}
	if settings.application == "" {
		settings.application = "admin"
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse google_workspace per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("google_workspace per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	return settings, nil
}
