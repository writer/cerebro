package github

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
)

type settings struct {
	family              string
	owner               string
	repo                string
	token               string
	appID               string
	appInstallationID   string
	appPrivateKey       string
	appPrivateKeyBase64 string
	baseURL             string
	state               string
	auditInclude        string
	auditPhrase         string
	auditOrder          string
	auditLogCanary      bool
	perPage             int
}

func parseSettings(cfg sourcecdk.Config, requireRepo bool, allowLoopbackBaseURL bool) (_ settings, err error) {
	defer func() {
		if err != nil && !errors.Is(err, sourcecdk.ErrInvalidConfig) {
			err = fmt.Errorf("%w: %w", sourcecdk.ErrInvalidConfig, err)
		}
	}()
	settings := settings{
		family: sourcecdk.ConfigValue(cfg, "family"),
		owner:  sourcecdk.ConfigValue(cfg, "owner"),
		repo:   sourcecdk.ConfigValue(cfg, "repo"),
		token:  sourcecdk.ConfigValue(cfg, "token"),
		appID:  sourcecdk.ConfigValue(cfg, "app_id"),
		appInstallationID: firstNonEmptyString(
			sourcecdk.ConfigValue(cfg, "app_installation_id"),
			sourcecdk.ConfigValue(cfg, "installation_id"),
		),
		appPrivateKey: firstNonEmptyString(
			sourcecdk.ConfigValue(cfg, "app_private_key"),
			sourcecdk.ConfigValue(cfg, "private_key"),
		),
		appPrivateKeyBase64: firstNonEmptyString(
			sourcecdk.ConfigValue(cfg, "app_private_key_base64"),
			sourcecdk.ConfigValue(cfg, "private_key_base64"),
		),
		baseURL:      sourcecdk.ConfigValue(cfg, "base_url"),
		state:        sourcecdk.ConfigValue(cfg, "state"),
		auditInclude: sourcecdk.ConfigValue(cfg, "include"),
		auditPhrase:  sourcecdk.ConfigValue(cfg, "phrase"),
		auditOrder:   sourcecdk.ConfigValue(cfg, "order"),
		perPage:      defaultPageSize,
	}
	if settings.baseURL != "" {
		baseURL, err := sourcehttp.NormalizeGitHubBaseURL(settings.baseURL, allowLoopbackBaseURL)
		if err != nil {
			return settings, err
		}
		settings.baseURL = baseURL
	}
	if settings.owner == "" {
		return settings, fmt.Errorf("github owner is required")
	}
	if err := settings.validateAuth(); err != nil {
		return settings, err
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	switch settings.family {
	case familyAudit, familyDependabot, familyOrgInventory, familyPullRequest, familyRepository, familySecretScanning:
	default:
		return settings, fmt.Errorf("github family must be one of %s, %s, %s, %s, %s, or %s", familyPullRequest, familyAudit, familyDependabot, familyOrgInventory, familyRepository, familySecretScanning)
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse github per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("github per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	if rawAuditLogCanary := sourcecdk.ConfigValue(cfg, "audit_log_canary"); rawAuditLogCanary != "" {
		if settings.auditLogCanary, err = strconv.ParseBool(rawAuditLogCanary); err != nil {
			return settings, fmt.Errorf("parse github audit_log_canary: %w", err)
		}
	}
	switch settings.family {
	case familyPullRequest:
		if requireRepo && settings.repo == "" {
			return settings, fmt.Errorf("github repo is required")
		}
		if settings.state == "" {
			settings.state = defaultState
		}
		switch settings.state {
		case "all", "closed", "open":
		default:
			return settings, fmt.Errorf("github state must be one of open, closed, or all")
		}
		if settings.auditInclude != "" || settings.auditOrder != "" || settings.auditPhrase != "" {
			return settings, fmt.Errorf("github include, order, and phrase are only supported when family=%q", familyAudit)
		}
	case familyDependabot:
		if !settings.hasAuth() {
			return settings, fmt.Errorf("github token or app auth is required when family=%q", familyDependabot)
		}
		if settings.repo == "" {
			return settings, fmt.Errorf("github repo is required when family=%q", familyDependabot)
		}
		if settings.state == "" {
			settings.state = defaultState
		}
		switch settings.state {
		case "auto_dismissed", "dismissed", "fixed", "open":
		default:
			return settings, fmt.Errorf("github state must be one of auto_dismissed, dismissed, fixed, or open when family=%q", familyDependabot)
		}
		if settings.auditInclude != "" || settings.auditOrder != "" || settings.auditPhrase != "" {
			return settings, fmt.Errorf("github include, order, and phrase are only supported when family=%q", familyAudit)
		}
	case familyOrgInventory:
		if !settings.hasAuth() {
			return settings, fmt.Errorf("github token or app auth is required when family=%q", familyOrgInventory)
		}
		if settings.repo != "" {
			return settings, fmt.Errorf("github repo is not supported when family=%q", familyOrgInventory)
		}
		if settings.state != "" {
			return settings, fmt.Errorf("github state is not supported when family=%q", familyOrgInventory)
		}
		if settings.auditInclude != "" || settings.auditOrder != "" || settings.auditPhrase != "" {
			return settings, fmt.Errorf("github include, order, and phrase are only supported when family=%q", familyAudit)
		}
	case familySecretScanning:
		if !settings.hasAuth() {
			return settings, fmt.Errorf("github token or app auth is required when family=%q", familySecretScanning)
		}
		if settings.repo != "" {
			return settings, fmt.Errorf("github repo is not supported when family=%q (org-level scan)", familySecretScanning)
		}
		if settings.state == "" {
			settings.state = defaultState
		}
		switch settings.state {
		case "open", "resolved":
		default:
			return settings, fmt.Errorf("github state must be one of open or resolved when family=%q", familySecretScanning)
		}
		if settings.auditInclude != "" || settings.auditOrder != "" || settings.auditPhrase != "" {
			return settings, fmt.Errorf("github include, order, and phrase are only supported when family=%q", familyAudit)
		}
	case familyRepository:
		if settings.state != "" {
			return settings, fmt.Errorf("github state is only supported when family=%q", familyPullRequest)
		}
		if settings.auditInclude != "" || settings.auditOrder != "" || settings.auditPhrase != "" {
			return settings, fmt.Errorf("github include, order, and phrase are only supported when family=%q", familyAudit)
		}
	case familyAudit:
		if !settings.hasAuth() {
			return settings, fmt.Errorf("github token or app auth is required when family=%q", familyAudit)
		}
		if settings.repo != "" {
			return settings, fmt.Errorf("github repo is not supported when family=%q", familyAudit)
		}
		if settings.state != "" {
			return settings, fmt.Errorf("github state is only supported when family=%q", familyPullRequest)
		}
		if settings.auditInclude == "" {
			settings.auditInclude = defaultAuditInclude
		}
		switch settings.auditInclude {
		case "all", "git", "web":
		default:
			return settings, fmt.Errorf("github include must be one of all, git, or web")
		}
		if settings.auditOrder == "" {
			settings.auditOrder = defaultAuditOrder
		}
		switch settings.auditOrder {
		case "asc", "desc":
		default:
			return settings, fmt.Errorf("github order must be one of asc or desc")
		}
	}
	return settings, nil
}

func (st settings) githubAppAuthConfig() sourcehttp.GitHubAppAuthConfig {
	return sourcehttp.GitHubAppAuthConfig{
		AppID:            st.appID,
		InstallationID:   st.appInstallationID,
		PrivateKey:       st.appPrivateKey,
		PrivateKeyBase64: st.appPrivateKeyBase64,
		BaseURL:          st.baseURL,
	}
}

func (st settings) hasAuth() bool {
	return st.token != "" || st.usesGitHubAppAuth()
}

func (st settings) usesGitHubAppAuth() bool {
	return st.githubAppAuthConfig().Configured()
}

func (st settings) validateAuth() error {
	if err := st.githubAppAuthConfig().Validate(); err != nil {
		return fmt.Errorf("%w: %w", sourcecdk.ErrInvalidConfig, err)
	}
	return nil
}
