package auth0

import (
	"context"
	"embed"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml families.json
var sourceFS embed.FS

const (
	sourceID                      = "auth0"
	defaultFamily                 = familyUsers
	defaultBaseURLTemplate        = "https://${config.domain}/api/v2"
	tokenScheme                   = "Bearer"
	oauthTokenURLTemplate         = "https://${config.domain}/oauth/token" // #nosec G101 -- token endpoint URL template, not credential material.
	oauthScopeSeparator           = " "
	oauthTokenExpirationBuffer    = 60 * time.Second
	familyUsers                   = "users"
	familyRoles                   = "roles"
	familyAuditEvents             = "audit_events"
	familyClients                 = "clients"
	familyConnections             = "connections"
	familyOrganizations           = "organizations"
	familyOrganizationMembers     = "organization_members"
	familyRoleUsers               = "role_users"
	familyOrganizationMemberRoles = "organization_member_roles"
)

var templateKeys = []string{"domain", "client_id", "client_secret"}

var oauthScopes = []string{"read:clients", "read:connections", "read:logs", "read:organization_member_roles", "read:organization_members", "read:organizations", "read:roles", "read:users"}

var oauthTokenParams = map[string]string{"audience": "https://${config.domain}/api/v2/"}

type Source struct {
	inner         *jsonapi.Source
	allowLoopback bool
	tokenCache    sourcehttp.ClientCredentialsCache
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	families, err := auth0Families()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		TokenScheme:     tokenScheme,
		Families:        families,
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func auth0Families() ([]jsonapi.Family, error) {
	return jsonapi.LoadFamiliesFromFS(sourceFS, "families.json")
}

func familyNames() []string {
	return []string{familyUsers, familyRoles, familyAuditEvents, familyClients, familyConnections, familyOrganizations, familyOrganizationMembers, familyRoleUsers, familyOrganizationMemberRoles}
}

func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Spec()
}

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return err
	}
	if sourcecdk.ConfigValue(runtimeCfg, "family") == familyOrganizationMemberRoles {
		sets, err := organizationMemberRoleParamSets(runtimeCfg)
		if err != nil {
			return err
		}
		return s.inner.CheckPathParamSets(ctx, runtimeCfg, sets)
	}
	if param, values := pathParamValues(runtimeCfg, sourcecdk.ConfigValue(runtimeCfg, "family")); param != "" {
		return s.inner.CheckPathParamValues(ctx, runtimeCfg, param, values)
	}
	return s.inner.Check(ctx, runtimeCfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if sourcecdk.ConfigValue(runtimeCfg, "family") == familyOrganizationMemberRoles {
		sets, err := organizationMemberRoleParamSets(runtimeCfg)
		if err != nil {
			return nil, err
		}
		return s.inner.DiscoverPathParamSets(ctx, runtimeCfg, sets)
	}
	if param, values := pathParamValues(runtimeCfg, sourcecdk.ConfigValue(runtimeCfg, "family")); param != "" {
		return s.inner.DiscoverPathParamValues(ctx, runtimeCfg, param, values)
	}
	return s.inner.Discover(ctx, runtimeCfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if sourcecdk.ConfigValue(runtimeCfg, "family") == familyOrganizationMemberRoles {
		sets, err := organizationMemberRoleParamSets(runtimeCfg)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		return s.inner.ReadPathParamSetsWithCheckpoint(ctx, runtimeCfg, cursor, nil, sets)
	}
	if param, values := pathParamValues(runtimeCfg, sourcecdk.ConfigValue(runtimeCfg, "family")); param != "" {
		return s.inner.ReadPathParamValues(ctx, runtimeCfg, cursor, param, values)
	}
	return s.inner.Read(ctx, runtimeCfg, cursor)
}

func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if sourcecdk.ConfigValue(runtimeCfg, "family") == familyOrganizationMemberRoles {
		sets, err := organizationMemberRoleParamSets(runtimeCfg)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		return s.inner.ReadPathParamSetsWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint, sets)
	}
	if param, values := pathParamValues(runtimeCfg, sourcecdk.ConfigValue(runtimeCfg, "family")); param != "" {
		return s.inner.ReadPathParamValuesWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint, param, values)
	}
	return s.inner.ReadWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint)
}

func (s *Source) runtimeConfig(ctx context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	values := cfg.Values()
	if err := validateAuth0Domain(sourcecdk.ConfigValue(cfg, "domain")); err != nil {
		return sourcecdk.Config{}, err
	}
	if strings.TrimSpace(values["base_url"]) == "" && strings.TrimSpace(defaultBaseURLTemplate) != "" {
		baseURL, err := sourcecdk.RenderConfigTemplate(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
		if err != nil {
			return sourcecdk.Config{}, err
		}
		values["base_url"] = baseURL
	}
	if s == nil {
		return sourcecdk.Config{}, fmt.Errorf("%s source is required", sourceID)
	}
	token, err := s.tokenCache.Token(ctx, cfg, sourcehttp.ClientCredentialsOptions{
		SourceID:         sourceID,
		TokenURLTemplate: oauthTokenURLTemplate,
		TemplateKeys:     templateKeys,
		Scopes:           oauthScopes,
		ScopeSeparator:   oauthScopeSeparator,
		TokenParams:      oauthTokenParams,
		ExpirationBuffer: oauthTokenExpirationBuffer,
		AllowLoopback:    s.allowLoopback,
	})
	if err != nil {
		return sourcecdk.Config{}, err
	}
	values["token"] = token
	return sourcecdk.NewConfig(values), nil
}

func validateAuth0Domain(value string) error {
	domain := strings.ToLower(strings.TrimSpace(value))
	if domain == "" {
		return fmt.Errorf("%w: %s domain is required", sourcecdk.ErrInvalidConfig, sourceID)
	}
	if strings.Contains(domain, "://") || strings.ContainsAny(domain, "/?#@") || strings.Contains(domain, ":") {
		return fmt.Errorf("%w: %s domain must be a bare Auth0 hostname", sourcecdk.ErrInvalidConfig, sourceID)
	}
	if !strings.HasSuffix(domain, ".auth0.com") {
		return fmt.Errorf("%w: %s domain must be an Auth0 hostname", sourcecdk.ErrInvalidConfig, sourceID)
	}
	return nil
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(sourceFS, "catalog.yaml")
}

func pathParamValues(cfg sourcecdk.Config, family string) (string, []string) {
	switch strings.TrimSpace(family) {
	case familyRoleUsers:
		return "role_id", configListValues(cfg, "role_ids", "role_id")
	case familyOrganizationMembers:
		return "organization_id", configListValues(cfg, "organization_ids", "organization_id")
	default:
		return "", nil
	}
}

func organizationMemberRoleParamSets(cfg sourcecdk.Config) ([]map[string]string, error) {
	organizationIDs := configListValues(cfg, "organization_ids", "organization_id")
	userIDs := configListValues(cfg, "user_ids", "user_id")
	if len(organizationIDs) == 0 {
		return nil, fmt.Errorf("%w: %s organization_ids values are required", sourcecdk.ErrInvalidConfig, sourceID)
	}
	if len(userIDs) == 0 {
		return nil, fmt.Errorf("%w: %s user_ids values are required", sourcecdk.ErrInvalidConfig, sourceID)
	}
	sets := make([]map[string]string, 0, len(organizationIDs)*len(userIDs))
	seen := map[string]struct{}{}
	for _, organizationID := range organizationIDs {
		for _, userID := range userIDs {
			key := organizationID + "\x00" + userID
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			sets = append(sets, map[string]string{"organization_id": organizationID, "user_id": userID})
		}
	}
	return sets, nil
}

func configListValues(cfg sourcecdk.Config, keys ...string) []string {
	values := []string{}
	for _, key := range keys {
		raw := strings.TrimSpace(sourcecdk.ConfigValue(cfg, key))
		if raw == "" {
			continue
		}
		for _, part := range strings.Split(raw, ",") {
			if part = strings.TrimSpace(part); part != "" {
				values = append(values, part)
			}
		}
	}
	return values
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
