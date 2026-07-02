package fivetran

import (
	"context"
	"embed"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/fivetranapi"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = fivetranapi.SourceID
	defaultFamily          = fivetranapi.DefaultFamily
	defaultHealthPath      = fivetranapi.DefaultHealthPath
	defaultBaseURLTemplate = fivetranapi.DefaultBaseURLTemplate
)

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "basic",
		Families:        fivetranapi.Families(),
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return err
	}
	if param, values := fivetranPathParamValues(runtimeCfg); param != "" {
		values, err = s.resolvePathParamValues(ctx, runtimeCfg, param, values)
		if err != nil {
			return err
		}
		return s.inner.CheckPathParamValues(ctx, runtimeCfg, param, values)
	}
	path := fivetranapi.FirstNonEmpty(sourcecdk.ConfigValue(runtimeCfg, "health_path"), defaultHealthPath)
	if err := s.inner.CheckPath(ctx, runtimeCfg, path, nil); err != nil {
		return err
	}
	return s.inner.Check(ctx, runtimeCfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if param, values := fivetranPathParamValues(runtimeCfg); param != "" {
		values, err = s.resolvePathParamValues(ctx, runtimeCfg, param, values)
		if err != nil {
			return nil, err
		}
		return s.discoverScoped(ctx, runtimeCfg, param, values)
	}
	return s.inner.Discover(ctx, runtimeCfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.ReadWithCheckpoint(ctx, cfg, cursor, nil)
}

func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if param, values := fivetranPathParamValues(runtimeCfg); param != "" {
		values, err = s.resolvePathParamValues(ctx, runtimeCfg, param, values)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		return s.inner.ReadPathParamValuesWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint, param, values)
	}
	return s.inner.ReadWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint)
}

func (s *Source) runtimeConfig(_ context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, []string{"base_url"})
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func fivetranPathParamValues(cfg sourcecdk.Config) (string, []string) {
	switch fivetranapi.FamilyName(cfg) {
	case fivetranapi.FamilyUserConnections, fivetranapi.FamilyUserGroups:
		return "user_id", fivetranapi.ConfigListValues(cfg, "user_ids", "user_id")
	case fivetranapi.FamilyTeamUsers, fivetranapi.FamilyTeamConnections, fivetranapi.FamilyTeamGroups:
		return "team_id", fivetranapi.ConfigListValues(cfg, "team_ids", "team_id")
	case fivetranapi.FamilyGroupUsers, fivetranapi.FamilyGroupConnections, fivetranapi.FamilyGroupPublicKeys, fivetranapi.FamilyGroupServiceAccounts:
		return "group_id", fivetranapi.ConfigListValues(cfg, "group_ids", "group_id")
	case fivetranapi.FamilyConnectionCertificates, fivetranapi.FamilyConnectionFingerprints, fivetranapi.FamilyConnectionSchemas, fivetranapi.FamilyConnectionState:
		return "connection_id", fivetranapi.ConfigListValues(cfg, "connection_ids", "connection_id")
	case fivetranapi.FamilyDestinationCertificates, fivetranapi.FamilyDestinationFingerprints:
		return "destination_id", fivetranapi.ConfigListValues(cfg, "destination_ids", "destination_id")
	case fivetranapi.FamilyExternalSecretManagerAssignments:
		return "external_secret_manager_id", fivetranapi.ConfigListValues(cfg, "external_secret_manager_ids", "external_secret_manager_id", "esm_ids", "esm_id")
	case fivetranapi.FamilyProxyAgentConnections:
		return "proxy_agent_id", fivetranapi.ConfigListValues(cfg, "proxy_agent_ids", "proxy_agent_id", "agent_ids", "agent_id")
	case fivetranapi.FamilyConnectorMetadataDetails:
		return "service", fivetranapi.ConfigListValues(cfg, "connector_services", "services", "service")
	case fivetranapi.FamilyTransformationPackageDetails:
		return "package_definition_id", fivetranapi.ConfigListValues(cfg, "package_definition_ids", "package_definition_id")
	default:
		return "", nil
	}
}

func (s *Source) discoverScoped(ctx context.Context, cfg sourcecdk.Config, param string, values []string) ([]sourcecdk.URN, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: fivetran %s requires at least one %s", sourcecdk.ErrInvalidConfig, fivetranapi.FamilyName(cfg), param)
	}
	return s.inner.DiscoverPathParamValues(ctx, cfg, param, values)
}

func (s *Source) resolvePathParamValues(ctx context.Context, cfg sourcecdk.Config, param string, values []string) ([]string, error) {
	values = compactStrings(values)
	if len(values) > 0 {
		return values, nil
	}
	parentFamily, parentAttribute := fivetranParentFamilyForParam(param)
	if parentFamily == "" || parentAttribute == "" {
		return nil, nil
	}
	parentCfg := configWithValue(cfg, "family", parentFamily)
	ids := []string{}
	var cursor *cerebrov1.SourceCursor
	for page := 0; page < 1000; page++ {
		pull, err := s.inner.Read(ctx, parentCfg, cursor)
		if err != nil {
			return nil, fmt.Errorf("discover fivetran %s values from %s: %w", param, parentFamily, err)
		}
		for _, event := range pull.Events {
			if event == nil {
				continue
			}
			if value := strings.TrimSpace(event.Attributes[parentAttribute]); value != "" {
				ids = append(ids, value)
			}
		}
		if sourcecdk.CursorToken(pull.NextCursor) == "" {
			return compactStrings(ids), nil
		}
		cursor = pull.NextCursor
	}
	return nil, fmt.Errorf("fivetran %s parent fanout exceeded page limit", param)
}

func fivetranParentFamilyForParam(param string) (string, string) {
	switch param {
	case "user_id":
		return fivetranapi.FamilyUsers, "user_id"
	case "team_id":
		return fivetranapi.FamilyTeams, "team_id"
	case "group_id":
		return fivetranapi.FamilyGroups, "group_id"
	case "connection_id":
		return fivetranapi.FamilyConnections, "resource_id"
	case "destination_id":
		return fivetranapi.FamilyDestinations, "resource_id"
	case "external_secret_manager_id":
		return fivetranapi.FamilyExternalSecretManagers, "resource_id"
	case "proxy_agent_id":
		return fivetranapi.FamilyProxyAgents, "resource_id"
	case "service":
		return fivetranapi.FamilyConnectorMetadata, "service"
	case "package_definition_id":
		return fivetranapi.FamilyTransformationPackageMetadata, "resource_id"
	default:
		return "", ""
	}
}

func configWithValue(cfg sourcecdk.Config, key string, value string) sourcecdk.Config {
	values := cfg.Values()
	values[key] = value
	return sourcecdk.NewConfig(values)
}

func compactStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
	}
}
