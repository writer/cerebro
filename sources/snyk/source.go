package snyk

import (
	"context"
	"embed"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
	"github.com/writer/cerebro/sources/internal/snykapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = "snyk"
	defaultFamily          = snykapi.DefaultFamily
	defaultAPIVersion      = snykapi.DefaultAPIVersion
	defaultHealthPath      = snykapi.DefaultHealthPath
	defaultBaseURLTemplate = snykapi.DefaultBaseURLTemplate
	tokenScheme            = snykapi.TokenScheme
	apiVersionConfig       = snykapi.APIVersionConfig
	familyOrgs             = snykapi.FamilyOrgs
	familyGroups           = snykapi.FamilyGroups
	familyProjects         = snykapi.FamilyProjects
	familyTargets          = snykapi.FamilyTargets
	familyAssets           = snykapi.FamilyAssets
	familyFindings         = snykapi.FamilyFindings
	familyVulnerabilities  = snykapi.FamilyVulnerabilities
	familyOrgMemberships   = snykapi.FamilyOrgMemberships
	familyServiceAccounts  = snykapi.FamilyServiceAccounts
	familyAuditLogs        = snykapi.FamilyAuditLogs
	familyCollections      = snykapi.FamilyCollections
	familyCloudEnvs        = snykapi.FamilyCloudEnvs
	familyCloudResources   = snykapi.FamilyCloudResources
	familyCloudScans       = snykapi.FamilyCloudScans
	familyGroupMemberships = snykapi.FamilyGroupMemberships
	familyGroupSvcAccounts = snykapi.FamilyGroupSvcAccounts
	familyGroupAuditLogs   = snykapi.FamilyGroupAuditLogs
	familyAssetProjects    = snykapi.FamilyAssetProjects
	familyAssetTargets     = snykapi.FamilyAssetTargets
)

type Source struct {
	inner *jsonapi.Source
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "api_token",
		TokenScheme:     tokenScheme,
		Families:        snykapi.Families(),
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
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
	if err := s.checkHealth(ctx, runtimeCfg); err != nil {
		return err
	}
	if param, values := snykapi.PathParamValues(runtimeCfg, sourcecdk.ConfigValue(runtimeCfg, "family")); param != "" {
		return s.inner.CheckPathParamValues(ctx, runtimeCfg, param, values)
	}
	return s.inner.Check(ctx, runtimeCfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if param, values := snykapi.PathParamValues(runtimeCfg, sourcecdk.ConfigValue(runtimeCfg, "family")); param != "" {
		return s.inner.DiscoverPathParamValues(ctx, runtimeCfg, param, values)
	}
	return s.inner.Discover(ctx, runtimeCfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if param, values := snykapi.PathParamValues(runtimeCfg, sourcecdk.ConfigValue(runtimeCfg, "family")); param != "" {
		return s.inner.ReadPathParamValues(ctx, runtimeCfg, cursor, param, values)
	}
	return s.inner.Read(ctx, runtimeCfg, cursor)
}

func (s *Source) runtimeConfig(_ context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	runtimeCfg, err := sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, []string{"token"})
	if err != nil {
		return sourcecdk.Config{}, err
	}
	values := runtimeCfg.Values()
	if strings.TrimSpace(values[apiVersionConfig]) == "" {
		values[apiVersionConfig] = defaultAPIVersion
	}
	return sourcecdk.NewConfig(values), nil
}

func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {
	path := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "health_path"))
	if path == "" {
		path = defaultHealthPath
	}
	return s.inner.CheckPath(ctx, cfg, path, nil)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
	}
}
