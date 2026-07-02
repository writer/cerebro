package fivetran

import (
	"context"
	"embed"
	"fmt"

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

var templateKeys = []string{"base_url"}

type Source struct {
	inner         *jsonapi.Source
	allowLoopback bool
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
		AuthModel:       "basic",
		Families:        fivetranapi.Families(),
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
	if param, values := fivetranPathParamValues(runtimeCfg); param != "" {
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
		return s.inner.ReadPathParamValuesWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint, param, values)
	}
	return s.inner.ReadWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint)
}

func (s *Source) runtimeConfig(_ context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
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
	case fivetranapi.FamilyGroupUsers, fivetranapi.FamilyGroupConnections:
		return "group_id", fivetranapi.ConfigListValues(cfg, "group_ids", "group_id")
	case fivetranapi.FamilyConnectionCertificates, fivetranapi.FamilyConnectionFingerprints:
		return "connection_id", fivetranapi.ConfigListValues(cfg, "connection_ids", "connection_id")
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

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
