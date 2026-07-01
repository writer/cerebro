package box

import (
	"context"
	"embed"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/boxapi"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = boxapi.SourceID
	defaultFamily          = boxapi.DefaultFamily
	defaultHealthPath      = boxapi.DefaultHealthPath
	defaultBaseURLTemplate = boxapi.DefaultBaseURLTemplate
	tokenScheme            = boxapi.TokenScheme
	familyUsers            = boxapi.FamilyUsers
	familyContentAssets    = boxapi.FamilyContentAssets
	familyGroups           = boxapi.FamilyGroups
	familyGroupMemberships = boxapi.FamilyGroupMemberships
	familyAuditEvents      = boxapi.FamilyAuditEvents
)

var templateKeys = boxapi.TemplateKeys

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
		SourceID:                    sourceID,
		DefaultFamily:               defaultFamily,
		RequireTenantID:             true,
		AuthModel:                   "oauth_client_credentials",
		TokenScheme:                 tokenScheme,
		OAuthTokenURL:               "https://api.box.com/oauth2/token",
		OAuthTokenRequestAuthMethod: "client_secret_post",
		OAuthTokenParams: map[string]string{
			"box_subject_type": "${config.box_subject_type}",
			"box_subject_id":   "${config.box_subject_id}",
		},
		Families: boxapi.Families(),
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
	if param, values := boxapi.PathParamValues(runtimeCfg); param != "" {
		return s.inner.CheckPathParamValues(ctx, runtimeCfg, param, values)
	}
	if err := s.checkHealth(ctx, runtimeCfg); err != nil {
		return err
	}
	return s.inner.Check(ctx, runtimeCfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if param, values := boxapi.PathParamValues(runtimeCfg); param != "" {
		return s.inner.DiscoverPathParamValues(ctx, runtimeCfg, param, values)
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
	if param, values := boxapi.PathParamValues(runtimeCfg); param != "" {
		return s.inner.ReadPathParamValuesWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint, param, values)
	}
	return s.inner.ReadWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint)
}

func (s *Source) runtimeConfig(_ context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	values := cfg.Values()
	if strings.TrimSpace(values["box_subject_type"]) == "" {
		values["box_subject_type"] = "enterprise"
	}
	if strings.TrimSpace(values["box_subject_id"]) == "" {
		values["box_subject_id"] = strings.TrimSpace(values["enterprise_id"])
	}
	if strings.TrimSpace(values["box_subject_id"]) == "" && firstNonEmpty(values["token"], values["access_token"], values["api_token"]) != "" {
		values["box_subject_id"] = "token_override"
	}
	return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, sourcecdk.NewConfig(values), templateKeys)
}

func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {
	path := firstNonEmpty(sourcecdk.ConfigValue(cfg, "health_path"), defaultHealthPath)
	return s.inner.CheckPath(ctx, cfg, path, nil)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
