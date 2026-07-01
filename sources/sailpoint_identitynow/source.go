package sailpoint_identitynow

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
	"github.com/writer/cerebro/sources/internal/sailpointapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID                   = "sailpoint_identitynow"
	defaultFamily              = sailpointapi.FamilyIdentities
	defaultHealthPath          = "/identities"
	defaultBaseURLTemplate     = "https://${config.tenant}.api.identitynow.com/v2025"
	oauthTokenURLTemplate      = "https://${config.tenant}.api.identitynow.com/oauth/token" // #nosec G101 -- token endpoint URL template, not credential material.
	oauthScopeSeparator        = " "
	oauthTokenExpirationBuffer = 60 * time.Second
)

var templateKeys = []string{"tenant", "client_id", "client_secret"}

var oauthRuntimeConfigOptions = sourcehttp.ClientCredentialsRuntimeConfigOptions{
	SourceID:               sourceID,
	DefaultBaseURLTemplate: defaultBaseURLTemplate,
	TemplateKeys:           templateKeys,
	TokenURLTemplate:       oauthTokenURLTemplate,
	Scopes:                 []string{"sp:scopes:all"},
	ScopeSeparator:         oauthScopeSeparator,
	ExpirationBuffer:       oauthTokenExpirationBuffer,
}

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
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  defaultBaseURLTemplate,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "bearer_token",
		Families:        sailpointapi.Families(),
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
	if fanout, ok := fanoutFor(runtimeCfg); ok {
		return s.inner.CheckPathParamValues(ctx, runtimeCfg, fanout.Param, fanoutValues(runtimeCfg, fanout.ConfigKey))
	}
	return s.inner.Check(ctx, runtimeCfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if fanout, ok := fanoutFor(runtimeCfg); ok {
		return s.inner.DiscoverPathParamValues(ctx, runtimeCfg, fanout.Param, fanoutValues(runtimeCfg, fanout.ConfigKey))
	}
	return s.inner.Discover(ctx, runtimeCfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if fanout, ok := fanoutFor(runtimeCfg); ok {
		return s.inner.ReadPathParamValues(ctx, runtimeCfg, cursor, fanout.Param, fanoutValues(runtimeCfg, fanout.ConfigKey))
	}
	return s.inner.Read(ctx, runtimeCfg, cursor)
}

func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if fanout, ok := fanoutFor(runtimeCfg); ok {
		return s.inner.ReadPathParamValuesWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint, fanout.Param, fanoutValues(runtimeCfg, fanout.ConfigKey))
	}
	return s.inner.ReadWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint)
}

func (s *Source) runtimeConfig(ctx context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	if s == nil {
		return sourcecdk.Config{}, fmt.Errorf("%s source is required", sourceID)
	}
	if strings.TrimSpace(sourcecdk.ConfigValue(cfg, "token")) != "" {
		return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
	}
	options := oauthRuntimeConfigOptions
	options.TokenCache = &s.tokenCache
	options.AllowLoopback = s.allowLoopback
	return sourcehttp.ResolveClientCredentialsRuntimeConfig(ctx, cfg, options)
}

func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {
	path := firstNonEmpty(sourcecdk.ConfigValue(cfg, "health_path"), defaultHealthPath)
	return s.inner.CheckPath(ctx, cfg, path, nil)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func fanoutFor(cfg sourcecdk.Config) (sailpointapi.Fanout, bool) {
	return sailpointapi.FanoutFor(sourcecdk.ConfigValue(cfg, "family"))
}

func fanoutValues(cfg sourcecdk.Config, key string) []string {
	raw := sourcecdk.ConfigValue(cfg, key)
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\t' || r == ' '
	})
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
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
