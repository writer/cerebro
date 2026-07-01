package onelogin

import (
	"context"
	"embed"
	"fmt"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/sources/internal/jsonapi"
	"github.com/writer/cerebro/sources/internal/oneloginapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID                   = oneloginapi.SourceID
	defaultFamily              = oneloginapi.DefaultFamily
	defaultHealthPath          = oneloginapi.DefaultHealthPath
	defaultBaseURLTemplate     = oneloginapi.DefaultBaseURLTemplate
	tokenScheme                = oneloginapi.TokenScheme
	oauthTokenURLTemplate      = oneloginapi.OAuthTokenURLTemplate
	oauthScopeSeparator        = " "
	oauthTokenExpirationBuffer = 60 * time.Second
)

var templateKeys = []string{"subdomain", "client_id", "client_secret"}

var oauthScopes = []string{}

var oauthTokenParams = map[string]string{}

var oauthRuntimeConfigOptions = sourcehttp.ClientCredentialsRuntimeConfigOptions{
	SourceID:               sourceID,
	DefaultBaseURLTemplate: defaultBaseURLTemplate,
	TemplateKeys:           templateKeys,
	TokenURLTemplate:       oauthTokenURLTemplate,
	Scopes:                 oauthScopes,
	ScopeSeparator:         oauthScopeSeparator,
	TokenParams:            oauthTokenParams,
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
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "oauth_client_credentials",
		TokenScheme:     tokenScheme,
		Families:        oneloginapi.Families(),
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
	if param, values := oneloginapi.PathParamValues(runtimeCfg); param != "" {
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
	if param, values := oneloginapi.PathParamValues(runtimeCfg); param != "" {
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
	if param, values := oneloginapi.PathParamValues(runtimeCfg); param != "" {
		return s.inner.ReadPathParamValuesWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint, param, values)
	}
	return s.inner.ReadWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint)
}

func (s *Source) runtimeConfig(ctx context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	if s == nil {
		return sourcecdk.Config{}, fmt.Errorf("%s source is required", sourceID)
	}
	options := oauthRuntimeConfigOptions
	options.TokenCache = &s.tokenCache
	options.AllowLoopback = s.allowLoopback
	return sourcehttp.ResolveClientCredentialsRuntimeConfig(ctx, cfg, options)
}

func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {
	path := sourcecdk.ConfigValue(cfg, "health_path")
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
		s.allowLoopback = true
	}
}
