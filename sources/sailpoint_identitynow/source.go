package sailpoint_identitynow

import (
	"context"
	"embed"
	"fmt"
	"net/url"
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
	var fanoutValues []string
	if fanout, ok := fanoutFor(runtimeCfg); ok {
		fanoutValues, err = requiredFanoutValues(runtimeCfg, fanout)
		if err != nil {
			return err
		}
	}
	if err := s.checkHealth(ctx, healthCheckConfig(runtimeCfg)); err != nil {
		return err
	}
	if fanout, ok := fanoutFor(runtimeCfg); ok {
		return s.inner.CheckPathParamValues(ctx, runtimeCfg, fanout.Param, fanoutValues)
	}
	return s.inner.Check(ctx, runtimeCfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if fanout, ok := fanoutFor(runtimeCfg); ok {
		values, err := requiredFanoutValues(runtimeCfg, fanout)
		if err != nil {
			return nil, err
		}
		return s.inner.DiscoverPathParamValues(ctx, runtimeCfg, fanout.Param, values)
	}
	return s.inner.Discover(ctx, runtimeCfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if fanout, ok := fanoutFor(runtimeCfg); ok {
		values, err := requiredFanoutValues(runtimeCfg, fanout)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		return s.inner.ReadPathParamValues(ctx, runtimeCfg, cursor, fanout.Param, values)
	}
	return s.inner.Read(ctx, runtimeCfg, cursor)
}

func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if fanout, ok := fanoutFor(runtimeCfg); ok {
		values, err := requiredFanoutValues(runtimeCfg, fanout)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		return s.inner.ReadPathParamValuesWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint, fanout.Param, values)
	}
	return s.inner.ReadWithCheckpoint(ctx, runtimeCfg, cursor, checkpoint)
}

func (s *Source) runtimeConfig(ctx context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	if s == nil {
		return sourcecdk.Config{}, fmt.Errorf("%s source is required", sourceID)
	}
	runtimeCfg, err := sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
	if err != nil {
		return sourcecdk.Config{}, err
	}
	if err := validateManagedBaseURLHost(sourcecdk.ConfigValue(runtimeCfg, "base_url"), s.allowLoopback); err != nil {
		return sourcecdk.Config{}, err
	}
	if strings.TrimSpace(sourcecdk.ConfigValue(cfg, "token")) != "" {
		return runtimeCfg, nil
	}
	options := oauthRuntimeConfigOptions
	options.TokenCache = &s.tokenCache
	options.AllowLoopback = s.allowLoopback
	tokenURLTemplate, err := managedOAuthTokenURLForBaseURL(sourcecdk.ConfigValue(runtimeCfg, "base_url"))
	if err != nil {
		return sourcecdk.Config{}, err
	}
	options.TokenURLTemplate = tokenURLTemplate
	return sourcehttp.ResolveClientCredentialsRuntimeConfig(ctx, runtimeCfg, options)
}

func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {
	path := firstNonEmpty(sourcecdk.ConfigValue(cfg, "health_path"), defaultHealthPath)
	return s.inner.CheckPath(ctx, cfg, path, nil)
}

func healthCheckConfig(cfg sourcecdk.Config) sourcecdk.Config {
	runtimeValues := cfg.Values()
	healthValues := make(map[string]string, len(runtimeValues)+1)
	for key, value := range runtimeValues {
		healthValues[key] = value
	}
	healthValues["family"] = defaultFamily
	return sourcecdk.NewConfig(healthValues)
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

func managedOAuthTokenURLForBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse %s base_url for token endpoint: %w", sourceID, err)
	}
	if !parsed.IsAbs() || strings.TrimSpace(parsed.Host) == "" {
		return "", fmt.Errorf("%w: %s base_url must be absolute for OAuth token endpoint", sourcecdk.ErrInvalidConfig, sourceID)
	}
	parsed.Path = "/oauth/token"
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
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

func requiredFanoutValues(cfg sourcecdk.Config, fanout sailpointapi.Fanout) ([]string, error) {
	values := fanoutValues(cfg, fanout.ConfigKey)
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: %s %s is required for %s", sourcecdk.ErrInvalidConfig, sourceID, fanout.ConfigKey, sourcecdk.ConfigValue(cfg, "family"))
	}
	return values, nil
}

func validateManagedBaseURLHost(raw string, allowLoopback bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("parse %s base_url: %w", sourceID, err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return fmt.Errorf("%w: %s base_url must include a host", sourcecdk.ErrInvalidConfig, sourceID)
	}
	if allowLoopback && sourcehttp.IsLoopbackHost(host) {
		return nil
	}
	for _, suffix := range []string{"api.identitynow.com", "api.identitynow-fed.com"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s base_url host is not allowed", sourcecdk.ErrInvalidConfig, sourceID)
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
