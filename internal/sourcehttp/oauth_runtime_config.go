package sourcehttp

import (
	"context"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
)

// ClientCredentialsRuntimeConfigOptions describes runtime config resolution for
// generated OAuth client-credentials sources.
type ClientCredentialsRuntimeConfigOptions struct {
	SourceID               string
	DefaultBaseURLTemplate string
	TemplateKeys           []string
	TokenCache             *ClientCredentialsCache
	TokenURLTemplate       string
	Scopes                 []string
	ScopeSeparator         string
	TokenParams            map[string]string
	ExpirationBuffer       time.Duration
	AllowLoopback          bool
}

// ResolveClientCredentialsRuntimeConfig renders provider-managed runtime
// values and injects a cached OAuth access token into the source config.
func ResolveClientCredentialsRuntimeConfig(ctx context.Context, cfg sourcecdk.Config, options ClientCredentialsRuntimeConfigOptions) (sourcecdk.Config, error) {
	runtimeCfg, err := sourcecdk.ResolveBaseURLConfig(options.SourceID, options.DefaultBaseURLTemplate, cfg, options.TemplateKeys)
	if err != nil {
		return sourcecdk.Config{}, err
	}
	token, err := options.TokenCache.Token(ctx, cfg, ClientCredentialsOptions{
		SourceID:         options.SourceID,
		TokenURLTemplate: options.TokenURLTemplate,
		TemplateKeys:     options.TemplateKeys,
		Scopes:           options.Scopes,
		ScopeSeparator:   options.ScopeSeparator,
		TokenParams:      options.TokenParams,
		ExpirationBuffer: options.ExpirationBuffer,
		AllowLoopback:    options.AllowLoopback,
	})
	if err != nil {
		return sourcecdk.Config{}, err
	}
	values := runtimeCfg.Values()
	values["token"] = token
	return sourcecdk.NewConfig(values), nil
}
