package sourceregistry

import (
	"fmt"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
	akeylessource "github.com/writer/cerebro/sources/akeyless"
	anthropicsource "github.com/writer/cerebro/sources/anthropic"
	archetypesource "github.com/writer/cerebro/sources/archetype"
	aureliussource "github.com/writer/cerebro/sources/aurelius"
	auth0source "github.com/writer/cerebro/sources/auth0"
	awssource "github.com/writer/cerebro/sources/aws"
	azuresource "github.com/writer/cerebro/sources/azure"
	backstagesource "github.com/writer/cerebro/sources/backstage"
	catalogruntimesource "github.com/writer/cerebro/sources/catalogruntime"
	cerebrosource "github.com/writer/cerebro/sources/cerebro"
	cloudflaresource "github.com/writer/cerebro/sources/cloudflare"
	cosmosource "github.com/writer/cerebro/sources/cosmo"
	dopplersource "github.com/writer/cerebro/sources/doppler"
	duosource "github.com/writer/cerebro/sources/duo"
	emaildomainhealthsource "github.com/writer/cerebro/sources/emaildomainhealth"
	evidencecassource "github.com/writer/cerebro/sources/evidencecas"
	gcpsource "github.com/writer/cerebro/sources/gcp"
	githubsource "github.com/writer/cerebro/sources/github"
	googleworkspacesource "github.com/writer/cerebro/sources/googleworkspace"
	grcsource "github.com/writer/cerebro/sources/grc"
	hashicorpvaultsource "github.com/writer/cerebro/sources/hashicorp_vault"
	kandjisource "github.com/writer/cerebro/sources/kandji"
	kolidesource "github.com/writer/cerebro/sources/kolide"
	kubernetessource "github.com/writer/cerebro/sources/kubernetes"
	oktasource "github.com/writer/cerebro/sources/okta"
	openaisource "github.com/writer/cerebro/sources/openai"
	pagerdutysource "github.com/writer/cerebro/sources/pagerduty"
	panopticonsource "github.com/writer/cerebro/sources/panopticon"
	sdksource "github.com/writer/cerebro/sources/sdk"
	securitytoolingmapsource "github.com/writer/cerebro/sources/securitytoolingmap"
	sentineloneSource "github.com/writer/cerebro/sources/sentinelone"
	slacksource "github.com/writer/cerebro/sources/slack"
	tailscalesource "github.com/writer/cerebro/sources/tailscale"
	trivysource "github.com/writer/cerebro/sources/trivy"
	trustedendpointsource "github.com/writer/cerebro/sources/trustedendpoint"
	vulnviewsource "github.com/writer/cerebro/sources/vulnview"
)

type builtinSourceLoader struct {
	name string
	load func() (sourcecdk.Source, error)
}

var builtinSourceLoaders = []builtinSourceLoader{
	{
		name: "evidence_cas",
		load: func() (sourcecdk.Source, error) {
			return evidencecassource.New()
		},
	},
	{
		name: "aurelius",
		load: func() (sourcecdk.Source, error) {
			return aureliussource.New()
		},
	},
	{
		name: "anthropic",
		load: func() (sourcecdk.Source, error) {
			return anthropicsource.New()
		},
	},
	{
		name: "akeyless",
		load: func() (sourcecdk.Source, error) {
			return akeylessource.New()
		},
	},
	{
		name: "archetype",
		load: func() (sourcecdk.Source, error) {
			return archetypesource.New()
		},
	},
	{
		name: "auth0",
		load: func() (sourcecdk.Source, error) {
			return auth0source.New()
		},
	},
	{
		name: "aws",
		load: func() (sourcecdk.Source, error) {
			return awssource.New()
		},
	},
	{
		name: "azure",
		load: func() (sourcecdk.Source, error) {
			return azuresource.New()
		},
	},
	{
		name: "backstage",
		load: func() (sourcecdk.Source, error) {
			return backstagesource.New()
		},
	},
	{
		name: "cerebro",
		load: func() (sourcecdk.Source, error) {
			return cerebrosource.New()
		},
	},
	{
		name: "cloudflare",
		load: func() (sourcecdk.Source, error) {
			return cloudflaresource.New()
		},
	},
	{
		name: "cosmo",
		load: func() (sourcecdk.Source, error) {
			return cosmosource.New()
		},
	},
	{
		name: "duo",
		load: func() (sourcecdk.Source, error) {
			return duosource.New()
		},
	},
	{
		name: "doppler",
		load: func() (sourcecdk.Source, error) {
			return dopplersource.New()
		},
	},
	{
		name: "email_domain_health",
		load: func() (sourcecdk.Source, error) {
			return emaildomainhealthsource.New()
		},
	},
	{
		name: "gcp",
		load: func() (sourcecdk.Source, error) {
			return gcpsource.New()
		},
	},
	{
		name: "github",
		load: func() (sourcecdk.Source, error) {
			return githubsource.New()
		},
	},
	{
		name: "google_workspace",
		load: func() (sourcecdk.Source, error) {
			return googleworkspacesource.New()
		},
	},
	{
		name: "grc",
		load: func() (sourcecdk.Source, error) {
			return grcsource.New()
		},
	},
	{
		name: "hashicorp_vault",
		load: func() (sourcecdk.Source, error) {
			return hashicorpvaultsource.New()
		},
	},
	{
		name: "kandji",
		load: func() (sourcecdk.Source, error) {
			return kandjisource.New()
		},
	},
	{
		name: "kubernetes",
		load: func() (sourcecdk.Source, error) {
			return kubernetessource.New()
		},
	},
	{
		name: "kolide",
		load: func() (sourcecdk.Source, error) {
			return kolidesource.New()
		},
	},
	{
		name: "okta",
		load: func() (sourcecdk.Source, error) {
			return oktasource.New()
		},
	},
	{
		name: "openai",
		load: func() (sourcecdk.Source, error) {
			return openaisource.New()
		},
	},
	{
		name: "panopticon",
		load: func() (sourcecdk.Source, error) {
			return panopticonsource.New()
		},
	},
	{
		name: "pagerduty",
		load: func() (sourcecdk.Source, error) {
			return pagerdutysource.New()
		},
	},
	{
		name: "sdk",
		load: func() (sourcecdk.Source, error) {
			return sdksource.New()
		},
	},
	{
		name: "sentinelone",
		load: func() (sourcecdk.Source, error) {
			return sentineloneSource.New()
		},
	},
	{
		name: "slack",
		load: func() (sourcecdk.Source, error) {
			return slacksource.New()
		},
	},
	{
		name: "tailscale",
		load: func() (sourcecdk.Source, error) {
			return tailscalesource.New()
		},
	},
	{
		name: "security_tooling_map",
		load: func() (sourcecdk.Source, error) {
			return securitytoolingmapsource.New()
		},
	},
	{
		name: "trusted_endpoint",
		load: func() (sourcecdk.Source, error) {
			return trustedendpointsource.New()
		},
	},
	{
		name: "trivy",
		load: func() (sourcecdk.Source, error) {
			return trivysource.New()
		},
	},
	{
		name: "vulnview",
		load: func() (sourcecdk.Source, error) {
			return vulnviewsource.New()
		},
	},
}

// DynamicDefinitionSource adapts a stored dynamic connector definition into the
// source layer without exposing concrete source packages to callers.
func DynamicDefinitionSource(definition connectordefinitions.Definition) (sourcecdk.Source, error) {
	return catalogruntimesource.NewDefinition(definition)
}

// Builtin constructs the in-process source registry for the rewrite skeleton.
func Builtin() (*sourcecdk.Registry, error) {
	sources := make([]sourcecdk.Source, 0, len(builtinSourceLoaders))
	registered := map[string]struct{}{}
	for _, loader := range builtinSourceLoaders {
		source, err := loader.load()
		if err != nil {
			return nil, fmt.Errorf("load %s source: %w", loader.name, err)
		}
		if spec := source.Spec(); spec != nil {
			registered[spec.Id] = struct{}{}
		}
		sources = append(sources, source)
	}
	catalog, err := connectorcatalog.Builtin()
	if err != nil {
		return nil, fmt.Errorf("load connector definition catalog: %w", err)
	}
	for _, entry := range catalog.Entries {
		sourceID := entry.Definition.SourceID
		if _, ok := registered[sourceID]; ok || entry.Status != connectorcatalog.StatusGenerateable {
			continue
		}
		source, err := catalogruntimesource.New(entry)
		if err != nil {
			return nil, fmt.Errorf("load catalog source %s: %w", sourceID, err)
		}
		registered[sourceID] = struct{}{}
		sources = append(sources, source)
	}
	registry, err := sourcecdk.NewRegistry(sources...)
	if err != nil {
		return nil, err
	}
	return registry.WithBuiltinDefinitionCatalog(), nil
}
