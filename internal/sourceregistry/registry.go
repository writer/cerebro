package sourceregistry

import (
	"context"
	"fmt"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
	acunetixsource "github.com/writer/cerebro/sources/acunetix"
	adobeworkfrontsource "github.com/writer/cerebro/sources/adobe_workfront"
	aircallsource "github.com/writer/cerebro/sources/aircall"
	airfocussource "github.com/writer/cerebro/sources/airfocus"
	akeylesssource "github.com/writer/cerebro/sources/akeyless"
	anthropicsource "github.com/writer/cerebro/sources/anthropic"
	archetypesource "github.com/writer/cerebro/sources/archetype"
	asanasource "github.com/writer/cerebro/sources/asana"
	aureliussource "github.com/writer/cerebro/sources/aurelius"
	auth0source "github.com/writer/cerebro/sources/auth0"
	awssource "github.com/writer/cerebro/sources/aws"
	azuresource "github.com/writer/cerebro/sources/azure"
	backstagesource "github.com/writer/cerebro/sources/backstage"
	beezupsource "github.com/writer/cerebro/sources/beezup"
	bitwardensource "github.com/writer/cerebro/sources/bitwarden"
	boxsource "github.com/writer/cerebro/sources/box"
	catalogruntimesource "github.com/writer/cerebro/sources/catalogruntime"
	cerebrosource "github.com/writer/cerebro/sources/cerebro"
	cloudflaresource "github.com/writer/cerebro/sources/cloudflare"
	conjursource "github.com/writer/cerebro/sources/conjur"
	cosmosource "github.com/writer/cerebro/sources/cosmo"
	datadogsource "github.com/writer/cerebro/sources/datadog"
	deepseeksource "github.com/writer/cerebro/sources/deepseek"
	digitaloceansource "github.com/writer/cerebro/sources/digitalocean"
	discordsource "github.com/writer/cerebro/sources/discord"
	dopplersource "github.com/writer/cerebro/sources/doppler"
	duosource "github.com/writer/cerebro/sources/duo"
	emaildomainhealthsource "github.com/writer/cerebro/sources/emaildomainhealth"
	evidencecassource "github.com/writer/cerebro/sources/evidencecas"
	fivetransource "github.com/writer/cerebro/sources/fivetran"
	gcpsource "github.com/writer/cerebro/sources/gcp"
	githubsource "github.com/writer/cerebro/sources/github"
	googledrivesource "github.com/writer/cerebro/sources/google_drive"
	googleworkspacesource "github.com/writer/cerebro/sources/googleworkspace"
	grcsource "github.com/writer/cerebro/sources/grc"
	hashicorpvaultsource "github.com/writer/cerebro/sources/hashicorp_vault"
	increasesource "github.com/writer/cerebro/sources/increase"
	jirasource "github.com/writer/cerebro/sources/jira"
	jumpcloudsource "github.com/writer/cerebro/sources/jumpcloud"
	kandjisource "github.com/writer/cerebro/sources/kandji"
	kolidesource "github.com/writer/cerebro/sources/kolide"
	kubernetessource "github.com/writer/cerebro/sources/kubernetes"
	langchainsource "github.com/writer/cerebro/sources/langchain"
	langfusesource "github.com/writer/cerebro/sources/langfuse"
	linodesource "github.com/writer/cerebro/sources/linode"
	oktasource "github.com/writer/cerebro/sources/okta"
	oneloginsource "github.com/writer/cerebro/sources/onelogin"
	openaisource "github.com/writer/cerebro/sources/openai"
	pagerdutysource "github.com/writer/cerebro/sources/pagerduty"
	panopticonsource "github.com/writer/cerebro/sources/panopticon"
	sailpointidentitynowsource "github.com/writer/cerebro/sources/sailpoint_identitynow"
	sdksource "github.com/writer/cerebro/sources/sdk"
	securitytoolingmapsource "github.com/writer/cerebro/sources/securitytoolingmap"
	sentinelonesource "github.com/writer/cerebro/sources/sentinelone"
	snyksource "github.com/writer/cerebro/sources/snyk"
	tailscalesource "github.com/writer/cerebro/sources/tailscale"
	trivysource "github.com/writer/cerebro/sources/trivy"
	trustedendpointsource "github.com/writer/cerebro/sources/trustedendpoint"
	twiliosource "github.com/writer/cerebro/sources/twilio"
	vulnviewsource "github.com/writer/cerebro/sources/vulnview"
	writersource "github.com/writer/cerebro/sources/writer"
)

type DefinitionFixtureReadResult = catalogruntimesource.FixtureReadResult

type builtinSourceLoader struct {
	name string
	load func() (sourcecdk.Source, error)
}

var builtinSourceLoaders = []builtinSourceLoader{
	{
		name: "acunetix",
		load: func() (sourcecdk.Source, error) {
			return acunetixsource.New()
		},
	},
	{
		name: "adobe_workfront",
		load: func() (sourcecdk.Source, error) {
			return adobeworkfrontsource.New()
		},
	},
	{
		name: "aircall",
		load: func() (sourcecdk.Source, error) {
			return aircallsource.New()
		},
	},
	{
		name: "airfocus",
		load: func() (sourcecdk.Source, error) {
			return airfocussource.New()
		},
	},
	{
		name: "akeyless",
		load: func() (sourcecdk.Source, error) {
			return akeylesssource.New()
		},
	},
	{
		name: "anthropic",
		load: func() (sourcecdk.Source, error) {
			return anthropicsource.New()
		},
	},
	{
		name: "archetype",
		load: func() (sourcecdk.Source, error) {
			return archetypesource.New()
		},
	},
	{
		name: "asana",
		load: func() (sourcecdk.Source, error) {
			return asanasource.New()
		},
	},
	{
		name: "aurelius",
		load: func() (sourcecdk.Source, error) {
			return aureliussource.New()
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
		name: "beezup",
		load: func() (sourcecdk.Source, error) {
			return beezupsource.New()
		},
	},
	{
		name: "bitwarden",
		load: func() (sourcecdk.Source, error) {
			return bitwardensource.New()
		},
	},
	{
		name: "box",
		load: func() (sourcecdk.Source, error) {
			return boxsource.New()
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
		name: "conjur",
		load: func() (sourcecdk.Source, error) {
			return conjursource.New()
		},
	},
	{
		name: "cosmo",
		load: func() (sourcecdk.Source, error) {
			return cosmosource.New()
		},
	},
	{
		name: "datadog",
		load: func() (sourcecdk.Source, error) {
			return datadogsource.New()
		},
	},
	{
		name: "deepseek",
		load: func() (sourcecdk.Source, error) {
			return deepseeksource.New()
		},
	},
	{
		name: "digitalocean",
		load: func() (sourcecdk.Source, error) {
			return digitaloceansource.New()
		},
	},
	{
		name: "discord",
		load: func() (sourcecdk.Source, error) {
			return discordsource.New()
		},
	},
	{
		name: "doppler",
		load: func() (sourcecdk.Source, error) {
			return dopplersource.New()
		},
	},
	{
		name: "duo",
		load: func() (sourcecdk.Source, error) {
			return duosource.New()
		},
	},
	{
		name: "emaildomainhealth",
		load: func() (sourcecdk.Source, error) {
			return emaildomainhealthsource.New()
		},
	},
	{
		name: "evidencecas",
		load: func() (sourcecdk.Source, error) {
			return evidencecassource.New()
		},
	},
	{
		name: "fivetran",
		load: func() (sourcecdk.Source, error) {
			return fivetransource.New()
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
		name: "google_drive",
		load: func() (sourcecdk.Source, error) {
			return googledrivesource.New()
		},
	},
	{
		name: "googleworkspace",
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
		name: "increase",
		load: func() (sourcecdk.Source, error) {
			return increasesource.New()
		},
	},
	{
		name: "jira",
		load: func() (sourcecdk.Source, error) {
			return jirasource.New()
		},
	},
	{
		name: "jumpcloud",
		load: func() (sourcecdk.Source, error) {
			return jumpcloudsource.New()
		},
	},
	{
		name: "kandji",
		load: func() (sourcecdk.Source, error) {
			return kandjisource.New()
		},
	},
	{
		name: "kolide",
		load: func() (sourcecdk.Source, error) {
			return kolidesource.New()
		},
	},
	{
		name: "kubernetes",
		load: func() (sourcecdk.Source, error) {
			return kubernetessource.New()
		},
	},
	{
		name: "langchain",
		load: func() (sourcecdk.Source, error) {
			return langchainsource.New()
		},
	},
	{
		name: "langfuse",
		load: func() (sourcecdk.Source, error) {
			return langfusesource.New()
		},
	},
	{
		name: "linode",
		load: func() (sourcecdk.Source, error) {
			return linodesource.New()
		},
	},
	{
		name: "okta",
		load: func() (sourcecdk.Source, error) {
			return oktasource.New()
		},
	},
	{
		name: "onelogin",
		load: func() (sourcecdk.Source, error) {
			return oneloginsource.New()
		},
	},
	{
		name: "openai",
		load: func() (sourcecdk.Source, error) {
			return openaisource.New()
		},
	},
	{
		name: "pagerduty",
		load: func() (sourcecdk.Source, error) {
			return pagerdutysource.New()
		},
	},
	{
		name: "panopticon",
		load: func() (sourcecdk.Source, error) {
			return panopticonsource.New()
		},
	},
	{
		name: "sailpoint_identitynow",
		load: func() (sourcecdk.Source, error) {
			return sailpointidentitynowsource.New()
		},
	},
	{
		name: "sdk",
		load: func() (sourcecdk.Source, error) {
			return sdksource.New()
		},
	},
	{
		name: "securitytoolingmap",
		load: func() (sourcecdk.Source, error) {
			return securitytoolingmapsource.New()
		},
	},
	{
		name: "sentinelone",
		load: func() (sourcecdk.Source, error) {
			return sentinelonesource.New()
		},
	},
	{
		name: "snyk",
		load: func() (sourcecdk.Source, error) {
			return snyksource.New()
		},
	},
	{
		name: "tailscale",
		load: func() (sourcecdk.Source, error) {
			return tailscalesource.New()
		},
	},
	{
		name: "trivy",
		load: func() (sourcecdk.Source, error) {
			return trivysource.New()
		},
	},
	{
		name: "trustedendpoint",
		load: func() (sourcecdk.Source, error) {
			return trustedendpointsource.New()
		},
	},
	{
		name: "twilio",
		load: func() (sourcecdk.Source, error) {
			return twiliosource.New()
		},
	},
	{
		name: "vulnview",
		load: func() (sourcecdk.Source, error) {
			return vulnviewsource.New()
		},
	},
	{
		name: "writer",
		load: func() (sourcecdk.Source, error) {
			return writersource.New()
		},
	},
}

// DynamicDefinitionSource adapts a stored dynamic connector definition into the
// source layer without exposing concrete source packages to callers.
func DynamicDefinitionSource(definition connectordefinitions.Definition) (sourcecdk.Source, error) {
	normalized, err := connectordefinitions.Normalize(definition)
	if err != nil {
		return nil, err
	}
	if normalized.Validation.Status == connectordefinitions.ValidationBlocked {
		return nil, fmt.Errorf("%w: connector definition %q is blocked: %s", connectordefinitions.ErrInvalidDefinition, normalized.SourceID, normalized.Validation.Summary)
	}
	if normalized.Ingest.Mode == connectordefinitions.IngestModeDeposit {
		return newDepositDefinitionSource(normalized), nil
	}
	return catalogruntimesource.NewDefinition(normalized)
}

func ReadDynamicDefinitionFixture(ctx context.Context, definition connectordefinitions.Definition, familyID string, body []byte) (DefinitionFixtureReadResult, error) {
	return catalogruntimesource.ReadDefinitionFixture(ctx, definition, familyID, body)
}

// Builtin constructs the in-process source registry for the rewrite skeleton.
func Builtin() (*sourcecdk.Registry, error) {
	return BuiltinWithCatalogOverrides(nil)
}

// BuiltinWithCatalogOverrides applies verified declarative catalog bytes to fixed kernel runtimes.
func BuiltinWithCatalogOverrides(overrides map[string][]byte) (*sourcecdk.Registry, error) {
	for sourceID := range overrides {
		if sourceID != "deepseek" {
			return nil, fmt.Errorf("connector catalog override %q is not supported", sourceID)
		}
	}
	sources := make([]sourcecdk.Source, 0, len(builtinSourceLoaders))
	registered := map[string]struct{}{}
	for _, loader := range builtinSourceLoaders {
		var source sourcecdk.Source
		var err error
		if loader.name == "deepseek" && len(overrides["deepseek"]) != 0 {
			source, err = deepseeksource.NewWithCatalog(overrides["deepseek"])
		} else {
			source, err = loader.load()
		}
		if err != nil {
			return nil, fmt.Errorf("load %s source: %w", loader.name, err)
		}
		if spec := source.Spec(); spec != nil {
			registered[spec.Id] = struct{}{}
		}
		sources = append(sources, source)
	}
	catalog, err := connectorcatalog.BuiltinRuntime()
	if err != nil {
		return nil, fmt.Errorf("load connector definition catalog: %w", err)
	}
	for _, entry := range catalog.Entries {
		sourceID := entry.Definition.SourceID
		if _, ok := registered[sourceID]; ok || entry.Report.Verdict != connectordefinitions.SupportVerdictSupported {
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
