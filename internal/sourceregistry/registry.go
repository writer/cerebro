package sourceregistry

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
	anthropicsource "github.com/writer/cerebro/sources/anthropic"
	archetypesource "github.com/writer/cerebro/sources/archetype"
	aureliussource "github.com/writer/cerebro/sources/aurelius"
	auth0source "github.com/writer/cerebro/sources/auth0"
	awssource "github.com/writer/cerebro/sources/aws"
	azuresource "github.com/writer/cerebro/sources/azure"
	catalogruntimesource "github.com/writer/cerebro/sources/catalogruntime"
	cerebrosource "github.com/writer/cerebro/sources/cerebro"
	cosmosource "github.com/writer/cerebro/sources/cosmo"
	emaildomainhealthsource "github.com/writer/cerebro/sources/emaildomainhealth"
	evidencecassource "github.com/writer/cerebro/sources/evidencecas"
	gcpsource "github.com/writer/cerebro/sources/gcp"
	githubsource "github.com/writer/cerebro/sources/github"
	googledrivesource "github.com/writer/cerebro/sources/google_drive"
	googleworkspacesource "github.com/writer/cerebro/sources/googleworkspace"
	grcsource "github.com/writer/cerebro/sources/grc"
	kandjisource "github.com/writer/cerebro/sources/kandji"
	kolidesource "github.com/writer/cerebro/sources/kolide"
	kubernetessource "github.com/writer/cerebro/sources/kubernetes"
	langfusesource "github.com/writer/cerebro/sources/langfuse"
	linodesource "github.com/writer/cerebro/sources/linode"
	oktasource "github.com/writer/cerebro/sources/okta"
	oneloginsource "github.com/writer/cerebro/sources/onelogin"
	panopticonsource "github.com/writer/cerebro/sources/panopticon"
	sailpointidentitynowsource "github.com/writer/cerebro/sources/sailpoint_identitynow"
	sdksource "github.com/writer/cerebro/sources/sdk"
	securitytoolingmapsource "github.com/writer/cerebro/sources/securitytoolingmap"
	snyksource "github.com/writer/cerebro/sources/snyk"
	trivysource "github.com/writer/cerebro/sources/trivy"
	trustedendpointsource "github.com/writer/cerebro/sources/trustedendpoint"
	vulnviewsource "github.com/writer/cerebro/sources/vulnview"
	writersource "github.com/writer/cerebro/sources/writer"
)

type DefinitionFixtureReadResult = catalogruntimesource.FixtureReadResult

type builtinSourceLoader struct {
	name string
	load func() (sourcecdk.Source, error)
}

var workerCatalogSourceIDs = []string{"asana", "digitalocean", "discord", "pagerduty", "sentinelone"}

var builtinSourceLoaders = []builtinSourceLoader{
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
		name: "cerebro",
		load: func() (sourcecdk.Source, error) {
			return cerebrosource.New()
		},
	},
	{
		name: "cosmo",
		load: func() (sourcecdk.Source, error) {
			return cosmosource.New()
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
		name: "snyk",
		load: func() (sourcecdk.Source, error) {
			return snyksource.New()
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

// BuiltinWithCatalogOverrides applies verified declarative catalog bytes to supported runtimes.
func BuiltinWithCatalogOverrides(overrides map[string][]byte) (*sourcecdk.Registry, error) {
	for sourceID := range overrides {
		if sourceID != "deepseek" {
			return nil, fmt.Errorf("connector catalog override %q is not supported", sourceID)
		}
	}
	sources := make([]sourcecdk.Source, 0, len(builtinSourceLoaders))
	registered := map[string]struct{}{}
	standardPlans, err := loadStandardSourcePlans()
	if err != nil {
		return nil, err
	}
	for _, loader := range builtinSourceLoaders {
		var source sourcecdk.Source
		var err error
		source, err = loader.load()
		if err != nil {
			return nil, fmt.Errorf("load %s source: %w", loader.name, err)
		}
		if spec := source.Spec(); spec != nil {
			registered[spec.Id] = struct{}{}
		}
		sources = append(sources, source)
	}
	metadataOnlyIDs := append(slices.Clone(workerCatalogSourceIDs), slices.Sorted(maps.Keys(standardPlans))...)
	for _, sourceID := range metadataOnlyIDs {
		source, err := newMetadataOnlyCatalogSource(sourceID)
		if err != nil {
			return nil, fmt.Errorf("load %s metadata-only source: %w", sourceID, err)
		}
		registered[sourceID] = struct{}{}
		sources = append(sources, source)
	}
	catalog, err := connectorcatalog.BuiltinRuntime()
	if err != nil {
		return nil, fmt.Errorf("load connector definition catalog: %w", err)
	}
	for _, entry := range catalog.Entries {
		sourceID := entry.Definition.SourceID
		if _, ok := registered[sourceID]; ok {
			continue
		}
		var source sourcecdk.Source
		if entry.Report.Verdict != connectordefinitions.SupportVerdictSupported {
			continue
		} else if catalogBytes := overrides[sourceID]; len(catalogBytes) != 0 {
			source, err = catalogruntimesource.NewWithCatalog(entry, catalogBytes)
		} else {
			source, err = catalogruntimesource.New(entry)
		}
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
