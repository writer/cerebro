package sourceregistry

import (
	"fmt"

	"github.com/writer/cerebro/internal/sourcecdk"
	aureliussource "github.com/writer/cerebro/sources/aurelius"
	awssource "github.com/writer/cerebro/sources/aws"
	azuresource "github.com/writer/cerebro/sources/azure"
	backstagesource "github.com/writer/cerebro/sources/backstage"
	cerebrosource "github.com/writer/cerebro/sources/cerebro"
	cosmosource "github.com/writer/cerebro/sources/cosmo"
	evidencecassource "github.com/writer/cerebro/sources/evidencecas"
	gcpsource "github.com/writer/cerebro/sources/gcp"
	githubsource "github.com/writer/cerebro/sources/github"
	googleworkspacesource "github.com/writer/cerebro/sources/googleworkspace"
	grcsource "github.com/writer/cerebro/sources/grc"
	kandjisource "github.com/writer/cerebro/sources/kandji"
	kolidesource "github.com/writer/cerebro/sources/kolide"
	oktasource "github.com/writer/cerebro/sources/okta"
	panopticonsource "github.com/writer/cerebro/sources/panopticon"
	sdksource "github.com/writer/cerebro/sources/sdk"
	securitytoolingmapsource "github.com/writer/cerebro/sources/securitytoolingmap"
	sentineloneSource "github.com/writer/cerebro/sources/sentinelone"
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
		name: "cosmo",
		load: func() (sourcecdk.Source, error) {
			return cosmosource.New()
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
		name: "okta",
		load: func() (sourcecdk.Source, error) {
			return oktasource.New()
		},
	},
	{
		name: "panopticon",
		load: func() (sourcecdk.Source, error) {
			return panopticonsource.New()
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
		name: "vulnview",
		load: func() (sourcecdk.Source, error) {
			return vulnviewsource.New()
		},
	},
}

// Builtin constructs the in-process source registry for the rewrite skeleton.
func Builtin() (*sourcecdk.Registry, error) {
	sources := make([]sourcecdk.Source, 0, len(builtinSourceLoaders))
	for _, loader := range builtinSourceLoaders {
		source, err := loader.load()
		if err != nil {
			return nil, fmt.Errorf("load %s source: %w", loader.name, err)
		}
		sources = append(sources, source)
	}
	return sourcecdk.NewRegistry(sources...)
}
