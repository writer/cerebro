package sourceregistry

import (
	"fmt"

	"github.com/writer/cerebro/internal/sourcecdk"
	awssource "github.com/writer/cerebro/sources/aws"
	gcpsource "github.com/writer/cerebro/sources/gcp"
	githubsource "github.com/writer/cerebro/sources/github"
	googleworkspacesource "github.com/writer/cerebro/sources/googleworkspace"
	oktasource "github.com/writer/cerebro/sources/okta"
	sdksource "github.com/writer/cerebro/sources/sdk"
)

type builtinSourceLoader struct {
	name string
	load func() (sourcecdk.Source, error)
}

var builtinSourceLoaders = []builtinSourceLoader{
	{
		name: "aws",
		load: func() (sourcecdk.Source, error) {
			return awssource.New()
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
		name: "okta",
		load: func() (sourcecdk.Source, error) {
			return oktasource.New()
		},
	},
	{
		name: "sdk",
		load: func() (sourcecdk.Source, error) {
			return sdksource.New()
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
