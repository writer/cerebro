package sourceregistry

import (
	"fmt"

	"github.com/writer/cerebro/internal/sourcecdk"
	githubsource "github.com/writer/cerebro/sources/github"
	oktasource "github.com/writer/cerebro/sources/okta"
)

type builtinSourceLoader struct {
	name string
	load func() (sourcecdk.Source, error)
}

var builtinSourceLoaders = []builtinSourceLoader{
	{
		name: "github",
		load: func() (sourcecdk.Source, error) {
			return githubsource.New()
		},
	},
	{
		name: "okta",
		load: func() (sourcecdk.Source, error) {
			return oktasource.New()
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
