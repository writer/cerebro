package sourceregistry

import (
	"fmt"

	"github.com/writer/cerebro/internal/sourcecdk"
	githubsource "github.com/writer/cerebro/sources/github"
)

// Builtin constructs the in-process source registry for the rewrite skeleton.
func Builtin() (*sourcecdk.Registry, error) {
	github, err := githubsource.New()
	if err != nil {
		return nil, fmt.Errorf("load github source: %w", err)
	}
	return sourcecdk.NewRegistry(github)
}
