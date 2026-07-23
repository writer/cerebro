package docker_hub

import (
	"embed"
	"fmt"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/sources/catalogruntime"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID           = "docker_hub"
	defaultFamily      = familyRepositories
	familyRepositories = "repositories"
)

// Source is the shared catalog-backed runtime used for Docker Hub.
type Source = catalogruntime.Source

// New constructs Docker Hub from its declarative connector definition.
func New() (*Source, error) {
	entry, ok, err := connectorcatalog.BuiltinEntry(sourceID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("connector definition %q not found", sourceID)
	}
	return catalogruntime.New(entry)
}
