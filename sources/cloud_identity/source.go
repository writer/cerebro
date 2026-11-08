// Package cloud_identity registers the bounded cloud-identity evidence source.
package cloud_identity

import (
	"embed"

	"github.com/writer/cerebro/internal/sourcecdk"
	cloudidentitysource "github.com/writer/cerebro/sources/internal/cloudidentity"
)

//go:embed catalog.yaml
var catalogFS embed.FS

func New() (*cloudidentitysource.Source, error) {
	spec, err := sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
	if err != nil {
		return nil, err
	}
	return cloudidentitysource.NewSource(spec, nil, nil)
}
