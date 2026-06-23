package sourcecdk

import (
	"embed"
	"fmt"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// LoadSpecFromFS reads a catalog YAML file from an embedded filesystem and
// parses it into a SourceSpec. This replaces the per-source loadSpec boilerplate
// that reads "catalog.yaml" and calls LoadCatalog.
func LoadSpecFromFS(fsys embed.FS, filename string) (*cerebrov1.SourceSpec, error) {
	data, err := fsys.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := LoadCatalog(data)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}
