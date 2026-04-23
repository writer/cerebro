package sourcecdk

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

type catalogFile struct {
	ID           string   `yaml:"id"`
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	EmittedKinds []string `yaml:"emitted_kinds"`
}

// LoadCatalog parses a source catalog.yaml file into a source spec.
func LoadCatalog(data []byte) (*cerebrov1.SourceSpec, error) {
	var catalog catalogFile
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("unmarshal catalog: %w", err)
	}
	catalog.ID = strings.TrimSpace(catalog.ID)
	catalog.Name = strings.TrimSpace(catalog.Name)
	catalog.Description = strings.TrimSpace(catalog.Description)
	if catalog.ID == "" {
		return nil, fmt.Errorf("catalog id is required")
	}
	if catalog.Name == "" {
		return nil, fmt.Errorf("catalog name is required")
	}
	return &cerebrov1.SourceSpec{
		Id:           catalog.ID,
		Name:         catalog.Name,
		Description:  catalog.Description,
		EmittedKinds: catalog.EmittedKinds,
	}, nil
}
