package sourcecdk

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

type catalogFile struct {
	ID             string                 `yaml:"id"`
	Name           string                 `yaml:"name"`
	Description    string                 `yaml:"description"`
	EmittedKinds   []string               `yaml:"emitted_kinds"`
	KindLifecycle  []catalogKindLifecycle `yaml:"kind_lifecycle"`
	EventContracts []EventContract        `yaml:"event_contracts"`
}

type catalogKindLifecycle struct {
	Kind        string `yaml:"kind"`
	Status      string `yaml:"status"`
	Replacement string `yaml:"replacement"`
}

type SourceCatalog struct {
	Spec           *cerebrov1.SourceSpec
	EventContracts []EventContract
}

// LoadCatalog parses a source catalog.yaml file into a source spec.
func LoadCatalog(data []byte) (*cerebrov1.SourceSpec, error) {
	catalog, err := LoadSourceCatalog(data)
	if err != nil {
		return nil, err
	}
	return catalog.Spec, nil
}

// LoadSourceCatalog parses a source catalog.yaml file, including optional event contracts.
func LoadSourceCatalog(data []byte) (*SourceCatalog, error) {
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
	emittedKinds, err := normalizeCatalogKinds(catalog.EmittedKinds)
	if err != nil {
		return nil, err
	}
	if err := validateCatalogLifecycle(catalog.KindLifecycle); err != nil {
		return nil, err
	}
	eventContracts, err := ValidateEventContracts(catalog.EventContracts)
	if err != nil {
		return nil, err
	}
	return &SourceCatalog{Spec: &cerebrov1.SourceSpec{
		Id:           catalog.ID,
		Name:         catalog.Name,
		Description:  catalog.Description,
		EmittedKinds: emittedKinds,
	}, EventContracts: eventContracts}, nil
}

func normalizeCatalogKinds(values []string) ([]string, error) {
	kinds := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		kind := strings.TrimSpace(value)
		if kind == "" {
			return nil, fmt.Errorf("emitted kind is required")
		}
		if !validEventKind(kind) {
			return nil, fmt.Errorf("emitted kind %q must use dot-separated lowercase identifiers", kind)
		}
		if _, ok := seen[kind]; ok {
			return nil, fmt.Errorf("duplicate emitted kind %q", kind)
		}
		seen[kind] = struct{}{}
		kinds = append(kinds, kind)
	}
	return kinds, nil
}

func validateCatalogLifecycle(entries []catalogKindLifecycle) error {
	seen := map[string]struct{}{}
	for _, entry := range entries {
		kind := strings.TrimSpace(entry.Kind)
		status := strings.ToLower(strings.TrimSpace(entry.Status))
		if kind == "" {
			return fmt.Errorf("kind_lifecycle kind is required")
		}
		if !validEventKind(kind) {
			return fmt.Errorf("kind_lifecycle kind %q must use dot-separated lowercase identifiers", kind)
		}
		if _, ok := seen[kind]; ok {
			return fmt.Errorf("duplicate kind_lifecycle kind %q", kind)
		}
		seen[kind] = struct{}{}
		switch status {
		case "active", "planned", "deprecated", "retired":
		default:
			return fmt.Errorf("kind_lifecycle kind %q has invalid status %q", kind, entry.Status)
		}
		replacement := strings.TrimSpace(entry.Replacement)
		if replacement != "" && !validEventKind(replacement) {
			return fmt.Errorf("kind_lifecycle kind %q has invalid replacement %q", kind, replacement)
		}
	}
	return nil
}
