// Package projectionspec defines data-driven projection template specifications
// that replace the hardcoded switch statements in sourcegen. Each projection
// template is described by a YAML spec that declares its required attributes,
// classification class, and graph label.
package projectionspec

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed templates/*.yaml
var templateFS embed.FS

// Template describes a single projection template that sourcegen and the
// classifier can reference. Adding a new entity type to the codegen system
// is a matter of adding a YAML file under templates/.
type Template struct {
	ID                 string   `yaml:"id" json:"id"`
	Class              string   `yaml:"class" json:"class"`
	GraphLabel         string   `yaml:"graph_label" json:"graph_label"`
	RequiredAttributes []string `yaml:"required_attributes" json:"required_attributes"`
	URNKindPrefix      string   `yaml:"urn_kind_prefix" json:"urn_kind_prefix"`
	EventKindPrefix    bool     `yaml:"event_kind_prefix" json:"event_kind_prefix"`
	Description        string   `yaml:"description" json:"description"`
}

// Registry holds all loaded projection template specs.
type Registry struct {
	templates map[string]Template
	ids       []string
}

// Load reads and validates all embedded projection template specs.
func Load() (*Registry, error) {
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		return nil, fmt.Errorf("read projection template specs: %w", err)
	}
	registry := &Registry{templates: make(map[string]Template)}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		payload, err := templateFS.ReadFile("templates/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read template %s: %w", entry.Name(), err)
		}
		var template Template
		if err := yaml.Unmarshal(payload, &template); err != nil {
			return nil, fmt.Errorf("parse template %s: %w", entry.Name(), err)
		}
		if strings.TrimSpace(template.ID) == "" {
			return nil, fmt.Errorf("template %s: id is required", entry.Name())
		}
		if strings.TrimSpace(template.Class) == "" {
			return nil, fmt.Errorf("template %s: class is required", entry.Name())
		}
		if len(template.RequiredAttributes) == 0 {
			return nil, fmt.Errorf("template %s: required_attributes cannot be empty", entry.Name())
		}
		if _, exists := registry.templates[template.ID]; exists {
			return nil, fmt.Errorf("duplicate projection template id: %s", template.ID)
		}
		registry.templates[template.ID] = template
		registry.ids = append(registry.ids, template.ID)
	}
	sort.Strings(registry.ids)
	return registry, nil
}

// Get returns a projection template by ID.
func (r *Registry) Get(id string) (Template, bool) {
	template, ok := r.templates[id]
	return template, ok
}

// IDs returns all registered template IDs in sorted order.
func (r *Registry) IDs() []string {
	return append([]string(nil), r.ids...)
}

// ClassFor returns the executable projection class for a template ID. This
// replaces the hardcoded switch in sourcegen/generator.go.
func (r *Registry) ClassFor(id string) (string, bool) {
	template, ok := r.templates[id]
	if !ok {
		return "", false
	}
	return template.Class, true
}

// RequiredAttributesFor returns the required attributes for a projection class.
// This replaces requiredAttributesForClass in sourcegen/generator.go.
func (r *Registry) RequiredAttributesFor(class string) []string {
	for _, template := range r.templates {
		if template.Class == class {
			return append([]string(nil), template.RequiredAttributes...)
		}
	}
	return nil
}
