package sourcecdk

import (
	"context"
	"fmt"
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
)

// URN identifies an entity surfaced by a source.
type URN string

// ParseURN validates the canonical Cerebro URN format.
func ParseURN(raw string) (URN, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("urn is required")
	}
	if !strings.HasPrefix(value, "urn:cerebro:") {
		return "", fmt.Errorf("invalid cerebro urn %q", value)
	}
	parts := strings.Split(value, ":")
	if len(parts) != 5 || parts[0] != "urn" || parts[1] != "cerebro" || parts[2] == "" || parts[3] == "" || parts[4] == "" {
		return "", fmt.Errorf("invalid cerebro urn %q", value)
	}
	return URN(value), nil
}

// String returns the raw URN string.
func (u URN) String() string {
	return string(u)
}

// Config carries source-specific static configuration.
type Config struct {
	values map[string]string
}

// NewConfig snapshots source configuration.
func NewConfig(values map[string]string) Config {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return Config{values: cloned}
}

// Lookup returns a single config value.
func (c Config) Lookup(key string) (string, bool) {
	value, ok := c.values[key]
	return value, ok
}

// Values returns a cloned map of all config entries.
func (c Config) Values() map[string]string {
	return NewConfig(c.values).values
}

// Pull is one page of source output.
type Pull struct {
	Events     []*primitives.Event
	Checkpoint *cerebrov1.SourceCheckpoint
	NextCursor *cerebrov1.SourceCursor
}

// Source is the common integration contract for the rewrite.
type Source interface {
	Spec() *cerebrov1.SourceSpec
	Check(context.Context, Config) error
	Discover(context.Context, Config) ([]URN, error)
	Read(context.Context, Config, *cerebrov1.SourceCursor) (Pull, error)
}

// Registry indexes sources by their stable identifier.
type Registry struct {
	sources map[string]Source
}

// NewRegistry constructs a source registry and rejects duplicate or invalid specs.
func NewRegistry(sources ...Source) (*Registry, error) {
	indexed := make(map[string]Source, len(sources))
	for _, source := range sources {
		if source == nil {
			return nil, fmt.Errorf("source is required")
		}
		spec := source.Spec()
		if spec == nil {
			return nil, fmt.Errorf("source spec is required")
		}
		rawID := spec.Id
		id := strings.TrimSpace(rawID)
		if id == "" {
			return nil, fmt.Errorf("source id is required")
		}
		if id != rawID {
			return nil, fmt.Errorf("source id %q must not have leading/trailing whitespace", rawID)
		}
		if _, exists := indexed[id]; exists {
			return nil, fmt.Errorf("duplicate source id %q", id)
		}
		indexed[id] = source
	}
	return &Registry{sources: indexed}, nil
}

// Get returns a registered source by ID.
func (r *Registry) Get(id string) (Source, bool) {
	if r == nil {
		return nil, false
	}
	source, ok := r.sources[id]
	return source, ok
}

// List returns all registered source specs sorted by ID.
func (r *Registry) List() []*cerebrov1.SourceSpec {
	if r == nil {
		return nil
	}
	ids := make([]string, 0, len(r.sources))
	for id := range r.sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	specs := make([]*cerebrov1.SourceSpec, 0, len(ids))
	for _, id := range ids {
		specs = append(specs, r.sources[id].Spec())
	}
	return specs
}
