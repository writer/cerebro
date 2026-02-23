package policy

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ResourceTableMapping captures one resource-to-table mapping entry.
type ResourceTableMapping struct {
	Resource string
	Tables   []string
}

// MappingRegistry stores normalized resource-to-table mappings.
type MappingRegistry struct {
	mu       sync.RWMutex
	mappings map[string][]string
}

var (
	globalMappingRegistry     *MappingRegistry
	globalMappingRegistryOnce sync.Once
)

// GlobalMappingRegistry returns the singleton mapping registry.
func GlobalMappingRegistry() *MappingRegistry {
	globalMappingRegistryOnce.Do(func() {
		registry := NewMappingRegistry()
		for resource, tables := range ResourceToTableMapping {
			registry.MustRegister(resource, tables)
		}
		globalMappingRegistry = registry
	})
	return globalMappingRegistry
}

// NewMappingRegistry creates an empty registry.
func NewMappingRegistry() *MappingRegistry {
	return &MappingRegistry{mappings: make(map[string][]string)}
}

// Register validates and stores a mapping.
func (r *MappingRegistry) Register(resource string, tables []string) error {
	normalizedResource, normalizedTables, err := normalizeMapping(resource, tables)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.mappings[normalizedResource]; exists {
		return fmt.Errorf("resource mapping %q already registered", normalizedResource)
	}
	r.mappings[normalizedResource] = normalizedTables
	return nil
}

// MustRegister stores a mapping and panics on validation failures.
func (r *MappingRegistry) MustRegister(resource string, tables []string) {
	if err := r.Register(resource, tables); err != nil {
		panic(fmt.Sprintf("failed to register mapping for %q: %v", resource, err))
	}
}

// Get returns mapped tables for a resource.
func (r *MappingRegistry) Get(resource string) ([]string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tables, ok := r.mappings[strings.TrimSpace(resource)]
	if !ok {
		return nil, false
	}
	return append([]string(nil), tables...), true
}

// List returns all mappings sorted by resource.
func (r *MappingRegistry) List() []ResourceTableMapping {
	r.mu.RLock()
	defer r.mu.RUnlock()

	resources := make([]string, 0, len(r.mappings))
	for resource := range r.mappings {
		resources = append(resources, resource)
	}
	sort.Strings(resources)

	mappings := make([]ResourceTableMapping, 0, len(resources))
	for _, resource := range resources {
		mappings = append(mappings, ResourceTableMapping{
			Resource: resource,
			Tables:   append([]string(nil), r.mappings[resource]...),
		})
	}
	return mappings
}

// Validate checks mapping integrity.
func (r *MappingRegistry) Validate() []error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var errs []error
	for resource, tables := range r.mappings {
		if strings.TrimSpace(resource) == "" {
			errs = append(errs, fmt.Errorf("mapping contains empty resource key"))
		}
		if len(tables) == 0 {
			errs = append(errs, fmt.Errorf("resource %q has no mapped tables", resource))
			continue
		}
		for _, table := range tables {
			if !isValidMappedTableName(table) {
				errs = append(errs, fmt.Errorf("resource %q maps to invalid table name %q", resource, table))
			}
		}
	}

	return errs
}

// ValidateNativeTableMappings verifies cloud-native table references are known.
func (r *MappingRegistry) ValidateNativeTableMappings(availableTables []string) []error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	available := normalizeTableSet(availableTables)

	errs := make([]error, 0)
	for resource, tables := range r.mappings {
		for _, table := range tables {
			name := strings.ToLower(strings.TrimSpace(table))
			if !isNativeCloudTable(name) {
				continue
			}
			if _, ok := available[name]; !ok {
				errs = append(errs, fmt.Errorf("resource %q maps to unknown native table %q", resource, name))
			}
		}
	}

	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return errs
}

// OrphanNativeTables returns native cloud tables that exist but have no policy mapping.
func (r *MappingRegistry) OrphanNativeTables(availableTables []string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	available := normalizeTableSet(availableTables)
	mappedNative := make(map[string]struct{})

	for _, tables := range r.mappings {
		for _, table := range tables {
			name := strings.ToLower(strings.TrimSpace(table))
			if isNativeCloudTable(name) {
				mappedNative[name] = struct{}{}
			}
		}
	}

	orphans := make([]string, 0)
	for table := range available {
		if !isNativeCloudTable(table) {
			continue
		}
		if _, ok := mappedNative[table]; ok {
			continue
		}
		orphans = append(orphans, table)
	}

	sort.Strings(orphans)
	return orphans
}

func normalizeTableSet(availableTables []string) map[string]struct{} {
	available := make(map[string]struct{}, len(availableTables))
	for _, table := range availableTables {
		trimmed := strings.ToLower(strings.TrimSpace(table))
		if trimmed == "" {
			continue
		}
		available[trimmed] = struct{}{}
	}
	return available
}

func normalizeMapping(resource string, tables []string) (string, []string, error) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "", nil, fmt.Errorf("resource is required")
	}

	normalizedTables := make([]string, 0, len(tables))
	seen := make(map[string]struct{}, len(tables))
	for _, table := range tables {
		name := strings.ToLower(strings.TrimSpace(table))
		if name == "" {
			continue
		}
		if !isValidMappedTableName(name) {
			return "", nil, fmt.Errorf("invalid table name %q for resource %q", table, resource)
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		normalizedTables = append(normalizedTables, name)
	}

	if len(normalizedTables) == 0 {
		return "", nil, fmt.Errorf("resource %q must map to at least one table", resource)
	}

	return resource, normalizedTables, nil
}

func isValidMappedTableName(name string) bool {
	if name == "*" {
		return true
	}
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}

func isNativeCloudTable(table string) bool {
	return strings.HasPrefix(table, "aws_") ||
		strings.HasPrefix(table, "gcp_") ||
		strings.HasPrefix(table, "azure_") ||
		strings.HasPrefix(table, "k8s_")
}
