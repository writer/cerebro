package connectorvalidation

import (
	"embed"
	"fmt"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed registry.yaml
var builtinRegistryFS embed.FS

var (
	builtinOnce     sync.Once
	builtinRegistry Registry
	builtinErr      error
)

func BuiltinRegistry() (Registry, error) {
	builtinOnce.Do(func() {
		payload, err := builtinRegistryFS.ReadFile("registry.yaml")
		if err != nil {
			builtinErr = err
			return
		}
		builtinRegistry, builtinErr = LoadRegistry(payload)
	})
	return builtinRegistry, builtinErr
}

func LoadRegistry(payload []byte) (Registry, error) {
	var registry Registry
	if err := yaml.Unmarshal(payload, &registry); err != nil {
		return Registry{}, fmt.Errorf("unmarshal connector validation registry: %w", err)
	}
	for i := range registry.Entries {
		registry.Entries[i] = NormalizeEntryValidation(registry.Entries[i].SourceID, registry.Entries[i], "")
		if registry.Entries[i].SourceID == "" {
			return Registry{}, fmt.Errorf("entries[%d] source_id is required", i)
		}
	}
	sort.SliceStable(registry.Entries, func(i, j int) bool {
		return registry.Entries[i].SourceID < registry.Entries[j].SourceID
	})
	return registry, nil
}

func (r Registry) BySourceID(sourceID string) (ConnectorValidation, bool) {
	sourceID = strings.TrimSpace(sourceID)
	for _, entry := range r.Entries {
		if entry.SourceID == sourceID {
			return entry, true
		}
	}
	return ConnectorValidation{}, false
}

func BuiltinValidationForSource(sourceID string) ConnectorValidation {
	registry, err := BuiltinRegistry()
	if err != nil {
		return NormalizeEntryValidation(sourceID, ConnectorValidation{}, "")
	}
	if validation, ok := registry.BySourceID(sourceID); ok {
		return validation
	}
	return NormalizeEntryValidation(sourceID, ConnectorValidation{}, "")
}

func BuiltinGradeForSourceFamily(sourceID string, familyID string) Grade {
	return FamilyGrade(BuiltinValidationForSource(sourceID), familyID)
}
