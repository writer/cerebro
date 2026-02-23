package policy

import (
	"testing"

	nativesync "github.com/writerinternal/cerebro/internal/sync"
)

func TestGlobalMappingRegistry_LoadsAllMappings(t *testing.T) {
	registry := GlobalMappingRegistry()
	mappings := registry.List()

	if len(mappings) != len(ResourceToTableMapping) {
		t.Fatalf("expected %d mappings, got %d", len(ResourceToTableMapping), len(mappings))
	}
}

func TestGlobalMappingRegistry_Validate(t *testing.T) {
	registry := GlobalMappingRegistry()
	errs := registry.Validate()

	if len(errs) > 0 {
		for _, err := range errs {
			t.Errorf("mapping validation error: %v", err)
		}
	}
}

func TestGlobalMappingRegistry_NativeTablesExist(t *testing.T) {
	registry := GlobalMappingRegistry()
	errList := registry.ValidateNativeTableMappings(nativesync.SupportedTableNames())

	if len(errList) > 0 {
		for _, err := range errList {
			t.Errorf("native table mapping error: %v", err)
		}
	}
}

func TestResourceToTablesForType_UsesRegistry(t *testing.T) {
	tables := resourceToTablesForType("aws::iam::user")
	if len(tables) != 2 {
		t.Fatalf("expected aws::iam::user to map to 2 tables, got %d", len(tables))
	}
}
