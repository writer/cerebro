package policy

import (
	"testing"

	nativesync "github.com/evalops/cerebro/internal/sync"
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

func TestMappingRegistry_OrphanNativeTables(t *testing.T) {
	registry := NewMappingRegistry()
	registry.MustRegister("aws::s3::bucket", []string{"aws_s3_buckets"})
	registry.MustRegister("custom::resource", []string{"custom_table"})

	orphans := registry.OrphanNativeTables([]string{
		"aws_s3_buckets",
		"aws_ec2_instances",
		"custom_table",
		"not_native_table",
	})

	if len(orphans) != 1 || orphans[0] != "aws_ec2_instances" {
		t.Fatalf("expected aws_ec2_instances to be orphaned, got %v", orphans)
	}
}
