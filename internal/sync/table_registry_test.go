package sync

import (
	"reflect"
	"slices"
	"testing"
)

func TestTableRegistry_RegisterAllTables(t *testing.T) {
	RegisterAllTables()
	registry := GlobalTableRegistry()

	stats := registry.Stats()
	if stats.TotalTables == 0 {
		t.Fatal("expected non-empty table registry")
	}

	if stats.ByProvider[TableProviderAWS] == 0 {
		t.Fatal("expected AWS tables to be registered")
	}
	if stats.ByProvider[TableProviderGCP] == 0 {
		t.Fatal("expected GCP tables to be registered")
	}
	if stats.ByProvider[TableProviderAzure] == 0 {
		t.Fatal("expected Azure tables to be registered")
	}
	if stats.ByProvider[TableProviderKubernetes] == 0 {
		t.Fatal("expected Kubernetes tables to be registered")
	}

	missing := registry.VerifyExpectedTables()
	if len(missing) > 0 {
		t.Fatalf("missing expected tables: %v", missing)
	}
}

func TestTableRegistry_Validate(t *testing.T) {
	RegisterAllTables()
	registry := GlobalTableRegistry()

	errs := registry.Validate()
	if len(errs) > 0 {
		for _, err := range errs {
			t.Errorf("validation error: %v", err)
		}
	}
}

func TestTableRegistry_MultiSourceTableMerging(t *testing.T) {
	RegisterAllTables()
	registry := GlobalTableRegistry()

	table, ok := registry.Get("gcp_compute_instances")
	if !ok {
		t.Fatal("expected gcp_compute_instances to be registered")
	}

	if !containsTableSource(table.Sources, TableSourceNative) {
		t.Fatalf("expected gcp_compute_instances to include %q source", TableSourceNative)
	}
	if !containsTableSource(table.Sources, TableSourceAssetInventory) {
		t.Fatalf("expected gcp_compute_instances to include %q source", TableSourceAssetInventory)
	}

	securityTable, ok := registry.Get("gcp_artifact_registry_images")
	if !ok {
		t.Fatal("expected gcp_artifact_registry_images to be registered")
	}
	if !containsTableSource(securityTable.Sources, TableSourceSecurity) {
		t.Fatalf("expected gcp_artifact_registry_images to include %q source", TableSourceSecurity)
	}
}

func TestSupportedTableNames_UsesRegistry(t *testing.T) {
	RegisterAllTables()
	registryNames := GlobalTableRegistry().Names()
	supported := SupportedTableNames()

	if !reflect.DeepEqual(supported, registryNames) {
		t.Fatalf("supported table names diverged from registry\nregistry=%v\nsupported=%v", registryNames, supported)
	}
}

func TestTableRegistry_RejectsInvalidRegistration(t *testing.T) {
	registry := NewTableRegistry()

	err := registry.Register(TableRegistration{
		Name:     "Invalid Table Name",
		Provider: TableProviderAWS,
		Columns:  []string{"id"},
	})
	if err == nil {
		t.Fatal("expected invalid table name registration to fail")
	}

	err = registry.Register(TableRegistration{
		Name:    "valid_table",
		Columns: []string{"id"},
	})
	if err == nil {
		t.Fatal("expected missing provider registration to fail")
	}
}

func TestExpectedTables_IncludeKubernetesInventoryAndRBACBaseline(t *testing.T) {
	required := []string{
		"k8s_cluster_inventory",
		"k8s_core_pods",
		"k8s_core_namespaces",
		"k8s_core_configmaps",
		"k8s_core_nodes",
		"k8s_core_persistent_volumes",
		"k8s_core_services",
		"k8s_core_service_accounts",
		"k8s_apps_deployments",
		"k8s_networking_ingresses",
		"k8s_rbac_cluster_roles",
		"k8s_rbac_roles",
		"k8s_rbac_cluster_role_bindings",
		"k8s_rbac_role_bindings",
		"k8s_rbac_service_account_bindings",
		"k8s_rbac_risky_bindings",
		"k8s_audit_events",
	}

	for _, table := range required {
		if !slices.Contains(ExpectedTables, table) {
			t.Fatalf("expected %q in ExpectedTables baseline", table)
		}
	}
}

func containsTableSource(sources []TableSource, target TableSource) bool {
	for _, source := range sources {
		if source == target {
			return true
		}
	}
	return false
}
