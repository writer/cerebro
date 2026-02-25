package sync

import "testing"

func TestSerializeAKSAgentPools(t *testing.T) {
	count := int32(3)
	pools := []azureManagedClusterAgentPool{
		{
			Name:                strPtr("nodepool1"),
			Count:               &count,
			VMSize:              strPtr("Standard_D4s_v5"),
			Mode:                strPtr("System"),
			OSType:              strPtr("Linux"),
			OrchestratorVersion: strPtr("1.30.1"),
		},
	}

	serialized := serializeAKSAgentPools(pools)
	if len(serialized) != 1 {
		t.Fatalf("expected 1 serialized pool, got %d", len(serialized))
	}

	pool := serialized[0]
	if pool["name"] != "nodepool1" {
		t.Fatalf("unexpected pool name: %#v", pool["name"])
	}
	if pool["count"] != int32(3) {
		t.Fatalf("unexpected pool count: %#v", pool["count"])
	}
	if pool["vm_size"] != "Standard_D4s_v5" {
		t.Fatalf("unexpected VM size: %#v", pool["vm_size"])
	}
}

func TestSerializeAKSAgentPoolsEmpty(t *testing.T) {
	if got := serializeAKSAgentPools(nil); got != nil {
		t.Fatalf("expected nil for empty pools, got %#v", got)
	}
}

func TestAzureTablesIncludeAKSAndRBACPolicyGraphAndDefender(t *testing.T) {
	tables := (&AzureSyncEngine{}).getAzureTables()
	lookup := make(map[string]struct{}, len(tables))
	for _, table := range tables {
		lookup[table.Name] = struct{}{}
	}

	if _, ok := lookup["azure_aks_clusters"]; !ok {
		t.Fatal("expected azure_aks_clusters in Azure table set")
	}
	if _, ok := lookup["azure_rbac_role_assignments"]; !ok {
		t.Fatal("expected azure_rbac_role_assignments in Azure table set")
	}
	if _, ok := lookup["azure_policy_assignments"]; !ok {
		t.Fatal("expected azure_policy_assignments in Azure table set")
	}
	if _, ok := lookup["azure_graph_service_principals"]; !ok {
		t.Fatal("expected azure_graph_service_principals in Azure table set")
	}
	if _, ok := lookup["azure_defender_assessments"]; !ok {
		t.Fatal("expected azure_defender_assessments in Azure table set")
	}
}

func TestMapStringAnyFold(t *testing.T) {
	values := map[string]interface{}{
		"Source":     "Azure",
		"resourceID": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Compute/virtualMachines/vm-a",
	}

	if got := mapStringAnyFold(values, "source"); got != "Azure" {
		t.Fatalf("unexpected source value: %q", got)
	}

	if got := mapStringAnyFold(values, "resourceId"); got != "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Compute/virtualMachines/vm-a" {
		t.Fatalf("unexpected resource id: %q", got)
	}

	if got := mapStringAnyFold(values, "missing"); got != "" {
		t.Fatalf("expected empty value for missing key, got %q", got)
	}
}

func TestIsAzureGraphPermissionError(t *testing.T) {
	if !isAzureGraphPermissionError(assertError("status 403: Authorization_RequestDenied")) {
		t.Fatal("expected authorization denied error to be treated as permission error")
	}
	if !isAzureGraphPermissionError(assertError("Insufficient privileges to complete the operation")) {
		t.Fatal("expected insufficient privileges error to be treated as permission error")
	}
	if isAzureGraphPermissionError(assertError("timeout while listing resources")) {
		t.Fatal("did not expect timeout to be treated as permission error")
	}
}

func TestAzureScopedResourceID(t *testing.T) {
	if got := azureScopedResourceID("sub-a", "sp-1"); got != "sub-a:sp-1" {
		t.Fatalf("unexpected scoped id: %q", got)
	}
	if got := azureScopedResourceID("", "sp-1"); got != "sp-1" {
		t.Fatalf("unexpected unscoped id: %q", got)
	}
	if got := azureScopedResourceID("sub-a", ""); got != "" {
		t.Fatalf("expected empty id for empty resource id, got %q", got)
	}
}

func assertError(message string) error {
	return errString(message)
}

type errString string

func (e errString) Error() string {
	return string(e)
}

func strPtr(value string) *string {
	return &value
}
