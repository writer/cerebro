package sync

import (
	"reflect"
	"testing"
)

func TestBuildAWSCoverageMatrix(t *testing.T) {
	entries := BuildAWSCoverageMatrix([]string{"us-west-2", "us-east-1", "us-east-1"})
	if len(entries) == 0 {
		t.Fatal("expected non-empty coverage matrix")
	}

	lookup := make(map[string]AWSCoverageEntry, len(entries))
	for _, entry := range entries {
		lookup[entry.Table] = entry
	}

	iam, ok := lookup["aws_iam_roles"]
	if !ok {
		t.Fatal("expected aws_iam_roles entry")
	}
	if iam.Service != "iam" {
		t.Fatalf("expected iam service, got %q", iam.Service)
	}
	if iam.Scope != "global" {
		t.Fatalf("expected global scope for IAM roles, got %q", iam.Scope)
	}
	if !reflect.DeepEqual(iam.Regions, []string{"us-east-1"}) {
		t.Fatalf("unexpected IAM regions: %#v", iam.Regions)
	}

	ec2, ok := lookup["aws_ec2_instances"]
	if !ok {
		t.Fatal("expected aws_ec2_instances entry")
	}
	if ec2.Service != "ec2" {
		t.Fatalf("expected ec2 service, got %q", ec2.Service)
	}
	if ec2.Scope != "regional" {
		t.Fatalf("expected regional scope for EC2 instances, got %q", ec2.Scope)
	}
	if !reflect.DeepEqual(ec2.Regions, []string{"us-east-1", "us-west-2"}) {
		t.Fatalf("unexpected EC2 regions: %#v", ec2.Regions)
	}
	if !reflect.DeepEqual(ec2.PrimaryKeys, []string{"arn"}) {
		t.Fatalf("unexpected EC2 primary keys: %#v", ec2.PrimaryKeys)
	}

	route53, ok := lookup["aws_route53_record_sets"]
	if !ok {
		t.Fatal("expected aws_route53_record_sets entry")
	}
	wantComposite := []string{"hosted_zone_id", "name", "type", "set_identifier", "region"}
	if !reflect.DeepEqual(route53.PrimaryKeys, wantComposite) {
		t.Fatalf("unexpected route53 primary keys: %#v", route53.PrimaryKeys)
	}
}

func TestBuildAWSCoverageMatrixUsesDefaultRegions(t *testing.T) {
	entries := BuildAWSCoverageMatrix(nil)
	lookup := make(map[string]AWSCoverageEntry, len(entries))
	for _, entry := range entries {
		lookup[entry.Table] = entry
	}

	ec2, ok := lookup["aws_ec2_instances"]
	if !ok {
		t.Fatal("expected aws_ec2_instances entry")
	}
	if len(ec2.Regions) != len(DefaultAWSRegions) {
		t.Fatalf("expected %d default regions, got %d", len(DefaultAWSRegions), len(ec2.Regions))
	}
}

func TestAWSCoverageGaps(t *testing.T) {
	t.Run("detects missing required tables", func(t *testing.T) {
		gaps := AWSCoverageGaps([]AWSCoverageEntry{{Table: "aws_iam_roles"}, {Table: "aws_ec2_instances"}})
		if len(gaps) == 0 {
			t.Fatal("expected missing-table gaps")
		}

		foundIAM := false
		for _, gap := range gaps {
			if gap.Service != "iam" {
				continue
			}
			foundIAM = true
			if !reflect.DeepEqual(gap.MissingTables, []string{"aws_iam_users", "aws_iam_policies"}) {
				t.Fatalf("unexpected IAM gaps: %#v", gap.MissingTables)
			}
		}
		if !foundIAM {
			t.Fatal("expected IAM gap to be reported")
		}
	})

	t.Run("full AWS matrix has no core-service gaps", func(t *testing.T) {
		gaps := AWSCoverageGaps(BuildAWSCoverageMatrix(nil))
		if len(gaps) != 0 {
			t.Fatalf("expected no gaps, got %#v", gaps)
		}
	})
}

func TestBuildGCPCoverageMatrix(t *testing.T) {
	entries := BuildGCPCoverageMatrix()
	if len(entries) == 0 {
		t.Fatal("expected non-empty GCP coverage matrix")
	}

	lookup := make(map[string]GCPCoverageEntry, len(entries))
	for _, entry := range entries {
		lookup[entry.Table] = entry
	}

	instances, ok := lookup["gcp_compute_instances"]
	if !ok {
		t.Fatal("expected gcp_compute_instances entry")
	}
	if instances.Service != "compute" {
		t.Fatalf("expected compute service, got %q", instances.Service)
	}
	if !instances.NativeAPI || !instances.AssetInventory {
		t.Fatalf("expected gcp_compute_instances to be present in both sources: %#v", instances)
	}

	secretManager, ok := lookup["gcp_secretmanager_secrets"]
	if !ok {
		t.Fatal("expected gcp_secretmanager_secrets entry")
	}
	if secretManager.NativeAPI {
		t.Fatalf("expected gcp_secretmanager_secrets to be asset-only: %#v", secretManager)
	}
	if !secretManager.AssetInventory {
		t.Fatalf("expected gcp_secretmanager_secrets to include asset inventory source: %#v", secretManager)
	}
}

func TestSummarizeGCPCoverageSources(t *testing.T) {
	summary := SummarizeGCPCoverageSources([]GCPCoverageEntry{
		{Table: "gcp_a", NativeAPI: true, AssetInventory: true},
		{Table: "gcp_b", NativeAPI: true},
		{Table: "gcp_c", AssetInventory: true},
	})

	if !reflect.DeepEqual(summary.BothSources, []string{"gcp_a"}) {
		t.Fatalf("unexpected both-sources tables: %#v", summary.BothSources)
	}
	if !reflect.DeepEqual(summary.NativeOnly, []string{"gcp_b"}) {
		t.Fatalf("unexpected native-only tables: %#v", summary.NativeOnly)
	}
	if !reflect.DeepEqual(summary.AssetInventoryOnly, []string{"gcp_c"}) {
		t.Fatalf("unexpected asset-only tables: %#v", summary.AssetInventoryOnly)
	}
}

func TestBuildAzureCoverageMatrix(t *testing.T) {
	entries := BuildAzureCoverageMatrix()
	if len(entries) == 0 {
		t.Fatal("expected non-empty Azure coverage matrix")
	}

	lookup := make(map[string]AzureCoverageEntry, len(entries))
	for _, entry := range entries {
		lookup[entry.Table] = entry
	}

	vm, ok := lookup["azure_compute_virtual_machines"]
	if !ok {
		t.Fatal("expected azure_compute_virtual_machines entry")
	}
	if vm.Service != "compute" {
		t.Fatalf("expected compute service, got %q", vm.Service)
	}
	if vm.Source != "arm" {
		t.Fatalf("expected ARM source, got %q", vm.Source)
	}
	if !reflect.DeepEqual(vm.PrimaryKeys, []string{"id"}) {
		t.Fatalf("unexpected VM primary keys: %#v", vm.PrimaryKeys)
	}

	if _, ok := lookup["azure_keyvault_keys"]; !ok {
		t.Fatal("expected azure_keyvault_keys entry")
	}
	if _, ok := lookup["azure_functions_apps"]; !ok {
		t.Fatal("expected azure_functions_apps entry")
	}

	aks, ok := lookup["azure_aks_clusters"]
	if !ok {
		t.Fatal("expected azure_aks_clusters entry")
	}
	if aks.Service != "aks" {
		t.Fatalf("expected aks service, got %q", aks.Service)
	}
	if !reflect.DeepEqual(aks.PrimaryKeys, []string{"id"}) {
		t.Fatalf("unexpected AKS primary keys: %#v", aks.PrimaryKeys)
	}

	aksNodePools, ok := lookup["azure_aks_node_pools"]
	if !ok {
		t.Fatal("expected azure_aks_node_pools entry")
	}
	if aksNodePools.Service != "aks" {
		t.Fatalf("expected aks service for node pools, got %q", aksNodePools.Service)
	}
	if !reflect.DeepEqual(aksNodePools.PrimaryKeys, []string{"id"}) {
		t.Fatalf("unexpected AKS node pool primary keys: %#v", aksNodePools.PrimaryKeys)
	}

	rbac, ok := lookup["azure_rbac_role_assignments"]
	if !ok {
		t.Fatal("expected azure_rbac_role_assignments entry")
	}
	if rbac.Service != "rbac" {
		t.Fatalf("expected rbac service, got %q", rbac.Service)
	}
	if !reflect.DeepEqual(rbac.PrimaryKeys, []string{"id"}) {
		t.Fatalf("unexpected RBAC primary keys: %#v", rbac.PrimaryKeys)
	}

	policy, ok := lookup["azure_policy_assignments"]
	if !ok {
		t.Fatal("expected azure_policy_assignments entry")
	}
	if policy.Service != "policy" {
		t.Fatalf("expected policy service, got %q", policy.Service)
	}
	if !reflect.DeepEqual(policy.PrimaryKeys, []string{"id"}) {
		t.Fatalf("unexpected policy assignment primary keys: %#v", policy.PrimaryKeys)
	}

	graphPrincipals, ok := lookup["azure_graph_service_principals"]
	if !ok {
		t.Fatal("expected azure_graph_service_principals entry")
	}
	if graphPrincipals.Service != "graph" {
		t.Fatalf("expected graph service, got %q", graphPrincipals.Service)
	}
	if graphPrincipals.Source != "graph" {
		t.Fatalf("expected graph source, got %q", graphPrincipals.Source)
	}
	if !reflect.DeepEqual(graphPrincipals.PrimaryKeys, []string{"id"}) {
		t.Fatalf("unexpected graph principal primary keys: %#v", graphPrincipals.PrimaryKeys)
	}

	defender, ok := lookup["azure_defender_assessments"]
	if !ok {
		t.Fatal("expected azure_defender_assessments entry")
	}
	if defender.Service != "defender" {
		t.Fatalf("expected defender service, got %q", defender.Service)
	}
	if !reflect.DeepEqual(defender.PrimaryKeys, []string{"id"}) {
		t.Fatalf("unexpected Defender primary keys: %#v", defender.PrimaryKeys)
	}
}
