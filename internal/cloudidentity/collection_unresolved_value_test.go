package cloudidentity

import (
	"context"
	"testing"
	"time"
)

// collectionUnresolvedValueTestPorts builds a single-target AWS plan whose
// resolved cohort (IRSA-annotated, never a bare KSA placeholder) starts
// ConsumerInventoryComplete=true, so a demotion can only come from the
// renderer gap under test. objectGaps are the renderer's own
// cloud_identity.manifest.unresolved_value_in_object gaps to inject.
func collectionUnresolvedValueTestPlanAndPorts(objectGaps []Gap) (ScanPlan, CollectionPorts) {
	dep := deploymentManifest("api", "payments", "api-sa",
		[]map[string]any{{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/api:v1"}}, nil)
	sa := serviceAccountManifest("api-sa", "payments", map[string]string{
		manifestInventoryAnnotationIRSARole: "arn:aws:iam::123456789012:role/api-role",
	})
	target := ScanTarget{
		Name: "payments", Environment: "prod", Cluster: "cluster-a", Provider: AWS, Account: "123456789012", Region: "us-east-1",
		Manifests: []ManifestInput{{
			Source:           SourcePin{Repository: "github.com/example/gitops", Revision: "abc123"},
			Release:          "payments",
			UnresolvedValues: []string{"vpcId"},
		}},
	}
	plan := ScanPlan{
		Scope:    "test",
		Targets:  []ScanTarget{target},
		Services: []ServiceMapping{{Service: "api", Repository: "example-org/api", ImagePrefixes: []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/api"}}},
	}
	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"payments": {dep, sa}}, gaps: map[string][]Gap{"payments": objectGaps}},
		Declarations: fakeDeclarationReader{},
		Clouds:       map[Provider]CloudReader{AWS: fakeCloudReader{}},
		Investigator: fakeInvestigator{},
	}
	return plan, ports
}

// TestCollectUnresolvedValueInObjectOnNonIdentityObjectNeverDemotesCompleteness
// reproduces review finding #4: an unresolved Terraform-contract value
// marker reaching a non-identity-bearing object (here, a ConfigMap) must
// never demote collection or cohort completeness -- it stays a visible,
// but merely workload/object-scoped, gap.
func TestCollectUnresolvedValueInObjectOnNonIdentityObjectNeverDemotesCompleteness(t *testing.T) {
	objectGap := Gap{Code: "cloud_identity.manifest.unresolved_value_in_object", Scope: "v1|ConfigMap|payments|cfg", Message: "rendered object carries the unresolved marker"}
	plan, ports := collectionUnresolvedValueTestPlanAndPorts([]Gap{objectGap})

	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !hasGapCode(result.Gaps, "cloud_identity.manifest.unresolved_value_in_object") {
		t.Fatalf("expected the renderer's own object-scoped gap to remain visible, got %+v", result.Gaps)
	}
	if hasGapCode(result.Gaps, "cloud_identity.manifest.unresolved_contract_value") {
		t.Fatalf("the removed blanket per-key gap must never be emitted, got %+v", result.Gaps)
	}
	if !result.InventoryComplete {
		t.Fatalf("expected InventoryComplete=true: the marker never reached an identity-bearing object")
	}
	evidence := collectionFindEvidence(t, result, "api")
	if !evidence.ConsumerInventoryComplete {
		t.Fatalf("expected ConsumerInventoryComplete=true, got false; gaps=%+v", evidence.Gaps)
	}
}

// TestCollectUnresolvedValueInObjectOnServiceAccountDemotesAffectedCohort
// reproduces the other half of review finding #4: an unresolved
// Terraform-contract value marker reaching an identity-bearing object (a
// ServiceAccount) DOES demote the affected cohort/collection completeness,
// the same as any other target-scoped inventory gap.
func TestCollectUnresolvedValueInObjectOnServiceAccountDemotesAffectedCohort(t *testing.T) {
	objectGap := Gap{Code: "cloud_identity.manifest.unresolved_value_in_object", Scope: "v1|ServiceAccount|payments|api-sa", Message: "rendered object carries the unresolved marker"}
	plan, ports := collectionUnresolvedValueTestPlanAndPorts([]Gap{objectGap})

	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.InventoryComplete {
		t.Fatalf("expected InventoryComplete=false: the marker reached an identity-bearing ServiceAccount")
	}
	evidence := collectionFindEvidence(t, result, "api")
	if evidence.ConsumerInventoryComplete {
		t.Fatalf("expected the affected cohort's ConsumerInventoryComplete=false, got true")
	}
	if !hasGapCode(evidence.Gaps, "target_inventory_incomplete") {
		t.Fatalf("expected a target_inventory_incomplete gap on the affected cohort, got %+v", evidence.Gaps)
	}
}

// TestCollectionGapIsIdentityBearingObjectClassification pins the object
// classification itself across representative kinds.
func TestCollectionGapIsIdentityBearingObjectClassification(t *testing.T) {
	cases := []struct {
		scope string
		want  bool
	}{
		{"v1|ServiceAccount|payments|api-sa", true},
		{"apps/v1|Deployment|payments|api", true},
		{"argoproj.io/v1alpha1|Rollout|payments|api", true},
		{"iam.services.k8s.aws/v1alpha1|Role|payments|api-role", true},
		{"eks.services.k8s.aws/v1alpha1|PodIdentityAssociation|payments|api", true},
		{"iam.aws.upbound.io/v1beta1|Role|payments|api-role", true},
		{"v1|ConfigMap|payments|cfg", false},
		{"karpenter.k8s.aws/v1|EC2NodeClass|karpenter-system|default", false},
		{"not-a-well-formed-scope", true}, // unrecognized shape: conservative.
	}
	for _, c := range cases {
		if got := collectionGapIsIdentityBearingObject(c.scope); got != c.want {
			t.Errorf("collectionGapIsIdentityBearingObject(%q) = %v, want %v", c.scope, got, c.want)
		}
	}
}
