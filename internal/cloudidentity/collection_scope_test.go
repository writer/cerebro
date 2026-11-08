package cloudidentity

import (
	"context"
	"testing"
	"time"
)

// fakeRepositoryReader hands back a trivial repository for any pin;
// collectTarget/collectTerraform only use it to gate Render/Compose/
// Declarations calls, never to assert on repository content in these tests.
type fakeRepositoryReader struct{}

func (fakeRepositoryReader) ReadRepository(_ context.Context, pin SourcePin) (Repository, error) {
	return Repository{Pin: pin}, nil
}

// fakeRegistryReader always resolves a fully pinned, deployment-exact image
// so Investigate always runs on a complete source without further gaps.
type fakeRegistryReader struct{}

func (fakeRegistryReader) ReadImage(_ context.Context, image string) (ImageProvenance, error) {
	return ImageProvenance{
		Image:            image,
		Digest:           "sha256:" + image,
		DeploymentPinned: true,
		Source:           SourcePin{Repository: "github.com/example/app", Revision: "abc123", Exact: true},
	}, nil
}

// fakeManifestRenderer returns pre-registered manifests/gaps keyed by the
// ManifestInput.Release field, so each test target controls its own render
// output without any real chart/Argo rendering.
type fakeManifestRenderer struct {
	render map[string][]Manifest
	gaps   map[string][]Gap
}

func (f fakeManifestRenderer) Render(_ context.Context, req ManifestRequest) ([]Manifest, []Gap, error) {
	return f.render[req.Release], f.gaps[req.Release], nil
}

func (f fakeManifestRenderer) Compose(_ context.Context, _ ComposeRequest) ([]Manifest, []Gap, error) {
	return nil, nil, nil
}

type fakeDeclarationReader struct{}

func (fakeDeclarationReader) ReadDeclarations(_ context.Context, _ TerraformInput) ([]Declaration, []Gap, error) {
	return nil, nil, nil
}

// fakeCloudReader reports every principal as fully observed and defined so
// only inventory-stage gaps drive ConsumerInventoryComplete in these tests.
type fakeCloudReader struct{}

func (fakeCloudReader) Observe(_ context.Context, _ CloudRequest) (Observation, error) {
	return Observation{Policy: PolicyState{Complete: true, Grants: []Grant{}}}, nil
}

func (fakeCloudReader) Define(_ context.Context, _ DefinitionRequest) (Definitions, error) {
	return Definitions{Complete: true}, nil
}

type fakeInvestigator struct{}

func (fakeInvestigator) Investigate(_ context.Context, req InvestigationRequest) (Investigation, error) {
	return Investigation{ConsumerID: req.Workload.ID, Source: req.Workload.Source, Validation: Validation{ScopeComplete: true}}, nil
}

func collectionTestPorts(render map[string][]Manifest) CollectionPorts {
	return CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: render},
		Declarations: fakeDeclarationReader{},
		Clouds:       map[Provider]CloudReader{AWS: fakeCloudReader{}, GCP: fakeCloudReader{}},
		Investigator: fakeInvestigator{},
	}
}

func collectionTestManifestInput(release string) ManifestInput {
	return ManifestInput{Source: SourcePin{Repository: "github.com/example/gitops", Revision: "abc123"}, Release: release}
}

func collectionFindEvidence(t *testing.T, result Collection, idSubstring string) Evidence {
	t.Helper()
	for _, e := range result.Evidence {
		for _, c := range e.Consumers {
			if c.ID == idSubstring || c.Name == idSubstring {
				return e
			}
		}
	}
	t.Fatalf("no evidence cohort found for consumer %q among %d cohorts", idSubstring, len(result.Evidence))
	return Evidence{}
}

// TestCollectUnmappedWorkloadGapIsWorkloadScopedAndNeverCrossesTargets
// reproduces the reviewed defect: one unmapped-service workload in an
// unrelated account must never demote an unrelated, fully resolved
// principal's ConsumerInventoryComplete. unmapped_service only narrows the
// uncertainty of the one workload it describes.
func TestCollectUnmappedWorkloadGapIsWorkloadScopedAndNeverCrossesTargets(t *testing.T) {
	supportedDep := deploymentManifest("checkout-api", "shop", "checkout-sa",
		[]map[string]any{{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/checkout:v1"}}, nil)
	supportedSA := serviceAccountManifest("checkout-sa", "shop", map[string]string{
		manifestInventoryAnnotationIRSARole: "arn:aws:iam::111111111111:role/checkout-role",
	})
	unmappedDep := deploymentManifest("random-job", "ops", "default",
		[]map[string]any{{"name": "app", "image": "unmapped-registry.example.com/mystery:v1"}}, nil)

	plan := ScanPlan{
		Scope: "org:writer",
		Targets: []ScanTarget{
			{Name: "a", Cluster: "eks-a", Provider: AWS, Account: "111111111111", Region: "us-east-1",
				Manifests: []ManifestInput{collectionTestManifestInput("a")}},
			{Name: "b", Cluster: "eks-b", Provider: AWS, Account: "222222222222", Region: "us-east-1",
				Manifests: []ManifestInput{collectionTestManifestInput("b")}},
		},
		Services: []ServiceMapping{
			{Service: "checkout", ImagePrefixes: []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/checkout"}, Repository: "github.com/example/checkout"},
		},
	}
	ports := collectionTestPorts(
		map[string][]Manifest{"a": {supportedSA, supportedDep}, "b": {unmappedDep}},
	)

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !hasGapCode(result.Gaps, "cloud_identity.inventory.unmapped_service") {
		t.Fatalf("expected unmapped_service gap in result, got %+v", result.Gaps)
	}
	supported := collectionFindEvidence(t, result, "checkout-api")
	if !supported.ConsumerInventoryComplete {
		t.Fatalf("workload-scoped gap in an unrelated account demoted an unrelated supported principal: %+v", supported)
	}
}

// TestCollectTargetScopedGapInGCPProjectMarksSameProjectCohortsIncomplete
// reproduces the required positive case: a target-scoped gap (unresolved
// namespace -- a manifest that can hide which workload/identity it belongs
// to) in one GCP project must mark ConsumerInventoryComplete=false only for
// cohorts whose principal/consumer shares that project; a different
// project's cohort stays complete.
func TestCollectTargetScopedGapInGCPProjectMarksSameProjectCohortsIncomplete(t *testing.T) {
	gappedDep := Manifest{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]any{"name": "billing-api"},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
				"serviceAccountName": "default",
				"containers":         []any{map[string]any{"name": "app", "image": "gcr.io/proj-a/billing:v1"}},
			}}},
		},
		Reference: Reference{Repository: "github.com/example/gitops", Revision: "abc123", Path: "deploy/billing.yaml"},
	}
	cleanDep := deploymentManifest("reporting-api", "reporting", "default",
		[]map[string]any{{"name": "app", "image": "gcr.io/proj-b/reporting:v1"}}, nil)

	plan := ScanPlan{
		Scope: "org:writer",
		Targets: []ScanTarget{
			{Name: "proj-a", Cluster: "gke-a", Provider: GCP, Project: "proj-a",
				Manifests: []ManifestInput{collectionTestManifestInput("proj-a")}},
			{Name: "proj-b", Cluster: "gke-b", Provider: GCP, Project: "proj-b",
				Manifests: []ManifestInput{collectionTestManifestInput("proj-b")}},
		},
		Services: []ServiceMapping{
			{Service: "billing", ImagePrefixes: []string{"gcr.io/proj-a/billing"}, Repository: "github.com/example/billing"},
			{Service: "reporting", ImagePrefixes: []string{"gcr.io/proj-b/reporting"}, Repository: "github.com/example/reporting"},
		},
	}
	ports := collectionTestPorts(
		map[string][]Manifest{"proj-a": {gappedDep}, "proj-b": {cleanDep}},
	)

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !hasGapCode(result.Gaps, "cloud_identity.inventory.unresolved_namespace") {
		t.Fatalf("expected unresolved_namespace gap, got %+v", result.Gaps)
	}
	if result.InventoryComplete {
		t.Fatalf("Collection.InventoryComplete must be false: a target-scoped gap was produced")
	}
	gapped := collectionFindEvidence(t, result, "billing-api")
	if gapped.ConsumerInventoryComplete {
		t.Fatalf("principal in the gapped project must be marked incomplete: %+v", gapped)
	}
	clean := collectionFindEvidence(t, result, "reporting-api")
	if !clean.ConsumerInventoryComplete {
		t.Fatalf("an unrelated project's cohort must stay complete: %+v", clean)
	}
}

const (
	collectionScopePaymentsRoleID      = "arn:aws:iam::111111111111:role/payments-role"
	collectionScopeClusterAProviderARN = "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/CLUSTERA"
	collectionScopeClusterBProviderARN = "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/CLUSTERB"
)

// collectionTargetScopeAWSPorts builds a two-AWS-target, same-account plan:
// target "cluster-a" has a target-scoped render gap and no identity-bearing
// workloads of its own; target "cluster-b" hosts a payments-api workload
// whose IRSA role's observed trust (keyed by the role ARN) is supplied by
// trust.
func collectionTargetScopeAWSPorts(trust map[string]Observation) (ScanPlan, CollectionPorts) {
	paymentsSA := serviceAccountManifest("payments-sa", "payments", map[string]string{
		manifestInventoryAnnotationIRSARole: collectionScopePaymentsRoleID,
	})
	paymentsDep := deploymentManifest("payments-api", "payments", "payments-sa",
		[]map[string]any{{"name": "app", "image": "111111111111.dkr.ecr.us-east-1.amazonaws.com/payments:v1"}}, nil)

	plan := ScanPlan{
		Scope: "org:example-org",
		Targets: []ScanTarget{
			{Name: "cluster-a", Cluster: "cluster-a", Provider: AWS, Account: "111111111111", Region: "us-east-1",
				Manifests: []ManifestInput{collectionTestManifestInput("a")}},
			{Name: "cluster-b", Cluster: "cluster-b", Provider: AWS, Account: "111111111111", Region: "us-east-1",
				Manifests: []ManifestInput{collectionTestManifestInput("b")}},
		},
		Services: []ServiceMapping{
			{Service: "payments", ImagePrefixes: []string{"111111111111.dkr.ecr.us-east-1.amazonaws.com/payments"}, Repository: "github.com/example/payments"},
		},
	}
	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests: fakeManifestRenderer{
			render: map[string][]Manifest{"b": {paymentsSA, paymentsDep}},
			gaps:   map[string][]Gap{"a": {{Code: "cloud_identity.manifest.render_incomplete", Scope: "a", Message: "manifest render did not complete for target cluster-a"}}},
		},
		Declarations: fakeDeclarationReader{},
		Clouds:       map[Provider]CloudReader{AWS: fakeTrustCloudReader{byPrincipal: trust}},
		Investigator: fakeInvestigator{},
	}
	return plan, ports
}

// TestCollectTargetScopedGapNeverDemotesClosedCohortConfinedToAnotherCluster
// reproduces the reviewed static defect: a target-scoped render gap in
// cluster A's target must never demote a role whose consumers and exact
// observed trust are confined to cluster B in the SAME AWS account --
// bare account equality is no longer sufficient to scope the gap.
func TestCollectTargetScopedGapNeverDemotesClosedCohortConfinedToAnotherCluster(t *testing.T) {
	plan, ports := collectionTargetScopeAWSPorts(map[string]Observation{
		collectionScopePaymentsRoleID: {
			Policy: PolicyState{Complete: true, Trust: []Grant{{
				Effect:  "Allow",
				Actions: []string{"sts:AssumeRoleWithWebIdentity"},
				Members: []string{"Federated:" + collectionScopeClusterBProviderARN},
				Conditions: []Condition{{
					Operator: "StringEquals",
					Key:      "oidc.eks.us-east-1.amazonaws.com/id/CLUSTERB:sub",
					Values:   []string{"system:serviceaccount:payments:payments-sa"},
				}},
			}}},
			ResolvedIdentifiers: map[string]string{
				"aws_eks_oidc_provider_arn:cluster-a": collectionScopeClusterAProviderARN,
				"aws_eks_oidc_provider_arn:cluster-b": collectionScopeClusterBProviderARN,
			},
		},
	})

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !hasGapCode(result.Gaps, "cloud_identity.manifest.render_incomplete") {
		t.Fatalf("expected target-scoped render gap in result, got %+v", result.Gaps)
	}
	payments := collectionFindEvidence(t, result, "payments-api")
	if !payments.ConsumerInventoryComplete {
		t.Fatalf("a role whose consumers and exact observed trust are confined to cluster B must never be demoted by cluster A's gap: %+v", payments)
	}
}

// TestCollectTargetScopedGapDemotesUnknownTrustInSameAccount is the
// conservative control: a principal with unknown/empty observed trust must
// still be demoted by a target-scoped gap in the same account, since
// unresolved trust can never positively rule out admitting cluster A.
func TestCollectTargetScopedGapDemotesUnknownTrustInSameAccount(t *testing.T) {
	plan, ports := collectionTargetScopeAWSPorts(nil)

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	payments := collectionFindEvidence(t, result, "payments-api")
	if payments.ConsumerInventoryComplete {
		t.Fatalf("unknown/empty observed trust must conservatively be demoted by a target-scoped gap in the same account: %+v", payments)
	}
	if !hasGapCode(payments.Gaps, "target_inventory_incomplete") {
		t.Fatalf("expected target_inventory_incomplete gap, got %+v", payments.Gaps)
	}
}

// TestCollectTargetScopedGapDemotesTrustAdmittingClusterA is the positive
// control: a role whose observed Federated trust names cluster A's own
// resolved OIDC provider could admit cluster A's hidden workloads, so it
// must be demoted by cluster A's gap even though its only KNOWN consumer
// is in cluster B.
func TestCollectTargetScopedGapDemotesTrustAdmittingClusterA(t *testing.T) {
	plan, ports := collectionTargetScopeAWSPorts(map[string]Observation{
		collectionScopePaymentsRoleID: {
			Policy: PolicyState{Complete: true, Trust: []Grant{{
				Effect:  "Allow",
				Actions: []string{"sts:AssumeRoleWithWebIdentity"},
				Members: []string{"Federated:" + collectionScopeClusterAProviderARN},
				Conditions: []Condition{{
					Operator: "StringEquals",
					Key:      "oidc.eks.us-east-1.amazonaws.com/id/CLUSTERA:sub",
					Values:   []string{"system:serviceaccount:payments:payments-sa"},
				}},
			}}},
			ResolvedIdentifiers: map[string]string{
				"aws_eks_oidc_provider_arn:cluster-a": collectionScopeClusterAProviderARN,
				"aws_eks_oidc_provider_arn:cluster-b": collectionScopeClusterBProviderARN,
			},
		},
	})

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	payments := collectionFindEvidence(t, result, "payments-api")
	if payments.ConsumerInventoryComplete {
		t.Fatalf("trust naming cluster A's own resolved OIDC provider could admit cluster A's hidden workloads and must be demoted: %+v", payments)
	}
}
