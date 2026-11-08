package cloudidentity

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// federatedGCPTestDeclarationReader returns a fixed, pre-built declaration set
// regardless of which Terraform root triggered the read: exactly what
// internal/cloudidentity/iac/gcp.go's gcpServiceAccountIAM/gcpResourceIAM
// produce for a federated target's own paired GCP identity Terraform root
// (synthetic fixture; the iac package's own tests cover HCL evaluation
// itself).
type federatedGCPTestDeclarationReader struct {
	declarations []Declaration
}

func (r federatedGCPTestDeclarationReader) ReadDeclarations(_ context.Context, _ TerraformInput) ([]Declaration, []Gap, error) {
	return r.declarations, nil, nil
}

// federatedGCPTestCloudReader simulates the live GCP reader's relevant code
// paths: a bare-KSA probe (any other Kind) observes empty/complete
// Observed but may still resolve a GKE default-pool alias identifier the
// way a real reader's own generic probe does (ksaResolvedIdentifiers),
// proving ordering -- not member content -- is what stops a federated GCP
// target's custom-pool identity from being pre-empted by the generic
// alias (review finding #2a). A direct Google service account read (Kind
// federatedGCPServiceAccountKind) returns this test's configured live
// grants/trust/provider facts for that
// exact principal; a direct custom-pool principal read (Kind
// federatedGCPDirectPrincipalKind) returns its own configured live grants.
type federatedGCPTestCloudReader struct {
	gsaGrants              map[string][]Grant
	gsaTrust               map[string][]Grant
	gsaProviders           map[string][]GCPWorkloadIdentityPoolProvider
	directGrants           map[string][]Grant
	ksaResolvedIdentifiers map[string]string
	// defs overrides the roles Define resolves; when unset, Define
	// resolves "roles/iam.workloadIdentityUser" as impersonation-capable,
	// the default binding role every fixture in this file declares.
	defs Definitions
}

func (r federatedGCPTestCloudReader) Observe(_ context.Context, req CloudRequest) (Observation, error) {
	switch req.Principal.Kind {
	case federatedGCPServiceAccountKind:
		return Observation{
			Policy:                       PolicyState{Complete: true, Grants: r.gsaGrants[req.Principal.ID], Trust: r.gsaTrust[req.Principal.ID]},
			GCPWorkloadIdentityProviders: r.gsaProviders[req.Principal.ID],
		}, nil
	case federatedGCPDirectPrincipalKind:
		return Observation{Policy: PolicyState{Complete: true, Grants: r.directGrants[req.Principal.ID]}}, nil
	default:
		return Observation{Policy: PolicyState{Complete: true, Grants: []Grant{}}, ResolvedIdentifiers: r.ksaResolvedIdentifiers}, nil
	}
}

func (r federatedGCPTestCloudReader) Define(_ context.Context, _ DefinitionRequest) (Definitions, error) {
	if len(r.defs.Roles) > 0 {
		return r.defs, nil
	}
	return Definitions{Complete: true, Roles: []RoleDefinition{
		{Name: "roles/iam.workloadIdentityUser", Permissions: []string{"iam.serviceAccounts.getAccessToken"}},
	}}, nil
}

// federatedGCPTestSubject, federatedGCPTestGSAID, federatedGCPTestCluster and
// federatedGCPTestProjectNumber/PoolID are shared across every test in this
// file so each case only varies the one fact it is testing.
const (
	federatedGCPTestCluster       = "example-federated-eks-00"
	federatedGCPTestProject       = "federated-project"
	federatedGCPTestProjectNumber = "999999999999"
	federatedGCPTestPoolID        = "example-federated-eks"
	federatedGCPTestGSAID         = "federated-worker@federated-project.iam.gserviceaccount.com"
)

var federatedGCPTestSubject = "principal://iam.googleapis.com/projects/" + federatedGCPTestProjectNumber + "/locations/global/workloadIdentityPools/" + federatedGCPTestPoolID + "/subject/system:serviceaccount:payments:payments-sa"

// federatedGCPTestPlan builds the standard AWS target with a paired GCP project
// plus its rendered EKS workload, shared across every test in this file.
func federatedGCPTestPlan() (ScanPlan, Manifest, Manifest) {
	dep := deploymentManifest("worker", "payments", "payments-sa",
		[]map[string]any{{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/worker:v1"}}, nil)
	sa := serviceAccountManifest("payments-sa", "payments", nil)
	plan := ScanPlan{
		Scope: "org:writer",
		Targets: []ScanTarget{
			{
				Name: "federated-a", Environment: "prod", Cluster: federatedGCPTestCluster, Provider: AWS,
				Account: "111111111111", Project: federatedGCPTestProject, Region: "us-east-1",
				Manifests: []ManifestInput{collectionTestManifestInput("federated")},
				Terraform: []TerraformRoot{{Source: SourcePin{Repository: "example-org/federated-infra", Revision: "abc123"}, Root: "modules/federated/example/gcp-identity", Region: "us-east4"}},
			},
		},
		Services: []ServiceMapping{{Service: "worker", Repository: "example-org/worker", ImagePrefixes: []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/worker"}}},
	}
	return plan, dep, sa
}

// federatedGCPTestGSADeclaration is the GSA impersonation declaration
// gpcServiceAccountIAM produces: a declared trust grant naming
// federatedGCPTestSubject, plus the target's own declared custom-pool
// provider identity (Contract A.6: project number + pool id).
func federatedGCPTestGSADeclaration() Declaration {
	return Declaration{
		Principal: Principal{ID: federatedGCPTestGSAID, Provider: GCP, Kind: "service_account", Project: federatedGCPTestProject},
		Policy:    PolicyState{Complete: true, Trust: []Grant{{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{federatedGCPTestSubject}, References: []Reference{{Digest: "test"}}}}},
		GCPWorkloadIdentityProviders: []GCPWorkloadIdentityPoolProvider{
			{ProjectNumber: federatedGCPTestProjectNumber, PoolID: federatedGCPTestPoolID, Issuer: "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE", References: []Reference{{Digest: "test"}}},
		},
	}
}

func federatedGCPTestFindGCPEvidence(result Collection) *Evidence {
	for i := range result.Evidence {
		if result.Evidence[i].Principal.Provider == GCP {
			return &result.Evidence[i]
		}
	}
	return nil
}

// TestCollectFederatedGCPCohortAliasesToTrustedServiceAccount reproduces finding
// #2: an AWS target with a paired GCP project must ALSO collect that
// project's GCP identity domain, aliasing its cluster's bare KSA onto the
// Google service account the target's own paired GCP identity Terraform
// trusting that exact custom-pool subject (Contract A.6's project number +
// pool, never a bare pool id match -- finding #2c), re-reading that
// service account's OWN live GCP IAM policy, and keeping the alias only
// because that OWN live Trust still confirms the exact declared binding
// (finding #2d).
func TestCollectFederatedGCPCohortAliasesToTrustedServiceAccount(t *testing.T) {
	plan, dep, sa := federatedGCPTestPlan()
	declarations := []Declaration{federatedGCPTestGSADeclaration()}
	gsaGrants := []Grant{{ID: "roles/storage.objectViewer", Effect: "Allow", Role: "roles/storage.objectViewer", Resources: []string{"projects/federated-project"}, References: []Reference{{Digest: "test"}}}}
	gsaTrust := []Grant{{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{federatedGCPTestSubject}, References: []Reference{{Digest: "test"}}}}
	gsaProviders := []GCPWorkloadIdentityPoolProvider{{ProjectNumber: federatedGCPTestProjectNumber, PoolID: federatedGCPTestPoolID, ProviderID: "eks", State: "ACTIVE", Issuer: "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"}}

	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"federated": {dep, sa}}},
		Declarations: federatedGCPTestDeclarationReader{declarations: declarations},
		Clouds: map[Provider]CloudReader{
			AWS: fakeCloudReader{},
			GCP: federatedGCPTestCloudReader{
				gsaGrants:    map[string][]Grant{federatedGCPTestGSAID: gsaGrants},
				gsaTrust:     map[string][]Grant{federatedGCPTestGSAID: gsaTrust},
				gsaProviders: map[string][]GCPWorkloadIdentityPoolProvider{federatedGCPTestGSAID: gsaProviders},
			},
		},
		Investigator: fakeInvestigator{},
	}

	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	gcpEvidence := federatedGCPTestFindGCPEvidence(result)
	if gcpEvidence == nil {
		t.Fatalf("expected a GCP cohort for the target's paired project, got none among %d cohorts", len(result.Evidence))
	}
	if gcpEvidence.Principal.ID != federatedGCPTestGSAID {
		t.Fatalf("GCP cohort principal = %q, want it aliased to the declared trusted service account %q", gcpEvidence.Principal.ID, federatedGCPTestGSAID)
	}
	if gcpEvidence.Principal.Kind != federatedGCPServiceAccountKind {
		t.Fatalf("GCP cohort principal kind = %q, want %q (so the existing live GCP reader observes it as a service account)", gcpEvidence.Principal.Kind, federatedGCPServiceAccountKind)
	}
	if len(gcpEvidence.Observed.Grants) != 1 || gcpEvidence.Observed.Grants[0].Role != "roles/storage.objectViewer" {
		t.Fatalf("expected the GSA's OWN live-observed grants (proving a second, aliased Observe call happened), got %+v", gcpEvidence.Observed.Grants)
	}
	if gcpEvidence.Schema != SchemaVersion || gcpEvidence.Scope != plan.Scope || gcpEvidence.CollectedAt.IsZero() {
		t.Fatalf("expected the re-aliased cohort to carry the same Schema/Scope/CollectedAt as every other cohort, got %+v", gcpEvidence)
	}
	// GCPWorkloadIdentityProviders is now LIVE (Observation-sourced), never
	// declared (review finding #2e/Contract A): it must equal the mock
	// reader's own live facts, not the declaration's.
	if len(gcpEvidence.GCPWorkloadIdentityProviders) != 1 || gcpEvidence.GCPWorkloadIdentityProviders[0].ProjectNumber != federatedGCPTestProjectNumber || gcpEvidence.GCPWorkloadIdentityProviders[0].State != "ACTIVE" {
		t.Fatalf("expected the GSA's own LIVE custom-pool provider facts to be captured, got %+v", gcpEvidence.GCPWorkloadIdentityProviders)
	}
	if len(gcpEvidence.Declared.Trust) != 1 || gcpEvidence.Declared.Trust[0].Members[0] != federatedGCPTestSubject {
		t.Fatalf("expected the declared trust (never promoted to access on its own) to be attached, got %+v", gcpEvidence.Declared.Trust)
	}
	if len(gcpEvidence.Consumers) != 1 || gcpEvidence.Consumers[0].Namespace != "payments" || gcpEvidence.Consumers[0].ServiceAccount != "payments-sa" {
		t.Fatalf("expected the target's own EKS workload as the GSA's consumer, got %+v", gcpEvidence.Consumers)
	}
	if !strings.Contains(gcpEvidence.Consumers[0].ID, ":gcp") {
		t.Fatalf("expected the GCP-domain consumer workload ID to be distinct from its AWS twin, got %q", gcpEvidence.Consumers[0].ID)
	}

	// The AWS-domain cohort for the same workload must still exist,
	// unaffected (legacy AWS collection behavior unchanged).
	var awsEvidence *Evidence
	for i := range result.Evidence {
		if result.Evidence[i].Principal.Provider == AWS {
			awsEvidence = &result.Evidence[i]
		}
	}
	if awsEvidence == nil {
		t.Fatalf("expected the target's own AWS-domain cohort to still be collected")
	}
}

// TestCollectFederatedGCPCohortResolvesBeforeGenericAlias reproduces finding
// #2a precisely: even when the live reader's own bare-KSA probe resolves
// a GKE default-pool alias identifier for this exact KSA (ResolvedIdentifiers,
// exactly as collectionResolvedPrincipal/collectionResolvedCohorts would
// consume), the target's own declared custom-pool trust still wins, because
// collectFederatedGCPCohorts resolves federated identities BEFORE generic alias
// resolution ever runs for them.
func TestCollectFederatedGCPCohortResolvesBeforeGenericAlias(t *testing.T) {
	plan, dep, sa := federatedGCPTestPlan()
	declarations := []Declaration{federatedGCPTestGSADeclaration()}
	gsaTrust := []Grant{{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{federatedGCPTestSubject}, References: []Reference{{Digest: "test"}}}}

	ksaSubject := manifestInventoryKSASubject(federatedGCPTestCluster, "payments", "payments-sa")
	gkeAlias := "principal://iam.googleapis.com/projects/" + federatedGCPTestProjectNumber + "/locations/global/workloadIdentityPools/" + federatedGCPTestProject + ".svc.id.goog/subject/ns/payments/sa/payments-sa"

	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"federated": {dep, sa}}},
		Declarations: federatedGCPTestDeclarationReader{declarations: declarations},
		Clouds: map[Provider]CloudReader{
			AWS: fakeCloudReader{},
			GCP: federatedGCPTestCloudReader{
				gsaTrust: map[string][]Grant{federatedGCPTestGSAID: gsaTrust},
				ksaResolvedIdentifiers: map[string]string{
					"gcp_ksa_principal:" + ksaSubject: gkeAlias,
					"project_number":                  federatedGCPTestProjectNumber,
				},
			},
		},
		Investigator: fakeInvestigator{},
	}

	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	gcpEvidence := federatedGCPTestFindGCPEvidence(result)
	if gcpEvidence == nil {
		t.Fatalf("expected a GCP cohort, got none among %d cohorts", len(result.Evidence))
	}
	if gcpEvidence.Principal.ID == gkeAlias || gcpEvidence.Principal.Kind == "gcp_workload_identity_principal" && gcpEvidence.Principal.ID != federatedGCPTestSubject {
		t.Fatalf("GCP cohort was resolved onto the generic GKE default-pool alias %q instead of the target's own declared custom-pool trust", gcpEvidence.Principal.ID)
	}
	if gcpEvidence.Principal.ID != federatedGCPTestGSAID {
		t.Fatalf("expected the target's own custom-pool resolution to win over the generic GKE alias, got principal %q", gcpEvidence.Principal.ID)
	}
}

// TestCollectFederatedGCPCohortDirectCustomPoolPrincipal reproduces finding #2b:
// a custom-pool member granted a role DIRECTLY (project/org/folder- or
// resource-level IAM), never through impersonating a Google service
// account, must still become a cohort -- Contract A.5's direct-principal
// Principal shape.
func TestCollectFederatedGCPCohortDirectCustomPoolPrincipal(t *testing.T) {
	plan, dep, sa := federatedGCPTestPlan()
	directGrant := Grant{ID: "g1", Effect: "Allow", Role: "roles/storage.objectViewer", Resources: []string{"projects/federated-project"}, References: []Reference{{Digest: "test"}}}
	declarations := []Declaration{
		{
			Principal: Principal{ID: federatedGCPTestSubject, Provider: GCP, Kind: "gcp_kubernetes_service_account", Project: federatedGCPTestProject},
			Policy:    PolicyState{Complete: true, Grants: []Grant{directGrant}},
			GCPWorkloadIdentityProviders: []GCPWorkloadIdentityPoolProvider{
				{ProjectNumber: federatedGCPTestProjectNumber, PoolID: federatedGCPTestPoolID, References: []Reference{{Digest: "test"}}},
			},
		},
	}
	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"federated": {dep, sa}}},
		Declarations: federatedGCPTestDeclarationReader{declarations: declarations},
		Clouds: map[Provider]CloudReader{
			AWS: fakeCloudReader{},
			GCP: federatedGCPTestCloudReader{directGrants: map[string][]Grant{federatedGCPTestSubject: {directGrant}}},
		},
		Investigator: fakeInvestigator{},
	}

	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	gcpEvidence := federatedGCPTestFindGCPEvidence(result)
	if gcpEvidence == nil {
		t.Fatalf("expected a GCP cohort for the direct custom-pool principal, got none among %d cohorts", len(result.Evidence))
	}
	if gcpEvidence.Principal.ID != federatedGCPTestSubject {
		t.Fatalf("direct-principal cohort ID = %q, want the exact declared subject %q", gcpEvidence.Principal.ID, federatedGCPTestSubject)
	}
	if gcpEvidence.Principal.Kind != federatedGCPDirectPrincipalKind {
		t.Fatalf("direct-principal cohort Kind = %q, want %q (Contract A.5)", gcpEvidence.Principal.Kind, federatedGCPDirectPrincipalKind)
	}
	if gcpEvidence.Principal.Project != federatedGCPTestProject {
		t.Fatalf("direct-principal cohort Project = %q, want %q", gcpEvidence.Principal.Project, federatedGCPTestProject)
	}
	if len(gcpEvidence.Observed.Grants) != 1 || gcpEvidence.Observed.Grants[0].Role != "roles/storage.objectViewer" {
		t.Fatalf("expected the direct principal's OWN live-observed grants, got %+v", gcpEvidence.Observed.Grants)
	}
}

// TestCollectFederatedGCPCohortRejectsCrossFederationPoolMatch reproduces finding
// #2c: a declared trust member naming the right namespace/serviceAccount
// but through a DIFFERENT pool than the one this project's own
// paired GCP identity Terraform root declares must never cross-match (two federated GCP targets sharing a
// namespace/serviceAccount name through unrelated pools).
func TestCollectFederatedGCPCohortRejectsCrossFederationPoolMatch(t *testing.T) {
	plan, dep, sa := federatedGCPTestPlan()
	declaration := federatedGCPTestGSADeclaration()
	// The declared provider fact names a DIFFERENT pool id than the one
	// embedded in the trust member's own subject string.
	declaration.GCPWorkloadIdentityProviders = []GCPWorkloadIdentityPoolProvider{
		{ProjectNumber: federatedGCPTestProjectNumber, PoolID: "unrelated-other-federated-eks"},
	}
	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"federated": {dep, sa}}},
		Declarations: federatedGCPTestDeclarationReader{declarations: []Declaration{declaration}},
		Clouds: map[Provider]CloudReader{
			AWS: fakeCloudReader{},
			GCP: federatedGCPTestCloudReader{},
		},
		Investigator: fakeInvestigator{},
	}

	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	gcpEvidence := federatedGCPTestFindGCPEvidence(result)
	if gcpEvidence == nil {
		t.Fatalf("expected a GCP cohort (left unresolved), got none among %d cohorts", len(result.Evidence))
	}
	if !isUnresolvedCloudPrincipal(gcpEvidence.Principal) {
		t.Fatalf("expected the KSA to stay unresolved when the declared trust's pool does not match this project's own declared pool, got principal %+v", gcpEvidence.Principal)
	}
}

// TestCollectFederatedGCPCohortKeepsUnresolvedWhenBindingNotLive reproduces
// finding #2d: the GSA's own re-observed live IAM policy no longer
// confirms the target's declared custom-pool trust binding (removed,
// renamed, or narrowed) -- the KSA must stay unresolved with an explicit
// gap, never silently keep the declared trust as if it were still granted.
func TestCollectFederatedGCPCohortKeepsUnresolvedWhenBindingNotLive(t *testing.T) {
	plan, dep, sa := federatedGCPTestPlan()
	declarations := []Declaration{federatedGCPTestGSADeclaration()}
	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"federated": {dep, sa}}},
		Declarations: federatedGCPTestDeclarationReader{declarations: declarations},
		Clouds: map[Provider]CloudReader{
			AWS: fakeCloudReader{},
			// GSA's own live Trust is empty: the declared binding is no
			// longer live.
			GCP: federatedGCPTestCloudReader{},
		},
		Investigator: fakeInvestigator{},
	}

	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	gcpEvidence := federatedGCPTestFindGCPEvidence(result)
	if gcpEvidence == nil {
		t.Fatalf("expected a GCP cohort (left unresolved), got none among %d cohorts", len(result.Evidence))
	}
	if !isUnresolvedCloudPrincipal(gcpEvidence.Principal) {
		t.Fatalf("expected the KSA to stay unresolved when the GSA's own live Trust does not confirm the declared binding, got principal %+v", gcpEvidence.Principal)
	}
	if !hasGapCode(gcpEvidence.Gaps, "cloud_identity.gcp.custom_pool_binding_not_live") {
		t.Fatalf("expected cloud_identity.gcp.custom_pool_binding_not_live gap, got %+v", gcpEvidence.Gaps)
	}
}

// TestCollectOrdinaryAWSTargetProducesNoGCPCohort confirms an AWS target
// with no paired GCP project (every pre-existing, ordinary AWS target)
// never triggers the extra GCP-provider Inventory pass or any GCP cohort,
// even when a GCP CloudReader is configured -- finding #2's fix must never
// change legacy AWS-only collection behavior.
func TestCollectOrdinaryAWSTargetProducesNoGCPCohort(t *testing.T) {
	dep := deploymentManifest("api", "shop", "api-sa",
		[]map[string]any{{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/api:v1"}}, nil)
	sa := serviceAccountManifest("api-sa", "shop", map[string]string{
		manifestInventoryAnnotationIRSARole: "arn:aws:iam::111111111111:role/api-role",
	})
	plan := ScanPlan{
		Scope: "org:writer",
		Targets: []ScanTarget{
			{Name: "legacy", Environment: "prod", Cluster: "eks-legacy", Provider: AWS, Account: "111111111111", Region: "us-east-1",
				Manifests: []ManifestInput{collectionTestManifestInput("legacy")}},
		},
		Services: []ServiceMapping{{Service: "api", Repository: "example-org/api", ImagePrefixes: []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/api"}}},
	}
	ports := collectionTestPorts(map[string][]Manifest{"legacy": {dep, sa}})
	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	for _, e := range result.Evidence {
		if e.Principal.Provider == GCP {
			t.Fatalf("unexpected GCP cohort for an ordinary AWS target: %+v", e)
		}
	}
}

// federatedGCPTestAWSIssuerReader simulates the AWS reader's own IRSA/OIDC
// trust confirmation (sources/internal/cloudidentity/aws_observe.go's
// resolveWorkloadLinkage): observing an "aws_iam_role" principal returns
// ResolvedIdentifiers["aws_eks_oidc_issuer:<cluster>"] = issuer for every
// cluster named issuer != "". Every other principal Kind observes empty/
// complete, exactly like fakeCloudReader.
type federatedGCPTestAWSIssuerReader struct {
	issuer map[string]string
}

func (r federatedGCPTestAWSIssuerReader) Observe(_ context.Context, req CloudRequest) (Observation, error) {
	if req.Principal.Kind != manifestInventoryKindAWSRole {
		return Observation{Policy: PolicyState{Complete: true, Grants: []Grant{}}}, nil
	}
	resolved := map[string]string{}
	for _, consumer := range req.Consumers {
		if issuer, ok := r.issuer[consumer.Cluster]; ok && issuer != "" {
			resolved["aws_eks_oidc_issuer:"+consumer.Cluster] = issuer
		}
	}
	return Observation{Policy: PolicyState{Complete: true, Grants: []Grant{}}, ResolvedIdentifiers: resolved}, nil
}

func (federatedGCPTestAWSIssuerReader) Define(_ context.Context, _ DefinitionRequest) (Definitions, error) {
	return Definitions{Complete: true}, nil
}

// TestCollectFederatedGCPCohortCarriesClusterEKSOIDCIssuer reproduces review
// finding #2/Contract C4: a resolved custom-pool GCP cohort (GSA or
// direct principal) must carry the SAME EKS OIDC issuer the AWS reader
// already resolved for its own consumer cluster
// (aws_eks_oidc_issuer:<cluster>), so the detector can confirm the
// declared custom-pool provider actually belongs to this cluster -- never
// only the GCP reader's own project_number. When no AWS observation
// resolved an issuer for that cluster, the value must never be fabricated:
// a scoped gap is attached instead.
func TestCollectFederatedGCPCohortCarriesClusterEKSOIDCIssuer(t *testing.T) {
	issuer := "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
	dep := deploymentManifest("worker", "payments", "payments-sa",
		[]map[string]any{{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/worker:v1"}}, nil)
	sa := serviceAccountManifest("payments-sa", "payments", map[string]string{
		manifestInventoryAnnotationIRSARole: "arn:aws:iam::111111111111:role/payments-role",
	})
	plan := ScanPlan{
		Scope: "org:writer",
		Targets: []ScanTarget{
			{
				Name: "federated-a", Environment: "prod", Cluster: federatedGCPTestCluster, Provider: AWS,
				Account: "111111111111", Project: federatedGCPTestProject, Region: "us-east-1",
				Manifests: []ManifestInput{collectionTestManifestInput("federated")},
				Terraform: []TerraformRoot{{Source: SourcePin{Repository: "example-org/federated-infra", Revision: "abc123"}, Root: "modules/federated/example/gcp-identity", Region: "us-east4"}},
			},
		},
		Services: []ServiceMapping{{Service: "worker", Repository: "example-org/worker", ImagePrefixes: []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/worker"}}},
	}
	declarations := []Declaration{federatedGCPTestGSADeclaration()}
	gsaTrust := []Grant{{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{federatedGCPTestSubject}, References: []Reference{{Digest: "test"}}}}

	t.Run("issuer available from the AWS reader's own observation", func(t *testing.T) {
		ports := CollectionPorts{
			Repositories: fakeRepositoryReader{},
			Registry:     fakeRegistryReader{},
			Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"federated": {dep, sa}}},
			Declarations: federatedGCPTestDeclarationReader{declarations: declarations},
			Clouds: map[Provider]CloudReader{
				AWS: federatedGCPTestAWSIssuerReader{issuer: map[string]string{federatedGCPTestCluster: issuer}},
				GCP: federatedGCPTestCloudReader{gsaTrust: map[string][]Grant{federatedGCPTestGSAID: gsaTrust}},
			},
			Investigator: fakeInvestigator{},
		}
		result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("Collect() error = %v", err)
		}
		gcpEvidence := federatedGCPTestFindGCPEvidence(result)
		if gcpEvidence == nil {
			t.Fatalf("expected a GCP cohort, got none among %d cohorts", len(result.Evidence))
		}
		key := "aws_eks_oidc_issuer:" + federatedGCPTestCluster
		if gcpEvidence.ResolvedIdentifiers[key] != issuer {
			t.Fatalf("resolved_identifiers[%q] = %q, want the AWS-resolved issuer %q (got %+v)", key, gcpEvidence.ResolvedIdentifiers[key], issuer, gcpEvidence.ResolvedIdentifiers)
		}
		if hasGapCode(gcpEvidence.Gaps, federatedGCPCustomPoolIssuerGapCode) {
			t.Fatalf("unexpected %s gap when the issuer was available, got %+v", federatedGCPCustomPoolIssuerGapCode, gcpEvidence.Gaps)
		}
	})

	t.Run("issuer unavailable is gapped, never fabricated", func(t *testing.T) {
		ports := CollectionPorts{
			Repositories: fakeRepositoryReader{},
			Registry:     fakeRegistryReader{},
			Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"federated": {dep, sa}}},
			Declarations: federatedGCPTestDeclarationReader{declarations: declarations},
			Clouds: map[Provider]CloudReader{
				AWS: fakeCloudReader{},
				GCP: federatedGCPTestCloudReader{gsaTrust: map[string][]Grant{federatedGCPTestGSAID: gsaTrust}},
			},
			Investigator: fakeInvestigator{},
		}
		result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("Collect() error = %v", err)
		}
		gcpEvidence := federatedGCPTestFindGCPEvidence(result)
		if gcpEvidence == nil {
			t.Fatalf("expected a GCP cohort, got none among %d cohorts", len(result.Evidence))
		}
		key := "aws_eks_oidc_issuer:" + federatedGCPTestCluster
		if _, ok := gcpEvidence.ResolvedIdentifiers[key]; ok {
			t.Fatalf("expected no fabricated issuer, got resolved_identifiers=%+v", gcpEvidence.ResolvedIdentifiers)
		}
		if !hasGapCode(gcpEvidence.Gaps, federatedGCPCustomPoolIssuerGapCode) {
			t.Fatalf("expected %s gap when no issuer was available, got %+v", federatedGCPCustomPoolIssuerGapCode, gcpEvidence.Gaps)
		}
	})
}

// TestCollectFederatedGCPCohortEmitsEveryDeclaredCustomPoolPrincipal reproduces
// review finding #3: a workload's rendered ServiceAccount declared to
// impersonate MORE THAN ONE Google service account through the identical
// custom-pool subject, while simultaneously carrying a direct-principal
// grant on that same subject, must have every one of those live-
// confirmed/direct principals emitted as its own cohort -- never only the
// first declared match.
func TestCollectFederatedGCPCohortEmitsEveryDeclaredCustomPoolPrincipal(t *testing.T) {
	plan, dep, sa := federatedGCPTestPlan()
	first := federatedGCPTestGSADeclaration()
	second := first
	secondID := "second@federated-project.iam.gserviceaccount.com"
	second.Principal.ID = secondID
	directGrant := Grant{ID: "g1", Effect: "Allow", Role: "roles/storage.objectViewer", Resources: []string{"projects/federated-project"}, References: []Reference{{Digest: "test"}}}
	direct := Declaration{
		Principal: Principal{ID: federatedGCPTestSubject, Provider: GCP, Kind: federatedGCPDirectPrincipalKind, Project: federatedGCPTestProject},
		Policy:    PolicyState{Complete: true, Grants: []Grant{directGrant}},
		GCPWorkloadIdentityProviders: []GCPWorkloadIdentityPoolProvider{
			{ProjectNumber: federatedGCPTestProjectNumber, PoolID: federatedGCPTestPoolID, References: []Reference{{Digest: "test"}}},
		},
	}
	declarations := []Declaration{first, second, direct}
	gsaTrust := []Grant{{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{federatedGCPTestSubject}, References: []Reference{{Digest: "test"}}}}
	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"federated": {dep, sa}}},
		Declarations: federatedGCPTestDeclarationReader{declarations: declarations},
		Clouds: map[Provider]CloudReader{
			AWS: fakeCloudReader{},
			GCP: federatedGCPTestCloudReader{
				gsaTrust:     map[string][]Grant{federatedGCPTestGSAID: gsaTrust, secondID: gsaTrust},
				directGrants: map[string][]Grant{federatedGCPTestSubject: {directGrant}},
			},
		},
		Investigator: fakeInvestigator{},
	}

	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	var ids []string
	for _, e := range result.Evidence {
		if e.Principal.Provider == GCP {
			ids = append(ids, e.Principal.ID)
		}
	}
	sort.Strings(ids)
	want := []string{federatedGCPTestGSAID, federatedGCPTestSubject, secondID}
	sort.Strings(want)
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("expected every declared custom-pool principal to be emitted, got %v want %v", ids, want)
	}
}

// TestCollectFederatedGCPCohortRequiresProvenImpersonationRole:
// federatedGCPCustomPoolBindingIsLive runs right after collectObservation,
// which never resolves role Definitions by itself. A live binding whose
// role resolves without any impersonation permission (here
// roles/iam.serviceAccountViewer) must never alias the workload onto the
// GSA; the KSA stays unresolved with the custom_pool_binding_not_live gap.
func TestCollectFederatedGCPCohortRequiresProvenImpersonationRole(t *testing.T) {
	plan, dep, sa := federatedGCPTestPlan()
	declarations := []Declaration{federatedGCPTestGSADeclaration()}
	viewerTrust := []Grant{{Effect: "Allow", Role: "roles/iam.serviceAccountViewer", Members: []string{federatedGCPTestSubject}, References: []Reference{{Digest: "test"}}}}
	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"federated": {dep, sa}}},
		Declarations: federatedGCPTestDeclarationReader{declarations: declarations},
		Clouds: map[Provider]CloudReader{
			AWS: fakeCloudReader{},
			GCP: federatedGCPTestCloudReader{
				gsaTrust: map[string][]Grant{federatedGCPTestGSAID: viewerTrust},
				defs: Definitions{Complete: true, Roles: []RoleDefinition{
					{Name: "roles/iam.serviceAccountViewer", Permissions: []string{"iam.serviceAccounts.get"}},
				}},
			},
		},
		Investigator: fakeInvestigator{},
	}

	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	gcpEvidence := federatedGCPTestFindGCPEvidence(result)
	if gcpEvidence == nil {
		t.Fatalf("expected a GCP cohort (left unresolved), got none among %d cohorts", len(result.Evidence))
	}
	if !isUnresolvedCloudPrincipal(gcpEvidence.Principal) {
		t.Fatalf("expected the KSA to stay unresolved when the GSA's trust role resolves but grants no impersonation permission, got principal %+v", gcpEvidence.Principal)
	}
	if !hasGapCode(gcpEvidence.Gaps, "cloud_identity.gcp.custom_pool_binding_not_live") {
		t.Fatalf("expected cloud_identity.gcp.custom_pool_binding_not_live gap, got %+v", gcpEvidence.Gaps)
	}
	for _, e := range result.Evidence {
		if e.Principal.ID == federatedGCPTestGSAID {
			t.Fatalf("unexpected alias to the GSA from a non-impersonation-capable role: %+v", e)
		}
	}
}

// TestCollectFederatedGCPCohortAnnotatedGSAStillExpandsCustomPool: an
// already-configured GSA (an iam.gke.io/gcp-service-account annotation)
// still gets its cluster issuer, and a separately declared
// direct-principal grant on the identical Kubernetes subject is still
// emitted.
func TestCollectFederatedGCPCohortAnnotatedGSAStillExpandsCustomPool(t *testing.T) {
	plan, dep, _ := federatedGCPTestPlan()
	sa := serviceAccountManifest("payments-sa", "payments", map[string]string{
		manifestInventoryAnnotationGCPGSA: federatedGCPTestGSAID,
	})
	direct := Declaration{
		Principal: Principal{ID: federatedGCPTestSubject, Provider: GCP, Kind: federatedGCPDirectPrincipalKind, Project: federatedGCPTestProject},
		Policy:    PolicyState{Complete: true, Grants: []Grant{{Effect: "Allow", Role: "roles/storage.objectViewer"}}},
		GCPWorkloadIdentityProviders: []GCPWorkloadIdentityPoolProvider{
			{ProjectNumber: federatedGCPTestProjectNumber, PoolID: federatedGCPTestPoolID},
		},
	}
	declarations := []Declaration{federatedGCPTestGSADeclaration(), direct}
	issuer := "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"federated": {dep, sa}}},
		Declarations: federatedGCPTestDeclarationReader{declarations: declarations},
		Clouds: map[Provider]CloudReader{
			AWS: federatedGCPTestAWSKSAIssuerReader{issuer: map[string]string{federatedGCPTestCluster: issuer}},
			GCP: federatedGCPTestCloudReader{directGrants: map[string][]Grant{federatedGCPTestSubject: {{Effect: "Allow", Role: "roles/storage.objectViewer"}}}},
		},
		Investigator: fakeInvestigator{},
	}

	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	var gsa *Evidence
	sawDirect := false
	for i := range result.Evidence {
		if result.Evidence[i].Principal.ID == federatedGCPTestGSAID {
			gsa = &result.Evidence[i]
		}
		if result.Evidence[i].Principal.ID == federatedGCPTestSubject {
			sawDirect = true
		}
	}
	if gsa == nil {
		t.Fatalf("expected the annotated GSA cohort, got none among %+v", result.Evidence)
	}
	if !sawDirect {
		t.Fatalf("expected the declared direct-principal cohort on the same subject to still be emitted, got %+v", result.Evidence)
	}
	key := "aws_eks_oidc_issuer:" + federatedGCPTestCluster
	if gsa.ResolvedIdentifiers[key] != issuer {
		t.Fatalf("expected the annotated GSA to carry the cluster issuer, got %+v", gsa.ResolvedIdentifiers)
	}
}

// TestCollectFederatedGCPCohortPodIdentityPathCarriesClusterIssuer: an
// aws_eks_oidc_issuer:<cluster> resolved on the Pod Identity
// (aws_kubernetes_service_account) path reaches the target's GCP cohort for
// a cluster with no IRSA cohort at all.
func TestCollectFederatedGCPCohortPodIdentityPathCarriesClusterIssuer(t *testing.T) {
	plan, dep, sa := federatedGCPTestPlan()
	declarations := []Declaration{federatedGCPTestGSADeclaration()}
	gsaTrust := []Grant{{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{federatedGCPTestSubject}, References: []Reference{{Digest: "test"}}}}
	issuer := "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
	// podIdentityIssuerReader simulates the fixed AWS reader: it resolves
	// aws_eks_oidc_issuer:<cluster> from the aws_kubernetes_service_account
	// (Pod Identity) principal kind, the same key the IRSA path has always
	// produced -- federatedGCPTestPlan's own ServiceAccount carries no IRSA
	// annotation, so every AWS-domain workload here is Pod-Identity-only.
	podIdentityIssuerReader := federatedGCPTestAWSKSAIssuerReader{issuer: map[string]string{federatedGCPTestCluster: issuer}}
	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"federated": {dep, sa}}},
		Declarations: federatedGCPTestDeclarationReader{declarations: declarations},
		Clouds: map[Provider]CloudReader{
			AWS: podIdentityIssuerReader,
			GCP: federatedGCPTestCloudReader{gsaTrust: map[string][]Grant{federatedGCPTestGSAID: gsaTrust}},
		},
		Investigator: fakeInvestigator{},
	}

	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	gcpEvidence := federatedGCPTestFindGCPEvidence(result)
	if gcpEvidence == nil {
		t.Fatalf("expected a GCP cohort, got none among %d cohorts", len(result.Evidence))
	}
	key := "aws_eks_oidc_issuer:" + federatedGCPTestCluster
	if gcpEvidence.ResolvedIdentifiers[key] != issuer {
		t.Fatalf("resolved_identifiers[%q] = %q, want the Pod-Identity-path-resolved issuer %q (got %+v)", key, gcpEvidence.ResolvedIdentifiers[key], issuer, gcpEvidence.ResolvedIdentifiers)
	}
	if hasGapCode(gcpEvidence.Gaps, federatedGCPCustomPoolIssuerGapCode) {
		t.Fatalf("unexpected %s gap when the Pod-Identity-path issuer was available, got %+v", federatedGCPCustomPoolIssuerGapCode, gcpEvidence.Gaps)
	}
}

// federatedGCPTestAWSKSAIssuerReader simulates the fixed AWS reader's
// aws_kubernetes_service_account (Pod Identity) path resolving
// ResolvedIdentifiers["aws_eks_oidc_issuer:<cluster>"] = issuer for every
// cluster named issuer != "", the same key federatedGCPTestAWSIssuerReader
// simulates for the aws_iam_role (IRSA) path. An issuerByAccount entry for
// the consumer's account takes precedence, so same-named clusters in
// different accounts can resolve different issuers.
type federatedGCPTestAWSKSAIssuerReader struct {
	issuer          map[string]string
	issuerByAccount map[string]string
}

func (r federatedGCPTestAWSKSAIssuerReader) Observe(_ context.Context, req CloudRequest) (Observation, error) {
	if req.Principal.Kind != manifestInventoryKindAWSKubernetesSA {
		return Observation{Policy: PolicyState{Complete: true, Grants: []Grant{}}}, nil
	}
	resolved := map[string]string{}
	for _, consumer := range req.Consumers {
		issuer, ok := r.issuerByAccount[consumer.CloudAccount]
		if !ok {
			issuer = r.issuer[consumer.Cluster]
		}
		if issuer != "" {
			resolved["aws_eks_oidc_issuer:"+consumer.Cluster] = issuer
		}
	}
	return Observation{Policy: PolicyState{Complete: true, Grants: []Grant{}}, ResolvedIdentifiers: resolved}, nil
}

func (federatedGCPTestAWSKSAIssuerReader) Define(_ context.Context, _ DefinitionRequest) (Definitions, error) {
	return Definitions{Complete: true}, nil
}

// TestCollectFederatedGCPCohortSameNamedClustersStayDistinctDomains: two federated
// targets whose clusters share a name (but differ in account/project/
// region) render the identical cluster/namespace/serviceAccount subject;
// each domain's placeholder must stay its own cohort so the second target's
// declared GSA is still collected.
func TestCollectFederatedGCPCohortSameNamedClustersStayDistinctDomains(t *testing.T) {
	const cluster = "same-cluster"
	dep := deploymentManifest("worker", "payments", "payments-sa",
		[]map[string]any{{"name": "app", "image": "example/worker:v1"}}, nil)
	sa := serviceAccountManifest("payments-sa", "payments", nil)
	targets := []ScanTarget{
		{
			Name: "a", Environment: "prod", Cluster: cluster, Provider: AWS,
			Account: "111111111111", Project: "project-a", Region: "us-east-1",
			Manifests: []ManifestInput{collectionTestManifestInput("a")},
			Terraform: []TerraformRoot{{Source: SourcePin{Repository: "repo", Revision: "rev"}, Root: "a"}},
		},
		{
			Name: "b", Environment: "prod", Cluster: cluster, Provider: AWS,
			Account: "222222222222", Project: "project-b", Region: "us-west-2",
			Manifests: []ManifestInput{collectionTestManifestInput("b")},
			Terraform: []TerraformRoot{{Source: SourcePin{Repository: "repo", Revision: "rev"}, Root: "b"}},
		},
	}
	subjectA := "principal://iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/pool-a/subject/system:serviceaccount:payments:payments-sa"
	subjectB := "principal://iam.googleapis.com/projects/222/locations/global/workloadIdentityPools/pool-b/subject/system:serviceaccount:payments:payments-sa"
	const gsaA, gsaB = "a@project-a.iam.gserviceaccount.com", "b@project-b.iam.gserviceaccount.com"
	mk := func(id, project, number, pool, subject string) Declaration {
		return Declaration{
			Principal:                    Principal{ID: id, Provider: GCP, Kind: "service_account", Project: project},
			Policy:                       PolicyState{Complete: true, Trust: []Grant{{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{subject}}}},
			GCPWorkloadIdentityProviders: []GCPWorkloadIdentityPoolProvider{{ProjectNumber: number, PoolID: pool}},
		}
	}
	declarations := []Declaration{mk(gsaA, "project-a", "111", "pool-a", subjectA), mk(gsaB, "project-b", "222", "pool-b", subjectB)}
	ports := collectionTestPorts(map[string][]Manifest{"a": {dep, sa}, "b": {dep, sa}})
	ports.Declarations = federatedGCPTestDeclarationReader{declarations: declarations}
	ports.Clouds[GCP] = federatedGCPTestCloudReader{
		gsaTrust: map[string][]Grant{
			gsaA: {{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{subjectA}}},
			gsaB: {{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{subjectB}}},
		},
	}

	result, err := Collect(context.Background(), ScanPlan{
		Scope:    "org",
		Targets:  targets,
		Services: []ServiceMapping{{Service: "worker", Repository: "repo", ImagePrefixes: []string{"example/worker"}}},
	}, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	sawA, sawB := false, false
	for _, e := range result.Evidence {
		sawA = sawA || e.Principal.ID == gsaA
		sawB = sawB || e.Principal.ID == gsaB
	}
	if !sawA || !sawB {
		t.Fatalf("expected both federated domains' own GSAs to be collected despite sharing a cluster name, got a=%v b=%v evidence=%+v", sawA, sawB, result.Evidence)
	}
}

// TestCollectFederatedGCPCohortExpandsPerSubjectConsumerPartition reproduces
// review finding #4: an already-annotated GSA shared by TWO Kubernetes
// subjects on the same federated target (sa-a and sa-b) must expand each subject
// against ONLY that subject's own declared custom-pool trust, never
// collapse onto the cohort's first consumer -- a GSA declared to trust
// sa-a's subject must never be emitted carrying sa-b's consumer (and vice
// versa), even though both come from the identical resolved GSA cohort.
func TestCollectFederatedGCPCohortExpandsPerSubjectConsumerPartition(t *testing.T) {
	plan, _, _ := federatedGCPTestPlan()
	depA := deploymentManifest("worker-a", "payments", "sa-a",
		[]map[string]any{{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/worker:v1"}}, nil)
	saA := serviceAccountManifest("sa-a", "payments", map[string]string{manifestInventoryAnnotationGCPGSA: federatedGCPTestGSAID})
	depB := deploymentManifest("worker-b", "payments", "sa-b",
		[]map[string]any{{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/worker:v1"}}, nil)
	saB := serviceAccountManifest("sa-b", "payments", map[string]string{manifestInventoryAnnotationGCPGSA: federatedGCPTestGSAID})

	subjectA := "principal://iam.googleapis.com/projects/" + federatedGCPTestProjectNumber + "/locations/global/workloadIdentityPools/" + federatedGCPTestPoolID + "/subject/system:serviceaccount:payments:sa-a"
	subjectB := "principal://iam.googleapis.com/projects/" + federatedGCPTestProjectNumber + "/locations/global/workloadIdentityPools/" + federatedGCPTestPoolID + "/subject/system:serviceaccount:payments:sa-b"
	const extraA, extraB = "extra-a@federated-project.iam.gserviceaccount.com", "extra-b@federated-project.iam.gserviceaccount.com"
	mkDecl := func(id, subject string) Declaration {
		return Declaration{
			Principal: Principal{ID: id, Provider: GCP, Kind: "service_account", Project: federatedGCPTestProject},
			Policy:    PolicyState{Complete: true, Trust: []Grant{{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{subject}, References: []Reference{{Digest: "test"}}}}},
			GCPWorkloadIdentityProviders: []GCPWorkloadIdentityPoolProvider{
				{ProjectNumber: federatedGCPTestProjectNumber, PoolID: federatedGCPTestPoolID, References: []Reference{{Digest: "test"}}},
			},
		}
	}
	declarations := []Declaration{mkDecl(extraA, subjectA), mkDecl(extraB, subjectB)}
	issuer := "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"

	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"federated": {depA, saA, depB, saB}}},
		Declarations: federatedGCPTestDeclarationReader{declarations: declarations},
		Clouds: map[Provider]CloudReader{
			AWS: federatedGCPTestAWSKSAIssuerReader{issuer: map[string]string{federatedGCPTestCluster: issuer}},
			GCP: federatedGCPTestCloudReader{
				gsaTrust: map[string][]Grant{
					extraA: {{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{subjectA}, References: []Reference{{Digest: "test"}}}},
					extraB: {{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{subjectB}, References: []Reference{{Digest: "test"}}}},
				},
			},
		},
		Investigator: fakeInvestigator{},
	}

	result, err := Collect(context.Background(), plan, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	byID := map[string]*Evidence{}
	for i := range result.Evidence {
		if result.Evidence[i].Principal.Provider == GCP {
			byID[result.Evidence[i].Principal.ID] = &result.Evidence[i]
		}
	}
	annotated, okAnnotated := byID[federatedGCPTestGSAID]
	a, okA := byID[extraA]
	b, okB := byID[extraB]
	if !okAnnotated || !okA || !okB {
		t.Fatalf("expected the annotated GSA plus both extra-a/extra-b cohorts, got %+v", byID)
	}
	if len(annotated.Consumers) != 2 {
		t.Fatalf("expected the annotated GSA to keep BOTH consumers, got %+v", annotated.Consumers)
	}
	if len(a.Consumers) != 1 || a.Consumers[0].ServiceAccount != "sa-a" {
		t.Fatalf("expected %s to carry ONLY sa-a's consumer, got %+v", extraA, a.Consumers)
	}
	if len(b.Consumers) != 1 || b.Consumers[0].ServiceAccount != "sa-b" {
		t.Fatalf("expected %s to carry ONLY sa-b's consumer, got %+v", extraB, b.Consumers)
	}
	key := "aws_eks_oidc_issuer:" + federatedGCPTestCluster
	if a.ResolvedIdentifiers[key] != issuer || b.ResolvedIdentifiers[key] != issuer {
		t.Fatalf("expected both extra GSAs to carry the cluster issuer, got a=%+v b=%+v", a.ResolvedIdentifiers, b.ResolvedIdentifiers)
	}
}

// TestCollectFederatedGCPCohortCrossProjectAnnotatedGSAResolvesEveryFederatedDomain
// reproduces review finding #6: a single GSA, owned by a GCP project
// DIFFERENT from any federated GCP target's own paired project (e.g. a shared identity
// project), annotated onto consumers in TWO distinct federated GCP targets, must
// still be routed as a federated cohort (never by matching Principal.Project
// against a federated GCP target's own project) and must carry the AWS-resolved EKS OIDC
// issuer for EVERY distinct federated-consumer cluster domain -- never only
// its first consumer's. A GSA declared in one consumer's own federated GCP project
// to trust that exact subject must also be emitted, carrying ONLY that
// one consumer (proving expansion partitions by the CONSUMER's project,
// never the resolved GSA's).
func TestCollectFederatedGCPCohortCrossProjectAnnotatedGSAResolvesEveryFederatedDomain(t *testing.T) {
	const sharedGSA = "shared@identity-project.iam.gserviceaccount.com"
	dep := deploymentManifest("worker", "payments", "shared",
		[]map[string]any{{"name": "app", "image": "example/worker:v1"}}, nil)
	sa := serviceAccountManifest("shared", "payments", map[string]string{manifestInventoryAnnotationGCPGSA: sharedGSA})
	targets := []ScanTarget{
		{
			Name: "a", Environment: "prod", Cluster: "cluster-a", Provider: AWS,
			Account: "111111111111", Project: "project-a", Region: "us-east-1",
			Manifests: []ManifestInput{collectionTestManifestInput("a")},
			Terraform: []TerraformRoot{{Source: SourcePin{Repository: "repo", Revision: "rev"}, Root: "a"}},
		},
		{
			Name: "b", Environment: "prod", Cluster: "cluster-b", Provider: AWS,
			Account: "222222222222", Project: "project-b", Region: "us-west-2",
			Manifests: []ManifestInput{collectionTestManifestInput("b")},
			Terraform: []TerraformRoot{{Source: SourcePin{Repository: "repo", Revision: "rev"}, Root: "b"}},
		},
	}
	subjectA := "principal://iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/pool-a/subject/system:serviceaccount:payments:shared"
	const extraA = "extra@project-a.iam.gserviceaccount.com"
	declarations := []Declaration{
		{
			Principal: Principal{ID: extraA, Provider: GCP, Kind: "service_account", Project: "project-a"},
			Policy:    PolicyState{Complete: true, Trust: []Grant{{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{subjectA}, References: []Reference{{Digest: "test"}}}}},
			GCPWorkloadIdentityProviders: []GCPWorkloadIdentityPoolProvider{
				{ProjectNumber: "111", PoolID: "pool-a", References: []Reference{{Digest: "test"}}},
			},
		},
	}
	issuerA, issuerB := "https://oidc.eks.us-east-1.amazonaws.com/id/A", "https://oidc.eks.us-west-2.amazonaws.com/id/B"

	ports := collectionTestPorts(map[string][]Manifest{"a": {dep, sa}, "b": {dep, sa}})
	ports.Declarations = federatedGCPTestDeclarationReader{declarations: declarations}
	ports.Clouds[AWS] = federatedGCPTestAWSKSAIssuerReader{issuer: map[string]string{"cluster-a": issuerA, "cluster-b": issuerB}}
	ports.Clouds[GCP] = federatedGCPTestCloudReader{
		gsaTrust: map[string][]Grant{
			extraA: {{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{subjectA}, References: []Reference{{Digest: "test"}}}},
		},
	}

	result, err := Collect(context.Background(), ScanPlan{
		Scope:    "org",
		Targets:  targets,
		Services: []ServiceMapping{{Service: "worker", Repository: "repo", ImagePrefixes: []string{"example/worker"}}},
	}, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	var annotated *Evidence
	var extra *Evidence
	for i := range result.Evidence {
		switch result.Evidence[i].Principal.ID {
		case sharedGSA:
			annotated = &result.Evidence[i]
		case extraA:
			extra = &result.Evidence[i]
		}
	}
	if annotated == nil {
		t.Fatalf("expected the cross-project annotated GSA to be routed as a federated cohort (never skipped for not matching a federated GCP target's own project), got %+v", result.Evidence)
	}
	if len(annotated.Consumers) != 2 {
		t.Fatalf("expected the annotated GSA to keep BOTH federated consumers, got %+v", annotated.Consumers)
	}
	keyA, keyB := "aws_eks_oidc_issuer:cluster-a", "aws_eks_oidc_issuer:cluster-b"
	if annotated.ResolvedIdentifiers[keyA] != issuerA || annotated.ResolvedIdentifiers[keyB] != issuerB {
		t.Fatalf("expected the annotated GSA to carry BOTH clusters' issuers, got %+v", annotated.ResolvedIdentifiers)
	}
	if hasGapCode(annotated.Gaps, federatedGCPCustomPoolIssuerGapCode) {
		t.Fatalf("unexpected %s gap when both clusters' issuers were available, got %+v", federatedGCPCustomPoolIssuerGapCode, annotated.Gaps)
	}
	if extra == nil {
		t.Fatalf("expected the federated-project-declared GSA %s to be emitted, got %+v", extraA, result.Evidence)
	}
	if len(extra.Consumers) != 1 || extra.Consumers[0].CloudProject != "project-a" {
		t.Fatalf("expected %s to carry ONLY the project-a consumer (expansion must use the consumer's own project), got %+v", extraA, extra.Consumers)
	}
}

// TestCollectFederatedGCPCohortMergedSubjectsLeaveConflictingIssuerUnset: one
// GSA resolved from two Kubernetes subjects whose federated targets' clusters share a
// name but resolve different issuers must carry neither issuer. Attached
// per subject before the merge, the merged GSA kept whichever subject
// merged last, letting the detector link the other federated target's consumer through
// a provider its own cluster never issued for.
func TestCollectFederatedGCPCohortMergedSubjectsLeaveConflictingIssuerUnset(t *testing.T) {
	const cluster = "shared-cluster"
	const annotatedGSA = "shared@project-a.iam.gserviceaccount.com"
	const extraGSA = "extra@project-a.iam.gserviceaccount.com"
	workload := func(serviceAccount string) (Manifest, Manifest) {
		dep := deploymentManifest("worker-"+serviceAccount, "payments", serviceAccount,
			[]map[string]any{{"name": "app", "image": "example/worker:v1"}}, nil)
		return dep, serviceAccountManifest(serviceAccount, "payments", map[string]string{manifestInventoryAnnotationGCPGSA: annotatedGSA})
	}
	depA, saA := workload("sa-a")
	depB, saB := workload("sa-b")
	target := func(name, account, region string) ScanTarget {
		return ScanTarget{
			Name: name, Environment: "prod", Cluster: cluster, Provider: AWS,
			Account: account, Project: "project-a", Region: region,
			Manifests: []ManifestInput{collectionTestManifestInput(name)},
			Terraform: []TerraformRoot{{Source: SourcePin{Repository: "repo", Revision: "rev"}, Root: name}},
		}
	}
	subject := func(serviceAccount string) string {
		return "principal://iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/pool-a/subject/system:serviceaccount:payments:" + serviceAccount
	}
	trust := []Grant{{Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{subject("sa-a"), subject("sa-b")}, References: []Reference{{Digest: "test"}}}}
	ports := collectionTestPorts(map[string][]Manifest{"a": {depA, saA}, "b": {depB, saB}})
	ports.Declarations = federatedGCPTestDeclarationReader{declarations: []Declaration{{
		Principal:                    Principal{ID: extraGSA, Provider: GCP, Kind: "service_account", Project: "project-a"},
		Policy:                       PolicyState{Complete: true, Trust: trust},
		GCPWorkloadIdentityProviders: []GCPWorkloadIdentityPoolProvider{{ProjectNumber: "111", PoolID: "pool-a", References: []Reference{{Digest: "test"}}}},
	}}}
	ports.Clouds[AWS] = federatedGCPTestAWSKSAIssuerReader{issuerByAccount: map[string]string{
		"111111111111": "https://oidc.eks.us-east-1.amazonaws.com/id/A",
		"222222222222": "https://oidc.eks.us-west-2.amazonaws.com/id/B",
	}}
	ports.Clouds[GCP] = federatedGCPTestCloudReader{gsaTrust: map[string][]Grant{extraGSA: trust}}

	result, err := Collect(context.Background(), ScanPlan{
		Scope:    "org",
		Targets:  []ScanTarget{target("a", "111111111111", "us-east-1"), target("b", "222222222222", "us-west-2")},
		Services: []ServiceMapping{{Service: "worker", Repository: "repo", ImagePrefixes: []string{"example/worker"}}},
	}, ports, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	var extra *Evidence
	for i := range result.Evidence {
		if result.Evidence[i].Principal.ID == extraGSA {
			extra = &result.Evidence[i]
		}
	}
	if extra == nil || len(extra.Consumers) != 2 {
		t.Fatalf("expected %s resolved from both subjects, got %+v", extraGSA, result.Evidence)
	}
	key := "aws_eks_oidc_issuer:" + cluster
	if issuer, ok := extra.ResolvedIdentifiers[key]; ok {
		t.Fatalf("resolved_identifiers[%q] = %q, want unset: the two federated targets' same-named clusters resolve different issuers", key, issuer)
	}
	if !hasGapCode(extra.Gaps, federatedGCPCustomPoolIssuerGapCode) {
		t.Fatalf("expected the %s gap, got %+v", federatedGCPCustomPoolIssuerGapCode, extra.Gaps)
	}
}
