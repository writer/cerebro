package cloudidentity

import (
	"context"
	"testing"
	"time"
)

// fakeTrustCloudReader returns a caller-registered Observation keyed by
// Principal.ID, falling back to a fully-observed-but-empty-trust
// Observation (the "unknown trust" case for subjectMayAssumePrincipal) for
// any principal with no registered entry.
type fakeTrustCloudReader struct {
	byPrincipal map[string]Observation
}

func (f fakeTrustCloudReader) Observe(_ context.Context, req CloudRequest) (Observation, error) {
	if obs, ok := f.byPrincipal[req.Principal.ID]; ok {
		return obs, nil
	}
	return Observation{Policy: PolicyState{Complete: true, Grants: []Grant{}}}, nil
}

func (f fakeTrustCloudReader) Define(_ context.Context, _ DefinitionRequest) (Definitions, error) {
	return Definitions{Complete: true}, nil
}

// collectionSubjectScopeAWSPorts builds a cluster-like AWS target: a
// checkout-sa-backed role workload (checkout-api) plus an envoy sidecar
// whose ServiceAccount ("shared") is never rendered, reproducing
// cloud_identity.inventory.service_account_not_rendered scoped to subject
// "shared/shared".
func collectionSubjectScopeAWSPorts(trust map[string]Observation) (ScanPlan, CollectionPorts) {
	checkoutSA := serviceAccountManifest("checkout-sa", "checkout", map[string]string{
		manifestInventoryAnnotationIRSARole: "arn:aws:iam::111111111111:role/checkout-role",
	})
	checkoutDep := deploymentManifest("checkout-api", "checkout", "checkout-sa",
		[]map[string]any{{"name": "app", "image": "111111111111.dkr.ecr.us-east-1.amazonaws.com/checkout:v1"}}, nil)
	envoyDep := deploymentManifest("envoy-sidecar", "shared", "shared",
		[]map[string]any{{"name": "envoy", "image": "envoyproxy/envoy:v1.28"}}, nil)

	plan := ScanPlan{
		Scope: "org:example-org",
		Targets: []ScanTarget{
			{Name: "demo", Cluster: "cluster-aws", Provider: AWS, Account: "111111111111", Region: "us-east-1",
				Manifests: []ManifestInput{collectionTestManifestInput("demo")}},
		},
		Services: []ServiceMapping{
			{Service: "checkout", ImagePrefixes: []string{"111111111111.dkr.ecr.us-east-1.amazonaws.com/checkout"}, Repository: "github.com/example/checkout"},
			{Service: "envoy", ImagePrefixes: []string{"envoyproxy/envoy"}, Repository: "github.com/example/envoy"},
		},
	}
	ports := collectionTestPorts(map[string][]Manifest{"demo": {checkoutSA, checkoutDep, envoyDep}})
	ports.Clouds = map[Provider]CloudReader{AWS: fakeTrustCloudReader{byPrincipal: trust}}
	return plan, ports
}

const checkoutRoleID = "arn:aws:iam::111111111111:role/checkout-role"

// TestCollectUnrenderedServiceAccountLeavesUnrelatedTrustComplete is
// acceptance case (a): the hidden ServiceAccount subject ("shared/shared")
// is never admitted by checkout-role's live trust (which only admits a
// different Kubernetes subject), so checkout-api's cohort stays complete.
func TestCollectUnrenderedServiceAccountLeavesUnrelatedTrustComplete(t *testing.T) {
	providerARN := "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE123"
	plan, ports := collectionSubjectScopeAWSPorts(map[string]Observation{
		checkoutRoleID: {
			Policy: PolicyState{Complete: true, Trust: []Grant{{
				Effect:  "Allow",
				Members: []string{"Federated:" + providerARN},
				Conditions: []Condition{{
					Operator: "StringEquals",
					Key:      "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE123:sub",
					Values:   []string{"system:serviceaccount:checkout:checkout-sa"},
				}},
			}}},
			ResolvedIdentifiers: map[string]string{"aws_eks_oidc_provider_arn:cluster-aws": providerARN},
		},
	})

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !hasGapCode(result.Gaps, "cloud_identity.inventory.service_account_not_rendered") {
		t.Fatalf("expected service_account_not_rendered gap, got %+v", result.Gaps)
	}
	checkout := collectionFindEvidence(t, result, "checkout-api")
	if !checkout.ConsumerInventoryComplete {
		t.Fatalf("trust admitting only a different subject must never demote this cohort: %+v", checkout)
	}
	if hasGapCode(checkout.Gaps, "unrendered_service_account_trust") {
		t.Fatalf("no subject-trust gap expected on an unaffected cohort: %+v", checkout.Gaps)
	}
}

// TestCollectUnrenderedServiceAccountDemotesAdmittingTrust is acceptance
// case (b): checkout-role's live Federated trust exactly admits the hidden
// subject "system:serviceaccount:shared:shared" for the target cluster's
// resolved OIDC provider, so the cohort is demoted with the subject gap.
func TestCollectUnrenderedServiceAccountDemotesAdmittingTrust(t *testing.T) {
	providerARN := "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE123"
	plan, ports := collectionSubjectScopeAWSPorts(map[string]Observation{
		checkoutRoleID: {
			Policy: PolicyState{Complete: true, Trust: []Grant{{
				Effect:  "Allow",
				Members: []string{"Federated:" + providerARN},
				Conditions: []Condition{{
					Operator: "StringEquals",
					Key:      "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE123:sub",
					Values:   []string{"system:serviceaccount:shared:shared"},
				}},
			}}},
			ResolvedIdentifiers: map[string]string{"aws_eks_oidc_provider_arn:cluster-aws": providerARN},
		},
	})

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	checkout := collectionFindEvidence(t, result, "checkout-api")
	if checkout.ConsumerInventoryComplete {
		t.Fatalf("trust admitting the hidden subject must demote this cohort: %+v", checkout)
	}
	if !hasGapCode(checkout.Gaps, "unrendered_service_account_trust") {
		t.Fatalf("expected unrendered_service_account_trust gap naming the subject, got %+v", checkout.Gaps)
	}
}

// TestCollectUnrenderedServiceAccountDemotesUnknownTrust is acceptance case
// (c): a principal with no registered (unknown/incomplete) trust is
// conservatively treated as possibly admitting the hidden subject.
func TestCollectUnrenderedServiceAccountDemotesUnknownTrust(t *testing.T) {
	plan, ports := collectionSubjectScopeAWSPorts(nil)

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	checkout := collectionFindEvidence(t, result, "checkout-api")
	if checkout.ConsumerInventoryComplete {
		t.Fatalf("unknown/empty observed trust must be conservative (incomplete): %+v", checkout)
	}
	if !hasGapCode(checkout.Gaps, "unrendered_service_account_trust") {
		t.Fatalf("expected unrendered_service_account_trust gap, got %+v", checkout.Gaps)
	}
}

// TestCollectUnrenderedServiceAccountGCPLegacyMemberForm is acceptance case
// (d): the GCP analogue, using the legacy "serviceAccount:<project>.svc.id.goog[<ns>/<sa>]"
// trust member form to admit the hidden subject.
func TestCollectUnrenderedServiceAccountGCPLegacyMemberForm(t *testing.T) {
	billingSA := serviceAccountManifest("billing-sa", "billing", map[string]string{
		manifestInventoryAnnotationGCPGSA: "billing@example-project.iam.gserviceaccount.com",
	})
	billingDep := deploymentManifest("billing-api", "billing", "billing-sa",
		[]map[string]any{{"name": "app", "image": "gcr.io/example-project/billing:v1"}}, nil)
	envoyDep := deploymentManifest("envoy-sidecar", "shared", "shared",
		[]map[string]any{{"name": "envoy", "image": "envoyproxy/envoy:v1.28"}}, nil)

	plan := ScanPlan{
		Scope: "org:example-org",
		Targets: []ScanTarget{
			{Name: "demo-gcp", Cluster: "cluster-gcp", Provider: GCP, Project: "example-project",
				Manifests: []ManifestInput{collectionTestManifestInput("demo-gcp")}},
		},
		Services: []ServiceMapping{
			{Service: "billing", ImagePrefixes: []string{"gcr.io/example-project/billing"}, Repository: "github.com/example/billing"},
			{Service: "envoy", ImagePrefixes: []string{"envoyproxy/envoy"}, Repository: "github.com/example/envoy"},
		},
	}
	ports := collectionTestPorts(map[string][]Manifest{"demo-gcp": {billingSA, billingDep, envoyDep}})
	billingPrincipalID := "billing@example-project.iam.gserviceaccount.com"
	ports.Clouds = map[Provider]CloudReader{GCP: fakeTrustCloudReader{byPrincipal: map[string]Observation{
		billingPrincipalID: {
			Policy: PolicyState{Complete: true, Trust: []Grant{{
				Effect:  "Allow",
				Members: []string{"serviceAccount:example-project.svc.id.goog[shared/shared]"},
			}}},
		},
	}}}

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !hasGapCode(result.Gaps, "cloud_identity.inventory.service_account_not_rendered") {
		t.Fatalf("expected service_account_not_rendered gap, got %+v", result.Gaps)
	}
	billing := collectionFindEvidence(t, result, "billing-api")
	if billing.ConsumerInventoryComplete {
		t.Fatalf("legacy serviceAccount: member admitting the hidden subject must demote this cohort: %+v", billing)
	}
	if !hasGapCode(billing.Gaps, "unrendered_service_account_trust") {
		t.Fatalf("expected unrendered_service_account_trust gap, got %+v", billing.Gaps)
	}
}
