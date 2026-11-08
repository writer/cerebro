package cloudidentity

import (
	"context"
	"testing"
	"time"
)

// collectionPodIdentityPorts builds a one-target AWS cell-style plan: a
// "worker" ServiceAccount with no IRSA annotation (the Pod Identity
// convention), a single Deployment consumer, and a Clouds reader whose
// Observe confirms a live EKS Pod Identity association for that exact
// consumer. manifests additionally carries whatever ACK declaration
// fixtures the test wants rendered alongside the workload.
func collectionPodIdentityPorts(roleARN string, extraManifests ...Manifest) (ScanPlan, CollectionPorts) {
	sa := serviceAccountManifest("worker", "payments", nil)
	dep := deploymentManifest("payments-api", "payments", "worker",
		[]map[string]any{{"name": "app", "image": "111111111111.dkr.ecr.us-east-1.amazonaws.com/payments:v1"}}, nil)
	manifests := append([]Manifest{sa, dep}, extraManifests...)

	plan := ScanPlan{
		Scope: "org:example-org",
		Targets: []ScanTarget{
			{Name: "cluster-a", Cluster: "cluster-a", Provider: AWS, Account: "111111111111", Region: "us-east-1",
				Manifests: []ManifestInput{collectionTestManifestInput("cell")}},
		},
		Services: []ServiceMapping{
			{Service: "payments", ImagePrefixes: []string{"111111111111.dkr.ecr.us-east-1.amazonaws.com/payments"}, Repository: "github.com/example/payments"},
		},
	}
	resolved := map[string]string{"aws_pod_identity_role:k8s://cluster-a/payments/sa/worker": roleARN}
	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"cell": manifests}},
		Declarations: fakeDeclarationReader{},
		Clouds: map[Provider]CloudReader{AWS: fakeTrustCloudReader{byPrincipal: map[string]Observation{
			"k8s://cluster-a/payments/sa/worker": {Policy: PolicyState{Complete: true}, ResolvedIdentifiers: resolved},
		}}},
		Investigator: fakeInvestigator{},
	}
	return plan, ports
}

// TestCollectLiveOnlyPodIdentityAssociationGapWithoutDeclaration reproduces
// the required coverage: a live-observed EKS Pod Identity association with
// no corresponding ACK PodIdentityAssociation object among the collected
// manifests is recorded as a "live-only" gap, never silently absorbed and
// never treated as drift or excess (a posture decision this package no
// longer makes).
func TestCollectLiveOnlyPodIdentityAssociationGapWithoutDeclaration(t *testing.T) {
	roleARN := "arn:aws:iam::111111111111:role/ack/cluster-a/cluster-a-payments-worker"
	plan, ports := collectionPodIdentityPorts(roleARN)

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	evidence := collectionFindEvidence(t, result, "payments-api")
	if evidence.Principal.ID != roleARN {
		t.Fatalf("expected the cohort to alias onto the live-resolved role, got principal %+v", evidence.Principal)
	}
	var sawGap bool
	for _, g := range evidence.Gaps {
		if g.Code == "cloud_identity.ack_declaration.live_only_pod_identity_association" {
			sawGap = true
		}
	}
	if !sawGap {
		t.Fatalf("expected a live_only_pod_identity_association gap, got %+v", evidence.Gaps)
	}
}

// TestCollectNoLiveOnlyPodIdentityAssociationGapWhenDeclared is the
// positive control: the same live association, but with a matching ACK
// PodIdentityAssociation object among the rendered manifests, produces no
// live-only gap.
func TestCollectNoLiveOnlyPodIdentityAssociationGapWhenDeclared(t *testing.T) {
	roleARN := "arn:aws:iam::111111111111:role/ack/cluster-a/cluster-a-payments-worker"
	pia := ackManifest(ackEKSAPIGroup+"/v1alpha1", "PodIdentityAssociation", map[string]any{
		"clusterName":    "cluster-a",
		"namespace":      "payments",
		"serviceAccount": "worker",
		"roleARN":        roleARN,
	}, "worker-pia", "payments")
	plan, ports := collectionPodIdentityPorts(roleARN, pia)

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	evidence := collectionFindEvidence(t, result, "payments-api")
	for _, g := range evidence.Gaps {
		if g.Code == "cloud_identity.ack_declaration.live_only_pod_identity_association" {
			t.Fatalf("expected no live_only_pod_identity_association gap when a matching PodIdentityAssociation is declared, got %+v", evidence.Gaps)
		}
	}
}
