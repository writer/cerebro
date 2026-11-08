package cloudidentity

import (
	"context"
	"testing"
	"time"
)

// collectionDeclaredPodIdentityPorts mirrors collectionPodIdentityPorts but
// never confirms a live EKS Pod Identity association: the Clouds reader has
// no registered entry for the KSA subject, so evidence.ResolvedIdentifiers
// carries nothing for it, exactly the "declared only, live read unavailable
// or no live association exists" scenario finding #5 covers.
func collectionDeclaredPodIdentityPorts(extraManifests ...Manifest) (ScanPlan, CollectionPorts) {
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
	ports := CollectionPorts{
		Repositories: fakeRepositoryReader{},
		Registry:     fakeRegistryReader{},
		Manifests:    fakeManifestRenderer{render: map[string][]Manifest{"cell": manifests}},
		Declarations: fakeDeclarationReader{},
		Clouds:       map[Provider]CloudReader{AWS: fakeTrustCloudReader{byPrincipal: map[string]Observation{}}},
		Investigator: fakeInvestigator{},
	}
	return plan, ports
}

// TestCollectDeclaredPodIdentityAssociationJoinsUnverifiedWithoutLiveConfirmation
// is the required coverage for finding #5: a declared ACK
// PodIdentityAssociation with no live EKS Pod Identity confirmation must
// still join the KSA cohort onto its declared role, tagged for the
// projector's unverified associated_with/basis=ack_pod_identity_association
// edge -- never a dropped relationship, and never a live-confirmed
// can_assume (no ResolvedIdentifiers entry is written).
func TestCollectDeclaredPodIdentityAssociationJoinsUnverifiedWithoutLiveConfirmation(t *testing.T) {
	roleARN := "arn:aws:iam::111111111111:role/ack/cluster-a/cluster-a-payments-worker"
	pia := ackManifest(ackEKSAPIGroup+"/v1alpha1", "PodIdentityAssociation", map[string]any{
		"clusterName":    "cluster-a",
		"namespace":      "payments",
		"serviceAccount": "worker",
		"roleARN":        roleARN,
	}, "worker-pia", "payments")
	plan, ports := collectionDeclaredPodIdentityPorts(pia)

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	evidence := collectionFindEvidence(t, result, "payments-api")
	if evidence.Principal.ID != roleARN {
		t.Fatalf("expected the cohort to alias onto the declared role, got principal %+v", evidence.Principal)
	}
	if evidence.Principal.Kind != manifestInventoryKindAWSRole {
		t.Fatalf("expected principal kind %q, got %q", manifestInventoryKindAWSRole, evidence.Principal.Kind)
	}
	if role := evidence.ResolvedIdentifiers[ackLivePodIdentityResolvedPrefix+"k8s://cluster-a/payments/sa/worker"]; role != "" {
		t.Fatalf("expected no live-resolved identifier (declaration alone must never confer can_assume), got %q", role)
	}
	var consumer *Workload
	for i := range evidence.Consumers {
		if evidence.Consumers[i].ID == "payments-api" || evidence.Consumers[i].Name == "payments-api" {
			consumer = &evidence.Consumers[i]
		}
	}
	if consumer == nil {
		// Fall back to the first (and only) consumer; collectionFindEvidence
		// already asserted the cohort was found by workload id substring.
		if len(evidence.Consumers) == 0 {
			t.Fatalf("expected at least one consumer, got none")
		}
		consumer = &evidence.Consumers[0]
	}
	if got := consumer.Configuration["identity_binding_kind"]; got != "ack_pod_identity_association" {
		t.Fatalf("expected consumer Configuration[identity_binding_kind]=ack_pod_identity_association, got %q (configuration=%+v)", got, consumer.Configuration)
	}
}

// TestCollectNoDeclaredPromotionWithoutPodIdentityDeclarationOrLiveRead is
// the negative control: no live association and no declared
// PodIdentityAssociation leaves the cohort as an unresolved bare-KSA
// principal (unchanged, pre-existing behavior) rather than inventing an
// association from nothing.
func TestCollectNoDeclaredPromotionWithoutPodIdentityDeclarationOrLiveRead(t *testing.T) {
	plan, ports := collectionDeclaredPodIdentityPorts()

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	evidence := collectionFindEvidence(t, result, "payments-api")
	if evidence.Principal.ID != "k8s://cluster-a/payments/sa/worker" {
		t.Fatalf("expected the cohort to remain an unresolved bare-KSA principal, got %+v", evidence.Principal)
	}
}
