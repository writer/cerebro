package cloudidentity

import "testing"

// sharingProviderARN/sharingTrust/sharingResolvedIdentifiers provide a
// single AWS IRSA Federated trust grant (exact subject
// "system:serviceaccount:ns1:sa1" on "cluster1") plus its resolved OIDC
// provider ARN, so every test consumer sharing that namespace/service
// account/cluster is positively linked per the consumer-linkage contract
// (AssessSharing only counts linked consumers toward Supported/Clear).
const sharingProviderARN = "arn:aws:iam::111111111111:oidc-provider/oidc.eks.cluster1.amazonaws.com/id/EXAMPLE"

func sharingLinkedTrust() PolicyState {
	return PolicyState{Complete: true, Trust: []Grant{{
		ID:      "trust1",
		Effect:  "Allow",
		Actions: []string{"sts:AssumeRoleWithWebIdentity"},
		Members: []string{"Federated:" + sharingProviderARN},
		Conditions: []Condition{{
			Operator: "StringEquals",
			Key:      "oidc.eks.cluster1.amazonaws.com:sub",
			Values:   []string{"system:serviceaccount:ns1:sa1"},
		}},
	}}}
}

func sharingResolvedIdentifiers() map[string]string {
	return map[string]string{"aws_eks_oidc_provider_arn:cluster1": sharingProviderARN}
}

func consumerWorkload(id, service, name string) Workload {
	return Workload{ID: id, Service: service, Name: name, Namespace: "ns1", ServiceAccount: "sa1", Cluster: "cluster1", Kind: "Deployment"}
}

func TestAssessSharingReplicasOfOneServiceAreClear(t *testing.T) {
	e := Evidence{
		Principal: Principal{ID: "role-a", Provider: AWS},
		Consumers: []Workload{
			consumerWorkload("w1", "checkout", "checkout-7d9f"),
			consumerWorkload("w2", "checkout", "checkout-7d9f-replica2"),
			consumerWorkload("w3", "checkout", "checkout-cronjob"),
		},
		ConsumerInventoryComplete: true,
		Observed:                  sharingLinkedTrust(),
		ResolvedIdentifiers:       sharingResolvedIdentifiers(),
	}
	s := AssessSharing(e)
	if s.Status != Clear {
		t.Fatalf("Status = %v, want Clear for replicas of one service; gaps=%+v", s.Status, s.Gaps)
	}
	if len(s.Services) != 1 || s.Services[0] != "checkout" {
		t.Errorf("Services = %v", s.Services)
	}
}

func TestAssessSharingDistinctServicesAreSupportedEvenWithIncompleteInventory(t *testing.T) {
	e := Evidence{
		Principal: Principal{ID: "role-a", Provider: AWS},
		Consumers: []Workload{
			consumerWorkload("w1", "checkout", "checkout-1"),
			consumerWorkload("w2", "billing", "billing-1"),
		},
		// Positive evidence of >=2 distinct services is monotonic: an
		// incomplete inventory elsewhere must not block Supported.
		ConsumerInventoryComplete: false,
		Observed:                  sharingLinkedTrust(),
		ResolvedIdentifiers:       sharingResolvedIdentifiers(),
	}
	s := AssessSharing(e)
	if s.Status != Supported {
		t.Fatalf("Status = %v, want Supported for 2 distinct services even with incomplete inventory; gaps=%+v", s.Status, s.Gaps)
	}
	if len(s.Services) != 2 {
		t.Errorf("Services = %v, want 2 distinct services", s.Services)
	}
	if len(s.ConsumerIDs) != 2 {
		t.Errorf("ConsumerIDs = %v", s.ConsumerIDs)
	}
}

func TestAssessSharingOneServiceIncompleteInventoryIsIncomplete(t *testing.T) {
	e := Evidence{
		Principal:                 Principal{ID: "role-a", Provider: AWS},
		Consumers:                 []Workload{consumerWorkload("w1", "checkout", "checkout-1")},
		ConsumerInventoryComplete: false,
		Observed:                  sharingLinkedTrust(),
		ResolvedIdentifiers:       sharingResolvedIdentifiers(),
	}
	s := AssessSharing(e)
	if s.Status != Incomplete {
		t.Fatalf("Status = %v, want Incomplete: a single known service with an incomplete inventory cannot prove no sharing", s.Status)
	}
}

func TestAssessSharingNoConsumersCompleteInventoryIsClear(t *testing.T) {
	e := Evidence{Principal: Principal{ID: "role-a"}, ConsumerInventoryComplete: true}
	s := AssessSharing(e)
	if s.Status != Clear {
		t.Fatalf("Status = %v, want Clear for zero consumers with a confirmed-complete inventory", s.Status)
	}
}

func TestAssessSharingNoConsumersIncompleteInventoryIsIncomplete(t *testing.T) {
	e := Evidence{Principal: Principal{ID: "role-a"}, ConsumerInventoryComplete: false}
	s := AssessSharing(e)
	if s.Status != Incomplete {
		t.Fatalf("Status = %v, want Incomplete for zero observed consumers with an unconfirmed inventory", s.Status)
	}
}

func TestAssessSharingUnclassifiedWorkloadDoesNotBlockAlreadyProvenSharing(t *testing.T) {
	e := Evidence{
		Principal: Principal{ID: "role-a", Provider: AWS},
		Consumers: []Workload{
			consumerWorkload("w1", "checkout", "checkout-1"),
			consumerWorkload("w2", "billing", "billing-1"),
			{ID: "w3", Service: "", Namespace: "ns1", ServiceAccount: "sa1", Cluster: "cluster1", Name: "mystery"},
		},
		ConsumerInventoryComplete: true,
		Observed:                  sharingLinkedTrust(),
		ResolvedIdentifiers:       sharingResolvedIdentifiers(),
	}
	s := AssessSharing(e)
	if s.Status != Supported {
		t.Fatalf("Status = %v, want Supported: 2 named distinct services already proves sharing regardless of one unclassified workload; gaps=%+v", s.Status, s.Gaps)
	}
	if !hasGapCode(s.Gaps, "cloudidentity.unclassified_workload_service") {
		t.Errorf("expected unclassified workload gap, got %+v", s.Gaps)
	}
}

func TestAssessSharingDifferingKindsSameServiceAreNotSharing(t *testing.T) {
	e := Evidence{
		Principal: Principal{ID: "role-a", Provider: AWS},
		Consumers: []Workload{
			{ID: "w1", Service: "checkout", Kind: "Deployment", Namespace: "ns1", ServiceAccount: "sa1", Cluster: "cluster1", Name: "checkout-api"},
			{ID: "w2", Service: "checkout", Kind: "CronJob", Namespace: "ns1", ServiceAccount: "sa1", Cluster: "cluster1", Name: "checkout-reconciler"},
		},
		ConsumerInventoryComplete: true,
		Observed:                  sharingLinkedTrust(),
		ResolvedIdentifiers:       sharingResolvedIdentifiers(),
	}
	s := AssessSharing(e)
	if s.Status != Clear {
		t.Fatalf("Status = %v, want Clear: different Kinds of the same logical Service are not sharing participants; gaps=%+v", s.Status, s.Gaps)
	}
}

func TestAssessSharingUnlinkedConsumerBlocksSupported(t *testing.T) {
	// Two distinct services exist in the inventory, but only one consumer
	// has a positively verified observed-trust linkage; the unlinked
	// consumer must not count toward sharing.
	e := Evidence{
		Principal: Principal{ID: "role-a", Provider: AWS},
		Consumers: []Workload{
			consumerWorkload("w1", "checkout", "checkout-1"),
			{ID: "w2", Service: "billing", Namespace: "ns2", ServiceAccount: "sa2", Cluster: "cluster1", Kind: "Deployment", Name: "billing-1"},
		},
		ConsumerInventoryComplete: true,
		Observed:                  sharingLinkedTrust(),
		ResolvedIdentifiers:       sharingResolvedIdentifiers(),
	}
	s := AssessSharing(e)
	if s.Status == Supported {
		t.Fatalf("Status = %v, want not Supported: the billing consumer has no verified trust linkage", s.Status)
	}
	if !hasGapCode(s.Gaps, "cloudidentity.unverified_consumer_linkage") {
		t.Errorf("expected unverified_consumer_linkage gap for the unlinked consumer, got %+v", s.Gaps)
	}
}

// TestAssessSharingObservedIncompleteBlocksClear reproduces the reviewed
// counterexample: a single, fully linked service with Observed.Complete
// false must never read as Clear -- the live trust surface itself has not
// been confirmed complete, so an unseen second service could still be
// positively linked once observation finishes.
func TestAssessSharingObservedIncompleteBlocksClear(t *testing.T) {
	observed := sharingLinkedTrust()
	observed.Complete = false
	e := Evidence{
		Principal:                 Principal{ID: "role-a", Provider: AWS},
		Consumers:                 []Workload{consumerWorkload("w1", "checkout", "checkout-1")},
		ConsumerInventoryComplete: true,
		Observed:                  observed,
		ResolvedIdentifiers:       sharingResolvedIdentifiers(),
	}
	s := AssessSharing(e)
	if s.Status == Clear {
		t.Fatalf("Status = %v, want not Clear: Observed.Complete=false must block Clear even with one fully linked service", s.Status)
	}
}

// TestAssessSharingGCPCELFalseBindingDoesNotLink reproduces the reviewed
// counterexample: a GCP binding conditioned on CEL literal "false" must
// never positively link its consumer (it is inert and grants nothing), so
// 2 services must not read as Supported when only 1 consumer is actually
// linked.
func TestAssessSharingGCPCELFalseBindingDoesNotLink(t *testing.T) {
	const linkRole = "roles/iam.workloadIdentityUser"
	defs := Definitions{Roles: []RoleDefinition{{Name: linkRole, Permissions: []string{"iam.serviceAccounts.getAccessToken"}}}}
	e := Evidence{
		Principal: Principal{ID: "gsa-a", Provider: GCP},
		Consumers: []Workload{
			{ID: "w1", Service: "checkout", Namespace: "ns1", ServiceAccount: "sa1", CloudProject: "proj-a", Kind: "Deployment", Name: "checkout-1"},
			{ID: "w2", Service: "billing", Namespace: "ns2", ServiceAccount: "sa2", CloudProject: "proj-a", Kind: "Deployment", Name: "billing-1"},
		},
		ConsumerInventoryComplete: true,
		Observed: PolicyState{Complete: true, Trust: []Grant{
			{ID: "t1", Effect: "Allow", Role: linkRole, Members: []string{"serviceAccount:proj-a.svc.id.goog[ns1/sa1]"}},
			{ID: "t2", Effect: "Allow", Role: linkRole, Members: []string{"serviceAccount:proj-a.svc.id.goog[ns2/sa2]"}, Conditions: []Condition{{Expression: "false"}}},
		}},
		Definitions: defs,
	}
	s := AssessSharing(e)
	if s.Status == Supported {
		t.Fatalf("Status = %v, want not Supported: a CEL `false` binding must never positively link a consumer; gaps=%+v", s.Status, s.Gaps)
	}
	if !hasGapCode(s.Gaps, "cloudidentity.unverified_consumer_linkage") {
		t.Errorf("expected unverified_consumer_linkage gap for the CEL-false-bound consumer, got %+v", s.Gaps)
	}
}

// TestAssessSharingGCPUnresolvedRoleDoesNotLink reproduces the reviewed
// counterexample: a GCP binding whose role is absent from Definitions.Roles
// is conservatively possibly-capable for the excess gate, but it must never
// positively link a consumer for sharing -- its actual capability is
// unconfirmed.
func TestAssessSharingGCPUnresolvedRoleDoesNotLink(t *testing.T) {
	const linkRole = "roles/iam.workloadIdentityUser"
	defs := Definitions{Roles: []RoleDefinition{{Name: linkRole, Permissions: []string{"iam.serviceAccounts.getAccessToken"}}}}
	e := Evidence{
		Principal: Principal{ID: "gsa-a", Provider: GCP},
		Consumers: []Workload{
			{ID: "w1", Service: "checkout", Namespace: "ns1", ServiceAccount: "sa1", CloudProject: "proj-a", Kind: "Deployment", Name: "checkout-1"},
			{ID: "w2", Service: "billing", Namespace: "ns2", ServiceAccount: "sa2", CloudProject: "proj-a", Kind: "Deployment", Name: "billing-1"},
		},
		ConsumerInventoryComplete: true,
		Observed: PolicyState{Complete: true, Trust: []Grant{
			{ID: "t1", Effect: "Allow", Role: linkRole, Members: []string{"serviceAccount:proj-a.svc.id.goog[ns1/sa1]"}},
			{ID: "t2", Effect: "Allow", Role: "roles/some.unresolvedCustomRole", Members: []string{"serviceAccount:proj-a.svc.id.goog[ns2/sa2]"}},
		}},
		Definitions: defs,
	}
	s := AssessSharing(e)
	if s.Status == Supported {
		t.Fatalf("Status = %v, want not Supported: a role absent from Definitions.Roles must never positively link a consumer; gaps=%+v", s.Status, s.Gaps)
	}
	if !hasGapCode(s.Gaps, "cloudidentity.unverified_consumer_linkage") {
		t.Errorf("expected unverified_consumer_linkage gap for the unresolved-role-bound consumer, got %+v", s.Gaps)
	}
}

// TestAssessSharingAWSFederatedTagSessionOnlyDoesNotLink reproduces the
// reviewed counterexample: an AWS federated trust statement whose Actions
// permit only sts:TagSession (never sts:AssumeRoleWithWebIdentity) grants
// no assumption at all and must never positively link a consumer.
func TestAssessSharingAWSFederatedTagSessionOnlyDoesNotLink(t *testing.T) {
	e := Evidence{
		Principal: Principal{ID: "role-a", Provider: AWS},
		Consumers: []Workload{
			consumerWorkload("w1", "checkout", "checkout-1"),
			{ID: "w2", Service: "billing", Namespace: "ns2", ServiceAccount: "sa2", Cluster: "cluster1", Kind: "Deployment", Name: "billing-1"},
		},
		ConsumerInventoryComplete: true,
		Observed: PolicyState{Complete: true, Trust: []Grant{
			{
				ID: "t1", Effect: "Allow", Actions: []string{"sts:AssumeRoleWithWebIdentity"},
				Members:    []string{"Federated:" + sharingProviderARN},
				Conditions: []Condition{{Operator: "StringEquals", Key: "oidc.eks.cluster1.amazonaws.com:sub", Values: []string{"system:serviceaccount:ns1:sa1"}}},
			},
			{
				ID: "t2", Effect: "Allow", Actions: []string{"sts:TagSession"},
				Members:    []string{"Federated:" + sharingProviderARN},
				Conditions: []Condition{{Operator: "StringEquals", Key: "oidc.eks.cluster1.amazonaws.com:sub", Values: []string{"system:serviceaccount:ns2:sa2"}}},
			},
		}},
		ResolvedIdentifiers: sharingResolvedIdentifiers(),
	}
	s := AssessSharing(e)
	if s.Status == Supported {
		t.Fatalf("Status = %v, want not Supported: a TagSession-only federated statement must never positively link a consumer; gaps=%+v", s.Status, s.Gaps)
	}
	if !hasGapCode(s.Gaps, "cloudidentity.unverified_consumer_linkage") {
		t.Errorf("expected unverified_consumer_linkage gap for the TagSession-only-bound consumer, got %+v", s.Gaps)
	}
}
