package cloudidentity

import "testing"

func gcpConsumer(cloudProject string) Workload {
	return Workload{ID: "w1", Service: "checkout", Namespace: "ns1", ServiceAccount: "sa1", CloudProject: cloudProject, Source: exactPin()}
}

func TestAssessGCPTrustBracketBindingMatchesPoolProject(t *testing.T) {
	e := Evidence{
		Principal:                 Principal{ID: "gsa-a", Provider: GCP},
		Consumers:                 []Workload{gcpConsumer("workload-proj")},
		ConsumerInventoryComplete: true,
		CollectedAt:               testNow,
		Investigations:            []Investigation{{ConsumerID: "w1", Source: exactPin(), Validation: validInvestigationValidation()}},
		Definitions:               Definitions{Complete: true},
		Declared: PolicyState{
			Complete: true,
			Trust: []Grant{{
				ID: "trust1", Effect: "Allow",
				Members: []string{"serviceAccount:workload-proj.svc.id.goog[ns1/sa1]"},
			}},
		},
		Observed: PolicyState{Complete: true},
	}

	ok, gaps := assessTrustCoverage(e)
	if !ok {
		t.Fatalf("expected trust coverage ok when bracket binding's pool project matches consumer CloudProject, gaps=%+v", gaps)
	}
}

func TestAssessGCPTrustBracketBindingWrongProjectIsFlagged(t *testing.T) {
	e := Evidence{
		Principal: Principal{ID: "gsa-a", Provider: GCP},
		Consumers: []Workload{gcpConsumer("workload-proj")},
		Declared: PolicyState{Trust: []Grant{{
			ID: "trust1", Effect: "Allow",
			Members: []string{"serviceAccount:some-other-proj.svc.id.goog[ns1/sa1]"},
		}}},
	}
	ok, gaps := assessTrustCoverage(e)
	if ok {
		t.Fatal("expected trust coverage to flag a binding whose pool project differs from the consumer's own CloudProject")
	}
	if !hasGapCode(gaps, "cloudidentity.unresolved_trust_consumer") {
		t.Errorf("expected unresolved_trust_consumer gap, got %+v", gaps)
	}
}

func TestAssessGCPTrustCrossProjectGSAIsLegitimateWhenPoolProjectMatches(t *testing.T) {
	// The GSA being impersonated can live in a project different from the
	// consuming GKE workload's project (legitimate cross-project Workload
	// Identity); only the pool project (which equals the GKE workload's own
	// project) is checked, never the GSA's own project.
	e := Evidence{
		Principal: Principal{ID: "gsa-in-shared-project", Provider: GCP},
		Consumers: []Workload{gcpConsumer("gke-cluster-project")},
		Declared: PolicyState{Trust: []Grant{{
			ID: "trust1", Effect: "Allow",
			// The pool project matches the consumer's own GKE project, even
			// though this principal (the GSA) itself was defined/read from a
			// different ("shared-tools") project.
			Members: []string{"serviceAccount:gke-cluster-project.svc.id.goog[ns1/sa1]"},
		}}},
	}
	ok, gaps := assessTrustCoverage(e)
	if !ok {
		t.Fatalf("cross-project GSA usage must be accepted when the pool project matches the consumer's project, gaps=%+v", gaps)
	}
}

func TestAssessGCPTrustPrincipalFormatRequiresMatchingProjectNumber(t *testing.T) {
	member := "principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/workload-proj.svc.id.goog/subject/ns/ns1/sa/sa1"

	t.Run("matchingNumberIsOK", func(t *testing.T) {
		e := Evidence{
			Principal:           Principal{ID: "gsa-a", Provider: GCP},
			Consumers:           []Workload{gcpConsumer("workload-proj")},
			ResolvedIdentifiers: map[string]string{"gcp_project_number:workload-proj": "123456789"},
			Declared:            PolicyState{Trust: []Grant{{ID: "trust1", Effect: "Allow", Members: []string{member}}}},
		}
		ok, gaps := assessTrustCoverage(e)
		if !ok {
			t.Fatalf("expected ok, gaps=%+v", gaps)
		}
	})

	t.Run("mismatchedNumberIsFlagged", func(t *testing.T) {
		e := Evidence{
			Principal:           Principal{ID: "gsa-a", Provider: GCP},
			Consumers:           []Workload{gcpConsumer("workload-proj")},
			ResolvedIdentifiers: map[string]string{"gcp_project_number:workload-proj": "999999999"},
			Declared:            PolicyState{Trust: []Grant{{ID: "trust1", Effect: "Allow", Members: []string{member}}}},
		}
		ok, _ := assessTrustCoverage(e)
		if ok {
			t.Fatal("expected a project-number mismatch to be flagged")
		}
	})
}

func TestAssessAWSTrustFlagsDirectAccountDelegation(t *testing.T) {
	e := Evidence{
		Principal: Principal{ID: "role-a", Provider: AWS},
		Consumers: []Workload{baseConsumer()},
		Declared: PolicyState{Trust: []Grant{{
			ID: "trust1", Effect: "Allow", Members: []string{"AWS:arn:aws:iam::222222222222:root"},
		}}},
	}
	ok, gaps := assessTrustCoverage(e)
	if ok {
		t.Fatal("a direct AWS account/root delegation is outside the reviewed Kubernetes consumer inventory and must be flagged")
	}
	if !hasGapCode(gaps, "cloudidentity.unresolved_trust_consumer") {
		t.Errorf("expected unresolved_trust_consumer gap, got %+v", gaps)
	}
}

func TestAssessTrustCoverageEmptyTrustIsOK(t *testing.T) {
	e := Evidence{Principal: Principal{ID: "role-a", Provider: AWS}}
	ok, gaps := assessTrustCoverage(e)
	if !ok || len(gaps) != 0 {
		t.Fatalf("expected ok with no gaps for empty Trust, got ok=%v gaps=%+v", ok, gaps)
	}
}

func TestAssessTrustMultiClusterSameSubjectBothResolved(t *testing.T) {
	// Two consumers share one namespace/service-account subject across
	// different clusters; each has its own exact Federated trust grant and
	// resolved provider ARN. Indexing a subject to a single Workload would
	// make the second grant's reconciliation compare against the wrong
	// consumer's cluster and spuriously flag it.
	e := Evidence{
		Principal: Principal{ID: "role-a", Provider: AWS},
		Consumers: []Workload{
			{ID: "w1", Namespace: "payments", ServiceAccount: "worker", Cluster: "cluster-a"},
			{ID: "w2", Namespace: "payments", ServiceAccount: "worker", Cluster: "cluster-b"},
		},
		Declared: PolicyState{Trust: []Grant{
			{
				ID:      "trust-a",
				Effect:  "Allow",
				Members: []string{"Federated:arn:aws:iam::111111111111:oidc-provider/oidc.eks.cluster-a.amazonaws.com/id/EX"},
				Conditions: []Condition{{
					Operator: "StringEquals", Key: "oidc.eks.cluster-a.amazonaws.com/id/EX:sub",
					Values: []string{"system:serviceaccount:payments:worker"},
				}},
			},
			{
				ID:      "trust-b",
				Effect:  "Allow",
				Members: []string{"Federated:arn:aws:iam::111111111111:oidc-provider/oidc.eks.cluster-b.amazonaws.com/id/EX"},
				Conditions: []Condition{{
					Operator: "StringEquals", Key: "oidc.eks.cluster-b.amazonaws.com/id/EX:sub",
					Values: []string{"system:serviceaccount:payments:worker"},
				}},
			},
		}},
		ResolvedIdentifiers: map[string]string{
			"aws_eks_oidc_provider_arn:cluster-a": "arn:aws:iam::111111111111:oidc-provider/oidc.eks.cluster-a.amazonaws.com/id/EX",
			"aws_eks_oidc_provider_arn:cluster-b": "arn:aws:iam::111111111111:oidc-provider/oidc.eks.cluster-b.amazonaws.com/id/EX",
		},
	}
	ok, gaps := assessTrustCoverage(e)
	if !ok {
		t.Fatalf("expected trust coverage ok for two same-subject consumers each with their own resolved cluster provider ARN, gaps=%+v", gaps)
	}
	if hasGapCode(gaps, "cloudidentity.unresolved_trust_consumer") {
		t.Errorf("unexpected unresolved_trust_consumer gap: %+v", gaps)
	}
}

func TestAssessAWSPodIdentityTrustGate(t *testing.T) {
	consumer := Workload{ID: "w1", Cluster: "cluster-a", Namespace: "payments", ServiceAccount: "worker"}
	baseGrant := Grant{ID: "trust-pi", Effect: "Allow", Members: []string{"Service:pods.eks.amazonaws.com"}}

	t.Run("restrictedWithAssociationEvidenceIsAccepted", func(t *testing.T) {
		g := baseGrant
		g.Conditions = []Condition{
			{Operator: "StringEquals", Key: "aws:RequestTag/eks-cluster-name", Values: []string{"cluster-a"}},
			{Operator: "StringEquals", Key: "aws:RequestTag/kubernetes-namespace", Values: []string{"payments"}},
			{Operator: "StringEquals", Key: "aws:RequestTag/kubernetes-service-account", Values: []string{"worker"}},
		}
		e := Evidence{
			Principal: Principal{ID: "arn:aws:iam::111111111111:role/pi-role", Provider: AWS},
			Consumers: []Workload{consumer},
			Observed:  PolicyState{Trust: []Grant{g}},
			ResolvedIdentifiers: map[string]string{
				"aws_pod_identity_role:k8s://cluster-a/payments/sa/worker": "arn:aws:iam::111111111111:role/pi-role",
			},
		}
		ok, gaps := assessTrustCoverage(e)
		if !ok {
			t.Fatalf("expected Pod Identity trust accepted with matching association evidence and session-tag restriction, gaps=%+v", gaps)
		}
	})

	t.Run("unrestrictedIsFlagged", func(t *testing.T) {
		e := Evidence{
			Principal: Principal{ID: "arn:aws:iam::111111111111:role/pi-role", Provider: AWS},
			Consumers: []Workload{consumer},
			Observed:  PolicyState{Trust: []Grant{baseGrant}},
		}
		ok, gaps := assessTrustCoverage(e)
		if ok {
			t.Fatal("expected unrestricted Pod Identity trust (no session-tag conditions) to be flagged")
		}
		if !hasGapCode(gaps, "cloudidentity.unresolved_trust_consumer") {
			t.Errorf("expected unresolved_trust_consumer gap, got %+v", gaps)
		}
	})
}

func TestAssessGCPTrustRoleClassification(t *testing.T) {
	consumer := Workload{ID: "w1", Namespace: "ns1", ServiceAccount: "sa1", CloudProject: "workload-proj"}
	defs := Definitions{Roles: []RoleDefinition{
		{Name: "roles/iam.serviceAccountViewer", Permissions: []string{"iam.serviceAccounts.get", "iam.serviceAccounts.list"}},
		{Name: "roles/iam.workloadIdentityUser", Permissions: []string{"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken"}},
	}}

	t.Run("viewerOnlyRoleIsNeitherTrustNorLinkage", func(t *testing.T) {
		e := Evidence{
			Principal: Principal{ID: "gsa-a", Provider: GCP},
			Consumers: []Workload{consumer},
			Observed: PolicyState{Trust: []Grant{{
				ID: "trust1", Effect: "Allow", Role: "roles/iam.serviceAccountViewer",
				Members: []string{"serviceAccount:workload-proj.svc.id.goog[ns1/sa1]"},
			}}},
			Definitions: defs,
		}
		ok, gaps := assessTrustCoverage(e)
		if !ok {
			t.Fatalf("a known non-capable (viewer-only) role must be ignored by the trust gate, not flagged, gaps=%+v", gaps)
		}
		if linked := linkedConsumers(e); linked["w1"] {
			t.Error("a viewer-only role binding must not count as consumer linkage")
		}
	})

	t.Run("workloadIdentityUserBindingLinks", func(t *testing.T) {
		e := Evidence{
			Principal: Principal{ID: "gsa-a", Provider: GCP},
			Consumers: []Workload{consumer},
			Observed: PolicyState{Trust: []Grant{{
				ID: "trust1", Effect: "Allow", Role: "roles/iam.workloadIdentityUser",
				Members: []string{"serviceAccount:workload-proj.svc.id.goog[ns1/sa1]"},
			}}},
			Definitions: defs,
		}
		ok, gaps := assessTrustCoverage(e)
		if !ok {
			t.Fatalf("expected workloadIdentityUser binding accepted, gaps=%+v", gaps)
		}
		if linked := linkedConsumers(e); !linked["w1"] {
			t.Error("a workloadIdentityUser binding to the exact consumer KSA must link it")
		}
	})
}

// TestLinkedConsumersAWSPodIdentityRequiresTrustStatement reproduces the
// reviewed defect: EKS Pod Identity association evidence
// (ResolvedIdentifiers "aws_pod_identity_role:<subject>") cannot mint
// credentials on its own -- it must never positively link a consumer
// without a corresponding Observed.Trust Allow statement for
// Service:pods.eks.amazonaws.com whose actions actually cover
// sts:AssumeRole and sts:TagSession.
func TestLinkedConsumersAWSPodIdentityRequiresTrustStatement(t *testing.T) {
	consumer := Workload{ID: "w1", Cluster: "cluster-a", Namespace: "payments", ServiceAccount: "worker"}
	roleID := "arn:aws:iam::111111111111:role/pi-role"
	resolved := map[string]string{"aws_pod_identity_role:k8s://cluster-a/payments/sa/worker": roleID}

	t.Run("associationWithoutTrustStatementDoesNotLink", func(t *testing.T) {
		e := Evidence{
			Principal:           Principal{ID: roleID, Provider: AWS},
			Consumers:           []Workload{consumer},
			Observed:            PolicyState{Complete: true},
			ResolvedIdentifiers: resolved,
		}
		if linked := linkedConsumers(e); linked["w1"] {
			t.Error("Pod Identity association evidence without an Observed.Trust pods.eks.amazonaws.com statement must never positively link a consumer")
		}
	})

	t.Run("associationWithAssumeRoleTagSessionStatementLinks", func(t *testing.T) {
		e := Evidence{
			Principal: Principal{ID: roleID, Provider: AWS},
			Consumers: []Workload{consumer},
			Observed: PolicyState{Complete: true, Trust: []Grant{{
				Effect:  "Allow",
				Actions: []string{"sts:AssumeRole", "sts:TagSession"},
				Members: []string{"Service:pods.eks.amazonaws.com"},
				Conditions: []Condition{
					{Operator: "StringEquals", Key: "aws:RequestTag/eks-cluster-name", Values: []string{"cluster-a"}},
					{Operator: "StringEquals", Key: "aws:RequestTag/kubernetes-namespace", Values: []string{"payments"}},
					{Operator: "StringEquals", Key: "aws:RequestTag/kubernetes-service-account", Values: []string{"worker"}},
				},
			}}},
			ResolvedIdentifiers: resolved,
		}
		if linked := linkedConsumers(e); !linked["w1"] {
			t.Error("association evidence plus a qualifying AssumeRole/TagSession Pod Identity statement must link the consumer")
		}
	})
}
