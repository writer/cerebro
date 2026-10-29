package cloudidentity

import (
	"testing"
	"time"
)

func TestResolvedCohortsUnionAWSRoleConsumers(t *testing.T) {
	role := Principal{ID: "arn:aws:iam::111111111111:role/workloads", Provider: AWS, Kind: "aws_iam_role", Account: "111111111111"}
	ksa := role
	ksa.ID, ksa.Kind = "k8s://cluster-a/payments/sa/worker", "aws_kubernetes_service_account"
	providerARN := "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE1111111111111111"
	trusted := PolicyState{Complete: true, Trust: []Grant{
		{
			Effect:  "Allow",
			Actions: []string{"sts:AssumeRoleWithWebIdentity"},
			Members: []string{"Federated:" + providerARN},
			Conditions: []Condition{{
				Operator: "StringEquals",
				Key:      "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE1111111111111111:sub",
				Values:   []string{"system:serviceaccount:payments:api"},
			}},
		},
		{
			Effect:  "Allow",
			Actions: []string{"sts:AssumeRole", "sts:TagSession"},
			Members: []string{"Service:pods.eks.amazonaws.com"},
			Conditions: []Condition{
				{Operator: "StringEquals", Key: "aws:RequestTag/eks-cluster-name", Values: []string{"cluster-a"}},
				{Operator: "StringEquals", Key: "aws:RequestTag/kubernetes-namespace", Values: []string{"payments"}},
				{Operator: "StringEquals", Key: "aws:RequestTag/kubernetes-service-account", Values: []string{"worker"}},
			},
		},
	}}
	first := Evidence{
		Principal:                 role,
		ConsumerInventoryComplete: true,
		Consumers:                 []Workload{{ID: "api", Service: "api", Cluster: "cluster-a", Namespace: "payments", ServiceAccount: "api", Principals: []Principal{role}}},
		Observed:                  trusted,
		Definitions:               Definitions{Complete: true},
		ResolvedIdentifiers:       map[string]string{"aws_eks_oidc_provider_arn:cluster-a": providerARN},
	}
	second := Evidence{
		Principal:                 ksa,
		ConsumerInventoryComplete: true,
		Consumers:                 []Workload{{ID: "worker", Service: "worker", Cluster: "cluster-a", Namespace: "payments", ServiceAccount: "worker", Principals: []Principal{ksa}}},
		Observed:                  trusted,
		Definitions:               Definitions{Complete: true},
		ResolvedIdentifiers:       map[string]string{"aws_pod_identity_role:" + ksa.ID: role.ID},
	}
	cohorts := collectionResolvedCohorts([]Evidence{first, second})
	if len(cohorts) != 1 || cohorts[0].Principal != role {
		t.Fatalf("alias did not converge to owning role: %#v", cohorts)
	}
	sharing := AssessSharing(cohorts[0])
	if sharing.Status != Supported {
		t.Fatalf("distinct consumers of the resolved role were not shared: %#v", sharing)
	}
	for _, workload := range cohorts[0].Consumers {
		if len(workload.Principals) != 1 || workload.Principals[0] != role {
			t.Fatalf("consumer retained a cluster-local alias: %#v", workload)
		}
	}
	cohorts[0].Consumers[1].Service = "api"
	if sharing := AssessSharing(cohorts[0]); sharing.Status != Clear {
		t.Fatalf("replicas of one application were classified as shared: %#v", sharing)
	}
}

func TestResolvedCohortsUnionGCPIdentityAcrossClusters(t *testing.T) {
	canonical := "principal://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/example-project.svc.id.goog/subject/ns/apps/sa/default"
	cohorts := []Evidence{}
	for _, cluster := range []string{"cluster-a", "cluster-b"} {
		principal := Principal{ID: "k8s://" + cluster + "/apps/sa/default", Kind: "gcp_kubernetes_service_account", Provider: GCP, Project: "example-project"}
		cohorts = append(cohorts, Evidence{Principal: principal, ConsumerInventoryComplete: true, Consumers: []Workload{{ID: cluster, Service: cluster, Cluster: cluster, Namespace: "apps", ServiceAccount: "default", Principals: []Principal{principal}}}, Observed: PolicyState{Complete: true}, Definitions: Definitions{Complete: true}, ResolvedIdentifiers: map[string]string{"project_number": "111111111111", "gcp_ksa_principal:" + principal.ID: canonical}})
	}
	resolved := collectionResolvedCohorts(cohorts)
	if len(resolved) != 1 || resolved[0].Principal.ID != canonical || !resolved[0].ConsumerInventoryComplete {
		t.Fatalf("shared workload pool identity did not converge: %#v", resolved)
	}
	if sharing := AssessSharing(resolved[0]); sharing.Status != Supported {
		t.Fatalf("cross-cluster identity sharing lost: %#v", sharing)
	}
}

func TestConflictingObservationsCannotBecomeCompleteCohort(t *testing.T) {
	principal := Principal{ID: "arn:aws:iam::111111111111:role/workloads", Provider: AWS, Kind: "aws_iam_role", Account: "111111111111"}
	first := Evidence{Principal: principal, ConsumerInventoryComplete: true, Observed: PolicyState{Complete: true, ObservedAt: time.Unix(100, 0), Grants: []Grant{{Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"*"}}}}, Definitions: Definitions{Complete: true}}
	second := first
	second.Observed.Grants = []Grant{{Effect: "Allow", Actions: []string{"s3:PutObject"}, Resources: []string{"*"}}}
	resolved := collectionResolvedCohorts([]Evidence{first, second})
	if len(resolved) != 1 || resolved[0].Observed.Complete {
		t.Fatalf("disagreeing observations became authoritative: %#v", resolved)
	}
	found := false
	for _, gap := range resolved[0].Observed.Gaps {
		found = found || gap.Code == "observed_policy_conflict"
	}
	if !found {
		t.Fatalf("policy conflict was not attributed: %#v", resolved[0].Observed.Gaps)
	}
}

func TestConflictingConsumerDeclarationsBlockEveryAffectedPrincipal(t *testing.T) {
	first := Principal{ID: "arn:aws:iam::111111111111:role/api", Provider: AWS}
	second := Principal{ID: "arn:aws:iam::111111111111:role/worker", Provider: AWS}
	workloads := []Workload{
		{ID: "cluster/apps/api", Service: "api", Image: "example/api@sha256:abc", Principals: []Principal{first}},
		{ID: "cluster/apps/api", Service: "api", Image: "example/api@sha256:def", Principals: []Principal{second}},
	}
	cohorts := collectionCohorts(workloads)
	for _, principal := range []Principal{first, second} {
		cohort := cohorts[collectionPrincipalKey(principal)]
		if cohort.ConsumerInventoryComplete || len(cohort.Gaps) != 1 || cohort.Gaps[0].Code != "consumer_declaration_conflict" {
			t.Fatalf("ambiguous consumer became complete for %s: %#v", principal.ID, cohort)
		}
	}
}
