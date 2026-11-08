package cloudidentity

import "testing"

func TestCollectionIdentifiersRejectCrossTargetAndConflictingValues(t *testing.T) {
	target := ScanTarget{Cluster: "shared-name", Environment: "production", Account: "111111111111"}
	consumer := Workload{Cluster: target.Cluster, Environment: target.Environment, CloudAccount: target.Account}
	key := "aws_eks_oidc_issuer:" + target.Cluster
	other := consumer
	other.CloudAccount = "222222222222"
	observed := []Evidence{
		{Consumers: []Workload{consumer}, ResolvedIdentifiers: map[string]string{key: "https://issuer.example/a", "aws_pod_identity_role:ksa": "arn:role:unrelated", "aws_eks_oidc_issuer:other-cluster": "https://issuer.example/other"}},
		{Consumers: []Workload{other}, ResolvedIdentifiers: map[string]string{key: "https://issuer.example/cross-account"}},
	}
	got := collectionTargetIdentifiers(observed, target)
	if len(got) != 1 || got[key] != "https://issuer.example/a" {
		t.Fatalf("live identifiers crossed their target or identifier kind: %#v", got)
	}
	observed = append(observed, Evidence{Consumers: []Workload{consumer}, ResolvedIdentifiers: map[string]string{key: "https://issuer.example/conflict"}})
	if _, ok := collectionTargetIdentifiers(observed, target)[key]; ok {
		t.Fatal("conflicting live identity was selected as a Terraform fact")
	}
}
