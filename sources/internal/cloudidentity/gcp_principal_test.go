package cloudidentitysource

import "testing"

func TestGCPProjectFromServiceAccountEmail(t *testing.T) {
	project, ok := gcpProjectFromServiceAccountEmail("deploy@my-project.iam.gserviceaccount.com")
	if !ok || project != "my-project" {
		t.Fatalf("project = %q, ok = %v, want my-project/true", project, ok)
	}
	if _, ok := gcpProjectFromServiceAccountEmail("not-a-service-account@gmail.com"); ok {
		t.Fatal("accepted a non-GSA email")
	}
	if _, ok := gcpProjectFromServiceAccountEmail(""); ok {
		t.Fatal("accepted an empty email")
	}
}

func TestGCPParseKSAIdentity(t *testing.T) {
	identity, ok := gcpParseKSAIdentity("k8s://cluster-a/payments/sa/worker")
	if !ok {
		t.Fatal("failed to parse a well-formed KSA identity")
	}
	if identity.Cluster != "cluster-a" || identity.Namespace != "payments" || identity.ServiceAccount != "worker" {
		t.Fatalf("identity = %+v, want cluster-a/payments/worker", identity)
	}
	for _, bad := range []string{"", "k8s://cluster-a/payments/worker", "ns/payments/sa/worker", "k8s://cluster-a//sa/worker"} {
		if _, ok := gcpParseKSAIdentity(bad); ok {
			t.Fatalf("accepted malformed KSA identity %q", bad)
		}
	}
}

func TestGCPKSAApplicableMembersMatchesDocumentedGKEForms(t *testing.T) {
	candidates := gcpKSAApplicableMembers("111", "my-project", "payments", "worker")
	want := map[string]string{
		"principal://iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/my-project.svc.id.goog/subject/ns/payments/sa/worker": "exact",
		"serviceAccount:my-project.svc.id.goog[payments/worker]":                                                                                  "exact",
		"principalSet://iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/my-project.svc.id.goog/namespace/payments":         "namespace",
		"principalSet://iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/my-project.svc.id.goog/*":                          "pool",
	}
	if len(candidates) != len(want) {
		t.Fatalf("len(candidates) = %d, want %d", len(candidates), len(want))
	}
	for _, candidate := range candidates {
		level, ok := want[candidate.Member]
		if !ok {
			t.Fatalf("unexpected candidate member %q", candidate.Member)
		}
		if level != candidate.Specificity {
			t.Fatalf("specificity for %q = %q, want %q", candidate.Member, candidate.Specificity, level)
		}
	}
}

func TestGCPMatchingMembersExcludesUnrelatedNamespace(t *testing.T) {
	candidates := gcpKSAApplicableMembers("111", "my-project", "payments", "worker")
	matched, specificity := gcpMatchingMembers([]string{
		"principalSet://iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/my-project.svc.id.goog/namespace/checkout",
	}, candidates)
	if len(matched) != 0 || specificity != "" {
		t.Fatalf("matched = %v, specificity = %q, want no match for an unrelated namespace", matched, specificity)
	}

	matched, specificity = gcpMatchingMembers([]string{
		"principalSet://iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/my-project.svc.id.goog/namespace/payments",
	}, candidates)
	if len(matched) != 1 || specificity != "namespace" {
		t.Fatalf("matched = %v, specificity = %q, want one namespace match", matched, specificity)
	}
}

func TestGCPCanonicalKSAPrincipalParseAndBuildSymmetry(t *testing.T) {
	canonical := gcpCanonicalKSAURI("111", "my-project", "payments", "worker")
	want := "principal://iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/my-project.svc.id.goog/subject/ns/payments/sa/worker"
	if canonical != want {
		t.Fatalf("gcpCanonicalKSAURI() = %q, want %q", canonical, want)
	}
	projectNumber, projectID, namespace, serviceAccount, ok := gcpParseCanonicalKSAPrincipal(canonical)
	if !ok || projectNumber != "111" || projectID != "my-project" || namespace != "payments" || serviceAccount != "worker" {
		t.Fatalf("gcpParseCanonicalKSAPrincipal(%q) = (%q,%q,%q,%q,%v), want (111,my-project,payments,worker,true)", canonical, projectNumber, projectID, namespace, serviceAccount, ok)
	}
	for _, bad := range []string{"", "k8s://cluster-a/payments/sa/worker", "principalSet://iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/my-project.svc.id.goog/namespace/payments"} {
		if _, _, _, _, ok := gcpParseCanonicalKSAPrincipal(bad); ok {
			t.Fatalf("accepted non-canonical input %q", bad)
		}
	}
}

func TestGCPResolvableProjectIDRejectsPlaceholders(t *testing.T) {
	for _, bad := range []string{"", "${project_id}", "PROJECT_ID", "project-id", "<project>", "a"} {
		if gcpResolvableProjectID(bad) {
			t.Fatalf("accepted placeholder/invalid project id %q", bad)
		}
	}
	if !gcpResolvableProjectID("my-real-project-123") {
		t.Fatal("rejected a syntactically valid project id")
	}
}

func TestGCPKSAClusterScopedMemberAndHierarchyPrincipalSets(t *testing.T) {
	cluster := gcpKSAClusterScopedMember("111", "my-project", "us-central1", "cluster-a")
	want := "principalSet://iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/my-project.svc.id.goog/kubernetes.cluster/https://container.googleapis.com/v1/projects/my-project/locations/us-central1/clusters/cluster-a"
	if cluster != want {
		t.Fatalf("gcpKSAClusterScopedMember() = %q, want %q", cluster, want)
	}

	candidates := gcpHierarchyServiceAccountPrincipalSets([]gcpAncestor{
		{ResourceID: struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}{ID: "111", Type: "project"}},
		{ResourceID: struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}{ID: "999", Type: "folder"}},
		{ResourceID: struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}{ID: "123", Type: "organization"}},
		{ResourceID: struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}{ID: "unknown", Type: "bogus"}},
	})
	wantMembers := map[string]bool{
		"principalSet://cloudresourcemanager.googleapis.com/projects/111/type/ServiceAccount":      true,
		"principalSet://cloudresourcemanager.googleapis.com/folders/999/type/ServiceAccount":       true,
		"principalSet://cloudresourcemanager.googleapis.com/organizations/123/type/ServiceAccount": true,
	}
	if len(candidates) != len(wantMembers) {
		t.Fatalf("len(candidates) = %d, want %d (unrecognized ancestor type must be skipped, not guessed)", len(candidates), len(wantMembers))
	}
	for _, candidate := range candidates {
		if !wantMembers[candidate.Member] || candidate.Specificity != "hierarchy" {
			t.Fatalf("unexpected hierarchy candidate %+v", candidate)
		}
	}
}

func TestGCPKSAMemberCouldApply(t *testing.T) {
	base := "iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/my-project.svc.id.goog"
	cases := []struct {
		name         string
		member       string
		clusterKnown bool
		cluster      string
		want         bool
	}{
		{"different namespace subject never applies", "principal://" + base + "/subject/ns/checkout/sa/worker", true, "cluster-a", false},
		{"legacy form for a different service account never applies", "serviceAccount:my-project.svc.id.goog[payments/other]", true, "cluster-a", false},
		{"different namespace principalSet never applies", "principalSet://" + base + "/namespace/checkout", true, "cluster-a", false},
		{"cluster-scoped set for a different cluster never applies", "principalSet://" + base + "/kubernetes.cluster/https://container.googleapis.com/v1/projects/my-project/locations/us-central1/clusters/cluster-b", true, "cluster-a", false},
		{"cluster-scoped set for an unknown cluster location must be flagged", "principalSet://" + base + "/kubernetes.cluster/https://container.googleapis.com/v1/projects/my-project/locations/us-central1/clusters/cluster-a", false, "", true},
		{"undocumented pool-scoped form must be flagged", "principalSet://" + base + "/group/undocumented", true, "cluster-a", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := gcpKSAMemberCouldApply(tc.member, "payments", "worker", tc.clusterKnown, tc.cluster)
			if got != tc.want {
				t.Fatalf("gcpKSAMemberCouldApply(%q) = %v, want %v", tc.member, got, tc.want)
			}
		})
	}
}
