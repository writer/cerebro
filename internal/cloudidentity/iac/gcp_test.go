package iac

import (
	"context"
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// TestReadDeclarationsCapturesFullPoolProviderIdentity reproduces review
// finding #2e/Contract A.6: a declared
// google_iam_workload_identity_pool_provider's captured fact must carry
// its full identity (project number + pool id + provider id + canonical
// name), not just a bare pool id, so collectFederatedGCPCohorts
// (internal/cloudidentity/collection.go) can select a federated GCP
// target's own declared pool by (project number, pool) rather than cross-matching a
// differently-scoped pool sharing the same short id.
func TestReadDeclarationsCapturesFullPoolProviderIdentity(t *testing.T) {
	repo := singleFileRepo(`
resource "google_service_account" "gsa" {
  project    = "example-project"
  account_id = "cell-worker"
}

resource "google_iam_workload_identity_pool_provider" "cell" {
  project                            = "example-project"
  workload_identity_pool_id          = "example-cell-eks"
  workload_identity_pool_provider_id = "eks"
  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
  oidc {
    issuer_uri = "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
  }
}
`)
	declarations, gaps, err := NewDeclarationReader(nil).ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository:          repo,
		Project:             "example-project",
		ResolvedIdentifiers: map[string]string{"gcp_project_number:example-project": "999999999999"},
	})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	var gsa *ci.Declaration
	for i := range declarations {
		if declarations[i].Principal.Provider == ci.GCP {
			gsa = &declarations[i]
		}
	}
	if gsa == nil {
		t.Fatalf("expected a declared GCP principal, got %+v", declarations)
	}
	if len(gsa.GCPWorkloadIdentityProviders) != 1 {
		t.Fatalf("expected exactly one captured provider fact, got %+v", gsa.GCPWorkloadIdentityProviders)
	}
	got := gsa.GCPWorkloadIdentityProviders[0]
	if got.ProjectNumber != "999999999999" {
		t.Fatalf("ProjectNumber = %q, want %q", got.ProjectNumber, "999999999999")
	}
	if got.PoolID != "example-cell-eks" {
		t.Fatalf("PoolID = %q, want %q", got.PoolID, "example-cell-eks")
	}
	if got.ProviderID != "eks" {
		t.Fatalf("ProviderID = %q, want %q", got.ProviderID, "eks")
	}
	wantName := "projects/999999999999/locations/global/workloadIdentityPools/example-cell-eks/providers/eks"
	if got.Name != wantName {
		t.Fatalf("Name = %q, want %q", got.Name, wantName)
	}
	if got.Issuer != "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE" {
		t.Fatalf("Issuer = %q, unexpected", got.Issuer)
	}
}

// TestReadDeclarationsPoolProviderIdentityOmittedWithoutLiveProjectNumber
// confirms an unresolved GCP project number leaves ProjectNumber/Name
// empty on the captured fact (never fabricated), while still capturing
// every statically known field.
func TestReadDeclarationsPoolProviderIdentityOmittedWithoutLiveProjectNumber(t *testing.T) {
	repo := singleFileRepo(`
resource "google_service_account" "gsa" {
  project    = "example-project"
  account_id = "cell-worker"
}

resource "google_iam_workload_identity_pool_provider" "cell" {
  project                            = "example-project"
  workload_identity_pool_id          = "example-cell-eks"
  workload_identity_pool_provider_id = "eks"
}
`)
	declarations, _, err := NewDeclarationReader(nil).ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository: repo,
		Project:    "example-project",
	})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	var gsa *ci.Declaration
	for i := range declarations {
		if declarations[i].Principal.Provider == ci.GCP {
			gsa = &declarations[i]
		}
	}
	if gsa == nil || len(gsa.GCPWorkloadIdentityProviders) != 1 {
		t.Fatalf("expected exactly one captured provider fact, got %+v", declarations)
	}
	got := gsa.GCPWorkloadIdentityProviders[0]
	if got.PoolID != "example-cell-eks" {
		t.Fatalf("PoolID = %q, want %q", got.PoolID, "example-cell-eks")
	}
	if got.ProjectNumber != "" || got.Name != "" {
		t.Fatalf("expected ProjectNumber/Name to stay empty without a live project number, got %+v", got)
	}
}
