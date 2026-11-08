package sourceprojection

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/cloudidentity"
)

// TestCloudIdentityPrincipalEvidenceProjectionsGCPNonImpersonationRoleNeverYieldsCanImpersonate
// reproduces review finding #3: a custom role whose name merely CONTAINS
// "workloadIdentityUser" (here "roles/workloadIdentityUserViewer", a
// resolved, non-impersonation-capable viewer role) together with a member
// that exactly names the consumer's Kubernetes Workload Identity
// Federation subject must never produce a can_impersonate edge -- only a
// resolved role that actually grants an impersonation permission
// (gcpGrantIsTrustCapable, internal/cloudidentity) may.
func TestCloudIdentityPrincipalEvidenceProjectionsGCPNonImpersonationRoleNeverYieldsCanImpersonate(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	principal := cloudidentity.Principal{ID: "payments-sa@writer-prod.iam.gserviceaccount.com", Provider: cloudidentity.GCP, Kind: "gcp_service_account", Project: "writer-prod"}
	consumer := cloudidentity.Workload{
		ID: "payments/api", Service: "payments-api", Cluster: "prod-gke", Namespace: "payments",
		Name: "api", Kind: "Deployment", ServiceAccount: "api", CloudProject: "writer-prod",
		Source: cloudidentity.SourcePin{Repository: "example-org/payments", Revision: "abcdef1", Exact: true},
	}
	evidence := cloudidentity.Evidence{
		Schema: cloudidentity.SchemaVersion, Principal: principal, Scope: principal.ID,
		Consumers: []cloudidentity.Workload{consumer}, ConsumerInventoryComplete: true,
		Declared: cloudidentity.PolicyState{Complete: true},
		Observed: cloudidentity.PolicyState{
			Complete: true,
			Trust: []cloudidentity.Grant{{
				ID: "trust-1", Effect: "Allow", Role: "roles/workloadIdentityUserViewer",
				Members: []string{"serviceAccount:writer-prod.svc.id.goog[payments/api]"},
			}},
		},
		// The role resolves to a definition with NO impersonation
		// permission: a bare role-name substring match on
		// "workloadIdentityUser" would incorrectly admit this.
		Definitions: cloudidentity.Definitions{
			Complete: true,
			Roles: []cloudidentity.RoleDefinition{{
				Name:        "roles/workloadIdentityUserViewer",
				Permissions: []string{"iam.serviceAccounts.get", "iam.serviceAccounts.list"},
			}},
		},
		CollectedAt: baseTime,
	}
	event := cloudIdentityProjectionTestEvent(t, "event-gcp-false-positive", "writer", evidence)

	entities, links, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	wantPrincipalURN := identityPrincipalURN("writer", "gcp", "service_account", principal.ID, "")
	serviceAccount := findEntity(entities, "kubernetes.service_account")
	if serviceAccount == nil {
		t.Fatalf("missing kubernetes.service_account entity; got %v", entityTypes(entities))
	}
	if findLink(links, serviceAccount.URN, wantPrincipalURN, relationCanImpersonate) != nil {
		t.Fatal("a non-impersonation-capable role sharing the \"workloadIdentityUser\" substring must never yield can_impersonate")
	}
	link := findLink(links, serviceAccount.URN, wantPrincipalURN, relationAssociatedWith)
	if link == nil {
		t.Fatal("expected associated_with instead, since no live impersonation-capable binding was confirmed")
	}
	if link.Attributes["verified"] != "false" {
		t.Fatalf("expected associated_with verified=false, got %+v", link.Attributes)
	}
}
