package sourceprojection

import (
	"encoding/json"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/projectionmeta"
	cerebrourn "github.com/writer/cerebro/internal/urn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func cloudIdentityAWSTestEvidence(baseTime time.Time) cloudidentity.Evidence {
	principal := cloudidentity.Principal{
		ID:       "arn:aws:iam::222222222222:role/billing-worker",
		Provider: cloudidentity.AWS,
		Kind:     "aws_iam_role",
		Account:  "222222222222",
	}
	scope := principal.ID
	consumer := cloudidentity.Workload{
		ID:             "billing/billing-worker",
		Service:        "billing-worker",
		Environment:    "prod",
		Cluster:        "prod-use1",
		CloudAccount:   "222222222222",
		Namespace:      "billing",
		Name:           "billing-worker",
		Kind:           "Deployment",
		ServiceAccount: "billing-worker",
		Image:          "222222222222.dkr.ecr.us-east-1.amazonaws.com/billing-worker:9.9.9",
		Source: cloudidentity.SourcePin{
			Repository: "example-org/billing-worker",
			Revision:   "f6a7b8c9",
			Exact:      true,
		},
		Principals: []cloudidentity.Principal{principal},
	}
	grant := cloudidentity.Grant{
		ID:        "grant-billing",
		Effect:    "Allow",
		Actions:   []string{"dynamodb:GetItem"},
		Resources: []string{"arn:aws:dynamodb:us-east-1:222222222222:table/billing"},
		References: []cloudidentity.Reference{{
			Repository: "example-org/infra",
			Revision:   "a7b8c9d0",
			Path:       "modules/billing/iam.tf",
			StartLine:  3,
			EndLine:    9,
			Digest:     "sha256:iacdigest-billing",
		}},
	}
	return cloudidentity.Evidence{
		Schema:                    cloudidentity.SchemaVersion,
		Principal:                 principal,
		Scope:                     scope,
		Consumers:                 []cloudidentity.Workload{consumer},
		ConsumerInventoryComplete: true,
		Declared: cloudidentity.PolicyState{
			Grants:     []cloudidentity.Grant{grant},
			Complete:   true,
			ObservedAt: baseTime,
			References: grant.References,
		},
		Observed: cloudidentity.PolicyState{
			Grants:     []cloudidentity.Grant{grant},
			Complete:   true,
			ObservedAt: baseTime,
		},
		Definitions: cloudidentity.Definitions{Complete: true, Digest: "sha256:defsdigest-billing"},
		CollectedAt: baseTime,
	}
}

func cloudIdentityProjectionTestEvent(t *testing.T, id string, tenant string, evidence cloudidentity.Evidence) *cerebrov1.EventEnvelope {
	t.Helper()
	payload, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	return &cerebrov1.EventEnvelope{
		Id:       id,
		TenantId: tenant,
		SourceId: cloudidentity.SourceID,
		Kind:     cloudidentity.EventKind,
		Payload:  payload,
		Attributes: map[string]string{
			"principal_id":   evidence.Principal.ID,
			"resource_id":    evidence.Principal.ID,
			"cloud_provider": string(evidence.Principal.Provider),
			"scope":          evidence.Scope,
		},
		OccurredAt: timestamppb.New(evidence.CollectedAt),
	}
}

func entityTypes(entities []*ports.ProjectedEntity) []string {
	types := make([]string, 0, len(entities))
	for _, entity := range entities {
		types = append(types, entity.EntityType)
	}
	return types
}

func findEntity(entities []*ports.ProjectedEntity, entityType string) *ports.ProjectedEntity {
	for _, entity := range entities {
		if entity.EntityType == entityType {
			return entity
		}
	}
	return nil
}

func findLink(links []*ports.ProjectedLink, fromURN, toURN, relation string) *ports.ProjectedLink {
	for _, link := range links {
		if link.FromURN == fromURN && link.ToURN == toURN && link.Relation == relation {
			return link
		}
	}
	return nil
}

// TestCloudIdentityPrincipalEvidenceProjectionsAWSCanonicalJoinMatchesProviderProjection
// pins that this projector's canonical AWS principal URN is byte-identical
// to the URN aws_compute.go's EKS Pod Identity association projection
// already mints for the same role, and that a live Pod Identity
// association (carried in Evidence.ResolvedIdentifiers) yields can_assume.
func TestCloudIdentityPrincipalEvidenceProjectionsAWSCanonicalJoinMatchesProviderProjection(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSTestEvidence(baseTime)
	subject := "k8s://prod-use1/billing/sa/billing-worker"
	evidence.ResolvedIdentifiers = map[string]string{"aws_pod_identity_role:" + subject: evidence.Principal.ID}
	event := cloudIdentityProjectionTestEvent(t, "event-1", "writer", evidence)

	entities, links, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	for _, wantType := range []string{"kubernetes.workload", "kubernetes.service_account", cloudIdentityIACSourceEntityType} {
		if findEntity(entities, wantType) == nil {
			t.Fatalf("missing projected entity type %q; got types %v", wantType, entityTypes(entities))
		}
	}
	if findEntity(entities, "cloud_identity.principal") != nil {
		t.Fatal("projector must not create a scan-scoped cloud_identity.principal entity; VulnView owns posture, and the canonical principal is the AWS source's own entity")
	}

	wantPrincipalURN := identityPrincipalURN("writer", "aws", "role", evidence.Principal.ID, "")
	if wantPrincipalURN == "" {
		t.Fatal("identityPrincipalURN returned empty for a valid AWS role")
	}
	if got := cloudIdentityCanonicalPrincipalURN("writer", evidence.Principal); got != wantPrincipalURN {
		t.Fatalf("cloudIdentityCanonicalPrincipalURN() = %q, want %q (must match identityPrincipalURN directly, the same helper aws_compute.go uses)", got, wantPrincipalURN)
	}

	workload := findEntity(entities, "kubernetes.workload")
	serviceAccount := findEntity(entities, "kubernetes.service_account")
	iacSource := findEntity(entities, cloudIdentityIACSourceEntityType)
	if iacSource.Attributes["repository"] != "example-org/infra" || iacSource.Attributes["revision"] != "a7b8c9d0" {
		t.Fatalf("iac_source attrs = %+v, want example-org/infra@a7b8c9d0", iacSource.Attributes)
	}
	if findLink(links, workload.URN, serviceAccount.URN, relationRunsAs) == nil {
		t.Fatal("missing workload -runs_as-> service_account join")
	}
	if findLink(links, serviceAccount.URN, wantPrincipalURN, relationCanAssume) == nil {
		t.Fatal("missing service_account -can_assume-> principal join for a live EKS Pod Identity association")
	}
	if findLink(links, wantPrincipalURN, iacSource.URN, relationOwnedBy) == nil {
		t.Fatal("missing principal -owned_by-> iac_source join")
	}
}

// TestCloudIdentityPrincipalEvidenceProjectionsGCPCanonicalJoinMatchesProviderProjection
// mirrors the AWS test for GCP: the canonical principal URN must match
// identityPrincipalURN's "service_account" kind, and a live
// roles/iam.workloadIdentityUser binding -- resolved in Definitions.Roles
// with an actual impersonation permission (review finding #5: an
// unresolved role must never confirm the live edge) -- naming the exact
// consumer subject yields can_impersonate.
func TestCloudIdentityPrincipalEvidenceProjectionsGCPCanonicalJoinMatchesProviderProjection(t *testing.T) {
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
				ID: "trust-1", Effect: "Allow", Role: "roles/iam.workloadIdentityUser",
				Members: []string{"serviceAccount:writer-prod.svc.id.goog[payments/api]"},
			}},
		},
		Definitions: cloudidentity.Definitions{
			Complete: true,
			Roles: []cloudidentity.RoleDefinition{{
				Name: "roles/iam.workloadIdentityUser", Permissions: []string{"iam.serviceAccounts.getAccessToken"},
			}},
		},
		CollectedAt: baseTime,
	}
	event := cloudIdentityProjectionTestEvent(t, "event-gcp-1", "writer", evidence)

	entities, links, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	wantPrincipalURN := identityPrincipalURN("writer", "gcp", "service_account", principal.ID, "")
	if got := cloudIdentityCanonicalPrincipalURN("writer", principal); got != wantPrincipalURN {
		t.Fatalf("cloudIdentityCanonicalPrincipalURN() = %q, want %q", got, wantPrincipalURN)
	}
	serviceAccount := findEntity(entities, "kubernetes.service_account")
	if serviceAccount == nil {
		t.Fatalf("missing kubernetes.service_account entity; got %v", entityTypes(entities))
	}
	if findLink(links, serviceAccount.URN, wantPrincipalURN, relationCanImpersonate) == nil {
		t.Fatal("missing service_account -can_impersonate-> principal join for a live roles/iam.workloadIdentityUser binding")
	}
}

// TestCloudIdentityPrincipalEvidenceProjectionsWorkloadIdentityPrincipalURICanonicalJoin
// pins finding #6: a fully-qualified GCP Workload Identity Federation
// "principal://iam.googleapis.com/..." subject (kind
// gcp_workload_identity_principal, set only by collectionResolvedPrincipal
// once the collector has joined a consumer's KSA to its live federated
// identity) must canonicalize -- not be rejected -- and must land on the
// SAME graph node as the VulnView projector mints for the identical
// principal:// subject, so native evidence and imported findings never
// split into disconnected graph paths.
func TestCloudIdentityPrincipalEvidenceProjectionsWorkloadIdentityPrincipalURICanonicalJoin(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	principalURI := "principal://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/writer-prod.svc.id.goog/subject/ns/payments/sa/api"
	principal := cloudidentity.Principal{ID: principalURI, Provider: cloudidentity.GCP, Kind: "gcp_workload_identity_principal", Project: "writer-prod"}
	consumer := cloudidentity.Workload{
		ID: "payments/api", Service: "payments-api", Cluster: "prod-gke", Namespace: "payments",
		Name: "api", Kind: "Deployment", ServiceAccount: "api", CloudProject: "writer-prod",
		Source: cloudidentity.SourcePin{Repository: "example-org/payments", Revision: "abcdef1", Exact: true},
	}
	evidence := cloudidentity.Evidence{
		Schema: cloudidentity.SchemaVersion, Principal: principal, Scope: principal.ID,
		Consumers: []cloudidentity.Workload{consumer}, ConsumerInventoryComplete: true,
		Declared:    cloudidentity.PolicyState{Complete: true},
		Observed:    cloudidentity.PolicyState{Complete: true},
		Definitions: cloudidentity.Definitions{Complete: true},
		CollectedAt: baseTime,
	}
	event := cloudIdentityProjectionTestEvent(t, "event-gcp-wif-1", "writer", evidence)

	entities, _, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	if findEntity(entities, "cloud_identity.principal") != nil {
		t.Fatal("projector must not create a scan-scoped cloud_identity.principal entity")
	}

	got := cloudIdentityCanonicalPrincipalURN("writer", principal)
	if got == "" {
		t.Fatal("cloudIdentityCanonicalPrincipalURN() rejected a fully-qualified principal:// subject; only unresolved k8s:// placeholders must be rejected")
	}
	want := vulnViewCloudIdentityCanonicalPrincipalURN("writer", "gcp", principalURI)
	if want == "" {
		t.Fatal("vulnViewCloudIdentityCanonicalPrincipalURN() returned empty for a valid principal:// subject")
	}
	if got != want {
		t.Fatalf("native projector URN %q != VulnView projector URN %q for the identical principal:// subject; native evidence and imported findings must land on the same node", got, want)
	}

	// An unresolved k8s:// consumer placeholder (collector could not yet
	// join this consumer to a cloud principal) must still be rejected.
	unresolved := cloudidentity.Principal{ID: "k8s://prod-gke/payments/sa/api", Provider: cloudidentity.GCP, Kind: "gcp_kubernetes_service_account"}
	if got := cloudIdentityCanonicalPrincipalURN("writer", unresolved); got != "" {
		t.Fatalf("cloudIdentityCanonicalPrincipalURN() = %q, want empty for an unresolved k8s:// placeholder", got)
	}
}

// TestCloudIdentityPrincipalEvidenceProjectionsDeclaredOnlyNeverYieldsAccessEdge
// pins the core safety property: evidence with no observed (live) provider
// binding must never produce can_assume/can_impersonate, only
// associated_with with verified=false.
func TestCloudIdentityPrincipalEvidenceProjectionsDeclaredOnlyNeverYieldsAccessEdge(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSTestEvidence(baseTime)
	event := cloudIdentityProjectionTestEvent(t, "event-declared-only", "writer", evidence)

	entities, links, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	principalURN := identityPrincipalURN("writer", "aws", "role", evidence.Principal.ID, "")
	serviceAccount := findEntity(entities, "kubernetes.service_account")
	if serviceAccount == nil {
		t.Fatal("missing kubernetes.service_account entity")
	}
	if findLink(links, serviceAccount.URN, principalURN, relationCanAssume) != nil {
		t.Fatal("declared-only evidence must never yield a can_assume access edge")
	}
	if findLink(links, serviceAccount.URN, principalURN, relationCanImpersonate) != nil {
		t.Fatal("declared-only evidence must never yield a can_impersonate access edge")
	}
	link := findLink(links, serviceAccount.URN, principalURN, relationAssociatedWith)
	if link == nil {
		t.Fatal("expected an associated_with link for declaration-only evidence")
	}
	if link.Attributes["verified"] != "false" {
		t.Fatalf("associated_with verified = %q, want false", link.Attributes["verified"])
	}
	if link.Attributes["basis"] == "" {
		t.Fatal("associated_with must carry a non-empty basis")
	}
}

func TestCloudIdentityPrincipalEvidenceProjectionsRejectsMismatchedAttributes(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSTestEvidence(baseTime)
	event := cloudIdentityProjectionTestEvent(t, "event-mismatch", "writer", evidence)
	event.Attributes["scope"] = "arn:aws:iam::222222222222:role/unrelated-role"

	entities, links, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v, want nil (soft-skip ambiguous evidence)", err)
	}
	if len(entities) != 0 || len(links) != 0 {
		t.Fatalf("got %d entities / %d links for mismatched attrs, want none", len(entities), len(links))
	}
}

func TestCloudIdentityPrincipalEvidenceProjectionsMissingTenant(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSTestEvidence(baseTime)
	event := cloudIdentityProjectionTestEvent(t, "event-no-tenant", "", evidence)

	if _, _, err := cloudIdentityPrincipalEvidenceProjections(event); err == nil {
		t.Fatal("cloudIdentityPrincipalEvidenceProjections() error = nil, want error for a blank tenant")
	}
}

// TestCloudIdentityPrincipalEvidenceProjectionsTenantAccountIsolation covers
// both tenant isolation (identical evidence projected under two tenants
// must never collide on URN) and account isolation (two AWS roles that
// differ only by account must never collide either, since the role ARN
// itself embeds the account).
func TestCloudIdentityPrincipalEvidenceProjectionsTenantAccountIsolation(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSTestEvidence(baseTime)

	eventA := cloudIdentityProjectionTestEvent(t, "event-tenant-a", "tenant-a", evidence)
	entitiesA, linksA, err := cloudIdentityPrincipalEvidenceProjections(eventA)
	if err != nil {
		t.Fatalf("tenant-a projection error = %v", err)
	}
	eventB := cloudIdentityProjectionTestEvent(t, "event-tenant-b", "tenant-b", evidence)
	entitiesB, linksB, err := cloudIdentityPrincipalEvidenceProjections(eventB)
	if err != nil {
		t.Fatalf("tenant-b projection error = %v", err)
	}
	if len(entitiesA) == 0 || len(entitiesB) == 0 {
		t.Fatal("expected projected entities for both tenants")
	}
	urnsA := map[string]struct{}{}
	for _, entity := range entitiesA {
		if entity.TenantID != "tenant-a" {
			t.Fatalf("tenant-a entity %q has TenantID = %q, want tenant-a", entity.URN, entity.TenantID)
		}
		if cerebrourn.TenantID(entity.URN) != "tenant-a" {
			t.Fatalf("tenant-a entity URN %q does not embed tenant-a", entity.URN)
		}
		urnsA[entity.URN] = struct{}{}
	}
	for _, entity := range entitiesB {
		if entity.TenantID != "tenant-b" {
			t.Fatalf("tenant-b entity %q has TenantID = %q, want tenant-b", entity.URN, entity.TenantID)
		}
		if cerebrourn.TenantID(entity.URN) != "tenant-b" {
			t.Fatalf("tenant-b entity URN %q does not embed tenant-b", entity.URN)
		}
		if _, collide := urnsA[entity.URN]; collide {
			t.Fatalf("tenant-b entity URN %q collides with a tenant-a URN for identical payload; tenant isolation violated", entity.URN)
		}
	}
	for _, link := range linksA {
		if link.TenantID != "tenant-a" {
			t.Fatalf("tenant-a link has TenantID = %q, want tenant-a", link.TenantID)
		}
	}
	for _, link := range linksB {
		if link.TenantID != "tenant-b" {
			t.Fatalf("tenant-b link has TenantID = %q, want tenant-b", link.TenantID)
		}
	}

	other := cloudIdentityAWSTestEvidence(baseTime)
	other.Principal.ID = "arn:aws:iam::333333333333:role/billing-worker"
	other.Principal.Account = "333333333333"
	other.Scope = other.Principal.ID
	other.Consumers[0].Principals = []cloudidentity.Principal{other.Principal}
	eventC := cloudIdentityProjectionTestEvent(t, "event-account-c", "writer", other)
	entitiesC, _, err := cloudIdentityPrincipalEvidenceProjections(eventC)
	if err != nil {
		t.Fatalf("account-c projection error = %v", err)
	}
	// The canonical principal URN (the only URN that identifies the cloud
	// account's own role, as opposed to the Kubernetes workload identity
	// shared across both evidence revisions) must differ across accounts.
	writerPrincipalURN := cloudIdentityCanonicalPrincipalURN("writer", evidence.Principal)
	otherPrincipalURN := cloudIdentityCanonicalPrincipalURN("writer", other.Principal)
	if writerPrincipalURN == "" || otherPrincipalURN == "" {
		t.Fatalf("expected non-empty canonical principal URNs, got %q and %q", writerPrincipalURN, otherPrincipalURN)
	}
	if writerPrincipalURN == otherPrincipalURN {
		t.Fatalf("canonical principal URN %q collides across distinct AWS accounts", writerPrincipalURN)
	}
	for _, entity := range entitiesC {
		if entity.EntityType == cloudIdentityIACSourceEntityType {
			continue
		}
		if entity.URN == writerPrincipalURN {
			t.Fatalf("account-c entity URN %q collides with the writer-account canonical principal URN", entity.URN)
		}
	}
}

func TestCloudIdentityCoverageProjectionsFactsNotVerdict(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 11, 0, 0, 0, time.UTC)
	coverage := cloudidentity.CollectionCoverage{
		Schema: cloudidentity.SchemaVersion,
		Scope:  "org:writer",
		Gaps: []cloudidentity.Gap{{
			Code:    "budget_exceeded",
			Scope:   "org:writer",
			Message: "cohort exceeded the 768KiB per-principal budget",
		}},
		CollectedAt:       baseTime,
		InventoryComplete: false,
		GapCount:          1,
	}
	payload, err := json.Marshal(coverage)
	if err != nil {
		t.Fatalf("marshal coverage: %v", err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:         "event-coverage-1",
		TenantId:   "writer",
		SourceId:   cloudidentity.SourceID,
		Kind:       cloudidentity.CoverageEventKind,
		Payload:    payload,
		Attributes: map[string]string{"scope": coverage.Scope},
		OccurredAt: timestamppb.New(baseTime),
	}

	entities, _, err := cloudIdentityCoverageProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityCoverageProjections() error = %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("got %d coverage entities, want 1", len(entities))
	}
	entity := entities[0]
	if entity.EntityType != cloudIdentityCoverageEntityType {
		t.Fatalf("EntityType = %q, want %q", entity.EntityType, cloudIdentityCoverageEntityType)
	}
	if entity.Attributes["inventory_complete"] != "false" {
		t.Fatalf("inventory_complete = %q, want false", entity.Attributes["inventory_complete"])
	}
	if entity.Attributes["gap_count"] != "1" {
		t.Fatalf("gap_count = %q, want 1", entity.Attributes["gap_count"])
	}
	if entity.Attributes["gaps_truncated"] != "false" {
		t.Fatalf("gaps_truncated = %q, want false", entity.Attributes["gaps_truncated"])
	}
	if entity.Attributes["gap_codes"] == "" {
		t.Fatalf("gap_codes = %q, want budget_exceeded", entity.Attributes["gap_codes"])
	}
	if _, ok := entity.Attributes["handoff_status"]; ok {
		t.Fatal("handoff_status must be absent when no handoff was attempted")
	}
}

func TestCloudIdentityCoverageProjectionsPreservesTruncatedGapCount(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 11, 0, 0, 0, time.UTC)
	coverage := cloudidentity.CollectionCoverage{
		Schema:            cloudidentity.SchemaVersion,
		Scope:             "org:writer",
		CollectedAt:       baseTime,
		InventoryComplete: false,
		GapCount:          1,
		GapsTruncated:     true,
	}
	payload, err := json.Marshal(coverage)
	if err != nil {
		t.Fatalf("marshal coverage: %v", err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:         "event-coverage-2",
		TenantId:   "writer",
		SourceId:   cloudidentity.SourceID,
		Kind:       cloudidentity.CoverageEventKind,
		Payload:    payload,
		Attributes: map[string]string{"scope": coverage.Scope},
		OccurredAt: timestamppb.New(baseTime),
	}

	entities, _, err := cloudIdentityCoverageProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityCoverageProjections() error = %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("got %d coverage entities, want 1", len(entities))
	}
	entity := entities[0]
	if entity.Attributes["gap_count"] != "1" {
		t.Fatalf("gap_count = %q, want 1 (wire gap_count must survive even with an empty gaps array)", entity.Attributes["gap_count"])
	}
	if entity.Attributes["gaps_truncated"] != "true" {
		t.Fatalf("gaps_truncated = %q, want true", entity.Attributes["gaps_truncated"])
	}
}

// TestCloudIdentityCoverageProjectionsCarriesHandoffRef pins the contract's
// "coverage entity carries the handoff ref" requirement: the VulnView
// evidence bundle publish outcome is surfaced as attributes on the
// coverage entity.
func TestCloudIdentityCoverageProjectionsCarriesHandoffRef(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 11, 0, 0, 0, time.UTC)
	coverage := cloudidentity.CollectionCoverage{
		Schema: cloudidentity.SchemaVersion, Scope: "org:writer", CollectedAt: baseTime,
		InventoryComplete: true,
		Handoff: cloudidentity.CollectionHandoff{
			Status: "published", Bucket: "vulnview-cloud-identity-intake-111111111111",
			Key:    "cloud-identity/security/writer/20260401T110000Z-abc123.json.gz",
			SHA256: "abc123", SizeBytes: 4096, Stream: "security",
		},
	}
	payload, err := json.Marshal(coverage)
	if err != nil {
		t.Fatalf("marshal coverage: %v", err)
	}
	event := &cerebrov1.EventEnvelope{
		Id: "event-coverage-handoff", TenantId: "writer", SourceId: cloudidentity.SourceID,
		Kind: cloudidentity.CoverageEventKind, Payload: payload,
		Attributes: map[string]string{"scope": coverage.Scope}, OccurredAt: timestamppb.New(baseTime),
	}

	entities, _, err := cloudIdentityCoverageProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityCoverageProjections() error = %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("got %d coverage entities, want 1", len(entities))
	}
	attrs := entities[0].Attributes
	if attrs["handoff_status"] != "published" {
		t.Fatalf("handoff_status = %q, want published", attrs["handoff_status"])
	}
	if attrs["handoff_bucket"] == "" || attrs["handoff_key"] == "" || attrs["handoff_sha256"] == "" || attrs["handoff_stream"] != "security" {
		t.Fatalf("expected handoff bucket/key/sha256/stream attributes, got %+v", attrs)
	}
	// O7: a successful handoff must still explicitly write
	// handoff_error_code (empty), not merely omit it -- omitting the key
	// would leave a prior failed handoff's error code stranded on replay
	// (mergeGraphAttributes only clears a key it is given).
	if errorCode, ok := attrs["handoff_error_code"]; !ok || errorCode != "" {
		t.Fatalf("handoff_error_code = %q (present=%v), want empty and present", errorCode, ok)
	}
	// O7: the coverage entity must opt into strict observation precedence
	// keyed on CollectedAt, so a replayed older-but-complete coverage
	// observation can never overwrite a newer-but-incomplete one.
	if attrs[projectionmeta.AttributeObservedAt] != baseTime.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("attrs[%s] = %q, want %q", projectionmeta.AttributeObservedAt, attrs[projectionmeta.AttributeObservedAt], baseTime.UTC().Format(time.RFC3339Nano))
	}
	if attrs[projectionmeta.AttributeObservationPrecedence] != projectionmeta.ObservationPrecedenceStrict {
		t.Fatalf("attrs[%s] = %q, want %q", projectionmeta.AttributeObservationPrecedence, attrs[projectionmeta.AttributeObservationPrecedence], projectionmeta.ObservationPrecedenceStrict)
	}
}

// TestCloudIdentityCoverageProjectionsOrdersByCollectedAtStrict pins O7:
// confirmed against real Neo4j, an older-but-complete coverage
// observation replayed after a newer-but-incomplete one used to overwrite
// it (plain last-write-wins). The coverage entity's own `at`/
// observation_precedence attributes must order the two the same way
// projectionmeta.CompareObservations/StaleStrictObservation (the exact
// decision the graph store's merge makes) already orders every other
// strict-precedence entity in this package.
func TestCloudIdentityCoverageProjectionsOrdersByCollectedAtStrict(t *testing.T) {
	project := func(id string, collectedAt time.Time, inventoryComplete bool) map[string]string {
		coverage := cloudidentity.CollectionCoverage{
			Schema: cloudidentity.SchemaVersion, Scope: "org:writer", CollectedAt: collectedAt,
			InventoryComplete: inventoryComplete,
		}
		payload, err := json.Marshal(coverage)
		if err != nil {
			t.Fatalf("marshal coverage: %v", err)
		}
		event := &cerebrov1.EventEnvelope{
			Id: id, TenantId: "writer", SourceId: cloudidentity.SourceID,
			Kind: cloudidentity.CoverageEventKind, Payload: payload,
			Attributes: map[string]string{"scope": coverage.Scope}, OccurredAt: timestamppb.New(collectedAt),
		}
		entities, _, err := cloudIdentityCoverageProjections(event)
		if err != nil {
			t.Fatalf("cloudIdentityCoverageProjections() error = %v", err)
		}
		if len(entities) != 1 {
			t.Fatalf("got %d coverage entities, want 1", len(entities))
		}
		return entities[0].Attributes
	}
	newerIncomplete := project("event-coverage-t2", time.Date(2026, time.April, 1, 12, 0, 0, 0, time.UTC), false)
	olderComplete := project("event-coverage-t1", time.Date(2026, time.April, 1, 11, 0, 0, 0, time.UTC), true)
	if got := projectionmeta.CompareObservations(newerIncomplete, olderComplete); got != projectionmeta.ObservationOlder {
		t.Fatalf("older-but-complete coverage after newer-but-incomplete orders %v, want older", got)
	}
	if !projectionmeta.StaleStrictObservation(newerIncomplete, olderComplete) {
		t.Fatal("older-but-complete coverage replayed after newer-but-incomplete must be a stale strict observation")
	}
}

// TestCloudIdentityCoverageProjectionsClearsHandoffErrorCodeOnRecovery pins
// O7: confirmed against real Neo4j, a published handoff after a failed
// one kept the stale handoff_error_code because the old code only wrote
// the attribute when non-empty, so a successful write never carried the
// key needed to clear it. The fix always writes handoff_error_code
// (empty when none) whenever handoff status is present.
func TestCloudIdentityCoverageProjectionsClearsHandoffErrorCodeOnRecovery(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 11, 0, 0, 0, time.UTC)
	coverage := cloudidentity.CollectionCoverage{
		Schema: cloudidentity.SchemaVersion, Scope: "org:writer", CollectedAt: baseTime,
		InventoryComplete: true,
		Handoff: cloudidentity.CollectionHandoff{
			Status: "published", Bucket: "vulnview-cloud-identity-intake-111111111111",
			Key:    "cloud-identity/security/writer/20260401T110000Z-abc123.json.gz",
			SHA256: "abc123", SizeBytes: 4096, Stream: "security",
			// No ErrorCode: this is the recovery write after a prior
			// failed handoff.
		},
	}
	payload, err := json.Marshal(coverage)
	if err != nil {
		t.Fatalf("marshal coverage: %v", err)
	}
	event := &cerebrov1.EventEnvelope{
		Id: "event-coverage-recovered", TenantId: "writer", SourceId: cloudidentity.SourceID,
		Kind: cloudidentity.CoverageEventKind, Payload: payload,
		Attributes: map[string]string{"scope": coverage.Scope}, OccurredAt: timestamppb.New(baseTime),
	}
	entities, _, err := cloudIdentityCoverageProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityCoverageProjections() error = %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("got %d coverage entities, want 1", len(entities))
	}
	// The key must be PRESENT and empty, not merely absent: an absent key
	// leaves a stale stored handoff_error_code value untouched on merge
	// (graphstore/neo4j/store.go mergeGraphAttributes's last-write-wins
	// only overwrites keys it is actually given), while an explicit empty
	// value does clear it.
	errorCode, ok := entities[0].Attributes["handoff_error_code"]
	if !ok {
		t.Fatal("handoff_error_code key must be present (empty) on a published handoff, so a prior failed handoff's code is cleared on merge")
	}
	if errorCode != "" {
		t.Fatalf("handoff_error_code = %q, want empty", errorCode)
	}
}

// TestCloudIdentityReplayingLegacyPrincipalEvidenceYieldsNoLegacyPrincipalEntity
// replays an older-shaped principal_evidence event (no cutover-era fields
// populated) and confirms the cutover projector never resurrects the
// removed scan-scoped cloud_identity.principal entity kind.
func TestCloudIdentityReplayingLegacyPrincipalEvidenceYieldsNoLegacyPrincipalEntity(t *testing.T) {
	baseTime := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSTestEvidence(baseTime)
	event := cloudIdentityProjectionTestEvent(t, "legacy-replay-1", "writer", evidence)

	entities, _, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	for _, entity := range entities {
		if entity.EntityType == "cloud_identity.principal" {
			t.Fatalf("replaying a legacy principal_evidence event must never project a cloud_identity.principal entity, got %+v", entity)
		}
	}
}

// TestCloudIdentityAddCanonicalPrincipalEntityQueryableWithoutProviderConnector
// pins defect #1: when no aws/gcp connector covers the account yet (the
// likely state for a newly onboarded cell account), cloud_identity's own
// principal evidence must still upsert the canonical AWS role node itself
// -- using the SAME entity type ("aws.role") and URN
// (identityPrincipalURN/cloudIdentityCanonicalPrincipalURN) the AWS
// connector would mint -- so a role-centric neighborhood query finds the
// node instead of not_found.
func TestCloudIdentityAddCanonicalPrincipalEntityQueryableWithoutProviderConnector(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSTestEvidence(baseTime)
	event := cloudIdentityProjectionTestEvent(t, "event-no-connector", "writer", evidence)

	entities, _, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	wantPrincipalURN := identityPrincipalURN("writer", "aws", "role", evidence.Principal.ID, "")
	role := findEntity(entities, "aws.role")
	if role == nil {
		t.Fatalf("missing aws.role canonical principal entity with no aws connector coverage; got %v", entityTypes(entities))
	}
	if role.URN != wantPrincipalURN {
		t.Fatalf("role.URN = %q, want %q", role.URN, wantPrincipalURN)
	}
	if role.Attributes["role_arn"] != evidence.Principal.ID {
		t.Fatalf("role.Attributes[role_arn] = %q, want %q", role.Attributes["role_arn"], evidence.Principal.ID)
	}
	if role.Attributes["account_id"] != "222222222222" {
		t.Fatalf("role.Attributes[account_id] = %q, want 222222222222", role.Attributes["account_id"])
	}
}

// TestCloudIdentityCanonicalPrincipalMergesWithAWSEKSPodIdentityProjection
// pins the other half of defect #1: projecting cloud_identity's own
// evidence for a role AND the existing aws.eks_pod_identity_association
// event for the same role must merge into exactly one graph node (same
// URN), with attributes from both sides present -- never two competing
// aws.role nodes.
func TestCloudIdentityCanonicalPrincipalMergesWithAWSEKSPodIdentityProjection(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSTestEvidence(baseTime)
	ciEvent := cloudIdentityProjectionTestEvent(t, "event-merge-ci", "writer", evidence)
	ciEntities, ciLinks, err := cloudIdentityPrincipalEvidenceProjections(ciEvent)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}

	awsEvent := &cerebrov1.EventEnvelope{
		Id: "event-merge-aws", TenantId: "writer", SourceId: "aws", Kind: "aws.eks_pod_identity_association",
		Attributes: map[string]string{
			"association_arn": "arn:aws:eks:us-east-1:222222222222:podidentityassociation/prod-use1/a-1",
			"association_id":  "a-1",
			"cluster_arn":     "arn:aws:eks:us-east-1:222222222222:cluster/prod-use1",
			"cluster_name":    "prod-use1",
			"domain":          "222222222222",
			"namespace":       "billing",
			"resource_id":     "arn:aws:eks:us-east-1:222222222222:podidentityassociation/prod-use1/a-1",
			"resource_name":   "billing-worker",
			"resource_type":   "eks_pod_identity_association",
			"role_arn":        evidence.Principal.ID,
			"role_name":       "billing-worker",
			"service_account": "billing-worker",
		},
	}
	awsEntities, _, err := awsEKSPodIdentityAssociationProjections(awsEvent)
	if err != nil {
		t.Fatalf("awsEKSPodIdentityAssociationProjections() error = %v", err)
	}

	entities, _ := projectionMaps(ciEntities, ciLinks)
	for _, entity := range awsEntities {
		addEntity(entities, entity)
	}

	wantPrincipalURN := identityPrincipalURN("writer", "aws", "role", evidence.Principal.ID, "")
	roleCount := 0
	var merged *ports.ProjectedEntity
	for _, entity := range entities {
		if entity.EntityType == "aws.role" {
			roleCount++
			merged = entity
		}
	}
	if roleCount != 1 {
		t.Fatalf("got %d aws.role nodes after merging cloud_identity and aws EKS Pod Identity projections, want exactly 1", roleCount)
	}
	if merged.URN != wantPrincipalURN {
		t.Fatalf("merged.URN = %q, want %q", merged.URN, wantPrincipalURN)
	}
	if merged.Attributes["role_arn"] != evidence.Principal.ID {
		t.Fatalf("merged.Attributes[role_arn] = %q, want %q", merged.Attributes["role_arn"], evidence.Principal.ID)
	}
	if merged.Attributes["role_name"] != "billing-worker" {
		t.Fatalf("merged role_name = %q, want aws connector's role_name to be present after merge", merged.Attributes["role_name"])
	}
}

// TestCloudIdentityCanonicalPrincipalTenantIsolation pins tenant
// isolation: the identical ARN in another tenant must mint a different
// canonical principal URN.
func TestCloudIdentityCanonicalPrincipalTenantIsolation(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidenceA := cloudIdentityAWSTestEvidence(baseTime)
	eventA := cloudIdentityProjectionTestEvent(t, "event-tenant-a", "tenant-a", evidenceA)
	entitiesA, _, err := cloudIdentityPrincipalEvidenceProjections(eventA)
	if err != nil {
		t.Fatalf("tenant-a error = %v", err)
	}
	evidenceB := cloudIdentityAWSTestEvidence(baseTime)
	eventB := cloudIdentityProjectionTestEvent(t, "event-tenant-b", "tenant-b", evidenceB)
	entitiesB, _, err := cloudIdentityPrincipalEvidenceProjections(eventB)
	if err != nil {
		t.Fatalf("tenant-b error = %v", err)
	}
	roleA := findEntity(entitiesA, "aws.role")
	roleB := findEntity(entitiesB, "aws.role")
	if roleA == nil || roleB == nil {
		t.Fatalf("missing aws.role entity in one tenant: A=%v B=%v", roleA, roleB)
	}
	if roleA.URN == roleB.URN {
		t.Fatalf("same ARN in two tenants minted the identical URN %q, want tenant-scoped URNs", roleA.URN)
	}
}

// TestCloudIdentityCanonicalPrincipalSimilarRoleNameDifferentAccount pins
// that a similarly-named role in a different AWS account never collides
// with the canonical node for this evidence's own role.
func TestCloudIdentityCanonicalPrincipalSimilarRoleNameDifferentAccount(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSTestEvidence(baseTime)
	event := cloudIdentityProjectionTestEvent(t, "event-similar-role", "writer", evidence)
	entities, _, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	role := findEntity(entities, "aws.role")
	if role == nil {
		t.Fatal("missing aws.role entity")
	}
	otherAccountURN := identityPrincipalURN("writer", "aws", "role", "arn:aws:iam::999999999999:role/billing-worker", "")
	if role.URN == otherAccountURN {
		t.Fatalf("role.URN collided with a similarly-named role in a different account: %q", role.URN)
	}
}

// TestCloudIdentityConsumerKSAURNMatchesAWSEKSPodIdentityProjection pins
// defect #2: cloud_identity's consumer KSA URN for a given account,
// cluster, namespace, and service account must be byte-identical to the
// URN the existing aws EKS Pod Identity projection already mints for the
// same coordinates (via awsEKSKubernetesAttributes), so they land on the
// same node instead of a second, cluster-name-only node.
func TestCloudIdentityConsumerKSAURNMatchesAWSEKSPodIdentityProjection(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSTestEvidence(baseTime)
	event := cloudIdentityProjectionTestEvent(t, "event-ksa-match", "writer", evidence)
	entities, _, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	serviceAccount := findEntity(entities, "kubernetes.service_account")
	if serviceAccount == nil {
		t.Fatal("missing kubernetes.service_account entity")
	}
	awsKubernetesAttrs := awsEKSKubernetesAttributes(map[string]string{"domain": "222222222222", "cluster_name": "prod-use1"}, "billing", "billing-worker")
	wantURN := kubernetesServiceAccountURN("writer", awsKubernetesAttrs)
	if serviceAccount.URN != wantURN {
		t.Fatalf("serviceAccount.URN = %q, want %q (must match the aws EKS Pod Identity projector's KSA URN)", serviceAccount.URN, wantURN)
	}
}

// TestCloudIdentityConsumerKSATwoClustersSameNameDifferentAccountsDistinctNodes
// pins defect #2's collision fix: two clusters that share a bare name in
// different AWS accounts must mint two distinct KSA nodes, never one.
func TestCloudIdentityConsumerKSATwoClustersSameNameDifferentAccountsDistinctNodes(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidenceA := cloudIdentityAWSTestEvidence(baseTime)
	evidenceA.Consumers[0].Cluster = "shared-name"
	evidenceA.Consumers[0].CloudAccount = "111111111111"
	eventA := cloudIdentityProjectionTestEvent(t, "event-cluster-collision-a", "writer", evidenceA)
	entitiesA, _, err := cloudIdentityPrincipalEvidenceProjections(eventA)
	if err != nil {
		t.Fatalf("account A error = %v", err)
	}

	evidenceB := cloudIdentityAWSTestEvidence(baseTime)
	evidenceB.Consumers[0].Cluster = "shared-name"
	evidenceB.Consumers[0].CloudAccount = "999999999999"
	eventB := cloudIdentityProjectionTestEvent(t, "event-cluster-collision-b", "writer", evidenceB)
	entitiesB, _, err := cloudIdentityPrincipalEvidenceProjections(eventB)
	if err != nil {
		t.Fatalf("account B error = %v", err)
	}

	ksaA := findEntity(entitiesA, "kubernetes.service_account")
	ksaB := findEntity(entitiesB, "kubernetes.service_account")
	if ksaA == nil || ksaB == nil {
		t.Fatalf("missing KSA entity: A=%v B=%v", ksaA, ksaB)
	}
	if ksaA.URN == ksaB.URN {
		t.Fatalf("same cluster name in different accounts minted the identical KSA URN %q, want distinct nodes", ksaA.URN)
	}
}

// TestCloudIdentityConsumerWithoutAccountOrProjectMintsNoKSALink pins
// defect #2's safety rule: a consumer with neither CloudAccount nor
// CloudProject known must never mint a collision-prone cluster-name-only
// workload/KSA URN -- the consumer link is skipped entirely.
func TestCloudIdentityConsumerWithoutAccountOrProjectMintsNoKSALink(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityAWSTestEvidence(baseTime)
	evidence.Consumers[0].CloudAccount = ""
	evidence.Consumers[0].CloudProject = ""
	event := cloudIdentityProjectionTestEvent(t, "event-no-account", "writer", evidence)
	entities, links, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	if findEntity(entities, "kubernetes.service_account") != nil {
		t.Fatalf("expected no kubernetes.service_account entity with no known account/project; got %v", entityTypes(entities))
	}
	if findEntity(entities, "kubernetes.workload") != nil {
		t.Fatalf("expected no kubernetes.workload entity with no known account/project; got %v", entityTypes(entities))
	}
	principalURN := identityPrincipalURN("writer", "aws", "role", evidence.Principal.ID, "")
	for _, link := range links {
		if link.ToURN == principalURN {
			t.Fatalf("expected no consumer link to the principal with no resolvable workload/KSA identity, got %+v", link)
		}
	}
}

// TestCloudIdentityConsumerGKEWorkloadIsProjectQualified pins defect #2
// for GCP: a GKE consumer's KSA URN must be qualified by
// Workload.CloudProject (preferring CloudAccount when both happen to be
// set, matching an AWS cell target with a paired GCP project).
func TestCloudIdentityConsumerGKEWorkloadIsProjectQualified(t *testing.T) {
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
		Declared:    cloudidentity.PolicyState{Complete: true},
		Observed:    cloudidentity.PolicyState{Complete: true},
		Definitions: cloudidentity.Definitions{Complete: true},
		CollectedAt: baseTime,
	}
	event := cloudIdentityProjectionTestEvent(t, "event-gke-project", "writer", evidence)
	entities, _, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	serviceAccount := findEntity(entities, "kubernetes.service_account")
	if serviceAccount == nil {
		t.Fatal("missing kubernetes.service_account entity")
	}
	wantURN := kubernetesServiceAccountURN("writer", map[string]string{
		"cluster_id": "writer-prod:prod-gke", "namespace": "payments", "service_account_name": "api",
	})
	if serviceAccount.URN != wantURN {
		t.Fatalf("serviceAccount.URN = %q, want project-qualified %q", serviceAccount.URN, wantURN)
	}
}
