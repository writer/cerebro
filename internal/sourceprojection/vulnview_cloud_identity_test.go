package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

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

func vulnViewCloudIdentityFindingEvent(attrOverrides map[string]string, payload string) *cerebrov1.EventEnvelope {
	attrs := map[string]string{
		"finding_id": "cloud_identity|cloud_identity_excess_privilege|aws|arn:aws:iam::222222222222:role/billing-worker|writer",
		"source":     "cloud_identity", "check_id": "cloud_identity_excess_privilege", "check_version": "1", "detector_version": "1.0.0",
		"status": "open", "severity": "high", "title": "Excess privilege",
		"resource_provider": "aws", "resource_account": "222222222222", "principal_id": "arn:aws:iam::222222222222:role/billing-worker",
		"principal_kind": "aws_role", "cohort_scope": "writer",
		"version": "3", "updated_at": "2026-04-01T09:00:00Z",
	}
	for k, v := range attrOverrides {
		if v == "" {
			delete(attrs, k)
			continue
		}
		attrs[k] = v
	}
	if payload == "" {
		payload = "{}"
	}
	return &cerebrov1.EventEnvelope{
		Id: "event-finding-1", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.finding",
		Payload: []byte(payload), Attributes: attrs,
	}
}

func TestVulnViewFindingCloudIdentityAWSCanonicalJoin(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(nil, "")
	entities, links, err := vulnViewFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, "vulnview.finding")
	if finding == nil {
		t.Fatalf("missing finding entity; got %v", entityTypes(entities))
	}
	wantPrincipalURN := identityPrincipalURN("writer", "aws", "role", "arn:aws:iam::222222222222:role/billing-worker", "")
	if findLink(links, wantPrincipalURN, finding.URN, relationHasEvidence) == nil {
		t.Fatal("missing canonical AWS principal -has_evidence-> finding join")
	}
	role := findEntity(entities, "aws.role")
	if role == nil {
		t.Fatalf("missing aws.role principal endpoint entity; got %v", entityTypes(entities))
	}
	if role.URN != wantPrincipalURN {
		t.Fatalf("role.URN = %q, want %q", role.URN, wantPrincipalURN)
	}
	if role.Attributes["role_arn"] != "arn:aws:iam::222222222222:role/billing-worker" || role.Attributes["account_id"] != "222222222222" {
		t.Fatalf("role.Attributes = %+v", role.Attributes)
	}
	if !role.CreateOnly {
		t.Fatal("aws.role principal stub CreateOnly = false, want true (F05: must never overwrite a richer provider-owned entity)")
	}
	if finding.Attributes["observation_version"] != "3" {
		t.Fatalf("observation_version = %q, want 3", finding.Attributes["observation_version"])
	}
}

func TestVulnViewFindingCloudIdentityGCPCanonicalJoin(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(map[string]string{
		"resource_provider": "gcp", "resource_account": "", "resource_project": "writer-prod",
		"principal_id": "payments-sa@writer-prod.iam.gserviceaccount.com", "principal_kind": "gcp_service_account",
	}, "")
	entities, links, err := vulnViewFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, "vulnview.finding")
	if finding == nil {
		t.Fatal("missing finding entity")
	}
	wantPrincipalURN := identityPrincipalURN("writer", "gcp", "service_account", "payments-sa@writer-prod.iam.gserviceaccount.com", "")
	if findLink(links, wantPrincipalURN, finding.URN, relationHasEvidence) == nil {
		t.Fatal("missing canonical GCP principal -has_evidence-> finding join")
	}
	sa := findEntity(entities, "gcp.service_account")
	if sa == nil {
		t.Fatalf("missing gcp.service_account principal endpoint entity; got %v", entityTypes(entities))
	}
	if sa.URN != wantPrincipalURN {
		t.Fatalf("sa.URN = %q, want %q", sa.URN, wantPrincipalURN)
	}
	if sa.Attributes["email"] != "payments-sa@writer-prod.iam.gserviceaccount.com" || sa.Attributes["project_id"] != "writer-prod" {
		t.Fatalf("sa.Attributes = %+v", sa.Attributes)
	}
	if !sa.CreateOnly {
		t.Fatal("gcp.service_account principal stub CreateOnly = false, want true (F05: must never overwrite a richer provider-owned entity)")
	}
}

func TestVulnViewFindingCloudIdentityPrincipalURICanonicalJoin(t *testing.T) {
	principalURI := "principal://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/writer-prod.svc.id.goog/subject/ns/payments/sa/api"
	event := vulnViewCloudIdentityFindingEvent(map[string]string{
		"resource_provider": "gcp", "resource_account": "", "principal_id": principalURI, "principal_kind": "gcp_workload_identity_principal",
	}, "")
	entities, links, err := vulnViewFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, "vulnview.finding")
	if finding == nil {
		t.Fatal("missing finding entity")
	}
	wantPrincipalURN := identityPrincipalURN("writer", "gcp", "service_account", principalURI, "")
	if wantPrincipalURN == "" {
		t.Fatal("expected a non-empty canonical URN for a principal:// subject")
	}
	if findLink(links, wantPrincipalURN, finding.URN, relationHasEvidence) == nil {
		t.Fatal("missing canonical principal:// -has_evidence-> finding join")
	}
	if got := vulnViewCloudIdentityCanonicalPrincipalURN("writer", "gcp", principalURI); got != wantPrincipalURN {
		t.Fatalf("canonical URN not stable across calls: %q != %q", got, wantPrincipalURN)
	}
}

func TestVulnViewFindingCloudIdentityMissingSubjectNoJoin(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(map[string]string{"principal_id": "", "resource_provider": ""}, "")
	entities, links, err := vulnViewFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, "vulnview.finding")
	if finding == nil {
		t.Fatal("missing finding entity even without a resolvable principal")
	}
	for _, link := range links {
		if link.ToURN == finding.URN && link.Relation == relationHasEvidence {
			t.Fatalf("unexpected has_evidence link with no resolvable principal: %+v", link)
		}
	}
}

// TestVulnViewFindingCloudIdentityMalformedAWSPrincipalNoJoin pins defect
// #5: a non-ARN AWS principal id must never mint a dangling canonical
// role URN, even though it is nonempty.
func TestVulnViewFindingCloudIdentityMalformedAWSPrincipalNoJoin(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(map[string]string{"principal_id": "aws", "principal_kind": "aws_role"}, "")
	entities, links, err := vulnViewFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, "vulnview.finding")
	if finding == nil {
		t.Fatal("missing finding entity even without a resolvable principal")
	}
	for _, link := range links {
		if link.ToURN == finding.URN && link.Relation == relationHasEvidence {
			t.Fatalf("unexpected has_evidence link for malformed AWS principal id: %+v", link)
		}
	}
}

// TestVulnViewFindingCloudIdentityKubernetesPlaceholderSubjectNoJoin pins
// defect #5: a raw k8s:// placeholder subject (VulnView could not yet
// join this consumer to a cloud principal) must never mint a canonical
// join.
func TestVulnViewFindingCloudIdentityKubernetesPlaceholderSubjectNoJoin(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(map[string]string{
		"principal_id": "k8s://prod-eks/billing/sa/worker", "principal_kind": "aws_kubernetes_service_account",
	}, "")
	entities, links, err := vulnViewFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, "vulnview.finding")
	if finding == nil {
		t.Fatal("missing finding entity even without a resolvable principal")
	}
	for _, link := range links {
		if link.ToURN == finding.URN && link.Relation == relationHasEvidence {
			t.Fatalf("unexpected has_evidence link for a k8s:// placeholder subject: %+v", link)
		}
	}
}

// TestVulnViewFindingCloudIdentityMalformedGCPPrincipalNoJoin pins defect
// #5 for GCP: a non-email, non-principal:// GCP principal id must never
// mint a dangling canonical service-account URN.
func TestVulnViewFindingCloudIdentityMalformedGCPPrincipalNoJoin(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(map[string]string{
		"resource_provider": "gcp", "resource_account": "", "principal_id": "not-an-email", "principal_kind": "gcp_service_account",
	}, "")
	entities, links, err := vulnViewFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, "vulnview.finding")
	if finding == nil {
		t.Fatal("missing finding entity even without a resolvable principal")
	}
	for _, link := range links {
		if link.ToURN == finding.URN && link.Relation == relationHasEvidence {
			t.Fatalf("unexpected has_evidence link for malformed GCP principal id: %+v", link)
		}
	}
}

func TestVulnViewCloudIdentityUnresolvedPrincipalSubjectRejectsMalformedAWSValues(t *testing.T) {
	for _, id := range []string{"aws", "aws_kubernetes_service_account", "k8s://cluster/ns/sa/name"} {
		if !vulnViewCloudIdentityUnresolvedPrincipalSubject("aws", "aws_role", id) {
			t.Fatalf("vulnViewCloudIdentityUnresolvedPrincipalSubject(aws, aws_role, %q) = false, want true", id)
		}
	}
}

func TestVulnViewCloudIdentityUnresolvedPrincipalSubjectRejectsMalformedGCPEmail(t *testing.T) {
	if !vulnViewCloudIdentityUnresolvedPrincipalSubject("gcp", "gcp_service_account", "not-an-email") {
		t.Fatal("vulnViewCloudIdentityUnresolvedPrincipalSubject(gcp, gcp_service_account, not-an-email) = false, want true")
	}
}

func TestVulnViewCloudIdentityUnresolvedPrincipalSubjectAcceptsResolvedGCPPrincipalURI(t *testing.T) {
	uri := "principal://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/writer-prod.svc.id.goog/subject/ns/payments/sa/api"
	if vulnViewCloudIdentityUnresolvedPrincipalSubject("gcp", "gcp_workload_identity_principal", uri) {
		t.Fatal("vulnViewCloudIdentityUnresolvedPrincipalSubject() = true for a fully resolved principal:// subject, want false")
	}
}

const cloudIdentityConsumersCompletePayload = `{"details":{"consumersComplete":true,"consumers":[{"cluster":"prod-use1","namespace":"billing","serviceAccount":"billing-worker","cloudAccount":"222222222222"}]}}`

// TestVulnViewFindingAddCloudIdentityLinksDoesNotMaterializeConsumerKSAEntity
// pins R06: the regular (ordinary-entity) projector must never materialize
// a consumer's kubernetes.service_account stub itself -- that stub is a
// CreateOnly counterpart of the separate Contract C9 associated_with link
// set and must only ever be created inside that set's own guarded store
// operation (as its Endpoints), so a stale or losing observation can
// never leak it into the graph ahead of the winning decision.
func TestVulnViewFindingAddCloudIdentityLinksDoesNotMaterializeConsumerKSAEntity(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(nil, cloudIdentityConsumersCompletePayload)
	entities, _, err := vulnViewFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections() error = %v", err)
	}
	if ksa := findEntity(entities, "kubernetes.service_account"); ksa != nil {
		t.Fatalf("regular projector materialized a kubernetes.service_account entity directly: %#v; it must only ever be created as the link set's Endpoints", ksa)
	}
}

// TestVulnViewFindingLinkSetProjectionsBuildsConsumerAssociatedWithSet
// pins Contract C9: a cloud_identity finding whose export marks the
// consumer list consumersComplete produces exactly one link set owned by
// the finding itself (whose own version orders it), asserting
// associated_with to each consumer KSA and carrying that KSA as a
// CreateOnly Endpoints stub (R06) instead of an ordinary entity.
func TestVulnViewFindingLinkSetProjectionsBuildsConsumerAssociatedWithSet(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(map[string]string{ports.EventAttributeSourceRuntimeID: "vulnview-runtime-1"}, cloudIdentityConsumersCompletePayload)
	sets, err := vulnViewFindingLinkSetProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingLinkSetProjections() error = %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("len(sets) = %d, want 1", len(sets))
	}
	set := sets[0]
	wantFindingURN := projectionURN("writer", "vulnview_finding", event.GetAttributes()["finding_id"])
	if set.OwnerURN != wantFindingURN {
		t.Fatalf("OwnerURN = %q, want %q", set.OwnerURN, wantFindingURN)
	}
	if set.Relation != relationAssociatedWith || !set.Outgoing {
		t.Fatalf("Relation/Outgoing = %q/%v, want associated_with/true", set.Relation, set.Outgoing)
	}
	if set.RuntimeID != "vulnview-runtime-1" {
		t.Fatalf("set.RuntimeID = %q, want vulnview-runtime-1", set.RuntimeID)
	}
	if len(set.Links) != 1 {
		t.Fatalf("len(Links) = %d, want 1", len(set.Links))
	}
	link := set.Links[0]
	if link.FromURN != wantFindingURN {
		t.Fatalf("link.FromURN = %q, want %q", link.FromURN, wantFindingURN)
	}
	if link.Relation != relationAssociatedWith {
		t.Fatalf("link.Relation = %q, want associated_with", link.Relation)
	}
	if set.Observation["observation_version"] != "3" || set.Observation["observation_precedence"] != "strict" {
		t.Fatalf("Observation = %+v, want strict version 3", set.Observation)
	}
	if len(set.Endpoints) != 1 {
		t.Fatalf("len(Endpoints) = %d, want 1", len(set.Endpoints))
	}
	endpoint := set.Endpoints[0]
	if endpoint.URN != link.ToURN {
		t.Fatalf("Endpoints[0].URN = %q, want %q (the link's consumer counterpart)", endpoint.URN, link.ToURN)
	}
	if !endpoint.CreateOnly {
		t.Fatal("Endpoints[0].CreateOnly = false, want true (R06: must never overwrite a richer connector-owned entity)")
	}
	if endpoint.SourceID != set.SourceID || endpoint.RuntimeID != set.RuntimeID {
		t.Fatalf("Endpoints[0] source/runtime = %q/%q, want them to equal the set's own %q/%q (ordinary projected entities always carry this provenance)", endpoint.SourceID, endpoint.RuntimeID, set.SourceID, set.RuntimeID)
	}
	if endpoint.Attributes[ports.EventAttributeSourceRuntimeID] != "vulnview-runtime-1" {
		t.Fatalf("Endpoints[0].Attributes[%q] = %q, want vulnview-runtime-1", ports.EventAttributeSourceRuntimeID, endpoint.Attributes[ports.EventAttributeSourceRuntimeID])
	}
	if endpoint.Attributes["cluster_name"] != "prod-use1" || endpoint.Attributes["namespace"] != "billing" {
		t.Fatalf("endpoint attrs = %+v", endpoint.Attributes)
	}
	if err := ports.ValidateProjectedLinkSetEndpoints(set); err != nil {
		t.Fatalf("ValidateProjectedLinkSetEndpoints() error = %v, want the real projector's set to already satisfy the Endpoints contract", err)
	}
}

// Two checks on one principal carry independent version sequences. Their
// consumer sets must never share an ordering guard, or one finding's newer
// consumer list would be rejected as stale against the other finding's
// higher version.
func TestVulnViewFindingLinkSetsForOnePrincipalAreOrderedPerFinding(t *testing.T) {
	excess := vulnViewCloudIdentityFindingEvent(map[string]string{"version": "5"}, cloudIdentityConsumersCompletePayload)
	sharing := vulnViewCloudIdentityFindingEvent(map[string]string{
		"finding_id": "cloud_identity|cloud_identity_shared_principal|aws|arn:aws:iam::222222222222:role/billing-worker|writer",
		"check_id":   "cloud_identity_shared_principal",
		"version":    "2",
	}, cloudIdentityConsumersCompletePayload)
	excessSets, err := vulnViewFindingLinkSetProjections(excess)
	if err != nil || len(excessSets) != 1 {
		t.Fatalf("excess link sets = %d, err = %v", len(excessSets), err)
	}
	sharingSets, err := vulnViewFindingLinkSetProjections(sharing)
	if err != nil || len(sharingSets) != 1 {
		t.Fatalf("sharing link sets = %d, err = %v", len(sharingSets), err)
	}
	if excessSets[0].OwnerURN == sharingSets[0].OwnerURN {
		t.Fatalf("both findings' consumer sets share owner %q; version 2 would be ordered against version 5", excessSets[0].OwnerURN)
	}
}

// TestVulnViewFindingLinkSetProjectionsIncompleteWhenConsumersIncomplete
// pins F04: a partial/unavailable consumer list must never retract
// previously observed consumers, but the finding still owns an accepted
// Incomplete observation (no links) so a store's ordering guard advances
// and a later stale complete set cannot replace newer links.
func TestVulnViewFindingLinkSetProjectionsIncompleteWhenConsumersIncomplete(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(nil, `{"details":{"consumersComplete":false,"consumers":[{"cluster":"prod-use1","namespace":"billing","serviceAccount":"billing-worker","cloudAccount":"222222222222"}]}}`)
	sets, err := vulnViewFindingLinkSetProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingLinkSetProjections() error = %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("len(sets) = %d, want 1 for an incomplete consumer list", len(sets))
	}
	set := sets[0]
	if !set.Incomplete {
		t.Fatalf("Incomplete = false, want true for an incomplete consumer list")
	}
	if len(set.Links) != 0 {
		t.Fatalf("len(Links) = %d, want 0 for an incomplete consumer list", len(set.Links))
	}
	if len(set.Endpoints) != 0 {
		t.Fatalf("len(Endpoints) = %d, want 0 for an incomplete consumer list", len(set.Endpoints))
	}
	if set.Observation["observation_version"] != "3" {
		t.Fatalf("Observation = %+v, want strict version 3", set.Observation)
	}
}

// TestVulnViewFindingLinkSetProjectionsIncompleteWhenConsumerMissingRequiredField
// pins R04: a consumersComplete:true payload whose consumer is missing
// cluster/namespace/serviceAccount must downgrade the whole observation
// to Incomplete (no links, no endpoints) rather than silently skip that
// member and still authorize a reduced complete set.
func TestVulnViewFindingLinkSetProjectionsIncompleteWhenConsumerMissingRequiredField(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(nil, `{"details":{"consumersComplete":true,"consumers":[{"cluster":"prod-use1","namespace":"billing","serviceAccount":"billing-worker","cloudAccount":"222222222222"},{"cluster":"prod-use1","namespace":"","serviceAccount":"other-worker","cloudAccount":"222222222222"}]}}`)
	sets, err := vulnViewFindingLinkSetProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingLinkSetProjections() error = %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("len(sets) = %d, want 1", len(sets))
	}
	set := sets[0]
	if !set.Incomplete {
		t.Fatal("Incomplete = false, want true: a member missing a required identity field must downgrade the whole observation")
	}
	if len(set.Links) != 0 || len(set.Endpoints) != 0 {
		t.Fatalf("Links/Endpoints = %d/%d, want 0/0 for a downgraded observation", len(set.Links), len(set.Endpoints))
	}
	entities, _, err := vulnViewFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections() error = %v", err)
	}
	if ksa := findEntity(entities, "kubernetes.service_account"); ksa != nil {
		t.Fatalf("a downgraded observation must never materialize a consumer KSA entity: %#v", ksa)
	}
}

// TestVulnViewFindingLinkSetProjectionsIncompleteWhenConsumerMissingCloudQualifier
// pins R04: a consumer missing both cloudAccount and cloudProject (the
// owning-account qualifier) must likewise downgrade the whole observation
// to Incomplete, not just skip that one member.
func TestVulnViewFindingLinkSetProjectionsIncompleteWhenConsumerMissingCloudQualifier(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(nil, `{"details":{"consumersComplete":true,"consumers":[{"cluster":"prod-use1","namespace":"billing","serviceAccount":"billing-worker","cloudAccount":"222222222222"},{"cluster":"prod-use1","namespace":"billing","serviceAccount":"other-worker"}]}}`)
	sets, err := vulnViewFindingLinkSetProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingLinkSetProjections() error = %v", err)
	}
	if len(sets) != 1 || !sets[0].Incomplete {
		t.Fatalf("sets = %#v, want 1 Incomplete set: a member missing both cloudAccount/cloudProject must downgrade the whole observation", sets)
	}
	if len(sets[0].Links) != 0 || len(sets[0].Endpoints) != 0 {
		t.Fatalf("Links/Endpoints = %d/%d, want 0/0 for a downgraded observation", len(sets[0].Links), len(sets[0].Endpoints))
	}
}

// TestVulnViewFindingLinkSetProjectionsIncompleteWhenConsumerCloudAccountNotParseable
// pins RR03: a consumer whose cloudAccount is present and nonblank but
// not a valid 12-digit AWS account id (e.g. "not-an-account") fails the
// same canonical kubernetesServiceAccountURN/kubernetesCloudAccountID
// parser every other provider projection uses. A nonblank-only gate
// would let this member pass vulnViewFindingConsumerKSAAttrs and then be
// silently skipped later, letting the rest of a consumersComplete:true
// payload still authorize a reduced "complete" link set. It must instead
// downgrade the whole observation to Incomplete, with no links or
// endpoints -- never silently drop just that member.
func TestVulnViewFindingLinkSetProjectionsIncompleteWhenConsumerCloudAccountNotParseable(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(nil, `{"details":{"consumersComplete":true,"consumers":[{"cluster":"prod-use1","namespace":"billing","serviceAccount":"billing-worker","cloudAccount":"222222222222"},{"cluster":"prod-use1","namespace":"billing","serviceAccount":"other-worker","cloudAccount":"not-an-account"}]}}`)
	sets, err := vulnViewFindingLinkSetProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingLinkSetProjections() error = %v", err)
	}
	if len(sets) != 1 || !sets[0].Incomplete {
		t.Fatalf("sets = %#v, want 1 Incomplete set: a member whose cloudAccount is not parseable into a canonical identity must downgrade the whole observation", sets)
	}
	if len(sets[0].Links) != 0 || len(sets[0].Endpoints) != 0 {
		t.Fatalf("Links/Endpoints = %d/%d, want 0/0 for a downgraded observation", len(sets[0].Links), len(sets[0].Endpoints))
	}
}

// TestVulnViewFindingLinkSetProjectionsIncompleteWhenConsumerMemberNull pins
// R04: an explicit JSON null member inside an otherwise consumersComplete
// array must downgrade the whole observation to Incomplete, distinct from
// a genuinely empty array.
func TestVulnViewFindingLinkSetProjectionsIncompleteWhenConsumerMemberNull(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(nil, `{"details":{"consumersComplete":true,"consumers":[{"cluster":"prod-use1","namespace":"billing","serviceAccount":"billing-worker","cloudAccount":"222222222222"},null]}}`)
	sets, err := vulnViewFindingLinkSetProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingLinkSetProjections() error = %v", err)
	}
	if len(sets) != 1 || !sets[0].Incomplete {
		t.Fatalf("sets = %#v, want 1 Incomplete set: a null member must downgrade the whole observation", sets)
	}
}

// TestVulnViewFindingLinkSetProjectionsIncompleteWhenConsumersContainerAbsentOrNull
// pins R04: consumersComplete:true with the "consumers" key entirely
// absent, or explicitly JSON null, must be treated conservatively as
// Incomplete -- never as a genuinely complete empty list.
func TestVulnViewFindingLinkSetProjectionsIncompleteWhenConsumersContainerAbsentOrNull(t *testing.T) {
	for name, payload := range map[string]string{
		"absent": `{"details":{"consumersComplete":true}}`,
		"null":   `{"details":{"consumersComplete":true,"consumers":null}}`,
	} {
		t.Run(name, func(t *testing.T) {
			event := vulnViewCloudIdentityFindingEvent(nil, payload)
			sets, err := vulnViewFindingLinkSetProjections(event)
			if err != nil {
				t.Fatalf("vulnViewFindingLinkSetProjections() error = %v", err)
			}
			if len(sets) != 1 || !sets[0].Incomplete {
				t.Fatalf("sets = %#v, want 1 Incomplete set for a %s consumers container", sets, name)
			}
			if len(sets[0].Links) != 0 || len(sets[0].Endpoints) != 0 {
				t.Fatalf("Links/Endpoints = %d/%d, want 0/0", len(sets[0].Links), len(sets[0].Endpoints))
			}
		})
	}
}

// TestVulnViewFindingLinkSetProjectionsCompleteEmptyArrayStaysAuthoritative
// pins R04's control: a genuinely complete, empty consumers array (as
// opposed to an absent/null container) still clears the scoped links
// authoritatively.
func TestVulnViewFindingLinkSetProjectionsCompleteEmptyArrayStaysAuthoritative(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(nil, `{"details":{"consumersComplete":true,"consumers":[]}}`)
	sets, err := vulnViewFindingLinkSetProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingLinkSetProjections() error = %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("len(sets) = %d, want 1", len(sets))
	}
	if sets[0].Incomplete {
		t.Fatal("Incomplete = true, want false for a genuinely complete empty array")
	}
	if len(sets[0].Links) != 0 || len(sets[0].Endpoints) != 0 {
		t.Fatalf("Links/Endpoints = %d/%d, want 0/0 for a complete empty array", len(sets[0].Links), len(sets[0].Endpoints))
	}
}

// TestVulnViewFindingLinkSetProjectionsDedupesValidDuplicateConsumers pins
// R04's control: two consumer entries that canonicalize to the exact same
// Kubernetes service account dedupe into one link/endpoint rather than
// downgrading the observation or double-asserting.
func TestVulnViewFindingLinkSetProjectionsDedupesValidDuplicateConsumers(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(nil, `{"details":{"consumersComplete":true,"consumers":[{"cluster":"prod-use1","namespace":"billing","serviceAccount":"billing-worker","cloudAccount":"222222222222"},{"cluster":"prod-use1","namespace":"billing","serviceAccount":"billing-worker","cloudAccount":"222222222222","service":"optional-descriptive-field"}]}}`)
	sets, err := vulnViewFindingLinkSetProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingLinkSetProjections() error = %v", err)
	}
	if len(sets) != 1 || sets[0].Incomplete {
		t.Fatalf("sets = %#v, want 1 complete set", sets)
	}
	if len(sets[0].Links) != 1 {
		t.Fatalf("len(Links) = %d, want 1 (valid duplicates dedupe)", len(sets[0].Links))
	}
	if len(sets[0].Endpoints) != 1 {
		t.Fatalf("len(Endpoints) = %d, want 1 (valid duplicates dedupe)", len(sets[0].Endpoints))
	}
}

// TestVulnViewFindingLinkSetProjectionsOnlyForCloudIdentitySource pins
// that a non-cloud_identity finding never projects a link set, even if it
// happens to carry a details.consumers-shaped payload.
func TestVulnViewFindingLinkSetProjectionsOnlyForCloudIdentitySource(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(map[string]string{"source": "nuclei"}, cloudIdentityConsumersCompletePayload)
	sets, err := vulnViewFindingLinkSetProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingLinkSetProjections() error = %v", err)
	}
	if len(sets) != 0 {
		t.Fatalf("len(sets) = %d, want 0 for a non-cloud_identity source", len(sets))
	}
}

// TestProjectVulnViewCloudIdentityConsumerSetCarriesTrustedApplicationWorkspace
// pins RF01 through the production Service: a guarded consumer edge and the
// endpoint stub it creates share the finding's trusted application
// workspace, and an event without one keeps the tenant-wide legacy scope.
// ProjectLinkSets is the boundary coalesced graph ingest consumes;
// ProjectWithDelta is the per-event and rebuild path.
func TestProjectVulnViewCloudIdentityConsumerSetCarriesTrustedApplicationWorkspace(t *testing.T) {
	for name, workspaceID := range map[string]string{"workspace": "workspace-a", "legacy tenant-wide": ""} {
		t.Run(name, func(t *testing.T) {
			attrs := map[string]string{ports.EventAttributeSourceRuntimeID: "vulnview-runtime-1"}
			if workspaceID != "" {
				attrs[ports.EventAttributeApplicationWorkspaceID] = workspaceID
			}
			event := vulnViewCloudIdentityFindingEvent(attrs, cloudIdentityConsumersCompletePayload)

			sets, err := New(nil, nil).ProjectLinkSets(event)
			if err != nil {
				t.Fatalf("ProjectLinkSets() error = %v", err)
			}
			if len(sets) != 1 || sets[0].Incomplete || len(sets[0].Links) != 1 || len(sets[0].Endpoints) != 1 {
				t.Fatalf("ProjectLinkSets() = %#v, want one complete single-consumer set", sets)
			}
			if got := sets[0].Links[0].ApplicationWorkspaceID; got != workspaceID {
				t.Fatalf("consumer link workspace = %q, want %q", got, workspaceID)
			}
			if got := sets[0].Endpoints[0].ApplicationWorkspaceID; got != workspaceID {
				t.Fatalf("consumer endpoint workspace = %q, want %q", got, workspaceID)
			}

			graph := &projectionRecorder{}
			if _, _, err := New(nil, graph).ProjectWithDelta(context.Background(), event); err != nil {
				t.Fatalf("ProjectWithDelta() error = %v", err)
			}
			findingURN := projectionURN("writer", "vulnview_finding", event.GetAttributes()["finding_id"])
			consumerURN := sets[0].Links[0].ToURN
			if finding := graph.entities[findingURN]; finding == nil || finding.ApplicationWorkspaceID != workspaceID {
				t.Fatalf("finding entity = %#v, want workspace %q", finding, workspaceID)
			}
			stored := graph.linkSetLinks[ports.ProjectedLinkSetOwnerKey(sets[0])][consumerURN]
			if stored == nil || stored.ApplicationWorkspaceID != workspaceID {
				t.Fatalf("persisted consumer link = %#v, want workspace %q", stored, workspaceID)
			}
			if endpoint := graph.entities[consumerURN]; endpoint == nil || !endpoint.CreateOnly || endpoint.ApplicationWorkspaceID != workspaceID {
				t.Fatalf("persisted consumer endpoint = %#v, want a create-only stub in workspace %q", endpoint, workspaceID)
			}
		})
	}
}

// TestVulnViewFindingRetractsConsumersOnAuthoritativeEmptyList pins the
// F03/F10 interaction: a cloud_identity finding version whose export
// marks a genuinely complete, empty consumer list (consumersComplete
// true, no "consumers" event attribute because
// cloudIdentityConsumersSummary flattens an empty array to "") must
// retract a stale non-empty "consumers" attribute a prior version left on
// the finding entity, not merge/keep it indefinitely. consumers_complete
// itself stays present (true), since this observation does carry it.
func TestVulnViewFindingRetractsConsumersOnAuthoritativeEmptyList(t *testing.T) {
	populated := vulnViewCloudIdentityFindingEvent(map[string]string{
		"consumers_complete": "true", "consumers": "prod-use1/billing/billing-worker",
	}, "")
	populatedEntities, _, err := vulnViewFindingProjections(populated)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(populated) error = %v", err)
	}
	populatedFinding := findEntity(populatedEntities, "vulnview.finding")
	if populatedFinding == nil || populatedFinding.Attributes["consumers"] != "prod-use1/billing/billing-worker" {
		t.Fatalf("populated finding entity = %#v, want consumers attribute", populatedFinding)
	}

	emptyAuthoritative := vulnViewCloudIdentityFindingEvent(map[string]string{
		"consumers_complete": "true", "consumers": "", "version": "4",
	}, "")
	emptyEntities, _, err := vulnViewFindingProjections(emptyAuthoritative)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(emptyAuthoritative) error = %v", err)
	}
	emptyFinding := findEntity(emptyEntities, "vulnview.finding")
	if emptyFinding == nil {
		t.Fatal("missing finding entity")
	}
	if _, ok := emptyFinding.Attributes["consumers"]; ok {
		t.Fatalf("Attributes still carries stale consumers: %#v", emptyFinding.Attributes)
	}
	if emptyFinding.Attributes["consumers_complete"] != "true" {
		t.Fatalf("consumers_complete = %q, want true (this observation does carry it)", emptyFinding.Attributes["consumers_complete"])
	}
	retracted := map[string]bool{}
	for _, key := range emptyFinding.RetractedAttributes {
		retracted[key] = true
	}
	if !retracted["consumers"] {
		t.Fatalf("RetractedAttributes = %v, want it to include consumers (a stale list from a prior version)", emptyFinding.RetractedAttributes)
	}
	if retracted["consumers_complete"] {
		t.Fatalf("RetractedAttributes = %v, must not retract consumers_complete (this observation carries it)", emptyFinding.RetractedAttributes)
	}
}

// TestVulnViewFindingRetractsExcessAndSharingOnReset pins the F13
// follow-up: a cloud_identity finding version whose evidence no longer
// carries excess/sharing (the export mirrors the durable row's reset to
// an explicit null, Contract C7/X1) must retract the stale
// excess_declared/excess_observed/sharing_services/sharing_consumer_ids
// attributes a prior version left on the finding entity.
func TestVulnViewFindingRetractsExcessAndSharingOnReset(t *testing.T) {
	withExcess := vulnViewCloudIdentityFindingEvent(map[string]string{
		"excess_declared":  "s3:PutObject(arn:aws:s3:::bucket/*)",
		"excess_observed":  "s3:GetObject(arn:aws:s3:::bucket/*)",
		"sharing_services": "checkout,billing", "sharing_consumer_ids": "w1,w2",
	}, "")
	withExcessEntities, _, err := vulnViewFindingProjections(withExcess)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(withExcess) error = %v", err)
	}
	withExcessFinding := findEntity(withExcessEntities, "vulnview.finding")
	if withExcessFinding == nil || withExcessFinding.Attributes["excess_declared"] == "" || withExcessFinding.Attributes["sharing_services"] == "" {
		t.Fatalf("withExcess finding entity = %#v, want excess/sharing attributes", withExcessFinding)
	}

	reset := vulnViewCloudIdentityFindingEvent(map[string]string{
		"excess_declared": "", "excess_observed": "", "sharing_services": "", "sharing_consumer_ids": "",
		"version": "4",
	}, "")
	resetEntities, _, err := vulnViewFindingProjections(reset)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(reset) error = %v", err)
	}
	resetFinding := findEntity(resetEntities, "vulnview.finding")
	if resetFinding == nil {
		t.Fatal("missing finding entity")
	}
	for _, key := range []string{"excess_declared", "excess_observed", "sharing_services", "sharing_consumer_ids"} {
		if _, ok := resetFinding.Attributes[key]; ok {
			t.Fatalf("Attributes still carries stale %s: %#v", key, resetFinding.Attributes)
		}
	}
	retracted := map[string]bool{}
	for _, key := range resetFinding.RetractedAttributes {
		retracted[key] = true
	}
	for _, key := range []string{"excess_declared", "excess_observed", "sharing_services", "sharing_consumer_ids"} {
		if !retracted[key] {
			t.Fatalf("RetractedAttributes = %v, want it to include %q", resetFinding.RetractedAttributes, key)
		}
	}
}
