package sourceprojection

import (
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/projectionmeta"
)

func vulnViewCloudIdentityFindingEvent(tenant string, attrOverrides map[string]string) *cerebrov1.EventEnvelope {
	attrs := map[string]string{
		"finding_id": "cloud_identity|cloud_identity_excess_privilege|aws|arn:aws:iam::222222222222:role/billing-worker|writer",
		"check_id":   "cloud_identity_excess_privilege", "check_version": "1", "detector_version": "1.0.0",
		"status": "open", "severity": "high", "title": "Excess privilege",
		"cloud_provider": "aws", "account_id": "222222222222", "principal_id": "arn:aws:iam::222222222222:role/billing-worker",
		"principal_kind": "aws_role", "cohort_scope": "writer", "evidence_stream": "security",
		"version": "3", "updated_at": "2026-04-01T09:00:00Z",
	}
	for k, v := range attrOverrides {
		if v == "" {
			delete(attrs, k)
			continue
		}
		attrs[k] = v
	}
	return &cerebrov1.EventEnvelope{
		Id: "event-finding-1", TenantId: tenant, SourceId: "vulnview", Kind: "vulnview.cloud_identity_finding",
		Payload: []byte(`{}`), Attributes: attrs,
	}
}

func TestVulnViewCloudIdentityFindingAWSCanonicalJoin(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent("writer", nil)
	entities, links, err := vulnViewCloudIdentityFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewCloudIdentityFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, vulnViewCloudIdentityFindingEntityType)
	if finding == nil {
		t.Fatalf("missing finding entity; got %v", entityTypes(entities))
	}
	wantPrincipalURN := identityPrincipalURN("writer", "aws", "role", "arn:aws:iam::222222222222:role/billing-worker", "")
	if findLink(links, wantPrincipalURN, finding.URN, relationHasEvidence) == nil {
		t.Fatal("missing canonical AWS principal -has_evidence-> finding join")
	}
	if finding.Attributes["gap_codes"] != "" {
		t.Fatalf("gap_codes = %q, want empty for a fully resolved AWS subject", finding.Attributes["gap_codes"])
	}
}

// VulnView samples updatedAt before its conditional write commits, so a
// concurrent writer can commit a higher finding version with an earlier
// updatedAt. The projected finding must still order by version, in either
// delivery order.
func TestVulnViewCloudIdentityFindingVersionsOrderByVersion(t *testing.T) {
	project := func(version, status, updatedAt string) map[string]string {
		event := vulnViewCloudIdentityFindingEvent("writer", map[string]string{"version": version, "status": status, "updated_at": updatedAt})
		entities, _, err := vulnViewCloudIdentityFindingProjections(event)
		if err != nil {
			t.Fatalf("vulnViewCloudIdentityFindingProjections() error = %v", err)
		}
		finding := findEntity(entities, vulnViewCloudIdentityFindingEntityType)
		if finding == nil {
			t.Fatalf("missing finding entity; got %v", entityTypes(entities))
		}
		return finding.Attributes
	}
	fixed := project("2", "fixed", "2026-11-02T10:00:01.000000Z")
	reopened := project("3", "open", "2026-11-02T10:00:00.000000Z")
	if got := projectionmeta.CompareObservations(fixed, reopened); got != projectionmeta.ObservationNewer {
		t.Fatalf("version 3 after version 2 orders %v, want newer despite its earlier updated_at", got)
	}
	if !projectionmeta.StaleStrictObservation(reopened, fixed) {
		t.Fatal("version 2 replayed after version 3 must be a stale strict observation")
	}
}

func TestVulnViewCloudIdentityFindingGCPCanonicalJoin(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent("writer", map[string]string{
		"cloud_provider": "gcp", "account_id": "", "project_id": "writer-prod",
		"principal_id": "payments-sa@writer-prod.iam.gserviceaccount.com", "principal_kind": "gcp_service_account",
	})
	entities, links, err := vulnViewCloudIdentityFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewCloudIdentityFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, vulnViewCloudIdentityFindingEntityType)
	if finding == nil {
		t.Fatal("missing finding entity")
	}
	wantPrincipalURN := identityPrincipalURN("writer", "gcp", "service_account", "payments-sa@writer-prod.iam.gserviceaccount.com", "")
	if findLink(links, wantPrincipalURN, finding.URN, relationHasEvidence) == nil {
		t.Fatal("missing canonical GCP principal -has_evidence-> finding join")
	}
}

func TestVulnViewCloudIdentityFindingPrincipalURICanonicalJoin(t *testing.T) {
	principalURI := "principal://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/writer-prod.svc.id.goog/subject/ns/payments/sa/api"
	event := vulnViewCloudIdentityFindingEvent("writer", map[string]string{
		"cloud_provider": "gcp", "account_id": "", "principal_id": principalURI, "principal_kind": "gcp_workload_identity_principal",
	})
	entities, links, err := vulnViewCloudIdentityFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewCloudIdentityFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, vulnViewCloudIdentityFindingEntityType)
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
	// Replaying the exact same principal:// string must resolve to the
	// identical URN every time.
	if got := vulnViewCloudIdentityCanonicalPrincipalURN("writer", "gcp", principalURI); got != wantPrincipalURN {
		t.Fatalf("canonical URN not stable across calls: %q != %q", got, wantPrincipalURN)
	}
}

func TestVulnViewCloudIdentityFindingMissingSubjectSurfacedAsGap(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent("writer", map[string]string{"principal_id": "", "cloud_provider": ""})
	entities, links, err := vulnViewCloudIdentityFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewCloudIdentityFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, vulnViewCloudIdentityFindingEntityType)
	if finding == nil {
		t.Fatal("missing finding entity even without a resolvable principal")
	}
	if finding.Attributes["gap_codes"] == "" {
		t.Fatal("expected a non-empty gap_codes attribute for a missing/invalid principal subject")
	}
	for _, link := range links {
		if link.ToURN == finding.URN && link.Relation == relationHasEvidence {
			t.Fatalf("unexpected has_evidence link with no resolvable principal: %+v", link)
		}
	}
}

// TestVulnViewCloudIdentityFindingMalformedAWSPrincipalSurfacedAsGap pins
// defect #5: a non-ARN AWS principal id must never mint a dangling
// canonical role URN, even though it is nonempty.
func TestVulnViewCloudIdentityFindingMalformedAWSPrincipalSurfacedAsGap(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent("writer", map[string]string{"principal_id": "aws", "principal_kind": "aws_role"})
	entities, links, err := vulnViewCloudIdentityFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewCloudIdentityFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, vulnViewCloudIdentityFindingEntityType)
	if finding == nil {
		t.Fatal("missing finding entity even without a resolvable principal")
	}
	if finding.Attributes["gap_codes"] == "" {
		t.Fatal("expected a non-empty gap_codes attribute for a malformed AWS principal id")
	}
	for _, link := range links {
		if link.ToURN == finding.URN && link.Relation == relationHasEvidence {
			t.Fatalf("unexpected has_evidence link for malformed AWS principal id: %+v", link)
		}
	}
}

// TestVulnViewCloudIdentityFindingKubernetesPlaceholderSubjectSurfacedAsGap
// pins defect #5: a raw k8s:// placeholder subject (the collector could not
// yet join this consumer to a cloud principal) must never mint a canonical
// join, even when it reaches the finding family rather than the assessment
// family.
func TestVulnViewCloudIdentityFindingKubernetesPlaceholderSubjectSurfacedAsGap(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent("writer", map[string]string{
		"principal_id": "k8s://prod-eks/billing/sa/worker", "principal_kind": "aws_kubernetes_service_account",
	})
	entities, links, err := vulnViewCloudIdentityFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewCloudIdentityFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, vulnViewCloudIdentityFindingEntityType)
	if finding == nil {
		t.Fatal("missing finding entity even without a resolvable principal")
	}
	if finding.Attributes["gap_codes"] == "" {
		t.Fatal("expected a non-empty gap_codes attribute for a k8s:// placeholder subject")
	}
	for _, link := range links {
		if link.ToURN == finding.URN && link.Relation == relationHasEvidence {
			t.Fatalf("unexpected has_evidence link for a k8s:// placeholder subject: %+v", link)
		}
	}
}

// TestVulnViewCloudIdentityFindingMalformedGCPPrincipalSurfacedAsGap pins
// defect #5 for GCP: a non-email, non-principal:// GCP principal id must
// never mint a dangling canonical service-account URN.
func TestVulnViewCloudIdentityFindingMalformedGCPPrincipalSurfacedAsGap(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent("writer", map[string]string{
		"cloud_provider": "gcp", "account_id": "", "principal_id": "not-an-email", "principal_kind": "gcp_service_account",
	})
	entities, links, err := vulnViewCloudIdentityFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewCloudIdentityFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, vulnViewCloudIdentityFindingEntityType)
	if finding == nil {
		t.Fatal("missing finding entity even without a resolvable principal")
	}
	if finding.Attributes["gap_codes"] == "" {
		t.Fatal("expected a non-empty gap_codes attribute for a malformed GCP principal id")
	}
	for _, link := range links {
		if link.ToURN == finding.URN && link.Relation == relationHasEvidence {
			t.Fatalf("unexpected has_evidence link for malformed GCP principal id: %+v", link)
		}
	}
}

// TestVulnViewCloudIdentityUnresolvedPrincipalSubjectRejectsMalformedAWSValues
// pins the review's exact examples for defect #5: "aws",
// "aws_kubernetes_service_account", and a raw k8s:// subject must all be
// treated as unresolved, never canonicalized into an AWS role URN.
func TestVulnViewCloudIdentityUnresolvedPrincipalSubjectRejectsMalformedAWSValues(t *testing.T) {
	for _, id := range []string{"aws", "aws_kubernetes_service_account", "k8s://cluster/ns/sa/name"} {
		if !vulnViewCloudIdentityUnresolvedPrincipalSubject("aws", "aws_role", id) {
			t.Fatalf("vulnViewCloudIdentityUnresolvedPrincipalSubject(aws, aws_role, %q) = false, want true", id)
		}
	}
}

// TestVulnViewCloudIdentityUnresolvedPrincipalSubjectRejectsMalformedGCPEmail
// pins defect #5 for GCP: a non-email value must never pass validation.
func TestVulnViewCloudIdentityUnresolvedPrincipalSubjectRejectsMalformedGCPEmail(t *testing.T) {
	if !vulnViewCloudIdentityUnresolvedPrincipalSubject("gcp", "gcp_service_account", "not-an-email") {
		t.Fatal("vulnViewCloudIdentityUnresolvedPrincipalSubject(gcp, gcp_service_account, not-an-email) = false, want true")
	}
}

// TestVulnViewCloudIdentityUnresolvedPrincipalSubjectAcceptsResolvedGCPPrincipalURI
// pins Contract H: a fully resolved GCP principal:// subject always passes,
// regardless of kind.
func TestVulnViewCloudIdentityUnresolvedPrincipalSubjectAcceptsResolvedGCPPrincipalURI(t *testing.T) {
	uri := "principal://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/writer-prod.svc.id.goog/subject/ns/payments/sa/api"
	if vulnViewCloudIdentityUnresolvedPrincipalSubject("gcp", "gcp_workload_identity_principal", uri) {
		t.Fatal("vulnViewCloudIdentityUnresolvedPrincipalSubject() = true for a fully resolved principal:// subject, want false")
	}
}

func TestVulnViewCloudIdentityRunProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{
		Id: "event-run-1", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.cloud_identity_run",
		Payload: []byte(`{}`),
		Attributes: map[string]string{
			"scan_id": "scan-1", "run_id": "run-1", "cohort_scope": "writer", "evidence_stream": "security",
			"authoritative": "true", "completed_at": "2026-04-01T09:00:00Z", "detector_version": "1.0.0",
			"bundle_key": "cloud-identity/security/writer/key.json.gz", "bundle_sha256": "abc", "bundle_principal_count": "2",
			"bundle_collected_at": "2026-04-01T08:55:00Z", "reasons": "scan_completed,evidence_fresh",
			"count_supported": "1", "count_candidate": "0", "count_incomplete": "0", "count_clear": "1",
			"collection_coverage_complete": "true", "collection_coverage_gap_codes": "", "collection_coverage_gap_count": "0",
		},
	}
	entities, _, err := vulnViewCloudIdentityRunProjections(event)
	if err != nil {
		t.Fatalf("vulnViewCloudIdentityRunProjections() error = %v", err)
	}
	run := findEntity(entities, vulnViewCloudIdentityRunEntityType)
	if run == nil {
		t.Fatalf("missing run entity; got %v", entityTypes(entities))
	}
	if run.Attributes["scan_id"] != "scan-1" || run.Attributes["run_id"] != "run-1" || run.Attributes["bundle_sha256"] != "abc" {
		t.Fatalf("run attrs = %+v", run.Attributes)
	}
	// Finding #10: reconciliation reasons, bundle collection time, counts,
	// and collection coverage must survive into the run entity's
	// attributes, not just the scan/run identifiers and bundle digest.
	if run.Attributes["reasons"] != "scan_completed,evidence_fresh" {
		t.Fatalf("run.Attributes[reasons] = %q, want scan_completed,evidence_fresh", run.Attributes["reasons"])
	}
	if run.Attributes["bundle_collected_at"] != "2026-04-01T08:55:00Z" {
		t.Fatalf("run.Attributes[bundle_collected_at] = %q", run.Attributes["bundle_collected_at"])
	}
	if run.Attributes["count_supported"] != "1" || run.Attributes["count_clear"] != "1" {
		t.Fatalf("run counts not carried: %+v", run.Attributes)
	}
	if run.Attributes["collection_coverage_complete"] != "true" {
		t.Fatalf("run.Attributes[collection_coverage_complete] = %q, want true", run.Attributes["collection_coverage_complete"])
	}
}

// TestVulnViewCloudIdentityFindingLinksToRunEntity pins finding #10's
// graph-context requirement: a finding carrying lastScanId/lastRunId must
// join -[belongs_to]-> the vulnview.cloud_identity_run entity for that
// run, so a role-centric query starting at the finding can reach the
// run's bundle freshness and coverage without a second lookup.
func TestVulnViewCloudIdentityFindingLinksToRunEntity(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent("writer", map[string]string{
		"last_scan_id": "scan-1", "last_run_id": "run-1", "side": "live", "drift": "false",
		"evidence_bundle_key": "cloud-identity/security/writer/key.json.gz", "evidence_bundle_sha256": "abc",
		"evidence_principal_evidence_sha256": "def", "evidence_collected_at": "2026-04-01T08:55:00Z",
	})
	entities, links, err := vulnViewCloudIdentityFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewCloudIdentityFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, vulnViewCloudIdentityFindingEntityType)
	if finding == nil {
		t.Fatal("missing finding entity")
	}
	if finding.Attributes["last_run_id"] != "run-1" || finding.Attributes["side"] != "live" || finding.Attributes["evidence_bundle_sha256"] != "abc" {
		t.Fatalf("finding attrs missing contracted run/evidence context: %+v", finding.Attributes)
	}
	runURN := projectionURN("writer", vulnViewCloudIdentityRunURNKind, "scan-1", "run-1")
	if findLink(links, finding.URN, runURN, relationBelongsTo) == nil {
		t.Fatal("missing finding -belongs_to-> run join")
	}
}

func TestVulnViewCloudIdentityAssessmentProjectionAndConsumerLinks(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"consumers": []map[string]any{
			{"id": "w1", "cluster": "prod-eks", "namespace": "billing", "serviceAccount": "billing-worker", "cloudAccount": "222222222222"},
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	event := &cerebrov1.EventEnvelope{
		Id: "event-assessment-1", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.cloud_identity_assessment",
		Payload:    payload,
		OccurredAt: timestamppb.New(time.Date(2026, time.April, 1, 9, 10, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"scan_id": "scan-1", "run_id": "run-1", "check_id": "cloud_identity_excess_privilege", "check_version": "1",
			"cloud_provider": "aws", "account_id": "222222222222", "principal_id": "arn:aws:iam::222222222222:role/billing-worker",
			"principal_kind": "aws_role", "cohort_scope": "writer", "status": "supported", "severity": "high", "title": "Excess privilege",
			"finding_id":     "cloud_identity|cloud_identity_excess_privilege|aws|arn:aws:iam::222222222222:role/billing-worker|writer",
			"evidence_fresh": "true",
		},
	}
	entities, links, err := vulnViewCloudIdentityAssessmentProjections(event)
	if err != nil {
		t.Fatalf("vulnViewCloudIdentityAssessmentProjections() error = %v", err)
	}
	assessment := findEntity(entities, vulnViewCloudIdentityAssessmentEntityType)
	if assessment == nil {
		t.Fatalf("missing assessment entity; got %v", entityTypes(entities))
	}
	wantPrincipalURN := identityPrincipalURN("writer", "aws", "role", "arn:aws:iam::222222222222:role/billing-worker", "")
	if findLink(links, wantPrincipalURN, assessment.URN, relationHasEvidence) == nil {
		t.Fatal("missing canonical principal -has_evidence-> assessment join")
	}
	if assessment.Attributes["finding_id"] == "" || assessment.Attributes["evidence_fresh"] != "true" {
		t.Fatalf("assessment attrs missing contracted findingId/evidenceFresh: %+v", assessment.Attributes)
	}
	// Contract G/H: strict observation-time precedence.
	if assessment.Attributes["at"] != "2026-04-01T09:10:00Z" {
		t.Fatalf("assessment.Attributes[at] = %q, want 2026-04-01T09:10:00Z", assessment.Attributes["at"])
	}
	if assessment.Attributes["observation_precedence"] != "strict" {
		t.Fatalf("assessment.Attributes[observation_precedence] = %q, want strict", assessment.Attributes["observation_precedence"])
	}
	ksa := findEntity(entities, "kubernetes.service_account")
	if ksa == nil {
		t.Fatalf("missing cluster-qualified consumer KSA entity; got %v", entityTypes(entities))
	}
	wantKSAURN := kubernetesServiceAccountURN("writer", map[string]string{
		"cluster_id": "222222222222:prod-eks", "namespace": "billing", "service_account_name": "billing-worker",
	})
	if ksa.URN != wantKSAURN {
		t.Fatalf("ksa.URN = %q, want account-qualified %q", ksa.URN, wantKSAURN)
	}
	if findLink(links, assessment.URN, ksa.URN, relationAssociatedWith) == nil {
		t.Fatal("missing assessment -> consumer KSA link")
	}
	runURN := projectionURN("writer", vulnViewCloudIdentityRunURNKind, "scan-1", "run-1")
	if findLink(links, assessment.URN, runURN, relationBelongsTo) == nil {
		t.Fatal("missing assessment -belongs_to-> run join")
	}
}

// TestVulnViewCloudIdentityAssessmentConsumerWithoutAccountOrProjectMintsNoKSALink
// pins defect #2's safety rule for the VulnView assessment consumer path:
// a consumer with neither cloud_account nor cloud_project must never mint
// a collision-prone cluster-name-only KSA URN.
func TestVulnViewCloudIdentityAssessmentConsumerWithoutAccountOrProjectMintsNoKSALink(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"consumers": []map[string]any{
			{"id": "w1", "cluster": "prod-eks", "namespace": "billing", "service_account": "billing-worker"},
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	event := &cerebrov1.EventEnvelope{
		Id: "event-assessment-no-account", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.cloud_identity_assessment",
		Payload: payload,
		Attributes: map[string]string{
			"scan_id": "scan-1", "run_id": "run-1", "check_id": "cloud_identity_excess_privilege", "check_version": "1",
			"cloud_provider": "aws", "account_id": "222222222222", "principal_id": "k8s://prod-eks/billing/sa/billing-worker",
			"principal_kind": "aws_kubernetes_service_account", "cohort_scope": "writer", "status": "incomplete",
		},
	}
	entities, _, err := vulnViewCloudIdentityAssessmentProjections(event)
	if err != nil {
		t.Fatalf("vulnViewCloudIdentityAssessmentProjections() error = %v", err)
	}
	if findEntity(entities, "kubernetes.service_account") != nil {
		t.Fatalf("expected no KSA entity with no cloud_account/cloud_project consumer field; got %v", entityTypes(entities))
	}
}

// TestVulnViewCloudIdentityAssessmentConsumerTwoClustersSameNameDifferentAccountsDistinctNodes
// pins defect #2's collision fix for the VulnView assessment consumer
// path: two clusters sharing a bare name in different AWS accounts must
// mint two distinct KSA nodes.
func TestVulnViewCloudIdentityAssessmentConsumerTwoClustersSameNameDifferentAccountsDistinctNodes(t *testing.T) {
	assessmentEvent := func(id, account string) *cerebrov1.EventEnvelope {
		payload, err := json.Marshal(map[string]any{
			"consumers": []map[string]any{
				{"id": "w1", "cluster": "shared-name", "namespace": "billing", "serviceAccount": "billing-worker", "cloudAccount": account},
			},
		})
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		return &cerebrov1.EventEnvelope{
			Id: id, TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.cloud_identity_assessment",
			Payload: payload,
			Attributes: map[string]string{
				"scan_id": "scan-1", "run_id": "run-1", "check_id": "cloud_identity_excess_privilege", "check_version": "1",
				"cloud_provider": "aws", "account_id": account, "principal_id": "arn:aws:iam::" + account + ":role/billing-worker",
				"principal_kind": "aws_role", "cohort_scope": "writer", "status": "supported",
			},
		}
	}
	entitiesA, _, err := vulnViewCloudIdentityAssessmentProjections(assessmentEvent("event-assessment-cluster-a", "111111111111"))
	if err != nil {
		t.Fatalf("account A error = %v", err)
	}
	entitiesB, _, err := vulnViewCloudIdentityAssessmentProjections(assessmentEvent("event-assessment-cluster-b", "999999999999"))
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

// TestVulnViewCloudIdentityAssessmentConsumerGCPProjectQualified pins
// defect #2 for a GCP assessment's consumer: the KSA URN must be
// qualified by cloud_project, not a bare cluster name.
func TestVulnViewCloudIdentityAssessmentConsumerGCPProjectQualified(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"consumers": []map[string]any{
			{"id": "w1", "cluster": "prod-gke", "namespace": "payments", "serviceAccount": "api", "cloudProject": "writer-prod"},
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	event := &cerebrov1.EventEnvelope{
		Id: "event-assessment-gcp", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.cloud_identity_assessment",
		Payload: payload,
		Attributes: map[string]string{
			"scan_id": "scan-1", "run_id": "run-1", "check_id": "cloud_identity_excess_privilege", "check_version": "1",
			"cloud_provider": "gcp", "project_id": "writer-prod", "principal_id": "payments-sa@writer-prod.iam.gserviceaccount.com",
			"principal_kind": "gcp_service_account", "cohort_scope": "writer", "status": "supported",
		},
	}
	entities, _, err := vulnViewCloudIdentityAssessmentProjections(event)
	if err != nil {
		t.Fatalf("vulnViewCloudIdentityAssessmentProjections() error = %v", err)
	}
	ksa := findEntity(entities, "kubernetes.service_account")
	if ksa == nil {
		t.Fatal("missing kubernetes.service_account entity")
	}
	wantURN := kubernetesServiceAccountURN("writer", map[string]string{
		"cluster_id": "writer-prod:prod-gke", "namespace": "payments", "service_account_name": "api",
	})
	if ksa.URN != wantURN {
		t.Fatalf("ksa.URN = %q, want project-qualified %q", ksa.URN, wantURN)
	}
}

// TestVulnViewCloudIdentityFindingTenantIsolation pins URN tenant scoping
// for the new entity kinds, matching the pattern already pinned for the
// cloud_identity source's own projector.
func TestVulnViewCloudIdentityFindingTenantIsolation(t *testing.T) {
	eventA := vulnViewCloudIdentityFindingEvent("tenant-a", nil)
	entitiesA, _, err := vulnViewCloudIdentityFindingProjections(eventA)
	if err != nil {
		t.Fatalf("tenant-a error = %v", err)
	}
	eventB := vulnViewCloudIdentityFindingEvent("tenant-b", nil)
	entitiesB, _, err := vulnViewCloudIdentityFindingProjections(eventB)
	if err != nil {
		t.Fatalf("tenant-b error = %v", err)
	}
	findingA := findEntity(entitiesA, vulnViewCloudIdentityFindingEntityType)
	findingB := findEntity(entitiesB, vulnViewCloudIdentityFindingEntityType)
	if findingA == nil || findingB == nil {
		t.Fatal("missing finding entity for one of the tenants")
	}
	if findingA.URN == findingB.URN {
		t.Fatalf("finding URN collided across tenants: %q", findingA.URN)
	}
	if findingA.TenantID != "tenant-a" || findingB.TenantID != "tenant-b" {
		t.Fatalf("TenantID = %q/%q, want tenant-a/tenant-b", findingA.TenantID, findingB.TenantID)
	}
}
