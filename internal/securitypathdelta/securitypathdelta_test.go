package securitypathdelta

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/attackpath"
)

func TestSnapshotPathIdentityIgnoresInputOrderAndLabels(t *testing.T) {
	observedAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	first := testPath("resource-a", "principal-a", "permission-a", "runs_as", "first labels", observedAt)
	second := testPath("resource-b", "principal-b", "permission-b", "attached_to", "second labels", observedAt)

	left := mustSnapshot(t, snapshotInput("run-a", observedAt, true, first, second))
	first.Path.ExposedResource.Label = "renamed resource"
	first.Path.PublicPrincipal.Label = "renamed public principal"
	first.Path.ExposureEdge.From.Label = "renamed public principal"
	first.Path.ExposureEdge.To.Label = "renamed resource"
	first.Path.TraversalEdges[0].From.Label = "renamed resource"
	right := mustSnapshot(t, snapshotInput("run-b", observedAt.Add(time.Minute), true, second, first))

	if left.PathSetDigest != right.PathSetDigest {
		t.Fatalf("path set digest changed after reorder/labels: %q != %q", left.PathSetDigest, right.PathSetDigest)
	}
	leftIDs := pathIdentityByRoute(left.Paths)
	rightIDs := pathIdentityByRoute(right.Paths)
	if len(leftIDs) != len(rightIDs) {
		t.Fatalf("path identity count changed: %d != %d", len(leftIDs), len(rightIDs))
	}
	for routeID, pathID := range leftIDs {
		if rightIDs[routeID] != pathID {
			t.Fatalf("route %q path ID changed after reorder/labels: %q != %q", routeID, pathID, rightIDs[routeID])
		}
	}
}

func TestCompareReportsProofChangeWithoutReportingNewRoute(t *testing.T) {
	beforeAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	beforePath := testPath("resource-a", "principal-a", "permission-a", "runs_as", "before", beforeAt)
	afterPath := testPath("resource-a", "principal-a", "permission-a", "attached_to", "after", beforeAt.Add(time.Minute))
	before := mustSnapshot(t, snapshotInput("run-before", beforeAt, true, beforePath))
	after := mustSnapshot(t, snapshotInput("run-after", beforeAt.Add(time.Minute), true, afterPath))

	delta, err := Compare(&before, after)
	if err != nil {
		t.Fatal(err)
	}
	if delta.State != DeltaStateCompared || len(delta.ProofChanged) != 1 || len(delta.NewlyObserved) != 0 || len(delta.NoLongerObserved) != 0 {
		t.Fatalf("delta = %#v, want one proof change only", delta)
	}
	change := delta.ProofChanged[0]
	if change.BeforePaths[0].RouteID != change.AfterPaths[0].RouteID || change.BeforePaths[0].ID == change.AfterPaths[0].ID {
		t.Fatalf("proof change identities = %#v", change)
	}
	if len(change.AfterPaths[0].Ownerships) != 1 || change.AfterPaths[0].Ownerships[0].Owner.ID != "urn:owner:platform" || len(change.AfterPaths[0].Provenance) == 0 || change.AfterPaths[0].Provenance[0].EventID == "" {
		t.Fatalf("owner/provenance not copied from attack path: %#v", change.AfterPaths[0])
	}
}

func TestCompareReportsSourceProofChangeOnTheSameRoute(t *testing.T) {
	beforeAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	beforePath := testPath("resource-a", "principal-a", "permission-a", "runs_as", "before", beforeAt)
	afterPath := beforePath
	afterPath.Path.ExposureEdge.SourceEventID = "event-exposure-refresh"
	afterPath.Path.ExposureEdge.ObservedAt = beforeAt.Add(time.Minute)
	before := mustSnapshot(t, snapshotInput("run-before", beforeAt, true, beforePath))
	after := mustSnapshot(t, snapshotInput("run-after", beforeAt.Add(time.Minute), true, afterPath))

	delta, err := Compare(&before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.ProofChanged) != 1 || delta.ProofChanged[0].BeforePaths[0].RouteID != delta.ProofChanged[0].AfterPaths[0].RouteID {
		t.Fatalf("delta = %#v, want source proof change on the same route", delta)
	}
}

func TestCompareAssertsAddedAndRemovedOnlyForCompleteSnapshots(t *testing.T) {
	beforeAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	oldPath := testPath("resource-old", "principal-old", "permission-old", "runs_as", "old", beforeAt)
	newPath := testPath("resource-new", "principal-new", "permission-new", "runs_as", "new", beforeAt.Add(time.Minute))
	before := mustSnapshot(t, snapshotInput("run-before", beforeAt, true, oldPath))
	completeAfter := mustSnapshot(t, snapshotInput("run-complete", beforeAt.Add(time.Minute), true, newPath))

	completeDelta, err := Compare(&before, completeAfter)
	if err != nil {
		t.Fatal(err)
	}
	if len(completeDelta.NewlyObserved) != 1 || len(completeDelta.NoLongerObserved) != 1 {
		t.Fatalf("complete delta changes = %#v", completeDelta)
	}

	incompleteAfter := mustSnapshot(t, snapshotInput("run-incomplete", beforeAt.Add(2*time.Minute), false, newPath))
	incompleteDelta, err := Compare(&before, incompleteAfter)
	if err != nil {
		t.Fatal(err)
	}
	if incompleteAfter.Completeness.State != CompletenessIncomplete || incompleteDelta.State != DeltaStateIndeterminate ||
		len(incompleteDelta.NewlyObserved) != 0 || len(incompleteDelta.NoLongerObserved) != 0 || len(incompleteDelta.ProofChanged) != 0 {
		t.Fatalf("incomplete delta asserted a change: %#v", incompleteDelta)
	}
}

func TestSnapshotMissingSourceProofIsIncomplete(t *testing.T) {
	observedAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	path := testPath("resource-a", "principal-a", "permission-a", "runs_as", "missing proof", observedAt)
	path.Path.PrivilegeEdge.SourceEventID = ""
	snapshot := mustSnapshot(t, snapshotInput("run-incomplete-proof", observedAt, true, path))
	if snapshot.Completeness.State != CompletenessIncomplete || !containsReason(snapshot.Completeness.Reasons, "proof_edge_event_missing") {
		t.Fatalf("snapshot completeness = %#v, want missing proof event reason", snapshot.Completeness)
	}
}

func TestSnapshotRequiresCurrentReceiptForEveryProofRuntime(t *testing.T) {
	observedAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	path := testPath("resource-a", "principal-a", "permission-a", "runs_as", "mixed runtime", observedAt)
	path.Path.PrivilegeEdge.SourceRuntimeID = "runtime-effective-permission"
	input := snapshotInput("run-mixed", observedAt, true, path)

	missing := mustSnapshot(t, input)
	if missing.Completeness.State != CompletenessIncomplete || !containsReason(missing.Completeness.Reasons, "proof_runtime_receipt_missing:runtime-effective-permission") {
		t.Fatalf("missing runtime receipt completeness = %#v", missing.Completeness)
	}

	input.Receipt.RuntimeReceipts = []RuntimeCollectionReceiptInput{{
		SourceRuntimeID:         "runtime-effective-permission",
		SourceID:                "aws",
		ProviderFamily:          "effective_permissions",
		ConfigRevision:          "sha256:effective-permission-config",
		RuntimeWatermark:        observedAt.Add(-2 * time.Minute),
		LastSyncedAt:            observedAt.Add(-time.Minute),
		GraphCheckpointID:       "checkpoint-effective-permission",
		GraphRunID:              "graph-effective-permission",
		GraphRunStartedAt:       observedAt.Add(-40 * time.Second),
		GraphRunFinishedAt:      observedAt.Add(-30 * time.Second),
		GraphCheckpointComplete: true,
		GraphCheckpointCurrent:  true,
	}}
	complete := mustSnapshot(t, input)
	if complete.Completeness.State != CompletenessComplete || len(complete.Receipt.ProofRuntimeIDs) != 2 || len(complete.Receipt.RuntimeReceipts) != 2 {
		t.Fatalf("covered mixed-runtime snapshot = %#v", complete)
	}
}

func TestVerificationRequiresCompleteAfterAndChecksEquivalentRoute(t *testing.T) {
	beforeAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	referencePath := testPath("resource-a", "principal-a", "permission-a", "runs_as", "before", beforeAt)
	equivalentRoute := testPath("resource-a", "principal-a", "permission-a", "attached_to", "after", beforeAt.Add(time.Minute))
	reference := mustSnapshot(t, snapshotInput("run-before", beforeAt, true, referencePath))
	completeAfter := mustSnapshot(t, snapshotInput("run-after", beforeAt.Add(time.Minute), true, equivalentRoute))

	verification, err := VerifyObservedAbsent(reference, completeAfter, []string{reference.Paths[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if verification.State != VerificationStillObserved || len(verification.StillObserved) != 1 || verification.StillObserved[0].RouteID != reference.Paths[0].RouteID {
		t.Fatalf("equivalent route verification = %#v, want still_observed", verification)
	}

	incompleteAfter := mustSnapshot(t, snapshotInput("run-incomplete", beforeAt.Add(2*time.Minute), false))
	verification, err = VerifyObservedAbsent(reference, incompleteAfter, []string{reference.Paths[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if verification.State != VerificationIndeterminate {
		t.Fatalf("incomplete verification state = %q, want indeterminate", verification.State)
	}

	completeAbsent := mustSnapshot(t, snapshotInput("run-absent", beforeAt.Add(3*time.Minute), true))
	verification, err = VerifyObservedAbsent(reference, completeAbsent, []string{reference.Paths[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if verification.State != VerificationIndeterminate || !containsReason(verification.Reasons, "verification_runtime_scope_missing:runtime-aws") {
		t.Fatalf("unscoped absent verification = %#v, want explicit reference runtime scope", verification)
	}

	coveredAbsentInput := snapshotInput("run-covered-absent", beforeAt.Add(4*time.Minute), true)
	coveredAbsentInput.RequiredProofRuntimeIDs = []string{"runtime-aws"}
	coveredAbsent := mustSnapshot(t, coveredAbsentInput)
	verification, err = VerifyObservedAbsent(reference, coveredAbsent, []string{reference.Paths[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if verification.State != VerificationObservedAbsent {
		t.Fatalf("covered absent verification state = %#v, want observed_absent", verification)
	}

	checkpointOnlyInput := snapshotInput("run-checkpoint-only", beforeAt.Add(5*time.Minute), true)
	checkpointOnlyInput.RequiredProofRuntimeIDs = []string{"runtime-aws"}
	checkpointOnlyInput.Receipt.CollectionMode = CollectionModeCheckpointed
	checkpointOnly := mustSnapshot(t, checkpointOnlyInput)
	verification, err = VerifyObservedAbsent(reference, checkpointOnly, []string{reference.Paths[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if verification.State != VerificationIndeterminate || !containsReason(verification.Reasons, "fresh_graph_collection_required") {
		t.Fatalf("checkpoint-only verification = %#v, want fresh collection requirement", verification)
	}
}

func TestSnapshotRequiresReceiptsForExplicitRuntimeScopeWithoutPaths(t *testing.T) {
	observedAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	input := snapshotInput("run-empty", observedAt, true)
	input.RequiredProofRuntimeIDs = []string{"runtime-reference"}

	missing := mustSnapshot(t, input)
	if missing.Completeness.State != CompletenessIncomplete || !containsReason(missing.Completeness.Reasons, "proof_runtime_receipt_missing:runtime-reference") {
		t.Fatalf("empty scoped snapshot completeness = %#v, want missing reference runtime receipt", missing.Completeness)
	}

	input.Receipt.RuntimeReceipts = []RuntimeCollectionReceiptInput{
		testRuntimeReceiptInput("runtime-reference", "inventory", "sha256:reference-config", observedAt),
	}
	covered := mustSnapshot(t, input)
	if covered.Completeness.State != CompletenessComplete || len(covered.Receipt.ProofRuntimeIDs) != 1 || covered.Receipt.ProofRuntimeIDs[0] != "runtime-reference" {
		t.Fatalf("covered empty snapshot = %#v, want complete explicit runtime scope", covered)
	}
}

func TestReceiptNormalizesAndBindsProviderFamilyAndConfigRevision(t *testing.T) {
	observedAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	input := snapshotInput("run-receipt-identity", observedAt, true)
	input.Receipt.ProviderFamily = "  INVENTORY  "
	input.Receipt.ConfigRevision = "  sha256:config-a  "
	input.Receipt.RuntimeReceipts = []RuntimeCollectionReceiptInput{
		testRuntimeReceiptInput("runtime-secondary", "  EFFECTIVE_PERMISSIONS  ", "  sha256:secondary-a  ", observedAt),
	}
	input.RequiredProofRuntimeIDs = []string{"runtime-aws", "runtime-secondary"}

	first := mustSnapshot(t, input)
	if first.Receipt.ProviderFamily != "inventory" || first.Receipt.ConfigRevision != "sha256:config-a" {
		t.Fatalf("normalized primary receipt = %#v", first.Receipt)
	}
	if len(first.Receipt.RuntimeReceipts) != 2 || first.Receipt.RuntimeReceipts[1].ProviderFamily != "effective_permissions" || first.Receipt.RuntimeReceipts[1].ConfigRevision != "sha256:secondary-a" {
		t.Fatalf("normalized runtime receipt = %#v", first.Receipt.RuntimeReceipts)
	}

	input.Receipt.ConfigRevision = "sha256:config-b"
	second := mustSnapshot(t, input)
	if first.Receipt.ID == second.Receipt.ID || first.Receipt.Digest == second.Receipt.Digest || first.Digest == second.Digest {
		t.Fatalf("configuration revision did not change receipt identity/digests: first=%#v second=%#v", first.Receipt, second.Receipt)
	}

	input.Receipt.ConfigRevision = "sha256:config-a"
	input.Receipt.RuntimeReceipts[0].ConfigRevision = "sha256:secondary-b"
	third := mustSnapshot(t, input)
	if first.Receipt.ID != third.Receipt.ID || first.Receipt.Digest == third.Receipt.Digest || first.Digest == third.Digest {
		t.Fatalf("supplemental configuration revision not bound to receipt/snapshot digest: first=%#v third=%#v", first.Receipt, third.Receipt)
	}
}

func TestSnapshotRequiresCollectionIdentityForEveryProofRuntime(t *testing.T) {
	observedAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	input := snapshotInput("run-missing-identity", observedAt, true)
	input.RequiredProofRuntimeIDs = []string{"runtime-secondary"}
	secondary := testRuntimeReceiptInput("runtime-secondary", "", "", observedAt)
	input.Receipt.RuntimeReceipts = []RuntimeCollectionReceiptInput{secondary}

	snapshot := mustSnapshot(t, input)
	if snapshot.Completeness.State != CompletenessIncomplete ||
		!containsReason(snapshot.Completeness.Reasons, "proof_runtime:runtime-secondary:provider_family_missing") ||
		!containsReason(snapshot.Completeness.Reasons, "proof_runtime:runtime-secondary:config_revision_missing") {
		t.Fatalf("missing runtime collection identity completeness = %#v", snapshot.Completeness)
	}
}

func TestVerificationRefusesProviderFamilyOrConfigRevisionChange(t *testing.T) {
	beforeAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	reference := mustSnapshot(t, snapshotInput("run-reference", beforeAt, true, testPath("resource-a", "principal-a", "permission-a", "runs_as", "before", beforeAt)))

	afterInput := snapshotInput("run-after", beforeAt.Add(time.Minute), true)
	afterInput.RequiredProofRuntimeIDs = []string{"runtime-aws"}
	afterInput.Receipt.ProviderFamily = "identity"
	afterInput.Receipt.ConfigRevision = "sha256:config-b"
	after := mustSnapshot(t, afterInput)
	verification, err := VerifyObservedAbsent(reference, after, []string{reference.Paths[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if verification.State != VerificationIndeterminate ||
		!containsReason(verification.Reasons, "verification_runtime_provider_family_changed:runtime-aws") ||
		!containsReason(verification.Reasons, "verification_runtime_config_revision_changed:runtime-aws") {
		t.Fatalf("changed collection identity verification = %#v, want provider and config reasons", verification)
	}
}

func TestVerificationRefusesSupplementalRuntimeConfigRevisionChange(t *testing.T) {
	beforeAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	referencePath := testPath("resource-a", "principal-a", "permission-a", "runs_as", "before", beforeAt)
	referencePath.Path.PrivilegeEdge.SourceRuntimeID = "runtime-secondary"
	referenceInput := snapshotInput("run-reference-mixed", beforeAt, true, referencePath)
	referenceInput.Receipt.RuntimeReceipts = []RuntimeCollectionReceiptInput{
		testRuntimeReceiptInput("runtime-secondary", "effective_permissions", "sha256:secondary-a", beforeAt),
	}
	reference := mustSnapshot(t, referenceInput)

	afterAt := beforeAt.Add(time.Minute)
	afterInput := snapshotInput("run-after-mixed", afterAt, true)
	afterInput.RequiredProofRuntimeIDs = []string{"runtime-aws", "runtime-secondary"}
	afterInput.Receipt.RuntimeReceipts = []RuntimeCollectionReceiptInput{
		testRuntimeReceiptInput("runtime-secondary", "effective_permissions", "sha256:secondary-b", afterAt),
	}
	after := mustSnapshot(t, afterInput)
	verification, err := VerifyObservedAbsent(reference, after, []string{reference.Paths[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if verification.State != VerificationIndeterminate || !containsReason(verification.Reasons, "verification_runtime_config_revision_changed:runtime-secondary") {
		t.Fatalf("changed supplemental runtime verification = %#v, want config revision reason", verification)
	}
}

func TestCandidateEdgeCutsRankSharedObservedEdgeByCoverage(t *testing.T) {
	observedAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	first := testPath("resource-a", "principal-a", "permission-a", "runs_as", "first", observedAt)
	second := testPath("resource-a", "principal-b", "permission-b", "attached_to", "second", observedAt)
	snapshot := mustSnapshot(t, snapshotInput("run-a", observedAt, true, first, second))

	candidates := RankCandidateEdgeCuts(snapshot.Paths)
	if len(candidates) == 0 {
		t.Fatal("candidate edge cuts are empty")
	}
	if candidates[0].Edge.Relation != "can_reach" || candidates[0].RouteCoverage != 2 || candidates[0].PathCoverage != 2 || candidates[0].State != candidateEdgeCutState {
		t.Fatalf("top candidate = %#v, want shared observed exposure edge", candidates[0])
	}
	if candidates[0].Rank != 1 {
		t.Fatalf("top candidate rank = %d, want 1", candidates[0].Rank)
	}
}

func testPath(resource, principal, permission, traversalRelation, label string, observedAt time.Time) ObservedPath {
	public := attackpath.NodeRef{URN: "urn:public", EntityType: "aws.public_principal", Label: "public internet " + label}
	exposed := attackpath.NodeRef{URN: "urn:" + resource, EntityType: "aws.compute", Label: resource + " " + label}
	account := attackpath.NodeRef{URN: "urn:account", EntityType: "cloud.account", Label: "production"}
	principalNode := attackpath.NodeRef{URN: "urn:" + principal, EntityType: "aws.iam.role", Label: principal + " " + label}
	permissionNode := attackpath.NodeRef{URN: "urn:" + permission, EntityType: "aws.iam.permission", Label: permission + " " + label}
	owner := attackpath.NodeRef{URN: "urn:owner:platform", EntityType: "owner.team", Label: "Platform"}
	edge := func(from attackpath.NodeRef, relation string, to attackpath.NodeRef, eventID string) attackpath.Edge {
		return attackpath.Edge{
			From: from, Relation: relation, To: to, Direction: "forward",
			SourceID: "aws", SourceRuntimeID: "runtime-aws", SourceEventID: eventID, ObservedAt: observedAt,
		}
	}
	return ObservedPath{Path: attackpath.Path{
		PublicPrincipal:       public,
		ExposedResource:       exposed,
		CloudAccount:          account,
		Principal:             principalNode,
		Permission:            permissionNode,
		Ownerships:            []attackpath.Ownership{{Owner: owner, Edge: edge(exposed, "owned_by", owner, "event-owner")}},
		ReachRelation:         "can_reach",
		AccessRelation:        "can_admin",
		RelationChain:         []string{traversalRelation},
		ExposureEdge:          edge(public, "can_reach", exposed, "event-exposure"),
		ResourceAccountEdge:   edge(exposed, "belongs_to", account, "event-resource-account"),
		TraversalEdges:        []attackpath.Edge{edge(exposed, traversalRelation, principalNode, "event-traversal")},
		PrivilegeEdge:         edge(principalNode, "can_admin", permissionNode, "event-privilege"),
		PermissionAccountEdge: edge(permissionNode, "belongs_to", account, "event-permission-account"),
	}}
}

func snapshotInput(observationID string, observedAt time.Time, complete bool, paths ...ObservedPath) SnapshotInput {
	receipt := CollectionReceiptInput{
		SourceRuntimeID:    "runtime-aws",
		SourceID:           "aws",
		ProviderFamily:     "inventory",
		ConfigRevision:     "sha256:config-a",
		RuntimeWatermark:   observedAt.Add(-2 * time.Minute),
		LastSyncedAt:       observedAt.Add(-time.Minute),
		CollectionMode:     CollectionModeGraphResetFullScan,
		GraphCheckpointID:  "checkpoint-aws",
		GraphRunID:         observationID + "-graph",
		GraphRunStartedAt:  observedAt.Add(-30 * time.Second),
		GraphRunFinishedAt: observedAt.Add(-20 * time.Second),
		CollectionGraphProjectionReceipt: CollectionGraphProjectionReceipt{
			GraphPagesRead: 1,
		},
		GraphMaterialLinkReconciliationRequested: true,
		GraphMaterialLinkReconciliationSupported: true,
		GraphMaterialLinkReconciliationCompleted: true,
		GraphCheckpointComplete:                  true,
		GraphCheckpointCurrent:                   true,
		ObservedPathCount:                        len(paths),
		TotalPathCount:                           len(paths),
		LeaseHeld:                                true,
	}
	if !complete {
		receipt.GraphCheckpointCurrent = false
		receipt.Limitations = []string{"graph advanced during collection"}
	}
	return SnapshotInput{
		TenantID:         "tenant-a",
		ScopeID:          "production",
		DetectorID:       "cloud-public-exposure-privileged-principal",
		DetectorRevision: "v1",
		ObservationID:    observationID,
		ObservedAt:       observedAt,
		Receipt:          receipt,
		Paths:            paths,
	}
}

func testRuntimeReceiptInput(runtimeID string, family string, revision string, observedAt time.Time) RuntimeCollectionReceiptInput {
	return RuntimeCollectionReceiptInput{
		SourceRuntimeID:         runtimeID,
		SourceID:                "aws",
		ProviderFamily:          family,
		ConfigRevision:          revision,
		RuntimeWatermark:        observedAt.Add(-2 * time.Minute),
		LastSyncedAt:            observedAt.Add(-time.Minute),
		GraphCheckpointID:       "checkpoint-" + runtimeID,
		GraphRunID:              "graph-" + runtimeID,
		GraphRunStartedAt:       observedAt.Add(-40 * time.Second),
		GraphRunFinishedAt:      observedAt.Add(-30 * time.Second),
		GraphCheckpointComplete: true,
		GraphCheckpointCurrent:  true,
	}
}

func mustSnapshot(t *testing.T, input SnapshotInput) Snapshot {
	t.Helper()
	snapshot, err := NewSnapshot(input)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func pathIdentityByRoute(paths []SecurityPath) map[string]string {
	result := make(map[string]string, len(paths))
	for _, path := range paths {
		result[path.RouteID] = path.ID
	}
	return result
}

func containsReason(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
