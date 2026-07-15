package securitypathdelta

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/attackpath"
)

const (
	materialityCritical                = "critical"
	reasonPublicToPrivileged           = "public_to_privileged"
	candidateEdgeCutState              = "candidate_only"
	CollectionModeCheckpointed         = "checkpointed"
	CollectionModeSourceSyncProjection = "source_sync_projection"
	CollectionModeGraphResetFullScan   = "graph_reset_full_scan"
)

func NewSnapshot(input SnapshotInput) (Snapshot, error) {
	tenantID := strings.TrimSpace(input.TenantID)
	scopeID := strings.TrimSpace(input.ScopeID)
	detectorID := strings.TrimSpace(input.DetectorID)
	detectorRevision := strings.TrimSpace(input.DetectorRevision)
	observationID := strings.TrimSpace(input.ObservationID)
	observedAt := canonicalTime(input.ObservedAt)
	if tenantID == "" || scopeID == "" || detectorID == "" || detectorRevision == "" || observationID == "" || observedAt.IsZero() {
		return Snapshot{}, fmt.Errorf("%w: snapshot identity and observation time are required", ErrInvalidInput)
	}

	paths := make([]SecurityPath, 0, len(input.Paths))
	seen := make(map[string]SecurityPath, len(input.Paths))
	for _, observed := range input.Paths {
		path, pathErr := normalizePath(tenantID, observed)
		if pathErr != nil {
			return Snapshot{}, pathErr
		}
		if existing, ok := seen[path.ID]; ok {
			if !sameCanonicalValue(existing, path) {
				return Snapshot{}, fmt.Errorf("%w: path %q has conflicting operator context", ErrInvalidInput, path.ID)
			}
			continue
		}
		seen[path.ID] = path
		paths = append(paths, path)
	}
	sortSecurityPaths(paths)
	proofRuntimeIDs := normalizedStrings(append(securityPathRuntimeIDs(paths), input.RequiredProofRuntimeIDs...))
	incompleteReasons := append([]string(nil), input.IncompleteReasons...)
	for _, path := range paths {
		for _, edge := range path.ProofEdges {
			incompleteReasons = append(incompleteReasons, missingProvenanceReasons(edge)...)
		}
		for _, ownership := range path.Ownerships {
			incompleteReasons = append(incompleteReasons, missingProvenanceReasons(ownership.Edge)...)
		}
	}
	receipt, completeness, err := newCollectionReceipt(observationID, observedAt, input.Receipt, incompleteReasons, len(paths), proofRuntimeIDs)
	if err != nil {
		return Snapshot{}, err
	}

	pathIDs := make([]string, 0, len(paths))
	for _, path := range paths {
		pathIDs = append(pathIDs, path.ID)
	}
	pathSetDigest, err := digestValue(struct {
		Version string   `json:"version"`
		Paths   []string `json:"paths"`
	}{Version: "security-path-set/v1", Paths: pathIDs})
	if err != nil {
		return Snapshot{}, err
	}

	snapshot := Snapshot{
		ID: digestStrings(
			"security-path-snapshot/v1",
			tenantID,
			scopeID,
			detectorID,
			detectorRevision,
			observationID,
		),
		TenantID:         tenantID,
		ScopeID:          scopeID,
		DetectorID:       detectorID,
		DetectorRevision: detectorRevision,
		ObservationID:    observationID,
		ObservedAt:       observedAt,
		Receipt:          receipt,
		Completeness:     completeness,
		Paths:            paths,
		PathSetDigest:    pathSetDigest,
	}
	snapshot.Digest, err = digestValue(snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func normalizePath(tenantID string, input ObservedPath) (SecurityPath, error) {
	raw := input.Path
	if strings.TrimSpace(raw.PublicPrincipal.URN) == "" || strings.TrimSpace(raw.ExposedResource.URN) == "" ||
		strings.TrimSpace(raw.CloudAccount.URN) == "" || strings.TrimSpace(raw.Principal.URN) == "" ||
		strings.TrimSpace(raw.Permission.URN) == "" || strings.TrimSpace(raw.ReachRelation) == "" ||
		strings.TrimSpace(raw.AccessRelation) == "" || !attackpath.BoundaryProofMatches(raw) || !attackpath.AccountProofMatches(raw) || !attackpath.TraversalProofMatches(raw.RelationChain, raw.TraversalEdges) {
		return SecurityPath{}, fmt.Errorf("%w: attack path must include endpoints and a valid traversal proof", ErrInvalidInput)
	}

	publicPrincipal := nodeRef(raw.PublicPrincipal)
	exposedResource := nodeRef(raw.ExposedResource)
	cloudAccount := nodeRef(raw.CloudAccount)
	principal := nodeRef(raw.Principal)
	permission := nodeRef(raw.Permission)

	edges := make([]ProofEdge, 0, len(raw.TraversalEdges)+4)
	edges = append(edges, proofEdge(raw.ExposureEdge))
	edges = append(edges, proofEdge(raw.ResourceAccountEdge))
	for _, edge := range raw.TraversalEdges {
		edges = append(edges, proofEdge(edge))
	}
	edges = append(edges, proofEdge(raw.PrivilegeEdge))
	edges = append(edges, proofEdge(raw.PermissionAccountEdge))

	routeID := digestStrings(
		"security-route/v1",
		tenantID,
		publicPrincipal.URN,
		exposedResource.URN,
		cloudAccount.URN,
		principal.URN,
		permission.URN,
	)
	ownerships, err := normalizeOwnerships(raw.ExposedResource, raw.Ownerships)
	if err != nil {
		return SecurityPath{}, err
	}
	proofDigest, err := digestValue(struct {
		Version    string                   `json:"version"`
		Edges      []proofEvidenceEdge      `json:"edges"`
		Ownerships []ownershipProofEvidence `json:"ownerships,omitempty"`
	}{Version: "security-path-proof/v2", Edges: proofEvidenceEdges(edges), Ownerships: ownershipProofEvidenceValues(ownerships)})
	if err != nil {
		return SecurityPath{}, err
	}

	provenance := provenanceFromEdges(edges)
	for _, ownership := range ownerships {
		provenance = append(provenance, provenanceFromEdges([]ProofEdge{ownership.Edge})...)
	}
	provenance = normalizeProvenance(append(provenance, input.Provenance...))
	ownershipState := "unassigned"
	if len(ownerships) == 1 {
		ownershipState = "assigned"
	} else if len(ownerships) > 1 {
		ownershipState = "multiple"
	}
	path := SecurityPath{
		ID:              digestStrings("security-path/v2", routeID, proofDigest),
		RouteID:         routeID,
		ProofDigest:     proofDigest,
		Materiality:     materialityCritical,
		ReasonCodes:     []string{reasonPublicToPrivileged},
		PublicPrincipal: publicPrincipal,
		ExposedResource: exposedResource,
		CloudAccount:    cloudAccount,
		Principal:       principal,
		Permission:      permission,
		ProofEdges:      edges,
		OwnershipState:  ownershipState,
		Ownerships:      ownerships,
		Provenance:      provenance,
	}
	return path, nil
}

func proofEdge(value attackpath.Edge) ProofEdge {
	from := nodeRef(value.From)
	to := nodeRef(value.To)
	relation := strings.TrimSpace(value.Relation)
	direction := strings.TrimSpace(value.Direction)
	return ProofEdge{
		ID:                  digestStrings("security-path-edge/v1", from.URN, relation, to.URN, direction),
		From:                from,
		Relation:            relation,
		To:                  to,
		Direction:           direction,
		SourceID:            strings.TrimSpace(value.SourceID),
		SourceRuntimeID:     strings.TrimSpace(value.SourceRuntimeID),
		AssertionRuntimeIDs: normalizedStrings(append(append([]string(nil), value.AssertionRuntimeIDs...), value.SourceRuntimeID)),
		SourceEventID:       strings.TrimSpace(value.SourceEventID),
		ObservedAt:          canonicalTime(value.ObservedAt),
	}
}

type proofEvidenceEdge struct {
	ID                  string    `json:"id"`
	SourceID            string    `json:"source_id,omitempty"`
	SourceRuntimeID     string    `json:"source_runtime_id,omitempty"`
	AssertionRuntimeIDs []string  `json:"assertion_runtime_ids,omitempty"`
	SourceEventID       string    `json:"source_event_id,omitempty"`
	ObservedAt          time.Time `json:"observed_at,omitempty"`
}

type ownershipProofEvidence struct {
	OwnerID string            `json:"owner_id"`
	Edge    proofEvidenceEdge `json:"edge"`
}

func proofEvidenceEdges(edges []ProofEdge) []proofEvidenceEdge {
	result := make([]proofEvidenceEdge, 0, len(edges))
	for _, edge := range edges {
		result = append(result, proofEvidenceEdge{
			ID: edge.ID, SourceID: edge.SourceID, SourceRuntimeID: edge.SourceRuntimeID,
			AssertionRuntimeIDs: append([]string(nil), edge.AssertionRuntimeIDs...), SourceEventID: edge.SourceEventID, ObservedAt: edge.ObservedAt,
		})
	}
	return result
}

func ownershipProofEvidenceValues(values []OwnershipProof) []ownershipProofEvidence {
	result := make([]ownershipProofEvidence, 0, len(values))
	for _, value := range values {
		result = append(result, ownershipProofEvidence{OwnerID: value.Owner.ID, Edge: proofEvidenceEdges([]ProofEdge{value.Edge})[0]})
	}
	return result
}

func normalizeOwnerships(exposed attackpath.NodeRef, values []attackpath.Ownership) ([]OwnershipProof, error) {
	result := make([]OwnershipProof, 0, len(values))
	for _, value := range values {
		owner := OwnerRef{ID: strings.TrimSpace(value.Owner.URN), Name: strings.TrimSpace(value.Owner.Label)}
		edge := proofEdge(value.Edge)
		if owner.ID == "" || edge.Relation != "owned_by" || edge.Direction != "forward" ||
			edge.From.URN != strings.TrimSpace(exposed.URN) || edge.To.URN != owner.ID {
			return nil, fmt.Errorf("%w: ownership proof must bind the exposed resource to its owner", ErrInvalidInput)
		}
		result = append(result, OwnershipProof{Owner: owner, Edge: edge})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Owner.ID != result[j].Owner.ID {
			return result[i].Owner.ID < result[j].Owner.ID
		}
		if result[i].Edge.ID != result[j].Edge.ID {
			return result[i].Edge.ID < result[j].Edge.ID
		}
		return result[i].Edge.SourceEventID < result[j].Edge.SourceEventID
	})
	return result, nil
}

func missingProvenanceReasons(edge ProofEdge) []string {
	var reasons []string
	if edge.SourceID == "" {
		reasons = append(reasons, "proof_edge_source_missing")
	}
	if edge.SourceRuntimeID == "" {
		reasons = append(reasons, "proof_edge_runtime_missing")
	}
	if edge.SourceEventID == "" {
		reasons = append(reasons, "proof_edge_event_missing")
	}
	if edge.ObservedAt.IsZero() {
		reasons = append(reasons, "proof_edge_observed_at_missing")
	}
	return reasons
}

func provenanceFromEdges(edges []ProofEdge) []ProvenanceRef {
	values := make([]ProvenanceRef, 0, len(edges))
	for _, edge := range edges {
		values = append(values, ProvenanceRef{
			SourceID:   edge.SourceID,
			RuntimeID:  edge.SourceRuntimeID,
			EventID:    edge.SourceEventID,
			ObservedAt: edge.ObservedAt,
		})
	}
	return normalizeProvenance(values)
}

func nodeRef(value attackpath.NodeRef) NodeRef {
	return NodeRef{
		URN:        strings.TrimSpace(value.URN),
		EntityType: strings.TrimSpace(value.EntityType),
		Label:      strings.TrimSpace(value.Label),
	}
}

func newCollectionReceipt(observationID string, observedAt time.Time, input CollectionReceiptInput, explicitReasons []string, actualPathCount int, proofRuntimeIDs []string) (CollectionReceipt, Completeness, error) {
	if input.ObservedPathCount < 0 || input.TotalPathCount < 0 || input.TotalPathCount < input.ObservedPathCount ||
		input.SourcePagesRead < 0 || input.SourceEventsAppended < 0 || input.SourceEntitiesProjected < 0 || input.SourceLinksProjected < 0 ||
		input.GraphPagesRead < 0 || input.GraphEventsRead < 0 || input.GraphEntitiesProjected < 0 || input.GraphLinksProjected < 0 || input.GraphStaleMaterialLinksDeleted < 0 {
		return CollectionReceipt{}, Completeness{}, fmt.Errorf("%w: collection path counts are invalid", ErrInvalidInput)
	}
	if input.ObservedPathCount != actualPathCount {
		return CollectionReceipt{}, Completeness{}, fmt.Errorf("%w: collection receipt observed_path_count does not match normalized paths", ErrInvalidInput)
	}
	watermark := canonicalTime(input.RuntimeWatermark)
	lastSyncedAt := canonicalTime(input.LastSyncedAt)
	graphRunStartedAt := canonicalTime(input.GraphRunStartedAt)
	graphRunFinishedAt := canonicalTime(input.GraphRunFinishedAt)
	if (!watermark.IsZero() && watermark.After(observedAt)) || (!lastSyncedAt.IsZero() && lastSyncedAt.After(observedAt)) ||
		(!graphRunStartedAt.IsZero() && graphRunStartedAt.After(observedAt)) || (!graphRunFinishedAt.IsZero() && graphRunFinishedAt.After(observedAt)) {
		return CollectionReceipt{}, Completeness{}, fmt.Errorf("%w: collection timestamps cannot follow the observation", ErrInvalidInput)
	}
	if !graphRunStartedAt.IsZero() && !graphRunFinishedAt.IsZero() && graphRunFinishedAt.Before(graphRunStartedAt) {
		return CollectionReceipt{}, Completeness{}, fmt.Errorf("%w: graph run cannot finish before it starts", ErrInvalidInput)
	}

	receipt := CollectionReceipt{
		ID: digestStrings(
			"security-path-collection-receipt/v2",
			strings.TrimSpace(observationID),
			strings.TrimSpace(input.SourceRuntimeID),
			strings.TrimSpace(input.SourceID),
			normalizeProviderFamily(input.ProviderFamily),
			strings.TrimSpace(input.ConfigRevision),
			strings.TrimSpace(input.GraphCheckpointID),
			strings.TrimSpace(input.GraphRunID),
		),
		SourceRuntimeID:                          strings.TrimSpace(input.SourceRuntimeID),
		SourceID:                                 strings.TrimSpace(input.SourceID),
		ProviderFamily:                           normalizeProviderFamily(input.ProviderFamily),
		ConfigRevision:                           strings.TrimSpace(input.ConfigRevision),
		RuntimeWatermark:                         watermark,
		LastSyncedAt:                             lastSyncedAt,
		CollectionMode:                           strings.TrimSpace(input.CollectionMode),
		SourcePagesRead:                          input.SourcePagesRead,
		SourceEventsAppended:                     input.SourceEventsAppended,
		SourceEntitiesProjected:                  input.SourceEntitiesProjected,
		SourceLinksProjected:                     input.SourceLinksProjected,
		GraphCheckpointID:                        strings.TrimSpace(input.GraphCheckpointID),
		GraphRunID:                               strings.TrimSpace(input.GraphRunID),
		GraphRunStartedAt:                        graphRunStartedAt,
		GraphRunFinishedAt:                       graphRunFinishedAt,
		GraphPagesRead:                           input.GraphPagesRead,
		GraphEventsRead:                          input.GraphEventsRead,
		GraphEntitiesProjected:                   input.GraphEntitiesProjected,
		GraphLinksProjected:                      input.GraphLinksProjected,
		GraphMaterialLinkReconciliationRequested: input.GraphMaterialLinkReconciliationRequested,
		GraphMaterialLinkReconciliationSupported: input.GraphMaterialLinkReconciliationSupported,
		GraphMaterialLinkReconciliationCompleted: input.GraphMaterialLinkReconciliationCompleted,
		GraphStaleMaterialLinksDeleted:           input.GraphStaleMaterialLinksDeleted,
		GraphCheckpointComplete:                  input.GraphCheckpointComplete,
		GraphCheckpointCurrent:                   input.GraphCheckpointCurrent,
		ObservedPathCount:                        input.ObservedPathCount,
		TotalPathCount:                           input.TotalPathCount,
		LeaseHeld:                                input.LeaseHeld,
		Limitations:                              normalizedStrings(input.Limitations),
		ProofRuntimeIDs:                          normalizedStrings(proofRuntimeIDs),
	}
	runtimeInputs := append([]RuntimeCollectionReceiptInput(nil), input.RuntimeReceipts...)
	if receipt.SourceRuntimeID != "" {
		runtimeInputs = append(runtimeInputs, RuntimeCollectionReceiptInput{
			SourceRuntimeID:         receipt.SourceRuntimeID,
			SourceID:                receipt.SourceID,
			ProviderFamily:          receipt.ProviderFamily,
			ConfigRevision:          receipt.ConfigRevision,
			RuntimeWatermark:        receipt.RuntimeWatermark,
			LastSyncedAt:            receipt.LastSyncedAt,
			GraphCheckpointID:       receipt.GraphCheckpointID,
			GraphRunID:              receipt.GraphRunID,
			GraphRunStartedAt:       receipt.GraphRunStartedAt,
			GraphRunFinishedAt:      receipt.GraphRunFinishedAt,
			GraphCheckpointComplete: receipt.GraphCheckpointComplete,
			GraphCheckpointCurrent:  receipt.GraphCheckpointCurrent,
			Limitations:             receipt.Limitations,
		})
	}
	runtimeReceipts, runtimeReasons, err := normalizeRuntimeCollectionReceipts(runtimeInputs, observedAt, receipt.ProofRuntimeIDs)
	if err != nil {
		return CollectionReceipt{}, Completeness{}, err
	}
	receipt.RuntimeReceipts = runtimeReceipts
	receipt.Digest, err = digestValue(receipt)
	if err != nil {
		return CollectionReceipt{}, Completeness{}, err
	}

	reasons := append([]string{}, explicitReasons...)
	reasons = append(reasons, runtimeReasons...)
	reasons = append(reasons, receipt.Limitations...)
	if receipt.SourceRuntimeID == "" {
		reasons = append(reasons, "source_runtime_missing")
	}
	if receipt.SourceID == "" {
		reasons = append(reasons, "source_missing")
	}
	if receipt.ProviderFamily == "" {
		reasons = append(reasons, "provider_family_missing")
	}
	if receipt.ConfigRevision == "" {
		reasons = append(reasons, "config_revision_missing")
	}
	if receipt.RuntimeWatermark.IsZero() {
		reasons = append(reasons, "runtime_watermark_missing")
	}
	if receipt.LastSyncedAt.IsZero() {
		reasons = append(reasons, "last_sync_missing")
	}
	switch receipt.CollectionMode {
	case CollectionModeCheckpointed, CollectionModeSourceSyncProjection, CollectionModeGraphResetFullScan:
	default:
		reasons = append(reasons, "collection_mode_invalid")
	}
	if receipt.CollectionMode == CollectionModeSourceSyncProjection && receipt.SourcePagesRead == 0 {
		reasons = append(reasons, "source_sync_pages_missing")
	}
	if receipt.CollectionMode == CollectionModeGraphResetFullScan {
		if !receipt.GraphMaterialLinkReconciliationRequested {
			reasons = append(reasons, "material_link_reconciliation_not_requested")
		}
		if !receipt.GraphMaterialLinkReconciliationSupported {
			reasons = append(reasons, "authoritative_material_link_reconciliation_unsupported")
		}
		if !receipt.GraphMaterialLinkReconciliationCompleted {
			reasons = append(reasons, "material_link_reconciliation_incomplete")
		}
	}
	if receipt.GraphCheckpointID == "" {
		reasons = append(reasons, "graph_checkpoint_missing")
	}
	if receipt.GraphRunID == "" {
		reasons = append(reasons, "graph_run_missing")
	}
	if receipt.GraphRunStartedAt.IsZero() {
		reasons = append(reasons, "graph_run_started_at_missing")
	}
	if receipt.GraphRunFinishedAt.IsZero() {
		reasons = append(reasons, "graph_run_finished_at_missing")
	}
	if !receipt.GraphCheckpointComplete {
		reasons = append(reasons, "graph_checkpoint_incomplete")
	}
	if !receipt.GraphCheckpointCurrent {
		reasons = append(reasons, "graph_checkpoint_not_current")
	}
	if receipt.ObservedPathCount != receipt.TotalPathCount {
		reasons = append(reasons, "path_collection_partial")
	}
	if !receipt.LeaseHeld {
		reasons = append(reasons, "source_read_lease_not_held")
	}
	reasons = normalizedStrings(reasons)
	if len(reasons) != 0 {
		return receipt, Completeness{State: CompletenessIncomplete, Reasons: reasons}, nil
	}
	return receipt, Completeness{State: CompletenessComplete}, nil
}

func securityPathRuntimeIDs(paths []SecurityPath) []string {
	set := map[string]struct{}{}
	for _, path := range paths {
		for _, edge := range path.ProofEdges {
			for _, runtimeID := range append(append([]string(nil), edge.AssertionRuntimeIDs...), edge.SourceRuntimeID) {
				if runtimeID = strings.TrimSpace(runtimeID); runtimeID != "" {
					set[runtimeID] = struct{}{}
				}
			}
		}
		for _, ownership := range path.Ownerships {
			for _, runtimeID := range append(append([]string(nil), ownership.Edge.AssertionRuntimeIDs...), ownership.Edge.SourceRuntimeID) {
				if runtimeID = strings.TrimSpace(runtimeID); runtimeID != "" {
					set[runtimeID] = struct{}{}
				}
			}
		}
	}
	return setStrings(set)
}

func normalizeRuntimeCollectionReceipts(inputs []RuntimeCollectionReceiptInput, observedAt time.Time, requiredRuntimeIDs []string) ([]RuntimeCollectionReceipt, []string, error) {
	byRuntime := make(map[string]RuntimeCollectionReceipt, len(inputs))
	for _, input := range inputs {
		runtimeID := strings.TrimSpace(input.SourceRuntimeID)
		if runtimeID == "" {
			continue
		}
		receipt := RuntimeCollectionReceipt{
			SourceRuntimeID:         runtimeID,
			SourceID:                strings.TrimSpace(input.SourceID),
			ProviderFamily:          normalizeProviderFamily(input.ProviderFamily),
			ConfigRevision:          strings.TrimSpace(input.ConfigRevision),
			RuntimeWatermark:        canonicalTime(input.RuntimeWatermark),
			LastSyncedAt:            canonicalTime(input.LastSyncedAt),
			GraphCheckpointID:       strings.TrimSpace(input.GraphCheckpointID),
			GraphRunID:              strings.TrimSpace(input.GraphRunID),
			GraphRunStartedAt:       canonicalTime(input.GraphRunStartedAt),
			GraphRunFinishedAt:      canonicalTime(input.GraphRunFinishedAt),
			GraphCheckpointComplete: input.GraphCheckpointComplete,
			GraphCheckpointCurrent:  input.GraphCheckpointCurrent,
			Limitations:             normalizedStrings(input.Limitations),
		}
		if receipt.RuntimeWatermark.After(observedAt) || receipt.LastSyncedAt.After(observedAt) || receipt.GraphRunStartedAt.After(observedAt) || receipt.GraphRunFinishedAt.After(observedAt) {
			return nil, nil, fmt.Errorf("%w: proof runtime receipt timestamps cannot follow the observation", ErrInvalidInput)
		}
		if !receipt.GraphRunStartedAt.IsZero() && !receipt.GraphRunFinishedAt.IsZero() && receipt.GraphRunFinishedAt.Before(receipt.GraphRunStartedAt) {
			return nil, nil, fmt.Errorf("%w: proof runtime graph run cannot finish before it starts", ErrInvalidInput)
		}
		if existing, ok := byRuntime[runtimeID]; ok && !sameCanonicalValue(existing, receipt) {
			return nil, nil, fmt.Errorf("%w: proof runtime %q has conflicting collection receipts", ErrInvalidInput, runtimeID)
		}
		byRuntime[runtimeID] = receipt
	}
	orderedIDs := make([]string, 0, len(byRuntime))
	for runtimeID := range byRuntime {
		orderedIDs = append(orderedIDs, runtimeID)
	}
	sort.Strings(orderedIDs)
	receipts := make([]RuntimeCollectionReceipt, 0, len(orderedIDs))
	for _, runtimeID := range orderedIDs {
		receipts = append(receipts, byRuntime[runtimeID])
	}

	var reasons []string
	for _, runtimeID := range requiredRuntimeIDs {
		receipt, ok := byRuntime[runtimeID]
		if !ok {
			reasons = append(reasons, "proof_runtime_receipt_missing:"+runtimeID)
			continue
		}
		reasons = append(reasons, runtimeReceiptIncompleteReasons("proof_runtime:"+runtimeID+":", receipt)...)
	}
	return receipts, normalizedStrings(reasons), nil
}

func runtimeReceiptIncompleteReasons(prefix string, receipt RuntimeCollectionReceipt) []string {
	var reasons []string
	if receipt.SourceID == "" {
		reasons = append(reasons, prefix+"source_missing")
	}
	if receipt.ProviderFamily == "" {
		reasons = append(reasons, prefix+"provider_family_missing")
	}
	if receipt.ConfigRevision == "" {
		reasons = append(reasons, prefix+"config_revision_missing")
	}
	if receipt.RuntimeWatermark.IsZero() {
		reasons = append(reasons, prefix+"runtime_watermark_missing")
	}
	if receipt.LastSyncedAt.IsZero() {
		reasons = append(reasons, prefix+"last_sync_missing")
	}
	if receipt.GraphCheckpointID == "" {
		reasons = append(reasons, prefix+"graph_checkpoint_missing")
	}
	if receipt.GraphRunID == "" {
		reasons = append(reasons, prefix+"graph_run_missing")
	}
	if receipt.GraphRunStartedAt.IsZero() || receipt.GraphRunFinishedAt.IsZero() {
		reasons = append(reasons, prefix+"graph_run_time_missing")
	}
	if !receipt.GraphCheckpointComplete {
		reasons = append(reasons, prefix+"graph_checkpoint_incomplete")
	}
	if !receipt.GraphCheckpointCurrent {
		reasons = append(reasons, prefix+"graph_checkpoint_not_current")
	}
	for _, limitation := range receipt.Limitations {
		reasons = append(reasons, prefix+limitation)
	}
	return reasons
}

func normalizeProvenance(values []ProvenanceRef) []ProvenanceRef {
	byKey := make(map[string]ProvenanceRef, len(values))
	for _, value := range values {
		value.SourceID = strings.TrimSpace(value.SourceID)
		value.RuntimeID = strings.TrimSpace(value.RuntimeID)
		value.EventID = strings.TrimSpace(value.EventID)
		value.ObservedAt = canonicalTime(value.ObservedAt)
		if value.SourceID == "" && value.RuntimeID == "" && value.EventID == "" && value.ObservedAt.IsZero() {
			continue
		}
		key := strings.Join([]string{value.SourceID, value.RuntimeID, value.EventID, value.ObservedAt.Format(time.RFC3339Nano)}, "\x00")
		byKey[key] = value
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]ProvenanceRef, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out
}

func snapshotRef(snapshot Snapshot) SnapshotRef {
	return SnapshotRef{
		ID:           snapshot.ID,
		Digest:       snapshot.Digest,
		ObservedAt:   snapshot.ObservedAt,
		Completeness: snapshot.Completeness,
	}
}

func sortSecurityPaths(paths []SecurityPath) {
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].RouteID != paths[j].RouteID {
			return paths[i].RouteID < paths[j].RouteID
		}
		return paths[i].ID < paths[j].ID
	})
}

func normalizedStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizeProviderFamily(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC()
}

func digestStrings(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestValue(value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("%w: encode deterministic digest: %w", ErrInvalidInput, err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func sameCanonicalValue(left any, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}
