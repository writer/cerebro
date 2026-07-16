package securitypathdelta

import (
	"fmt"
	"strings"
)

// VerifyObservedAbsent checks whether the routes represented by requested path
// IDs are absent from a later complete observation. It deliberately reports
// observed_absent rather than claiming that a remediation was effective.
func VerifyObservedAbsent(reference Snapshot, after Snapshot, requestedPathIDs []string) (Verification, error) {
	if err := validateSnapshot(reference); err != nil {
		return Verification{}, err
	}
	if err := validateSnapshot(after); err != nil {
		return Verification{}, err
	}
	if reference.TenantID != after.TenantID || reference.ScopeID != after.ScopeID || reference.DetectorID != after.DetectorID || reference.DetectorRevision != after.DetectorRevision {
		return Verification{}, fmt.Errorf("%w: reference and after snapshots must share tenant, scope, and detector revision", ErrInvalidInput)
	}
	if !after.ObservedAt.After(reference.ObservedAt) {
		return Verification{}, fmt.Errorf("%w: verification observation must follow the reference", ErrInvalidInput)
	}
	pathIDs := normalizedStrings(requestedPathIDs)
	if len(pathIDs) == 0 {
		return Verification{}, fmt.Errorf("%w: at least one requested path is required", ErrInvalidInput)
	}
	referenceByPath := make(map[string]SecurityPath, len(reference.Paths))
	for _, path := range reference.Paths {
		referenceByPath[path.ID] = path
	}
	routeSet := map[string]struct{}{}
	requestedReferencePaths := make([]SecurityPath, 0, len(pathIDs))
	for _, pathID := range pathIDs {
		path, ok := referenceByPath[pathID]
		if !ok {
			return Verification{}, fmt.Errorf("%w: requested path %q is not in the reference snapshot", ErrInvalidInput, pathID)
		}
		requestedReferencePaths = append(requestedReferencePaths, path)
		routeSet[path.RouteID] = struct{}{}
	}
	routeIDs := setStrings(routeSet)
	referenceRuntimeIDs := securityPathRuntimeIDs(requestedReferencePaths)
	requiredRuntimeIDs := normalizedStrings(append(referenceRuntimeIDs, securityPathRuntimeIDs(after.Paths)...))

	verification := Verification{
		TenantID:          after.TenantID,
		ScopeID:           after.ScopeID,
		DetectorID:        after.DetectorID,
		DetectorRevision:  after.DetectorRevision,
		Reference:         snapshotRef(reference),
		After:             snapshotRef(after),
		RequestedPathIDs:  pathIDs,
		RequestedRouteIDs: routeIDs,
		State:             VerificationIndeterminate,
	}
	if !snapshotIsComplete(after) {
		verification.Reasons = append([]string(nil), after.Completeness.Reasons...)
	} else if after.Receipt.CollectionMode != CollectionModeGraphResetFullScan {
		verification.Reasons = []string{"fresh_graph_collection_required"}
	} else if receiptReasons := verificationRuntimeReceiptReasons(reference.Receipt, after.Receipt, referenceRuntimeIDs, requiredRuntimeIDs); len(receiptReasons) != 0 {
		verification.Reasons = receiptReasons
	} else {
		afterByRoute := pathsByRoute(after.Paths)
		for _, routeID := range routeIDs {
			verification.StillObserved = append(verification.StillObserved, afterByRoute[routeID]...)
		}
		sortSecurityPaths(verification.StillObserved)
		if len(verification.StillObserved) == 0 {
			verification.State = VerificationObservedAbsent
		} else {
			verification.State = VerificationStillObserved
			verification.CandidateEdgeCuts = RankCandidateEdgeCuts(verification.StillObserved)
		}
	}
	verification.ID = digestStrings(
		"security-path-verification/v1",
		after.TenantID,
		after.ScopeID,
		after.DetectorID,
		after.DetectorRevision,
		reference.ID,
		after.ID,
		digestStrings(pathIDs...),
	)
	var err error
	verification.Digest, err = digestValue(verification)
	if err != nil {
		return Verification{}, err
	}
	return verification, nil
}

func verificationRuntimeReceiptReasons(reference CollectionReceipt, after CollectionReceipt, referenceRuntimeIDs []string, requiredRuntimeIDs []string) []string {
	afterScope := make(map[string]struct{}, len(after.ProofRuntimeIDs))
	for _, runtimeID := range after.ProofRuntimeIDs {
		afterScope[strings.TrimSpace(runtimeID)] = struct{}{}
	}
	referenceReceipts := runtimeReceiptsByID(reference.RuntimeReceipts)
	afterReceipts := runtimeReceiptsByID(after.RuntimeReceipts)
	referenceRuntimeSet := make(map[string]struct{}, len(referenceRuntimeIDs))
	for _, runtimeID := range referenceRuntimeIDs {
		referenceRuntimeSet[runtimeID] = struct{}{}
	}

	var reasons []string
	for _, runtimeID := range requiredRuntimeIDs {
		if _, ok := afterScope[runtimeID]; !ok {
			reasons = append(reasons, "verification_runtime_scope_missing:"+runtimeID)
			continue
		}
		afterReceipt, ok := afterReceipts[runtimeID]
		if !ok {
			reasons = append(reasons, "verification_runtime_receipt_missing:"+runtimeID)
			continue
		}
		reasons = append(reasons, runtimeReceiptIncompleteReasons("verification_runtime:"+runtimeID+":", afterReceipt)...)

		if _, requested := referenceRuntimeSet[runtimeID]; !requested {
			continue
		}
		referenceReceipt, ok := referenceReceipts[runtimeID]
		if !ok {
			reasons = append(reasons, "reference_runtime_receipt_missing:"+runtimeID)
			continue
		}
		if afterReceipt.ProviderFamily != referenceReceipt.ProviderFamily {
			reasons = append(reasons, "verification_runtime_provider_family_changed:"+runtimeID)
		}
		if afterReceipt.ConfigRevision != referenceReceipt.ConfigRevision {
			reasons = append(reasons, "verification_runtime_config_revision_changed:"+runtimeID)
		}
	}
	return normalizedStrings(reasons)
}

func runtimeReceiptsByID(receipts []RuntimeCollectionReceipt) map[string]RuntimeCollectionReceipt {
	byID := make(map[string]RuntimeCollectionReceipt, len(receipts))
	for _, receipt := range receipts {
		if runtimeID := strings.TrimSpace(receipt.SourceRuntimeID); runtimeID != "" {
			byID[runtimeID] = receipt
		}
	}
	return byID
}
