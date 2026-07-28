package securitypathdelta

import (
	"context"
	"fmt"
	"slices"
)

// RustAuthorityReceipt binds a security-path decision to the exact input and
// source snapshots evaluated by the embedded Rust kernel.
type RustAuthorityReceipt struct {
	Operation             string   `json:"operation"`
	SchemaVersion         string   `json:"schema_version"`
	InputDigest           string   `json:"input_digest"`
	SourceSnapshotDigests []string `json:"source_snapshot_digests"`
	DecisionDigest        string   `json:"decision_digest"`
}

// CompareRustAuthority obtains the comparison decision from the embedded Rust
// kernel. Go only hydrates the existing API record from source snapshots after
// validating every returned reference; evaluator failure has no Go fallback.
func CompareRustAuthority(ctx context.Context, before *Snapshot, after Snapshot) (Delta, RustAuthorityReceipt, error) {
	var response rustComparisonResponse
	receipt, err := evaluateRustSecurityPath(ctx, rustComparisonRequest{
		Operation: "compare",
		Before:    rustSnapshotPointer(before),
		After:     rustSnapshotFromSnapshot(after),
	}, &response)
	if err != nil {
		return Delta{}, RustAuthorityReceipt{}, err
	}
	if response.Operation != "compare" {
		return Delta{}, RustAuthorityReceipt{}, fmt.Errorf("%w: unexpected comparison operation", ErrRustEvaluatorUnavailable)
	}
	if response.Result.Digest == "" || response.Result.Digest != rustComparisonDecisionDigest(response.Result) {
		return Delta{}, RustAuthorityReceipt{}, fmt.Errorf("%w: comparison decision digest mismatch", ErrRustEvaluatorUnavailable)
	}
	delta, err := hydrateRustComparison(before, after, response.Result)
	if err != nil {
		return Delta{}, RustAuthorityReceipt{}, err
	}
	return delta, authorityReceipt("compare", receipt, response.Result.Digest), nil
}

// VerifyObservedAbsentRustAuthority obtains the verification decision from the
// embedded Rust kernel and fails closed when the decision cannot be bound back
// to the supplied snapshots.
func VerifyObservedAbsentRustAuthority(
	ctx context.Context,
	reference Snapshot,
	after Snapshot,
	requestedPathIDs []string,
) (Verification, RustAuthorityReceipt, error) {
	var response rustVerificationResponse
	receipt, err := evaluateRustSecurityPath(ctx, rustVerificationRequest{
		Operation:        "verify_observed_absent",
		Reference:        rustSnapshotFromSnapshot(reference),
		After:            rustSnapshotFromSnapshot(after),
		RequestedPathIDs: normalizedStrings(requestedPathIDs),
	}, &response)
	if err != nil {
		return Verification{}, RustAuthorityReceipt{}, err
	}
	if response.Operation != "verify_observed_absent" {
		return Verification{}, RustAuthorityReceipt{}, fmt.Errorf("%w: unexpected verification operation", ErrRustEvaluatorUnavailable)
	}
	if response.Result.Digest == "" || response.Result.Digest != rustVerificationDecisionDigest(response.Result) {
		return Verification{}, RustAuthorityReceipt{}, fmt.Errorf("%w: verification decision digest mismatch", ErrRustEvaluatorUnavailable)
	}
	verification, err := hydrateRustVerification(reference, after, response.Result)
	if err != nil {
		return Verification{}, RustAuthorityReceipt{}, err
	}
	return verification, authorityReceipt("verify_observed_absent", receipt, response.Result.Digest), nil
}

func authorityReceipt(operation string, receipt rustDecisionReceipt, decisionDigest string) RustAuthorityReceipt {
	return RustAuthorityReceipt{
		Operation:             operation,
		SchemaVersion:         receipt.SchemaVersion,
		InputDigest:           receipt.InputDigest,
		SourceSnapshotDigests: append([]string(nil), receipt.SourceSnapshotDigests...),
		DecisionDigest:        decisionDigest,
	}
}

func hydrateRustComparison(before *Snapshot, after Snapshot, decision rustComparisonDecision) (Delta, error) {
	state := DeltaState(decision.State)
	switch state {
	case DeltaStateInitial, DeltaStateCompared, DeltaStateIndeterminate:
	default:
		return Delta{}, fmt.Errorf("%w: unknown Rust comparison state %q", ErrRustEvaluatorUnavailable, decision.State)
	}
	afterPaths, err := pathsByID(after.Paths)
	if err != nil {
		return Delta{}, err
	}
	beforePaths := map[string]SecurityPath{}
	beforeID := ""
	beforeRef := SnapshotRef{}
	if before != nil {
		beforePaths, err = pathsByID(before.Paths)
		if err != nil {
			return Delta{}, err
		}
		beforeID = before.ID
		beforeRef = snapshotRef(*before)
	}
	newlyObserved, err := hydratePathIDs("newly observed", decision.NewlyObservedPathIDs, afterPaths)
	if err != nil {
		return Delta{}, err
	}
	noLongerObserved, err := hydratePathIDs("no longer observed", decision.NoLongerObservedPathIDs, beforePaths)
	if err != nil {
		return Delta{}, err
	}
	var proofChanged []ProofChange
	if len(decision.ProofChanged) != 0 {
		proofChanged = make([]ProofChange, 0, len(decision.ProofChanged))
	}
	for _, change := range decision.ProofChanged {
		beforeChanged, err := hydratePathIDs("changed before", change.BeforePathIDs, beforePaths)
		if err != nil {
			return Delta{}, err
		}
		afterChanged, err := hydratePathIDs("changed after", change.AfterPathIDs, afterPaths)
		if err != nil {
			return Delta{}, err
		}
		if !pathsShareRoute(beforeChanged, change.RouteID) || !pathsShareRoute(afterChanged, change.RouteID) {
			return Delta{}, fmt.Errorf("%w: Rust proof change references the wrong route", ErrRustEvaluatorUnavailable)
		}
		proofChanged = append(proofChanged, ProofChange{
			RouteID:     change.RouteID,
			BeforePaths: beforeChanged,
			AfterPaths:  afterChanged,
		})
	}
	cuts, err := hydrateCandidateCuts(decision.CandidateEdgeCuts, newlyObserved)
	if err != nil {
		return Delta{}, err
	}
	delta := Delta{
		TenantID:          after.TenantID,
		ScopeID:           after.ScopeID,
		DetectorID:        after.DetectorID,
		DetectorRevision:  after.DetectorRevision,
		State:             state,
		Before:            beforeRef,
		After:             snapshotRef(after),
		NewlyObserved:     newlyObserved,
		NoLongerObserved:  noLongerObserved,
		ProofChanged:      proofChanged,
		UnchangedRoutes:   decision.UnchangedRoutes,
		CandidateEdgeCuts: cuts,
	}
	delta.ID = digestStrings(
		"security-path-delta/v1",
		after.TenantID,
		after.ScopeID,
		after.DetectorID,
		after.DetectorRevision,
		beforeID,
		after.ID,
	)
	delta.Digest, err = digestValue(delta)
	if err != nil {
		return Delta{}, err
	}
	return delta, nil
}

func hydrateRustVerification(reference Snapshot, after Snapshot, decision rustVerificationDecision) (Verification, error) {
	state := VerificationState(decision.State)
	switch state {
	case VerificationObservedAbsent, VerificationStillObserved, VerificationIndeterminate:
	default:
		return Verification{}, fmt.Errorf("%w: unknown Rust verification state %q", ErrRustEvaluatorUnavailable, decision.State)
	}
	afterPaths, err := pathsByID(after.Paths)
	if err != nil {
		return Verification{}, err
	}
	stillObserved, err := hydratePathIDs("still observed", decision.StillObservedPathIDs, afterPaths)
	if err != nil {
		return Verification{}, err
	}
	cuts, err := hydrateCandidateCuts(decision.CandidateEdgeCuts, stillObserved)
	if err != nil {
		return Verification{}, err
	}
	verification := Verification{
		TenantID:          after.TenantID,
		ScopeID:           after.ScopeID,
		DetectorID:        after.DetectorID,
		DetectorRevision:  after.DetectorRevision,
		Reference:         snapshotRef(reference),
		After:             snapshotRef(after),
		RequestedPathIDs:  append([]string(nil), decision.RequestedPathIDs...),
		RequestedRouteIDs: append([]string(nil), decision.RequestedRouteIDs...),
		State:             state,
		Reasons:           append([]string(nil), decision.Reasons...),
		StillObserved:     stillObserved,
		CandidateEdgeCuts: cuts,
	}
	verification.ID = digestStrings(
		"security-path-verification/v1",
		after.TenantID,
		after.ScopeID,
		after.DetectorID,
		after.DetectorRevision,
		reference.ID,
		after.ID,
		digestStrings(decision.RequestedPathIDs...),
	)
	verification.Digest, err = digestValue(verification)
	if err != nil {
		return Verification{}, err
	}
	return verification, nil
}

func pathsByID(paths []SecurityPath) (map[string]SecurityPath, error) {
	result := make(map[string]SecurityPath, len(paths))
	for _, path := range paths {
		if _, exists := result[path.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate security path ID %q", ErrRustEvaluatorUnavailable, path.ID)
		}
		result[path.ID] = path
	}
	return result, nil
}

func hydratePathIDs(label string, ids []string, available map[string]SecurityPath) ([]SecurityPath, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	result := make([]SecurityPath, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("%w: duplicate Rust %s path ID %q", ErrRustEvaluatorUnavailable, label, id)
		}
		path, ok := available[id]
		if !ok {
			return nil, fmt.Errorf("%w: unknown Rust %s path ID %q", ErrRustEvaluatorUnavailable, label, id)
		}
		seen[id] = struct{}{}
		result = append(result, path)
	}
	sortSecurityPaths(result)
	return result, nil
}

func pathsShareRoute(paths []SecurityPath, routeID string) bool {
	if routeID == "" || len(paths) == 0 {
		return false
	}
	for _, path := range paths {
		if path.RouteID != routeID {
			return false
		}
	}
	return true
}

func hydrateCandidateCuts(cuts []CandidateEdgeCut, paths []SecurityPath) ([]CandidateEdgeCut, error) {
	if len(cuts) == 0 {
		return nil, nil
	}
	edges := make(map[string]ProofEdge)
	pathRoutes := make(map[string]string, len(paths))
	for _, path := range paths {
		pathRoutes[path.ID] = path.RouteID
		for _, edge := range path.ProofEdges {
			if _, exists := edges[edge.ID]; exists {
				continue
			}
			edges[edge.ID] = edge
		}
	}
	result := make([]CandidateEdgeCut, len(cuts))
	for index, cut := range cuts {
		edge, ok := edges[cut.Edge.ID]
		if !ok || edge.Relation != cut.Edge.Relation || edge.SourceRuntimeID != cut.Edge.SourceRuntimeID ||
			!slices.Equal(edge.AssertionRuntimeIDs, cut.Edge.AssertionRuntimeIDs) {
			return nil, fmt.Errorf("%w: Rust candidate edge %q is not bound to an eligible path", ErrRustEvaluatorUnavailable, cut.Edge.ID)
		}
		if cut.Rank != index+1 || cut.RouteCoverage != len(cut.CoveredRouteIDs) || cut.PathCoverage != len(cut.CoveredPathIDs) {
			return nil, fmt.Errorf("%w: Rust candidate cut coverage is inconsistent", ErrRustEvaluatorUnavailable)
		}
		coveredRoutes := make(map[string]struct{}, len(cut.CoveredRouteIDs))
		for _, routeID := range cut.CoveredRouteIDs {
			coveredRoutes[routeID] = struct{}{}
		}
		for _, pathID := range cut.CoveredPathIDs {
			routeID, ok := pathRoutes[pathID]
			if !ok {
				return nil, fmt.Errorf("%w: Rust candidate cut references unknown path %q", ErrRustEvaluatorUnavailable, pathID)
			}
			if _, ok := coveredRoutes[routeID]; !ok {
				return nil, fmt.Errorf("%w: Rust candidate cut omits covered route %q", ErrRustEvaluatorUnavailable, routeID)
			}
		}
		result[index] = cut
		result[index].Edge = edge
		result[index].CoveredRouteIDs = append([]string(nil), cut.CoveredRouteIDs...)
		result[index].CoveredPathIDs = append([]string(nil), cut.CoveredPathIDs...)
	}
	return result, nil
}
