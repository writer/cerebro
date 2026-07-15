package securitypathdelta

import (
	"fmt"
	"sort"
)

func Compare(before *Snapshot, after Snapshot) (Delta, error) {
	if err := validateSnapshot(after); err != nil {
		return Delta{}, err
	}
	delta := Delta{
		TenantID:         after.TenantID,
		ScopeID:          after.ScopeID,
		DetectorID:       after.DetectorID,
		DetectorRevision: after.DetectorRevision,
		After:            snapshotRef(after),
	}
	beforeID := ""
	if before == nil {
		delta.State = DeltaStateInitial
	} else {
		if err := validateSnapshot(*before); err != nil {
			return Delta{}, err
		}
		if before.TenantID != after.TenantID || before.ScopeID != after.ScopeID || before.DetectorID != after.DetectorID || before.DetectorRevision != after.DetectorRevision {
			return Delta{}, fmt.Errorf("%w: before and after snapshots must share tenant, scope, and detector revision", ErrInvalidInput)
		}
		if !after.ObservedAt.After(before.ObservedAt) {
			return Delta{}, fmt.Errorf("%w: after snapshot must be observed after before snapshot", ErrInvalidInput)
		}
		beforeID = before.ID
		delta.Before = snapshotRef(*before)
		if !snapshotIsComplete(*before) || !snapshotIsComplete(after) {
			delta.State = DeltaStateIndeterminate
		} else {
			delta.State = DeltaStateCompared
			populateChanges(&delta, *before, after)
		}
	}
	delta.ID = digestStrings("security-path-delta/v1", after.TenantID, after.ScopeID, after.DetectorID, after.DetectorRevision, beforeID, after.ID)
	var err error
	delta.Digest, err = digestValue(delta)
	if err != nil {
		return Delta{}, err
	}
	return delta, nil
}

func populateChanges(delta *Delta, before Snapshot, after Snapshot) {
	beforeRoutes := pathsByRoute(before.Paths)
	afterRoutes := pathsByRoute(after.Paths)
	routeIDs := map[string]struct{}{}
	for routeID := range beforeRoutes {
		routeIDs[routeID] = struct{}{}
	}
	for routeID := range afterRoutes {
		routeIDs[routeID] = struct{}{}
	}
	orderedRoutes := setStrings(routeIDs)
	for _, routeID := range orderedRoutes {
		beforePaths := beforeRoutes[routeID]
		afterPaths := afterRoutes[routeID]
		switch {
		case len(beforePaths) == 0:
			delta.NewlyObserved = append(delta.NewlyObserved, afterPaths...)
		case len(afterPaths) == 0:
			delta.NoLongerObserved = append(delta.NoLongerObserved, beforePaths...)
		case samePathIDs(beforePaths, afterPaths):
			delta.UnchangedRoutes++
		default:
			delta.ProofChanged = append(delta.ProofChanged, ProofChange{
				RouteID:     routeID,
				BeforePaths: append([]SecurityPath(nil), beforePaths...),
				AfterPaths:  append([]SecurityPath(nil), afterPaths...),
			})
		}
	}
	sortSecurityPaths(delta.NewlyObserved)
	sortSecurityPaths(delta.NoLongerObserved)
	delta.CandidateEdgeCuts = RankCandidateEdgeCuts(delta.NewlyObserved)
}

func pathsByRoute(paths []SecurityPath) map[string][]SecurityPath {
	result := make(map[string][]SecurityPath)
	for _, path := range paths {
		result[path.RouteID] = append(result[path.RouteID], path)
	}
	for routeID := range result {
		sortSecurityPaths(result[routeID])
	}
	return result
}

func samePathIDs(left []SecurityPath, right []SecurityPath) bool {
	if len(left) != len(right) {
		return false
	}
	leftIDs := make([]string, 0, len(left))
	rightIDs := make([]string, 0, len(right))
	for _, path := range left {
		leftIDs = append(leftIDs, path.ID)
	}
	for _, path := range right {
		rightIDs = append(rightIDs, path.ID)
	}
	sort.Strings(leftIDs)
	sort.Strings(rightIDs)
	for index := range leftIDs {
		if leftIDs[index] != rightIDs[index] {
			return false
		}
	}
	return true
}

func snapshotIsComplete(snapshot Snapshot) bool {
	receipt := snapshot.Receipt
	return snapshot.Completeness.State == CompletenessComplete && len(snapshot.Completeness.Reasons) == 0 &&
		receipt.SourceRuntimeID != "" && receipt.SourceID != "" && !receipt.RuntimeWatermark.IsZero() && !receipt.LastSyncedAt.IsZero() &&
		receipt.GraphCheckpointID != "" && receipt.GraphRunID != "" && receipt.GraphCheckpointComplete && receipt.GraphCheckpointCurrent &&
		receipt.ObservedPathCount == len(snapshot.Paths) && receipt.ObservedPathCount == receipt.TotalPathCount && receipt.LeaseHeld && len(receipt.Limitations) == 0
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.ID == "" || snapshot.Digest == "" || snapshot.TenantID == "" || snapshot.ScopeID == "" || snapshot.DetectorID == "" || snapshot.DetectorRevision == "" || snapshot.ObservationID == "" || snapshot.ObservedAt.IsZero() {
		return fmt.Errorf("%w: snapshot identity is required", ErrInvalidInput)
	}
	unsigned := snapshot
	unsigned.Digest = ""
	digest, err := digestValue(unsigned)
	if err != nil {
		return err
	}
	if digest != snapshot.Digest {
		return fmt.Errorf("%w: snapshot digest does not match its content", ErrInvalidInput)
	}
	return nil
}
