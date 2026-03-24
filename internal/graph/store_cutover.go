package graph

import (
	"context"
	"fmt"
	"reflect"
	"sort"
)

type StoreTraversalProbeKind string

const (
	StoreTraversalProbeBlastRadius   StoreTraversalProbeKind = "blast_radius"
	StoreTraversalProbeReverseAccess StoreTraversalProbeKind = "reverse_access"
)

type StoreParityMismatchClass string

const (
	StoreParityMismatchMissingNode    StoreParityMismatchClass = "missing_node"
	StoreParityMismatchMissingEdge    StoreParityMismatchClass = "missing_edge"
	StoreParityMismatchNodeModified   StoreParityMismatchClass = "node_modified"
	StoreParityMismatchTraversalDrift StoreParityMismatchClass = "traversal_drift"
	StoreParityMismatchReportDrift    StoreParityMismatchClass = "report_drift"
	StoreParityMismatchShadowError    StoreParityMismatchClass = "shadow_error"
)

type StoreTraversalProbe struct {
	Name        string                  `json:"name,omitempty"`
	Kind        StoreTraversalProbeKind `json:"kind"`
	PrincipalID string                  `json:"principal_id,omitempty"`
	ResourceID  string                  `json:"resource_id,omitempty"`
	MaxDepth    int                     `json:"max_depth,omitempty"`
}

type StoreParityMismatch struct {
	Class      StoreParityMismatchClass `json:"class"`
	Operation  string                   `json:"operation,omitempty"`
	Identifier string                   `json:"identifier,omitempty"`
	Details    map[string]any           `json:"details,omitempty"`
}

type StoreParityReport struct {
	PrimaryNodeCount int                   `json:"primary_node_count"`
	ShadowNodeCount  int                   `json:"shadow_node_count"`
	PrimaryEdgeCount int                   `json:"primary_edge_count"`
	ShadowEdgeCount  int                   `json:"shadow_edge_count"`
	SnapshotDiff     *GraphDiff            `json:"snapshot_diff,omitempty"`
	Mismatches       []StoreParityMismatch `json:"mismatches,omitempty"`
}

func (r StoreParityReport) HasDrift() bool {
	return len(r.Mismatches) > 0
}

type ShadowReadGraphStore struct {
	GraphStore
	shadow  GraphStore
	observe func(context.Context, StoreParityReport)
}

func NewShadowReadGraphStore(primary, shadow GraphStore, observe func(context.Context, StoreParityReport)) GraphStore {
	if primary == nil || shadow == nil {
		return primary
	}
	return &ShadowReadGraphStore{
		GraphStore: primary,
		shadow:     shadow,
		observe:    observe,
	}
}

func CompareGraphStores(ctx context.Context, primary, shadow GraphStore, probes []StoreTraversalProbe) (*StoreParityReport, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if primary == nil || shadow == nil {
		return nil, ErrStoreUnavailable
	}
	primarySnapshot, err := primary.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot primary store: %w", err)
	}
	shadowSnapshot, err := shadow.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot shadow store: %w", err)
	}
	report := buildSnapshotParityReport(primarySnapshot, shadowSnapshot)
	for _, probe := range probes {
		mismatch, err := compareTraversalProbe(ctx, primary, shadow, probe)
		if err != nil {
			return nil, err
		}
		if mismatch != nil {
			report.Mismatches = append(report.Mismatches, *mismatch)
		}
	}
	return &report, nil
}

func (s *ShadowReadGraphStore) Snapshot(ctx context.Context) (*Snapshot, error) {
	primarySnapshot, err := s.GraphStore.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	shadowSnapshot, shadowErr := s.shadow.Snapshot(ctx)
	if shadowErr != nil {
		s.emitShadowError(ctx, "snapshot", shadowErr)
		return primarySnapshot, nil
	}
	report := buildSnapshotParityReport(primarySnapshot, shadowSnapshot)
	s.emit(ctx, report)
	return primarySnapshot, nil
}

func (s *ShadowReadGraphStore) BlastRadius(ctx context.Context, principalID string, maxDepth int) (*BlastRadiusResult, error) {
	primaryResult, err := s.GraphStore.BlastRadius(ctx, principalID, maxDepth)
	if err != nil {
		return nil, err
	}
	shadowResult, shadowErr := s.shadow.BlastRadius(ctx, principalID, maxDepth)
	if shadowErr != nil {
		s.emitShadowError(ctx, "blast_radius", shadowErr)
		return primaryResult, nil
	}
	s.emitTraversalDrift(ctx, "blast_radius", principalID, normalizeBlastRadiusResult(primaryResult), normalizeBlastRadiusResult(shadowResult))
	return primaryResult, nil
}

func (s *ShadowReadGraphStore) ReverseAccess(ctx context.Context, resourceID string, maxDepth int) (*ReverseAccessResult, error) {
	primaryResult, err := s.GraphStore.ReverseAccess(ctx, resourceID, maxDepth)
	if err != nil {
		return nil, err
	}
	shadowResult, shadowErr := s.shadow.ReverseAccess(ctx, resourceID, maxDepth)
	if shadowErr != nil {
		s.emitShadowError(ctx, "reverse_access", shadowErr)
		return primaryResult, nil
	}
	s.emitTraversalDrift(ctx, "reverse_access", resourceID, normalizeReverseAccessResult(primaryResult), normalizeReverseAccessResult(shadowResult))
	return primaryResult, nil
}

func (s *ShadowReadGraphStore) emitTraversalDrift(ctx context.Context, operation, identifier string, primarySummary, shadowSummary map[string]any) {
	if reflect.DeepEqual(primarySummary, shadowSummary) {
		return
	}
	s.emit(ctx, StoreParityReport{
		Mismatches: []StoreParityMismatch{{
			Class:      StoreParityMismatchTraversalDrift,
			Operation:  operation,
			Identifier: identifier,
			Details: map[string]any{
				"primary": primarySummary,
				"shadow":  shadowSummary,
			},
		}},
	})
}

func (s *ShadowReadGraphStore) emitShadowError(ctx context.Context, operation string, err error) {
	s.emit(ctx, StoreParityReport{
		Mismatches: []StoreParityMismatch{{
			Class:     StoreParityMismatchShadowError,
			Operation: operation,
			Details: map[string]any{
				"error": err.Error(),
			},
		}},
	})
}

func (s *ShadowReadGraphStore) emit(ctx context.Context, report StoreParityReport) {
	if s == nil || s.observe == nil || !report.HasDrift() {
		return
	}
	s.observe(ctx, report)
}

func buildSnapshotParityReport(primary, shadow *Snapshot) StoreParityReport {
	report := StoreParityReport{}
	if primary != nil {
		report.PrimaryNodeCount, report.PrimaryEdgeCount = activeSnapshotCounts(primary)
	}
	if shadow != nil {
		report.ShadowNodeCount, report.ShadowEdgeCount = activeSnapshotCounts(shadow)
	}
	report.SnapshotDiff = DiffSnapshots(primary, shadow)
	for _, node := range report.SnapshotDiff.NodesAdded {
		if node == nil {
			continue
		}
		report.Mismatches = append(report.Mismatches, StoreParityMismatch{
			Class:      StoreParityMismatchMissingNode,
			Operation:  "snapshot",
			Identifier: node.ID,
			Details: map[string]any{
				"direction": "shadow_extra",
			},
		})
	}
	for _, node := range report.SnapshotDiff.NodesRemoved {
		if node == nil {
			continue
		}
		report.Mismatches = append(report.Mismatches, StoreParityMismatch{
			Class:      StoreParityMismatchMissingNode,
			Operation:  "snapshot",
			Identifier: node.ID,
			Details: map[string]any{
				"direction": "shadow_missing",
			},
		})
	}
	for _, edge := range report.SnapshotDiff.EdgesAdded {
		if edge == nil {
			continue
		}
		report.Mismatches = append(report.Mismatches, StoreParityMismatch{
			Class:      StoreParityMismatchMissingEdge,
			Operation:  "snapshot",
			Identifier: edge.ID,
			Details: map[string]any{
				"direction": "shadow_extra",
			},
		})
	}
	for _, edge := range report.SnapshotDiff.EdgesRemoved {
		if edge == nil {
			continue
		}
		report.Mismatches = append(report.Mismatches, StoreParityMismatch{
			Class:      StoreParityMismatchMissingEdge,
			Operation:  "snapshot",
			Identifier: edge.ID,
			Details: map[string]any{
				"direction": "shadow_missing",
			},
		})
	}
	for _, change := range report.SnapshotDiff.NodesModified {
		report.Mismatches = append(report.Mismatches, StoreParityMismatch{
			Class:      StoreParityMismatchNodeModified,
			Operation:  "snapshot",
			Identifier: change.NodeID,
			Details: map[string]any{
				"changed_keys": append([]string(nil), change.ChangedKeys...),
			},
		})
	}
	return report
}

func activeSnapshotCounts(snapshot *Snapshot) (int, int) {
	if snapshot == nil {
		return 0, 0
	}
	var nodes, edges int
	for _, node := range snapshot.Nodes {
		if isSnapshotNodeActive(node) {
			nodes++
		}
	}
	for _, edge := range snapshot.Edges {
		if isSnapshotEdgeActive(edge) {
			edges++
		}
	}
	return nodes, edges
}

func compareTraversalProbe(ctx context.Context, primary, shadow GraphStore, probe StoreTraversalProbe) (*StoreParityMismatch, error) {
	switch probe.Kind {
	case StoreTraversalProbeBlastRadius:
		primaryResult, err := primary.BlastRadius(ctx, probe.PrincipalID, probe.MaxDepth)
		if err != nil {
			return nil, fmt.Errorf("run primary blast radius probe %q: %w", probe.Name, err)
		}
		shadowResult, err := shadow.BlastRadius(ctx, probe.PrincipalID, probe.MaxDepth)
		if err != nil {
			return nil, fmt.Errorf("run shadow blast radius probe %q: %w", probe.Name, err)
		}
		return traversalMismatch("blast_radius", firstNonEmpty(probe.Name, probe.PrincipalID), normalizeBlastRadiusResult(primaryResult), normalizeBlastRadiusResult(shadowResult)), nil
	case StoreTraversalProbeReverseAccess:
		primaryResult, err := primary.ReverseAccess(ctx, probe.ResourceID, probe.MaxDepth)
		if err != nil {
			return nil, fmt.Errorf("run primary reverse access probe %q: %w", probe.Name, err)
		}
		shadowResult, err := shadow.ReverseAccess(ctx, probe.ResourceID, probe.MaxDepth)
		if err != nil {
			return nil, fmt.Errorf("run shadow reverse access probe %q: %w", probe.Name, err)
		}
		return traversalMismatch("reverse_access", firstNonEmpty(probe.Name, probe.ResourceID), normalizeReverseAccessResult(primaryResult), normalizeReverseAccessResult(shadowResult)), nil
	default:
		return nil, fmt.Errorf("unsupported traversal probe kind %q", probe.Kind)
	}
}

func traversalMismatch(operation, identifier string, primarySummary, shadowSummary map[string]any) *StoreParityMismatch {
	if reflect.DeepEqual(primarySummary, shadowSummary) {
		return nil
	}
	return &StoreParityMismatch{
		Class:      StoreParityMismatchTraversalDrift,
		Operation:  operation,
		Identifier: identifier,
		Details: map[string]any{
			"primary": primarySummary,
			"shadow":  shadowSummary,
		},
	}
}

func normalizeBlastRadiusResult(result *BlastRadiusResult) map[string]any {
	if result == nil {
		return map[string]any{"reachable_nodes": []string{}}
	}
	reachable := make([]string, 0, len(result.ReachableNodes))
	depths := make(map[string]int, len(result.ReachableNodes))
	for _, node := range result.ReachableNodes {
		if node == nil || node.Node == nil || node.Node.ID == "" {
			continue
		}
		reachable = append(reachable, node.Node.ID)
		depths[node.Node.ID] = node.Depth
	}
	sort.Strings(reachable)
	foreign := append([]string(nil), result.ForeignAccounts...)
	sort.Strings(foreign)
	return map[string]any{
		"principal_id":     result.PrincipalID,
		"reachable_nodes":  reachable,
		"depths":           depths,
		"total_count":      result.TotalCount,
		"foreign_accounts": foreign,
	}
}

func normalizeReverseAccessResult(result *ReverseAccessResult) map[string]any {
	if result == nil {
		return map[string]any{"accessible_by": []string{}}
	}
	accessible := make([]string, 0, len(result.AccessibleBy))
	for _, node := range result.AccessibleBy {
		if node == nil || node.Node == nil || node.Node.ID == "" {
			continue
		}
		accessible = append(accessible, node.Node.ID)
	}
	sort.Strings(accessible)
	return map[string]any{
		"resource_id":   result.ResourceID,
		"accessible_by": accessible,
		"total_count":   result.TotalCount,
	}
}
