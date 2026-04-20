package graph

import (
	"context"
	"strings"
)

// TenantScopedNodePresenceStore reports whether a backend contains any nodes
// explicitly scoped to a tenant without requiring a full graph materialization.
type TenantScopedNodePresenceStore interface {
	HasTenantScopedNodes(ctx context.Context, tenantID string) (bool, error)
}

func AsTenantScopedNodePresenceStore(store GraphStore) (TenantScopedNodePresenceStore, bool) {
	if store == nil {
		return nil, false
	}
	checker, ok := store.(TenantScopedNodePresenceStore)
	return checker, ok
}

var _ TenantScopedNodePresenceStore = (*Graph)(nil)
var _ TenantScopedNodePresenceStore = (*SnapshotGraphStore)(nil)
var _ TenantScopedNodePresenceStore = (*TenantScopedReadOnlyGraphStore)(nil)
var _ TenantScopedNodePresenceStore = (*NeptuneGraphStore)(nil)

func (g *Graph) HasTenantScopedNodes(ctx context.Context, tenantID string) (bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return false, err
	}
	if g == nil {
		return false, ErrStoreUnavailable
	}
	return g.HasScopedNodesForTenant(strings.TrimSpace(tenantID)), nil
}

func (s *SnapshotGraphStore) HasTenantScopedNodes(ctx context.Context, tenantID string) (bool, error) {
	view, err := s.viewGraph(ctx)
	if err != nil {
		return false, err
	}
	return view.HasScopedNodesForTenant(strings.TrimSpace(tenantID)), nil
}

func (s *TenantScopedReadOnlyGraphStore) HasTenantScopedNodes(ctx context.Context, tenantID string) (bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return false, err
	}
	if s == nil || s.store == nil {
		return false, ErrStoreUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return false, nil
	}
	if checker, ok := AsTenantScopedNodePresenceStore(s.store); ok {
		return checker.HasTenantScopedNodes(ctx, tenantID)
	}
	snapshot, err := s.store.Snapshot(ctx)
	if err != nil {
		return false, err
	}
	if snapshot == nil {
		return false, ErrStoreUnavailable
	}
	view := GraphViewFromSnapshot(snapshot)
	if view == nil {
		return false, ErrStoreUnavailable
	}
	return view.HasScopedNodesForTenant(tenantID), nil
}
