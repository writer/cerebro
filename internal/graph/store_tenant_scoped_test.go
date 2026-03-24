package graph

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type recordingTenantScopeAwareGraphStore struct {
	GraphStore
	scope TenantReadScope
}

func (r *recordingTenantScopeAwareGraphStore) SupportsTenantReadScope() bool {
	return true
}

func (r *recordingTenantScopeAwareGraphStore) LookupNode(ctx context.Context, id string) (*Node, bool, error) {
	scope, _ := TenantReadScopeFromContext(ctx)
	r.scope = scope
	return r.GraphStore.LookupNode(ctx, id)
}

func TestTenantScopedReadOnlyGraphStoreAppliesTenantScope(t *testing.T) {
	base := New()
	base.AddNode(&Node{ID: "service:tenant-a", Kind: NodeKindService, TenantID: "tenant-a"})
	base.BuildIndex()

	store := &recordingTenantScopeAwareGraphStore{GraphStore: base}
	scoped := NewTenantScopedReadOnlyGraphStore(store, "tenant-a")

	if _, ok, err := scoped.LookupNode(context.Background(), "service:tenant-a"); err != nil || !ok {
		t.Fatalf("LookupNode() = (%v, %v), want present; err=%v", ok, err, err)
	}
	if got := store.scope.TenantIDs; !reflect.DeepEqual(got, []string{"tenant-a"}) {
		t.Fatalf("tenant scope = %#v, want [tenant-a]", got)
	}
	if !SupportsTenantReadScope(store) {
		t.Fatal("expected tenant scope support helper to recognize the wrapped store")
	}
}

func TestTenantScopedReadOnlyGraphStoreRejectsWrites(t *testing.T) {
	base := New()
	store := &recordingTenantScopeAwareGraphStore{GraphStore: base}
	scoped := NewTenantScopedReadOnlyGraphStore(store, "tenant-a")

	err := scoped.UpsertNode(context.Background(), &Node{ID: "service:new", Kind: NodeKindService, TenantID: "tenant-a"})
	if !errors.Is(err, ErrStoreReadOnly) {
		t.Fatalf("UpsertNode() error = %v, want ErrStoreReadOnly", err)
	}
	if _, ok := base.GetNode("service:new"); ok {
		t.Fatal("expected read-only scoped store to leave the backing graph unchanged")
	}
}
