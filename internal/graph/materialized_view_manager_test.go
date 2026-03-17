package graph

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestMaterializedDetectionViewManagerIgnoresIrrelevantChanges(t *testing.T) {
	g := New()
	manager := NewMaterializedDetectionViewManager(g, MaterializedDetectionViewsConfig{
		RefreshDebounce:      2 * time.Second,
		BlastRadiusTopNLimit: 5,
		BlastRadiusTopNDepth: 2,
	}, testMaterializedViewLogger())

	var blastRefreshes atomic.Int32
	var toxicRefreshes atomic.Int32
	manager.blastRadiusRefreshHook = func() { blastRefreshes.Add(1) }
	manager.toxicRefreshHook = func() { toxicRefreshes.Add(1) }

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(manager.Stop)

	waitForAtomicCount(t, &blastRefreshes, 1, time.Second)
	waitForAtomicCount(t, &toxicRefreshes, 1, time.Second)

	g.AddNode(&Node{ID: "document:runbook", Kind: NodeKindDocument, Name: "runbook"})
	assertAtomicCountStays(t, &blastRefreshes, 1, 100*time.Millisecond)
	assertAtomicCountStays(t, &toxicRefreshes, 1, 100*time.Millisecond)

	g.AddNode(&Node{ID: "customer:acme", Kind: NodeKindCustomer, Name: "Acme"})
	waitForAtomicCount(t, &toxicRefreshes, 2, 2*time.Second)
	assertAtomicCountStays(t, &blastRefreshes, 1, 100*time.Millisecond)
}

func TestMaterializedDetectionViewManagerBlastRadiusViewTracksMutations(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "alice"})
	g.AddNode(&Node{ID: "bucket:logs", Kind: NodeKindBucket, Name: "logs", Risk: RiskHigh})

	manager := NewMaterializedDetectionViewManager(g, MaterializedDetectionViewsConfig{
		RefreshDebounce:      2 * time.Second,
		BlastRadiusTopNLimit: 5,
		BlastRadiusTopNDepth: 2,
	}, testMaterializedViewLogger())

	var blastRefreshes atomic.Int32
	manager.blastRadiusRefreshHook = func() { blastRefreshes.Add(1) }

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(manager.Stop)

	waitForAtomicCount(t, &blastRefreshes, 1, time.Second)
	initial := waitForBlastRadiusViewVersion(t, manager, g.currentBlastRadiusCacheVersion(), time.Second)
	if initial == nil {
		t.Fatal("expected initial blast radius view")
	}
	if len(initial.Entries) != 0 {
		t.Fatalf("expected empty initial entries, got %d", len(initial.Entries))
	}

	g.AddEdge(&Edge{
		ID:     "edge-1",
		Source: "user:alice",
		Target: "bucket:logs",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	waitForAtomicCount(t, &blastRefreshes, 2, 2*time.Second)
	view := waitForBlastRadiusViewVersion(t, manager, g.currentBlastRadiusCacheVersion(), 2*time.Second)
	if view == nil {
		t.Fatal("expected blast radius view after mutation")
	}
	if len(view.Entries) != 1 {
		t.Fatalf("len(view.Entries) = %d, want 1", len(view.Entries))
	}
	if view.Entries[0].PrincipalID != "user:alice" {
		t.Fatalf("view.Entries[0].PrincipalID = %q, want user:alice", view.Entries[0].PrincipalID)
	}
	if view.Entries[0].ReachableCount != 1 {
		t.Fatalf("view.Entries[0].ReachableCount = %d, want 1", view.Entries[0].ReachableCount)
	}
}

func TestMaterializedDetectionViewManagerCoalescesRapidChanges(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "alice"})
	g.AddNode(&Node{ID: "bucket:logs", Kind: NodeKindBucket, Name: "logs"})

	manager := NewMaterializedDetectionViewManager(g, MaterializedDetectionViewsConfig{
		RefreshDebounce:      2 * time.Second,
		BlastRadiusTopNLimit: 5,
		BlastRadiusTopNDepth: 3,
	}, testMaterializedViewLogger())

	var blastRefreshes atomic.Int32
	manager.blastRadiusRefreshHook = func() { blastRefreshes.Add(1) }

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(manager.Stop)

	waitForAtomicCount(t, &blastRefreshes, 1, time.Second)

	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Name: "admin"})
	g.AddEdge(&Edge{ID: "edge-1", Source: "user:alice", Target: "role:admin", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "edge-2", Source: "role:admin", Target: "bucket:logs", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	waitForAtomicCount(t, &blastRefreshes, 2, 2*time.Second)
	assertAtomicCountStays(t, &blastRefreshes, 2, 100*time.Millisecond)
}

func waitForAtomicCount(t *testing.T, value *atomic.Int32, want int32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if value.Load() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if value.Load() >= want {
		return
	}
	t.Fatalf("timed out waiting for atomic count %d, got %d", want, value.Load())
}

func assertAtomicCountStays(t *testing.T, value *atomic.Int32, want int32, duration time.Duration) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if value.Load() != want {
			t.Fatalf("expected atomic count to stay at %d, got %d", want, value.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitForBlastRadiusViewVersion(
	t *testing.T,
	manager *MaterializedDetectionViewManager,
	wantVersion uint64,
	timeout time.Duration,
) *BlastRadiusTopNView {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		view := manager.BlastRadiusTopNView()
		if view != nil && view.Version == wantVersion {
			return view
		}
		time.Sleep(5 * time.Millisecond)
	}
	view := manager.BlastRadiusTopNView()
	if view == nil {
		t.Fatalf("timed out waiting for blast radius view version %d", wantVersion)
	}
	t.Fatalf("timed out waiting for blast radius view version %d, got %d", wantVersion, view.Version)
	return nil
}

func testMaterializedViewLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
