package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/health"
)

func TestGraphHealthSnapshotAggregatesLiveGraphPersistenceAndTiers(t *testing.T) {
	now := time.Date(2026, time.March, 20, 18, 0, 0, 0, time.UTC)

	current := graph.New()
	current.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, TenantID: "tenant-a"})
	current.AddNode(&graph.Node{ID: "bucket:prod", Kind: graph.NodeKindBucket})
	current.AddEdge(&graph.Edge{ID: "edge:read", Source: "service:payments", Target: "bucket:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	current.SetMetadata(graph.Metadata{
		BuiltAt:   now.Add(-10 * time.Minute),
		NodeCount: current.NodeCount(),
		EdgeCount: current.EdgeCount(),
	})

	store := mustPersistToolGraph(t, current)
	manager := newTenantGraphShardManager(10*time.Minute, time.Hour, filepath.Join(t.TempDir(), "tenant-shards"), 1, store, nil)
	manager.now = func() time.Time { return now }

	warm := graph.New()
	warm.AddNode(&graph.Node{ID: "service:tenant-b", Kind: graph.NodeKindService, TenantID: "tenant-b"})
	warm.SetMetadata(graph.Metadata{
		BuiltAt:   now.Add(-30 * time.Minute),
		NodeCount: warm.NodeCount(),
		EdgeCount: warm.EdgeCount(),
	})
	manager.saveWarmShard("generation-1", "tenant-b", warm, now)

	application := &App{
		GraphSnapshots: store,
		graphWriterLease: &graphWriterLeaseManager{
			status: GraphWriterLeaseStatus{
				Enabled:       true,
				Role:          GraphWriterRoleWriter,
				LeaseHolderID: "writer-1",
				OwnerID:       "writer-1",
			},
		},
	}
	application.setSecurityGraph(current)
	application.tenantSecurityGraphShards = manager
	manager.SetSource(current)
	if got := manager.GraphForTenant(current, "tenant-a"); got == nil || got.NodeCount() == 0 {
		t.Fatal("expected tenant-a graph to seed hot tier")
	}

	snapshot := application.GraphHealthSnapshot(now)
	if snapshot.NodeCount != current.NodeCount() {
		t.Fatalf("NodeCount = %d, want %d", snapshot.NodeCount, current.NodeCount())
	}
	if snapshot.EdgeCount != current.EdgeCount() {
		t.Fatalf("EdgeCount = %d, want %d", snapshot.EdgeCount, current.EdgeCount())
	}
	if snapshot.SnapshotCount != 1 {
		t.Fatalf("SnapshotCount = %d, want 1", snapshot.SnapshotCount)
	}
	if !snapshot.LastMutationAt.Equal(now.Add(-10 * time.Minute)) {
		t.Fatalf("LastMutationAt = %s, want %s", snapshot.LastMutationAt, now.Add(-10*time.Minute))
	}
	if snapshot.WriterLease.LeaseHolderID != "writer-1" {
		t.Fatalf("LeaseHolderID = %q, want writer-1", snapshot.WriterLease.LeaseHolderID)
	}
	if snapshot.TierDistribution.Hot != 2 || snapshot.TierDistribution.Warm != 2 || snapshot.TierDistribution.Cold != 1 {
		t.Fatalf("TierDistribution = %+v, want hot=2 warm=2 cold=1", snapshot.TierDistribution)
	}
	if snapshot.MemoryUsageEstimateBytes <= 0 {
		t.Fatalf("expected positive memory estimate, got %d", snapshot.MemoryUsageEstimateBytes)
	}
}

func TestGraphHealthSnapshotUsesConfiguredStoreWhenLiveGraphUnavailable(t *testing.T) {
	now := time.Date(2026, time.March, 20, 18, 0, 0, 0, time.UTC)

	configured := graph.New()
	configured.AddNode(&graph.Node{ID: "service:configured", Kind: graph.NodeKindService})
	configured.SetMetadata(graph.Metadata{
		BuiltAt:   now.Add(-time.Hour),
		NodeCount: configured.NodeCount(),
		EdgeCount: configured.EdgeCount(),
	})

	application := &App{}
	setConfiguredGraphFromGraph(t, application, configured)

	snapshot := application.GraphHealthSnapshot(now)
	if snapshot.NodeCount != 1 || snapshot.EdgeCount != 0 {
		t.Fatalf("snapshot counts = (%d,%d), want (1,0)", snapshot.NodeCount, snapshot.EdgeCount)
	}
	if snapshot.SnapshotCount != 0 {
		t.Fatalf("SnapshotCount = %d, want 0", snapshot.SnapshotCount)
	}
	if snapshot.TierDistribution.Hot != 0 || snapshot.TierDistribution.Warm != 0 || snapshot.TierDistribution.Cold != 0 {
		t.Fatalf("TierDistribution = %+v, want hot=0 warm=0 cold=0", snapshot.TierDistribution)
	}
	if snapshot.LastMutationAt.IsZero() {
		t.Fatal("expected last mutation timestamp from configured store")
	}
}

func TestGraphRuntimeHealthCheckReportsDegradedWhenOnlySnapshotsRemain(t *testing.T) {
	now := time.Date(2026, time.March, 20, 18, 0, 0, 0, time.UTC)

	persisted := graph.New()
	persisted.AddNode(&graph.Node{ID: "service:persisted", Kind: graph.NodeKindService})
	persisted.SetMetadata(graph.Metadata{
		BuiltAt:   now.Add(-time.Hour),
		NodeCount: persisted.NodeCount(),
		EdgeCount: persisted.EdgeCount(),
	})

	application := &App{
		GraphSnapshots: mustPersistToolGraph(t, persisted),
	}

	result := application.graphRuntimeHealthCheck()(context.Background())
	if result.Status != health.StatusDegraded {
		t.Fatalf("graphRuntimeHealthCheck status = %s, want degraded", result.Status)
	}
	if result.Message != "persistent graph unavailable; persisted snapshots available" {
		t.Fatalf("graphRuntimeHealthCheck message = %q", result.Message)
	}
}
