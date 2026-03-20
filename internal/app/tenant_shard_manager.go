package app

import (
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
)

const (
	defaultGraphTenantShardIdleTTL         = time.Hour
	defaultGraphTenantWarmShardTTL         = 24 * time.Hour
	defaultGraphTenantWarmShardMaxRetained = 1
	defaultGraphTenantHotShardMaxEntries   = 64
)

// tenantGraphShardManager maintains tenant-scoped graph shards across three
// tiers: hot in-memory shards, warm on-disk tenant snapshots, and cold full
// graph snapshots recovered through the graph persistence store.
type tenantGraphShardManager struct {
	mu         sync.Mutex
	source     *graph.Graph
	generation string
	snapshots  *graph.GraphPersistenceStore
	now        func() time.Time
	tiers      *graph.TierManager
	findings   atomic.Pointer[tenantFindingStoreRef]
}

type tenantFindingStoreRef struct {
	store findings.FindingStore
}

func newTenantGraphShardManager(idleTTL, warmTTL time.Duration, warmBasePath string, warmMaxSnapshots int, snapshots *graph.GraphPersistenceStore, findingStore findings.FindingStore) *tenantGraphShardManager {
	manager := &tenantGraphShardManager{
		snapshots: snapshots,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
	manager.setFindingsStore(findingStore)
	manager.tiers = graph.NewTierManager(graph.TierManagerOptions{
		HotRetention:     idleTTL,
		WarmRetention:    warmTTL,
		HotMaxEntries:    defaultGraphTenantHotShardMaxEntries,
		WarmBasePath:     strings.TrimSpace(warmBasePath),
		WarmMaxSnapshots: warmMaxSnapshots,
		Now: func() time.Time {
			return manager.now()
		},
		Pin: func(key string) bool {
			return manager.shouldPinTenant(strings.TrimSpace(key))
		},
	})
	return manager
}

func (m *tenantGraphShardManager) Configure(idleTTL, warmTTL time.Duration, warmBasePath string, warmMaxSnapshots int, snapshots *graph.GraphPersistenceStore, findingStore findings.FindingStore) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshots = snapshots
	m.setFindingsStore(findingStore)
	if m.tiers == nil {
		m.tiers = graph.NewTierManager(graph.TierManagerOptions{})
	}
	m.tiers.Configure(graph.TierManagerOptions{
		HotRetention:     idleTTL,
		WarmRetention:    warmTTL,
		HotMaxEntries:    defaultGraphTenantHotShardMaxEntries,
		WarmBasePath:     strings.TrimSpace(warmBasePath),
		WarmMaxSnapshots: warmMaxSnapshots,
		Now: func() time.Time {
			return m.now()
		},
		Pin: func(key string) bool {
			return m.shouldPinTenant(strings.TrimSpace(key))
		},
	})
}

func (m *tenantGraphShardManager) SetSource(source *graph.Graph) {
	if m == nil {
		return
	}
	nextGeneration := tenantGraphSourceGeneration(source)
	m.mu.Lock()
	defer m.mu.Unlock()
	if source == nil {
		nextGeneration = m.generation
	}
	if source == m.source && nextGeneration == m.generation {
		return
	}
	m.source = source
	m.generation = nextGeneration
	if m.tiers != nil {
		m.tiers.ResetHot()
	}
}

func (m *tenantGraphShardManager) GraphForTenant(source *graph.Graph, tenantID string) *graph.Graph {
	tenantID = strings.TrimSpace(tenantID)
	if m == nil {
		if source == nil || tenantID == "" {
			return source
		}
		return source.SubgraphForTenant(tenantID)
	}
	if tenantID == "" {
		return source
	}

	now := m.now()
	sourceGeneration := tenantGraphSourceGeneration(source)

	m.mu.Lock()
	if source != nil {
		if source != m.source || sourceGeneration != m.generation {
			m.source = source
			m.generation = sourceGeneration
			if m.tiers != nil {
				m.tiers.ResetHot()
			}
		}
	} else if source != m.source {
		m.source = nil
		if m.tiers != nil {
			m.tiers.ResetHot()
		}
	}
	generation := m.generation
	m.mu.Unlock()

	if m.tiers != nil {
		if shard := m.tiers.HotGraph(generation, tenantID); shard != nil {
			return shard
		}
		if generation != "" {
			if shard := m.tiers.WarmGraph(generation, tenantID); shard != nil {
				return m.promoteHotShard(source, generation, tenantID, shard, now)
			}
		}
	}

	if source != nil {
		if shard, hasScopedNodes := source.SubgraphForTenantWithScopedNodes(tenantID); shard != nil {
			if !hasScopedNodes {
				return shard
			}
			m.saveWarmShard(sourceGeneration, tenantID, shard, now)
			return m.promoteHotShard(source, sourceGeneration, tenantID, shard, now)
		}
	}

	coldGeneration, shard := m.loadColdShard(tenantID, sourceGeneration)
	if shard == nil {
		return nil
	}
	m.saveWarmShard(coldGeneration, tenantID, shard, now)
	return m.promoteHotShard(source, coldGeneration, tenantID, shard, now)
}

func (m *tenantGraphShardManager) WarmStoreForTenant(tenantID string) graph.GraphStore {
	tenantID = strings.TrimSpace(tenantID)
	if m == nil || tenantID == "" {
		return nil
	}

	m.mu.Lock()
	generation := m.generation
	m.mu.Unlock()
	if generation == "" || m.tiers == nil {
		return nil
	}

	if shard := m.tiers.HotGraph(generation, tenantID); shard != nil {
		return shard
	}
	return m.tiers.WarmStore(generation, tenantID)
}

func (m *tenantGraphShardManager) EvictExpired(now time.Time) int {
	if m == nil || m.tiers == nil {
		return 0
	}
	return m.tiers.Evict(now.UTC())
}

func (m *tenantGraphShardManager) shouldPinTenant(tenantID string) bool {
	if m == nil {
		return false
	}
	storeRef := m.findings.Load()
	if storeRef == nil || storeRef.store == nil {
		return false
	}
	return storeRef.store.Count(findings.FindingFilter{TenantID: tenantID, Status: "OPEN"}) > 0
}

func (m *tenantGraphShardManager) promoteHotShard(source *graph.Graph, generation, tenantID string, shardGraph *graph.Graph, now time.Time) *graph.Graph {
	if m == nil || shardGraph == nil {
		return shardGraph
	}
	m.mu.Lock()
	var finalize func()
	if source == nil {
		if m.source != nil {
			m.mu.Unlock()
			return shardGraph
		}
		if generation != "" && generation != m.generation {
			m.generation = generation
			if m.tiers != nil {
				m.tiers.ResetHot()
			}
		}
	} else {
		if source != m.source {
			m.mu.Unlock()
			return shardGraph
		}
		if generation != "" && m.generation != "" && generation != m.generation {
			m.mu.Unlock()
			return shardGraph
		}
	}
	if m.tiers != nil {
		_, finalize = m.tiers.PromoteHotDeferred(generation, tenantID, shardGraph, now)
	}
	m.mu.Unlock()
	if finalize != nil {
		finalize()
	}
	return shardGraph
}

func (m *tenantGraphShardManager) saveWarmShard(generation, tenantID string, shardGraph *graph.Graph, now time.Time) {
	if m == nil || m.tiers == nil {
		return
	}
	m.tiers.SaveWarm(generation, tenantID, shardGraph, now)
}

func (m *tenantGraphShardManager) loadColdShard(tenantID, liveGeneration string) (string, *graph.Graph) {
	if m == nil || m.snapshots == nil {
		return "", nil
	}
	snapshot, record, _, err := m.snapshots.LoadLatestSnapshot()
	if err != nil || snapshot == nil {
		return "", nil
	}
	generation := tenantGraphSnapshotGeneration(snapshot, record)
	if liveGeneration != "" && generation != "" && generation != liveGeneration {
		return "", nil
	}
	view := graph.GraphViewFromSnapshot(snapshot)
	if view == nil {
		return generation, nil
	}
	return generation, view.SubgraphForTenant(tenantID)
}

func tenantGraphSourceGeneration(source *graph.Graph) string {
	if source == nil {
		return ""
	}
	if record := graph.CurrentGraphSnapshotRecord(source); record != nil {
		if id := strings.TrimSpace(record.ID); id != "" {
			return id
		}
	}
	meta := source.Metadata()
	if meta.BuiltAt.IsZero() {
		return ""
	}
	return "built-at-" + meta.BuiltAt.UTC().Format(time.RFC3339Nano)
}

func tenantGraphSnapshotGeneration(snapshot *graph.Snapshot, record *graph.GraphSnapshotRecord) string {
	if record != nil {
		if id := strings.TrimSpace(record.ID); id != "" {
			return id
		}
	}
	if snapshot == nil || snapshot.Metadata.BuiltAt.IsZero() {
		return ""
	}
	return "built-at-" + snapshot.Metadata.BuiltAt.UTC().Format(time.RFC3339Nano)
}

func (m *tenantGraphShardManager) setFindingsStore(store findings.FindingStore) {
	if m == nil {
		return
	}
	if store == nil {
		m.findings.Store(nil)
		return
	}
	m.findings.Store(&tenantFindingStoreRef{store: store})
}

func (a *App) graphTenantShardIdleTTL() time.Duration {
	if a == nil || a.Config == nil || a.Config.GraphTenantShardIdleTTL <= 0 {
		return defaultGraphTenantShardIdleTTL
	}
	return a.Config.GraphTenantShardIdleTTL
}

func (a *App) graphTenantWarmShardTTL() time.Duration {
	if a == nil || a.Config == nil || a.Config.GraphTenantWarmShardTTL <= 0 {
		return defaultGraphTenantWarmShardTTL
	}
	return a.Config.GraphTenantWarmShardTTL
}

func (a *App) graphTenantWarmShardMaxRetained() int {
	if a == nil || a.Config == nil || a.Config.GraphTenantWarmShardMaxRetained <= 0 {
		return defaultGraphTenantWarmShardMaxRetained
	}
	return a.Config.GraphTenantWarmShardMaxRetained
}

func (a *App) graphTenantWarmShardPath() string {
	if a == nil {
		return ""
	}
	basePath := ""
	if a.GraphSnapshots != nil && a.GraphSnapshots.LocalStore() != nil {
		basePath = strings.TrimSpace(a.GraphSnapshots.LocalStore().BasePath())
	}
	if basePath == "" && a.Config != nil {
		basePath = strings.TrimSpace(a.Config.GraphSnapshotPath)
	}
	if basePath == "" {
		return ""
	}
	return filepath.Join(basePath, "tenant-shards")
}

func (a *App) ensureTenantSecurityGraphShards() *tenantGraphShardManager {
	if a == nil {
		return nil
	}
	a.tenantShardMu.Lock()
	defer a.tenantShardMu.Unlock()
	if a.tenantSecurityGraphShards == nil {
		a.tenantSecurityGraphShards = newTenantGraphShardManager(
			a.graphTenantShardIdleTTL(),
			a.graphTenantWarmShardTTL(),
			a.graphTenantWarmShardPath(),
			a.graphTenantWarmShardMaxRetained(),
			a.GraphSnapshots,
			a.Findings,
		)
		return a.tenantSecurityGraphShards
	}
	a.tenantSecurityGraphShards.Configure(
		a.graphTenantShardIdleTTL(),
		a.graphTenantWarmShardTTL(),
		a.graphTenantWarmShardPath(),
		a.graphTenantWarmShardMaxRetained(),
		a.GraphSnapshots,
		a.Findings,
	)
	return a.tenantSecurityGraphShards
}

func (a *App) currentTenantSecurityGraphShards() *tenantGraphShardManager {
	if a == nil {
		return nil
	}
	a.tenantShardMu.Lock()
	defer a.tenantShardMu.Unlock()
	return a.tenantSecurityGraphShards
}
