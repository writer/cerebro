package app

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/graph"
)

const (
	defaultGraphTenantShardIdleTTL         = 15 * time.Minute
	defaultGraphTenantWarmShardTTL         = 24 * time.Hour
	defaultGraphTenantWarmShardMaxRetained = 1
	tenantGraphWarmCleanupInterval         = 15 * time.Minute
)

type tenantGraphShard struct {
	graph      *graph.Graph
	lastAccess time.Time
}

// tenantGraphShardManager maintains tenant-scoped graph shards across three
// tiers: hot in-memory shards, warm on-disk tenant snapshots, and cold full
// graph snapshots recovered through the graph persistence store.
type tenantGraphShardManager struct {
	mu               sync.Mutex
	source           *graph.Graph
	generation       string
	idleTTL          time.Duration
	warmTTL          time.Duration
	warmBasePath     string
	warmMaxSnapshots int
	snapshots        *graph.GraphPersistenceStore
	findings         findings.FindingStore
	now              func() time.Time
	lastWarmCleanup  time.Time
	shards           map[string]tenantGraphShard
}

func newTenantGraphShardManager(idleTTL, warmTTL time.Duration, warmBasePath string, warmMaxSnapshots int, snapshots *graph.GraphPersistenceStore, findingStore findings.FindingStore) *tenantGraphShardManager {
	if idleTTL <= 0 {
		idleTTL = defaultGraphTenantShardIdleTTL
	}
	if warmTTL <= 0 {
		warmTTL = defaultGraphTenantWarmShardTTL
	}
	if warmMaxSnapshots <= 0 {
		warmMaxSnapshots = defaultGraphTenantWarmShardMaxRetained
	}
	return &tenantGraphShardManager{
		idleTTL:          idleTTL,
		warmTTL:          warmTTL,
		warmBasePath:     strings.TrimSpace(warmBasePath),
		warmMaxSnapshots: warmMaxSnapshots,
		snapshots:        snapshots,
		findings:         findingStore,
		now: func() time.Time {
			return time.Now().UTC()
		},
		shards: make(map[string]tenantGraphShard),
	}
}

func (m *tenantGraphShardManager) Configure(idleTTL, warmTTL time.Duration, warmBasePath string, warmMaxSnapshots int, snapshots *graph.GraphPersistenceStore, findingStore findings.FindingStore) {
	if m == nil {
		return
	}
	if idleTTL <= 0 {
		idleTTL = defaultGraphTenantShardIdleTTL
	}
	if warmTTL <= 0 {
		warmTTL = defaultGraphTenantWarmShardTTL
	}
	if warmMaxSnapshots <= 0 {
		warmMaxSnapshots = defaultGraphTenantWarmShardMaxRetained
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idleTTL = idleTTL
	m.warmTTL = warmTTL
	m.warmBasePath = strings.TrimSpace(warmBasePath)
	m.warmMaxSnapshots = warmMaxSnapshots
	m.snapshots = snapshots
	m.findings = findingStore
	if m.shards == nil {
		m.shards = make(map[string]tenantGraphShard)
	}
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
	clear(m.shards)
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
			clear(m.shards)
		}
	} else if source != m.source {
		m.source = nil
		clear(m.shards)
	}
	m.evictExpiredLocked(now)
	if shard, ok := m.shards[tenantID]; ok && shard.graph != nil {
		shard.lastAccess = now
		m.shards[tenantID] = shard
		result := shard.graph
		m.mu.Unlock()
		return result
	}
	generation := m.generation
	m.mu.Unlock()

	m.maybeCleanupWarmTier(now)

	if generation != "" {
		if shard := m.loadWarmShard(generation, tenantID, now); shard != nil {
			return m.promoteHotShard(source, generation, tenantID, shard, now)
		}
	}

	if source != nil {
		if shard := source.SubgraphForTenant(tenantID); shard != nil {
			if sourceGeneration != "" {
				m.saveWarmShard(sourceGeneration, tenantID, shard, now)
			}
			return m.promoteHotShard(source, sourceGeneration, tenantID, shard, now)
		}
	}

	coldGeneration, shard := m.loadColdShard(tenantID, sourceGeneration)
	if shard == nil {
		return nil
	}
	if coldGeneration != "" {
		m.saveWarmShard(coldGeneration, tenantID, shard, now)
	}
	return m.promoteHotShard(source, coldGeneration, tenantID, shard, now)
}

func (m *tenantGraphShardManager) EvictExpired(now time.Time) int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.evictExpiredLocked(now.UTC())
}

func (m *tenantGraphShardManager) evictExpiredLocked(now time.Time) int {
	if m.idleTTL <= 0 || len(m.shards) == 0 {
		return 0
	}
	cutoff := now.Add(-m.idleTTL)
	evicted := 0
	for tenantID, shard := range m.shards {
		if shard.lastAccess.After(cutoff) || m.shouldPinTenantLocked(tenantID) {
			continue
		}
		delete(m.shards, tenantID)
		evicted++
	}
	return evicted
}

func (m *tenantGraphShardManager) shouldPinTenantLocked(tenantID string) bool {
	if m == nil || m.findings == nil {
		return false
	}
	return m.findings.Count(findings.FindingFilter{TenantID: tenantID, Status: "OPEN"}) > 0
}

func (m *tenantGraphShardManager) promoteHotShard(source *graph.Graph, generation, tenantID string, shardGraph *graph.Graph, now time.Time) *graph.Graph {
	if m == nil || shardGraph == nil {
		return shardGraph
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if source == nil {
		if m.source != nil {
			return shardGraph
		}
		if generation != "" && generation != m.generation {
			m.generation = generation
			clear(m.shards)
		}
	} else {
		if source != m.source {
			return shardGraph
		}
		if generation != "" && m.generation != "" && generation != m.generation {
			return shardGraph
		}
	}
	m.shards[tenantID] = tenantGraphShard{
		graph:      shardGraph,
		lastAccess: now,
	}
	return shardGraph
}

func (m *tenantGraphShardManager) loadWarmShard(generation, tenantID string, now time.Time) *graph.Graph {
	if m == nil || generation == "" || strings.TrimSpace(m.warmBasePath) == "" {
		return nil
	}
	store := tenantGraphWarmStore(m.warmBasePath, generation, tenantID, m.warmMaxSnapshots)
	snapshot, _, err := store.LoadLatestSnapshot()
	if err != nil || snapshot == nil {
		return nil
	}
	tenantDir := store.BasePath()
	touchPath(tenantDir, now)
	touchPath(filepath.Dir(tenantDir), now)
	return graph.GraphViewFromSnapshot(snapshot)
}

func (m *tenantGraphShardManager) saveWarmShard(generation, tenantID string, shardGraph *graph.Graph, now time.Time) {
	if m == nil || generation == "" || shardGraph == nil || strings.TrimSpace(m.warmBasePath) == "" {
		return
	}
	store := tenantGraphWarmStore(m.warmBasePath, generation, tenantID, m.warmMaxSnapshots)
	if _, _, err := store.SaveGraph(shardGraph); err != nil {
		return
	}
	tenantDir := store.BasePath()
	touchPath(tenantDir, now)
	touchPath(filepath.Dir(tenantDir), now)
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

func (m *tenantGraphShardManager) maybeCleanupWarmTier(now time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	basePath := strings.TrimSpace(m.warmBasePath)
	warmTTL := m.warmTTL
	interval := tenantGraphWarmCleanupInterval
	if warmTTL > 0 && warmTTL < interval {
		interval = warmTTL
	}
	if basePath == "" || warmTTL <= 0 {
		m.mu.Unlock()
		return
	}
	if !m.lastWarmCleanup.IsZero() && now.Sub(m.lastWarmCleanup) < interval {
		m.mu.Unlock()
		return
	}
	m.lastWarmCleanup = now
	m.mu.Unlock()

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return
	}
	cutoff := now.Add(-warmTTL)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(basePath, entry.Name()))
	}
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

func tenantGraphWarmStore(basePath, generation, tenantID string, maxSnapshots int) *graph.SnapshotStore {
	return graph.NewSnapshotStore(tenantGraphWarmDir(basePath, generation, tenantID), maxSnapshots)
}

func tenantGraphWarmDir(basePath, generation, tenantID string) string {
	return filepath.Join(
		strings.TrimSpace(basePath),
		tenantGraphCacheDirName("generation", generation),
		tenantGraphCacheDirName("tenant", tenantID),
	)
}

func tenantGraphCacheDirName(prefix, value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return prefix + "-" + hex.EncodeToString(sum[:8])
}

func touchPath(path string, now time.Time) {
	if strings.TrimSpace(path) == "" || now.IsZero() {
		return
	}
	_ = os.Chtimes(path, now, now)
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
