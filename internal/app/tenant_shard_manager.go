package app

import (
	"strings"
	"sync"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

const defaultGraphTenantShardIdleTTL = 15 * time.Minute

type tenantGraphShard struct {
	graph      *graph.Graph
	lastAccess time.Time
}

// tenantGraphShardManager caches tenant-scoped graph shards derived from the
// current hot graph. It invalidates the cache whenever the source graph pointer
// changes and lazily evicts idle shards on later reads.
type tenantGraphShardManager struct {
	mu      sync.Mutex
	source  *graph.Graph
	idleTTL time.Duration
	now     func() time.Time
	shards  map[string]tenantGraphShard
}

func newTenantGraphShardManager(idleTTL time.Duration) *tenantGraphShardManager {
	if idleTTL <= 0 {
		idleTTL = defaultGraphTenantShardIdleTTL
	}
	return &tenantGraphShardManager{
		idleTTL: idleTTL,
		now: func() time.Time {
			return time.Now().UTC()
		},
		shards: make(map[string]tenantGraphShard),
	}
}

func (m *tenantGraphShardManager) SetSource(source *graph.Graph) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if source == m.source {
		return
	}
	m.source = source
	clear(m.shards)
}

func (m *tenantGraphShardManager) GraphForTenant(source *graph.Graph, tenantID string) *graph.Graph {
	tenantID = strings.TrimSpace(tenantID)
	if m == nil {
		return nil
	}
	if source == nil {
		m.SetSource(nil)
		return nil
	}
	if tenantID == "" {
		return source
	}

	now := m.now()

	m.mu.Lock()
	defer m.mu.Unlock()

	if source != m.source {
		m.source = source
		clear(m.shards)
	}
	m.evictExpiredLocked(now)

	if shard, ok := m.shards[tenantID]; ok && shard.graph != nil {
		shard.lastAccess = now
		m.shards[tenantID] = shard
		return shard.graph
	}

	shardGraph := source.SubgraphForTenant(tenantID)
	if shardGraph == nil {
		return nil
	}
	m.shards[tenantID] = tenantGraphShard{
		graph:      shardGraph,
		lastAccess: now,
	}
	return shardGraph
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
		if shard.lastAccess.After(cutoff) {
			continue
		}
		delete(m.shards, tenantID)
		evicted++
	}
	return evicted
}

func (a *App) graphTenantShardIdleTTL() time.Duration {
	if a == nil || a.Config == nil || a.Config.GraphTenantShardIdleTTL <= 0 {
		return defaultGraphTenantShardIdleTTL
	}
	return a.Config.GraphTenantShardIdleTTL
}

func (a *App) ensureTenantSecurityGraphShards() *tenantGraphShardManager {
	if a == nil {
		return nil
	}
	a.tenantShardMu.Lock()
	defer a.tenantShardMu.Unlock()
	if a.tenantSecurityGraphShards == nil {
		a.tenantSecurityGraphShards = newTenantGraphShardManager(a.graphTenantShardIdleTTL())
	}
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
