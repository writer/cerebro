package app

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/health"
)

const (
	// Heuristic sizing constants for a materialized graph view. These are not
	// exact object sizes; they provide a stable order-of-magnitude estimate for
	// operators without forcing a full snapshot serialization on every request.
	graphHealthEstimatedNodeBytes = 768
	graphHealthEstimatedEdgeBytes = 384
)

type GraphTierDistribution struct {
	Hot  int `json:"hot"`
	Warm int `json:"warm"`
	Cold int `json:"cold"`
}

type GraphHealthSnapshot struct {
	EvaluatedAt              time.Time              `json:"evaluated_at"`
	NodeCount                int                    `json:"node_count"`
	EdgeCount                int                    `json:"edge_count"`
	SnapshotCount            int                    `json:"snapshot_count"`
	LastMutationAt           time.Time              `json:"last_mutation_at,omitempty"`
	WriterLease              GraphWriterLeaseStatus `json:"writer_lease"`
	TierDistribution         GraphTierDistribution  `json:"tier_distribution"`
	MemoryUsageEstimateBytes int64                  `json:"memory_usage_estimate_bytes"`
}

func (a *App) GraphHealthSnapshot(now time.Time) GraphHealthSnapshot {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	snapshot := GraphHealthSnapshot{
		EvaluatedAt: now,
		WriterLease: a.GraphWriterLeaseStatusSnapshot(),
	}

	view, err := a.currentOrStoredPassiveSecurityGraphView()
	if err != nil && a != nil && a.Logger != nil {
		a.Logger.Warn("failed to resolve graph for health snapshot", "error", err)
	}
	if view != nil {
		snapshot.NodeCount = view.NodeCount()
		snapshot.EdgeCount = view.EdgeCount()
	}

	records, recordsErr := a.graphSnapshotRecords()
	snapshot.SnapshotCount = len(records)
	if recordsErr != nil {
		snapshot.SnapshotCount = 0
	}
	snapshot.LastMutationAt = a.graphLastMutationAt(view, records, recordsErr)
	snapshot.TierDistribution = a.graphTierDistribution(snapshot.SnapshotCount)
	snapshot.MemoryUsageEstimateBytes = EstimateGraphMemoryUsageBytes(snapshot.NodeCount, snapshot.EdgeCount)
	return snapshot
}

func (a *App) graphRuntimeHealthCheck() health.Checker {
	return func(_ context.Context) health.CheckResult {
		start := time.Now().UTC()
		snapshot := a.GraphHealthSnapshot(start)
		result := health.CheckResult{
			Name:      "graph_runtime",
			Timestamp: start,
		}

		switch {
		case snapshot.NodeCount > 0 && (snapshot.TierDistribution.Hot > 0 || (a != nil && a.configuredSecurityGraphReady)):
			result.Status = health.StatusHealthy
			result.Message = fmt.Sprintf(
				"graph ready; nodes=%d edges=%d snapshots=%d hot=%d warm=%d cold=%d",
				snapshot.NodeCount,
				snapshot.EdgeCount,
				snapshot.SnapshotCount,
				snapshot.TierDistribution.Hot,
				snapshot.TierDistribution.Warm,
				snapshot.TierDistribution.Cold,
			)
		case snapshot.SnapshotCount > 0:
			result.Status = health.StatusDegraded
			result.Message = "persistent graph unavailable; persisted snapshots available"
		default:
			result.Status = health.StatusUnknown
			result.Message = "graph not initialized"
		}
		result.Latency = time.Since(start)
		return result
	}
}

func (a *App) graphSnapshotRecords() ([]graph.GraphSnapshotRecord, error) {
	if a == nil || a.GraphSnapshots == nil {
		return nil, nil
	}
	return a.GraphSnapshots.ListGraphSnapshotRecords()
}

func (a *App) graphLastMutationAt(view *graph.Graph, records []graph.GraphSnapshotRecord, recordsErr error) time.Time {
	if a != nil && a.SecurityGraphBuilder != nil {
		if last := a.SecurityGraphBuilder.LastMutation().Until; !last.IsZero() {
			return last.UTC()
		}
	}
	if view != nil {
		if builtAt := view.Metadata().BuiltAt; !builtAt.IsZero() {
			return builtAt.UTC()
		}
	}
	if a != nil && a.GraphSnapshots != nil {
		if recordsErr == nil && len(records) > 0 {
			return graphSnapshotRecordTimestamp(records[len(records)-1])
		}
		if persistedAt := a.GraphSnapshots.Status().LastPersistedAt; persistedAt != nil && !persistedAt.IsZero() {
			return persistedAt.UTC()
		}
	}
	return time.Time{}
}

func (a *App) graphTierDistribution(snapshotCount int) GraphTierDistribution {
	distribution := GraphTierDistribution{
		Cold: snapshotCount,
	}
	if a == nil {
		return distribution
	}
	if current := a.currentLiveSecurityGraph(); current != nil && current.NodeCount() > 0 {
		distribution.Hot++
	}
	if manager := a.currentTenantSecurityGraphShards(); manager != nil {
		distribution.Hot += manager.hotShardCount()
		distribution.Warm = manager.warmShardCount()
	}
	return distribution
}

// EstimateGraphMemoryUsageBytes applies the graph health sizing heuristic.
func EstimateGraphMemoryUsageBytes(nodeCount, edgeCount int) int64 {
	if nodeCount <= 0 && edgeCount <= 0 {
		return 0
	}
	return int64(nodeCount)*graphHealthEstimatedNodeBytes + int64(edgeCount)*graphHealthEstimatedEdgeBytes
}

func graphSnapshotRecordTimestamp(record graph.GraphSnapshotRecord) time.Time {
	switch {
	case record.BuiltAt != nil && !record.BuiltAt.IsZero():
		return record.BuiltAt.UTC()
	case record.CapturedAt != nil && !record.CapturedAt.IsZero():
		return record.CapturedAt.UTC()
	case record.LastObservedAt != nil && !record.LastObservedAt.IsZero():
		return record.LastObservedAt.UTC()
	case record.FirstObservedAt != nil && !record.FirstObservedAt.IsZero():
		return record.FirstObservedAt.UTC()
	default:
		return time.Time{}
	}
}

func (m *tenantGraphShardManager) hotShardCount() int {
	if m == nil || m.tiers == nil {
		return 0
	}
	return m.tiers.HotCount()
}

func (m *tenantGraphShardManager) warmShardCount() int {
	if m == nil {
		return 0
	}
	basePath := ""
	if m.tiers != nil {
		basePath = m.tiers.WarmBasePath()
	}
	if basePath == "" {
		return 0
	}

	tenantDirs := make(map[string]struct{})
	_ = filepath.WalkDir(basePath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry == nil || entry.IsDir() {
			return nil
		}
		if matched, _ := filepath.Match("graph-*.json.gz", entry.Name()); !matched {
			return nil
		}
		tenantDir := filepath.Dir(path)
		tenantDirs[tenantDir] = struct{}{}
		return nil
	})
	return len(tenantDirs)
}
