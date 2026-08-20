package graphagent

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const graphProbeCountsCacheTTL = 2 * time.Minute

var graphProbeCountsCache = struct {
	sync.Mutex
	entries map[string]graphProbeCountsCacheEntry
}{
	entries: map[string]graphProbeCountsCacheEntry{},
}

type graphProbeCountsCacheEntry struct {
	ExpiresAt    time.Time
	EntityTypes  []GraphProbeCount
	Relations    []GraphProbeCount
	SourceCount  int64
	FindingCount int64
}

type GraphProbe struct {
	ScopeURN     string            `json:"scope_urn,omitempty"`
	ScopeFound   bool              `json:"scope_found,omitempty"`
	ScopeType    string            `json:"scope_type,omitempty"`
	ScopeLabel   string            `json:"scope_label,omitempty"`
	EntityTypes  []GraphProbeCount `json:"entity_types,omitempty"`
	Relations    []GraphProbeCount `json:"relations,omitempty"`
	SourceCount  int64             `json:"source_count,omitempty"`
	FindingCount int64             `json:"finding_count,omitempty"`
	Warnings     []string          `json:"warnings,omitempty"`
}

type GraphProbeCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

func collectGraphProbe(ctx context.Context, entityKindCounts ports.EntityKindCountStore, relationCounts ports.RelationCountStore, neighborhoods ports.GraphNeighborhoodStore, request AskRequest) GraphProbe {
	probe := GraphProbe{ScopeURN: strings.TrimSpace(request.ScopeURN)}
	if entityKindCounts == nil && relationCounts == nil && neighborhoods == nil {
		probe.Warnings = append(probe.Warnings, "graph_store_unavailable")
		return probe
	}
	if probe.ScopeURN != "" {
		if neighborhoods == nil {
			probe.Warnings = append(probe.Warnings, "scope_not_found")
		} else if neighborhood, err := neighborhoods.GetEntityNeighborhood(ctx, probe.ScopeURN, 10); err != nil {
			probe.Warnings = append(probe.Warnings, "scope_not_found")
		} else if neighborhood != nil && neighborhood.Root != nil {
			probe.ScopeFound = true
			probe.ScopeType = neighborhood.Root.EntityType
			probe.ScopeLabel = neighborhood.Root.Label
		}
	}
	if cached, ok := cachedGraphProbeCounts(request.TenantID); ok {
		probe.EntityTypes = cached.EntityTypes
		probe.Relations = cached.Relations
		probe.SourceCount = cached.SourceCount
		probe.FindingCount = cached.FindingCount
		return probe
	}
	warningsBeforeCounts := len(probe.Warnings)
	if entityKindCounts == nil || relationCounts == nil {
		probe.Warnings = append(probe.Warnings, "graph_count_store_unavailable")
		return probe
	}
	probe.EntityTypes = probeEntityKindCounts(ctx, entityKindCounts, request.TenantID, &probe)
	probe.Relations = probeRelationCounts(ctx, relationCounts, request.TenantID, &probe)
	probe.SourceCount = countForName(probe.EntityTypes, "source")
	probe.FindingCount = countForName(probe.EntityTypes, "finding")
	if len(probe.Warnings) == warningsBeforeCounts {
		storeGraphProbeCounts(request.TenantID, probe)
	}
	return probe
}

func cachedGraphProbeCounts(tenantID string) (graphProbeCountsCacheEntry, bool) {
	key := strings.TrimSpace(tenantID)
	if key == "" {
		return graphProbeCountsCacheEntry{}, false
	}
	now := time.Now()
	graphProbeCountsCache.Lock()
	defer graphProbeCountsCache.Unlock()
	entry, ok := graphProbeCountsCache.entries[key]
	if !ok || now.After(entry.ExpiresAt) {
		delete(graphProbeCountsCache.entries, key)
		return graphProbeCountsCacheEntry{}, false
	}
	entry.EntityTypes = copyGraphProbeCounts(entry.EntityTypes)
	entry.Relations = copyGraphProbeCounts(entry.Relations)
	return entry, true
}

func storeGraphProbeCounts(tenantID string, probe GraphProbe) {
	key := strings.TrimSpace(tenantID)
	if key == "" {
		return
	}
	graphProbeCountsCache.Lock()
	defer graphProbeCountsCache.Unlock()
	graphProbeCountsCache.entries[key] = graphProbeCountsCacheEntry{
		ExpiresAt:    time.Now().Add(graphProbeCountsCacheTTL),
		EntityTypes:  copyGraphProbeCounts(probe.EntityTypes),
		Relations:    copyGraphProbeCounts(probe.Relations),
		SourceCount:  probe.SourceCount,
		FindingCount: probe.FindingCount,
	}
}

func copyGraphProbeCounts(counts []GraphProbeCount) []GraphProbeCount {
	if len(counts) == 0 {
		return nil
	}
	return append([]GraphProbeCount(nil), counts...)
}

func resetGraphProbeCountsCacheForTest() {
	graphProbeCountsCache.Lock()
	defer graphProbeCountsCache.Unlock()
	graphProbeCountsCache.entries = map[string]graphProbeCountsCacheEntry{}
}

func probeEntityKindCounts(ctx context.Context, store ports.EntityKindCountStore, tenantID string, probe *GraphProbe) []GraphProbeCount {
	page, err := store.CountEntityKinds(ctx, ports.EntityKindCountRequest{
		Filter: ports.EntityCatalogFilter{TenantID: strings.TrimSpace(tenantID)},
		Limit:  20,
	})
	if err != nil {
		if probe != nil {
			probe.Warnings = append(probe.Warnings, "probe_query_failed:"+truncateProbeWarning(err.Error()))
		}
		return nil
	}
	counts := make([]GraphProbeCount, 0, len(page.Counts))
	for _, count := range page.Counts {
		name := strings.TrimSpace(count.EntityKind)
		if name == "" {
			name = "unknown"
		}
		counts = append(counts, GraphProbeCount{Name: name, Count: int64(count.Count)}) // #nosec G115 -- graph probe counts are diagnostic only.
	}
	return sortProbeCounts(counts)
}

func probeRelationCounts(ctx context.Context, store ports.RelationCountStore, tenantID string, probe *GraphProbe) []GraphProbeCount {
	page, err := store.CountRelations(ctx, ports.RelationCountRequest{
		TenantID: strings.TrimSpace(tenantID),
		Limit:    20,
	})
	if err != nil {
		if probe != nil {
			probe.Warnings = append(probe.Warnings, "probe_query_failed:"+truncateProbeWarning(err.Error()))
		}
		return nil
	}
	counts := make([]GraphProbeCount, 0, len(page.Counts))
	for _, count := range page.Counts {
		name := strings.TrimSpace(count.Relation)
		if name == "" {
			name = "unknown"
		}
		counts = append(counts, GraphProbeCount{Name: name, Count: int64(count.Count)}) // #nosec G115 -- graph probe counts are diagnostic only.
	}
	return sortProbeCounts(counts)
}

func sortProbeCounts(counts []GraphProbeCount) []GraphProbeCount {
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].Count != counts[j].Count {
			return counts[i].Count > counts[j].Count
		}
		return counts[i].Name < counts[j].Name
	})
	return counts
}

func countForName(counts []GraphProbeCount, name string) int64 {
	for _, count := range counts {
		if strings.EqualFold(count.Name, name) {
			return count.Count
		}
	}
	return 0
}

func truncateProbeWarning(value string) string {
	if len(value) <= 120 {
		return value
	}
	return value[:120]
}
