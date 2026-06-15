package graphagent

import (
	"context"
	"fmt"
	"sort"
	"strconv"
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

func collectGraphProbe(ctx context.Context, store ports.GraphQueryStore, request AskRequest, params map[string]any) GraphProbe {
	probe := GraphProbe{ScopeURN: strings.TrimSpace(request.ScopeURN)}
	if store == nil {
		probe.Warnings = append(probe.Warnings, "graph_store_unavailable")
		return probe
	}
	if probe.ScopeURN != "" {
		neighborhood, err := store.GetEntityNeighborhood(ctx, probe.ScopeURN, 10)
		if err != nil {
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
	probe.EntityTypes = probeCounts(ctx, store, params, `MATCH (n:Entity {tenant_id: $tenant_id})
RETURN n.entity_type AS name, count(n) AS count
ORDER BY count DESC, name
LIMIT 20`, &probe)
	probe.Relations = probeCounts(ctx, store, params, `MATCH (:Entity {tenant_id: $tenant_id})-[r:RELATION]->(:Entity {tenant_id: $tenant_id})
RETURN r.relation AS name, count(r) AS count
ORDER BY count DESC, name
LIMIT 20`, &probe)
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

func probeCounts(ctx context.Context, store ports.GraphQueryStore, params map[string]any, query string, probe *GraphProbe) []GraphProbeCount {
	rows, err := store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: query, Params: params, RowLimit: 20})
	if err != nil {
		if probe != nil {
			probe.Warnings = append(probe.Warnings, "probe_query_failed:"+truncateProbeWarning(err.Error()))
		}
		return nil
	}
	counts := make([]GraphProbeCount, 0, len(rows))
	for _, row := range cypherRowsToMaps(rows) {
		nameValue := row["name"]
		name := strings.TrimSpace(fmt.Sprint(nameValue))
		if name == "" || name == "<nil>" {
			name = "unknown"
		}
		counts = append(counts, GraphProbeCount{Name: name, Count: int64RowValue(row["count"])})
	}
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

func int64RowValue(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	case string:
		parsed, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return parsed
	default:
		return 0
	}
}

func truncateProbeWarning(value string) string {
	if len(value) <= 120 {
		return value
	}
	return value[:120]
}
