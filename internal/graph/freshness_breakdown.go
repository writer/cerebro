package graph

import (
	"sort"
	"strings"
	"time"
)

// FreshnessScopeMetrics summarizes recency coverage for one provider or kind.
type FreshnessScopeMetrics struct {
	Scope                string     `json:"scope"`
	StaleAfterSeconds    float64    `json:"stale_after_seconds"`
	TotalNodes           int        `json:"total_nodes"`
	NodesWithObserved    int        `json:"nodes_with_observed"`
	FreshNodes           int        `json:"fresh_nodes"`
	StaleNodes           int        `json:"stale_nodes"`
	FreshnessPercent     float64    `json:"freshness_percent"`
	MedianAgeHours       float64    `json:"median_age_hours"`
	P95AgeHours          float64    `json:"p95_age_hours"`
	OldestNodeAgeSeconds float64    `json:"oldest_node_age_seconds"`
	NewestNodeAgeSeconds float64    `json:"newest_node_age_seconds"`
	LastSyncTime         *time.Time `json:"last_sync_time,omitempty"`
}

// FreshnessBreakdown is the typed freshness status for the graph.
type FreshnessBreakdown struct {
	GeneratedAt              time.Time               `json:"generated_at"`
	DefaultStaleAfterSeconds float64                 `json:"default_stale_after_seconds"`
	Overall                  FreshnessMetrics        `json:"overall"`
	Providers                []FreshnessScopeMetrics `json:"providers,omitempty"`
	Kinds                    []FreshnessScopeMetrics `json:"kinds,omitempty"`
}

// FreshnessBreakdown computes aggregate plus provider/kind recency metrics for active nodes.
func (g *Graph) FreshnessBreakdown(now time.Time, defaultStaleAfter time.Duration, providerSLAs map[string]time.Duration) FreshnessBreakdown {
	if g == nil {
		if now.IsZero() {
			now = temporalNowUTC()
		}
		if defaultStaleAfter <= 0 {
			defaultStaleAfter = defaultFreshnessStaleAfter
		}
		now = now.UTC()
		return FreshnessBreakdown{
			GeneratedAt:              now,
			DefaultStaleAfterSeconds: defaultStaleAfter.Seconds(),
		}
	}
	if now.IsZero() {
		now = temporalNowUTC()
	}
	if defaultStaleAfter <= 0 {
		defaultStaleAfter = defaultFreshnessStaleAfter
	}
	now = now.UTC()

	out := FreshnessBreakdown{
		GeneratedAt:              now,
		DefaultStaleAfterSeconds: defaultStaleAfter.Seconds(),
		Overall:                  g.Freshness(now, defaultStaleAfter),
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	providers := make(map[string][]*Node)
	kinds := make(map[string][]*Node)
	for _, node := range g.nodes {
		if node == nil || node.DeletedAt != nil {
			continue
		}
		provider := strings.ToLower(strings.TrimSpace(node.Provider))
		if provider == "" {
			provider = "unknown"
		}
		kind := strings.ToLower(strings.TrimSpace(string(node.Kind)))
		if kind == "" {
			kind = "unknown"
		}
		providers[provider] = append(providers[provider], node)
		kinds[kind] = append(kinds[kind], node)
	}

	out.Providers = buildFreshnessScopeMetrics(now, defaultStaleAfter, providerSLAs, providers)
	out.Kinds = buildFreshnessScopeMetrics(now, defaultStaleAfter, nil, kinds)
	return out
}

func buildFreshnessScopeMetrics(now time.Time, defaultStaleAfter time.Duration, overrides map[string]time.Duration, grouped map[string][]*Node) []FreshnessScopeMetrics {
	if len(grouped) == 0 {
		return nil
	}
	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]FreshnessScopeMetrics, 0, len(keys))
	for _, key := range keys {
		staleAfter := defaultStaleAfter
		if overrides != nil {
			if override, ok := overrides[key]; ok && override > 0 {
				staleAfter = override
			}
		}
		out = append(out, freshnessMetricsForNodes(now, key, staleAfter, grouped[key]))
	}
	return out
}

func freshnessMetricsForNodes(now time.Time, scope string, staleAfter time.Duration, nodes []*Node) FreshnessScopeMetrics {
	out := FreshnessScopeMetrics{
		Scope:             scope,
		StaleAfterSeconds: staleAfter.Seconds(),
		TotalNodes:        len(nodes),
	}
	if staleAfter <= 0 {
		staleAfter = defaultFreshnessStaleAfter
		out.StaleAfterSeconds = staleAfter.Seconds()
	}

	agesHours := make([]float64, 0, len(nodes))
	oldestAge := time.Duration(0)
	newestAge := time.Duration(0)
	lastSyncSet := false
	for _, node := range nodes {
		if node == nil {
			continue
		}
		observedAt, ok := graphObservedAt(node)
		if !ok {
			continue
		}
		out.NodesWithObserved++
		age := now.Sub(observedAt.UTC())
		if age < 0 {
			age = 0
		}
		if age <= staleAfter {
			out.FreshNodes++
		} else {
			out.StaleNodes++
		}
		agesHours = append(agesHours, age.Hours())
		if !lastSyncSet || observedAt.After(*out.LastSyncTime) {
			copy := observedAt.UTC()
			out.LastSyncTime = &copy
			lastSyncSet = true
			newestAge = age
		}
		if age > oldestAge {
			oldestAge = age
		}
	}
	if out.TotalNodes > 0 {
		out.FreshnessPercent = (float64(out.FreshNodes) / float64(out.TotalNodes)) * 100
	}
	if len(agesHours) == 0 {
		return out
	}
	sort.Float64s(agesHours)
	out.MedianAgeHours = percentile(agesHours, 0.50)
	out.P95AgeHours = percentile(agesHours, 0.95)
	out.OldestNodeAgeSeconds = oldestAge.Seconds()
	out.NewestNodeAgeSeconds = newestAge.Seconds()
	return out
}
