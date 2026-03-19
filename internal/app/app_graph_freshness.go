package app

import (
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/metrics"
)

const defaultGraphFreshnessSLA = 6 * time.Hour

type GraphFreshnessBreach struct {
	Provider           string     `json:"provider"`
	LastSyncTime       *time.Time `json:"last_sync_time,omitempty"`
	LastSyncAgeSeconds float64    `json:"last_sync_age_seconds"`
	StaleAfterSeconds  float64    `json:"stale_after_seconds"`
	TotalNodes         int        `json:"total_nodes"`
	StaleNodes         int        `json:"stale_nodes"`
}

type GraphFreshnessStatus struct {
	EvaluatedAt time.Time                `json:"evaluated_at"`
	Healthy     bool                     `json:"healthy"`
	Breakdown   graph.FreshnessBreakdown `json:"breakdown"`
	Breaches    []GraphFreshnessBreach   `json:"breaches,omitempty"`
}

func (a *App) GraphFreshnessStatusSnapshot(now time.Time) GraphFreshnessStatus {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	status := GraphFreshnessStatus{
		EvaluatedAt: now.UTC(),
		Healthy:     true,
	}
	securityGraph, err := a.currentOrStoredPassiveSecurityGraphView()
	if err != nil && a != nil && a.Logger != nil {
		a.Logger.Warn("failed to resolve security graph for freshness status", "error", err)
	}
	if securityGraph == nil {
		return status
	}

	defaultSLA := defaultGraphFreshnessSLA
	if a != nil && a.Config != nil && a.Config.GraphFreshnessDefaultSLA > 0 {
		defaultSLA = a.Config.GraphFreshnessDefaultSLA
	}
	providerSLAs := make(map[string]time.Duration)
	if a != nil && a.Config != nil {
		for provider, duration := range a.Config.GraphFreshnessProviderSLAs {
			provider = strings.ToLower(strings.TrimSpace(provider))
			if provider == "" || duration <= 0 {
				continue
			}
			providerSLAs[provider] = duration
		}
	}

	status.Breakdown = securityGraph.FreshnessBreakdown(now.UTC(), defaultSLA, providerSLAs)
	status.Breaches = graphFreshnessBreaches(status.Breakdown.Providers, now.UTC())
	status.Healthy = len(status.Breaches) == 0
	publishGraphFreshnessMetrics(status.Breakdown.Providers)
	return status
}

func graphFreshnessBreaches(providers []graph.FreshnessScopeMetrics, now time.Time) []GraphFreshnessBreach {
	out := make([]GraphFreshnessBreach, 0)
	for _, provider := range providers {
		if provider.LastSyncTime == nil || provider.LastSyncTime.IsZero() {
			continue
		}
		lastSyncAgeSeconds := now.Sub(provider.LastSyncTime.UTC()).Seconds()
		if lastSyncAgeSeconds < 0 {
			lastSyncAgeSeconds = 0
		}
		if lastSyncAgeSeconds <= provider.StaleAfterSeconds {
			continue
		}
		out = append(out, GraphFreshnessBreach{
			Provider:           provider.Scope,
			LastSyncTime:       copyTimePtr(provider.LastSyncTime),
			LastSyncAgeSeconds: lastSyncAgeSeconds,
			StaleAfterSeconds:  provider.StaleAfterSeconds,
			TotalNodes:         provider.TotalNodes,
			StaleNodes:         provider.StaleNodes,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSyncAgeSeconds != out[j].LastSyncAgeSeconds {
			return out[i].LastSyncAgeSeconds > out[j].LastSyncAgeSeconds
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}

func publishGraphFreshnessMetrics(providers []graph.FreshnessScopeMetrics) {
	metrics.ResetGraphFreshnessProviderMetrics()
	for _, provider := range providers {
		lastSync := time.Time{}
		if provider.LastSyncTime != nil {
			lastSync = provider.LastSyncTime.UTC()
		}
		metrics.SetGraphFreshnessProvider(provider.Scope, provider.FreshnessPercent, provider.OldestNodeAgeSeconds, lastSync)
	}
}

func copyTimePtr(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	copy := value.UTC()
	return &copy
}
