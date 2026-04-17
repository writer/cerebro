package app

import (
	"log/slog"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/metrics"
)

func (a *App) setGraphBuildState(state GraphBuildState, builtAt time.Time, err error) {
	if a == nil {
		return
	}
	a.graphBuildMu.Lock()
	defer a.graphBuildMu.Unlock()
	a.graphBuildState = state
	if !builtAt.IsZero() {
		a.graphBuildLastAt = builtAt.UTC()
	}
	if err != nil {
		a.graphBuildErr = strings.TrimSpace(err.Error())
	} else {
		a.graphBuildErr = ""
	}
	metrics.SetGraphBuildStatus(string(state))
	if state == GraphBuildSuccess && !builtAt.IsZero() {
		metrics.SetGraphLastUpdate(builtAt.UTC())
	}
}

func (a *App) currentLiveSecurityGraph() *graph.Graph {
	if a == nil {
		return nil
	}
	a.securityGraphInitMu.RLock()
	defer a.securityGraphInitMu.RUnlock()
	return a.SecurityGraph
}

func (a *App) setSecurityGraph(g *graph.Graph) {
	if a == nil {
		return
	}
	a.securityGraphInitMu.Lock()
	defer a.securityGraphInitMu.Unlock()
	a.SecurityGraph = g
	if g == nil {
		metrics.SetGraphCounts(0, 0)
		a.Propagation = nil
		if manager := a.currentTenantSecurityGraphShards(); manager != nil {
			manager.SetSource(nil)
		}
		return
	}
	metrics.SetGraphCounts(g.NodeCount(), g.EdgeCount())
	a.Propagation = graph.NewPropagationEngine(g)
	if manager := a.currentTenantSecurityGraphShards(); manager != nil {
		manager.SetSource(g)
	}
}

func (a *App) publishSecurityGraphRuntimeView(g *graph.Graph) {
	if a == nil {
		return
	}

	a.securityGraphInitMu.Lock()
	defer a.securityGraphInitMu.Unlock()

	if a.retainHotSecurityGraph() {
		a.SecurityGraph = g
		if g == nil {
			metrics.SetGraphCounts(0, 0)
			a.Propagation = nil
			if manager := a.currentTenantSecurityGraphShards(); manager != nil {
				manager.SetSource(nil)
			}
			return
		}
		metrics.SetGraphCounts(g.NodeCount(), g.EdgeCount())
		a.Propagation = graph.NewPropagationEngine(g)
		if manager := a.currentTenantSecurityGraphShards(); manager != nil {
			manager.SetSource(g)
		}
		return
	}

	a.SecurityGraph = nil
	a.Propagation = nil
	if manager := a.currentTenantSecurityGraphShards(); manager != nil {
		manager.SetSource(nil)
	}
	if g == nil {
		metrics.SetGraphCounts(0, 0)
		a.releaseBuilderGraphRuntimeLocked()
		return
	}
	metrics.SetGraphCounts(g.NodeCount(), g.EdgeCount())
	a.releaseBuilderGraphRuntimeLocked()
}

func (a *App) releaseBuilderGraphRuntimeLocked() {
	if a == nil || a.retainHotSecurityGraph() || a.SecurityGraphBuilder == nil {
		return
	}
	placeholder := graph.New()
	a.configureGraphRuntimeBehavior(placeholder)
	a.SecurityGraphBuilder.ReplaceGraph(placeholder)
}

func logUnboundedRetentionWarnings(logger *slog.Logger, cfg *Config) {
	if logger == nil || cfg == nil {
		return
	}
	retention := map[string]int{
		"audit":         cfg.AuditRetentionDays,
		"sessions":      cfg.SessionRetentionDays,
		"graph":         cfg.GraphRetentionDays,
		"access_review": cfg.AccessReviewRetentionDays,
	}
	for name, days := range retention {
		if days == 0 {
			logger.Warn("retention disabled; data will grow unbounded", "dataset", name)
		}
	}
}
