package app

import (
	"log/slog"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/metrics"
)

type GraphBuildState string

const (
	GraphBuildNotStarted GraphBuildState = "not_started"
	GraphBuildBuilding   GraphBuildState = "building"
	GraphBuildSuccess    GraphBuildState = "success"
	GraphBuildFailed     GraphBuildState = "failed"
)

type GraphBuildSnapshot struct {
	State       GraphBuildState `json:"state"`
	LastBuildAt time.Time       `json:"last_build_at,omitempty"`
	LastError   string          `json:"last_error,omitempty"`
	NodeCount   int             `json:"node_count"`
}

type RetentionStatus struct {
	AuditDays        int `json:"audit_days"`
	SessionDays      int `json:"session_days"`
	GraphDays        int `json:"graph_days"`
	AccessReviewDays int `json:"access_review_days"`
}

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

func (a *App) CurrentSecurityGraph() *graph.Graph {
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
		a.Propagation = nil
		return
	}
	a.Propagation = graph.NewPropagationEngine(g)
}

func (a *App) GraphBuildSnapshot() GraphBuildSnapshot {
	if a == nil {
		return GraphBuildSnapshot{}
	}
	a.graphBuildMu.RLock()
	snapshot := GraphBuildSnapshot{
		State:       a.graphBuildState,
		LastBuildAt: a.graphBuildLastAt,
		LastError:   a.graphBuildErr,
	}
	a.graphBuildMu.RUnlock()

	if securityGraph := a.CurrentSecurityGraph(); securityGraph != nil {
		snapshot.NodeCount = securityGraph.NodeCount()
	}
	return snapshot
}

func (a *App) CurrentRetentionStatus() RetentionStatus {
	if a == nil || a.Config == nil {
		return RetentionStatus{}
	}
	return RetentionStatus{
		AuditDays:        a.Config.AuditRetentionDays,
		SessionDays:      a.Config.SessionRetentionDays,
		GraphDays:        a.Config.GraphRetentionDays,
		AccessReviewDays: a.Config.AccessReviewRetentionDays,
	}
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
