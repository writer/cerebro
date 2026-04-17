package graphruntime

import (
	"context"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
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

func (a *Runtime) CurrentSecurityGraph() *graph.Graph {
	if current := a.currentLiveSecurityGraph(); current != nil {
		if current.NodeCount() > 0 || current.EdgeCount() > 0 {
			return current
		}
	}
	if a == nil {
		return nil
	}
	if view, err := a.CurrentConfiguredSecurityGraphView(context.Background()); err == nil && view != nil {
		return view
	}
	return a.currentLiveSecurityGraph()
}

func (a *Runtime) CurrentSecurityGraphForTenant(tenantID string) *graph.Graph {
	if a == nil {
		return nil
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return a.CurrentSecurityGraph()
	}
	current := a.currentLiveSecurityGraph()
	if a.retainHotSecurityGraph() {
		manager := a.ensureTenantSecurityGraphShards()
		if manager != nil {
			if scoped := manager.GraphForTenant(current, tenantID); scoped != nil {
				return scoped
			}
		}
	}
	current = a.CurrentSecurityGraph()
	if current == nil {
		return nil
	}
	return current.SubgraphForTenant(tenantID)
}

func (a *Runtime) GraphBuildSnapshot() GraphBuildSnapshot {
	state := a.buildSnapshotState()
	snapshot := GraphBuildSnapshot{
		State:       state.State,
		LastBuildAt: state.LastBuildAt,
		LastError:   state.LastError,
	}

	securityGraph, err := a.CurrentOrStoredPassiveSecurityGraphView()
	if err != nil {
		if logger := a.logger(); logger != nil {
			logger.Warn("failed to resolve security graph for build snapshot", "error", err)
		}
	}
	if securityGraph != nil {
		snapshot.NodeCount = securityGraph.NodeCount()
	}
	return snapshot
}

func (a *Runtime) CurrentRetentionStatus() RetentionStatus {
	if a == nil || a.config() == nil {
		return RetentionStatus{}
	}
	cfg := a.config()
	return RetentionStatus{
		AuditDays:        cfg.AuditRetentionDays,
		SessionDays:      cfg.SessionRetentionDays,
		GraphDays:        cfg.GraphRetentionDays,
		AccessReviewDays: cfg.AccessReviewRetentionDays,
	}
}
