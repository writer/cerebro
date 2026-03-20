package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/writer/cerebro/internal/graph"
	risk "github.com/writer/cerebro/internal/graph/risk"
	"github.com/writer/cerebro/internal/metrics"
)

const riskEngineStateGraphID = "security-graph"

func (s *Server) graphRiskEngine(ctx context.Context) *risk.RiskEngine {
	if s == nil || s.app == nil {
		return nil
	}

	source := s.app.CurrentSecurityGraph()
	if source != nil {
		s.riskEngineMu.Lock()
		defer s.riskEngineMu.Unlock()
		if s.riskEngine == nil || s.riskEngineSource != source {
			engine := s.newConfiguredRiskEngine(source)
			s.restoreRiskEngineStateLocked(ctx, engine)
			s.riskEngine = engine
			s.riskEngineSource = source
			s.riskEngineSnapshotKey = riskEngineSnapshotKey(graph.CreateSnapshot(source))
		}
		return s.riskEngine
	}

	store := s.app.CurrentSecurityGraphStore()
	if store == nil {
		return nil
	}

	snapshotCtx, cancel := s.riskEngineStateContext(ctx)
	defer cancel()
	snapshot, err := store.Snapshot(snapshotCtx)
	if err != nil {
		if s.app.Logger != nil {
			s.app.Logger.Warn("failed to load graph snapshot for risk engine", "error", err)
		}
		return nil
	}
	view := graph.GraphViewFromSnapshot(snapshot)
	if view == nil {
		return nil
	}
	snapshotKey := riskEngineSnapshotKey(snapshot)

	s.riskEngineMu.Lock()
	defer s.riskEngineMu.Unlock()
	if s.riskEngine != nil && s.riskEngineSource == nil && s.riskEngineSnapshotKey == snapshotKey {
		return s.riskEngine
	}

	previousEngine := s.riskEngine
	previousKey := s.riskEngineSnapshotKey
	engine := s.newConfiguredRiskEngine(view)
	if !s.restoreRiskEngineStateLocked(ctx, engine) && previousEngine != nil && previousKey == snapshotKey {
		if err := engine.RestoreSnapshot(previousEngine.Snapshot()); err != nil && s.app.Logger != nil {
			s.app.Logger.Warn("failed to restore in-memory risk engine state snapshot", "error", err)
		}
	}

	s.riskEngine = engine
	s.riskEngineSource = nil
	s.riskEngineSnapshotKey = snapshotKey
	return s.riskEngine
}

func (s *Server) riskEngineStateContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	// #nosec G118 -- this helper returns the cancel func to callers, which always defer it.
	timeoutCtx, cancel := context.WithTimeout(ctx, s.riskEngineStateTimeout())
	return timeoutCtx, cancel
}

func (s *Server) riskEngineStateRestoreContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	} else {
		ctx = context.WithoutCancel(ctx)
	}
	// #nosec G118 -- this helper returns the cancel func to callers, which always defer it.
	timeoutCtx, cancel := context.WithTimeout(ctx, s.riskEngineStateTimeout())
	return timeoutCtx, cancel
}

func riskEngineSnapshotKey(snapshot *graph.Snapshot) string {
	if snapshot == nil {
		return ""
	}
	activeNodeIDs := make(map[string]struct{}, len(snapshot.Nodes))
	nodes := make([]*graph.Node, 0, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		if node == nil || node.ID == "" || node.DeletedAt != nil {
			continue
		}
		activeNodeIDs[node.ID] = struct{}{}
		nodes = append(nodes, node)
	}
	edges := make([]*graph.Edge, 0, len(snapshot.Edges))
	for _, edge := range snapshot.Edges {
		if edge == nil || edge.DeletedAt != nil {
			continue
		}
		if _, ok := activeNodeIDs[edge.Source]; !ok {
			continue
		}
		if _, ok := activeNodeIDs[edge.Target]; !ok {
			continue
		}
		edges = append(edges, edge)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].ID != nodes[j].ID {
			return nodes[i].ID < nodes[j].ID
		}
		if nodes[i].Kind != nodes[j].Kind {
			return nodes[i].Kind < nodes[j].Kind
		}
		return nodes[i].Version < nodes[j].Version
	})
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].ID != edges[j].ID {
			return edges[i].ID < edges[j].ID
		}
		if edges[i].Source != edges[j].Source {
			return edges[i].Source < edges[j].Source
		}
		if edges[i].Target != edges[j].Target {
			return edges[i].Target < edges[j].Target
		}
		if edges[i].Kind != edges[j].Kind {
			return edges[i].Kind < edges[j].Kind
		}
		return edges[i].Version < edges[j].Version
	})
	payload, err := json.Marshal(struct {
		Nodes []*graph.Node `json:"nodes"`
		Edges []*graph.Edge `json:"edges"`
	}{
		Nodes: nodes,
		Edges: edges,
	})
	if err != nil {
		return fmt.Sprintf("fallback|%d|%d|%d|%d", len(nodes), len(edges), snapshot.Metadata.NodeCount, snapshot.Metadata.EdgeCount)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:16])
}

func (s *Server) newConfiguredRiskEngine(g *graph.Graph) *risk.RiskEngine {
	engine := risk.NewRiskEngine(g)
	if s != nil && s.app != nil && s.app.Config != nil {
		engine.SetCrossTenantPrivacyConfig(risk.CrossTenantPrivacyConfig{
			MinTenantCount:    s.app.Config.GraphCrossTenantMinTenants,
			MinPatternSupport: s.app.Config.GraphCrossTenantMinSupport,
		})
	}
	return engine
}

func (s *Server) restoreRiskEngineStateLocked(ctx context.Context, engine *risk.RiskEngine) bool {
	if s == nil || s.app == nil || engine == nil {
		return false
	}
	repo := s.app.RiskEngineStateRepo
	if repo == nil {
		return false
	}

	loadCtx, cancel := s.riskEngineStateRestoreContext(ctx)
	defer cancel()
	payload, err := repo.LoadSnapshot(loadCtx, riskEngineStateGraphID)
	if err != nil {
		if s.app.Logger != nil {
			s.app.Logger.Warn("failed to load risk engine state", "error", err)
		}
		metrics.RecordGraphStatePersistence("load_failed")
		return false
	}
	if len(payload) == 0 {
		return false
	}

	var snapshot risk.RiskEngineSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		if s.app.Logger != nil {
			s.app.Logger.Warn("failed to decode risk engine state snapshot", "error", err)
		}
		metrics.RecordGraphStatePersistence("load_decode_failed")
		return false
	}
	if err := engine.RestoreSnapshot(snapshot); err != nil {
		if s.app.Logger != nil {
			s.app.Logger.Warn("failed to restore risk engine snapshot", "error", err)
		}
		metrics.RecordGraphStatePersistence("load_restore_failed")
		return false
	}
	metrics.RecordGraphStatePersistence("loaded")
	return true
}

func (s *Server) persistRiskEngineState(ctx context.Context, engine *risk.RiskEngine) {
	if s == nil || s.app == nil || engine == nil || s.app.RiskEngineStateRepo == nil {
		return
	}

	snapshot := engine.Snapshot()
	payload, err := json.Marshal(snapshot)
	if err != nil {
		if s.app.Logger != nil {
			s.app.Logger.Warn("failed to encode risk engine state snapshot", "error", err)
		}
		metrics.RecordGraphStatePersistence("save_encode_failed")
		return
	}
	saveCtx := ctx
	if saveCtx == nil {
		saveCtx = context.Background()
	}
	saveCtx, cancel := context.WithTimeout(saveCtx, s.riskEngineStateTimeout())
	defer cancel()
	if err := s.app.RiskEngineStateRepo.SaveSnapshot(saveCtx, riskEngineStateGraphID, payload); err != nil {
		if s.app.Logger != nil {
			s.app.Logger.Warn("failed to persist risk engine state", "error", err)
		}
		metrics.RecordGraphStatePersistence("save_failed")
		return
	}
	metrics.RecordGraphStatePersistence("saved")
}
