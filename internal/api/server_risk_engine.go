package api

import (
	"context"
	"encoding/json"

	risk "github.com/evalops/cerebro/internal/graph/risk"
	"github.com/evalops/cerebro/internal/metrics"
)

const riskEngineStateGraphID = "security-graph"

func (s *Server) graphRiskEngine() *risk.RiskEngine {
	if s == nil || s.app == nil || s.app.SecurityGraph == nil {
		return nil
	}

	source := s.app.SecurityGraph
	s.riskEngineMu.Lock()
	defer s.riskEngineMu.Unlock()

	if s.riskEngine == nil || s.riskEngineSource != source {
		engine := risk.NewRiskEngine(source)
		if s.app.Config != nil {
			engine.SetCrossTenantPrivacyConfig(risk.CrossTenantPrivacyConfig{
				MinTenantCount:    s.app.Config.GraphCrossTenantMinTenants,
				MinPatternSupport: s.app.Config.GraphCrossTenantMinSupport,
			})
		}
		if repo := s.app.RiskEngineStateRepo; repo != nil {
			loadCtx, cancel := context.WithTimeout(context.Background(), s.riskEngineStateTimeout())
			defer cancel()
			payload, err := repo.LoadSnapshot(loadCtx, riskEngineStateGraphID)
			if err != nil {
				if s.app.Logger != nil {
					s.app.Logger.Warn("failed to load risk engine state", "error", err)
				}
				metrics.RecordGraphStatePersistence("load_failed")
			} else if len(payload) > 0 {
				var snapshot risk.RiskEngineSnapshot
				if err := json.Unmarshal(payload, &snapshot); err != nil {
					if s.app.Logger != nil {
						s.app.Logger.Warn("failed to decode risk engine state snapshot", "error", err)
					}
					metrics.RecordGraphStatePersistence("load_decode_failed")
				} else if err := engine.RestoreSnapshot(snapshot); err != nil {
					if s.app.Logger != nil {
						s.app.Logger.Warn("failed to restore risk engine snapshot", "error", err)
					}
					metrics.RecordGraphStatePersistence("load_restore_failed")
				} else {
					metrics.RecordGraphStatePersistence("loaded")
				}
			}
		}
		s.riskEngine = engine
		s.riskEngineSource = source
	}
	return s.riskEngine
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
