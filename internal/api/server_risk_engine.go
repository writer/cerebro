package api

import "github.com/evalops/cerebro/internal/graph"

func (s *Server) graphRiskEngine() *graph.RiskEngine {
	if s == nil || s.app == nil || s.app.SecurityGraph == nil {
		return nil
	}

	source := s.app.SecurityGraph
	s.riskEngineMu.Lock()
	defer s.riskEngineMu.Unlock()

	if s.riskEngine == nil || s.riskEngineSource != source {
		s.riskEngine = graph.NewRiskEngine(source)
		s.riskEngineSource = source
	}
	return s.riskEngine
}
