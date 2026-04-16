package api

import (
	"context"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func (s *Server) currentGraphIntelligenceGraph(ctx context.Context) *graph.Graph {
	if s == nil || s.graphIntelligence == nil {
		return nil
	}
	g, err := s.graphIntelligence.CurrentGraph(ctx)
	if err != nil {
		return nil
	}
	return g
}

func (s *Server) graphIntelligenceEntityGraph(ctx context.Context, entityID string, validAt, recordedAt time.Time) (*graph.Graph, error) {
	if s == nil || s.graphIntelligence == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return s.graphIntelligence.CurrentEntityGraph(ctx, entityID, validAt, recordedAt)
}
