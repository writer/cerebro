package workflowprojection

import (
	"context"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

func (s *Service) projectFindingTombstoned(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	payload, err := workflowevents.DecodeFindingTombstoned(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	deleted, err := s.deleteFindingActiveLinks(ctx, payload.Finding)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	return ports.ProjectionResult{LinksDeleted: deleted}, nil
}
