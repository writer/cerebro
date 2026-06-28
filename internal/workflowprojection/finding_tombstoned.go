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
	result := ports.ProjectionResult{EventsProjected: 1}
	finding := findingSnapshotWithTombstoneMetadata(payload)
	if err := s.ensureFindingEntity(ctx, finding, &result); err != nil {
		return ports.ProjectionResult{}, err
	}
	deleted, err := s.deleteFindingActiveLinks(ctx, payload.Finding)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	result.LinksDeleted += deleted
	return result, nil
}

func findingSnapshotWithTombstoneMetadata(payload *workflowevents.FindingTombstoned) workflowevents.FindingSnapshot {
	finding := payload.Finding
	metadata := make(map[string]string, len(finding.Metadata))
	for key, value := range finding.Metadata {
		metadata[key] = value
	}
	metadata["status_reason"] = payload.Reason
	metadata["tombstoned"] = "true"
	metadata["tombstoned_at"] = payload.TombstonedAt
	metadata["prior_status"] = payload.PriorStatus
	finding.Metadata = metadata
	return finding
}
