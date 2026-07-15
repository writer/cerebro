package remediationanalytics

import (
	"context"
	"errors"

	"github.com/writer/cerebro/internal/observability"
	"github.com/writer/cerebro/internal/ports"
)

var ErrStoreUnavailable = errors.New("remediation outcome store is unavailable")

// Service projects normalized remediation outcomes and finding episodes into
// the existing Postgres current-state boundary. Its inputs must come from
// canonical finding, action, execution, verification, and source-health
// records so the projection remains rebuildable.
type Service struct {
	store ports.RemediationOutcomeStore
}

func New(store ports.RemediationOutcomeStore) *Service {
	return &Service{store: store}
}

func (s *Service) RecordOutcome(ctx context.Context, input OutcomeInput) (*ports.RemediationOutcomeRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	record, err := DeriveOutcome(input)
	if err != nil {
		return nil, err
	}
	stored, err := s.store.RecordRemediationOutcome(ctx, record)
	if err != nil {
		return nil, err
	}
	observability.RecordRemediationOutcome(ctx, observability.RemediationOutcomeMetrics{
		ActionType:          stored.ActionType,
		VerificationState:   stored.VerificationState,
		CensoredReason:      stored.CensoredReason,
		SourceHealth:        stored.SourceHealth,
		ProviderSucceeded:   stored.ProviderSucceeded,
		VerificationLatency: stored.VerificationLatency,
		HasLatency:          !stored.VerifiedAt.IsZero() && !stored.ActionCompletedAt.IsZero(),
	})
	return stored, nil
}

func (s *Service) ProjectEpisode(ctx context.Context, input EpisodeInput) (*ports.ResolutionEpisodeRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	record, err := DeriveEpisode(input)
	if err != nil {
		return nil, err
	}
	stored, err := s.store.UpsertResolutionEpisode(ctx, record)
	if err != nil {
		return nil, err
	}
	observability.RecordResolutionEpisode(ctx, observability.ResolutionEpisodeMetrics{
		ResolutionType:   stored.ResolutionType,
		DurabilityState:  stored.DurabilityState,
		SourceHealth:     stored.SourceHealth,
		TimeToResolution: stored.TimeToResolution,
		TimeToRecurrence: stored.TimeToRecurrence,
		HasResolution:    !stored.ResolvedAt.IsZero(),
		HasRecurrence:    !stored.ReopenedAt.IsZero(),
	})
	return stored, nil
}
