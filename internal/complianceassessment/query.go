package complianceassessment

import (
	"context"
	"errors"
	"strings"
)

var ErrResultPagingUnavailable = errors.New("assessment result paging is unavailable")

const (
	defaultResultChunkPageLimit = uint32(25)
	maxResultChunkPageLimit     = uint32(100)
)

type ResultChunkPage struct {
	Chunks       []ResultChunk `json:"chunks"`
	NextSequence uint32        `json:"next_sequence,omitempty"`
	HasMore      bool          `json:"has_more"`
}

type ResultChunkPageStore interface {
	ListResultChunksPage(context.Context, string, string, uint32, uint32) (ResultChunkPage, error)
}

func (s *Service) GetPlan(ctx context.Context, tenantID, planID string) (AssessmentPlanRevision, error) {
	if s == nil || s.store == nil {
		return AssessmentPlanRevision{}, ErrPlanNotFound
	}
	return s.store.GetPlan(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(planID))
}

func (s *Service) GetRun(ctx context.Context, tenantID, runID string) (AssessmentRun, error) {
	if s == nil || s.store == nil {
		return AssessmentRun{}, ErrRunNotFound
	}
	return s.store.GetRun(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(runID))
}

func (s *Service) ListResultChunksPage(ctx context.Context, tenantID, runID string, afterSequence, limit uint32) (ResultChunkPage, error) {
	if s == nil || s.store == nil {
		return ResultChunkPage{}, ErrResultPagingUnavailable
	}
	store, ok := s.store.(ResultChunkPageStore)
	if !ok {
		return ResultChunkPage{}, ErrResultPagingUnavailable
	}
	if limit == 0 {
		limit = defaultResultChunkPageLimit
	}
	if limit > maxResultChunkPageLimit {
		return ResultChunkPage{}, ErrInvalidResult
	}
	return store.ListResultChunksPage(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(runID), afterSequence, limit)
}
