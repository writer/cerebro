package findings

import (
	"context"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// ListFindings loads persisted findings for one runtime.
func (s *Service) ListFindings(ctx context.Context, request ListRequest) (*ListResult, error) {
	if s == nil || s.runtimeStore == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	runtime, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return nil, err
	}
	findings, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID:    strings.TrimSpace(runtime.GetTenantId()),
		RuntimeID:   runtimeID,
		FindingID:   strings.TrimSpace(request.FindingID),
		RuleID:      strings.TrimSpace(request.RuleID),
		Severity:    strings.TrimSpace(request.Severity),
		Status:      strings.TrimSpace(request.Status),
		ResourceURN: strings.TrimSpace(request.ResourceURN),
		EventID:     strings.TrimSpace(request.EventID),
		PolicyID:    strings.TrimSpace(request.PolicyID),
		Limit:       normalizeListLimit(request.Limit),
		Order:       request.Order,
	})
	if err != nil {
		return nil, fmt.Errorf("list findings for tenant %q runtime %q: %w", strings.TrimSpace(runtime.GetTenantId()), runtimeID, err)
	}
	return &ListResult{Findings: findings}, nil
}

// GetFinding loads one persisted finding by durable identifier.
func (s *Service) GetFinding(ctx context.Context, id string) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding id is required", ErrInvalidRequest)
	}
	finding, err := s.store.GetFinding(ctx, findingID)
	if err != nil {
		return nil, err
	}
	return finding, nil
}

// ListEvaluationRuns loads persisted finding evaluation runs for one runtime.
func (s *Service) ListEvaluationRuns(ctx context.Context, request ListEvaluationRunsRequest) (*ListEvaluationRunsResult, error) {
	if s == nil || s.runtimeStore == nil || s.runStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	if _, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID); err != nil {
		return nil, err
	}
	runs, err := s.runStore.ListFindingEvaluationRuns(ctx, ports.ListFindingEvaluationRunsRequest{
		RuntimeID: runtimeID,
		RuleID:    strings.TrimSpace(request.RuleID),
		Status:    strings.TrimSpace(request.Status),
		Limit:     request.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list finding evaluation runs for runtime %q: %w", runtimeID, err)
	}
	return &ListEvaluationRunsResult{Runs: runs}, nil
}

// GetEvaluationRun loads one persisted finding evaluation run.
func (s *Service) GetEvaluationRun(ctx context.Context, id string) (*cerebrov1.FindingEvaluationRun, error) {
	if s == nil || s.runStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	trimmedID := strings.TrimSpace(id)
	if trimmedID == "" {
		return nil, fmt.Errorf("%w: finding evaluation run id is required", ErrInvalidRequest)
	}
	run, err := s.runStore.GetFindingEvaluationRun(ctx, trimmedID)
	if err != nil {
		return nil, err
	}
	return run, nil
}

// ListEvidence loads persisted finding evidence for one runtime.
func (s *Service) ListEvidence(ctx context.Context, request ListEvidenceRequest) (*ListEvidenceResult, error) {
	if s == nil || s.runtimeStore == nil || s.evidenceStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	if _, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID); err != nil {
		return nil, err
	}
	evidence, err := s.evidenceStore.ListFindingEvidence(ctx, ports.ListFindingEvidenceRequest{
		RuntimeID:    runtimeID,
		FindingID:    strings.TrimSpace(request.FindingID),
		RunID:        strings.TrimSpace(request.RunID),
		RuleID:       strings.TrimSpace(request.RuleID),
		ClaimID:      strings.TrimSpace(request.ClaimID),
		EventID:      strings.TrimSpace(request.EventID),
		GraphRootURN: strings.TrimSpace(request.GraphRootURN),
		GraphPathURN: strings.TrimSpace(request.GraphPathURN),
		Limit:        request.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list finding evidence for runtime %q: %w", runtimeID, err)
	}
	return &ListEvidenceResult{Evidence: evidence}, nil
}

// GetEvidence loads one persisted finding evidence record.
func (s *Service) GetEvidence(ctx context.Context, id string) (*cerebrov1.FindingEvidence, error) {
	if s == nil || s.evidenceStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	trimmedID := strings.TrimSpace(id)
	if trimmedID == "" {
		return nil, fmt.Errorf("%w: finding evidence id is required", ErrInvalidRequest)
	}
	evidence, err := s.evidenceStore.GetFindingEvidence(ctx, trimmedID)
	if err != nil {
		return nil, err
	}
	return evidence, nil
}

func normalizeListLimit(limit uint32) uint32 {
	switch {
	case limit == 0:
		return defaultListLimit
	case limit > maxListLimit:
		return maxListLimit
	default:
		return limit
	}
}
