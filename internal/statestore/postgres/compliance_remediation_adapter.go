package postgres

import (
	"context"
	"errors"

	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/complianceremediation"
)

// GetWorkItem exposes the tenant-scoped remediation read port without leaking
// the Postgres projection record across the adapter boundary.
func (s *Store) GetWorkItem(ctx context.Context, tenantID, workItemID string) (complianceremediation.WorkItemRecord, error) {
	record, err := s.GetComplianceWorkItem(ctx, tenantID, workItemID)
	if errors.Is(err, ErrComplianceProjectionNotFound) {
		return complianceremediation.WorkItemRecord{}, complianceremediation.ErrNotFound
	}
	return complianceremediation.WorkItemRecord{Item: record.Item, Occurrences: record.Occurrences, Actions: record.Actions}, err
}

// GetRemediationPlan exposes the current plan through the remediation read port.
func (s *Store) GetRemediationPlan(ctx context.Context, tenantID, planID string) (complianceassessment.RemediationPlan, error) {
	record, err := s.GetComplianceRemediationPlan(ctx, tenantID, planID)
	if errors.Is(err, ErrComplianceProjectionNotFound) {
		return complianceassessment.RemediationPlan{}, complianceremediation.ErrNotFound
	}
	return record.Plan, err
}

func remediationProjectionMetadata(metadata complianceremediation.ProjectionMetadata) ComplianceProjectionMetadata {
	return ComplianceProjectionMetadata{EventID: metadata.EventID, ExpectedVersion: metadata.ExpectedVersion, OccurredAt: metadata.OccurredAt}
}

// ProjectWorkOccurrence applies one appended occurrence to current state.
func (s *Store) ProjectWorkOccurrence(ctx context.Context, metadata complianceremediation.ProjectionMetadata, item complianceassessment.WorkItem, occurrence complianceassessment.WorkOccurrence) error {
	_, err := (&ComplianceReviewProjector{store: s}).ProjectWorkOccurrence(ctx, remediationProjectionMetadata(metadata), item, occurrence)
	return err
}

// ProjectWorkAction applies one appended work action to current state.
func (s *Store) ProjectWorkAction(ctx context.Context, metadata complianceremediation.ProjectionMetadata, item complianceassessment.WorkItem, action complianceassessment.WorkActionRecord) error {
	_, err := (&ComplianceReviewProjector{store: s}).ProjectWorkAction(ctx, remediationProjectionMetadata(metadata), item, action)
	return err
}

// ProjectWorkReopen applies one appended work invalidation to current state.
func (s *Store) ProjectWorkReopen(ctx context.Context, metadata complianceremediation.ProjectionMetadata, item complianceassessment.WorkItem, reopen complianceassessment.WorkReopenRecord) error {
	_, err := (&ComplianceReviewProjector{store: s}).ProjectWorkReopen(ctx, remediationProjectionMetadata(metadata), item, reopen)
	return err
}

// ProjectRemediationPlan applies one appended remediation plan transition.
func (s *Store) ProjectRemediationPlan(ctx context.Context, metadata complianceremediation.ProjectionMetadata, plan complianceassessment.RemediationPlan) error {
	_, err := (&ComplianceReviewProjector{store: s}).ProjectRemediationPlan(ctx, remediationProjectionMetadata(metadata), plan)
	return err
}

// ProjectRemediationReopen applies one appended plan invalidation.
func (s *Store) ProjectRemediationReopen(ctx context.Context, metadata complianceremediation.ProjectionMetadata, plan complianceassessment.RemediationPlan, reopen complianceassessment.RemediationReopenRecord) error {
	_, err := (&ComplianceReviewProjector{store: s}).ProjectRemediationReopen(ctx, remediationProjectionMetadata(metadata), plan, reopen)
	return err
}

var (
	_ complianceremediation.Store     = (*Store)(nil)
	_ complianceremediation.Projector = (*Store)(nil)
)
