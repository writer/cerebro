package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	complianceassessment "github.com/writer/cerebro/internal/complianceassessment"
)

// ComplianceReviewProjection groups one review pointer with its immutable history.
type ComplianceReviewProjection struct {
	Review    complianceassessment.Review
	Revisions []complianceassessment.ReviewRevision
}

// ComplianceWorkItemProjection groups one work pointer with retained occurrences and actions.
type ComplianceWorkItemProjection struct {
	Item        complianceassessment.WorkItem
	Occurrences []complianceassessment.WorkOccurrence
	Actions     []complianceassessment.WorkActionRecord
}

// ComplianceRemediationProjection groups one plan with milestone rows from its own table.
type ComplianceRemediationProjection struct {
	Plan       complianceassessment.RemediationPlan
	Milestones []complianceassessment.RemediationMilestone
}

// GetComplianceReview loads one tenant-scoped review and all immutable revisions.
func (s *Store) GetComplianceReview(ctx context.Context, tenantID, reviewID string) (ComplianceReviewProjection, error) {
	var projection ComplianceReviewProjection
	body, err := s.getComplianceCurrentBody(ctx, "compliance_reviews", tenantID, reviewID)
	if err != nil {
		return projection, err
	}
	if err := json.Unmarshal(body, &projection.Review); err != nil {
		return projection, fmt.Errorf("decode compliance review: %w", err)
	}
	bodies, err := s.listComplianceImmutableBodies(ctx, "compliance_review_revisions", tenantID, reviewID)
	if err != nil {
		return projection, err
	}
	projection.Revisions = make([]complianceassessment.ReviewRevision, 0, len(bodies))
	for _, body := range bodies {
		var revision complianceassessment.ReviewRevision
		if err := json.Unmarshal(body, &revision); err != nil {
			return ComplianceReviewProjection{}, fmt.Errorf("decode compliance review revision: %w", err)
		}
		projection.Revisions = append(projection.Revisions, revision)
	}
	return projection, nil
}

// GetComplianceRisk loads one tenant-scoped risk projection.
func (s *Store) GetComplianceRisk(ctx context.Context, tenantID, riskID string) (complianceassessment.Risk, error) {
	var risk complianceassessment.Risk
	body, err := s.getComplianceCurrentBody(ctx, "compliance_risks", tenantID, riskID)
	if err != nil {
		return risk, err
	}
	if err := json.Unmarshal(body, &risk); err != nil {
		return risk, fmt.Errorf("decode compliance risk: %w", err)
	}
	return risk, nil
}

// GetComplianceException loads one tenant-scoped exception projection.
func (s *Store) GetComplianceException(ctx context.Context, tenantID, exceptionID string) (complianceassessment.Exception, error) {
	var exception complianceassessment.Exception
	body, err := s.getComplianceCurrentBody(ctx, "compliance_exceptions", tenantID, exceptionID)
	if err != nil {
		return exception, err
	}
	if err := json.Unmarshal(body, &exception); err != nil {
		return exception, fmt.Errorf("decode compliance exception: %w", err)
	}
	return exception, nil
}

// GetComplianceWorkItem loads one tenant-scoped work item and retained child records.
func (s *Store) GetComplianceWorkItem(ctx context.Context, tenantID, workItemID string) (ComplianceWorkItemProjection, error) {
	var projection ComplianceWorkItemProjection
	body, err := s.getComplianceCurrentBody(ctx, "compliance_work_items", tenantID, workItemID)
	if err != nil {
		return projection, err
	}
	if err := json.Unmarshal(body, &projection.Item); err != nil {
		return projection, fmt.Errorf("decode compliance work item: %w", err)
	}
	occurrenceBodies, err := s.listComplianceImmutableBodies(ctx, "compliance_work_occurrences", tenantID, workItemID)
	if err != nil {
		return projection, err
	}
	projection.Occurrences = make([]complianceassessment.WorkOccurrence, 0, len(occurrenceBodies))
	for _, childBody := range occurrenceBodies {
		var occurrence complianceassessment.WorkOccurrence
		if err := json.Unmarshal(childBody, &occurrence); err != nil {
			return ComplianceWorkItemProjection{}, fmt.Errorf("decode compliance work occurrence: %w", err)
		}
		projection.Occurrences = append(projection.Occurrences, occurrence)
	}
	projection.Item.Occurrences = append([]complianceassessment.WorkOccurrence(nil), projection.Occurrences...)
	actionBodies, err := s.listComplianceImmutableBodies(ctx, "compliance_work_actions", tenantID, workItemID)
	if err != nil {
		return projection, err
	}
	projection.Actions = make([]complianceassessment.WorkActionRecord, 0, len(actionBodies))
	for _, childBody := range actionBodies {
		var action complianceassessment.WorkActionRecord
		if err := json.Unmarshal(childBody, &action); err != nil {
			return ComplianceWorkItemProjection{}, fmt.Errorf("decode compliance work action: %w", err)
		}
		projection.Actions = append(projection.Actions, action)
	}
	return projection, nil
}

// GetComplianceRemediationPlan loads one tenant-scoped plan and current milestones.
func (s *Store) GetComplianceRemediationPlan(ctx context.Context, tenantID, planID string) (ComplianceRemediationProjection, error) {
	var projection ComplianceRemediationProjection
	body, err := s.getComplianceCurrentBody(ctx, "compliance_remediation_plans", tenantID, planID)
	if err != nil {
		return projection, err
	}
	if err := json.Unmarshal(body, &projection.Plan); err != nil {
		return projection, fmt.Errorf("decode compliance remediation plan: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT body_json
FROM compliance_remediation_milestones
WHERE tenant_id = $1 AND plan_id = $2
ORDER BY id`, strings.TrimSpace(tenantID), strings.TrimSpace(planID))
	if err != nil {
		return projection, fmt.Errorf("list compliance remediation milestones: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var childBody []byte
		if err := rows.Scan(&childBody); err != nil {
			return ComplianceRemediationProjection{}, fmt.Errorf("scan compliance remediation milestone: %w", err)
		}
		var milestone complianceassessment.RemediationMilestone
		if err := json.Unmarshal(childBody, &milestone); err != nil {
			return ComplianceRemediationProjection{}, fmt.Errorf("decode compliance remediation milestone: %w", err)
		}
		projection.Milestones = append(projection.Milestones, milestone)
	}
	if err := rows.Err(); err != nil {
		return ComplianceRemediationProjection{}, fmt.Errorf("iterate compliance remediation milestones: %w", err)
	}
	projection.Plan.Milestones = append([]complianceassessment.RemediationMilestone(nil), projection.Milestones...)
	return projection, nil
}

// GetComplianceProjectionReceipt loads one tenant-scoped event receipt.
func (s *Store) GetComplianceProjectionReceipt(ctx context.Context, tenantID, eventID string) (ComplianceProjectionReceipt, error) {
	if s == nil || s.db == nil {
		return ComplianceProjectionReceipt{}, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceReviewTables(ctx); err != nil {
		return ComplianceProjectionReceipt{}, err
	}
	tenantID = strings.TrimSpace(tenantID)
	eventID = strings.TrimSpace(eventID)
	if tenantID == "" || eventID == "" {
		return ComplianceProjectionReceipt{}, fmt.Errorf("%w: tenant and event ids are required", ErrComplianceProjectionInvalid)
	}
	receipt := ComplianceProjectionReceipt{}
	var version uint64
	if err := s.db.QueryRowContext(ctx, `
SELECT tenant_id, event_id, event_kind, aggregate_id, aggregate_version, payload_hash, applied_at
FROM compliance_review_event_receipts
WHERE tenant_id = $1 AND event_id = $2`, tenantID, eventID).Scan(
		&receipt.TenantID, &receipt.EventID, &receipt.EventKind, &receipt.AggregateID,
		&version, &receipt.PayloadHash, &receipt.AppliedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ComplianceProjectionReceipt{}, ErrComplianceProjectionNotFound
		}
		return ComplianceProjectionReceipt{}, fmt.Errorf("load compliance projection receipt: %w", err)
	}
	receipt.AggregateVersion = version
	return receipt, nil
}

func (s *Store) getComplianceCurrentBody(ctx context.Context, table, tenantID, id string) ([]byte, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if !complianceCurrentTableAllowed(table) {
		return nil, fmt.Errorf("%w: current projection table is invalid", ErrComplianceProjectionInvalid)
	}
	if err := s.ensureComplianceReviewTables(ctx); err != nil {
		return nil, err
	}
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return nil, fmt.Errorf("%w: tenant and aggregate ids are required", ErrComplianceProjectionInvalid)
	}
	// #nosec G201 -- table is restricted by complianceCurrentTableAllowed; identifiers are not interpolated.
	query := fmt.Sprintf(`SELECT body_json FROM %s WHERE tenant_id = $1 AND id = $2`, table)
	var body []byte
	if err := s.db.QueryRowContext(ctx, query, tenantID, id).Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrComplianceProjectionNotFound
		}
		return nil, fmt.Errorf("load %s current projection: %w", table, err)
	}
	return body, nil
}

func (s *Store) listComplianceImmutableBodies(ctx context.Context, table, tenantID, parentID string) ([][]byte, error) {
	if !complianceImmutableTableAllowed(table) {
		return nil, fmt.Errorf("%w: immutable projection table is invalid", ErrComplianceProjectionInvalid)
	}
	// #nosec G201 -- table and parent column are restricted by fixed allowlists; values are parameterized.
	query := fmt.Sprintf(`SELECT body_json FROM %s WHERE tenant_id = $1 AND %s = $2 ORDER BY sequence`, table, complianceImmutableParentColumn(table))
	rows, err := s.db.QueryContext(ctx, query, strings.TrimSpace(tenantID), strings.TrimSpace(parentID))
	if err != nil {
		return nil, fmt.Errorf("list %s immutable projections: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	bodies := make([][]byte, 0)
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, fmt.Errorf("scan %s immutable projection: %w", table, err)
		}
		bodies = append(bodies, body)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s immutable projections: %w", table, err)
	}
	return bodies, nil
}
