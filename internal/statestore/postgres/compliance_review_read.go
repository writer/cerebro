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
	projection := ComplianceReviewProjection{Revisions: []complianceassessment.ReviewRevision{}}
	body, err := s.getComplianceCurrentBody(ctx, "compliance_reviews", tenantID, reviewID)
	if err != nil {
		return projection, err
	}
	if err := json.Unmarshal(body, &projection.Review); err != nil {
		return projection, fmt.Errorf("decode compliance review: %w", err)
	}
	err = s.visitComplianceImmutableBodies(ctx, "compliance_review_revisions", tenantID, reviewID, func(body []byte) error {
		var revision complianceassessment.ReviewRevision
		if err := json.Unmarshal(body, &revision); err != nil {
			return fmt.Errorf("decode compliance review revision: %w", err)
		}
		projection.Revisions = append(projection.Revisions, revision)
		return nil
	})
	if err != nil {
		return ComplianceReviewProjection{}, err
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
	projection := ComplianceWorkItemProjection{
		Occurrences: []complianceassessment.WorkOccurrence{},
		Actions:     []complianceassessment.WorkActionRecord{},
	}
	body, err := s.getComplianceCurrentBodyWithoutChildren(ctx, "compliance_work_items", tenantID, workItemID)
	if err != nil {
		return projection, err
	}
	if err := json.Unmarshal(body, &projection.Item); err != nil {
		return projection, fmt.Errorf("decode compliance work item: %w", err)
	}
	err = s.visitComplianceImmutableBodies(ctx, "compliance_work_occurrences", tenantID, workItemID, func(body []byte) error {
		var occurrence complianceassessment.WorkOccurrence
		if err := json.Unmarshal(body, &occurrence); err != nil {
			return fmt.Errorf("decode compliance work occurrence: %w", err)
		}
		projection.Occurrences = append(projection.Occurrences, occurrence)
		return nil
	})
	if err != nil {
		return ComplianceWorkItemProjection{}, err
	}
	projection.Item.Occurrences = append([]complianceassessment.WorkOccurrence(nil), projection.Occurrences...)
	err = s.visitComplianceImmutableBodies(ctx, "compliance_work_actions", tenantID, workItemID, func(body []byte) error {
		var action complianceassessment.WorkActionRecord
		if err := json.Unmarshal(body, &action); err != nil {
			return fmt.Errorf("decode compliance work action: %w", err)
		}
		projection.Actions = append(projection.Actions, action)
		return nil
	})
	if err != nil {
		return ComplianceWorkItemProjection{}, err
	}
	return projection, nil
}

// GetComplianceRemediationPlan loads one tenant-scoped plan and current milestones.
func (s *Store) GetComplianceRemediationPlan(ctx context.Context, tenantID, planID string) (ComplianceRemediationProjection, error) {
	var projection ComplianceRemediationProjection
	body, err := s.getComplianceCurrentBodyWithoutChildren(ctx, "compliance_remediation_plans", tenantID, planID)
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
	return s.getComplianceCurrentBodyProjection(ctx, table, tenantID, id, "")
}

func (s *Store) getComplianceCurrentBodyWithoutChildren(ctx context.Context, table, tenantID, id string) ([]byte, error) {
	childField, ok := complianceCurrentChildField(table)
	if !ok {
		return nil, fmt.Errorf("%w: current projection table has no normalized children", ErrComplianceProjectionInvalid)
	}
	return s.getComplianceCurrentBodyProjection(ctx, table, tenantID, id, childField)
}

func (s *Store) getComplianceCurrentBodyProjection(ctx context.Context, table, tenantID, id, omittedField string) ([]byte, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if !complianceCurrentTableAllowed(table) {
		return nil, fmt.Errorf("%w: current projection table is invalid", ErrComplianceProjectionInvalid)
	}
	if omittedField != "" {
		childField, ok := complianceCurrentChildField(table)
		if !ok || childField != omittedField {
			return nil, fmt.Errorf("%w: current projection child field is invalid", ErrComplianceProjectionInvalid)
		}
	}
	if err := s.ensureComplianceReviewTables(ctx); err != nil {
		return nil, err
	}
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return nil, fmt.Errorf("%w: tenant and aggregate ids are required", ErrComplianceProjectionInvalid)
	}
	selectExpression := "body_json"
	args := []any{tenantID, id}
	if omittedField != "" {
		selectExpression = "body_json - $3"
		args = append(args, omittedField)
	}
	// #nosec G201 -- table is restricted by complianceCurrentTableAllowed and the select expression is closed above.
	query := fmt.Sprintf(`SELECT %s FROM %s WHERE tenant_id = $1 AND id = $2`, selectExpression, table)
	var body []byte
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrComplianceProjectionNotFound
		}
		return nil, fmt.Errorf("load %s current projection: %w", table, err)
	}
	return body, nil
}

func (s *Store) visitComplianceImmutableBodies(ctx context.Context, table, tenantID, parentID string, visit func([]byte) error) error {
	if !complianceImmutableTableAllowed(table) {
		return fmt.Errorf("%w: immutable projection table is invalid", ErrComplianceProjectionInvalid)
	}
	if visit == nil {
		return fmt.Errorf("%w: immutable projection visitor is required", ErrComplianceProjectionInvalid)
	}
	// #nosec G201 -- table and parent column are restricted by fixed allowlists; values are parameterized.
	query := fmt.Sprintf(`SELECT body_json FROM %s WHERE tenant_id = $1 AND %s = $2 ORDER BY sequence`, table, complianceImmutableParentColumn(table))
	rows, err := s.db.QueryContext(ctx, query, strings.TrimSpace(tenantID), strings.TrimSpace(parentID))
	if err != nil {
		return fmt.Errorf("list %s immutable projections: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return fmt.Errorf("scan %s immutable projection: %w", table, err)
		}
		if err := visit(body); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate %s immutable projections: %w", table, err)
	}
	return nil
}

func complianceCurrentChildField(table string) (string, bool) {
	switch table {
	case "compliance_work_items":
		return "occurrences", true
	case "compliance_remediation_plans":
		return "milestones", true
	default:
		return "", false
	}
}
