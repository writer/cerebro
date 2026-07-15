package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	complianceassessment "github.com/writer/cerebro/internal/complianceassessment"
)

var (
	ErrComplianceProjectionInvalid             = errors.New("invalid compliance projection")
	ErrComplianceProjectionVersionConflict     = errors.New("compliance projection version conflict")
	ErrComplianceProjectionIdempotencyConflict = errors.New("compliance projection idempotency conflict")
	ErrComplianceProjectionNotFound            = errors.New("compliance projection not found")
)

// ComplianceProjectionMetadata identifies one durable event being projected.
type ComplianceProjectionMetadata struct {
	EventID         string    `json:"event_id"`
	ExpectedVersion uint64    `json:"expected_version"`
	OccurredAt      time.Time `json:"occurred_at"`
}

// ComplianceProjectionReceipt proves that one exact event payload was applied.
type ComplianceProjectionReceipt struct {
	TenantID         string    `json:"tenant_id"`
	EventID          string    `json:"event_id"`
	EventKind        string    `json:"event_kind"`
	AggregateID      string    `json:"aggregate_id"`
	AggregateVersion uint64    `json:"aggregate_version"`
	PayloadHash      string    `json:"payload_hash"`
	AppliedAt        time.Time `json:"applied_at"`
	Applied          bool      `json:"applied"`
}

// ComplianceReviewProjector persists current projections and immutable child records.
// Domain transitions remain owned by complianceassessment; this type only projects them.
type ComplianceReviewProjector struct {
	store *Store
}

// NewComplianceReviewProjector constructs a Postgres projector over the current-state store.
func NewComplianceReviewProjector(store *Store) (*ComplianceReviewProjector, error) {
	if store == nil || store.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	return &ComplianceReviewProjector{store: store}, nil
}

// ProjectReview persists a review pointer and one immutable revision atomically.
func (p *ComplianceReviewProjector) ProjectReview(ctx context.Context, metadata ComplianceProjectionMetadata, review complianceassessment.Review, revision complianceassessment.ReviewRevision) (ComplianceProjectionReceipt, error) {
	if review.TenantID == "" || review.ID == "" || revision.TenantID != review.TenantID || revision.ReviewID != review.ID || revision.AutomatedResultHash != review.AutomatedResultHash || revision.Revision != review.CurrentRevision || revision.ID != review.CurrentRevisionID {
		return ComplianceProjectionReceipt{}, fmt.Errorf("%w: review and revision scope or lineage differ", ErrComplianceProjectionInvalid)
	}
	payload := struct {
		Review   complianceassessment.Review         `json:"review"`
		Revision complianceassessment.ReviewRevision `json:"revision"`
	}{Review: review, Revision: revision}
	event := complianceProjectionEvent{metadata: metadata, tenantID: review.TenantID, kind: "review", aggregateID: review.ID, version: review.Version}
	return p.project(ctx, event, payload, func(tx *sql.Tx) error {
		if err := upsertComplianceCurrent(ctx, tx, "compliance_reviews", review.TenantID, review.ID, metadata.ExpectedVersion, review.Version, review); err != nil {
			return err
		}
		return insertComplianceImmutable(ctx, tx, "compliance_review_revisions", review.TenantID, revision.ID, review.ID, revision.Revision, revision.CreatedAt, revision)
	})
}

// ProjectRisk persists one current risk projection.
func (p *ComplianceReviewProjector) ProjectRisk(ctx context.Context, metadata ComplianceProjectionMetadata, risk complianceassessment.Risk) (ComplianceProjectionReceipt, error) {
	if strings.TrimSpace(risk.TenantID) == "" || strings.TrimSpace(risk.ID) == "" {
		return ComplianceProjectionReceipt{}, fmt.Errorf("%w: risk tenant and id are required", ErrComplianceProjectionInvalid)
	}
	event := complianceProjectionEvent{metadata: metadata, tenantID: risk.TenantID, kind: "risk", aggregateID: risk.ID, version: risk.Version}
	return p.project(ctx, event, risk, func(tx *sql.Tx) error {
		return upsertComplianceCurrent(ctx, tx, "compliance_risks", risk.TenantID, risk.ID, metadata.ExpectedVersion, risk.Version, risk)
	})
}

// ProjectException persists one current exception projection.
func (p *ComplianceReviewProjector) ProjectException(ctx context.Context, metadata ComplianceProjectionMetadata, exception complianceassessment.Exception) (ComplianceProjectionReceipt, error) {
	if strings.TrimSpace(exception.TenantID) == "" || strings.TrimSpace(exception.ID) == "" {
		return ComplianceProjectionReceipt{}, fmt.Errorf("%w: exception tenant and id are required", ErrComplianceProjectionInvalid)
	}
	event := complianceProjectionEvent{metadata: metadata, tenantID: exception.TenantID, kind: "exception", aggregateID: exception.ID, version: exception.Version}
	return p.project(ctx, event, exception, func(tx *sql.Tx) error {
		return upsertComplianceCurrent(ctx, tx, "compliance_exceptions", exception.TenantID, exception.ID, metadata.ExpectedVersion, exception.Version, exception)
	})
}

// ProjectWorkOccurrence persists a work pointer and one immutable run occurrence.
func (p *ComplianceReviewProjector) ProjectWorkOccurrence(ctx context.Context, metadata ComplianceProjectionMetadata, item complianceassessment.WorkItem, occurrence complianceassessment.WorkOccurrence) (ComplianceProjectionReceipt, error) {
	tenantID := strings.TrimSpace(item.Basis.TenantID)
	if tenantID == "" || strings.TrimSpace(item.ID) == "" || occurrence.WorkItemID != item.ID || strings.TrimSpace(occurrence.ID) == "" {
		return ComplianceProjectionReceipt{}, fmt.Errorf("%w: work item and occurrence scope differ", ErrComplianceProjectionInvalid)
	}
	payload := struct {
		Item       complianceassessment.WorkItem       `json:"item"`
		Occurrence complianceassessment.WorkOccurrence `json:"occurrence"`
	}{Item: item, Occurrence: occurrence}
	event := complianceProjectionEvent{metadata: metadata, tenantID: tenantID, kind: "work_occurrence", aggregateID: item.ID, version: item.Version}
	return p.project(ctx, event, payload, func(tx *sql.Tx) error {
		if err := upsertComplianceCurrent(ctx, tx, "compliance_work_items", tenantID, item.ID, metadata.ExpectedVersion, item.Version, item); err != nil {
			return err
		}
		return insertComplianceImmutable(ctx, tx, "compliance_work_occurrences", tenantID, occurrence.ID, item.ID, item.Version, occurrence.OccurredAt, occurrence)
	})
}

// ProjectWorkAction persists a work pointer and one immutable action.
func (p *ComplianceReviewProjector) ProjectWorkAction(ctx context.Context, metadata ComplianceProjectionMetadata, item complianceassessment.WorkItem, action complianceassessment.WorkActionRecord) (ComplianceProjectionReceipt, error) {
	tenantID := strings.TrimSpace(item.Basis.TenantID)
	if tenantID == "" || strings.TrimSpace(item.ID) == "" || action.WorkItemID != item.ID || strings.TrimSpace(action.ID) == "" {
		return ComplianceProjectionReceipt{}, fmt.Errorf("%w: work item and action scope differ", ErrComplianceProjectionInvalid)
	}
	payload := struct {
		Item   complianceassessment.WorkItem         `json:"item"`
		Action complianceassessment.WorkActionRecord `json:"action"`
	}{Item: item, Action: action}
	event := complianceProjectionEvent{metadata: metadata, tenantID: tenantID, kind: "work_action", aggregateID: item.ID, version: item.Version}
	return p.project(ctx, event, payload, func(tx *sql.Tx) error {
		if err := upsertComplianceCurrent(ctx, tx, "compliance_work_items", tenantID, item.ID, metadata.ExpectedVersion, item.Version, item); err != nil {
			return err
		}
		return insertComplianceImmutable(ctx, tx, "compliance_work_actions", tenantID, action.ID, item.ID, item.Version, action.CreatedAt, action)
	})
}

// ProjectWorkReopen persists an invalidated work item while binding the event
// receipt to its immutable reopen reason.
func (p *ComplianceReviewProjector) ProjectWorkReopen(ctx context.Context, metadata ComplianceProjectionMetadata, item complianceassessment.WorkItem, reopen complianceassessment.WorkReopenRecord) (ComplianceProjectionReceipt, error) {
	tenantID := strings.TrimSpace(item.Basis.TenantID)
	if tenantID == "" || strings.TrimSpace(item.ID) == "" || reopen.WorkItemID != item.ID || strings.TrimSpace(reopen.ID) == "" {
		return ComplianceProjectionReceipt{}, fmt.Errorf("%w: work item and reopen reason scope differ", ErrComplianceProjectionInvalid)
	}
	payload := struct {
		Item   complianceassessment.WorkItem         `json:"item"`
		Reopen complianceassessment.WorkReopenRecord `json:"reopen"`
	}{Item: item, Reopen: reopen}
	event := complianceProjectionEvent{metadata: metadata, tenantID: tenantID, kind: "work_reopen", aggregateID: item.ID, version: item.Version}
	return p.project(ctx, event, payload, func(tx *sql.Tx) error {
		return upsertComplianceCurrent(ctx, tx, "compliance_work_items", tenantID, item.ID, metadata.ExpectedVersion, item.Version, item)
	})
}

// ProjectRemediationPlan persists a plan and its current milestone projections.
func (p *ComplianceReviewProjector) ProjectRemediationPlan(ctx context.Context, metadata ComplianceProjectionMetadata, plan complianceassessment.RemediationPlan) (ComplianceProjectionReceipt, error) {
	if strings.TrimSpace(plan.TenantID) == "" || strings.TrimSpace(plan.ID) == "" || len(plan.Milestones) == 0 {
		return ComplianceProjectionReceipt{}, fmt.Errorf("%w: remediation tenant, id, and milestones are required", ErrComplianceProjectionInvalid)
	}
	event := complianceProjectionEvent{metadata: metadata, tenantID: plan.TenantID, kind: "remediation_plan", aggregateID: plan.ID, version: plan.Version}
	return p.project(ctx, event, plan, func(tx *sql.Tx) error {
		if err := upsertComplianceCurrent(ctx, tx, "compliance_remediation_plans", plan.TenantID, plan.ID, metadata.ExpectedVersion, plan.Version, plan); err != nil {
			return err
		}
		for _, milestone := range plan.Milestones {
			if err := upsertComplianceMilestone(ctx, tx, plan.TenantID, plan.ID, plan.Version, milestone); err != nil {
				return err
			}
		}
		return nil
	})
}

// ProjectRemediationReopen persists an invalidated plan while binding the event
// receipt to its immutable reopen reason.
func (p *ComplianceReviewProjector) ProjectRemediationReopen(ctx context.Context, metadata ComplianceProjectionMetadata, plan complianceassessment.RemediationPlan, reopen complianceassessment.RemediationReopenRecord) (ComplianceProjectionReceipt, error) {
	if strings.TrimSpace(plan.TenantID) == "" || strings.TrimSpace(plan.ID) == "" || reopen.PlanID != plan.ID || strings.TrimSpace(reopen.ID) == "" || len(plan.Milestones) == 0 {
		return ComplianceProjectionReceipt{}, fmt.Errorf("%w: remediation plan and reopen reason scope differ", ErrComplianceProjectionInvalid)
	}
	payload := struct {
		Plan   complianceassessment.RemediationPlan         `json:"plan"`
		Reopen complianceassessment.RemediationReopenRecord `json:"reopen"`
	}{Plan: plan, Reopen: reopen}
	event := complianceProjectionEvent{metadata: metadata, tenantID: plan.TenantID, kind: "remediation_reopen", aggregateID: plan.ID, version: plan.Version}
	return p.project(ctx, event, payload, func(tx *sql.Tx) error {
		if err := upsertComplianceCurrent(ctx, tx, "compliance_remediation_plans", plan.TenantID, plan.ID, metadata.ExpectedVersion, plan.Version, plan); err != nil {
			return err
		}
		for _, milestone := range plan.Milestones {
			if err := upsertComplianceMilestone(ctx, tx, plan.TenantID, plan.ID, plan.Version, milestone); err != nil {
				return err
			}
		}
		return nil
	})
}

type complianceProjectionEvent struct {
	metadata    ComplianceProjectionMetadata
	tenantID    string
	kind        string
	aggregateID string
	version     uint64
}

func (p *ComplianceReviewProjector) project(ctx context.Context, event complianceProjectionEvent, payload any, apply func(*sql.Tx) error) (ComplianceProjectionReceipt, error) {
	if p == nil || p.store == nil || p.store.db == nil {
		return ComplianceProjectionReceipt{}, errors.New("postgres is not configured")
	}
	event.metadata.EventID = strings.TrimSpace(event.metadata.EventID)
	event.tenantID = strings.TrimSpace(event.tenantID)
	event.kind = strings.TrimSpace(event.kind)
	event.aggregateID = strings.TrimSpace(event.aggregateID)
	event.metadata.OccurredAt = event.metadata.OccurredAt.UTC()
	if event.metadata.EventID == "" || event.tenantID == "" || event.kind == "" || event.aggregateID == "" || event.metadata.OccurredAt.IsZero() || event.version == 0 || event.version != event.metadata.ExpectedVersion+1 {
		return ComplianceProjectionReceipt{}, fmt.Errorf("%w: event identity, time, and next version are required", ErrComplianceProjectionInvalid)
	}
	if event.version > math.MaxInt64 || event.metadata.ExpectedVersion > math.MaxInt64 {
		return ComplianceProjectionReceipt{}, fmt.Errorf("%w: aggregate version exceeds Postgres bigint", ErrComplianceProjectionInvalid)
	}
	payloadHash, err := complianceProjectionPayloadHash(event, payload)
	if err != nil {
		return ComplianceProjectionReceipt{}, err
	}
	if err := p.store.ensureComplianceReviewTables(ctx); err != nil {
		return ComplianceProjectionReceipt{}, err
	}
	tx, err := p.store.db.BeginTx(ctx, nil)
	if err != nil {
		return ComplianceProjectionReceipt{}, fmt.Errorf("begin compliance projection: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('compliance_review_projection'), hashtext($1))`, event.tenantID+"|event|"+event.metadata.EventID); err != nil {
		return ComplianceProjectionReceipt{}, fmt.Errorf("lock compliance projection event: %w", err)
	}
	existing, found, err := loadComplianceProjectionReceipt(ctx, tx, event.tenantID, event.metadata.EventID)
	if err != nil {
		return ComplianceProjectionReceipt{}, err
	}
	if found {
		if existing.PayloadHash != payloadHash || existing.EventKind != event.kind || existing.AggregateID != event.aggregateID || existing.AggregateVersion != event.version {
			return ComplianceProjectionReceipt{}, fmt.Errorf("%w: tenant %q event %q", ErrComplianceProjectionIdempotencyConflict, event.tenantID, event.metadata.EventID)
		}
		existing.Applied = false
		return existing, nil
	}
	if err := apply(tx); err != nil {
		return ComplianceProjectionReceipt{}, err
	}
	receipt := ComplianceProjectionReceipt{
		TenantID: event.tenantID, EventID: event.metadata.EventID, EventKind: event.kind,
		AggregateID: event.aggregateID, AggregateVersion: event.version, PayloadHash: payloadHash, Applied: true,
	}
	if receipt.AggregateVersion > math.MaxInt64 {
		return ComplianceProjectionReceipt{}, fmt.Errorf("%w: receipt version exceeds Postgres bigint", ErrComplianceProjectionInvalid)
	}
	aggregateVersion := int64(receipt.AggregateVersion)
	if err := tx.QueryRowContext(ctx, `
INSERT INTO compliance_review_event_receipts (
  tenant_id, event_id, event_kind, aggregate_id, aggregate_version, payload_hash
)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING applied_at`, receipt.TenantID, receipt.EventID, receipt.EventKind, receipt.AggregateID, aggregateVersion, receipt.PayloadHash).Scan(&receipt.AppliedAt); err != nil {
		return ComplianceProjectionReceipt{}, fmt.Errorf("insert compliance projection receipt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ComplianceProjectionReceipt{}, fmt.Errorf("commit compliance projection: %w", err)
	}
	return receipt, nil
}

func complianceProjectionPayloadHash(event complianceProjectionEvent, payload any) (string, error) {
	envelope := struct {
		EventID         string    `json:"event_id"`
		TenantID        string    `json:"tenant_id"`
		Kind            string    `json:"kind"`
		AggregateID     string    `json:"aggregate_id"`
		ExpectedVersion uint64    `json:"expected_version"`
		Version         uint64    `json:"version"`
		OccurredAt      time.Time `json:"occurred_at"`
		Payload         any       `json:"payload"`
	}{
		EventID: event.metadata.EventID, TenantID: event.tenantID, Kind: event.kind,
		AggregateID: event.aggregateID, ExpectedVersion: event.metadata.ExpectedVersion,
		Version: event.version, OccurredAt: event.metadata.OccurredAt, Payload: payload,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("marshal compliance projection payload: %w", err)
	}
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func loadComplianceProjectionReceipt(ctx context.Context, tx *sql.Tx, tenantID, eventID string) (ComplianceProjectionReceipt, bool, error) {
	receipt := ComplianceProjectionReceipt{}
	var version uint64
	err := tx.QueryRowContext(ctx, `
SELECT tenant_id, event_id, event_kind, aggregate_id, aggregate_version, payload_hash, applied_at
FROM compliance_review_event_receipts
WHERE tenant_id = $1 AND event_id = $2`, tenantID, eventID).Scan(
		&receipt.TenantID, &receipt.EventID, &receipt.EventKind, &receipt.AggregateID,
		&version, &receipt.PayloadHash, &receipt.AppliedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ComplianceProjectionReceipt{}, false, nil
	}
	if err != nil {
		return ComplianceProjectionReceipt{}, false, fmt.Errorf("load compliance projection receipt: %w", err)
	}
	receipt.AggregateVersion = version
	return receipt, true, nil
}

func upsertComplianceCurrent(ctx context.Context, tx *sql.Tx, table, tenantID, id string, expectedVersion, version uint64, value any) error {
	if !complianceCurrentTableAllowed(table) || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" || version != expectedVersion+1 || version > math.MaxInt64 || expectedVersion > math.MaxInt64 {
		return fmt.Errorf("%w: current projection metadata is invalid", ErrComplianceProjectionInvalid)
	}
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal compliance current projection: %w", err)
	}
	// #nosec G201 -- table is restricted by complianceCurrentTableAllowed; all values are parameterized.
	query := fmt.Sprintf(`
INSERT INTO %s (tenant_id, id, version, body_json)
VALUES ($1, $2, $3, $4::jsonb)
ON CONFLICT (tenant_id, id) DO NOTHING
RETURNING version`, table)
	args := []any{tenantID, id, int64(version), string(body)}
	if expectedVersion != 0 {
		// #nosec G201 -- table is restricted by complianceCurrentTableAllowed; all values are parameterized.
		query = fmt.Sprintf(`
UPDATE %s
SET version = $3, body_json = $4::jsonb, updated_at = NOW()
WHERE tenant_id = $1 AND id = $2 AND version = $5
RETURNING version`, table)
		args = append(args, int64(expectedVersion))
	}
	var storedVersion int64
	err = tx.QueryRowContext(ctx, query, args...).Scan(&storedVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: tenant %q aggregate %q expected %d", ErrComplianceProjectionVersionConflict, tenantID, id, expectedVersion)
	}
	if err != nil {
		return fmt.Errorf("upsert %s current projection: %w", table, err)
	}
	return nil
}

func insertComplianceImmutable(ctx context.Context, tx *sql.Tx, table, tenantID, id, parentID string, sequence uint64, createdAt time.Time, value any) error {
	if !complianceImmutableTableAllowed(table) || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" || strings.TrimSpace(parentID) == "" || sequence == 0 || sequence > math.MaxInt64 || createdAt.IsZero() {
		return fmt.Errorf("%w: immutable projection metadata is invalid", ErrComplianceProjectionInvalid)
	}
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal compliance immutable projection: %w", err)
	}
	// #nosec G201 -- table is restricted by complianceImmutableTableAllowed; all values are parameterized.
	query := fmt.Sprintf(`
INSERT INTO %s (tenant_id, id, %s, sequence, body_json, created_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6)
ON CONFLICT (tenant_id, id)
DO UPDATE SET body_json = EXCLUDED.body_json
WHERE %s.%s = EXCLUDED.%s
  AND %s.sequence = EXCLUDED.sequence
  AND %s.body_json = EXCLUDED.body_json
RETURNING id`, table, complianceImmutableParentColumn(table), table,
		complianceImmutableParentColumn(table), complianceImmutableParentColumn(table), table, table)
	var storedID string
	err = tx.QueryRowContext(ctx, query, tenantID, id, parentID, int64(sequence), string(body), createdAt.UTC()).Scan(&storedID)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: immutable record %q conflicts with stored content", ErrComplianceProjectionIdempotencyConflict, id)
	}
	if err != nil {
		return fmt.Errorf("insert %s immutable projection: %w", table, err)
	}
	return nil
}

func upsertComplianceMilestone(ctx context.Context, tx *sql.Tx, tenantID, planID string, planVersion uint64, milestone complianceassessment.RemediationMilestone) error {
	if tenantID == "" || planID == "" || strings.TrimSpace(milestone.ID) == "" || planVersion == 0 || planVersion > math.MaxInt64 {
		return fmt.Errorf("%w: milestone projection metadata is invalid", ErrComplianceProjectionInvalid)
	}
	body, err := json.Marshal(milestone)
	if err != nil {
		return fmt.Errorf("marshal compliance milestone projection: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO compliance_remediation_milestones (
  tenant_id, id, plan_id, plan_version, body_json
)
VALUES ($1, $2, $3, $4, $5::jsonb)
ON CONFLICT (tenant_id, plan_id, id)
DO UPDATE SET plan_version = EXCLUDED.plan_version,
              body_json = EXCLUDED.body_json,
              updated_at = NOW()`, tenantID, milestone.ID, planID, int64(planVersion), string(body)); err != nil {
		return fmt.Errorf("upsert compliance milestone projection: %w", err)
	}
	return nil
}

func complianceCurrentTableAllowed(table string) bool {
	switch table {
	case "compliance_reviews", "compliance_risks", "compliance_exceptions", "compliance_work_items", "compliance_remediation_plans":
		return true
	default:
		return false
	}
}

func complianceImmutableTableAllowed(table string) bool {
	switch table {
	case "compliance_review_revisions", "compliance_work_occurrences", "compliance_work_actions":
		return true
	default:
		return false
	}
}

func complianceImmutableParentColumn(table string) string {
	switch table {
	case "compliance_review_revisions":
		return "review_id"
	default:
		return "work_item_id"
	}
}
