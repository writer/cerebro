package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/complianceimprovement"
)

const maxComplianceImprovementJSONBytes = 1024 * 1024

var (
	_ complianceimprovement.Store            = (*Store)(nil)
	_ complianceimprovement.TeamUpdateOutbox = (*Store)(nil)
)

func (s *Store) CreateComplianceImprovement(ctx context.Context, request complianceimprovement.CreateRecordRequest) (complianceimprovement.ImprovementRecord, bool, error) {
	if s == nil || s.db == nil {
		return complianceimprovement.ImprovementRecord{}, false, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceImprovementTables(ctx); err != nil {
		return complianceimprovement.ImprovementRecord{}, false, err
	}
	if err := validateImprovementCreateRequest(request); err != nil {
		return complianceimprovement.ImprovementRecord{}, false, err
	}
	runJSON, err := marshalComplianceImprovementJSON("run", request.Run)
	if err != nil {
		return complianceimprovement.ImprovementRecord{}, false, err
	}
	revisionJSON, err := marshalComplianceImprovementJSON("revision", request.Revision)
	if err != nil {
		return complianceimprovement.ImprovementRecord{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return complianceimprovement.ImprovementRecord{}, false, fmt.Errorf("begin compliance improvement create: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
INSERT INTO compliance_improvement_runs (
  tenant_id, id, program_id, state, decision_owner, version,
  current_revision_id, idempotency_key, run_json, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)
ON CONFLICT (tenant_id, id) DO NOTHING`,
		request.Run.TenantID, request.Run.ID, request.Run.ProgramID, request.Run.State,
		request.Run.DecisionOwner, request.Run.AggregateVersion, request.Run.CurrentRevisionID,
		request.Run.IdempotencyKey, runJSON, request.Run.CreatedAt, request.Run.UpdatedAt)
	if err != nil {
		return complianceimprovement.ImprovementRecord{}, false, fmt.Errorf("insert compliance improvement run: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return complianceimprovement.ImprovementRecord{}, false, fmt.Errorf("read compliance improvement insert result: %w", err)
	}
	if rows == 0 {
		existing, loadErr := getComplianceImprovementWith(ctx, tx, request.Run.TenantID, request.Run.ID, false)
		if loadErr != nil {
			return complianceimprovement.ImprovementRecord{}, false, loadErr
		}
		if existing.Run.ProgramID != request.Run.ProgramID || existing.Run.IdempotencyKey != request.Run.IdempotencyKey {
			return complianceimprovement.ImprovementRecord{}, false, complianceimprovement.ErrConflict
		}
		return existing, false, nil
	}
	if err := insertComplianceImprovementRevision(ctx, tx, request.Revision, revisionJSON); err != nil {
		return complianceimprovement.ImprovementRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return complianceimprovement.ImprovementRecord{}, false, fmt.Errorf("commit compliance improvement create: %w", err)
	}
	return complianceimprovement.ImprovementRecord{Run: request.Run, Revision: request.Revision}, true, nil
}

func (s *Store) GetComplianceImprovement(ctx context.Context, tenantID, runID string) (complianceimprovement.ImprovementRecord, error) {
	if s == nil || s.db == nil {
		return complianceimprovement.ImprovementRecord{}, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceImprovementTables(ctx); err != nil {
		return complianceimprovement.ImprovementRecord{}, err
	}
	return getComplianceImprovementWith(ctx, s.db, strings.TrimSpace(tenantID), strings.TrimSpace(runID), false)
}

func (s *Store) AppendComplianceImprovementRevision(ctx context.Context, request complianceimprovement.AppendRevisionRequest) (complianceimprovement.ImprovementRecord, error) {
	if s == nil || s.db == nil {
		return complianceimprovement.ImprovementRecord{}, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceImprovementTables(ctx); err != nil {
		return complianceimprovement.ImprovementRecord{}, err
	}
	if err := validateImprovementAppendRequest(request); err != nil {
		return complianceimprovement.ImprovementRecord{}, err
	}
	runJSON, err := marshalComplianceImprovementJSON("run", request.Run)
	if err != nil {
		return complianceimprovement.ImprovementRecord{}, err
	}
	revisionJSON, err := marshalComplianceImprovementJSON("revision", request.Revision)
	if err != nil {
		return complianceimprovement.ImprovementRecord{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return complianceimprovement.ImprovementRecord{}, fmt.Errorf("begin compliance improvement append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := getComplianceImprovementWith(ctx, tx, request.TenantID, request.RunID, true)
	if err != nil {
		return complianceimprovement.ImprovementRecord{}, err
	}
	if current.Run.AggregateVersion != request.ExpectedVersion || request.Run.AggregateVersion != request.ExpectedVersion+1 {
		return complianceimprovement.ImprovementRecord{}, complianceimprovement.ErrConflict
	}
	if request.Revision.Version.PredecessorID != current.Run.CurrentRevisionID {
		return complianceimprovement.ImprovementRecord{}, fmt.Errorf("%w: revision predecessor does not match current revision", complianceimprovement.ErrConflict)
	}
	if err := insertComplianceImprovementRevision(ctx, tx, request.Revision, revisionJSON); err != nil {
		return complianceimprovement.ImprovementRecord{}, err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE compliance_improvement_runs
SET state = $1, decision_owner = $2, version = $3, current_revision_id = $4,
    run_json = $5::jsonb, updated_at = $6
WHERE tenant_id = $7 AND id = $8 AND version = $9`,
		request.Run.State, request.Run.DecisionOwner, request.Run.AggregateVersion,
		request.Run.CurrentRevisionID, runJSON, request.Run.UpdatedAt,
		request.TenantID, request.RunID, request.ExpectedVersion)
	if err != nil {
		return complianceimprovement.ImprovementRecord{}, fmt.Errorf("update compliance improvement run: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return complianceimprovement.ImprovementRecord{}, complianceimprovement.ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return complianceimprovement.ImprovementRecord{}, fmt.Errorf("commit compliance improvement append: %w", err)
	}
	return complianceimprovement.ImprovementRecord{Run: request.Run, Revision: request.Revision}, nil
}

func (s *Store) EnqueueTeamUpdate(ctx context.Context, tenantID, idempotencyKey string, update complianceimprovement.TeamUpdate) (complianceimprovement.TeamUpdateReceipt, error) {
	if s == nil || s.db == nil {
		return complianceimprovement.TeamUpdateReceipt{}, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceImprovementTables(ctx); err != nil {
		return complianceimprovement.TeamUpdateReceipt{}, err
	}
	tenantID = strings.TrimSpace(tenantID)
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if tenantID == "" || idempotencyKey == "" || strings.TrimSpace(update.ProposalDigest) == "" {
		return complianceimprovement.TeamUpdateReceipt{}, fmt.Errorf("%w: tenant, idempotency key, and proposal digest are required", complianceimprovement.ErrInvalidRequest)
	}
	updateJSON, err := marshalComplianceImprovementJSON("team update", update)
	if err != nil {
		return complianceimprovement.TeamUpdateReceipt{}, err
	}
	outboxID := complianceImprovementOutboxID(tenantID, idempotencyKey)
	var receipt complianceimprovement.TeamUpdateReceipt
	err = s.db.QueryRowContext(ctx, `
INSERT INTO compliance_improvement_team_outbox (
  tenant_id, outbox_id, idempotency_key, proposal_digest, update_json, created_at
)
VALUES ($1, $2, $3, $4, $5::jsonb, $6)
ON CONFLICT (tenant_id, idempotency_key) DO UPDATE
SET idempotency_key = EXCLUDED.idempotency_key
RETURNING outbox_id, proposal_digest, created_at`,
		tenantID, outboxID, idempotencyKey, update.ProposalDigest, updateJSON, update.CreatedAt).
		Scan(&receipt.OutboxID, &receipt.ProposalDigest, &receipt.QueuedAt)
	if err != nil {
		return complianceimprovement.TeamUpdateReceipt{}, fmt.Errorf("enqueue compliance improvement team update: %w", err)
	}
	if receipt.ProposalDigest != update.ProposalDigest {
		return complianceimprovement.TeamUpdateReceipt{}, fmt.Errorf("%w: team update idempotency key already binds another proposal", complianceimprovement.ErrConflict)
	}
	return receipt, nil
}

type improvementQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func getComplianceImprovementWith(ctx context.Context, queryer improvementQueryer, tenantID, runID string, forUpdate bool) (complianceimprovement.ImprovementRecord, error) {
	query := `
SELECT r.run_json::text, v.revision_json::text
FROM compliance_improvement_runs r
JOIN compliance_improvement_revisions v
  ON v.tenant_id = r.tenant_id AND v.run_id = r.id AND v.revision_id = r.current_revision_id
WHERE r.tenant_id = $1 AND r.id = $2`
	if forUpdate {
		query += " FOR UPDATE OF r"
	}
	var runJSON, revisionJSON []byte
	if err := queryer.QueryRowContext(ctx, query, strings.TrimSpace(tenantID), strings.TrimSpace(runID)).Scan(&runJSON, &revisionJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return complianceimprovement.ImprovementRecord{}, complianceimprovement.ErrNotFound
		}
		return complianceimprovement.ImprovementRecord{}, fmt.Errorf("get compliance improvement: %w", err)
	}
	var record complianceimprovement.ImprovementRecord
	if err := json.Unmarshal(runJSON, &record.Run); err != nil {
		return complianceimprovement.ImprovementRecord{}, fmt.Errorf("decode compliance improvement run: %w", err)
	}
	if err := json.Unmarshal(revisionJSON, &record.Revision); err != nil {
		return complianceimprovement.ImprovementRecord{}, fmt.Errorf("decode compliance improvement revision: %w", err)
	}
	return record, nil
}

func insertComplianceImprovementRevision(ctx context.Context, tx *sql.Tx, revision complianceimprovement.ImprovementRevision, revisionJSON []byte) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO compliance_improvement_revisions (
  tenant_id, run_id, revision_id, version, content_digest,
  predecessor_id, created_by, revision_json, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)`,
		revision.TenantID, revision.RunID, revision.Version.RevisionID, revision.Version.Version,
		revision.Version.ContentDigest, revision.Version.PredecessorID, revision.Version.CreatedBy,
		revisionJSON, revision.Version.LastModified)
	if err != nil {
		return fmt.Errorf("insert compliance improvement revision: %w", err)
	}
	return nil
}

func validateImprovementCreateRequest(request complianceimprovement.CreateRecordRequest) error {
	if request.Run.TenantID == "" || request.Run.ID == "" || request.Run.ProgramID == "" || request.Run.AggregateVersion != 1 || request.Run.CurrentRevisionID == "" {
		return fmt.Errorf("%w: invalid initial improvement run", complianceimprovement.ErrInvalidRequest)
	}
	if request.Revision.TenantID != request.Run.TenantID || request.Revision.RunID != request.Run.ID || request.Revision.Version.Version != 1 || request.Revision.Version.RevisionID != request.Run.CurrentRevisionID {
		return fmt.Errorf("%w: initial revision does not match run", complianceimprovement.ErrInvalidRequest)
	}
	if err := request.Revision.Version.Validate(); err != nil {
		return fmt.Errorf("%w: invalid revision metadata: %v", complianceimprovement.ErrInvalidRequest, err)
	}
	return nil
}

func validateImprovementAppendRequest(request complianceimprovement.AppendRevisionRequest) error {
	if request.TenantID == "" || request.RunID == "" || request.Run.TenantID != request.TenantID || request.Run.ID != request.RunID {
		return fmt.Errorf("%w: append tenant and run identity must match", complianceimprovement.ErrInvalidRequest)
	}
	if request.Revision.TenantID != request.TenantID || request.Revision.RunID != request.RunID || request.Revision.Version.Version != request.Run.AggregateVersion || request.Revision.Version.RevisionID != request.Run.CurrentRevisionID {
		return fmt.Errorf("%w: appended revision does not match run", complianceimprovement.ErrInvalidRequest)
	}
	if err := request.Revision.Version.Validate(); err != nil {
		return fmt.Errorf("%w: invalid revision metadata: %v", complianceimprovement.ErrInvalidRequest, err)
	}
	return nil
}

func marshalComplianceImprovementJSON(label string, value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal compliance improvement %s: %w", label, err)
	}
	if len(payload) > maxComplianceImprovementJSONBytes {
		return nil, fmt.Errorf("%w: compliance improvement %s exceeds %d bytes", complianceimprovement.ErrInvalidRequest, label, maxComplianceImprovementJSONBytes)
	}
	return payload, nil
}

func complianceImprovementOutboxID(tenantID, idempotencyKey string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(idempotencyKey)))
	return "improvement-update-" + hex.EncodeToString(digest[:12])
}
