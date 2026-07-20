package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/policycandidate"
)

var policyCandidateStatements = []string{
	`CREATE TABLE IF NOT EXISTS policy_candidates (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		status TEXT NOT NULL,
		revision BIGINT NOT NULL,
		record JSONB NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS policy_candidates_tenant_updated_idx ON policy_candidates (tenant_id, updated_at DESC, id)`,
	`CREATE INDEX IF NOT EXISTS policy_candidates_tenant_status_idx ON policy_candidates (tenant_id, status, updated_at DESC, id)`,
	`CREATE TABLE IF NOT EXISTS policy_candidate_events (
		id BIGSERIAL PRIMARY KEY,
		candidate_id TEXT NOT NULL,
		tenant_id TEXT NOT NULL,
		revision BIGINT NOT NULL,
		from_status TEXT NOT NULL,
		to_status TEXT NOT NULL,
		policy_digest TEXT NOT NULL DEFAULT '',
		test_digest TEXT NOT NULL DEFAULT '',
		shadow_receipt_id TEXT NOT NULL DEFAULT '',
		occurred_at TIMESTAMPTZ NOT NULL,
		UNIQUE (candidate_id, revision)
	)`,
	`CREATE INDEX IF NOT EXISTS policy_candidate_events_tenant_candidate_idx ON policy_candidate_events (tenant_id, candidate_id, revision)`,
}

func (s *Store) ensurePolicyCandidateTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.findingIntel.policyCandidate, "policy_candidates", policyCandidateStatements)
}

func (s *Store) CreatePolicyCandidate(ctx context.Context, candidate *policycandidate.Candidate) error {
	if candidate == nil {
		return fmt.Errorf("%w: candidate is required", policycandidate.ErrInvalidRequest)
	}
	if err := s.ensurePolicyCandidateTables(ctx); err != nil {
		return err
	}
	record, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("encode policy candidate: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin policy candidate create: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `INSERT INTO policy_candidates (id, tenant_id, status, revision, record, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, candidate.ID, candidate.TenantID, candidate.Status, candidate.Revision, record, candidate.CreatedAt, candidate.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create policy candidate: %w", err)
	}
	if err := insertPolicyCandidateEvent(ctx, tx, candidate, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit policy candidate create: %w", err)
	}
	return nil
}

func (s *Store) GetPolicyCandidate(ctx context.Context, id string) (*policycandidate.Candidate, error) {
	if err := s.ensurePolicyCandidateTables(ctx); err != nil {
		return nil, err
	}
	var record []byte
	if err := s.db.QueryRowContext(ctx, `SELECT record FROM policy_candidates WHERE id = $1`, strings.TrimSpace(id)).Scan(&record); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, policycandidate.ErrNotFound
		}
		return nil, fmt.Errorf("get policy candidate: %w", err)
	}
	return decodePolicyCandidate(record)
}

func (s *Store) ListPolicyCandidates(ctx context.Context, request policycandidate.ListRequest) ([]*policycandidate.Candidate, error) {
	if err := s.ensurePolicyCandidateTables(ctx); err != nil {
		return nil, err
	}
	query := `SELECT record FROM policy_candidates WHERE tenant_id = $1`
	args := []any{request.TenantID}
	if request.Status != "" {
		query += ` AND status = $2 ORDER BY updated_at DESC, id LIMIT $3`
		args = append(args, request.Status, request.Limit)
	} else {
		query += ` ORDER BY updated_at DESC, id LIMIT $2`
		args = append(args, request.Limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list policy candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]*policycandidate.Candidate, 0)
	for rows.Next() {
		var record []byte
		if err := rows.Scan(&record); err != nil {
			return nil, fmt.Errorf("scan policy candidate: %w", err)
		}
		candidate, err := decodePolicyCandidate(record)
		if err != nil {
			return nil, err
		}
		result = append(result, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy candidates: %w", err)
	}
	return result, nil
}

func (s *Store) SavePolicyCandidate(ctx context.Context, candidate *policycandidate.Candidate, expectedRevision int64) error {
	if candidate == nil {
		return fmt.Errorf("%w: candidate is required", policycandidate.ErrInvalidRequest)
	}
	if err := s.ensurePolicyCandidateTables(ctx); err != nil {
		return err
	}
	record, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("encode policy candidate: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin policy candidate save: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var fromStatus string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM policy_candidates WHERE id = $1 AND tenant_id = $2 AND revision = $3 FOR UPDATE`, candidate.ID, candidate.TenantID, expectedRevision).Scan(&fromStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return policycandidate.ErrConflict
		}
		return fmt.Errorf("lock policy candidate: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE policy_candidates
		SET status = $1, revision = $2, record = $3, updated_at = $4
		WHERE id = $5 AND tenant_id = $6 AND revision = $7`, candidate.Status, candidate.Revision, record, candidate.UpdatedAt, candidate.ID, candidate.TenantID, expectedRevision)
	if err != nil {
		return fmt.Errorf("save policy candidate: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read policy candidate update count: %w", err)
	}
	if rows != 1 {
		return policycandidate.ErrConflict
	}
	if err := insertPolicyCandidateEvent(ctx, tx, candidate, fromStatus); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit policy candidate save: %w", err)
	}
	return nil
}

type policyCandidateSQLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertPolicyCandidateEvent(ctx context.Context, executor policyCandidateSQLExecutor, candidate *policycandidate.Candidate, fromStatus string) error {
	policyDigest := ""
	testDigest := ""
	if candidate.Artifacts != nil {
		policyDigest = candidate.Artifacts.PolicyDigest
		testDigest = candidate.Artifacts.TestDigest
	}
	shadowReceiptID := ""
	if candidate.Shadow != nil {
		shadowReceiptID = candidate.Shadow.ReceiptID
	}
	if _, err := executor.ExecContext(ctx, `INSERT INTO policy_candidate_events
		(candidate_id, tenant_id, revision, from_status, to_status, policy_digest, test_digest, shadow_receipt_id, occurred_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, candidate.ID, candidate.TenantID, candidate.Revision, fromStatus, candidate.Status, policyDigest, testDigest, shadowReceiptID, candidate.UpdatedAt); err != nil {
		return fmt.Errorf("append policy candidate event: %w", err)
	}
	return nil
}

func decodePolicyCandidate(record []byte) (*policycandidate.Candidate, error) {
	var candidate policycandidate.Candidate
	if err := json.Unmarshal(record, &candidate); err != nil {
		return nil, fmt.Errorf("decode policy candidate: %w", err)
	}
	return &candidate, nil
}
