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

	"github.com/writer/cerebro/internal/complianceassessment"
)

var ensureComplianceAssessmentStatements = []string{
	`CREATE TABLE IF NOT EXISTS compliance_assessment_plan_revisions (
  tenant_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  revision_version BIGINT NOT NULL,
  content_digest TEXT NOT NULL,
  record_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, revision_id),
  UNIQUE (tenant_id, plan_id, revision_version)
)`,
	`CREATE TABLE IF NOT EXISTS compliance_assessment_plans (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  current_revision_id TEXT NOT NULL,
  aggregate_version BIGINT NOT NULL,
  status TEXT NOT NULL,
  record_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, current_revision_id) REFERENCES compliance_assessment_plan_revisions (tenant_id, revision_id)
)`,
	`CREATE TABLE IF NOT EXISTS compliance_assessment_runs (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  plan_revision_id TEXT NOT NULL,
  aggregate_version BIGINT NOT NULL,
  state TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  job_id TEXT NOT NULL DEFAULT '',
  input_hash TEXT NOT NULL DEFAULT '',
  automated_result_hash TEXT NOT NULL DEFAULT '',
  record_json JSONB NOT NULL,
  requested_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, plan_revision_id) REFERENCES compliance_assessment_plan_revisions (tenant_id, revision_id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_assessment_runs_unbound_idx ON compliance_assessment_runs (requested_at, tenant_id, id) WHERE state = 'queued' AND job_id = ''`,
	`CREATE TABLE IF NOT EXISTS compliance_assessment_result_chunks (
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  first_result_id TEXT NOT NULL,
  last_result_id TEXT NOT NULL,
  result_count INTEGER NOT NULL,
  previous_digest TEXT NOT NULL DEFAULT '',
  chunk_digest TEXT NOT NULL,
  record_json JSONB NOT NULL,
  PRIMARY KEY (tenant_id, run_id, sequence),
  FOREIGN KEY (tenant_id, run_id) REFERENCES compliance_assessment_runs (tenant_id, id)
)`,
	`CREATE TABLE IF NOT EXISTS compliance_assessment_event_receipts (
  event_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  aggregate_version BIGINT NOT NULL,
  payload_digest TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS compliance_assessment_event_receipts_aggregate_idx ON compliance_assessment_event_receipts (tenant_id, aggregate_type, aggregate_id, aggregate_version)`,
}

const insertComplianceAssessmentResultChunk = `
INSERT INTO compliance_assessment_result_chunks (tenant_id,run_id,sequence,first_result_id,last_result_id,result_count,previous_digest,chunk_digest,record_json)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
ON CONFLICT (tenant_id,run_id,sequence) DO NOTHING`

func (s *Store) ensureComplianceAssessmentTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.complianceAssessment, "compliance_assessment", ensureComplianceAssessmentStatements)
}

func (s *Store) ApplyPlan(ctx context.Context, eventID string, plan complianceassessment.AssessmentPlanRevision, expectedVersion uint64) error {
	if err := s.ensureComplianceAssessmentConfigured(ctx); err != nil {
		return err
	}
	recordJSON, err := json.Marshal(plan)
	if err != nil {
		return fmt.Errorf("marshal assessment plan: %w", err)
	}
	digest := assessmentJSONDigest(recordJSON)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin assessment plan projection: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	applied, err := assessmentEventApplied(ctx, tx, eventID, digest)
	if err != nil || applied {
		if applied {
			return tx.Commit()
		}
		return err
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO compliance_assessment_plan_revisions (tenant_id,revision_id,plan_id,revision_version,content_digest,record_json,created_at)
VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)
ON CONFLICT (tenant_id, revision_id) DO NOTHING`, plan.TenantID, plan.RevisionID, plan.ID, plan.Version, plan.ContentDigest, string(recordJSON), plan.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("project assessment plan revision: %w", err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		var existing string
		if err := tx.QueryRowContext(ctx, `SELECT content_digest FROM compliance_assessment_plan_revisions WHERE tenant_id=$1 AND revision_id=$2`, plan.TenantID, plan.RevisionID).Scan(&existing); err != nil {
			return err
		}
		if existing != plan.ContentDigest {
			return complianceassessment.ErrAssessmentConflict
		}
	}
	if expectedVersion == 0 {
		result, err = tx.ExecContext(ctx, `
INSERT INTO compliance_assessment_plans (tenant_id,id,current_revision_id,aggregate_version,status,record_json)
VALUES ($1,$2,$3,$4,$5,$6::jsonb)
ON CONFLICT (tenant_id,id) DO NOTHING`, plan.TenantID, plan.ID, plan.RevisionID, plan.Version, plan.Status, string(recordJSON))
	} else {
		result, err = tx.ExecContext(ctx, `
UPDATE compliance_assessment_plans SET current_revision_id=$3,aggregate_version=$4,status=$5,record_json=$6::jsonb,updated_at=NOW()
WHERE tenant_id=$1 AND id=$2 AND aggregate_version=$7`, plan.TenantID, plan.ID, plan.RevisionID, plan.Version, plan.Status, string(recordJSON), expectedVersion)
	}
	if err != nil {
		return fmt.Errorf("project assessment plan current state: %w", err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return complianceassessment.ErrAssessmentConflict
	}
	if err := insertAssessmentReceipt(ctx, tx, eventID, plan.TenantID, "assessment_plan", plan.ID, plan.Version, digest); err != nil {
		return err
	}
	return commitAssessmentTx(tx, "assessment plan")
}

func (s *Store) GetPlan(ctx context.Context, tenantID, id string) (complianceassessment.AssessmentPlanRevision, error) {
	if err := s.ensureComplianceAssessmentConfigured(ctx); err != nil {
		return complianceassessment.AssessmentPlanRevision{}, err
	}
	var data []byte
	err := s.db.QueryRowContext(ctx, `
SELECT record_json FROM (
  SELECT record_json, 0 AS priority FROM compliance_assessment_plans WHERE tenant_id=$1 AND (id=$2 OR current_revision_id=$2)
  UNION ALL
  SELECT record_json, 1 AS priority FROM compliance_assessment_plan_revisions WHERE tenant_id=$1 AND revision_id=$2
) records ORDER BY priority LIMIT 1`, strings.TrimSpace(tenantID), strings.TrimSpace(id)).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return complianceassessment.AssessmentPlanRevision{}, complianceassessment.ErrPlanNotFound
	}
	if err != nil {
		return complianceassessment.AssessmentPlanRevision{}, fmt.Errorf("get assessment plan: %w", err)
	}
	var plan complianceassessment.AssessmentPlanRevision
	if err := json.Unmarshal(data, &plan); err != nil {
		return complianceassessment.AssessmentPlanRevision{}, fmt.Errorf("decode assessment plan: %w", err)
	}
	return plan, nil
}

func (s *Store) ApplyRun(ctx context.Context, eventID string, run complianceassessment.AssessmentRun, expectedVersion uint64) error {
	if err := s.ensureComplianceAssessmentConfigured(ctx); err != nil {
		return err
	}
	recordJSON, err := json.Marshal(run)
	if err != nil {
		return fmt.Errorf("marshal assessment run: %w", err)
	}
	digest := assessmentJSONDigest(recordJSON)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin assessment run projection: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	applied, err := assessmentEventApplied(ctx, tx, eventID, digest)
	if err != nil || applied {
		if applied {
			return tx.Commit()
		}
		return err
	}
	var result sql.Result
	if expectedVersion == 0 {
		result, err = tx.ExecContext(ctx, `
INSERT INTO compliance_assessment_runs (tenant_id,id,plan_revision_id,aggregate_version,state,idempotency_key,request_hash,job_id,input_hash,automated_result_hash,record_json,requested_at,completed_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13)
ON CONFLICT (tenant_id,id) DO NOTHING`, run.TenantID, run.ID, run.PlanRevisionID, run.Version, run.State, run.IdempotencyKey, run.RequestHash, run.JobID, run.InputHash, run.AutomatedResultHash, string(recordJSON), run.RequestedAt.UTC(), nullableTime(run.CompletedAt))
	} else {
		result, err = tx.ExecContext(ctx, `
UPDATE compliance_assessment_runs SET aggregate_version=$4,state=$5,job_id=$6,input_hash=$7,automated_result_hash=$8,record_json=$9::jsonb,completed_at=$10
WHERE tenant_id=$1 AND id=$2 AND aggregate_version=$3`, run.TenantID, run.ID, expectedVersion, run.Version, run.State, run.JobID, run.InputHash, run.AutomatedResultHash, string(recordJSON), nullableTime(run.CompletedAt))
	}
	if err != nil {
		return fmt.Errorf("project assessment run: %w", err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return complianceassessment.ErrAssessmentConflict
	}
	if err := insertAssessmentReceipt(ctx, tx, eventID, run.TenantID, "assessment_run", run.ID, run.Version, digest); err != nil {
		return err
	}
	return commitAssessmentTx(tx, "assessment run")
}

func (s *Store) GetRun(ctx context.Context, tenantID, runID string) (complianceassessment.AssessmentRun, error) {
	return s.getAssessmentRun(ctx, `SELECT record_json FROM compliance_assessment_runs WHERE tenant_id=$1 AND id=$2`, tenantID, runID)
}

func (s *Store) FindRunByIdempotency(ctx context.Context, tenantID, key string) (complianceassessment.AssessmentRun, error) {
	return s.getAssessmentRun(ctx, `SELECT record_json FROM compliance_assessment_runs WHERE tenant_id=$1 AND idempotency_key=$2`, tenantID, key)
}

func (s *Store) getAssessmentRun(ctx context.Context, query, tenantID, value string) (complianceassessment.AssessmentRun, error) {
	if err := s.ensureComplianceAssessmentConfigured(ctx); err != nil {
		return complianceassessment.AssessmentRun{}, err
	}
	var data []byte
	if err := s.db.QueryRowContext(ctx, query, strings.TrimSpace(tenantID), strings.TrimSpace(value)).Scan(&data); err != nil { // #nosec G202 -- callers supply fixed internal queries; values remain parameterized.
		if errors.Is(err, sql.ErrNoRows) {
			return complianceassessment.AssessmentRun{}, complianceassessment.ErrRunNotFound
		}
		return complianceassessment.AssessmentRun{}, err
	}
	var run complianceassessment.AssessmentRun
	if err := json.Unmarshal(data, &run); err != nil {
		return complianceassessment.AssessmentRun{}, fmt.Errorf("decode assessment run: %w", err)
	}
	return run, nil
}

func (s *Store) ListUnboundRuns(ctx context.Context, limit uint32) ([]complianceassessment.AssessmentRun, error) {
	if err := s.ensureComplianceAssessmentConfigured(ctx); err != nil {
		return nil, err
	}
	if limit == 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT record_json FROM compliance_assessment_runs WHERE state='queued' AND job_id='' ORDER BY requested_at,tenant_id,id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var result []complianceassessment.AssessmentRun
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var run complianceassessment.AssessmentRun
		if err := json.Unmarshal(data, &run); err != nil {
			return nil, err
		}
		result = append(result, run)
	}
	return result, rows.Err()
}

func (s *Store) ListNonterminalRuns(ctx context.Context, limit uint32) ([]complianceassessment.AssessmentRun, error) {
	if err := s.ensureComplianceAssessmentConfigured(ctx); err != nil {
		return nil, err
	}
	if limit == 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT record_json FROM compliance_assessment_runs WHERE state IN ('queued','collecting','evaluating') ORDER BY requested_at,tenant_id,id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var result []complianceassessment.AssessmentRun
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var run complianceassessment.AssessmentRun
		if err := json.Unmarshal(data, &run); err != nil {
			return nil, err
		}
		result = append(result, run)
	}
	return result, rows.Err()
}

func (s *Store) ApplyResultChunk(ctx context.Context, eventID, tenantID string, chunk complianceassessment.ResultChunk) error {
	if err := s.ensureComplianceAssessmentConfigured(ctx); err != nil {
		return err
	}
	recordJSON, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	digest := assessmentJSONDigest(recordJSON)
	tenantID = strings.TrimSpace(tenantID)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin assessment result chunk projection: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	applied, err := assessmentEventApplied(ctx, tx, eventID, digest)
	if err != nil {
		return err
	}
	if applied {
		return tx.Commit()
	}
	result, err := tx.ExecContext(ctx, insertComplianceAssessmentResultChunk, tenantID, chunk.RunID, chunk.Sequence, chunk.FirstResultID, chunk.LastResultID, chunk.Count, chunk.PreviousDigest, chunk.Digest, string(recordJSON))
	if err != nil {
		return fmt.Errorf("project assessment result chunk: %w", err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		var existingJSON []byte
		if err := tx.QueryRowContext(ctx, `SELECT record_json FROM compliance_assessment_result_chunks WHERE tenant_id=$1 AND run_id=$2 AND sequence=$3`, tenantID, chunk.RunID, chunk.Sequence).Scan(&existingJSON); err != nil {
			return fmt.Errorf("read existing assessment result chunk: %w", err)
		}
		if !assessmentResultChunkPayloadMatches(existingJSON, digest) {
			return complianceassessment.ErrAssessmentConflict
		}
	}
	if err := insertAssessmentReceipt(ctx, tx, eventID, tenantID, "assessment_result_chunk", chunk.RunID, uint64(chunk.Sequence), digest); err != nil {
		return err
	}
	return commitAssessmentTx(tx, "assessment result chunk")
}

func (s *Store) ListResultChunks(ctx context.Context, tenantID, runID string) ([]complianceassessment.ResultChunk, error) {
	if err := s.ensureComplianceAssessmentConfigured(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT record_json FROM compliance_assessment_result_chunks WHERE tenant_id=$1 AND run_id=$2 ORDER BY sequence`, strings.TrimSpace(tenantID), strings.TrimSpace(runID))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var result []complianceassessment.ResultChunk
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var chunk complianceassessment.ResultChunk
		if err := json.Unmarshal(data, &chunk); err != nil {
			return nil, err
		}
		result = append(result, chunk)
	}
	return result, rows.Err()
}

func (s *Store) ensureComplianceAssessmentConfigured(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	return s.ensureComplianceAssessmentTables(ctx)
}

func assessmentEventApplied(ctx context.Context, tx *sql.Tx, eventID, digest string) (bool, error) {
	var existing string
	err := tx.QueryRowContext(ctx, `SELECT payload_digest FROM compliance_assessment_event_receipts WHERE event_id=$1`, eventID).Scan(&existing)
	if err == nil {
		if existing == digest {
			return true, nil
		}
		return false, complianceassessment.ErrAssessmentConflict
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, err
}

type assessmentReceiptExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertAssessmentReceipt(ctx context.Context, tx assessmentReceiptExecutor, eventID, tenantID, aggregateType, aggregateID string, version uint64, digest string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO compliance_assessment_event_receipts (event_id,tenant_id,aggregate_type,aggregate_id,aggregate_version,payload_digest) VALUES ($1,$2,$3,$4,$5,$6)`, eventID, strings.TrimSpace(tenantID), aggregateType, aggregateID, version, digest)
	return err
}

func commitAssessmentTx(tx *sql.Tx, label string) error {
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s projection: %w", label, err)
	}
	return nil
}

func assessmentJSONDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func assessmentResultChunkPayloadMatches(data []byte, digest string) bool {
	var chunk complianceassessment.ResultChunk
	if err := json.Unmarshal(data, &chunk); err != nil {
		return false
	}
	canonical, err := json.Marshal(chunk)
	return err == nil && assessmentJSONDigest(canonical) == digest
}
