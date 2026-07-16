package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/policycandidate"
)

var policyExperimentStatements = []string{
	`CREATE TABLE IF NOT EXISTS policy_experiments (
		id TEXT PRIMARY KEY,
		candidate_id TEXT NOT NULL REFERENCES policy_candidates(id) ON DELETE RESTRICT,
		tenant_id TEXT NOT NULL,
		status TEXT NOT NULL,
		revision BIGINT NOT NULL,
		candidate_revision BIGINT NOT NULL,
		policy_digest TEXT NOT NULL,
		test_digest TEXT NOT NULL,
		catalog_digest TEXT NOT NULL,
		dataset_digest TEXT NOT NULL,
		checkpoints JSONB NOT NULL,
		status_reason TEXT NOT NULL DEFAULT '',
		observation_count BIGINT NOT NULL DEFAULT 0,
		record JSONB NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		started_at TIMESTAMPTZ,
		finished_at TIMESTAMPTZ
	)`,
	`CREATE INDEX IF NOT EXISTS policy_experiments_tenant_updated_idx ON policy_experiments (tenant_id, updated_at DESC, id)`,
	`CREATE INDEX IF NOT EXISTS policy_experiments_candidate_updated_idx ON policy_experiments (candidate_id, updated_at DESC, id)`,
	`CREATE INDEX IF NOT EXISTS policy_experiments_tenant_status_idx ON policy_experiments (tenant_id, status, updated_at DESC, id)`,
	`CREATE TABLE IF NOT EXISTS policy_experiment_observations (
		id TEXT PRIMARY KEY,
		experiment_id TEXT NOT NULL REFERENCES policy_experiments(id) ON DELETE RESTRICT,
		tenant_id TEXT NOT NULL,
		sequence BIGINT NOT NULL,
		kind TEXT NOT NULL,
		checkpoint_id TEXT NOT NULL DEFAULT '',
		dataset_case_id TEXT NOT NULL DEFAULT '',
		receipt_digest TEXT NOT NULL,
		idempotency_key TEXT NOT NULL,
		metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
		record JSONB NOT NULL,
		observed_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		UNIQUE (experiment_id, sequence)
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS policy_experiment_observations_idempotency_idx ON policy_experiment_observations (experiment_id, idempotency_key)`,
	`CREATE INDEX IF NOT EXISTS policy_experiment_observations_experiment_sequence_idx ON policy_experiment_observations (experiment_id, sequence)`,
}

func (s *Store) ensurePolicyExperimentTables(ctx context.Context) error {
	if err := s.ensurePolicyCandidateTables(ctx); err != nil {
		return err
	}
	return s.ensureStatements(ctx, &s.findingIntel.policyExperiment, "policy_experiments", policyExperimentStatements)
}

func (s *Store) CreatePolicyExperiment(ctx context.Context, experiment *policycandidate.PolicyExperiment) error {
	if err := validatePolicyExperimentRecord(experiment); err != nil {
		return err
	}
	if err := s.ensurePolicyExperimentTables(ctx); err != nil {
		return err
	}
	record, checkpoints, err := encodePolicyExperiment(experiment)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO policy_experiments
		(id, candidate_id, tenant_id, status, revision, candidate_revision, policy_digest, test_digest, catalog_digest, dataset_digest, checkpoints, status_reason, observation_count, record, created_at, updated_at, started_at, finished_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		ON CONFLICT (id) DO NOTHING`,
		experiment.ID, experiment.CandidateID, experiment.TenantID, experiment.Status, experiment.Revision,
		experiment.Pins.CandidateRevision, experiment.Pins.PolicyDigest, experiment.Pins.TestDigest,
		experiment.Pins.CatalogDigest, experiment.Pins.DatasetDigest, checkpoints, experiment.StatusReason,
		experiment.ObservationCount, record, experiment.CreatedAt, experiment.UpdatedAt, nullableExperimentTime(experiment.StartedAt), nullableExperimentTime(experiment.FinishedAt))
	if err != nil {
		return fmt.Errorf("create policy experiment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read policy experiment create count: %w", err)
	}
	if rows == 0 {
		existing, err := s.GetPolicyExperiment(ctx, experiment.ID)
		if err != nil {
			return err
		}
		if existing.CandidateID != experiment.CandidateID || existing.TenantID != experiment.TenantID || existing.Pins.CandidateRevision != experiment.Pins.CandidateRevision || existing.Pins.PolicyDigest != experiment.Pins.PolicyDigest || existing.Pins.TestDigest != experiment.Pins.TestDigest || existing.Pins.CatalogDigest != experiment.Pins.CatalogDigest || existing.Pins.DatasetDigest != experiment.Pins.DatasetDigest || string(mustJSON(existing.Pins.Checkpoints)) != string(mustJSON(experiment.Pins.Checkpoints)) {
			return policycandidate.ErrConflict
		}
	}
	return nil
}

func mustJSON(value any) []byte {
	payload, _ := json.Marshal(value)
	return payload
}

func nullableExperimentTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func (s *Store) GetPolicyExperiment(ctx context.Context, id string) (*policycandidate.PolicyExperiment, error) {
	if err := s.ensurePolicyExperimentTables(ctx); err != nil {
		return nil, err
	}
	var record []byte
	var observationCount int64
	if err := s.db.QueryRowContext(ctx, `SELECT record, observation_count FROM policy_experiments WHERE id = $1`, strings.TrimSpace(id)).Scan(&record, &observationCount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, policycandidate.ErrNotFound
		}
		return nil, fmt.Errorf("get policy experiment: %w", err)
	}
	return decodePolicyExperiment(record, observationCount)
}

func (s *Store) ListPolicyExperiments(ctx context.Context, request policycandidate.ListExperimentsRequest) ([]*policycandidate.PolicyExperiment, error) {
	if err := s.ensurePolicyExperimentTables(ctx); err != nil {
		return nil, err
	}
	query := `SELECT record, observation_count FROM policy_experiments WHERE tenant_id = $1`
	args := []any{request.TenantID}
	if request.CandidateID != "" {
		args = append(args, request.CandidateID)
		query += fmt.Sprintf(" AND candidate_id = $%d", len(args))
	}
	if request.Status != "" {
		args = append(args, request.Status)
		query += fmt.Sprintf(" AND status = $%d", len(args))
	}
	args = append(args, request.Limit)
	// #nosec G202 -- the suffix is fixed SQL and the limit remains parameterized.
	query += fmt.Sprintf(" ORDER BY updated_at DESC, id LIMIT $%d", len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list policy experiments: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]*policycandidate.PolicyExperiment, 0)
	for rows.Next() {
		var record []byte
		var observationCount int64
		if err := rows.Scan(&record, &observationCount); err != nil {
			return nil, fmt.Errorf("scan policy experiment: %w", err)
		}
		experiment, err := decodePolicyExperiment(record, observationCount)
		if err != nil {
			return nil, err
		}
		result = append(result, experiment)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy experiments: %w", err)
	}
	return result, nil
}

func (s *Store) SavePolicyExperiment(ctx context.Context, experiment *policycandidate.PolicyExperiment, expectedRevision int64) error {
	if err := validatePolicyExperimentRecord(experiment); err != nil {
		return err
	}
	if err := s.ensurePolicyExperimentTables(ctx); err != nil {
		return err
	}
	record, checkpoints, err := encodePolicyExperiment(experiment)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE policy_experiments SET status = $1, revision = $2, status_reason = $3, record = $4, updated_at = $5, started_at = $6, finished_at = $7
		WHERE id = $8 AND tenant_id = $9 AND revision = $10 AND candidate_id = $11 AND candidate_revision = $12
		AND policy_digest = $13 AND test_digest = $14 AND catalog_digest = $15 AND dataset_digest = $16
		AND checkpoints = $17 AND created_at = $18`,
		experiment.Status, experiment.Revision, experiment.StatusReason, record, experiment.UpdatedAt,
		nullableExperimentTime(experiment.StartedAt), nullableExperimentTime(experiment.FinishedAt), experiment.ID, experiment.TenantID, expectedRevision,
		experiment.CandidateID, experiment.Pins.CandidateRevision, experiment.Pins.PolicyDigest, experiment.Pins.TestDigest,
		experiment.Pins.CatalogDigest, experiment.Pins.DatasetDigest, checkpoints, experiment.CreatedAt)
	if err != nil {
		return fmt.Errorf("save policy experiment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read policy experiment update count: %w", err)
	}
	if rows != 1 {
		return policycandidate.ErrConflict
	}
	return nil
}

func (s *Store) AppendPolicyExperimentObservation(ctx context.Context, observation *policycandidate.PolicyExperimentObservation) (*policycandidate.PolicyExperimentObservation, error) {
	if err := validatePolicyExperimentObservationRecord(observation); err != nil {
		return nil, err
	}
	if err := s.ensurePolicyExperimentTables(ctx); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin policy experiment observation append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var tenantID, status string
	var observationCount int64
	if err := tx.QueryRowContext(ctx, `SELECT tenant_id, status, observation_count FROM policy_experiments WHERE id = $1 FOR UPDATE`, observation.ExperimentID).Scan(&tenantID, &status, &observationCount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, policycandidate.ErrNotFound
		}
		return nil, fmt.Errorf("lock policy experiment for observation: %w", err)
	}
	if tenantID != observation.TenantID || status != policycandidate.ExperimentStatusRunning {
		return nil, policycandidate.ErrConflict
	}
	var existingRecord []byte
	err = tx.QueryRowContext(ctx, `SELECT record FROM policy_experiment_observations WHERE experiment_id = $1 AND idempotency_key = $2`, observation.ExperimentID, observation.IdempotencyKey).Scan(&existingRecord)
	if err == nil {
		var existing policycandidate.PolicyExperimentObservation
		if err := json.Unmarshal(existingRecord, &existing); err != nil {
			return nil, fmt.Errorf("decode existing policy experiment observation: %w", err)
		}
		if existing.Kind != observation.Kind || existing.CheckpointID != observation.CheckpointID || existing.DatasetCaseID != observation.DatasetCaseID || existing.ReceiptDigest != observation.ReceiptDigest || !reflect.DeepEqual(existing.Metrics, observation.Metrics) {
			return nil, policycandidate.ErrConflict
		}
		existing.IdempotencyKey = observation.IdempotencyKey
		return &existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read existing policy experiment observation: %w", err)
	}
	if observationCount >= policycandidate.MaxExperimentObservations {
		return nil, policycandidate.ErrConflict
	}
	observation.Sequence = observationCount + 1
	record, err := json.Marshal(observation)
	if err != nil {
		return nil, fmt.Errorf("encode policy experiment observation: %w", err)
	}
	metrics, err := json.Marshal(observation.Metrics)
	if err != nil {
		return nil, fmt.Errorf("encode policy experiment observation metrics: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_experiment_observations (id, experiment_id, tenant_id, sequence, kind, checkpoint_id, dataset_case_id, receipt_digest, idempotency_key, metrics, record, observed_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		observation.ID, observation.ExperimentID, observation.TenantID, observation.Sequence, observation.Kind,
		observation.CheckpointID, observation.DatasetCaseID, observation.ReceiptDigest, observation.IdempotencyKey, metrics, record,
		observation.ObservedAt, observation.CreatedAt); err != nil {
		return nil, fmt.Errorf("append policy experiment observation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_experiments SET observation_count = $1 WHERE id = $2`, observation.Sequence, observation.ExperimentID); err != nil {
		return nil, fmt.Errorf("update policy experiment observation count: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit policy experiment observation: %w", err)
	}
	return observation, nil
}

func (s *Store) ListPolicyExperimentObservations(ctx context.Context, request policycandidate.ListExperimentObservationsRequest) ([]*policycandidate.PolicyExperimentObservation, error) {
	if err := s.ensurePolicyExperimentTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT record FROM policy_experiment_observations WHERE experiment_id = $1 ORDER BY sequence ASC LIMIT $2`, request.ExperimentID, request.Limit)
	if err != nil {
		return nil, fmt.Errorf("list policy experiment observations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]*policycandidate.PolicyExperimentObservation, 0)
	for rows.Next() {
		var record []byte
		if err := rows.Scan(&record); err != nil {
			return nil, fmt.Errorf("scan policy experiment observation: %w", err)
		}
		var observation policycandidate.PolicyExperimentObservation
		if err := json.Unmarshal(record, &observation); err != nil {
			return nil, fmt.Errorf("decode policy experiment observation: %w", err)
		}
		result = append(result, &observation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy experiment observations: %w", err)
	}
	return result, nil
}

func validatePolicyExperimentRecord(experiment *policycandidate.PolicyExperiment) error {
	if experiment == nil || strings.TrimSpace(experiment.ID) == "" || strings.TrimSpace(experiment.CandidateID) == "" || strings.TrimSpace(experiment.TenantID) == "" || strings.TrimSpace(experiment.Status) == "" || experiment.Revision < 1 || experiment.CreatedAt.IsZero() || experiment.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: complete policy experiment record is required", policycandidate.ErrInvalidRequest)
	}
	return nil
}

func validatePolicyExperimentObservationRecord(observation *policycandidate.PolicyExperimentObservation) error {
	if observation == nil || strings.TrimSpace(observation.ID) == "" || strings.TrimSpace(observation.ExperimentID) == "" || strings.TrimSpace(observation.TenantID) == "" || strings.TrimSpace(observation.Kind) == "" || strings.TrimSpace(observation.ReceiptDigest) == "" || strings.TrimSpace(observation.IdempotencyKey) == "" || observation.ObservedAt.IsZero() || observation.CreatedAt.IsZero() {
		return fmt.Errorf("%w: complete policy experiment observation is required", policycandidate.ErrInvalidRequest)
	}
	return nil
}

func encodePolicyExperiment(experiment *policycandidate.PolicyExperiment) ([]byte, []byte, error) {
	record, err := json.Marshal(experiment)
	if err != nil {
		return nil, nil, fmt.Errorf("encode policy experiment: %w", err)
	}
	checkpoints, err := json.Marshal(experiment.Pins.Checkpoints)
	if err != nil {
		return nil, nil, fmt.Errorf("encode policy experiment checkpoints: %w", err)
	}
	return record, checkpoints, nil
}

func decodePolicyExperiment(record []byte, observationCount int64) (*policycandidate.PolicyExperiment, error) {
	var experiment policycandidate.PolicyExperiment
	if err := json.Unmarshal(record, &experiment); err != nil {
		return nil, fmt.Errorf("decode policy experiment: %w", err)
	}
	experiment.ObservationCount = observationCount
	return &experiment, nil
}
