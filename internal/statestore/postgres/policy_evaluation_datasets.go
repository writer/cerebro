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

var policyEvaluationDatasetStatements = []string{
	`CREATE TABLE IF NOT EXISTS policy_evaluation_datasets (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		candidate_id TEXT NOT NULL REFERENCES policy_candidates(id) ON DELETE RESTRICT,
		name TEXT NOT NULL,
		current_revision_id TEXT NOT NULL,
		aggregate_version BIGINT NOT NULL CHECK (aggregate_version > 0),
		idempotency_key TEXT NOT NULL,
		create_request_hash TEXT NOT NULL,
		record JSONB NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		UNIQUE (tenant_id, candidate_id, idempotency_key)
	)`,
	`CREATE INDEX IF NOT EXISTS policy_evaluation_datasets_tenant_updated_idx ON policy_evaluation_datasets (tenant_id, updated_at DESC, id)`,
	`CREATE INDEX IF NOT EXISTS policy_evaluation_datasets_candidate_updated_idx ON policy_evaluation_datasets (tenant_id, candidate_id, updated_at DESC, id)`,
	`CREATE TABLE IF NOT EXISTS policy_evaluation_dataset_revisions (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		dataset_id TEXT NOT NULL REFERENCES policy_evaluation_datasets(id) ON DELETE RESTRICT,
		version BIGINT NOT NULL CHECK (version > 0),
		predecessor_id TEXT NOT NULL DEFAULT '',
		policy_digest TEXT NOT NULL,
		source_test_digest TEXT NOT NULL,
		content_digest TEXT NOT NULL,
		case_count INTEGER NOT NULL CHECK (case_count > 0 AND case_count <= 100),
		change_summary TEXT NOT NULL,
		created_by TEXT NOT NULL,
		idempotency_key TEXT NOT NULL,
		request_hash TEXT NOT NULL,
		record JSONB NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		UNIQUE (dataset_id, version),
		UNIQUE (dataset_id, idempotency_key)
	)`,
	`CREATE INDEX IF NOT EXISTS policy_evaluation_dataset_revisions_dataset_version_idx ON policy_evaluation_dataset_revisions (tenant_id, dataset_id, version)`,
	`CREATE TABLE IF NOT EXISTS policy_evaluation_dataset_cases (
		tenant_id TEXT NOT NULL,
		dataset_id TEXT NOT NULL REFERENCES policy_evaluation_datasets(id) ON DELETE RESTRICT,
		revision_id TEXT NOT NULL REFERENCES policy_evaluation_dataset_revisions(id) ON DELETE RESTRICT,
		case_id TEXT NOT NULL,
		ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
		content_digest TEXT NOT NULL,
		record JSONB NOT NULL,
		PRIMARY KEY (revision_id, case_id),
		UNIQUE (revision_id, ordinal)
	)`,
	`CREATE INDEX IF NOT EXISTS policy_evaluation_dataset_cases_revision_ordinal_idx ON policy_evaluation_dataset_cases (tenant_id, dataset_id, revision_id, ordinal)`,
}

var _ policycandidate.PolicyEvaluationDatasetStore = (*Store)(nil)

func (s *Store) ensurePolicyEvaluationDatasetTables(ctx context.Context) error {
	if err := s.ensurePolicyCandidateTables(ctx); err != nil {
		return err
	}
	return s.ensureStatements(ctx, &s.findingIntel.policyDataset, "policy_evaluation_datasets", policyEvaluationDatasetStatements)
}

func (s *Store) CreatePolicyEvaluationDataset(ctx context.Context, command policycandidate.CreatePolicyEvaluationDatasetRecord) (*policycandidate.PolicyEvaluationDataset, *policycandidate.PolicyEvaluationDatasetRevision, error) {
	if err := validatePolicyEvaluationDatasetCreate(command); err != nil {
		return nil, nil, err
	}
	if err := s.ensurePolicyEvaluationDatasetTables(ctx); err != nil {
		return nil, nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin policy evaluation dataset create: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "policy-evaluation-dataset\x00"+command.Dataset.TenantID+"\x00"+command.Dataset.CandidateID+"\x00"+command.IdempotencyKey); err != nil {
		return nil, nil, fmt.Errorf("lock policy evaluation dataset create key: %w", err)
	}
	existing, existingRevision, err := getPolicyEvaluationDatasetByCreateKey(ctx, tx, command.Dataset.TenantID, command.Dataset.CandidateID, command.IdempotencyKey)
	if err == nil {
		if existing.CreateRequestHash != command.Dataset.CreateRequestHash {
			return nil, nil, policycandidate.ErrConflict
		}
		return existing, existingRevision, nil
	}
	if !errors.Is(err, policycandidate.ErrNotFound) {
		return nil, nil, err
	}
	datasetRecord, err := json.Marshal(command.Dataset)
	if err != nil {
		return nil, nil, fmt.Errorf("encode policy evaluation dataset: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_evaluation_datasets
		(id, tenant_id, candidate_id, name, current_revision_id, aggregate_version, idempotency_key, create_request_hash, record, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, command.Dataset.ID, command.Dataset.TenantID,
		command.Dataset.CandidateID, command.Dataset.Name, command.Dataset.CurrentRevisionID, command.Dataset.AggregateVersion,
		command.IdempotencyKey, command.Dataset.CreateRequestHash, datasetRecord, command.Dataset.CreatedAt, command.Dataset.UpdatedAt); err != nil {
		return nil, nil, fmt.Errorf("create policy evaluation dataset: %w", err)
	}
	if err := insertPolicyEvaluationDatasetRevision(ctx, tx, command.Revision, command.Cases, command.IdempotencyKey); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit policy evaluation dataset create: %w", err)
	}
	return clonePolicyEvaluationDataset(command.Dataset), clonePolicyEvaluationDatasetRevision(command.Revision), nil
}

func (s *Store) AppendPolicyEvaluationDatasetRevision(ctx context.Context, command policycandidate.AppendPolicyEvaluationDatasetRevisionRecord) (*policycandidate.PolicyEvaluationDataset, *policycandidate.PolicyEvaluationDatasetRevision, error) {
	if err := validatePolicyEvaluationDatasetAppend(command); err != nil {
		return nil, nil, err
	}
	if err := s.ensurePolicyEvaluationDatasetTables(ctx); err != nil {
		return nil, nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin policy evaluation dataset append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := getPolicyEvaluationDatasetTx(ctx, tx, command.Dataset.TenantID, command.Dataset.ID, true)
	if err != nil {
		return nil, nil, err
	}
	existing, err := getPolicyEvaluationDatasetRevisionByKey(ctx, tx, command.Dataset.TenantID, command.Dataset.ID, command.IdempotencyKey)
	if err == nil {
		if existing.RequestHash != command.Revision.RequestHash {
			return nil, nil, policycandidate.ErrConflict
		}
		return current, existing, nil
	}
	if !errors.Is(err, policycandidate.ErrNotFound) {
		return nil, nil, err
	}
	if current.AggregateVersion != command.ExpectedVersion || current.CandidateID != command.Dataset.CandidateID ||
		command.Dataset.AggregateVersion != command.ExpectedVersion+1 || command.Revision.Version != command.Dataset.AggregateVersion ||
		command.Revision.PredecessorID != current.CurrentRevisionID {
		return nil, nil, policycandidate.ErrConflict
	}
	if err := insertPolicyEvaluationDatasetRevision(ctx, tx, command.Revision, command.Cases, command.IdempotencyKey); err != nil {
		return nil, nil, err
	}
	record, err := json.Marshal(command.Dataset)
	if err != nil {
		return nil, nil, fmt.Errorf("encode updated policy evaluation dataset: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE policy_evaluation_datasets SET current_revision_id=$1, aggregate_version=$2, record=$3, updated_at=$4
		WHERE id=$5 AND tenant_id=$6 AND aggregate_version=$7`, command.Dataset.CurrentRevisionID, command.Dataset.AggregateVersion,
		record, command.Dataset.UpdatedAt, command.Dataset.ID, command.Dataset.TenantID, command.ExpectedVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("advance policy evaluation dataset: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, nil, fmt.Errorf("read policy evaluation dataset advance count: %w", err)
	}
	if rows != 1 {
		return nil, nil, policycandidate.ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit policy evaluation dataset append: %w", err)
	}
	return clonePolicyEvaluationDataset(command.Dataset), clonePolicyEvaluationDatasetRevision(command.Revision), nil
}

func (s *Store) GetPolicyEvaluationDataset(ctx context.Context, tenantID, datasetID string) (*policycandidate.PolicyEvaluationDataset, error) {
	if err := s.ensurePolicyEvaluationDatasetTables(ctx); err != nil {
		return nil, err
	}
	return getPolicyEvaluationDatasetTx(ctx, s.db, tenantID, datasetID, false)
}

func (s *Store) ListPolicyEvaluationDatasets(ctx context.Context, request policycandidate.ListPolicyEvaluationDatasetsRequest) ([]*policycandidate.PolicyEvaluationDataset, error) {
	if err := s.ensurePolicyEvaluationDatasetTables(ctx); err != nil {
		return nil, err
	}
	query, args := `SELECT record, create_request_hash FROM policy_evaluation_datasets WHERE tenant_id=$1`, []any{request.TenantID}
	if request.CandidateID != "" {
		args = append(args, request.CandidateID)
		// #nosec G202 -- the suffix is fixed SQL and the value is parameterized.
		query += fmt.Sprintf(" AND candidate_id=$%d", len(args))
	}
	args = append(args, request.Limit)
	// #nosec G202 -- the suffix is fixed SQL and the limit remains parameterized.
	query += fmt.Sprintf(" ORDER BY updated_at DESC, id LIMIT $%d", len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list policy evaluation datasets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*policycandidate.PolicyEvaluationDataset
	for rows.Next() {
		var record []byte
		var requestHash string
		if err := rows.Scan(&record, &requestHash); err != nil {
			return nil, fmt.Errorf("scan policy evaluation dataset: %w", err)
		}
		dataset, err := decodePolicyEvaluationDataset(record, requestHash)
		if err != nil {
			return nil, err
		}
		out = append(out, dataset)
	}
	return out, rows.Err()
}

func (s *Store) GetPolicyEvaluationDatasetRevision(ctx context.Context, request policycandidate.GetPolicyEvaluationDatasetRevisionRequest) (*policycandidate.PolicyEvaluationDatasetRevision, error) {
	if err := s.ensurePolicyEvaluationDatasetTables(ctx); err != nil {
		return nil, err
	}
	var record []byte
	var requestHash string
	err := s.db.QueryRowContext(ctx, `SELECT record, request_hash FROM policy_evaluation_dataset_revisions WHERE tenant_id=$1 AND dataset_id=$2 AND id=$3`, request.TenantID, request.DatasetID, request.RevisionID).Scan(&record, &requestHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, policycandidate.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get policy evaluation dataset revision: %w", err)
	}
	return decodePolicyEvaluationDatasetRevision(record, requestHash)
}

func (s *Store) GetPolicyEvaluationDatasetRevisionSnapshot(ctx context.Context, request policycandidate.GetPolicyEvaluationDatasetRevisionRequest) (*policycandidate.PolicyEvaluationDatasetRevisionSnapshot, error) {
	if err := s.ensurePolicyEvaluationDatasetTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT r.record, r.request_hash, c.record
		FROM policy_evaluation_dataset_revisions r
		JOIN policy_evaluation_dataset_cases c ON c.tenant_id=r.tenant_id AND c.dataset_id=r.dataset_id AND c.revision_id=r.id
		WHERE r.tenant_id=$1 AND r.dataset_id=$2 AND r.id=$3 ORDER BY c.ordinal ASC`, request.TenantID, request.DatasetID, request.RevisionID)
	if err != nil {
		return nil, fmt.Errorf("load policy evaluation dataset revision snapshot: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var snapshot policycandidate.PolicyEvaluationDatasetRevisionSnapshot
	for rows.Next() {
		var revisionRecord, caseRecord []byte
		var requestHash string
		if err := rows.Scan(&revisionRecord, &requestHash, &caseRecord); err != nil {
			return nil, fmt.Errorf("scan policy evaluation dataset revision snapshot: %w", err)
		}
		if snapshot.Revision == nil {
			revision, err := decodePolicyEvaluationDatasetRevision(revisionRecord, requestHash)
			if err != nil {
				return nil, err
			}
			snapshot.Revision = revision
		}
		var testCase policycandidate.PolicyEvaluationDatasetCase
		if err := json.Unmarshal(caseRecord, &testCase); err != nil {
			return nil, fmt.Errorf("decode policy evaluation dataset snapshot case: %w", err)
		}
		snapshot.Cases = append(snapshot.Cases, &testCase)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy evaluation dataset revision snapshot: %w", err)
	}
	if snapshot.Revision == nil {
		return nil, policycandidate.ErrNotFound
	}
	if len(snapshot.Cases) != snapshot.Revision.CaseCount {
		return nil, fmt.Errorf("%w: policy evaluation dataset snapshot case count mismatch", policycandidate.ErrConflict)
	}
	return &snapshot, nil
}

func (s *Store) ListPolicyEvaluationDatasetRevisions(ctx context.Context, request policycandidate.ListPolicyEvaluationDatasetRevisionsRequest) ([]*policycandidate.PolicyEvaluationDatasetRevision, error) {
	if err := s.ensurePolicyEvaluationDatasetTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT record, request_hash FROM policy_evaluation_dataset_revisions WHERE tenant_id=$1 AND dataset_id=$2 ORDER BY version ASC LIMIT $3`, request.TenantID, request.DatasetID, request.Limit)
	if err != nil {
		return nil, fmt.Errorf("list policy evaluation dataset revisions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*policycandidate.PolicyEvaluationDatasetRevision
	for rows.Next() {
		var record []byte
		var requestHash string
		if err := rows.Scan(&record, &requestHash); err != nil {
			return nil, fmt.Errorf("scan policy evaluation dataset revision: %w", err)
		}
		revision, err := decodePolicyEvaluationDatasetRevision(record, requestHash)
		if err != nil {
			return nil, err
		}
		out = append(out, revision)
	}
	return out, rows.Err()
}

func (s *Store) ListPolicyEvaluationDatasetCases(ctx context.Context, request policycandidate.ListPolicyEvaluationDatasetCasesRequest) ([]*policycandidate.PolicyEvaluationDatasetCase, error) {
	if err := s.ensurePolicyEvaluationDatasetTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT record FROM policy_evaluation_dataset_cases WHERE tenant_id=$1 AND dataset_id=$2 AND revision_id=$3 ORDER BY ordinal ASC`, request.TenantID, request.DatasetID, request.RevisionID)
	if err != nil {
		return nil, fmt.Errorf("list policy evaluation dataset cases: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*policycandidate.PolicyEvaluationDatasetCase
	for rows.Next() {
		var record []byte
		if err := rows.Scan(&record); err != nil {
			return nil, fmt.Errorf("scan policy evaluation dataset case: %w", err)
		}
		var testCase policycandidate.PolicyEvaluationDatasetCase
		if err := json.Unmarshal(record, &testCase); err != nil {
			return nil, fmt.Errorf("decode policy evaluation dataset case: %w", err)
		}
		out = append(out, &testCase)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy evaluation dataset cases: %w", err)
	}
	if len(out) == 0 {
		var exists bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM policy_evaluation_dataset_revisions WHERE tenant_id=$1 AND dataset_id=$2 AND id=$3)`, request.TenantID, request.DatasetID, request.RevisionID).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check policy evaluation dataset revision: %w", err)
		}
		if !exists {
			return nil, policycandidate.ErrNotFound
		}
	}
	return out, nil
}

type policyEvaluationDatasetQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func getPolicyEvaluationDatasetTx(ctx context.Context, query policyEvaluationDatasetQuery, tenantID, datasetID string, lock bool) (*policycandidate.PolicyEvaluationDataset, error) {
	statement := `SELECT record, create_request_hash FROM policy_evaluation_datasets WHERE tenant_id=$1 AND id=$2`
	if lock {
		statement += ` FOR UPDATE`
	}
	var record []byte
	var requestHash string
	if err := query.QueryRowContext(ctx, statement, strings.TrimSpace(tenantID), strings.TrimSpace(datasetID)).Scan(&record, &requestHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, policycandidate.ErrNotFound
		}
		return nil, fmt.Errorf("get policy evaluation dataset: %w", err)
	}
	return decodePolicyEvaluationDataset(record, requestHash)
}

func getPolicyEvaluationDatasetByCreateKey(ctx context.Context, tx *sql.Tx, tenantID, candidateID, key string) (*policycandidate.PolicyEvaluationDataset, *policycandidate.PolicyEvaluationDatasetRevision, error) {
	var record []byte
	var requestHash string
	if err := tx.QueryRowContext(ctx, `SELECT record, create_request_hash FROM policy_evaluation_datasets WHERE tenant_id=$1 AND candidate_id=$2 AND idempotency_key=$3`, tenantID, candidateID, key).Scan(&record, &requestHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, policycandidate.ErrNotFound
		}
		return nil, nil, fmt.Errorf("get policy evaluation dataset create replay: %w", err)
	}
	dataset, err := decodePolicyEvaluationDataset(record, requestHash)
	if err != nil {
		return nil, nil, err
	}
	var revisionRecord []byte
	var revisionHash string
	if err := tx.QueryRowContext(ctx, `SELECT record, request_hash FROM policy_evaluation_dataset_revisions WHERE tenant_id=$1 AND dataset_id=$2 AND version=1`, tenantID, dataset.ID).Scan(&revisionRecord, &revisionHash); err != nil {
		return nil, nil, fmt.Errorf("get initial policy evaluation dataset revision: %w", err)
	}
	revision, err := decodePolicyEvaluationDatasetRevision(revisionRecord, revisionHash)
	return dataset, revision, err
}

func getPolicyEvaluationDatasetRevisionByKey(ctx context.Context, tx *sql.Tx, tenantID, datasetID, key string) (*policycandidate.PolicyEvaluationDatasetRevision, error) {
	var record []byte
	var requestHash string
	err := tx.QueryRowContext(ctx, `SELECT record, request_hash FROM policy_evaluation_dataset_revisions WHERE tenant_id=$1 AND dataset_id=$2 AND idempotency_key=$3`, tenantID, datasetID, key).Scan(&record, &requestHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, policycandidate.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get policy evaluation dataset revision replay: %w", err)
	}
	return decodePolicyEvaluationDatasetRevision(record, requestHash)
}

func insertPolicyEvaluationDatasetRevision(ctx context.Context, tx *sql.Tx, revision *policycandidate.PolicyEvaluationDatasetRevision, cases []*policycandidate.PolicyEvaluationDatasetCase, key string) error {
	record, err := json.Marshal(revision)
	if err != nil {
		return fmt.Errorf("encode policy evaluation dataset revision: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_evaluation_dataset_revisions
		(id,tenant_id,dataset_id,version,predecessor_id,policy_digest,source_test_digest,content_digest,case_count,change_summary,created_by,idempotency_key,request_hash,record,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, revision.ID, revision.TenantID, revision.DatasetID,
		revision.Version, revision.PredecessorID, revision.PolicyDigest, revision.SourceTestDigest, revision.ContentDigest, revision.CaseCount,
		revision.ChangeSummary, revision.CreatedBy, key, revision.RequestHash, record, revision.CreatedAt); err != nil {
		return fmt.Errorf("create policy evaluation dataset revision: %w", err)
	}
	for _, testCase := range cases {
		caseRecord, err := json.Marshal(testCase)
		if err != nil {
			return fmt.Errorf("encode policy evaluation dataset case: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_evaluation_dataset_cases (tenant_id,dataset_id,revision_id,case_id,ordinal,content_digest,record) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			revision.TenantID, testCase.DatasetID, testCase.RevisionID, testCase.ID, testCase.Ordinal, testCase.ContentDigest, caseRecord); err != nil {
			return fmt.Errorf("create policy evaluation dataset case: %w", err)
		}
	}
	return nil
}

func validatePolicyEvaluationDatasetCreate(command policycandidate.CreatePolicyEvaluationDatasetRecord) error {
	if command.Dataset == nil || command.Revision == nil || command.IdempotencyKey == "" || command.Dataset.AggregateVersion != 1 || command.Revision.Version != 1 ||
		command.Dataset.ID == "" || command.Dataset.TenantID == "" || command.Dataset.CandidateID == "" || command.Dataset.CurrentRevisionID != command.Revision.ID ||
		command.Revision.DatasetID != command.Dataset.ID || command.Revision.TenantID != command.Dataset.TenantID || command.Revision.RequestHash == "" ||
		command.Dataset.CreateRequestHash == "" || command.Revision.CaseCount != len(command.Cases) || len(command.Cases) == 0 {
		return fmt.Errorf("%w: complete policy evaluation dataset create record is required", policycandidate.ErrInvalidRequest)
	}
	return validatePolicyEvaluationDatasetCases(command.Dataset, command.Revision, command.Cases)
}

func validatePolicyEvaluationDatasetAppend(command policycandidate.AppendPolicyEvaluationDatasetRevisionRecord) error {
	if command.Dataset == nil || command.Revision == nil || command.IdempotencyKey == "" || command.ExpectedVersion == 0 ||
		command.Dataset.ID == "" || command.Dataset.TenantID == "" || command.Dataset.CandidateID == "" || command.Dataset.CurrentRevisionID != command.Revision.ID ||
		command.Revision.DatasetID != command.Dataset.ID || command.Revision.TenantID != command.Dataset.TenantID || command.Revision.RequestHash == "" ||
		command.Revision.CaseCount != len(command.Cases) || len(command.Cases) == 0 {
		return fmt.Errorf("%w: complete policy evaluation dataset append record is required", policycandidate.ErrInvalidRequest)
	}
	return validatePolicyEvaluationDatasetCases(command.Dataset, command.Revision, command.Cases)
}

func validatePolicyEvaluationDatasetCases(dataset *policycandidate.PolicyEvaluationDataset, revision *policycandidate.PolicyEvaluationDatasetRevision, cases []*policycandidate.PolicyEvaluationDatasetCase) error {
	seenIDs, seenOrdinals := map[string]struct{}{}, map[int]struct{}{}
	for ordinal, testCase := range cases {
		if testCase == nil || testCase.ID == "" || testCase.DatasetID != dataset.ID || testCase.RevisionID != revision.ID || testCase.ContentDigest == "" {
			return fmt.Errorf("%w: complete policy evaluation dataset cases are required", policycandidate.ErrInvalidRequest)
		}
		if testCase.Ordinal != ordinal {
			return fmt.Errorf("%w: policy evaluation dataset case ordinals must be contiguous", policycandidate.ErrInvalidRequest)
		}
		if _, ok := seenIDs[testCase.ID]; ok {
			return fmt.Errorf("%w: duplicate policy evaluation dataset case id", policycandidate.ErrInvalidRequest)
		}
		if _, ok := seenOrdinals[testCase.Ordinal]; ok || testCase.Ordinal < 0 {
			return fmt.Errorf("%w: duplicate policy evaluation dataset case ordinal", policycandidate.ErrInvalidRequest)
		}
		seenIDs[testCase.ID], seenOrdinals[testCase.Ordinal] = struct{}{}, struct{}{}
	}
	return nil
}

func decodePolicyEvaluationDataset(record []byte, requestHash string) (*policycandidate.PolicyEvaluationDataset, error) {
	var dataset policycandidate.PolicyEvaluationDataset
	if err := json.Unmarshal(record, &dataset); err != nil {
		return nil, fmt.Errorf("decode policy evaluation dataset: %w", err)
	}
	dataset.CreateRequestHash = requestHash
	return &dataset, nil
}

func decodePolicyEvaluationDatasetRevision(record []byte, requestHash string) (*policycandidate.PolicyEvaluationDatasetRevision, error) {
	var revision policycandidate.PolicyEvaluationDatasetRevision
	if err := json.Unmarshal(record, &revision); err != nil {
		return nil, fmt.Errorf("decode policy evaluation dataset revision: %w", err)
	}
	revision.RequestHash = requestHash
	return &revision, nil
}

func clonePolicyEvaluationDataset(dataset *policycandidate.PolicyEvaluationDataset) *policycandidate.PolicyEvaluationDataset {
	cloned := *dataset
	return &cloned
}

func clonePolicyEvaluationDatasetRevision(revision *policycandidate.PolicyEvaluationDatasetRevision) *policycandidate.PolicyEvaluationDatasetRevision {
	cloned := *revision
	return &cloned
}
