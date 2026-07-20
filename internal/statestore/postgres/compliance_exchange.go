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
	"time"

	"github.com/writer/cerebro/internal/complianceexchange"
)

var ensureComplianceExchangeStatements = []string{
	`CREATE TABLE IF NOT EXISTS compliance_exchange_staged_packages (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  package_id TEXT NOT NULL,
  manifest_digest TEXT NOT NULL,
  package_digest TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  manifest_bytes BYTEA NOT NULL,
  signature TEXT NOT NULL,
  file_count INTEGER NOT NULL,
  total_bytes BIGINT NOT NULL,
  staged_bytes BIGINT NOT NULL,
  status TEXT NOT NULL,
  version BIGINT NOT NULL,
  latest_validation_request_digest TEXT NOT NULL DEFAULT '',
  change_plan_digest TEXT NOT NULL DEFAULT '',
  signer_key_id TEXT NOT NULL DEFAULT '',
  algorithm TEXT NOT NULL DEFAULT '',
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  validated_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, idempotency_key)
)`,
	`CREATE TABLE IF NOT EXISTS compliance_exchange_staged_files (
  tenant_id TEXT NOT NULL,
  staging_id TEXT NOT NULL,
  file_ordinal INTEGER NOT NULL,
  path TEXT NOT NULL,
  media_type TEXT NOT NULL,
  logical_type TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  content BYTEA NOT NULL,
  PRIMARY KEY (tenant_id, staging_id, file_ordinal),
  FOREIGN KEY (tenant_id, staging_id)
    REFERENCES compliance_exchange_staged_packages (tenant_id, id) ON DELETE CASCADE
)`,
	`CREATE TABLE IF NOT EXISTS compliance_exchange_validations (
  tenant_id TEXT NOT NULL,
  staging_id TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  staging_version BIGINT NOT NULL,
  status TEXT NOT NULL,
  validation_result_json JSONB NOT NULL,
  signature_receipt_json JSONB,
  change_plan_digest TEXT NOT NULL DEFAULT '',
  validated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, staging_id, request_digest),
  FOREIGN KEY (tenant_id, staging_id)
    REFERENCES compliance_exchange_staged_packages (tenant_id, id) ON DELETE CASCADE
)`,
	`CREATE TABLE IF NOT EXISTS compliance_exchange_commit_intents (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  staging_id TEXT NOT NULL,
  expected_staging_version BIGINT NOT NULL,
  change_plan_digest TEXT NOT NULL,
  intent_digest TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  required_scope TEXT NOT NULL,
  status TEXT NOT NULL,
  version BIGINT NOT NULL,
  requested_by TEXT NOT NULL,
  authorized_by TEXT NOT NULL DEFAULT '',
  authorization_decision_id TEXT NOT NULL DEFAULT '',
  authorized_at TIMESTAMPTZ,
  event_id TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, staging_id)
    REFERENCES compliance_exchange_staged_packages (tenant_id, id) ON DELETE CASCADE
)`,
	`CREATE INDEX IF NOT EXISTS compliance_exchange_staged_packages_tenant_status_expiry_idx
  ON compliance_exchange_staged_packages (tenant_id, status, expires_at)`,
	`CREATE INDEX IF NOT EXISTS compliance_exchange_commit_intents_tenant_stage_status_idx
  ON compliance_exchange_commit_intents (tenant_id, staging_id, status, updated_at DESC)`,
}

var _ complianceexchange.StagingStore = (*Store)(nil)

func (s *Store) ensureComplianceExchangeTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.complianceExchange, "compliance exchange staging", ensureComplianceExchangeStatements)
}

func (s *Store) PutStagedPackage(ctx context.Context, stage complianceexchange.StagedPackage) (complianceexchange.StagedPackage, bool, error) {
	if s == nil || s.db == nil {
		return complianceexchange.StagedPackage{}, false, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceExchangeTables(ctx); err != nil {
		return complianceexchange.StagedPackage{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return complianceexchange.StagedPackage{}, false, fmt.Errorf("begin compliance exchange staging: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var insertedID string
	err = tx.QueryRowContext(ctx, `
INSERT INTO compliance_exchange_staged_packages (
  tenant_id, id, package_id, manifest_digest, package_digest, idempotency_key,
  manifest_bytes, signature, file_count, total_bytes, staged_bytes, status,
  version, expires_at, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
RETURNING id`, stage.TenantID, stage.ID, stage.PackageID, stage.ManifestDigest,
		stage.PackageDigest, stage.IdempotencyKey, stage.ManifestBytes, stage.Signature,
		stage.FileCount, stage.TotalBytes, stage.StagedBytes, stage.Status, stage.Version,
		stage.ExpiresAt, stage.CreatedAt, stage.UpdatedAt).Scan(&insertedID)
	created := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return complianceexchange.StagedPackage{}, false, fmt.Errorf("insert compliance exchange staged package: %w", err)
	}
	if !created {
		var existingID, existingDigest string
		if err := tx.QueryRowContext(ctx, `
SELECT id, package_digest
FROM compliance_exchange_staged_packages
WHERE tenant_id = $1 AND idempotency_key = $2`, stage.TenantID, stage.IdempotencyKey).Scan(&existingID, &existingDigest); err != nil {
			return complianceexchange.StagedPackage{}, false, fmt.Errorf("load compliance exchange staging replay: %w", err)
		}
		if existingDigest != stage.PackageDigest {
			return complianceexchange.StagedPackage{}, false, complianceexchange.ErrStagingDigest
		}
		insertedID = existingID
	} else {
		for index, file := range stage.Files {
			digest := sha256.Sum256(file.Data)
			if _, err := tx.ExecContext(ctx, `
INSERT INTO compliance_exchange_staged_files (
  tenant_id, staging_id, file_ordinal, path, media_type, logical_type, sha256, size_bytes, content
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, stage.TenantID, stage.ID, index, file.Path, file.MediaType,
				file.LogicalType, hex.EncodeToString(digest[:]), len(file.Data), file.Data); err != nil {
				return complianceexchange.StagedPackage{}, false, fmt.Errorf("insert compliance exchange staged file: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return complianceexchange.StagedPackage{}, false, fmt.Errorf("commit compliance exchange staging: %w", err)
	}
	stored, err := s.GetStagedPackage(ctx, stage.TenantID, insertedID)
	return stored, created, err
}

func (s *Store) GetStagedPackage(ctx context.Context, tenantID string, stagingID string) (complianceexchange.StagedPackage, error) {
	if s == nil || s.db == nil {
		return complianceexchange.StagedPackage{}, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceExchangeTables(ctx); err != nil {
		return complianceexchange.StagedPackage{}, err
	}
	stage, err := scanComplianceExchangeStagedPackage(s.db.QueryRowContext(ctx, stagedPackageSelect+`
WHERE tenant_id = $1 AND id = $2`, strings.TrimSpace(tenantID), strings.TrimSpace(stagingID)))
	if err != nil {
		return complianceexchange.StagedPackage{}, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT path, media_type, logical_type, content
FROM compliance_exchange_staged_files
WHERE tenant_id = $1 AND staging_id = $2
ORDER BY file_ordinal ASC`, stage.TenantID, stage.ID)
	if err != nil {
		return complianceexchange.StagedPackage{}, fmt.Errorf("list compliance exchange staged files: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var file complianceexchange.File
		if err := rows.Scan(&file.Path, &file.MediaType, &file.LogicalType, &file.Data); err != nil {
			return complianceexchange.StagedPackage{}, fmt.Errorf("scan compliance exchange staged file: %w", err)
		}
		stage.Files = append(stage.Files, file)
	}
	if err := rows.Err(); err != nil {
		return complianceexchange.StagedPackage{}, fmt.Errorf("list compliance exchange staged files: %w", err)
	}
	return stage, nil
}

func (s *Store) GetStagedValidation(ctx context.Context, tenantID string, stagingID string, requestDigest string) (complianceexchange.StagedValidation, error) {
	if s == nil || s.db == nil {
		return complianceexchange.StagedValidation{}, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceExchangeTables(ctx); err != nil {
		return complianceexchange.StagedValidation{}, err
	}
	return scanComplianceExchangeValidation(s.db.QueryRowContext(ctx, `
SELECT tenant_id, staging_id, request_digest, staging_version, status,
       validation_result_json::text, signature_receipt_json::text,
       change_plan_digest, validated_at
FROM compliance_exchange_validations
WHERE tenant_id = $1 AND staging_id = $2 AND request_digest = $3`,
		strings.TrimSpace(tenantID), strings.TrimSpace(stagingID), strings.TrimSpace(requestDigest)))
}

func (s *Store) PutStagedValidation(ctx context.Context, record complianceexchange.StagedValidation, expectedVersion uint64) (complianceexchange.StagedValidation, bool, error) {
	if s == nil || s.db == nil {
		return complianceexchange.StagedValidation{}, false, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceExchangeTables(ctx); err != nil {
		return complianceexchange.StagedValidation{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return complianceexchange.StagedValidation{}, false, fmt.Errorf("begin compliance exchange validation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var stageVersion uint64
	var expiresAt time.Time
	if err := tx.QueryRowContext(ctx, `
SELECT version, expires_at
FROM compliance_exchange_staged_packages
WHERE tenant_id = $1 AND id = $2
FOR UPDATE`, record.TenantID, record.StagingID).Scan(&stageVersion, &expiresAt); err != nil {
		return complianceexchange.StagedValidation{}, false, mapComplianceExchangeStageError(err)
	}
	prior, err := scanComplianceExchangeValidation(tx.QueryRowContext(ctx, `
SELECT tenant_id, staging_id, request_digest, staging_version, status,
       validation_result_json::text, signature_receipt_json::text,
       change_plan_digest, validated_at
FROM compliance_exchange_validations
WHERE tenant_id = $1 AND staging_id = $2 AND request_digest = $3`, record.TenantID, record.StagingID, record.RequestDigest))
	if err == nil {
		if err := tx.Commit(); err != nil {
			return complianceexchange.StagedValidation{}, false, fmt.Errorf("commit compliance exchange validation replay: %w", err)
		}
		return prior, true, nil
	}
	if !errors.Is(err, complianceexchange.ErrValidationNotFound) {
		return complianceexchange.StagedValidation{}, false, err
	}
	if !expiresAt.After(time.Now().UTC()) {
		return complianceexchange.StagedValidation{}, false, complianceexchange.ErrStagingExpired
	}
	if stageVersion != expectedVersion {
		return complianceexchange.StagedValidation{}, false, complianceexchange.ErrStagingVersion
	}
	record.StagingVersion = expectedVersion + 1
	resultJSON, err := json.Marshal(record.Result)
	if err != nil {
		return complianceexchange.StagedValidation{}, false, fmt.Errorf("marshal compliance exchange validation: %w", err)
	}
	var signatureJSON any
	if record.Signature != nil {
		content, marshalErr := json.Marshal(record.Signature)
		if marshalErr != nil {
			return complianceexchange.StagedValidation{}, false, fmt.Errorf("marshal compliance exchange signature receipt: %w", marshalErr)
		}
		signatureJSON = string(content)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO compliance_exchange_validations (
  tenant_id, staging_id, request_digest, staging_version, status,
  validation_result_json, signature_receipt_json, change_plan_digest, validated_at
)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9)`, record.TenantID, record.StagingID, record.RequestDigest,
		record.StagingVersion, record.Status, string(resultJSON), signatureJSON,
		record.ChangePlanDigest, record.ValidatedAt); err != nil {
		return complianceexchange.StagedValidation{}, false, fmt.Errorf("insert compliance exchange validation: %w", err)
	}
	signerKeyID, algorithm := "", ""
	if record.Signature != nil {
		signerKeyID, algorithm = record.Signature.SignerKeyID, record.Signature.Algorithm
	}
	result, err := tx.ExecContext(ctx, `
UPDATE compliance_exchange_staged_packages
SET status = $1, version = version + 1,
    latest_validation_request_digest = $2, change_plan_digest = $3,
    signer_key_id = $4, algorithm = $5, validated_at = $6, updated_at = $6
WHERE tenant_id = $7 AND id = $8 AND version = $9`, record.Status, record.RequestDigest,
		record.ChangePlanDigest, signerKeyID, algorithm, record.ValidatedAt,
		record.TenantID, record.StagingID, expectedVersion)
	if err != nil {
		return complianceexchange.StagedValidation{}, false, fmt.Errorf("advance compliance exchange staging validation: %w", err)
	}
	if err := requireOneComplianceExchangeRow(result); err != nil {
		return complianceexchange.StagedValidation{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return complianceexchange.StagedValidation{}, false, fmt.Errorf("commit compliance exchange validation: %w", err)
	}
	return record, false, nil
}

func (s *Store) PutCommitIntent(ctx context.Context, intent complianceexchange.CommitIntent) (complianceexchange.CommitIntent, bool, error) {
	if s == nil || s.db == nil {
		return complianceexchange.CommitIntent{}, false, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceExchangeTables(ctx); err != nil {
		return complianceexchange.CommitIntent{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return complianceexchange.CommitIntent{}, false, fmt.Errorf("begin compliance exchange commit intent: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var stageVersion uint64
	var stageStatus, planDigest string
	var expiresAt time.Time
	if err := tx.QueryRowContext(ctx, `
SELECT version, status, change_plan_digest, expires_at
FROM compliance_exchange_staged_packages
WHERE tenant_id = $1 AND id = $2
FOR UPDATE`, intent.TenantID, intent.StagingID).Scan(&stageVersion, &stageStatus, &planDigest, &expiresAt); err != nil {
		return complianceexchange.CommitIntent{}, false, mapComplianceExchangeStageError(err)
	}
	if !expiresAt.After(time.Now().UTC()) {
		return complianceexchange.CommitIntent{}, false, complianceexchange.ErrStagingExpired
	}
	if stageVersion != intent.ExpectedStagingVersion {
		return complianceexchange.CommitIntent{}, false, complianceexchange.ErrStagingVersion
	}
	if stageStatus != complianceexchange.StagingStatusValid || planDigest != intent.ChangePlanDigest {
		return complianceexchange.CommitIntent{}, false, complianceexchange.ErrStagingDigest
	}
	var insertedID string
	err = tx.QueryRowContext(ctx, `
INSERT INTO compliance_exchange_commit_intents (
  tenant_id, id, staging_id, expected_staging_version, change_plan_digest,
  intent_digest, idempotency_key, required_scope, status, version,
  requested_by, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
RETURNING id`, intent.TenantID, intent.ID, intent.StagingID, intent.ExpectedStagingVersion,
		intent.ChangePlanDigest, intent.IntentDigest, intent.IdempotencyKey,
		intent.RequiredScope, intent.Status, intent.Version, intent.RequestedBy,
		intent.CreatedAt, intent.UpdatedAt).Scan(&insertedID)
	created := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return complianceexchange.CommitIntent{}, false, fmt.Errorf("insert compliance exchange commit intent: %w", err)
	}
	if !created {
		var existingDigest string
		if err := tx.QueryRowContext(ctx, `
SELECT id, intent_digest
FROM compliance_exchange_commit_intents
WHERE tenant_id = $1 AND idempotency_key = $2`, intent.TenantID, intent.IdempotencyKey).Scan(&insertedID, &existingDigest); err != nil {
			return complianceexchange.CommitIntent{}, false, fmt.Errorf("load compliance exchange intent replay: %w", err)
		}
		if existingDigest != intent.IntentDigest {
			return complianceexchange.CommitIntent{}, false, complianceexchange.ErrStagingDigest
		}
	}
	stored, err := scanComplianceExchangeCommitIntent(tx.QueryRowContext(ctx, commitIntentSelect+`
WHERE tenant_id = $1 AND id = $2`, intent.TenantID, insertedID))
	if err != nil {
		return complianceexchange.CommitIntent{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return complianceexchange.CommitIntent{}, false, fmt.Errorf("commit compliance exchange commit intent: %w", err)
	}
	return stored, created, nil
}

func (s *Store) GetCommitIntent(ctx context.Context, tenantID string, intentID string) (complianceexchange.CommitIntent, error) {
	if s == nil || s.db == nil {
		return complianceexchange.CommitIntent{}, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceExchangeTables(ctx); err != nil {
		return complianceexchange.CommitIntent{}, err
	}
	return scanComplianceExchangeCommitIntent(s.db.QueryRowContext(ctx, commitIntentSelect+`
WHERE tenant_id = $1 AND id = $2`, strings.TrimSpace(tenantID), strings.TrimSpace(intentID)))
}

func (s *Store) MarkCommitIntentEventAppended(ctx context.Context, intent complianceexchange.CommitIntent, auth complianceexchange.AuthorizationReceipt, eventID string) (complianceexchange.CommitIntent, error) {
	if s == nil || s.db == nil {
		return complianceexchange.CommitIntent{}, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceExchangeTables(ctx); err != nil {
		return complianceexchange.CommitIntent{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return complianceexchange.CommitIntent{}, fmt.Errorf("begin compliance exchange append transition: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := scanComplianceExchangeCommitIntent(tx.QueryRowContext(ctx, commitIntentSelect+`
WHERE tenant_id = $1 AND id = $2
FOR UPDATE`, intent.TenantID, intent.ID))
	if err != nil {
		return complianceexchange.CommitIntent{}, err
	}
	if current.Status == complianceexchange.CommitIntentEventAppended {
		if current.EventID != eventID {
			return complianceexchange.CommitIntent{}, complianceexchange.ErrStagingDigest
		}
		if err := tx.Commit(); err != nil {
			return complianceexchange.CommitIntent{}, fmt.Errorf("commit compliance exchange append replay: %w", err)
		}
		return current, nil
	}
	if current.Version != intent.Version || current.ExpectedStagingVersion != intent.ExpectedStagingVersion {
		return complianceexchange.CommitIntent{}, complianceexchange.ErrStagingVersion
	}
	if strings.TrimSpace(eventID) == "" || strings.TrimSpace(auth.ActorID) == "" ||
		strings.TrimSpace(auth.DecisionID) == "" || auth.Scope != current.RequiredScope || auth.GrantedAt.IsZero() {
		return complianceexchange.CommitIntent{}, complianceexchange.ErrCommitAuthorization
	}
	var stageVersion uint64
	if err := tx.QueryRowContext(ctx, `
SELECT version
FROM compliance_exchange_staged_packages
WHERE tenant_id = $1 AND id = $2
FOR UPDATE`, current.TenantID, current.StagingID).Scan(&stageVersion); err != nil {
		return complianceexchange.CommitIntent{}, mapComplianceExchangeStageError(err)
	}
	if stageVersion != current.ExpectedStagingVersion {
		return complianceexchange.CommitIntent{}, complianceexchange.ErrStagingVersion
	}
	result, err := tx.ExecContext(ctx, `
UPDATE compliance_exchange_commit_intents
SET status = $1, version = version + 1, authorized_by = $2,
    authorization_decision_id = $3, authorized_at = $4, event_id = $5, updated_at = $4
WHERE tenant_id = $6 AND id = $7 AND version = $8`, complianceexchange.CommitIntentEventAppended,
		auth.ActorID, auth.DecisionID, auth.GrantedAt, eventID, current.TenantID, current.ID, current.Version)
	if err != nil {
		return complianceexchange.CommitIntent{}, fmt.Errorf("mark compliance exchange commit event appended: %w", err)
	}
	if err := requireOneComplianceExchangeRow(result); err != nil {
		return complianceexchange.CommitIntent{}, err
	}
	result, err = tx.ExecContext(ctx, `
UPDATE compliance_exchange_staged_packages
SET status = $1, version = version + 1, updated_at = $2
WHERE tenant_id = $3 AND id = $4 AND version = $5`, complianceexchange.StagingStatusCommitEventAppended,
		auth.GrantedAt, current.TenantID, current.StagingID, current.ExpectedStagingVersion)
	if err != nil {
		return complianceexchange.CommitIntent{}, fmt.Errorf("advance compliance exchange staging after append: %w", err)
	}
	if err := requireOneComplianceExchangeRow(result); err != nil {
		return complianceexchange.CommitIntent{}, err
	}
	current.Status = complianceexchange.CommitIntentEventAppended
	current.Version++
	current.AuthorizedBy = auth.ActorID
	current.AuthorizationDecisionID = auth.DecisionID
	current.AuthorizedAt = auth.GrantedAt
	current.EventID = eventID
	current.UpdatedAt = auth.GrantedAt
	if err := tx.Commit(); err != nil {
		return complianceexchange.CommitIntent{}, fmt.Errorf("commit compliance exchange append transition: %w", err)
	}
	return current, nil
}

const stagedPackageSelect = `
SELECT id, tenant_id, package_id, manifest_digest, package_digest, idempotency_key,
       manifest_bytes, signature, file_count, total_bytes, staged_bytes, status,
       version, latest_validation_request_digest, change_plan_digest,
       signer_key_id, algorithm, expires_at, created_at, updated_at, validated_at
FROM compliance_exchange_staged_packages`

func scanComplianceExchangeStagedPackage(row scanner) (complianceexchange.StagedPackage, error) {
	var stage complianceexchange.StagedPackage
	var validatedAt sql.NullTime
	if err := row.Scan(&stage.ID, &stage.TenantID, &stage.PackageID, &stage.ManifestDigest,
		&stage.PackageDigest, &stage.IdempotencyKey, &stage.ManifestBytes, &stage.Signature,
		&stage.FileCount, &stage.TotalBytes, &stage.StagedBytes, &stage.Status, &stage.Version,
		&stage.LatestValidationRequestDigest, &stage.ChangePlanDigest, &stage.SignerKeyID,
		&stage.Algorithm, &stage.ExpiresAt, &stage.CreatedAt, &stage.UpdatedAt, &validatedAt); err != nil {
		return complianceexchange.StagedPackage{}, mapComplianceExchangeStageError(err)
	}
	if validatedAt.Valid {
		stage.ValidatedAt = validatedAt.Time
	}
	return stage, nil
}

func scanComplianceExchangeValidation(row scanner) (complianceexchange.StagedValidation, error) {
	var record complianceexchange.StagedValidation
	var resultJSON string
	var signatureJSON sql.NullString
	if err := row.Scan(&record.TenantID, &record.StagingID, &record.RequestDigest,
		&record.StagingVersion, &record.Status, &resultJSON, &signatureJSON,
		&record.ChangePlanDigest, &record.ValidatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return complianceexchange.StagedValidation{}, complianceexchange.ErrValidationNotFound
		}
		return complianceexchange.StagedValidation{}, fmt.Errorf("scan compliance exchange validation: %w", err)
	}
	if err := json.Unmarshal([]byte(resultJSON), &record.Result); err != nil {
		return complianceexchange.StagedValidation{}, fmt.Errorf("decode compliance exchange validation: %w", err)
	}
	if signatureJSON.Valid {
		record.Signature = &complianceexchange.SignatureReceipt{}
		if err := json.Unmarshal([]byte(signatureJSON.String), record.Signature); err != nil {
			return complianceexchange.StagedValidation{}, fmt.Errorf("decode compliance exchange signature receipt: %w", err)
		}
	}
	return record, nil
}

const commitIntentSelect = `
SELECT id, tenant_id, staging_id, expected_staging_version, change_plan_digest,
       intent_digest, idempotency_key, required_scope, status, version,
       requested_by, authorized_by, authorization_decision_id, authorized_at,
       event_id, created_at, updated_at
FROM compliance_exchange_commit_intents`

func scanComplianceExchangeCommitIntent(row scanner) (complianceexchange.CommitIntent, error) {
	var intent complianceexchange.CommitIntent
	var authorizedAt sql.NullTime
	if err := row.Scan(&intent.ID, &intent.TenantID, &intent.StagingID,
		&intent.ExpectedStagingVersion, &intent.ChangePlanDigest, &intent.IntentDigest,
		&intent.IdempotencyKey, &intent.RequiredScope, &intent.Status, &intent.Version,
		&intent.RequestedBy, &intent.AuthorizedBy, &intent.AuthorizationDecisionID,
		&authorizedAt, &intent.EventID, &intent.CreatedAt, &intent.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return complianceexchange.CommitIntent{}, complianceexchange.ErrCommitIntentNotFound
		}
		return complianceexchange.CommitIntent{}, fmt.Errorf("scan compliance exchange commit intent: %w", err)
	}
	if authorizedAt.Valid {
		intent.AuthorizedAt = authorizedAt.Time
	}
	return intent, nil
}

func mapComplianceExchangeStageError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return complianceexchange.ErrStagingNotFound
	}
	return fmt.Errorf("load compliance exchange staging: %w", err)
}

func requireOneComplianceExchangeRow(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read compliance exchange transition result: %w", err)
	}
	if rows != 1 {
		return complianceexchange.ErrStagingVersion
	}
	return nil
}
