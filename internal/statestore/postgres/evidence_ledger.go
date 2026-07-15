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

	"github.com/writer/cerebro/internal/ports"
)

var ensureEvidenceLedgerStatements = []string{
	`CREATE TABLE IF NOT EXISTS grc_evidence_artifacts (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  record_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, id)
)`,
	`CREATE TABLE IF NOT EXISTS grc_evidence_versions (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  revision_version BIGINT NOT NULL,
  record_digest TEXT NOT NULL,
  content_digest TEXT NOT NULL,
  state TEXT NOT NULL,
  valid_until TIMESTAMPTZ,
  record_json JSONB NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, artifact_id, revision_version),
  UNIQUE (tenant_id, revision_id),
  FOREIGN KEY (tenant_id, artifact_id) REFERENCES grc_evidence_artifacts (tenant_id, id)
)`,
	`CREATE INDEX IF NOT EXISTS grc_evidence_versions_artifact_idx ON grc_evidence_versions (tenant_id, artifact_id, revision_version DESC)`,
	`CREATE INDEX IF NOT EXISTS grc_evidence_versions_expiry_idx ON grc_evidence_versions (tenant_id, valid_until) WHERE valid_until IS NOT NULL`,
	`CREATE TABLE IF NOT EXISTS grc_evidence_claims (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  artifact_version_id TEXT NOT NULL,
  aggregate_version BIGINT NOT NULL,
  review_state TEXT NOT NULL,
  invalidated_at TIMESTAMPTZ,
  record_digest TEXT NOT NULL,
  record_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, artifact_version_id) REFERENCES grc_evidence_versions (tenant_id, id)
)`,
	`CREATE INDEX IF NOT EXISTS grc_evidence_claims_version_idx ON grc_evidence_claims (tenant_id, artifact_version_id, id)`,
	`CREATE TABLE IF NOT EXISTS grc_evidence_event_receipts (
  event_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  aggregate_version BIGINT NOT NULL,
  payload_digest TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS grc_evidence_event_receipts_aggregate_idx ON grc_evidence_event_receipts (tenant_id, aggregate_type, aggregate_id, aggregate_version)`,
}

func (s *Store) ensureEvidenceLedgerTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.evidenceLedger, "grc_evidence_ledger", ensureEvidenceLedgerStatements)
}

func (s *Store) ApplyEvidenceVersion(ctx context.Context, eventID string, artifact ports.EvidenceArtifact, version ports.EvidenceVersion) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	eventID = strings.TrimSpace(eventID)
	if eventID == "" || artifact.TenantID == "" || artifact.ID == "" || version.ID == "" || version.ArtifactID != artifact.ID || version.TenantID != artifact.TenantID {
		return errors.New("evidence version event and tenant-scoped identity are required")
	}
	if err := s.ensureEvidenceLedgerTables(ctx); err != nil {
		return err
	}
	artifactJSON, err := json.Marshal(artifact)
	if err != nil {
		return fmt.Errorf("marshal evidence artifact: %w", err)
	}
	versionJSON, err := json.Marshal(version)
	if err != nil {
		return fmt.Errorf("marshal evidence version: %w", err)
	}
	payloadDigest := jsonDigest(versionJSON)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin evidence version projection: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	applied, err := evidenceEventApplied(ctx, tx, eventID, payloadDigest)
	if err != nil {
		return err
	}
	if applied {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO grc_evidence_artifacts (tenant_id, id, record_json, created_at)
VALUES ($1,$2,$3::jsonb,$4)
ON CONFLICT (tenant_id, id) DO NOTHING`, artifact.TenantID, artifact.ID, string(artifactJSON), artifact.CreatedAt.UTC()); err != nil {
		return fmt.Errorf("project evidence artifact: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO grc_evidence_versions (
  tenant_id,id,artifact_id,revision_id,revision_version,record_digest,content_digest,state,valid_until,record_json,recorded_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)
ON CONFLICT (tenant_id, id) DO NOTHING`, version.TenantID, version.ID, version.ArtifactID,
		version.Revision.RevisionID, version.Revision.Version, version.Revision.ContentDigest,
		version.Content.ContentDigest, version.State, nullableTime(version.ValidUntil), string(versionJSON), version.RecordedAt.UTC())
	if err != nil {
		return fmt.Errorf("project evidence version: %w", err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		var existingDigest string
		if err := tx.QueryRowContext(ctx, `SELECT record_digest FROM grc_evidence_versions WHERE tenant_id = $1 AND id = $2`, version.TenantID, version.ID).Scan(&existingDigest); err != nil {
			return fmt.Errorf("read existing evidence version: %w", err)
		}
		if existingDigest != version.Revision.ContentDigest {
			return ports.ErrEvidenceLedgerConflict
		}
	}
	if err := insertEvidenceReceipt(ctx, tx, eventID, version.TenantID, "evidence_version", version.ID, version.Revision.Version, payloadDigest); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit evidence version projection: %w", err)
	}
	return nil
}

func (s *Store) ApplyEvidenceClaim(ctx context.Context, eventID string, claim ports.EvidenceClaim, expectedVersion uint64) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureEvidenceLedgerTables(ctx); err != nil {
		return err
	}
	recordJSON, err := json.Marshal(claim)
	if err != nil {
		return fmt.Errorf("marshal evidence claim: %w", err)
	}
	digest := jsonDigest(recordJSON)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin evidence claim projection: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	applied, err := evidenceEventApplied(ctx, tx, eventID, digest)
	if err != nil {
		return err
	}
	if applied {
		return tx.Commit()
	}
	var result sql.Result
	if expectedVersion == 0 {
		result, err = tx.ExecContext(ctx, `
INSERT INTO grc_evidence_claims (tenant_id,id,artifact_version_id,aggregate_version,review_state,invalidated_at,record_digest,record_json,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)
ON CONFLICT (tenant_id, id) DO NOTHING`, claim.TenantID, claim.ID, claim.ArtifactVersionID, claim.Version,
			claim.Decision.ReviewState, nullableTime(claim.Decision.InvalidatedAt), digest, string(recordJSON), claim.CreatedAt.UTC())
	} else {
		result, err = tx.ExecContext(ctx, `
UPDATE grc_evidence_claims
SET aggregate_version = $4, review_state = $5, invalidated_at = $6, record_digest = $7, record_json = $8::jsonb, updated_at = NOW()
WHERE tenant_id = $1 AND id = $2 AND aggregate_version = $3`, claim.TenantID, claim.ID, expectedVersion, claim.Version,
			claim.Decision.ReviewState, nullableTime(claim.Decision.InvalidatedAt), digest, string(recordJSON))
	}
	if err != nil {
		return fmt.Errorf("project evidence claim: %w", err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ports.ErrEvidenceLedgerConflict
	}
	if err := insertEvidenceReceipt(ctx, tx, eventID, claim.TenantID, "evidence_claim", claim.ID, claim.Version, digest); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit evidence claim projection: %w", err)
	}
	return nil
}

func (s *Store) GetEvidenceArtifact(ctx context.Context, tenantID, artifactID string) (ports.EvidenceArtifact, error) {
	var value ports.EvidenceArtifact
	if err := s.getEvidenceJSON(ctx, `SELECT record_json FROM grc_evidence_artifacts WHERE tenant_id = $1 AND id = $2`, tenantID, artifactID, &value, ports.ErrEvidenceArtifactNotFound); err != nil {
		return ports.EvidenceArtifact{}, err
	}
	return value, nil
}

func (s *Store) GetEvidenceVersion(ctx context.Context, tenantID, versionID string) (ports.EvidenceVersion, error) {
	var value ports.EvidenceVersion
	if err := s.getEvidenceJSON(ctx, `SELECT record_json FROM grc_evidence_versions WHERE tenant_id = $1 AND id = $2`, tenantID, versionID, &value, ports.ErrEvidenceVersionNotFound); err != nil {
		return ports.EvidenceVersion{}, err
	}
	return value, nil
}

func (s *Store) GetEvidenceClaim(ctx context.Context, tenantID, claimID string) (ports.EvidenceClaim, error) {
	var value ports.EvidenceClaim
	if err := s.getEvidenceJSON(ctx, `SELECT record_json FROM grc_evidence_claims WHERE tenant_id = $1 AND id = $2`, tenantID, claimID, &value, ports.ErrEvidenceClaimNotFound); err != nil {
		return ports.EvidenceClaim{}, err
	}
	return value, nil
}

func (s *Store) ListEvidenceClaimsByVersion(ctx context.Context, tenantID, versionID string) ([]ports.EvidenceClaim, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureEvidenceLedgerTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT record_json FROM grc_evidence_claims WHERE tenant_id = $1 AND artifact_version_id = $2 ORDER BY id`, strings.TrimSpace(tenantID), strings.TrimSpace(versionID))
	if err != nil {
		return nil, fmt.Errorf("list evidence claims: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var result []ports.EvidenceClaim
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var claim ports.EvidenceClaim
		if err := json.Unmarshal(data, &claim); err != nil {
			return nil, fmt.Errorf("decode evidence claim: %w", err)
		}
		result = append(result, claim)
	}
	return result, rows.Err()
}

func (s *Store) getEvidenceJSON(ctx context.Context, query, tenantID, id string, target any, notFound error) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureEvidenceLedgerTables(ctx); err != nil {
		return err
	}
	var data []byte
	if err := s.db.QueryRowContext(ctx, query, strings.TrimSpace(tenantID), strings.TrimSpace(id)).Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return notFound
		}
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode evidence record: %w", err)
	}
	return nil
}

func evidenceEventApplied(ctx context.Context, tx *sql.Tx, eventID, digest string) (bool, error) {
	var existing string
	err := tx.QueryRowContext(ctx, `SELECT payload_digest FROM grc_evidence_event_receipts WHERE event_id = $1`, eventID).Scan(&existing)
	switch {
	case err == nil && existing == digest:
		return true, nil
	case err == nil:
		return false, ports.ErrEvidenceLedgerConflict
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	default:
		return false, fmt.Errorf("read evidence event receipt: %w", err)
	}
}

func insertEvidenceReceipt(ctx context.Context, tx *sql.Tx, eventID, tenantID, aggregateType, aggregateID string, version uint64, digest string) error {
	if _, err := tx.ExecContext(ctx, `
INSERT INTO grc_evidence_event_receipts (event_id,tenant_id,aggregate_type,aggregate_id,aggregate_version,payload_digest)
VALUES ($1,$2,$3,$4,$5,$6)`, eventID, tenantID, aggregateType, aggregateID, version, digest); err != nil {
		return fmt.Errorf("record evidence event receipt: %w", err)
	}
	return nil
}

func jsonDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}
