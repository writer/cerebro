package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/sourcehealth"
)

var ensureSourceRuntimeAuthorityEvidenceStatements = []string{`CREATE TABLE IF NOT EXISTS source_runtime_authority_evidence (
  decision_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  family_id TEXT NOT NULL,
  authority_epoch BIGINT NOT NULL,
  decision_kind TEXT NOT NULL,
  input_evidence_digest_sha256 TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  decided_at TIMESTAMPTZ NOT NULL,
  reason_code TEXT NOT NULL,
  authenticated_receipt_id TEXT NOT NULL DEFAULT '',
  receipt_signature TEXT NOT NULL DEFAULT '',
  previous_decision_id TEXT NOT NULL DEFAULT '',
  record_digest_sha256 TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS source_runtime_authority_evidence_family_idx ON source_runtime_authority_evidence (tenant_id, source_id, family_id, authority_epoch DESC, created_at DESC)`,
}

func (s *Store) AppendSourceRuntimeAuthorityEvidence(ctx context.Context, record sourcehealth.AuthorityEvidenceRecord) (sourcehealth.AuthorityEvidenceRecord, error) {
	if s == nil || s.db == nil {
		return sourcehealth.AuthorityEvidenceRecord{}, errors.New("postgres is not configured")
	}
	stream := sourcehealth.NewAuthorityEvidenceStream()
	record, err := stream.Append(record)
	if err != nil {
		return sourcehealth.AuthorityEvidenceRecord{}, err
	}
	if err := s.ensureSourceRuntimeAuthorityEvidenceTables(ctx); err != nil {
		return sourcehealth.AuthorityEvidenceRecord{}, err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO source_runtime_authority_evidence (
  decision_id, tenant_id, source_id, family_id, authority_epoch, decision_kind,
  input_evidence_digest_sha256, actor_id, decided_at, reason_code,
  authenticated_receipt_id, receipt_signature, previous_decision_id, record_digest_sha256
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		record.DecisionID,
		record.TenantID,
		record.SourceID,
		record.FamilyID,
		int64(record.AuthorityEpoch),
		string(record.DecisionKind),
		record.InputEvidenceDigestSHA256,
		record.ActorID,
		record.Timestamp,
		record.ReasonCode,
		record.AuthenticatedReceiptID,
		record.ReceiptSignature,
		record.PreviousDecisionID,
		record.RecordDigestSHA256,
	)
	if err != nil {
		return sourcehealth.AuthorityEvidenceRecord{}, fmt.Errorf("append source runtime authority evidence %q: %w", record.DecisionID, err)
	}
	return record, nil
}

func (s *Store) LatestSourceRuntimeAuthorityEvidence(ctx context.Context, tenantID, sourceID, familyID string) (sourcehealth.AuthorityEvidenceRecord, error) {
	if s == nil || s.db == nil {
		return sourcehealth.AuthorityEvidenceRecord{}, errors.New("postgres is not configured")
	}
	if err := s.ensureSourceRuntimeAuthorityEvidenceTables(ctx); err != nil {
		return sourcehealth.AuthorityEvidenceRecord{}, err
	}
	row := s.db.QueryRowContext(ctx, `
SELECT decision_id, tenant_id, source_id, family_id, authority_epoch, decision_kind,
       input_evidence_digest_sha256, actor_id, decided_at, reason_code,
       authenticated_receipt_id, receipt_signature, previous_decision_id, record_digest_sha256
FROM source_runtime_authority_evidence
WHERE tenant_id = $1 AND source_id = $2 AND family_id = $3
ORDER BY authority_epoch DESC, created_at DESC
LIMIT 1`, strings.TrimSpace(tenantID), strings.TrimSpace(sourceID), strings.TrimSpace(familyID))
	record, err := scanSourceRuntimeAuthorityEvidence(row)
	if err != nil {
		return sourcehealth.AuthorityEvidenceRecord{}, err
	}
	if err := sourcehealth.VerifyAuthorityEvidenceRecord(record); err != nil {
		return sourcehealth.AuthorityEvidenceRecord{}, err
	}
	return record, nil
}

func (s *Store) ensureSourceRuntimeAuthorityEvidenceTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	for _, statement := range ensureSourceRuntimeAuthorityEvidenceStatements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("ensure source runtime authority evidence table: %w", err)
		}
	}
	return nil
}

type authorityEvidenceScanner interface {
	Scan(dest ...any) error
}

func scanSourceRuntimeAuthorityEvidence(scanner authorityEvidenceScanner) (sourcehealth.AuthorityEvidenceRecord, error) {
	var record sourcehealth.AuthorityEvidenceRecord
	var decisionKind string
	var authorityEpoch int64
	if err := scanner.Scan(
		&record.DecisionID,
		&record.TenantID,
		&record.SourceID,
		&record.FamilyID,
		&authorityEpoch,
		&decisionKind,
		&record.InputEvidenceDigestSHA256,
		&record.ActorID,
		&record.Timestamp,
		&record.ReasonCode,
		&record.AuthenticatedReceiptID,
		&record.ReceiptSignature,
		&record.PreviousDecisionID,
		&record.RecordDigestSHA256,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sourcehealth.AuthorityEvidenceRecord{}, fmt.Errorf("%w: source runtime authority evidence not found", sourcehealth.ErrAuthorityEvidenceInvalid)
		}
		return sourcehealth.AuthorityEvidenceRecord{}, fmt.Errorf("query source runtime authority evidence: %w", err)
	}
	record.DecisionKind = sourcehealth.AuthorityDecisionKind(strings.TrimSpace(decisionKind))
	if authorityEpoch > 0 {
		record.AuthorityEpoch = uint64(authorityEpoch)
	}
	return record, nil
}
