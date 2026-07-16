package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/writer/cerebro/internal/ports"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

var ensureSourceRuntimePageLedgerStatements = []string{`CREATE TABLE IF NOT EXISTS source_runtime_page_ledger (
  attempt_id TEXT PRIMARY KEY,
  runtime_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL DEFAULT '',
  page_number INTEGER NOT NULL,
  status TEXT NOT NULL,
  records_scanned INTEGER NOT NULL DEFAULT 0,
  records_accepted INTEGER NOT NULL DEFAULT 0,
  records_quarantined INTEGER NOT NULL DEFAULT 0,
  duplicate_events INTEGER NOT NULL DEFAULT 0,
  admission_kernel TEXT NOT NULL DEFAULT '',
  admission_abi_version INTEGER NOT NULL DEFAULT 0,
  admission_contracts_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  admission_contracts_sha256 TEXT NOT NULL DEFAULT '',
  admission_scanned_sha256 TEXT NOT NULL DEFAULT '',
  admission_accepted_sha256 TEXT NOT NULL DEFAULT '',
  admission_result_sha256 TEXT NOT NULL DEFAULT '',
  entities_projected INTEGER NOT NULL DEFAULT 0,
  links_projected INTEGER NOT NULL DEFAULT 0,
  runtime_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  appended_at TIMESTAMPTZ,
  projected_at TIMESTAMPTZ,
  committed_at TIMESTAMPTZ
)`,
	`ALTER TABLE source_runtime_page_ledger
  ADD COLUMN IF NOT EXISTS records_quarantined INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS duplicate_events INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS admission_kernel TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS admission_abi_version INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS admission_contracts_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS admission_contracts_sha256 TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS admission_scanned_sha256 TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS admission_accepted_sha256 TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS admission_result_sha256 TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS source_runtime_page_ledger_runtime_status_idx ON source_runtime_page_ledger (runtime_id, status, updated_at ASC)`,
	`CREATE TABLE IF NOT EXISTS source_runtime_page_outbox (
  attempt_id TEXT NOT NULL REFERENCES source_runtime_page_ledger(attempt_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  event_id TEXT NOT NULL,
  event_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  appended_at TIMESTAMPTZ,
  projected_at TIMESTAMPTZ,
  PRIMARY KEY (attempt_id, ordinal),
  UNIQUE (attempt_id, event_id)
)`,
	`CREATE TABLE IF NOT EXISTS source_runtime_event_quarantine (
  tenant_id TEXT NOT NULL,
  quarantine_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_sha256 TEXT NOT NULL,
  rejection_code TEXT NOT NULL,
  rejection_field TEXT NOT NULL DEFAULT '',
  event_json JSONB NOT NULL,
  state TEXT NOT NULL DEFAULT 'captured' CHECK (state IN ('captured', 'pending', 'resolved', 'discarded')),
  occurrence_count BIGINT NOT NULL DEFAULT 0,
  first_observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, quarantine_id)
)`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS source_runtime_event_quarantine_runtime_state_idx ON source_runtime_event_quarantine (tenant_id, runtime_id, state, last_observed_at DESC, quarantine_id DESC)`,
	`CREATE TABLE IF NOT EXISTS source_runtime_page_quarantine (
  attempt_id TEXT NOT NULL REFERENCES source_runtime_page_ledger(attempt_id) ON DELETE CASCADE,
  input_index INTEGER NOT NULL,
  tenant_id TEXT NOT NULL,
  quarantine_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (attempt_id, input_index),
  FOREIGN KEY (tenant_id, quarantine_id) REFERENCES source_runtime_event_quarantine(tenant_id, quarantine_id) ON DELETE CASCADE
)`,
}

func (s *Store) BeginSourceRuntimePage(ctx context.Context, attempt ports.SourceRuntimePageAttempt) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureSourceRuntimePageLedgerTables(ctx); err != nil {
		return err
	}
	attemptID := strings.TrimSpace(attempt.AttemptID)
	if attemptID == "" {
		return errors.New("source runtime page attempt id is required")
	}
	contractsJSON := strings.TrimSpace(string(attempt.Admission.ContractsJSON))
	if contractsJSON == "" {
		contractsJSON = "[]"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin source runtime page ledger: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO source_runtime_page_ledger (
  attempt_id, runtime_id, source_id, tenant_id, page_number, status,
  records_scanned, records_accepted, records_quarantined, duplicate_events,
  admission_kernel, admission_abi_version, admission_contracts_json,
  admission_contracts_sha256, admission_scanned_sha256,
  admission_accepted_sha256, admission_result_sha256
)
VALUES ($1, $2, $3, $4, $5, 'started', $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $14, $15, $16)
ON CONFLICT (attempt_id)
DO UPDATE SET status = 'started',
              records_scanned = EXCLUDED.records_scanned,
              records_accepted = EXCLUDED.records_accepted,
              records_quarantined = EXCLUDED.records_quarantined,
              duplicate_events = EXCLUDED.duplicate_events,
              admission_kernel = EXCLUDED.admission_kernel,
              admission_abi_version = EXCLUDED.admission_abi_version,
              admission_contracts_json = EXCLUDED.admission_contracts_json,
              admission_contracts_sha256 = EXCLUDED.admission_contracts_sha256,
              admission_scanned_sha256 = EXCLUDED.admission_scanned_sha256,
              admission_accepted_sha256 = EXCLUDED.admission_accepted_sha256,
              admission_result_sha256 = EXCLUDED.admission_result_sha256,
              updated_at = NOW()`,
		attemptID,
		strings.TrimSpace(attempt.RuntimeID),
		strings.TrimSpace(attempt.SourceID),
		strings.TrimSpace(attempt.TenantID),
		attempt.PageNumber,
		attempt.RecordsScanned,
		len(attempt.Events),
		attempt.Admission.Quarantined,
		attempt.Admission.Duplicates,
		strings.TrimSpace(attempt.Admission.Kernel),
		attempt.Admission.ABIVersion,
		contractsJSON,
		strings.TrimSpace(attempt.Admission.ContractsSHA256),
		strings.TrimSpace(attempt.Admission.ScannedSHA256),
		strings.TrimSpace(attempt.Admission.AcceptedSHA256),
		strings.TrimSpace(attempt.Admission.ResultSHA256),
	); err != nil {
		return fmt.Errorf("upsert source runtime page ledger %q: %w", attemptID, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM source_runtime_page_outbox WHERE attempt_id = $1`, attemptID); err != nil {
		return fmt.Errorf("reset source runtime page outbox %q: %w", attemptID, err)
	}
	for index, event := range attempt.Events {
		payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(event)
		if err != nil {
			return fmt.Errorf("marshal source runtime page event %q: %w", event.GetId(), err)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO source_runtime_page_outbox (attempt_id, ordinal, event_id, event_json)
VALUES ($1, $2, $3, $4::jsonb)`, attemptID, index, event.GetId(), string(payload)); err != nil {
			return fmt.Errorf("insert source runtime page outbox event %q: %w", event.GetId(), err)
		}
	}
	for _, quarantine := range attempt.Quarantines {
		if strings.TrimSpace(quarantine.ID) == "" || quarantine.Event == nil || strings.TrimSpace(quarantine.EventID) == "" || quarantine.Event.GetId() != quarantine.EventID || strings.TrimSpace(quarantine.EventSHA256) == "" || strings.TrimSpace(quarantine.Code) == "" {
			return errors.New("source runtime page quarantine proof is incomplete")
		}
		payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(quarantine.Event)
		if err != nil {
			return fmt.Errorf("marshal quarantined source runtime event %q: %w", quarantine.EventID, err)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO source_runtime_event_quarantine (
  tenant_id, quarantine_id, runtime_id, source_id, event_id, event_sha256,
  rejection_code, rejection_field, event_json
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
ON CONFLICT (tenant_id, quarantine_id)
DO UPDATE SET event_json = EXCLUDED.event_json,
              updated_at = NOW()`,
			strings.TrimSpace(attempt.TenantID),
			strings.TrimSpace(quarantine.ID),
			strings.TrimSpace(attempt.RuntimeID),
			strings.TrimSpace(attempt.SourceID),
			strings.TrimSpace(quarantine.EventID),
			strings.TrimSpace(quarantine.EventSHA256),
			strings.TrimSpace(quarantine.Code),
			strings.TrimSpace(quarantine.Field),
			string(payload),
		); err != nil {
			return fmt.Errorf("upsert source runtime quarantine %q: %w", quarantine.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `
WITH linked AS (
  INSERT INTO source_runtime_page_quarantine (attempt_id, input_index, tenant_id, quarantine_id)
  VALUES ($1, $2, $3, $4)
  ON CONFLICT (attempt_id, input_index) DO NOTHING
  RETURNING tenant_id, quarantine_id
)
UPDATE source_runtime_event_quarantine AS quarantine
SET occurrence_count = quarantine.occurrence_count + 1,
    last_observed_at = NOW(),
    updated_at = NOW()
FROM linked
WHERE linked.tenant_id = quarantine.tenant_id
  AND linked.quarantine_id = quarantine.quarantine_id`,
			attemptID,
			quarantine.InputIndex,
			strings.TrimSpace(attempt.TenantID),
			strings.TrimSpace(quarantine.ID),
		); err != nil {
			return fmt.Errorf("link source runtime quarantine %q to page %q: %w", quarantine.ID, attemptID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit source runtime page ledger begin %q: %w", attemptID, err)
	}
	return nil
}

func (s *Store) MarkSourceRuntimePageAppended(ctx context.Context, attemptID string) error {
	return s.markSourceRuntimePage(ctx, attemptID, "appended", nil)
}

func (s *Store) MarkSourceRuntimePageProjected(ctx context.Context, attemptID string, projection ports.SourceRuntimePageProjection) error {
	return s.markSourceRuntimePage(ctx, attemptID, "projected", &projection)
}

func (s *Store) CommitSourceRuntimePage(ctx context.Context, attemptID string, runtime *cerebrov1.SourceRuntime) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureSourceRuntimePageLedgerTables(ctx); err != nil {
		return err
	}
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(runtime)
	if err != nil {
		return fmt.Errorf("marshal source runtime: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin source runtime page commit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := putSourceRuntime(ctx, tx, runtime); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE source_runtime_page_ledger
SET status = 'committed',
    runtime_json = $2::jsonb,
    updated_at = NOW(),
    committed_at = NOW()
WHERE attempt_id = $1`, strings.TrimSpace(attemptID), string(payload))
	if err != nil {
		return fmt.Errorf("commit source runtime page ledger %q: %w", attemptID, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("commit source runtime page ledger %q rows affected: %w", attemptID, err)
	}
	if rows == 0 {
		return fmt.Errorf("source runtime page ledger attempt %q not found", attemptID)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE source_runtime_event_quarantine AS quarantine
SET state = 'pending',
    updated_at = NOW()
FROM source_runtime_page_quarantine AS page_quarantine
WHERE page_quarantine.attempt_id = $1
  AND page_quarantine.tenant_id = quarantine.tenant_id
  AND page_quarantine.quarantine_id = quarantine.quarantine_id
  AND quarantine.state IN ('captured', 'resolved')`, strings.TrimSpace(attemptID)); err != nil {
		return fmt.Errorf("activate source runtime page quarantines %q: %w", attemptID, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit source runtime page progress %q: %w", attemptID, err)
	}
	return nil
}

func (s *Store) markSourceRuntimePage(ctx context.Context, attemptID string, status string, projection *ports.SourceRuntimePageProjection) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureSourceRuntimePageLedgerTables(ctx); err != nil {
		return err
	}
	timestampColumn := "appended_at"
	if status == "projected" {
		timestampColumn = "projected_at"
	}
	entitiesProjected := uint32(0)
	linksProjected := uint32(0)
	if projection != nil {
		entitiesProjected = projection.EntitiesProjected
		linksProjected = projection.LinksProjected
	}
	// #nosec G201 -- timestampColumn is selected from a fixed allowlist above.
	query := fmt.Sprintf(`
UPDATE source_runtime_page_ledger
SET status = $2,
    entities_projected = GREATEST(entities_projected, $3),
    links_projected = GREATEST(links_projected, $4),
    updated_at = NOW(),
    %s = NOW()
WHERE attempt_id = $1`, timestampColumn)
	result, err := s.db.ExecContext(ctx, query, strings.TrimSpace(attemptID), status, entitiesProjected, linksProjected)
	if err != nil {
		return fmt.Errorf("mark source runtime page %q %s: %w", attemptID, status, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark source runtime page %q rows affected: %w", attemptID, err)
	}
	if rows == 0 {
		return fmt.Errorf("source runtime page ledger attempt %q not found", attemptID)
	}
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf(`UPDATE source_runtime_page_outbox SET %s = NOW() WHERE attempt_id = $1`, timestampColumn), strings.TrimSpace(attemptID)); err != nil {
		return fmt.Errorf("mark source runtime page outbox %q %s: %w", attemptID, status, err)
	}
	return nil
}

func (s *Store) ensureSourceRuntimePageLedgerTables(ctx context.Context) error {
	if err := s.ensureSourceRuntimeTable(ctx); err != nil {
		return err
	}
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	for _, statement := range ensureSourceRuntimePageLedgerStatements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("ensure source runtime page ledger schema: %w", err)
		}
	}
	return nil
}

var _ ports.SourceRuntimePageLedgerStore = (*Store)(nil)
var _ sourceRuntimeExecutor = (*sql.Tx)(nil)
