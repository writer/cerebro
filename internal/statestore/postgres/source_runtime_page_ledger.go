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
  entities_projected INTEGER NOT NULL DEFAULT 0,
  links_projected INTEGER NOT NULL DEFAULT 0,
  runtime_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  appended_at TIMESTAMPTZ,
  projected_at TIMESTAMPTZ,
  committed_at TIMESTAMPTZ
)`,
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin source runtime page ledger: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO source_runtime_page_ledger (attempt_id, runtime_id, source_id, tenant_id, page_number, status, records_scanned, records_accepted)
VALUES ($1, $2, $3, $4, $5, 'started', $6, $7)
ON CONFLICT (attempt_id)
DO UPDATE SET status = 'started',
              records_scanned = EXCLUDED.records_scanned,
              records_accepted = EXCLUDED.records_accepted,
              updated_at = NOW()`,
		attemptID, strings.TrimSpace(attempt.RuntimeID), strings.TrimSpace(attempt.SourceID), strings.TrimSpace(attempt.TenantID), attempt.PageNumber, attempt.RecordsScanned, len(attempt.Events)); err != nil {
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
