package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var ensureGRCFindingDispositionStatements = []string{
	`CREATE TABLE IF NOT EXISTS grc_finding_dispositions (
  tenant_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  disposition TEXT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, finding_id)
)`,
	`CREATE INDEX IF NOT EXISTS grc_finding_dispositions_tenant_disposition_idx ON grc_finding_dispositions (tenant_id, disposition, updated_at DESC)`,
}

func (s *Store) ensureGRCFindingDispositionTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grcFindingDispositionReady, "grc finding disposition", ensureGRCFindingDispositionStatements)
}

func (s *Store) UpsertGRCFindingDispositions(ctx context.Context, update ports.GRCFindingDispositionBulkUpdate) ([]*ports.GRCFindingDispositionRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCFindingDispositionTables(ctx); err != nil {
		return nil, err
	}
	tenantID := strings.TrimSpace(update.TenantID)
	disposition := strings.TrimSpace(update.Disposition)
	updatedBy := strings.TrimSpace(update.UpdatedBy)
	findingIDs := sanitizedStringSlice(update.FindingIDs)
	if tenantID == "" || disposition == "" {
		return nil, errors.New("tenant_id and disposition are required")
	}
	if !ports.IsGRCFindingDisposition(disposition) {
		return nil, errors.New("disposition is invalid")
	}
	if len(findingIDs) == 0 {
		return nil, errors.New("at least one finding_id is required")
	}
	query, args := grcFindingDispositionUpsertQuery(tenantID, disposition, updatedBy, findingIDs)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("upsert finding dispositions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.GRCFindingDispositionRecord{}
	for rows.Next() {
		record, err := scanGRCFindingDisposition(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) ListGRCFindingDispositions(ctx context.Context, tenantID string, findingIDs []string) ([]*ports.GRCFindingDispositionRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCFindingDispositionTables(ctx); err != nil {
		return nil, err
	}
	tenantID = strings.TrimSpace(tenantID)
	ids := sanitizedStringSlice(findingIDs)
	if tenantID == "" || len(ids) == 0 {
		return []*ports.GRCFindingDispositionRecord{}, nil
	}
	clauses := []string{"tenant_id = $1"}
	args := []any{tenantID}
	addStringInFilter(&clauses, &args, "finding_id", ids)
	// #nosec G201 -- clauses are fixed column predicates and values remain parameterized.
	query := fmt.Sprintf(`
SELECT tenant_id, finding_id, disposition, updated_by, created_at, updated_at
FROM grc_finding_dispositions
WHERE %s`, strings.Join(clauses, " AND "))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list finding dispositions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.GRCFindingDispositionRecord{}
	for rows.Next() {
		record, err := scanGRCFindingDisposition(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func grcFindingDispositionUpsertQuery(tenantID, disposition, updatedBy string, findingIDs []string) (string, []any) {
	args := []any{tenantID, disposition, updatedBy}
	values := make([]string, 0, len(findingIDs))
	for i, findingID := range findingIDs {
		args = append(args, findingID)
		values = append(values, fmt.Sprintf("($1, $%d, $2, $3)", i+4))
	}
	// #nosec G201 -- value tuples use fixed parameter placeholders; all values remain parameterized.
	query := fmt.Sprintf(`
INSERT INTO grc_finding_dispositions (tenant_id, finding_id, disposition, updated_by)
VALUES %s
ON CONFLICT (tenant_id, finding_id) DO UPDATE
SET disposition = EXCLUDED.disposition,
    updated_by = EXCLUDED.updated_by,
    updated_at = NOW()
RETURNING tenant_id, finding_id, disposition, updated_by, created_at, updated_at`, strings.Join(values, ", "))
	return query, args
}

func scanGRCFindingDisposition(row scanner) (*ports.GRCFindingDispositionRecord, error) {
	record := &ports.GRCFindingDispositionRecord{}
	if err := row.Scan(&record.TenantID, &record.FindingID, &record.Disposition, &record.UpdatedBy, &record.CreatedAt, &record.UpdatedAt); err != nil {
		return nil, err
	}
	return record, nil
}
