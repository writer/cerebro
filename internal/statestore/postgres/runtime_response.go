package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var ensureRuntimeBlocklistStatements = []string{
	`CREATE TABLE IF NOT EXISTS runtime_blocklist_entries (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  entry_type TEXT NOT NULL,
  entry_value TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  source_job_id TEXT NOT NULL DEFAULT '',
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS runtime_blocklist_active_value_idx ON runtime_blocklist_entries (tenant_id, entry_type, entry_value) WHERE revoked_at IS NULL`,
	`CREATE INDEX IF NOT EXISTS runtime_blocklist_tenant_type_idx ON runtime_blocklist_entries (tenant_id, entry_type, updated_at DESC)`,
}

func (s *Store) PutRuntimeBlocklistEntry(ctx context.Context, entry ports.RuntimeBlocklistEntry) (*ports.RuntimeBlocklistEntry, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureRuntimeBlocklistTables(ctx); err != nil {
		return nil, err
	}
	entry.ID = strings.TrimSpace(entry.ID)
	entry.TenantID = strings.TrimSpace(entry.TenantID)
	entry.Type = strings.TrimSpace(entry.Type)
	entry.Value = strings.TrimSpace(entry.Value)
	if entry.ID == "" || entry.TenantID == "" || entry.Type == "" || entry.Value == "" {
		return nil, errors.New("runtime blocklist id, tenant_id, type, and value are required")
	}
	attrs, err := json.Marshal(entry.Attributes)
	if err != nil {
		return nil, fmt.Errorf("marshal runtime blocklist attributes: %w", err)
	}
	var expires any
	if !entry.ExpiresAt.IsZero() {
		expires = entry.ExpiresAt.UTC()
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO runtime_blocklist_entries (
  id, tenant_id, entry_type, entry_value, reason, source, source_job_id, attributes_json, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)
ON CONFLICT (tenant_id, entry_type, entry_value) WHERE revoked_at IS NULL
DO UPDATE SET reason = EXCLUDED.reason,
              source = EXCLUDED.source,
              source_job_id = EXCLUDED.source_job_id,
              attributes_json = EXCLUDED.attributes_json,
              expires_at = EXCLUDED.expires_at,
              updated_at = NOW()
RETURNING id`, entry.ID, entry.TenantID, entry.Type, entry.Value, entry.Reason, entry.Source, entry.SourceJobID, string(attrs), expires)
	if err := row.Scan(&entry.ID); err != nil {
		return nil, fmt.Errorf("upsert runtime blocklist entry: %w", err)
	}
	return s.getRuntimeBlocklistEntry(ctx, entry.ID)
}

func (s *Store) ListRuntimeBlocklistEntries(ctx context.Context, filter ports.RuntimeBlocklistFilter) ([]*ports.RuntimeBlocklistEntry, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureRuntimeBlocklistTables(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1=1"}
	args := []any{}
	addTextFilter(&clauses, &args, "tenant_id", filter.TenantID)
	addTextFilter(&clauses, &args, "entry_type", filter.Type)
	if !filter.IncludeRevoked {
		clauses = append(clauses, "revoked_at IS NULL")
	}
	limit := filter.Limit
	if limit == 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit)
	// #nosec G201 -- clauses are fixed column predicates and LIMIT placeholder index is derived from args.
	query := fmt.Sprintf(`
SELECT id, tenant_id, entry_type, entry_value, reason, source, source_job_id, attributes_json::text,
       expires_at, revoked_at, created_at, updated_at
FROM runtime_blocklist_entries
WHERE %s
ORDER BY updated_at DESC, id ASC
LIMIT $%d`, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list runtime blocklist entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	entries := []*ports.RuntimeBlocklistEntry{}
	for rows.Next() {
		entry, err := scanRuntimeBlocklistEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *Store) RevokeRuntimeBlocklistEntry(ctx context.Context, tenantID string, id string) (*ports.RuntimeBlocklistEntry, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureRuntimeBlocklistTables(ctx); err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	tenantID = strings.TrimSpace(tenantID)
	if id == "" {
		return nil, errors.New("runtime blocklist entry id is required")
	}
	clauses := []string{"id = $1"}
	args := []any{id}
	if tenantID != "" {
		args = append(args, tenantID)
		clauses = append(clauses, fmt.Sprintf("tenant_id = $%d", len(args)))
	}
	// #nosec G201 -- clauses are assembled only from fixed column predicates; values remain parameterized.
	query := fmt.Sprintf(`UPDATE runtime_blocklist_entries SET revoked_at = NOW(), updated_at = NOW() WHERE %s`, strings.Join(clauses, " AND "))
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("revoke runtime blocklist entry %q: %w", id, err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return nil, fmt.Errorf("%w: %s", ports.ErrRuntimeBlocklistEntryNotFound, id)
	}
	return s.getRuntimeBlocklistEntry(ctx, id)
}

func (s *Store) getRuntimeBlocklistEntry(ctx context.Context, id string) (*ports.RuntimeBlocklistEntry, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, entry_type, entry_value, reason, source, source_job_id, attributes_json::text,
       expires_at, revoked_at, created_at, updated_at
FROM runtime_blocklist_entries
WHERE id = $1`, id)
	entry, err := scanRuntimeBlocklistEntry(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrRuntimeBlocklistEntryNotFound, id)
		}
		return nil, err
	}
	return entry, nil
}

func (s *Store) ensureRuntimeBlocklistTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.runtimeBlocklistReady, "runtime blocklist", ensureRuntimeBlocklistStatements)
}

func scanRuntimeBlocklistEntry(row scanner) (*ports.RuntimeBlocklistEntry, error) {
	entry := &ports.RuntimeBlocklistEntry{}
	var attrs string
	var expires, revoked sql.NullTime
	if err := row.Scan(&entry.ID, &entry.TenantID, &entry.Type, &entry.Value, &entry.Reason, &entry.Source, &entry.SourceJobID, &attrs, &expires, &revoked, &entry.CreatedAt, &entry.UpdatedAt); err != nil {
		return nil, err
	}
	entry.Attributes = map[string]string{}
	_ = json.Unmarshal([]byte(attrs), &entry.Attributes)
	if expires.Valid {
		entry.ExpiresAt = expires.Time.UTC()
	}
	if revoked.Valid {
		entry.RevokedAt = revoked.Time.UTC()
	}
	return entry, nil
}
