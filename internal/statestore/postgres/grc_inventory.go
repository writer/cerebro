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

var ensureGRCInventoryScopeStatements = []string{
	`CREATE TABLE IF NOT EXISTS grc_inventory_scopes (
  tenant_id TEXT NOT NULL,
  asset_urn TEXT NOT NULL,
  source_id TEXT NOT NULL DEFAULT '',
  scope_state TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT '',
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, asset_urn)
)`,
	`CREATE INDEX IF NOT EXISTS grc_inventory_scopes_tenant_source_state_idx ON grc_inventory_scopes (tenant_id, source_id, scope_state, updated_at DESC)`,
}

func (s *Store) UpsertGRCInventoryScope(ctx context.Context, record ports.GRCInventoryScopeRecord) (*ports.GRCInventoryScopeRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCInventoryScopeTables(ctx); err != nil {
		return nil, err
	}
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.AssetURN = strings.TrimSpace(record.AssetURN)
	record.SourceID = strings.TrimSpace(record.SourceID)
	record.ScopeState = strings.TrimSpace(record.ScopeState)
	record.Reason = strings.TrimSpace(record.Reason)
	record.UpdatedBy = strings.TrimSpace(record.UpdatedBy)
	if record.TenantID == "" || record.AssetURN == "" || record.ScopeState == "" {
		return nil, errors.New("tenant_id, asset_urn, and scope_state are required")
	}
	if record.ScopeState != ports.GRCInventoryScopeStateIn && record.ScopeState != ports.GRCInventoryScopeStateOut {
		return nil, errors.New("scope_state must be in_scope or out_of_scope")
	}
	attrs, err := json.Marshal(record.Attributes)
	if err != nil {
		return nil, fmt.Errorf("marshal inventory scope attributes: %w", err)
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO grc_inventory_scopes (tenant_id, asset_urn, source_id, scope_state, reason, updated_by, attributes_json)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
ON CONFLICT (tenant_id, asset_urn)
DO UPDATE SET source_id = EXCLUDED.source_id,
              scope_state = EXCLUDED.scope_state,
              reason = EXCLUDED.reason,
              updated_by = EXCLUDED.updated_by,
              attributes_json = EXCLUDED.attributes_json,
              updated_at = NOW()
RETURNING tenant_id, asset_urn, source_id, scope_state, reason, updated_by, attributes_json::text, created_at, updated_at`,
		record.TenantID, record.AssetURN, record.SourceID, record.ScopeState, record.Reason, record.UpdatedBy, string(attrs))
	return scanGRCInventoryScope(row)
}

func (s *Store) ListGRCInventoryScopes(ctx context.Context, filter ports.GRCInventoryScopeFilter) ([]*ports.GRCInventoryScopeRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCInventoryScopeTables(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1=1"}
	args := []any{}
	addTextFilter(&clauses, &args, "tenant_id", filter.TenantID)
	addTextFilter(&clauses, &args, "source_id", filter.SourceID)
	addTextFilter(&clauses, &args, "scope_state", filter.ScopeState)
	addStringInFilter(&clauses, &args, "asset_urn", filter.AssetURNs)
	limit := filter.Limit
	if limit == 0 || limit > 500 {
		limit = 500
	}
	args = append(args, limit)
	// #nosec G201 -- clauses are assembled from fixed column predicates and values remain parameterized.
	query := fmt.Sprintf(`
SELECT tenant_id, asset_urn, source_id, scope_state, reason, updated_by, attributes_json::text, created_at, updated_at
FROM grc_inventory_scopes
WHERE %s
ORDER BY updated_at DESC, asset_urn ASC
LIMIT $%d`, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list inventory scopes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.GRCInventoryScopeRecord{}
	for rows.Next() {
		record, err := scanGRCInventoryScope(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) ensureGRCInventoryScopeTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grcInventoryScopeReady, "grc inventory scope", ensureGRCInventoryScopeStatements)
}

func scanGRCInventoryScope(row scanner) (*ports.GRCInventoryScopeRecord, error) {
	record := &ports.GRCInventoryScopeRecord{}
	var attrs string
	if err := row.Scan(&record.TenantID, &record.AssetURN, &record.SourceID, &record.ScopeState, &record.Reason, &record.UpdatedBy, &attrs, &record.CreatedAt, &record.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, err
	}
	record.Attributes = map[string]string{}
	_ = json.Unmarshal([]byte(attrs), &record.Attributes)
	return record, nil
}
