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

var ensureGRCInventoryAssetReportStatements = []string{
	`CREATE TABLE IF NOT EXISTS grc_inventory_asset_reports (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  asset_urn TEXT NOT NULL,
  source_id TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL,
  reporter TEXT NOT NULL DEFAULT '',
  triage_status TEXT NOT NULL,
  triage_reason TEXT NOT NULL DEFAULT '',
  triaged_by TEXT NOT NULL DEFAULT '',
  triaged_at TIMESTAMPTZ,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS grc_inventory_asset_reports_tenant_asset_status_idx ON grc_inventory_asset_reports (tenant_id, asset_urn, triage_status, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS grc_inventory_asset_reports_tenant_status_idx ON grc_inventory_asset_reports (tenant_id, triage_status, updated_at DESC)`,
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

func (s *Store) UpdateGRCInventoryAccountability(ctx context.Context, update ports.GRCInventoryAccountabilityUpdate) (*ports.GRCInventoryScopeRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCInventoryScopeTables(ctx); err != nil {
		return nil, err
	}
	update.TenantID = strings.TrimSpace(update.TenantID)
	update.AssetURN = strings.TrimSpace(update.AssetURN)
	update.SourceID = strings.TrimSpace(update.SourceID)
	update.UpdatedBy = strings.TrimSpace(update.UpdatedBy)
	if update.TenantID == "" || update.AssetURN == "" {
		return nil, errors.New("tenant_id and asset_urn are required")
	}
	setAttrs := sanitizedStringMap(update.SetAttributes)
	clearAttrs := sanitizedStringSlice(update.ClearAttributes)
	attrs, err := json.Marshal(setAttrs)
	if err != nil {
		return nil, fmt.Errorf("marshal inventory accountability attributes: %w", err)
	}
	clearKeys, err := json.Marshal(clearAttrs)
	if err != nil {
		return nil, fmt.Errorf("marshal inventory accountability clear keys: %w", err)
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO grc_inventory_scopes (tenant_id, asset_urn, source_id, scope_state, reason, updated_by, attributes_json)
VALUES ($1, $2, $3, 'in_scope', '', $4, $5::jsonb)
ON CONFLICT (tenant_id, asset_urn)
DO UPDATE SET source_id = CASE
                  WHEN EXCLUDED.source_id <> '' THEN EXCLUDED.source_id
                  ELSE grc_inventory_scopes.source_id
              END,
              updated_by = EXCLUDED.updated_by,
              attributes_json = (
                  SELECT COALESCE(jsonb_object_agg(existing.key, existing.value), '{}'::jsonb)
                  FROM jsonb_each(grc_inventory_scopes.attributes_json) AS existing(key, value)
                  WHERE NOT EXISTS (
                      SELECT 1
                      FROM jsonb_array_elements_text($6::jsonb) AS cleared(key)
                      WHERE cleared.key = existing.key
                  )
              ) || $5::jsonb,
              updated_at = NOW()
RETURNING tenant_id, asset_urn, source_id, scope_state, reason, updated_by, attributes_json::text, created_at, updated_at`,
		update.TenantID, update.AssetURN, update.SourceID, update.UpdatedBy, string(attrs), string(clearKeys))
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

func (s *Store) CreateGRCInventoryAssetReport(ctx context.Context, record ports.GRCInventoryAssetReportRecord) (*ports.GRCInventoryAssetReportRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCInventoryAssetReportTables(ctx); err != nil {
		return nil, err
	}
	record.ID = strings.TrimSpace(record.ID)
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.AssetURN = strings.TrimSpace(record.AssetURN)
	record.SourceID = strings.TrimSpace(record.SourceID)
	record.Reason = strings.TrimSpace(record.Reason)
	record.Reporter = strings.TrimSpace(record.Reporter)
	record.TriageStatus = strings.TrimSpace(record.TriageStatus)
	if record.ID == "" || record.TenantID == "" || record.AssetURN == "" || record.Reason == "" || record.TriageStatus == "" {
		return nil, errors.New("id, tenant_id, asset_urn, reason, and triage_status are required")
	}
	if !ports.IsGRCInventoryAssetReportStatus(record.TriageStatus) {
		return nil, errors.New("triage_status is invalid")
	}
	attrs, err := json.Marshal(emptyStringMap(record.Attributes))
	if err != nil {
		return nil, fmt.Errorf("marshal inventory asset report attributes: %w", err)
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO grc_inventory_asset_reports (id, tenant_id, asset_urn, source_id, reason, reporter, triage_status, attributes_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
RETURNING id, tenant_id, asset_urn, source_id, reason, reporter, triage_status, triage_reason, triaged_by, triaged_at, attributes_json::text, created_at, updated_at`,
		record.ID, record.TenantID, record.AssetURN, record.SourceID, record.Reason, record.Reporter, record.TriageStatus, string(attrs))
	return scanGRCInventoryAssetReport(row)
}

func (s *Store) GetGRCInventoryAssetReport(ctx context.Context, id string, tenantID string) (*ports.GRCInventoryAssetReportRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCInventoryAssetReportTables(ctx); err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	tenantID = strings.TrimSpace(tenantID)
	if id == "" {
		return nil, errors.New("id is required")
	}
	clauses := []string{"id = $1"}
	args := []any{id}
	addTextFilter(&clauses, &args, "tenant_id", tenantID)
	// #nosec G201 -- clauses are fixed column predicates and values remain parameterized.
	query := fmt.Sprintf(`
SELECT id, tenant_id, asset_urn, source_id, reason, reporter, triage_status, triage_reason, triaged_by, triaged_at, attributes_json::text, created_at, updated_at
FROM grc_inventory_asset_reports
WHERE %s
LIMIT 1`, strings.Join(clauses, " AND "))
	record, err := scanGRCInventoryAssetReport(s.db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ports.ErrGRCInventoryAssetReportNotFound, id)
	}
	return record, err
}

func (s *Store) ListGRCInventoryAssetReports(ctx context.Context, filter ports.GRCInventoryAssetReportFilter) ([]*ports.GRCInventoryAssetReportRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCInventoryAssetReportTables(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1=1"}
	args := []any{}
	addTextFilter(&clauses, &args, "tenant_id", filter.TenantID)
	addTextFilter(&clauses, &args, "source_id", filter.SourceID)
	addTextFilter(&clauses, &args, "triage_status", filter.TriageStatus)
	addStringInFilter(&clauses, &args, "asset_urn", filter.AssetURNs)
	limit := filter.Limit
	if limit == 0 || limit > 500 {
		limit = 500
	}
	args = append(args, limit)
	// #nosec G201 -- clauses are assembled from fixed column predicates and values remain parameterized.
	query := fmt.Sprintf(`
SELECT id, tenant_id, asset_urn, source_id, reason, reporter, triage_status, triage_reason, triaged_by, triaged_at, attributes_json::text, created_at, updated_at
FROM grc_inventory_asset_reports
WHERE %s
ORDER BY updated_at DESC, created_at DESC, id ASC
LIMIT $%d`, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list inventory asset reports: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.GRCInventoryAssetReportRecord{}
	for rows.Next() {
		record, err := scanGRCInventoryAssetReport(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) SummarizeGRCInventoryAssetReports(ctx context.Context, filter ports.GRCInventoryAssetReportFilter) ([]*ports.GRCInventoryAssetReportSummary, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCInventoryAssetReportTables(ctx); err != nil {
		return nil, err
	}
	if len(normalizedNonEmptyStrings(filter.AssetURNs)) == 0 {
		return []*ports.GRCInventoryAssetReportSummary{}, nil
	}
	clauses := []string{"1=1"}
	args := []any{}
	addTextFilter(&clauses, &args, "tenant_id", filter.TenantID)
	addTextFilter(&clauses, &args, "source_id", filter.SourceID)
	addTextFilter(&clauses, &args, "triage_status", filter.TriageStatus)
	addStringInFilter(&clauses, &args, "asset_urn", filter.AssetURNs)
	// #nosec G201 -- clauses are assembled from fixed column predicates and values remain parameterized.
	query := fmt.Sprintf(`
WITH ranked_reports AS (
  SELECT asset_urn,
         reason,
         triage_status,
         updated_at,
         COUNT(*) OVER (PARTITION BY asset_urn) AS report_count,
         ROW_NUMBER() OVER (PARTITION BY asset_urn ORDER BY updated_at DESC, created_at DESC, id ASC) AS report_rank
  FROM grc_inventory_asset_reports
  WHERE %s
)
SELECT asset_urn, report_count, triage_status, reason, updated_at
FROM ranked_reports
WHERE report_rank = 1
ORDER BY updated_at DESC, asset_urn ASC`, strings.Join(clauses, " AND "))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("summarize inventory asset reports: %w", err)
	}
	defer func() { _ = rows.Close() }()
	summaries := []*ports.GRCInventoryAssetReportSummary{}
	for rows.Next() {
		summary, err := scanGRCInventoryAssetReportSummary(rows)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, summary)
	}
	return summaries, rows.Err()
}

func (s *Store) UpdateGRCInventoryAssetReportTriage(ctx context.Context, update ports.GRCInventoryAssetReportTriageUpdate) (*ports.GRCInventoryAssetReportRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCInventoryAssetReportTables(ctx); err != nil {
		return nil, err
	}
	update.ID = strings.TrimSpace(update.ID)
	update.TenantID = strings.TrimSpace(update.TenantID)
	update.TriageStatus = strings.TrimSpace(update.TriageStatus)
	update.TriageReason = strings.TrimSpace(update.TriageReason)
	update.TriagedBy = strings.TrimSpace(update.TriagedBy)
	if update.ID == "" || update.TriageStatus == "" {
		return nil, errors.New("id and triage_status are required")
	}
	if !ports.IsGRCInventoryAssetReportStatus(update.TriageStatus) {
		return nil, errors.New("triage_status is invalid")
	}
	row := s.db.QueryRowContext(ctx, `
UPDATE grc_inventory_asset_reports
SET triage_status = $1,
    triage_reason = $2,
    triaged_by = CASE WHEN $1 = 'submitted' THEN '' ELSE $3 END,
    triaged_at = CASE WHEN $1 = 'submitted' THEN NULL ELSE NOW() END,
    updated_at = NOW()
WHERE id = $4 AND ($5 = '' OR tenant_id = $5)
RETURNING id, tenant_id, asset_urn, source_id, reason, reporter, triage_status, triage_reason, triaged_by, triaged_at, attributes_json::text, created_at, updated_at`,
		update.TriageStatus, update.TriageReason, update.TriagedBy, update.ID, update.TenantID)
	record, err := scanGRCInventoryAssetReport(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ports.ErrGRCInventoryAssetReportNotFound, update.ID)
	}
	return record, err
}

func (s *Store) ensureGRCInventoryAssetReportTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grcInventoryAssetReportReady, "grc inventory asset report", ensureGRCInventoryAssetReportStatements)
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

func scanGRCInventoryAssetReport(row scanner) (*ports.GRCInventoryAssetReportRecord, error) {
	record := &ports.GRCInventoryAssetReportRecord{}
	var attrs string
	var triagedAt sql.NullTime
	if err := row.Scan(&record.ID, &record.TenantID, &record.AssetURN, &record.SourceID, &record.Reason, &record.Reporter, &record.TriageStatus, &record.TriageReason, &record.TriagedBy, &triagedAt, &attrs, &record.CreatedAt, &record.UpdatedAt); err != nil {
		return nil, err
	}
	if triagedAt.Valid {
		value := triagedAt.Time
		record.TriagedAt = &value
	}
	record.Attributes = map[string]string{}
	_ = json.Unmarshal([]byte(attrs), &record.Attributes)
	return record, nil
}

func scanGRCInventoryAssetReportSummary(row scanner) (*ports.GRCInventoryAssetReportSummary, error) {
	summary := &ports.GRCInventoryAssetReportSummary{}
	if err := row.Scan(&summary.AssetURN, &summary.ReportCount, &summary.TriageStatus, &summary.Reason, &summary.UpdatedAt); err != nil {
		return nil, err
	}
	return summary, nil
}

func sanitizedStringMap(values map[string]string) map[string]string {
	sanitized := map[string]string{}
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		sanitized[key] = value
	}
	return sanitized
}

func sanitizedStringSlice(values []string) []string {
	sanitized := []string{}
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		sanitized = append(sanitized, value)
	}
	return sanitized
}

func emptyStringMap(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}
	return values
}
