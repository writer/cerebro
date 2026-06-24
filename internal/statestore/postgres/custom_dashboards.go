package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var _ ports.CustomDashboardStore = (*Store)(nil)

var ensureCustomDashboardStatements = []string{
	`CREATE TABLE IF NOT EXISTS custom_dashboards (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  organization_id TEXT NOT NULL DEFAULT '',
  workspace_id TEXT NOT NULL DEFAULT '',
  owner_user_id TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  visibility TEXT NOT NULL DEFAULT 'private',
  schema_version INTEGER NOT NULL DEFAULT 1,
  layout_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  widgets_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  filters_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  archived_at TIMESTAMPTZ
)`,
	`CREATE INDEX IF NOT EXISTS custom_dashboards_tenant_updated_idx ON custom_dashboards (tenant_id, updated_at DESC) WHERE archived_at IS NULL`,
	`CREATE INDEX IF NOT EXISTS custom_dashboards_workspace_updated_idx ON custom_dashboards (tenant_id, workspace_id, updated_at DESC) WHERE workspace_id <> '' AND archived_at IS NULL`,
	`CREATE INDEX IF NOT EXISTS custom_dashboards_owner_updated_idx ON custom_dashboards (tenant_id, owner_user_id, updated_at DESC) WHERE owner_user_id <> '' AND archived_at IS NULL`,
}

const customDashboardColumns = `id, tenant_id, organization_id, workspace_id, owner_user_id, name, description, visibility, schema_version, layout_json::text, widgets_json::text, filters_json::text, created_by, updated_by, created_at, updated_at, archived_at`

func (s *Store) ensureCustomDashboardTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.customDashboards, "custom dashboards", ensureCustomDashboardStatements)
}

func (s *Store) PutCustomDashboard(ctx context.Context, dashboard *ports.CustomDashboard) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if dashboard == nil {
		return errors.New("custom dashboard is required")
	}
	id := strings.TrimSpace(dashboard.ID)
	tenantID := strings.TrimSpace(dashboard.TenantID)
	name := strings.TrimSpace(dashboard.Name)
	if id == "" || tenantID == "" || name == "" {
		return errors.New("custom dashboard id, tenant_id, and name are required")
	}
	if err := s.ensureCustomDashboardTables(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO custom_dashboards (
  id, tenant_id, organization_id, workspace_id, owner_user_id, name, description,
  visibility, schema_version, layout_json, widgets_json, filters_json, created_by, updated_by
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12::jsonb, $13, $14)
ON CONFLICT (id) DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  organization_id = EXCLUDED.organization_id,
  workspace_id = EXCLUDED.workspace_id,
  owner_user_id = EXCLUDED.owner_user_id,
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  visibility = EXCLUDED.visibility,
  schema_version = EXCLUDED.schema_version,
  layout_json = EXCLUDED.layout_json,
  widgets_json = EXCLUDED.widgets_json,
  filters_json = EXCLUDED.filters_json,
  updated_by = EXCLUDED.updated_by,
  updated_at = NOW()`,
		id,
		tenantID,
		strings.TrimSpace(dashboard.OrganizationID),
		strings.TrimSpace(dashboard.WorkspaceID),
		strings.TrimSpace(dashboard.OwnerUserID),
		name,
		strings.TrimSpace(dashboard.Description),
		normalizeDashboardVisibility(dashboard.Visibility),
		normalizeDashboardSchemaVersion(dashboard.SchemaVersion),
		normalizeDashboardJSON(dashboard.LayoutJSON, "{}"),
		normalizeDashboardJSON(dashboard.WidgetsJSON, "[]"),
		normalizeDashboardJSON(dashboard.FiltersJSON, "{}"),
		strings.TrimSpace(dashboard.CreatedBy),
		strings.TrimSpace(dashboard.UpdatedBy),
	); err != nil {
		return fmt.Errorf("upsert custom dashboard %q: %w", id, err)
	}
	return nil
}

func (s *Store) GetCustomDashboard(ctx context.Context, dashboardID string) (*ports.CustomDashboard, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	id := strings.TrimSpace(dashboardID)
	if id == "" {
		return nil, errors.New("custom dashboard id is required")
	}
	if err := s.ensureCustomDashboardTables(ctx); err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT %s FROM custom_dashboards WHERE id = $1", customDashboardColumns), id)
	dashboard, err := scanCustomDashboard(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrCustomDashboardNotFound, id)
		}
		return nil, fmt.Errorf("query custom dashboard %q: %w", id, err)
	}
	return dashboard, nil
}

func (s *Store) ListCustomDashboards(ctx context.Context, filter ports.CustomDashboardFilter) ([]*ports.CustomDashboard, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureCustomDashboardTables(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1=1"}
	args := []any{}
	addStringClause := func(column string, value string) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return
		}
		args = append(args, trimmed)
		clauses = append(clauses, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	addStringClause("tenant_id", filter.TenantID)
	addStringClause("organization_id", filter.OrganizationID)
	addStringClause("workspace_id", filter.WorkspaceID)
	addStringClause("owner_user_id", filter.OwnerUserID)
	if !filter.IncludeArchived {
		clauses = append(clauses, "archived_at IS NULL")
	}
	args = append(args, customDashboardListLimit(filter.Limit))
	// #nosec G201 -- clauses use static column names and positional placeholders; values stay parameterized.
	query := fmt.Sprintf("SELECT %s FROM custom_dashboards WHERE %s ORDER BY updated_at DESC, id ASC LIMIT $%d", customDashboardColumns, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list custom dashboards: %w", err)
	}
	defer func() { _ = rows.Close() }()
	dashboards := []*ports.CustomDashboard{}
	for rows.Next() {
		item, err := scanCustomDashboard(rows)
		if err != nil {
			return nil, err
		}
		dashboards = append(dashboards, item)
	}
	return dashboards, rows.Err()
}

func (s *Store) DeleteCustomDashboard(ctx context.Context, dashboardID string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	id := strings.TrimSpace(dashboardID)
	if id == "" {
		return errors.New("custom dashboard id is required")
	}
	if err := s.ensureCustomDashboardTables(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE custom_dashboards SET archived_at = NOW(), updated_at = NOW() WHERE id = $1`, id); err != nil {
		return fmt.Errorf("archive custom dashboard %q: %w", id, err)
	}
	return nil
}

func customDashboardListLimit(limit uint32) uint32 {
	const (
		defaultLimit uint32 = 100
		maxLimit     uint32 = 500
	)
	switch {
	case limit == 0:
		return defaultLimit
	case limit > maxLimit:
		return maxLimit
	default:
		return limit
	}
}

func normalizeDashboardVisibility(visibility string) string {
	switch strings.ToLower(strings.TrimSpace(visibility)) {
	case "workspace", "organization":
		return strings.ToLower(strings.TrimSpace(visibility))
	default:
		return "private"
	}
}

func normalizeDashboardSchemaVersion(version int) int {
	if version <= 0 {
		return 1
	}
	return version
}

func normalizeDashboardJSON(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func scanCustomDashboard(row scanner) (*ports.CustomDashboard, error) {
	var dashboard ports.CustomDashboard
	var archivedAt sql.NullTime
	if err := row.Scan(
		&dashboard.ID,
		&dashboard.TenantID,
		&dashboard.OrganizationID,
		&dashboard.WorkspaceID,
		&dashboard.OwnerUserID,
		&dashboard.Name,
		&dashboard.Description,
		&dashboard.Visibility,
		&dashboard.SchemaVersion,
		&dashboard.LayoutJSON,
		&dashboard.WidgetsJSON,
		&dashboard.FiltersJSON,
		&dashboard.CreatedBy,
		&dashboard.UpdatedBy,
		&dashboard.CreatedAt,
		&dashboard.UpdatedAt,
		&archivedAt,
	); err != nil {
		return nil, err
	}
	if archivedAt.Valid {
		dashboard.ArchivedAt = archivedAt.Time
	}
	return &dashboard, nil
}
