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

var _ ports.ComplianceFrameworkSettingsStore = (*Store)(nil)

var ensureComplianceFrameworkSettingsStatements = []string{
	`CREATE TABLE IF NOT EXISTS compliance_framework_settings (
  tenant_id TEXT PRIMARY KEY,
  enabled_frameworks JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
}

const complianceFrameworkSettingsColumns = `tenant_id, enabled_frameworks::text, created_at, updated_at`

func (s *Store) ensureComplianceFrameworkSettingsTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.complianceFrameworkSettingsReady, "compliance framework settings", ensureComplianceFrameworkSettingsStatements)
}

// PutComplianceFrameworkSettings upserts one tenant's enabled framework list.
func (s *Store) PutComplianceFrameworkSettings(ctx context.Context, settings *ports.ComplianceFrameworkSettings) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if settings == nil {
		return errors.New("compliance framework settings are required")
	}
	tenantID := strings.TrimSpace(settings.TenantID)
	if tenantID == "" {
		return errors.New("compliance framework settings tenant_id is required")
	}
	enabled := settings.EnabledFrameworks
	if enabled == nil {
		enabled = []string{}
	}
	payload, err := json.Marshal(enabled)
	if err != nil {
		return fmt.Errorf("marshal enabled frameworks: %w", err)
	}
	if err := s.ensureComplianceFrameworkSettingsTable(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO compliance_framework_settings (tenant_id, enabled_frameworks)
VALUES ($1, $2::jsonb)
ON CONFLICT (tenant_id) DO UPDATE SET
  enabled_frameworks = EXCLUDED.enabled_frameworks,
  updated_at = NOW()`, tenantID, string(payload)); err != nil {
		return fmt.Errorf("upsert compliance framework settings for tenant %q: %w", tenantID, err)
	}
	return nil
}

// GetComplianceFrameworkSettings loads one tenant's enabled framework list.
func (s *Store) GetComplianceFrameworkSettings(ctx context.Context, tenantID string) (*ports.ComplianceFrameworkSettings, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	normalizedTenantID := strings.TrimSpace(tenantID)
	if normalizedTenantID == "" {
		return nil, errors.New("compliance framework settings tenant_id is required")
	}
	if err := s.ensureComplianceFrameworkSettingsTable(ctx); err != nil {
		return nil, err
	}
	// #nosec G201 -- column list is a fixed constant and tenant remains parameterized.
	row := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT %s FROM compliance_framework_settings WHERE tenant_id = $1", complianceFrameworkSettingsColumns), normalizedTenantID)
	settings, err := scanComplianceFrameworkSettings(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrComplianceFrameworkSettingsNotFound, normalizedTenantID)
		}
		return nil, fmt.Errorf("query compliance framework settings for tenant %q: %w", normalizedTenantID, err)
	}
	return settings, nil
}

func scanComplianceFrameworkSettings(row scanner) (*ports.ComplianceFrameworkSettings, error) {
	var settings ports.ComplianceFrameworkSettings
	var payload string
	var createdAt sql.NullTime
	var updatedAt sql.NullTime
	if err := row.Scan(&settings.TenantID, &payload, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(payload), &settings.EnabledFrameworks); err != nil {
		return nil, fmt.Errorf("decode enabled frameworks for tenant %q: %w", settings.TenantID, err)
	}
	if settings.EnabledFrameworks == nil {
		settings.EnabledFrameworks = []string{}
	}
	if createdAt.Valid {
		settings.CreatedAt = createdAt.Time.UTC()
	}
	if updatedAt.Valid {
		settings.UpdatedAt = updatedAt.Time.UTC()
	}
	return &settings, nil
}
