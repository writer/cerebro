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

var ensureRiskScoringConfigStatements = []string{
	`CREATE TABLE IF NOT EXISTS risk_scoring_configs (
  tenant_id TEXT PRIMARY KEY,
  config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
}

const riskScoringConfigColumns = `tenant_id, config_json::text, created_at, updated_at`

func (s *Store) ensureRiskScoringConfigTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.findingIntel.riskScoringConfig, "risk scoring config", ensureRiskScoringConfigStatements)
}

// PutRiskScoringConfig upserts one tenant-scoped risk scoring override.
func (s *Store) PutRiskScoringConfig(ctx context.Context, config *ports.RiskScoringConfig) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if config == nil {
		return errors.New("risk scoring config is required")
	}
	tenantID := strings.TrimSpace(config.TenantID)
	if tenantID == "" {
		return errors.New("risk scoring config tenant_id is required")
	}
	if err := s.ensureRiskScoringConfigTable(ctx); err != nil {
		return err
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal risk scoring config: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO risk_scoring_configs (tenant_id, config_json)
VALUES ($1, $2::jsonb)
ON CONFLICT (tenant_id) DO UPDATE SET
  config_json = EXCLUDED.config_json,
  updated_at = NOW()`, tenantID, string(payload)); err != nil {
		return fmt.Errorf("upsert risk scoring config for tenant %q: %w", tenantID, err)
	}
	return nil
}

// GetRiskScoringConfig loads one tenant-scoped risk scoring override.
func (s *Store) GetRiskScoringConfig(ctx context.Context, tenantID string) (*ports.RiskScoringConfig, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	normalizedTenantID := strings.TrimSpace(tenantID)
	if normalizedTenantID == "" {
		return nil, errors.New("risk scoring config tenant_id is required")
	}
	if err := s.ensureRiskScoringConfigTable(ctx); err != nil {
		return nil, err
	}
	// #nosec G201 -- column list is a fixed constant and tenant remains parameterized.
	row := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT %s FROM risk_scoring_configs WHERE tenant_id = $1", riskScoringConfigColumns), normalizedTenantID)
	config, err := scanRiskScoringConfig(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrRiskScoringConfigNotFound, normalizedTenantID)
		}
		return nil, fmt.Errorf("query risk scoring config for tenant %q: %w", normalizedTenantID, err)
	}
	return config, nil
}

// DeleteRiskScoringConfig removes one tenant-scoped risk scoring override.
func (s *Store) DeleteRiskScoringConfig(ctx context.Context, tenantID string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	normalizedTenantID := strings.TrimSpace(tenantID)
	if normalizedTenantID == "" {
		return errors.New("risk scoring config tenant_id is required")
	}
	if err := s.ensureRiskScoringConfigTable(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM risk_scoring_configs WHERE tenant_id = $1`, normalizedTenantID); err != nil {
		return fmt.Errorf("delete risk scoring config for tenant %q: %w", normalizedTenantID, err)
	}
	return nil
}

type riskScoringConfigScanner interface {
	Scan(dest ...any) error
}

func scanRiskScoringConfig(scanner riskScoringConfigScanner) (*ports.RiskScoringConfig, error) {
	var tenantID string
	var payload string
	var createdAt sql.NullTime
	var updatedAt sql.NullTime
	if err := scanner.Scan(&tenantID, &payload, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	var config ports.RiskScoringConfig
	if err := json.Unmarshal([]byte(payload), &config); err != nil {
		return nil, fmt.Errorf("decode risk scoring config for tenant %q: %w", tenantID, err)
	}
	config.TenantID = strings.TrimSpace(tenantID)
	if createdAt.Valid {
		config.CreatedAt = createdAt.Time.UTC()
	}
	if updatedAt.Valid {
		config.UpdatedAt = updatedAt.Time.UTC()
	}
	return &config, nil
}

var _ ports.RiskScoringConfigStore = (*Store)(nil)
