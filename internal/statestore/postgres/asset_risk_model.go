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

var _ ports.AssetRiskModelStore = (*Store)(nil)

var ensureAssetRiskModelStatements = []string{
	`CREATE TABLE IF NOT EXISTS asset_risk_models (
  tenant_id TEXT PRIMARY KEY,
  model_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
}

func (s *Store) ensureAssetRiskModelTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.findingIntel.assetRiskModel, "asset risk model", ensureAssetRiskModelStatements)
}

// PutAssetRiskModel upserts one tenant's asset risk model.
func (s *Store) PutAssetRiskModel(ctx context.Context, model *ports.AssetRiskModel) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if model == nil {
		return errors.New("asset risk model is required")
	}
	tenantID := strings.TrimSpace(model.TenantID)
	if tenantID == "" {
		return errors.New("asset risk model tenant_id is required")
	}
	if err := s.ensureAssetRiskModelTable(ctx); err != nil {
		return err
	}
	payload, err := json.Marshal(model)
	if err != nil {
		return fmt.Errorf("marshal asset risk model: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO asset_risk_models (tenant_id, model_json)
VALUES ($1, $2::jsonb)
ON CONFLICT (tenant_id) DO UPDATE SET
  model_json = EXCLUDED.model_json,
  updated_at = NOW()`, tenantID, string(payload)); err != nil {
		return fmt.Errorf("upsert asset risk model for tenant %q: %w", tenantID, err)
	}
	return nil
}

// GetAssetRiskModel loads one tenant's asset risk model.
func (s *Store) GetAssetRiskModel(ctx context.Context, tenantID string) (*ports.AssetRiskModel, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	normalizedTenantID := strings.TrimSpace(tenantID)
	if normalizedTenantID == "" {
		return nil, errors.New("asset risk model tenant_id is required")
	}
	if err := s.ensureAssetRiskModelTable(ctx); err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `SELECT tenant_id, model_json::text, created_at, updated_at FROM asset_risk_models WHERE tenant_id = $1`, normalizedTenantID)
	model, err := scanAssetRiskModel(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrAssetRiskModelNotFound, normalizedTenantID)
		}
		return nil, fmt.Errorf("query asset risk model for tenant %q: %w", normalizedTenantID, err)
	}
	return model, nil
}

// DeleteAssetRiskModel removes one tenant's asset risk model.
func (s *Store) DeleteAssetRiskModel(ctx context.Context, tenantID string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	normalizedTenantID := strings.TrimSpace(tenantID)
	if normalizedTenantID == "" {
		return errors.New("asset risk model tenant_id is required")
	}
	if err := s.ensureAssetRiskModelTable(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM asset_risk_models WHERE tenant_id = $1`, normalizedTenantID); err != nil {
		return fmt.Errorf("delete asset risk model for tenant %q: %w", normalizedTenantID, err)
	}
	return nil
}

func scanAssetRiskModel(scanner riskScoringConfigScanner) (*ports.AssetRiskModel, error) {
	var tenantID string
	var payload string
	var createdAt sql.NullTime
	var updatedAt sql.NullTime
	if err := scanner.Scan(&tenantID, &payload, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	var model ports.AssetRiskModel
	if err := json.Unmarshal([]byte(payload), &model); err != nil {
		return nil, fmt.Errorf("decode asset risk model for tenant %q: %w", tenantID, err)
	}
	model.TenantID = strings.TrimSpace(tenantID)
	if createdAt.Valid {
		model.CreatedAt = createdAt.Time.UTC()
	}
	if updatedAt.Valid {
		model.UpdatedAt = updatedAt.Time.UTC()
	}
	return &model, nil
}
