package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var ensureConnectorDefinitionStatements = []string{
	`CREATE TABLE IF NOT EXISTS connector_definitions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  runtime TEXT NOT NULL,
  stage TEXT NOT NULL,
  current_version INTEGER NOT NULL,
  definition_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE TABLE IF NOT EXISTS connector_definition_versions (
  definition_id TEXT NOT NULL REFERENCES connector_definitions(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  definition_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (definition_id, version)
)`,
	`CREATE INDEX IF NOT EXISTS connector_definitions_tenant_stage_idx ON connector_definitions (tenant_id, stage, updated_at DESC, id ASC)`,
	`CREATE INDEX IF NOT EXISTS connector_definitions_source_idx ON connector_definitions (source_id, updated_at DESC)`,
}

// PutConnectorDefinition upserts a connector definition and records an immutable version snapshot.
func (s *Store) PutConnectorDefinition(ctx context.Context, definition *ports.ConnectorDefinitionRecord) (*ports.ConnectorDefinitionRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := validateConnectorDefinitionRecord(definition); err != nil {
		return nil, err
	}
	if err := s.ensureConnectorDefinitionTable(ctx); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin connector definition upsert: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	record := *definition
	if record.CurrentVersion <= 0 {
		if err := tx.QueryRowContext(ctx, `SELECT current_version FROM connector_definitions WHERE id = $1`, record.ID).Scan(&record.CurrentVersion); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				record.CurrentVersion = 1
			} else {
				return nil, fmt.Errorf("read connector definition version %q: %w", record.ID, err)
			}
		} else {
			record.CurrentVersion++
		}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO connector_definitions (id, tenant_id, source_id, display_name, runtime, stage, current_version, definition_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
ON CONFLICT (id)
DO UPDATE SET tenant_id = EXCLUDED.tenant_id,
              source_id = EXCLUDED.source_id,
              display_name = EXCLUDED.display_name,
              runtime = EXCLUDED.runtime,
              stage = EXCLUDED.stage,
              current_version = EXCLUDED.current_version,
              definition_json = EXCLUDED.definition_json,
              updated_at = NOW()`,
		record.ID,
		record.TenantID,
		record.SourceID,
		record.DisplayName,
		record.Runtime,
		record.Stage,
		record.CurrentVersion,
		string(record.DefinitionJSON),
	); err != nil {
		return nil, fmt.Errorf("upsert connector definition %q: %w", record.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO connector_definition_versions (definition_id, version, tenant_id, source_id, stage, definition_json)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)
ON CONFLICT (definition_id, version)
DO UPDATE SET tenant_id = EXCLUDED.tenant_id,
              source_id = EXCLUDED.source_id,
              stage = EXCLUDED.stage,
              definition_json = EXCLUDED.definition_json`,
		record.ID,
		record.CurrentVersion,
		record.TenantID,
		record.SourceID,
		record.Stage,
		string(record.DefinitionJSON),
	); err != nil {
		return nil, fmt.Errorf("record connector definition version %q/%d: %w", record.ID, record.CurrentVersion, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit connector definition %q: %w", record.ID, err)
	}
	return s.GetConnectorDefinition(ctx, record.ID)
}

// GetConnectorDefinition loads one connector definition.
func (s *Store) GetConnectorDefinition(ctx context.Context, definitionID string) (*ports.ConnectorDefinitionRecord, error) {
	id := strings.TrimSpace(definitionID)
	if id == "" {
		return nil, errors.New("connector definition id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureConnectorDefinitionTable(ctx); err != nil {
		return nil, err
	}
	record := &ports.ConnectorDefinitionRecord{ID: id}
	var payload string
	if err := s.db.QueryRowContext(ctx, `
SELECT tenant_id, source_id, display_name, runtime, stage, current_version, definition_json::text, created_at, updated_at
FROM connector_definitions
WHERE id = $1`, id).Scan(
		&record.TenantID,
		&record.SourceID,
		&record.DisplayName,
		&record.Runtime,
		&record.Stage,
		&record.CurrentVersion,
		&payload,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrConnectorDefinitionNotFound, id)
		}
		return nil, fmt.Errorf("query connector definition %q: %w", id, err)
	}
	record.DefinitionJSON = []byte(payload)
	return record, nil
}

// ListConnectorDefinitions loads persisted connector definition current versions.
func (s *Store) ListConnectorDefinitions(ctx context.Context, filter ports.ConnectorDefinitionFilter) ([]*ports.ConnectorDefinitionRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureConnectorDefinitionTable(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1=1"}
	args := []any{}
	if tenantID := strings.TrimSpace(filter.TenantID); tenantID != "" {
		args = append(args, tenantID)
		clauses = append(clauses, fmt.Sprintf("tenant_id = $%d", len(args)))
	}
	if stage := strings.TrimSpace(filter.Stage); stage != "" {
		args = append(args, stage)
		clauses = append(clauses, fmt.Sprintf("stage = $%d", len(args)))
	}
	limit := filter.Limit
	if limit == 0 || limit > 500 {
		limit = 500
	}
	args = append(args, limit)
	// #nosec G201 -- clauses are fixed predicates; values remain parameterized.
	query := fmt.Sprintf(`
SELECT id, tenant_id, source_id, display_name, runtime, stage, current_version, definition_json::text, created_at, updated_at
FROM connector_definitions
WHERE %s
ORDER BY updated_at DESC, id ASC
LIMIT $%d`, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list connector definitions: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()
	var definitions []*ports.ConnectorDefinitionRecord
	for rows.Next() {
		record := &ports.ConnectorDefinitionRecord{}
		var payload string
		if err := rows.Scan(
			&record.ID,
			&record.TenantID,
			&record.SourceID,
			&record.DisplayName,
			&record.Runtime,
			&record.Stage,
			&record.CurrentVersion,
			&payload,
			&record.CreatedAt,
			&record.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan connector definition: %w", err)
		}
		record.DefinitionJSON = []byte(payload)
		definitions = append(definitions, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate connector definitions: %w", err)
	}
	return definitions, nil
}

func (s *Store) ensureConnectorDefinitionTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.connectorDefinitionReady, "connector definition", ensureConnectorDefinitionStatements)
}

func validateConnectorDefinitionRecord(record *ports.ConnectorDefinitionRecord) error {
	if record == nil {
		return errors.New("connector definition is required")
	}
	if strings.TrimSpace(record.ID) == "" {
		return errors.New("connector definition id is required")
	}
	if strings.TrimSpace(record.TenantID) == "" {
		return errors.New("connector definition tenant id is required")
	}
	if strings.TrimSpace(record.SourceID) == "" {
		return errors.New("connector definition source id is required")
	}
	if strings.TrimSpace(record.DisplayName) == "" {
		return errors.New("connector definition display name is required")
	}
	if strings.TrimSpace(record.Runtime) == "" {
		return errors.New("connector definition runtime is required")
	}
	if strings.TrimSpace(record.Stage) == "" {
		return errors.New("connector definition stage is required")
	}
	if len(record.DefinitionJSON) == 0 {
		return errors.New("connector definition payload is required")
	}
	return nil
}
