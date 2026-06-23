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
	var payload string
	if err := tx.QueryRowContext(ctx, `
INSERT INTO connector_definitions (id, tenant_id, source_id, display_name, runtime, stage, current_version, definition_json)
VALUES ($1, $2, $3, $4, $5, $6, 1, jsonb_set($7::jsonb, '{current_version}', to_jsonb(1::integer), true))
ON CONFLICT (id)
DO UPDATE SET source_id = EXCLUDED.source_id,
              display_name = EXCLUDED.display_name,
              runtime = EXCLUDED.runtime,
              stage = EXCLUDED.stage,
              current_version = connector_definitions.current_version + 1,
              definition_json = jsonb_set(EXCLUDED.definition_json, '{current_version}', to_jsonb((connector_definitions.current_version + 1)::integer), true),
              updated_at = NOW()
WHERE connector_definitions.tenant_id = EXCLUDED.tenant_id
RETURNING current_version, definition_json::text, created_at, updated_at`,
		record.ID,
		record.TenantID,
		record.SourceID,
		record.DisplayName,
		record.Runtime,
		record.Stage,
		string(record.DefinitionJSON),
	).Scan(&record.CurrentVersion, &payload, &record.CreatedAt, &record.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("upsert connector definition %q: tenant mismatch or stale write", record.ID)
		}
		return nil, fmt.Errorf("upsert connector definition %q: %w", record.ID, err)
	}
	record.DefinitionJSON = []byte(payload)
	result, err := tx.ExecContext(ctx, `
INSERT INTO connector_definition_versions (definition_id, version, tenant_id, source_id, stage, definition_json)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)
ON CONFLICT (definition_id, version) DO NOTHING`,
		record.ID,
		record.CurrentVersion,
		record.TenantID,
		record.SourceID,
		record.Stage,
		string(record.DefinitionJSON),
	)
	if err != nil {
		return nil, fmt.Errorf("record connector definition version %q/%d: %w", record.ID, record.CurrentVersion, err)
	}
	if inserted, err := result.RowsAffected(); err != nil {
		return nil, fmt.Errorf("check connector definition version insert %q/%d: %w", record.ID, record.CurrentVersion, err)
	} else if inserted != 1 {
		return nil, fmt.Errorf("record connector definition version %q/%d: immutable version already exists", record.ID, record.CurrentVersion)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit connector definition %q: %w", record.ID, err)
	}
	return &record, nil
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

// ListConnectorDefinitionVersions loads the immutable version history for one definition, newest first.
func (s *Store) ListConnectorDefinitionVersions(ctx context.Context, definitionID string) ([]*ports.ConnectorDefinitionVersionRecord, error) {
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
	rows, err := s.db.QueryContext(ctx, `
SELECT definition_id, version, tenant_id, source_id, stage, definition_json::text, created_at
FROM connector_definition_versions
WHERE definition_id = $1
ORDER BY version DESC`, id)
	if err != nil {
		return nil, fmt.Errorf("list connector definition versions %q: %w", id, err)
	}
	defer func() {
		_ = rows.Close()
	}()
	var versions []*ports.ConnectorDefinitionVersionRecord
	for rows.Next() {
		record := &ports.ConnectorDefinitionVersionRecord{}
		var payload string
		if err := rows.Scan(
			&record.DefinitionID,
			&record.Version,
			&record.TenantID,
			&record.SourceID,
			&record.Stage,
			&payload,
			&record.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan connector definition version: %w", err)
		}
		record.DefinitionJSON = []byte(payload)
		versions = append(versions, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate connector definition versions %q: %w", id, err)
	}
	return versions, nil
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
