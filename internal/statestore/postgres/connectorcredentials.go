package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var ensureConnectorCredentialStatements = []string{
	`CREATE TABLE IF NOT EXISTS connector_credentials (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  sealed BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS connector_credentials_tenant_source_idx ON connector_credentials (tenant_id, source_id, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS connector_credentials_runtime_idx ON connector_credentials (runtime_id, updated_at DESC)`,
}

func (s *Store) PutConnectorCredential(ctx context.Context, credential *ports.ConnectorCredentialRecord) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if credential == nil {
		return errors.New("connector credential is required")
	}
	if err := s.ensureConnectorCredentialTable(ctx); err != nil {
		return err
	}
	id := strings.TrimSpace(credential.ID)
	if id == "" {
		return errors.New("connector credential id is required")
	}
	if strings.TrimSpace(credential.TenantID) == "" {
		return errors.New("connector credential tenant id is required")
	}
	if strings.TrimSpace(credential.SourceID) == "" {
		return errors.New("connector credential source id is required")
	}
	if strings.TrimSpace(credential.RuntimeID) == "" {
		return errors.New("connector credential runtime id is required")
	}
	if strings.TrimSpace(credential.KeyID) == "" {
		return errors.New("connector credential key id is required")
	}
	if len(credential.Sealed) == 0 {
		return errors.New("connector credential envelope is required")
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO connector_credentials (id, tenant_id, source_id, runtime_id, key_id, sealed)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (id)
DO UPDATE SET tenant_id = EXCLUDED.tenant_id,
              source_id = EXCLUDED.source_id,
              runtime_id = EXCLUDED.runtime_id,
              key_id = EXCLUDED.key_id,
              sealed = EXCLUDED.sealed,
              updated_at = NOW()`,
		id,
		strings.TrimSpace(credential.TenantID),
		strings.TrimSpace(credential.SourceID),
		strings.TrimSpace(credential.RuntimeID),
		strings.TrimSpace(credential.KeyID),
		credential.Sealed,
	); err != nil {
		return fmt.Errorf("upsert connector credential %q: %w", id, err)
	}
	return nil
}

func (s *Store) GetConnectorCredential(ctx context.Context, credentialID string) (*ports.ConnectorCredentialRecord, error) {
	id := strings.TrimSpace(credentialID)
	if id == "" {
		return nil, errors.New("connector credential id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureConnectorCredentialTable(ctx); err != nil {
		return nil, err
	}
	record := &ports.ConnectorCredentialRecord{ID: id}
	if err := s.db.QueryRowContext(ctx, `
SELECT tenant_id, source_id, runtime_id, key_id, sealed, created_at, updated_at
FROM connector_credentials
WHERE id = $1`, id).Scan(
		&record.TenantID,
		&record.SourceID,
		&record.RuntimeID,
		&record.KeyID,
		&record.Sealed,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrConnectorCredentialNotFound, id)
		}
		return nil, fmt.Errorf("query connector credential %q: %w", id, err)
	}
	return record, nil
}

func (s *Store) ensureConnectorCredentialTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.connectorCredentialReady, "connector credential", ensureConnectorCredentialStatements)
}
