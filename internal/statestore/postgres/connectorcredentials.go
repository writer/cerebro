package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/connectorcredentials"
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
	`ALTER TABLE connector_credentials ADD COLUMN IF NOT EXISTS credential_store_id TEXT NOT NULL DEFAULT 'cerebro_vault'`,
	`ALTER TABLE connector_credentials ADD COLUMN IF NOT EXISTS auth_method TEXT NOT NULL DEFAULT 'encrypted_submission'`,
	`ALTER TABLE connector_credentials ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'valid'`,
	`ALTER TABLE connector_credentials ADD COLUMN IF NOT EXISTS fields_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`ALTER TABLE connector_credentials ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE connector_credentials ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE connector_credentials ADD COLUMN IF NOT EXISTS revoked_by TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE connector_credentials ADD COLUMN IF NOT EXISTS previous_credential_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE connector_credentials ADD COLUMN IF NOT EXISTS idempotency_key TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE connector_credentials ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ`,
	`ALTER TABLE connector_credentials ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ`,
	`ALTER TABLE connector_credentials ADD COLUMN IF NOT EXISTS last_validated_at TIMESTAMPTZ`,
	`CREATE INDEX IF NOT EXISTS connector_credentials_tenant_source_idx ON connector_credentials (tenant_id, source_id, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS connector_credentials_runtime_idx ON connector_credentials (runtime_id, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS connector_credentials_status_idx ON connector_credentials (tenant_id, source_id, status, updated_at DESC)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS connector_credentials_idempotency_idx ON connector_credentials (tenant_id, source_id, runtime_id, idempotency_key) WHERE idempotency_key <> ''`,
	`CREATE TABLE IF NOT EXISTS connector_credential_audit_events (
  id TEXT PRIMARY KEY,
  credential_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS connector_credential_audit_credential_idx ON connector_credential_audit_events (credential_id, created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS connector_credential_audit_tenant_source_idx ON connector_credential_audit_events (tenant_id, source_id, created_at DESC)`,
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
	fieldsJSON, err := json.Marshal(normalizeConnectorCredentialFields(credential.Fields))
	if err != nil {
		return fmt.Errorf("encode connector credential fields: %w", err)
	}
	status := strings.TrimSpace(credential.Status)
	if status == "" {
		status = connectorcredentials.StatusValid
	}
	storeID := strings.TrimSpace(credential.CredentialStoreID)
	if storeID == "" {
		storeID = "cerebro_vault"
	}
	authMethod := strings.TrimSpace(credential.AuthMethod)
	if authMethod == "" {
		authMethod = "encrypted_submission"
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO connector_credentials (
  id, tenant_id, source_id, runtime_id, credential_store_id, auth_method, status, key_id,
  fields_json, sealed, created_by, updated_by, revoked_by, previous_credential_id, idempotency_key,
  revoked_at, last_used_at, last_validated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13, $14, $15, $16, $17, $18)
ON CONFLICT (id)
DO UPDATE SET tenant_id = EXCLUDED.tenant_id,
              source_id = EXCLUDED.source_id,
              runtime_id = EXCLUDED.runtime_id,
              credential_store_id = EXCLUDED.credential_store_id,
              auth_method = EXCLUDED.auth_method,
              status = EXCLUDED.status,
              key_id = EXCLUDED.key_id,
              fields_json = EXCLUDED.fields_json,
              sealed = EXCLUDED.sealed,
              created_by = EXCLUDED.created_by,
              updated_by = EXCLUDED.updated_by,
              revoked_by = EXCLUDED.revoked_by,
              previous_credential_id = EXCLUDED.previous_credential_id,
              idempotency_key = EXCLUDED.idempotency_key,
              revoked_at = EXCLUDED.revoked_at,
              last_used_at = EXCLUDED.last_used_at,
              last_validated_at = EXCLUDED.last_validated_at,
              updated_at = NOW()`,
		id,
		strings.TrimSpace(credential.TenantID),
		strings.TrimSpace(credential.SourceID),
		strings.TrimSpace(credential.RuntimeID),
		storeID,
		authMethod,
		status,
		strings.TrimSpace(credential.KeyID),
		string(fieldsJSON),
		credential.Sealed,
		strings.TrimSpace(credential.CreatedBy),
		strings.TrimSpace(credential.UpdatedBy),
		strings.TrimSpace(credential.RevokedBy),
		strings.TrimSpace(credential.PreviousCredentialID),
		strings.TrimSpace(credential.IdempotencyKey),
		nullableTime(credential.RevokedAt),
		nullableTime(credential.LastUsedAt),
		nullableTime(credential.LastValidatedAt),
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
	record, err := scanConnectorCredentialRecord(s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, source_id, runtime_id, credential_store_id, auth_method, status, key_id,
       fields_json, sealed, created_by, updated_by, revoked_by, previous_credential_id, idempotency_key,
       created_at, updated_at, revoked_at, last_used_at, last_validated_at
FROM connector_credentials
WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrConnectorCredentialNotFound, id)
		}
		return nil, fmt.Errorf("query connector credential %q: %w", id, err)
	}
	return record, nil
}

func (s *Store) ListConnectorCredentials(ctx context.Context, filter ports.ConnectorCredentialFilter) ([]*ports.ConnectorCredentialRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureConnectorCredentialTable(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1 = 1"}
	args := []any{}
	addClause := func(column string, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	addClause("id", filter.ID)
	addClause("tenant_id", filter.TenantID)
	addClause("source_id", filter.SourceID)
	addClause("runtime_id", filter.RuntimeID)
	addClause("status", filter.Status)
	addClause("idempotency_key", filter.IdempotencyKey)
	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
SELECT id, tenant_id, source_id, runtime_id, credential_store_id, auth_method, status, key_id,
       fields_json, sealed, created_by, updated_by, revoked_by, previous_credential_id, idempotency_key,
       created_at, updated_at, revoked_at, last_used_at, last_validated_at
FROM connector_credentials
WHERE %s
ORDER BY updated_at DESC, created_at DESC
LIMIT $%d`, strings.Join(clauses, " AND "), len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list connector credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.ConnectorCredentialRecord{}
	for rows.Next() {
		record, err := scanConnectorCredentialRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate connector credentials: %w", err)
	}
	return records, nil
}

func (s *Store) UpdateConnectorCredentialMetadata(ctx context.Context, credentialID string, update ports.ConnectorCredentialMetadataUpdate) (*ports.ConnectorCredentialRecord, error) {
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
	assignments := []string{"updated_at = NOW()"}
	args := []any{}
	addString := func(column string, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		args = append(args, value)
		assignments = append(assignments, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	addString("status", update.Status)
	addString("updated_by", update.UpdatedBy)
	addString("revoked_by", update.RevokedBy)
	addString("previous_credential_id", update.PreviousCredentialID)
	if update.Fields != nil {
		fieldsJSON, err := json.Marshal(normalizeConnectorCredentialFields(update.Fields))
		if err != nil {
			return nil, fmt.Errorf("encode connector credential fields: %w", err)
		}
		args = append(args, string(fieldsJSON))
		assignments = append(assignments, fmt.Sprintf("fields_json = $%d::jsonb", len(args)))
	}
	addTime := func(column string, value *time.Time) {
		if value == nil {
			return
		}
		args = append(args, nullableTime(*value))
		assignments = append(assignments, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	addTime("revoked_at", update.RevokedAt)
	addTime("last_used_at", update.LastUsedAt)
	addTime("last_validated_at", update.LastValidatedAt)
	args = append(args, id)
	result, err := s.db.ExecContext(ctx, fmt.Sprintf("UPDATE connector_credentials SET %s WHERE id = $%d", strings.Join(assignments, ", "), len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("update connector credential %q: %w", id, err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return nil, fmt.Errorf("%w: %s", ports.ErrConnectorCredentialNotFound, id)
	}
	return s.GetConnectorCredential(ctx, id)
}

func (s *Store) MarkConnectorCredentialUsed(ctx context.Context, credentialID string, usedAt time.Time, staleBefore time.Time) (*ports.ConnectorCredentialRecord, bool, error) {
	id := strings.TrimSpace(credentialID)
	if id == "" {
		return nil, false, errors.New("connector credential id is required")
	}
	if s == nil || s.db == nil {
		return nil, false, errors.New("postgres is not configured")
	}
	if err := s.ensureConnectorCredentialTable(ctx); err != nil {
		return nil, false, err
	}
	if usedAt.IsZero() {
		usedAt = time.Now().UTC()
	}
	if staleBefore.IsZero() {
		staleBefore = usedAt.Add(-time.Hour)
	}
	record, err := scanConnectorCredentialRecord(s.db.QueryRowContext(ctx, `
UPDATE connector_credentials
SET last_used_at = $2, updated_at = $2
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at <= $3)
RETURNING id, tenant_id, source_id, runtime_id, credential_store_id, auth_method, status, key_id,
       fields_json, sealed, created_by, updated_by, revoked_by, previous_credential_id, idempotency_key,
       created_at, updated_at, revoked_at, last_used_at, last_validated_at`, id, usedAt.UTC(), staleBefore.UTC()))
	if err == nil {
		return record, true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		record, getErr := s.GetConnectorCredential(ctx, id)
		if getErr != nil {
			return nil, false, getErr
		}
		return record, false, nil
	}
	return nil, false, fmt.Errorf("mark connector credential used %q: %w", id, err)
}

func (s *Store) AppendConnectorCredentialAuditEvent(ctx context.Context, event *ports.ConnectorCredentialAuditRecord) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if event == nil {
		return errors.New("connector credential audit event is required")
	}
	if err := s.ensureConnectorCredentialTable(ctx); err != nil {
		return err
	}
	id := strings.TrimSpace(event.ID)
	if id == "" {
		id = fmt.Sprintf("credential-audit-%d", time.Now().UnixNano())
	}
	if strings.TrimSpace(event.CredentialID) == "" {
		return errors.New("connector credential audit credential id is required")
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO connector_credential_audit_events (
  id, credential_id, tenant_id, source_id, runtime_id, event_type, actor, status, detail, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, COALESCE($10::timestamptz, NOW()))`,
		id,
		strings.TrimSpace(event.CredentialID),
		strings.TrimSpace(event.TenantID),
		strings.TrimSpace(event.SourceID),
		strings.TrimSpace(event.RuntimeID),
		strings.TrimSpace(event.EventType),
		strings.TrimSpace(event.Actor),
		strings.TrimSpace(event.Status),
		strings.TrimSpace(event.Detail),
		nullableTime(event.CreatedAt),
	); err != nil {
		return fmt.Errorf("append connector credential audit event %q: %w", id, err)
	}
	return nil
}

func (s *Store) ListConnectorCredentialAuditEvents(ctx context.Context, credentialID string, limit int) ([]*ports.ConnectorCredentialAuditRecord, error) {
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
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, credential_id, tenant_id, source_id, runtime_id, event_type, actor, status, detail, created_at
FROM connector_credential_audit_events
WHERE credential_id = $1
ORDER BY created_at DESC
LIMIT $2`, id, limit)
	if err != nil {
		return nil, fmt.Errorf("list connector credential audit events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	events := []*ports.ConnectorCredentialAuditRecord{}
	for rows.Next() {
		event := &ports.ConnectorCredentialAuditRecord{}
		if err := rows.Scan(
			&event.ID,
			&event.CredentialID,
			&event.TenantID,
			&event.SourceID,
			&event.RuntimeID,
			&event.EventType,
			&event.Actor,
			&event.Status,
			&event.Detail,
			&event.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan connector credential audit event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate connector credential audit events: %w", err)
	}
	return events, nil
}

func (s *Store) ensureConnectorCredentialTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.connectorCredentialReady, "connector credential", ensureConnectorCredentialStatements)
}

type connectorCredentialScanner interface {
	Scan(dest ...any) error
}

func scanConnectorCredentialRecord(scanner connectorCredentialScanner) (*ports.ConnectorCredentialRecord, error) {
	record := &ports.ConnectorCredentialRecord{}
	var fieldsJSON []byte
	var createdBy sql.NullString
	var updatedBy sql.NullString
	var revokedBy sql.NullString
	var previousCredentialID sql.NullString
	var idempotencyKey sql.NullString
	var revokedAt sql.NullTime
	var lastUsedAt sql.NullTime
	var lastValidatedAt sql.NullTime
	if err := scanner.Scan(
		&record.ID,
		&record.TenantID,
		&record.SourceID,
		&record.RuntimeID,
		&record.CredentialStoreID,
		&record.AuthMethod,
		&record.Status,
		&record.KeyID,
		&fieldsJSON,
		&record.Sealed,
		&createdBy,
		&updatedBy,
		&revokedBy,
		&previousCredentialID,
		&idempotencyKey,
		&record.CreatedAt,
		&record.UpdatedAt,
		&revokedAt,
		&lastUsedAt,
		&lastValidatedAt,
	); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(fieldsJSON, &record.Fields); err != nil {
		return nil, fmt.Errorf("decode connector credential fields: %w", err)
	}
	record.Fields = normalizeConnectorCredentialFields(record.Fields)
	record.CreatedBy = createdBy.String
	record.UpdatedBy = updatedBy.String
	record.RevokedBy = revokedBy.String
	record.PreviousCredentialID = previousCredentialID.String
	record.IdempotencyKey = idempotencyKey.String
	if revokedAt.Valid {
		record.RevokedAt = revokedAt.Time
	}
	if lastUsedAt.Valid {
		record.LastUsedAt = lastUsedAt.Time
	}
	if lastValidatedAt.Valid {
		record.LastValidatedAt = lastValidatedAt.Time
	}
	return record, nil
}

func normalizeConnectorCredentialFields(fields []string) []string {
	seen := map[string]struct{}{}
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		seen[field] = struct{}{}
	}
	normalized := make([]string, 0, len(seen))
	for field := range seen {
		normalized = append(normalized, field)
	}
	sort.Strings(normalized)
	return normalized
}
