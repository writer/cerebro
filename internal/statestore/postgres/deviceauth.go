package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/deviceauth"
)

var ensureDeviceAuthStatements = []string{
	`CREATE TABLE IF NOT EXISTS device_records (
  device_id TEXT PRIMARY KEY,
  hardware_uuid TEXT NOT NULL,
  serial_number TEXT NOT NULL DEFAULT '',
  hostname TEXT NOT NULL DEFAULT '',
  tenant_id TEXT NOT NULL,
  os_type TEXT NOT NULL DEFAULT '',
  os_version TEXT NOT NULL DEFAULT '',
  agent_version TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  enrolled_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  revoked_reason TEXT NOT NULL DEFAULT '',
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS device_records_tenant_hwuuid_idx ON device_records (tenant_id, hardware_uuid)`,
	`CREATE INDEX IF NOT EXISTS device_records_tenant_idx ON device_records (tenant_id)`,
	`CREATE INDEX IF NOT EXISTS device_records_status_idx ON device_records (status)`,

	`CREATE TABLE IF NOT EXISTS device_bootstrap_tokens (
  token_hash BYTEA PRIMARY KEY,
  token_id TEXT NOT NULL UNIQUE,
  hardware_uuid TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  scopes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  consumed_by TEXT NOT NULL DEFAULT ''
)`,
	`CREATE INDEX IF NOT EXISTS device_bootstrap_tokens_tenant_idx ON device_bootstrap_tokens (tenant_id)`,
	`CREATE INDEX IF NOT EXISTS device_bootstrap_tokens_expires_idx ON device_bootstrap_tokens (expires_at)`,

	`CREATE TABLE IF NOT EXISTS device_refresh_tokens (
  token_hash BYTEA PRIMARY KEY,
  device_id TEXT NOT NULL,
  family_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  scopes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  family_revoked BOOLEAN NOT NULL DEFAULT FALSE,
  superseded BOOLEAN NOT NULL DEFAULT FALSE
)`,
	`CREATE INDEX IF NOT EXISTS device_refresh_tokens_device_idx ON device_refresh_tokens (device_id)`,
	`CREATE INDEX IF NOT EXISTS device_refresh_tokens_family_idx ON device_refresh_tokens (family_id)`,
	`CREATE INDEX IF NOT EXISTS device_refresh_tokens_expires_idx ON device_refresh_tokens (expires_at)`,

	`CREATE TABLE IF NOT EXISTS device_idempotency_keys (
  cache_key TEXT PRIMARY KEY,
  request_hash BYTEA NOT NULL,
  response_status INTEGER NOT NULL,
  response_body BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS device_idempotency_keys_expires_idx ON device_idempotency_keys (expires_at)`,
}

// EnrollDevice inserts or replaces a device row. Conflict on
// (tenant_id, hardware_uuid) replaces the existing row's identity columns
// and resets status to active.
func (s *Store) EnrollDevice(ctx context.Context, device deviceauth.DeviceRecord) (deviceauth.DeviceRecord, error) {
	if err := s.ensureDeviceAuthTables(ctx); err != nil {
		return deviceauth.DeviceRecord{}, err
	}
	deviceID := strings.TrimSpace(device.DeviceID)
	if deviceID == "" {
		return deviceauth.DeviceRecord{}, errors.New("device_id is required")
	}
	hardwareUUID := strings.TrimSpace(device.HardwareUUID)
	if hardwareUUID == "" {
		return deviceauth.DeviceRecord{}, errors.New("hardware_uuid is required")
	}
	tenantID := strings.TrimSpace(device.TenantID)
	if tenantID == "" {
		return deviceauth.DeviceRecord{}, errors.New("tenant_id is required")
	}
	metadata, err := metadataJSON(device.Metadata)
	if err != nil {
		return deviceauth.DeviceRecord{}, fmt.Errorf("marshal device metadata: %w", err)
	}
	enrolledAt := nullableUTC(device.EnrolledAt)
	lastSeen := nullableUTC(device.LastSeenAt)
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO device_records (
  device_id, hardware_uuid, serial_number, hostname, tenant_id,
  os_type, os_version, agent_version, status, enrolled_at, last_seen_at, metadata_json
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)
ON CONFLICT (tenant_id, hardware_uuid)
DO UPDATE SET
  device_id = EXCLUDED.device_id,
  serial_number = EXCLUDED.serial_number,
  hostname = EXCLUDED.hostname,
  os_type = EXCLUDED.os_type,
  os_version = EXCLUDED.os_version,
  agent_version = EXCLUDED.agent_version,
  status = 'active',
  revoked_at = NULL,
  revoked_reason = '',
  enrolled_at = EXCLUDED.enrolled_at,
  last_seen_at = EXCLUDED.last_seen_at,
  metadata_json = EXCLUDED.metadata_json,
  updated_at = NOW()
`,
		deviceID,
		hardwareUUID,
		strings.TrimSpace(device.SerialNumber),
		strings.TrimSpace(device.Hostname),
		tenantID,
		strings.TrimSpace(device.OSType),
		strings.TrimSpace(device.OSVersion),
		strings.TrimSpace(device.AgentVersion),
		deviceStatus(device.Status),
		enrolledAt,
		lastSeen,
		metadata,
	); err != nil {
		return deviceauth.DeviceRecord{}, fmt.Errorf("upsert device %q: %w", deviceID, err)
	}
	return s.LookupDeviceByHardware(ctx, tenantID, hardwareUUID)
}

// LookupDeviceByHardware returns the canonical row by (tenant_id, hardware_uuid).
func (s *Store) LookupDeviceByHardware(ctx context.Context, tenantID string, hardwareUUID string) (deviceauth.DeviceRecord, error) {
	if err := s.ensureDeviceAuthTables(ctx); err != nil {
		return deviceauth.DeviceRecord{}, err
	}
	row := s.db.QueryRowContext(ctx, `
SELECT device_id, hardware_uuid, serial_number, hostname, tenant_id,
       os_type, os_version, agent_version, status,
       enrolled_at, last_seen_at, revoked_at, metadata_json::text
FROM device_records
WHERE tenant_id = $1 AND hardware_uuid = $2`,
		strings.TrimSpace(tenantID), strings.TrimSpace(hardwareUUID))
	return scanDeviceRow(row)
}

// LookupDevice returns a device by its primary key.
func (s *Store) LookupDevice(ctx context.Context, deviceID string) (deviceauth.DeviceRecord, error) {
	if err := s.ensureDeviceAuthTables(ctx); err != nil {
		return deviceauth.DeviceRecord{}, err
	}
	row := s.db.QueryRowContext(ctx, `
SELECT device_id, hardware_uuid, serial_number, hostname, tenant_id,
       os_type, os_version, agent_version, status,
       enrolled_at, last_seen_at, revoked_at, metadata_json::text
FROM device_records
WHERE device_id = $1`,
		strings.TrimSpace(deviceID))
	return scanDeviceRow(row)
}

// MarkSeen updates last_seen_at on the device row.
func (s *Store) MarkSeen(ctx context.Context, deviceID string, at time.Time) error {
	if err := s.ensureDeviceAuthTables(ctx); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE device_records SET last_seen_at = $2, updated_at = NOW() WHERE device_id = $1`, strings.TrimSpace(deviceID), at.UTC())
	if err != nil {
		return fmt.Errorf("mark seen %q: %w", deviceID, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return deviceauth.ErrDeviceNotFound
	}
	return nil
}

// RevokeDevice flips the device status and records the revoke time.
func (s *Store) RevokeDevice(ctx context.Context, deviceID string, at time.Time, reason string) error {
	if err := s.ensureDeviceAuthTables(ctx); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE device_records
SET status = 'revoked', revoked_at = $2, revoked_reason = $3, updated_at = NOW()
WHERE device_id = $1`, strings.TrimSpace(deviceID), at.UTC(), strings.TrimSpace(reason))
	if err != nil {
		return fmt.Errorf("revoke device %q: %w", deviceID, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return deviceauth.ErrDeviceNotFound
	}
	return nil
}

// CreateBootstrapToken inserts a new bootstrap-token row.
func (s *Store) CreateBootstrapToken(ctx context.Context, token deviceauth.BootstrapToken) error {
	if err := s.ensureDeviceAuthTables(ctx); err != nil {
		return err
	}
	scopes, err := stringSliceJSON(token.Scopes)
	if err != nil {
		return fmt.Errorf("marshal bootstrap scopes: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO device_bootstrap_tokens (token_hash, token_id, hardware_uuid, tenant_id, scopes_json, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
		token.TokenHash[:],
		strings.TrimSpace(token.TokenID),
		strings.TrimSpace(token.HardwareUUID),
		strings.TrimSpace(token.TenantID),
		scopes,
		nullableUTC(token.CreatedAt),
		nullableUTC(token.ExpiresAt),
	); err != nil {
		return fmt.Errorf("create bootstrap token %q: %w", token.TokenID, err)
	}
	return nil
}

// ConsumeBootstrapToken atomically validates and consumes a bootstrap token.
func (s *Store) ConsumeBootstrapToken(ctx context.Context, hash [32]byte, hardwareUUID string, at time.Time, by string) (deviceauth.BootstrapToken, error) {
	if err := s.ensureDeviceAuthTables(ctx); err != nil {
		return deviceauth.BootstrapToken{}, err
	}
	var result deviceauth.BootstrapToken
	err := s.runInTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
SELECT token_id, hardware_uuid, tenant_id, scopes_json::text, created_at, expires_at, consumed_at, consumed_by
FROM device_bootstrap_tokens
WHERE token_hash = $1
FOR UPDATE`, hash[:])
		var (
			tokenID    string
			hwUUID     string
			tenantID   string
			scopesJSON string
			createdAt  time.Time
			expiresAt  time.Time
			consumedAt sql.NullTime
			consumedBy string
		)
		if err := row.Scan(&tokenID, &hwUUID, &tenantID, &scopesJSON, &createdAt, &expiresAt, &consumedAt, &consumedBy); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return deviceauth.ErrBootstrapTokenNotFound
			}
			return fmt.Errorf("select bootstrap token: %w", err)
		}
		if consumedAt.Valid {
			return deviceauth.ErrBootstrapTokenConsumed
		}
		if !expiresAt.IsZero() && at.After(expiresAt) {
			return deviceauth.ErrBootstrapTokenExpired
		}
		if hwUUID != "" && hwUUID != strings.TrimSpace(hardwareUUID) {
			return deviceauth.ErrBootstrapTokenMismatch
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE device_bootstrap_tokens
SET consumed_at = $2, consumed_by = $3
WHERE token_hash = $1`, hash[:], at.UTC(), strings.TrimSpace(by)); err != nil {
			return fmt.Errorf("update bootstrap token: %w", err)
		}
		scopes, err := stringSliceFromJSON(scopesJSON)
		if err != nil {
			return fmt.Errorf("decode bootstrap scopes: %w", err)
		}
		result = deviceauth.BootstrapToken{
			TokenID:      tokenID,
			TokenHash:    hash,
			HardwareUUID: hwUUID,
			TenantID:     tenantID,
			Scopes:       scopes,
			CreatedAt:    createdAt.UTC(),
			ExpiresAt:    expiresAt.UTC(),
		}
		return nil
	})
	if err != nil {
		return deviceauth.BootstrapToken{}, err
	}
	return result, nil
}

// IssueRefreshToken inserts a new refresh-token row.
func (s *Store) IssueRefreshToken(ctx context.Context, token deviceauth.RefreshToken) error {
	if err := s.ensureDeviceAuthTables(ctx); err != nil {
		return err
	}
	scopes, err := stringSliceJSON(token.Scopes)
	if err != nil {
		return fmt.Errorf("marshal refresh scopes: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO device_refresh_tokens (token_hash, device_id, family_id, generation, scopes_json, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
		token.TokenHash[:],
		strings.TrimSpace(token.DeviceID),
		strings.TrimSpace(token.FamilyID),
		token.Generation,
		scopes,
		nullableUTC(token.CreatedAt),
		nullableUTC(token.ExpiresAt),
	); err != nil {
		return fmt.Errorf("issue refresh token: %w", err)
	}
	return nil
}

// ConsumeRefreshToken consumes a refresh token by hash. On replay (already
// consumed) the entire family is revoked in the same transaction.
func (s *Store) ConsumeRefreshToken(ctx context.Context, hash [32]byte, at time.Time) (deviceauth.RefreshToken, error) {
	if err := s.ensureDeviceAuthTables(ctx); err != nil {
		return deviceauth.RefreshToken{}, err
	}
	var result deviceauth.RefreshToken
	err := s.runInTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
SELECT device_id, family_id, generation, scopes_json::text, created_at, expires_at, consumed_at, family_revoked
FROM device_refresh_tokens
WHERE token_hash = $1
FOR UPDATE`, hash[:])
		var (
			deviceID      string
			familyID      string
			generation    int
			scopesJSON    string
			createdAt     time.Time
			expiresAt     time.Time
			consumedAt    sql.NullTime
			familyRevoked bool
		)
		if err := row.Scan(&deviceID, &familyID, &generation, &scopesJSON, &createdAt, &expiresAt, &consumedAt, &familyRevoked); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return deviceauth.ErrRefreshNotFound
			}
			return fmt.Errorf("select refresh token: %w", err)
		}
		if familyRevoked {
			return deviceauth.ErrRefreshReplay
		}
		if consumedAt.Valid {
			if _, err := tx.ExecContext(ctx, `
UPDATE device_refresh_tokens
SET family_revoked = TRUE
WHERE family_id = $1`, familyID); err != nil {
				return fmt.Errorf("revoke family on replay: %w", err)
			}
			return deviceauth.ErrRefreshReplay
		}
		if !expiresAt.IsZero() && at.After(expiresAt) {
			return deviceauth.ErrRefreshExpired
		}
		var deviceStatus string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM device_records WHERE device_id = $1`, deviceID).Scan(&deviceStatus); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return deviceauth.ErrDeviceNotFound
			}
			return fmt.Errorf("lookup device for refresh: %w", err)
		}
		if deviceStatus != "" && deviceStatus != "active" {
			return deviceauth.ErrDeviceInactive
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE device_refresh_tokens
SET consumed_at = $2, superseded = TRUE
WHERE token_hash = $1`, hash[:], at.UTC()); err != nil {
			return fmt.Errorf("update refresh token: %w", err)
		}
		scopes, err := stringSliceFromJSON(scopesJSON)
		if err != nil {
			return fmt.Errorf("decode refresh scopes: %w", err)
		}
		result = deviceauth.RefreshToken{
			TokenHash:  hash,
			DeviceID:   deviceID,
			FamilyID:   familyID,
			Generation: generation,
			Scopes:     scopes,
			CreatedAt:  createdAt.UTC(),
			ExpiresAt:  expiresAt.UTC(),
		}
		return nil
	})
	if err != nil {
		return deviceauth.RefreshToken{}, err
	}
	return result, nil
}

// RevokeRefreshFamily revokes every refresh token in a family.
func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	if err := s.ensureDeviceAuthTables(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE device_refresh_tokens SET family_revoked = TRUE WHERE family_id = $1`, strings.TrimSpace(familyID)); err != nil {
		return fmt.Errorf("revoke family: %w", err)
	}
	return nil
}

// CheckIdempotency returns the cached response for the given key if it
// exists and the request hash matches.
func (s *Store) CheckIdempotency(ctx context.Context, key string, requestHash [32]byte) ([]byte, int, error) {
	if err := s.ensureDeviceAuthTables(ctx); err != nil {
		return nil, 0, err
	}
	row := s.db.QueryRowContext(ctx, `
SELECT request_hash, response_status, response_body, expires_at
FROM device_idempotency_keys
WHERE cache_key = $1`, strings.TrimSpace(key))
	var (
		storedHash []byte
		status     int
		body       []byte
		expiresAt  time.Time
	)
	if err := row.Scan(&storedHash, &status, &body, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("select idempotency: %w", err)
	}
	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM device_idempotency_keys WHERE cache_key = $1`, strings.TrimSpace(key))
		return nil, 0, nil
	}
	if !bytesEqual32(storedHash, requestHash[:]) {
		return nil, 0, deviceauth.ErrIdempotencyConflict
	}
	out := make([]byte, len(body))
	copy(out, body)
	return out, status, nil
}

// PutIdempotency caches a response under the given idempotency key.
func (s *Store) PutIdempotency(ctx context.Context, key string, requestHash [32]byte, status int, body []byte, expiresAt time.Time) error {
	if err := s.ensureDeviceAuthTables(ctx); err != nil {
		return err
	}
	stored := make([]byte, len(body))
	copy(stored, body)
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO device_idempotency_keys (cache_key, request_hash, response_status, response_body, expires_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (cache_key) DO NOTHING`,
		strings.TrimSpace(key),
		requestHash[:],
		status,
		stored,
		nullableUTC(expiresAt),
	); err != nil {
		return fmt.Errorf("put idempotency: %w", err)
	}
	return nil
}

func (s *Store) ensureDeviceAuthTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.deviceAuthTablesReady, "device_auth", ensureDeviceAuthStatements)
}

func (s *Store) runInTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func scanDeviceRow(row *sql.Row) (deviceauth.DeviceRecord, error) {
	var (
		deviceID     string
		hardwareUUID string
		serialNumber string
		hostname     string
		tenantID     string
		osType       string
		osVersion    string
		agentVersion string
		status       string
		enrolledAt   time.Time
		lastSeenAt   time.Time
		revokedAt    sql.NullTime
		metadataJSON string
	)
	if err := row.Scan(&deviceID, &hardwareUUID, &serialNumber, &hostname, &tenantID, &osType, &osVersion, &agentVersion, &status, &enrolledAt, &lastSeenAt, &revokedAt, &metadataJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return deviceauth.DeviceRecord{}, deviceauth.ErrDeviceNotFound
		}
		return deviceauth.DeviceRecord{}, fmt.Errorf("scan device row: %w", err)
	}
	metadata, err := metadataFromJSON(metadataJSON)
	if err != nil {
		return deviceauth.DeviceRecord{}, err
	}
	record := deviceauth.DeviceRecord{
		DeviceID:     deviceID,
		HardwareUUID: hardwareUUID,
		SerialNumber: serialNumber,
		Hostname:     hostname,
		TenantID:     tenantID,
		OSType:       osType,
		OSVersion:    osVersion,
		AgentVersion: agentVersion,
		Status:       status,
		EnrolledAt:   enrolledAt.UTC(),
		LastSeenAt:   lastSeenAt.UTC(),
		Metadata:     metadata,
	}
	if revokedAt.Valid {
		record.RevokedAt = revokedAt.Time.UTC()
	}
	return record, nil
}

func deviceStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return "active"
	}
	return status
}

func nullableUTC(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func metadataJSON(metadata map[string]string) (string, error) {
	if len(metadata) == 0 {
		return `{}`, nil
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func metadataFromJSON(payload string) (map[string]string, error) {
	payload = strings.TrimSpace(payload)
	if payload == "" || payload == "{}" {
		return nil, nil
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}
	return out, nil
}

func stringSliceJSON(values []string) (string, error) {
	if len(values) == 0 {
		return `[]`, nil
	}
	payload, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func stringSliceFromJSON(payload string) ([]string, error) {
	payload = strings.TrimSpace(payload)
	if payload == "" || payload == "[]" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		return nil, fmt.Errorf("unmarshal scopes: %w", err)
	}
	return out, nil
}

func bytesEqual32(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
