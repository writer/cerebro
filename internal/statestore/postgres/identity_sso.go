package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/writer/cerebro/internal/ports"
)

var _ ports.IdentitySSOStore = (*Store)(nil)

var ensureIdentitySSOStatements = []string{
	`CREATE TABLE IF NOT EXISTS identity_sso_connections (
  tenant_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  connection_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, connection_id)
)`,
	`CREATE TABLE IF NOT EXISTS identity_sso_policies (
  tenant_id TEXT PRIMARY KEY,
  policy_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE TABLE IF NOT EXISTS identity_sso_sessions (
  token_hash TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  groups_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  roles_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  user_agent TEXT NOT NULL DEFAULT '',
  ip_hash TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  idle_timeout_minutes INTEGER NOT NULL,
  revoked_at TIMESTAMPTZ
)`,
	`CREATE INDEX IF NOT EXISTS identity_sso_sessions_subject_idx ON identity_sso_sessions (tenant_id, subject)`,
	`CREATE INDEX IF NOT EXISTS identity_sso_sessions_email_idx ON identity_sso_sessions (tenant_id, lower(email))`,
	`CREATE INDEX IF NOT EXISTS identity_sso_sessions_connection_idx ON identity_sso_sessions (tenant_id, connection_id)`,
	`CREATE INDEX IF NOT EXISTS identity_sso_sessions_expiry_idx ON identity_sso_sessions (tenant_id, expires_at)`,
	`CREATE TABLE IF NOT EXISTS identity_scim_tokens (
  tenant_id TEXT NOT NULL,
  token_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  name TEXT NOT NULL,
  prefix TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  last_used_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, token_id)
)`,
	`CREATE TABLE IF NOT EXISTS identity_directory_users (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  source TEXT NOT NULL,
  user_name TEXT NOT NULL,
  external_id TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  display_name TEXT NOT NULL DEFAULT '',
  given_name TEXT NOT NULL DEFAULT '',
  family_name TEXT NOT NULL DEFAULT '',
  active BOOLEAN NOT NULL DEFAULT TRUE,
  jit_groups_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  last_login_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, user_id)
)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS identity_directory_users_name_idx ON identity_directory_users (tenant_id, connection_id, lower(user_name))`,
	`CREATE INDEX IF NOT EXISTS identity_directory_users_email_idx ON identity_directory_users (tenant_id, connection_id, lower(email))`,
	`CREATE TABLE IF NOT EXISTS identity_directory_groups (
  tenant_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  external_id TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, group_id)
)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS identity_directory_groups_name_idx ON identity_directory_groups (tenant_id, connection_id, lower(display_name))`,
	`CREATE TABLE IF NOT EXISTS identity_directory_memberships (
  tenant_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, group_id, user_id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES identity_directory_groups (tenant_id, group_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES identity_directory_users (tenant_id, user_id) ON DELETE CASCADE
)`,
	`CREATE INDEX IF NOT EXISTS identity_directory_memberships_user_idx ON identity_directory_memberships (tenant_id, user_id)`,
}

// identitySessionRetention keeps expired and revoked session rows briefly so
// admins can still see recent revocations before cleanup removes them.
const identitySessionRetention = 24 * time.Hour

var errIdentityTenantRequired = errors.New("identity sso tenant_id is required")

func (s *Store) ensureIdentitySSOTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	return s.ensureStatements(ctx, &s.identity.sso, "identity sso", ensureIdentitySSOStatements)
}

func (s *Store) identityTenant(ctx context.Context, tenantID string) (string, error) {
	if err := s.ensureIdentitySSOTables(ctx); err != nil {
		return "", err
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "", errIdentityTenantRequired
	}
	return tenantID, nil
}

func identityUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}

func identityJSONList(values []string) string {
	if values == nil {
		values = []string{}
	}
	payload, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(payload)
}

func decodeIdentityList(payload string) ([]string, error) {
	values := []string{}
	if strings.TrimSpace(payload) == "" {
		return values, nil
	}
	if err := json.Unmarshal([]byte(payload), &values); err != nil {
		return nil, err
	}
	return values, nil
}

func nullTimePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	at := value.Time.UTC()
	return &at
}

func nullTimeValue(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: value.UTC(), Valid: true}
}

func identityRollback(tx *sql.Tx) {
	_ = tx.Rollback()
}

// ListSSOConnections lists a tenant's connections ordered by name.
func (s *Store) ListSSOConnections(ctx context.Context, tenantID string) ([]ports.SSOConnection, error) {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return listSSOConnections(ctx, s.db, tenantID)
}

type identityQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func listSSOConnections(ctx context.Context, db identityQuerier, tenantID string) ([]ports.SSOConnection, error) {
	rows, err := db.QueryContext(ctx, `SELECT tenant_id, connection_json::text FROM identity_sso_connections WHERE tenant_id = $1 ORDER BY lower(connection_json->>'name'), connection_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list sso connections: %w", err)
	}
	defer func() { _ = rows.Close() }()
	connections := []ports.SSOConnection{}
	for rows.Next() {
		conn, err := scanSSOConnection(rows)
		if err != nil {
			return nil, err
		}
		connections = append(connections, *conn)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list sso connections: %w", err)
	}
	return connections, nil
}

func scanSSOConnection(scanner riskScoringConfigScanner) (*ports.SSOConnection, error) {
	var tenantID, payload string
	if err := scanner.Scan(&tenantID, &payload); err != nil {
		return nil, err
	}
	var conn ports.SSOConnection
	if err := json.Unmarshal([]byte(payload), &conn); err != nil {
		return nil, fmt.Errorf("decode sso connection: %w", err)
	}
	conn.TenantID = tenantID
	if conn.Domains == nil {
		conn.Domains = []string{}
	}
	if conn.RoleMappings == nil {
		conn.RoleMappings = []ports.SSORoleMapping{}
	}
	if conn.DefaultRoles == nil {
		conn.DefaultRoles = []string{}
	}
	return &conn, nil
}

// GetSSOConnection loads one connection.
func (s *Store) GetSSOConnection(ctx context.Context, tenantID string, connectionID string) (*ports.SSOConnection, error) {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `SELECT tenant_id, connection_json::text FROM identity_sso_connections WHERE tenant_id = $1 AND connection_id = $2`, tenantID, strings.TrimSpace(connectionID))
	conn, err := scanSSOConnection(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrSSOConnectionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get sso connection: %w", err)
	}
	return conn, nil
}

// PutSSOConnection inserts or replaces a connection. A per-tenant advisory
// lock serializes writers so domain uniqueness and the connection limit hold.
// The stored createdAt is never replaced, so two processes that both observe a
// missing connection and insert it converge on the first insert's timestamp.
func (s *Store) PutSSOConnection(ctx context.Context, connection *ports.SSOConnection, maxConnections int) error {
	if connection == nil || strings.TrimSpace(connection.ID) == "" {
		return errors.New("sso connection id is required")
	}
	tenantID, err := s.identityTenant(ctx, connection.TenantID)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(connection)
	if err != nil {
		return fmt.Errorf("encode sso connection: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sso connection write: %w", err)
	}
	defer identityRollback(tx)
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('identity_sso_connections:' || $1, 0))`, tenantID); err != nil {
		return fmt.Errorf("lock sso connections: %w", err)
	}
	existing, err := listSSOConnections(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if err := checkSSOConnectionPut(existing, *connection, maxConnections); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO identity_sso_connections (tenant_id, connection_id, connection_json, created_at, updated_at)
VALUES ($1, $2, $3::jsonb, $4, $5)
ON CONFLICT (tenant_id, connection_id) DO UPDATE SET
  connection_json = jsonb_set(EXCLUDED.connection_json, '{createdAt}',
    COALESCE(identity_sso_connections.connection_json->'createdAt', EXCLUDED.connection_json->'createdAt')),
  updated_at = EXCLUDED.updated_at`, tenantID, connection.ID, string(payload), connection.CreatedAt.UTC(), connection.UpdatedAt.UTC()); err != nil {
		return fmt.Errorf("upsert sso connection: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sso connection: %w", err)
	}
	return nil
}

func checkSSOConnectionPut(existing []ports.SSOConnection, next ports.SSOConnection, maxConnections int) error {
	isNew := true
	for _, conn := range existing {
		if conn.ID == next.ID {
			isNew = false
			continue
		}
		for _, domain := range next.Domains {
			if slices.Contains(conn.Domains, domain) {
				return fmt.Errorf("%w: %s is routed to connection %s", ports.ErrSSODomainConflict, domain, conn.ID)
			}
		}
	}
	if isNew && maxConnections > 0 && len(existing) >= maxConnections {
		return ports.ErrSSOConnectionLimit
	}
	return nil
}

// DeleteSSOConnection removes a connection with its sessions, SCIM tokens, and
// directory records.
func (s *Store) DeleteSSOConnection(ctx context.Context, tenantID string, connectionID string) error {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	connectionID = strings.TrimSpace(connectionID)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sso connection delete: %w", err)
	}
	defer identityRollback(tx)
	result, err := tx.ExecContext(ctx, `DELETE FROM identity_sso_connections WHERE tenant_id = $1 AND connection_id = $2`, tenantID, connectionID)
	if err != nil {
		return fmt.Errorf("delete sso connection: %w", err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return ports.ErrSSOConnectionNotFound
	}
	for _, statement := range []string{
		`DELETE FROM identity_sso_sessions WHERE tenant_id = $1 AND connection_id = $2`,
		`DELETE FROM identity_scim_tokens WHERE tenant_id = $1 AND connection_id = $2`,
		`DELETE FROM identity_directory_groups WHERE tenant_id = $1 AND connection_id = $2`,
		`DELETE FROM identity_directory_users WHERE tenant_id = $1 AND connection_id = $2`,
	} {
		if _, err := tx.ExecContext(ctx, statement, tenantID, connectionID); err != nil {
			return fmt.Errorf("delete sso connection dependents: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sso connection delete: %w", err)
	}
	return nil
}

// GetSSOPolicy loads the tenant SSO policy.
func (s *Store) GetSSOPolicy(ctx context.Context, tenantID string) (*ports.SSOPolicy, error) {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var payload string
	err = s.db.QueryRowContext(ctx, `SELECT policy_json::text FROM identity_sso_policies WHERE tenant_id = $1`, tenantID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrSSOPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get sso policy: %w", err)
	}
	var policy ports.SSOPolicy
	if err := json.Unmarshal([]byte(payload), &policy); err != nil {
		return nil, fmt.Errorf("decode sso policy: %w", err)
	}
	policy.TenantID = tenantID
	return &policy, nil
}

// PutSSOPolicy upserts the tenant SSO policy.
func (s *Store) PutSSOPolicy(ctx context.Context, policy *ports.SSOPolicy) error {
	if policy == nil {
		return errors.New("sso policy is required")
	}
	tenantID, err := s.identityTenant(ctx, policy.TenantID)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("encode sso policy: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO identity_sso_policies (tenant_id, policy_json, updated_at)
VALUES ($1, $2::jsonb, NOW())
ON CONFLICT (tenant_id) DO UPDATE SET policy_json = EXCLUDED.policy_json, updated_at = NOW()`, tenantID, string(payload)); err != nil {
		return fmt.Errorf("upsert sso policy: %w", err)
	}
	return nil
}

const identitySessionColumns = `tenant_id, session_id, token_hash, connection_id, subject, email, name, groups_json::text, roles_json::text, user_agent, ip_hash, created_at, last_seen_at, expires_at, idle_timeout_minutes, revoked_at`

func scanSSOSession(scanner riskScoringConfigScanner) (*ports.SSOSession, error) {
	var session ports.SSOSession
	var groups, roles string
	var revokedAt sql.NullTime
	if err := scanner.Scan(&session.TenantID, &session.ID, &session.TokenHash, &session.ConnectionID, &session.Subject,
		&session.Email, &session.Name, &groups, &roles, &session.UserAgent, &session.IPHash,
		&session.CreatedAt, &session.LastSeenAt, &session.ExpiresAt, &session.IdleTimeoutMinutes, &revokedAt); err != nil {
		return nil, err
	}
	var err error
	if session.Groups, err = decodeIdentityList(groups); err != nil {
		return nil, fmt.Errorf("decode sso session groups: %w", err)
	}
	if session.Roles, err = decodeIdentityList(roles); err != nil {
		return nil, fmt.Errorf("decode sso session roles: %w", err)
	}
	session.CreatedAt = session.CreatedAt.UTC()
	session.LastSeenAt = session.LastSeenAt.UTC()
	session.ExpiresAt = session.ExpiresAt.UTC()
	session.RevokedAt = nullTimePointer(revokedAt)
	return &session, nil
}

// CreateSSOSession stores a new session and prunes long-dead sessions for the tenant.
func (s *Store) CreateSSOSession(ctx context.Context, session *ports.SSOSession) error {
	if session == nil {
		return errors.New("sso session is required")
	}
	tenantID, err := s.identityTenant(ctx, session.TenantID)
	if err != nil {
		return err
	}
	cutoff := session.CreatedAt.Add(-identitySessionRetention).UTC()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM identity_sso_sessions WHERE tenant_id = $1 AND (expires_at < $2 OR revoked_at < $2)`, tenantID, cutoff); err != nil {
		return fmt.Errorf("prune sso sessions: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO identity_sso_sessions (token_hash, tenant_id, session_id, connection_id, subject, email, name, groups_json, roles_json, user_agent, ip_hash, created_at, last_seen_at, expires_at, idle_timeout_minutes)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, $11, $12, $13, $14, $15)`,
		session.TokenHash, tenantID, session.ID, session.ConnectionID, session.Subject, session.Email, session.Name,
		identityJSONList(session.Groups), identityJSONList(session.Roles), session.UserAgent, session.IPHash,
		session.CreatedAt.UTC(), session.LastSeenAt.UTC(), session.ExpiresAt.UTC(), session.IdleTimeoutMinutes); err != nil {
		if identityUniqueViolation(err) {
			return ports.ErrSSOSessionExists
		}
		return fmt.Errorf("insert sso session: %w", err)
	}
	return nil
}

// GetSSOSession loads a session by token hash, including expired or revoked rows.
func (s *Store) GetSSOSession(ctx context.Context, tenantID string, tokenHash string) (*ports.SSOSession, error) {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+identitySessionColumns+` FROM identity_sso_sessions WHERE tenant_id = $1 AND token_hash = $2`, tenantID, tokenHash)
	session, err := scanSSOSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrSSOSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get sso session: %w", err)
	}
	return session, nil
}

// TouchSSOSession advances lastSeenAt for a live session.
func (s *Store) TouchSSOSession(ctx context.Context, tenantID string, tokenHash string, seenAt time.Time) error {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE identity_sso_sessions SET last_seen_at = GREATEST(last_seen_at, $3) WHERE tenant_id = $1 AND token_hash = $2 AND revoked_at IS NULL`, tenantID, tokenHash, seenAt.UTC()); err != nil {
		return fmt.Errorf("touch sso session: %w", err)
	}
	return nil
}

// DeleteSSOSession removes a session. Deleting a missing session succeeds.
func (s *Store) DeleteSSOSession(ctx context.Context, tenantID string, tokenHash string) error {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM identity_sso_sessions WHERE tenant_id = $1 AND token_hash = $2`, tenantID, tokenHash); err != nil {
		return fmt.Errorf("delete sso session: %w", err)
	}
	return nil
}

// ListSSOSessions lists unrevoked, unexpired sessions, optionally for one
// subject (matched against subject or, case-insensitively, email).
func (s *Store) ListSSOSessions(ctx context.Context, tenantID string, subject string, now time.Time, limit int) ([]ports.SSOSession, error) {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+identitySessionColumns+` FROM identity_sso_sessions
WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > $2
  AND ($3 = '' OR subject = $3 OR lower(email) = lower($3))
ORDER BY last_seen_at DESC, session_id
LIMIT $4`, tenantID, now.UTC(), strings.TrimSpace(subject), max(limit, 1))
	if err != nil {
		return nil, fmt.Errorf("list sso sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	sessions := []ports.SSOSession{}
	for rows.Next() {
		session, err := scanSSOSession(rows)
		if err != nil {
			return nil, fmt.Errorf("scan sso session: %w", err)
		}
		sessions = append(sessions, *session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list sso sessions: %w", err)
	}
	return sessions, nil
}

// RevokeSSOSessions revokes every live session that matches a subject or email.
func (s *Store) RevokeSSOSessions(ctx context.Context, tenantID string, match ports.SSOSessionMatch, revokedAt time.Time) (int, error) {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	emails := make([]string, 0, len(match.Emails))
	for _, email := range match.Emails {
		if email = strings.ToLower(strings.TrimSpace(email)); email != "" {
			emails = append(emails, email)
		}
	}
	subjects := make([]string, 0, len(match.Subjects))
	for _, subject := range match.Subjects {
		if subject = strings.TrimSpace(subject); subject != "" {
			subjects = append(subjects, subject)
		}
	}
	if len(emails) == 0 && len(subjects) == 0 {
		return 0, nil
	}
	result, err := s.db.ExecContext(ctx, `UPDATE identity_sso_sessions SET revoked_at = $2
WHERE tenant_id = $1 AND revoked_at IS NULL
  AND (subject IN (SELECT jsonb_array_elements_text($3::jsonb)) OR lower(email) IN (SELECT jsonb_array_elements_text($4::jsonb)))`,
		tenantID, revokedAt.UTC(), identityJSONList(subjects), identityJSONList(emails))
	if err != nil {
		return 0, fmt.Errorf("revoke sso sessions: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("revoke sso sessions: %w", err)
	}
	return int(affected), nil
}
