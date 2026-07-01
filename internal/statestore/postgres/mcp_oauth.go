package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/mcpoauth"
)

var ensureMCPOAuthStatements = []string{
	`CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_secret TEXT NOT NULL DEFAULT '',
  client_name TEXT NOT NULL DEFAULT '',
  redirect_uris_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  public BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL
)`,
	`CREATE TABLE IF NOT EXISTS mcp_oauth_login_states (
  state_hash BYTEA PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  client_state TEXT NOT NULL DEFAULT '',
  resource TEXT NOT NULL,
  scopes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  scopes_explicit BOOLEAN NOT NULL DEFAULT FALSE,
  code_challenge TEXT NOT NULL,
  nonce TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
)`,
	`ALTER TABLE mcp_oauth_login_states ADD COLUMN IF NOT EXISTS scopes_explicit BOOLEAN NOT NULL DEFAULT FALSE`,
	`CREATE INDEX IF NOT EXISTS mcp_oauth_login_states_expires_idx ON mcp_oauth_login_states (expires_at)`,
	`CREATE TABLE IF NOT EXISTS mcp_oauth_authorization_codes (
  code_hash BYTEA PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  resource TEXT NOT NULL,
  subject TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '',
  tenant_id TEXT NOT NULL DEFAULT '',
  allowed_tenants_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  scopes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  roles_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  groups_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  code_challenge TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
)`,
	`ALTER TABLE mcp_oauth_authorization_codes ADD COLUMN IF NOT EXISTS roles_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`CREATE INDEX IF NOT EXISTS mcp_oauth_authorization_codes_client_idx ON mcp_oauth_authorization_codes (client_id)`,
	`CREATE INDEX IF NOT EXISTS mcp_oauth_authorization_codes_expires_idx ON mcp_oauth_authorization_codes (expires_at)`,
	`CREATE TABLE IF NOT EXISTS mcp_oauth_refresh_tokens (
  token_hash BYTEA PRIMARY KEY,
  client_id TEXT NOT NULL,
  resource TEXT NOT NULL,
  subject TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '',
  tenant_id TEXT NOT NULL DEFAULT '',
  allowed_tenants_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  scopes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  roles_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  groups_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  family_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  family_revoked BOOLEAN NOT NULL DEFAULT FALSE
)`,
	`ALTER TABLE mcp_oauth_refresh_tokens ADD COLUMN IF NOT EXISTS roles_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`CREATE INDEX IF NOT EXISTS mcp_oauth_refresh_tokens_client_idx ON mcp_oauth_refresh_tokens (client_id)`,
	`CREATE INDEX IF NOT EXISTS mcp_oauth_refresh_tokens_family_idx ON mcp_oauth_refresh_tokens (family_id)`,
	`CREATE INDEX IF NOT EXISTS mcp_oauth_refresh_tokens_expires_idx ON mcp_oauth_refresh_tokens (expires_at)`,
}

func (s *Store) SaveOAuthClient(ctx context.Context, client mcpoauth.OAuthClient) error {
	return s.saveOAuthClient(ctx, client, 0)
}

func (s *Store) SaveOAuthClientWithLimit(ctx context.Context, client mcpoauth.OAuthClient, maxClients int) error {
	return s.saveOAuthClient(ctx, client, maxClients)
}

func (s *Store) saveOAuthClient(ctx context.Context, client mcpoauth.OAuthClient, maxClients int) error {
	if err := s.ensureMCPOAuthTables(ctx); err != nil {
		return err
	}
	redirectURIs, err := stringSliceJSON(client.RedirectURIs)
	if err != nil {
		return fmt.Errorf("marshal mcp oauth client redirect URIs: %w", err)
	}
	args := []any{
		strings.TrimSpace(client.ClientID),
		strings.TrimSpace(client.ClientSecret),
		strings.TrimSpace(client.Name),
		redirectURIs,
		client.Public,
		nullableUTC(client.CreatedAt),
	}
	if maxClients > 0 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin save mcp oauth client: %w", err)
		}
		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback()
			}
		}()
		if _, err := tx.ExecContext(ctx, `LOCK TABLE mcp_oauth_clients IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return fmt.Errorf("lock mcp oauth clients: %w", err)
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mcp_oauth_clients`).Scan(&count); err != nil {
			return fmt.Errorf("count mcp oauth clients: %w", err)
		}
		if count >= maxClients {
			return mcpoauth.ErrOAuthClientLimitExceeded
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO mcp_oauth_clients (
  client_id, client_secret, client_name, redirect_uris_json, public, created_at
) VALUES ($1,$2,$3,$4::jsonb,$5,$6)`, args...); err != nil {
			return fmt.Errorf("save mcp oauth client: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit save mcp oauth client: %w", err)
		}
		committed = true
		return nil
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO mcp_oauth_clients (
  client_id, client_secret, client_name, redirect_uris_json, public, created_at
) VALUES ($1,$2,$3,$4::jsonb,$5,$6)`, args...)
	if err != nil {
		return fmt.Errorf("save mcp oauth client: %w", err)
	}
	return nil
}

func (s *Store) GetOAuthClient(ctx context.Context, clientID string) (mcpoauth.OAuthClient, error) {
	if err := s.ensureMCPOAuthTables(ctx); err != nil {
		return mcpoauth.OAuthClient{}, err
	}
	var client mcpoauth.OAuthClient
	var redirectJSON string
	row := s.db.QueryRowContext(ctx, `
SELECT client_id, client_secret, client_name, redirect_uris_json::text, public, created_at
FROM mcp_oauth_clients
WHERE client_id = $1`, strings.TrimSpace(clientID))
	if err := row.Scan(&client.ClientID, &client.ClientSecret, &client.Name, &redirectJSON, &client.Public, &client.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return mcpoauth.OAuthClient{}, mcpoauth.ErrNotFound
		}
		return mcpoauth.OAuthClient{}, fmt.Errorf("lookup mcp oauth client: %w", err)
	}
	redirectURIs, err := stringSliceFromJSON(redirectJSON)
	if err != nil {
		return mcpoauth.OAuthClient{}, err
	}
	client.RedirectURIs = redirectURIs
	return client, nil
}

func (s *Store) SaveLoginState(ctx context.Context, state mcpoauth.LoginState) error {
	if err := s.ensureMCPOAuthTables(ctx); err != nil {
		return err
	}
	scopes, err := stringSliceJSON(state.Scopes)
	if err != nil {
		return fmt.Errorf("marshal mcp oauth state scopes: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO mcp_oauth_login_states (
  state_hash, client_id, redirect_uri, client_state, resource, scopes_json, scopes_explicit,
  code_challenge, nonce, created_at, expires_at
) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$11)`,
		state.StateHash[:],
		strings.TrimSpace(state.ClientID),
		strings.TrimSpace(state.RedirectURI),
		strings.TrimSpace(state.ClientState),
		strings.TrimSpace(state.Resource),
		scopes,
		state.ScopesExplicit,
		strings.TrimSpace(state.CodeChallenge),
		strings.TrimSpace(state.Nonce),
		nullableUTC(state.CreatedAt),
		nullableUTC(state.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("save mcp oauth login state: %w", err)
	}
	return nil
}

func (s *Store) ConsumeLoginState(ctx context.Context, stateHash [32]byte, now time.Time) (mcpoauth.LoginState, error) {
	if err := s.ensureMCPOAuthTables(ctx); err != nil {
		return mcpoauth.LoginState{}, err
	}
	var result mcpoauth.LoginState
	err := s.runInTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
SELECT client_id, redirect_uri, client_state, resource, scopes_json::text, scopes_explicit,
       code_challenge, nonce, created_at, expires_at, consumed_at
FROM mcp_oauth_login_states
WHERE state_hash = $1
FOR UPDATE`, stateHash[:])
		var scopesJSON string
		var consumedAt sql.NullTime
		if err := row.Scan(&result.ClientID, &result.RedirectURI, &result.ClientState, &result.Resource, &scopesJSON, &result.ScopesExplicit, &result.CodeChallenge, &result.Nonce, &result.CreatedAt, &result.ExpiresAt, &consumedAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return mcpoauth.ErrNotFound
			}
			return fmt.Errorf("lookup mcp oauth login state: %w", err)
		}
		if consumedAt.Valid {
			return mcpoauth.ErrConsumed
		}
		if !now.Before(result.ExpiresAt) {
			return mcpoauth.ErrExpired
		}
		scopes, err := stringSliceFromJSON(scopesJSON)
		if err != nil {
			return err
		}
		result.Scopes = scopes
		if _, err := tx.ExecContext(ctx, `UPDATE mcp_oauth_login_states SET consumed_at = $2 WHERE state_hash = $1`, stateHash[:], now.UTC()); err != nil {
			return fmt.Errorf("consume mcp oauth login state: %w", err)
		}
		result.StateHash = stateHash
		return nil
	})
	return result, err
}

func (s *Store) SaveAuthorizationCode(ctx context.Context, code mcpoauth.AuthorizationCode) error {
	if err := s.ensureMCPOAuthTables(ctx); err != nil {
		return err
	}
	allowedTenants, err := stringSliceJSON(code.AllowedTenants)
	if err != nil {
		return fmt.Errorf("marshal allowed tenants: %w", err)
	}
	scopes, err := stringSliceJSON(code.Scopes)
	if err != nil {
		return fmt.Errorf("marshal scopes: %w", err)
	}
	roles, err := stringSliceJSON(code.Roles)
	if err != nil {
		return fmt.Errorf("marshal roles: %w", err)
	}
	groups, err := stringSliceJSON(code.Groups)
	if err != nil {
		return fmt.Errorf("marshal groups: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO mcp_oauth_authorization_codes (
  code_hash, client_id, redirect_uri, resource, subject, email, tenant_id,
  allowed_tenants_json, scopes_json, roles_json, groups_json, code_challenge, created_at, expires_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb,$11::jsonb,$12,$13,$14)`,
		code.CodeHash[:],
		strings.TrimSpace(code.ClientID),
		strings.TrimSpace(code.RedirectURI),
		strings.TrimSpace(code.Resource),
		strings.TrimSpace(code.Subject),
		strings.TrimSpace(code.Email),
		strings.TrimSpace(code.TenantID),
		allowedTenants,
		scopes,
		roles,
		groups,
		strings.TrimSpace(code.CodeChallenge),
		nullableUTC(code.CreatedAt),
		nullableUTC(code.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("save mcp oauth authorization code: %w", err)
	}
	return nil
}

func (s *Store) ConsumeAuthorizationCode(ctx context.Context, codeHash [32]byte, now time.Time) (mcpoauth.AuthorizationCode, error) {
	if err := s.ensureMCPOAuthTables(ctx); err != nil {
		return mcpoauth.AuthorizationCode{}, err
	}
	var result mcpoauth.AuthorizationCode
	err := s.runInTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
SELECT client_id, redirect_uri, resource, subject, email, tenant_id, allowed_tenants_json::text,
       scopes_json::text, roles_json::text, groups_json::text, code_challenge, created_at, expires_at, consumed_at
FROM mcp_oauth_authorization_codes
WHERE code_hash = $1
FOR UPDATE`, codeHash[:])
		var allowedJSON, scopesJSON, rolesJSON, groupsJSON string
		var consumedAt sql.NullTime
		if err := row.Scan(&result.ClientID, &result.RedirectURI, &result.Resource, &result.Subject, &result.Email, &result.TenantID, &allowedJSON, &scopesJSON, &rolesJSON, &groupsJSON, &result.CodeChallenge, &result.CreatedAt, &result.ExpiresAt, &consumedAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return mcpoauth.ErrNotFound
			}
			return fmt.Errorf("lookup mcp oauth authorization code: %w", err)
		}
		if consumedAt.Valid {
			return mcpoauth.ErrConsumed
		}
		if !now.Before(result.ExpiresAt) {
			return mcpoauth.ErrExpired
		}
		var err error
		if result.AllowedTenants, err = stringSliceFromJSON(allowedJSON); err != nil {
			return err
		}
		if result.Scopes, err = stringSliceFromJSON(scopesJSON); err != nil {
			return err
		}
		if result.Roles, err = stringSliceFromJSON(rolesJSON); err != nil {
			return err
		}
		if result.Groups, err = stringSliceFromJSON(groupsJSON); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mcp_oauth_authorization_codes SET consumed_at = $2 WHERE code_hash = $1`, codeHash[:], now.UTC()); err != nil {
			return fmt.Errorf("consume mcp oauth authorization code: %w", err)
		}
		result.CodeHash = codeHash
		return nil
	})
	return result, err
}

func (s *Store) SaveOAuthRefreshToken(ctx context.Context, token mcpoauth.RefreshToken) error {
	if err := s.ensureMCPOAuthTables(ctx); err != nil {
		return err
	}
	allowedTenants, err := stringSliceJSON(token.AllowedTenants)
	if err != nil {
		return fmt.Errorf("marshal allowed tenants: %w", err)
	}
	scopes, err := stringSliceJSON(token.Scopes)
	if err != nil {
		return fmt.Errorf("marshal scopes: %w", err)
	}
	roles, err := stringSliceJSON(token.Roles)
	if err != nil {
		return fmt.Errorf("marshal roles: %w", err)
	}
	groups, err := stringSliceJSON(token.Groups)
	if err != nil {
		return fmt.Errorf("marshal groups: %w", err)
	}
	familyID := strings.TrimSpace(token.FamilyID)
	err = s.runInTx(ctx, func(tx *sql.Tx) error {
		if err := lockMCPOAuthRefreshFamily(ctx, tx, familyID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO mcp_oauth_refresh_tokens (
  token_hash, client_id, resource, subject, email, tenant_id, allowed_tenants_json,
  scopes_json, roles_json, groups_json, family_id, generation, created_at, expires_at, family_revoked
) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10::jsonb,$11,$12,$13,$14,
  EXISTS (SELECT 1 FROM mcp_oauth_refresh_tokens WHERE family_id = $11 AND family_revoked)
)`,
			token.TokenHash[:],
			strings.TrimSpace(token.ClientID),
			strings.TrimSpace(token.Resource),
			strings.TrimSpace(token.Subject),
			strings.TrimSpace(token.Email),
			strings.TrimSpace(token.TenantID),
			allowedTenants,
			scopes,
			roles,
			groups,
			familyID,
			token.Generation,
			nullableUTC(token.CreatedAt),
			nullableUTC(token.ExpiresAt),
		)
		return err
	})
	if err != nil {
		return fmt.Errorf("issue mcp oauth refresh token: %w", err)
	}
	return nil
}

func (s *Store) ConsumeOAuthRefreshToken(ctx context.Context, tokenHash [32]byte, now time.Time) (mcpoauth.RefreshToken, error) {
	if err := s.ensureMCPOAuthTables(ctx); err != nil {
		return mcpoauth.RefreshToken{}, err
	}
	var result mcpoauth.RefreshToken
	replay := false
	err := s.runInTx(ctx, func(tx *sql.Tx) error {
		familyID, err := lookupMCPOAuthRefreshFamily(ctx, tx, tokenHash)
		if err != nil {
			return err
		}
		if err := lockMCPOAuthRefreshFamily(ctx, tx, familyID); err != nil {
			return err
		}
		row := tx.QueryRowContext(ctx, `
SELECT client_id, resource, subject, email, tenant_id, allowed_tenants_json::text,
       scopes_json::text, roles_json::text, groups_json::text, family_id, generation, created_at,
       expires_at, consumed_at, family_revoked
FROM mcp_oauth_refresh_tokens
WHERE token_hash = $1
FOR UPDATE`, tokenHash[:])
		var allowedJSON, scopesJSON, rolesJSON, groupsJSON string
		var consumedAt sql.NullTime
		if err := row.Scan(&result.ClientID, &result.Resource, &result.Subject, &result.Email, &result.TenantID, &allowedJSON, &scopesJSON, &rolesJSON, &groupsJSON, &result.FamilyID, &result.Generation, &result.CreatedAt, &result.ExpiresAt, &consumedAt, &result.FamilyRevoked); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return mcpoauth.ErrNotFound
			}
			return fmt.Errorf("lookup mcp oauth refresh token: %w", err)
		}
		if result.FamilyRevoked {
			replay = true
			return nil
		}
		if consumedAt.Valid {
			if _, err := tx.ExecContext(ctx, `UPDATE mcp_oauth_refresh_tokens SET family_revoked = TRUE WHERE family_id = $1`, result.FamilyID); err != nil {
				return fmt.Errorf("revoke mcp oauth refresh family: %w", err)
			}
			replay = true
			return nil
		}
		if !now.Before(result.ExpiresAt) {
			return mcpoauth.ErrExpired
		}
		var decodeErr error
		if result.AllowedTenants, decodeErr = stringSliceFromJSON(allowedJSON); decodeErr != nil {
			return decodeErr
		}
		if result.Scopes, decodeErr = stringSliceFromJSON(scopesJSON); decodeErr != nil {
			return decodeErr
		}
		if result.Roles, decodeErr = stringSliceFromJSON(rolesJSON); decodeErr != nil {
			return decodeErr
		}
		if result.Groups, decodeErr = stringSliceFromJSON(groupsJSON); decodeErr != nil {
			return decodeErr
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mcp_oauth_refresh_tokens SET consumed_at = $2 WHERE token_hash = $1`, tokenHash[:], now.UTC()); err != nil {
			return fmt.Errorf("consume mcp oauth refresh token: %w", err)
		}
		result.TokenHash = tokenHash
		return nil
	})
	if err == nil && replay {
		err = mcpoauth.ErrReplay
	}
	return result, err
}

func (s *Store) RevokeOAuthRefreshFamily(ctx context.Context, familyID string) error {
	if err := s.ensureMCPOAuthTables(ctx); err != nil {
		return err
	}
	familyID = strings.TrimSpace(familyID)
	var affected int64
	err := s.runInTx(ctx, func(tx *sql.Tx) error {
		if err := lockMCPOAuthRefreshFamily(ctx, tx, familyID); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE mcp_oauth_refresh_tokens SET family_revoked = TRUE WHERE family_id = $1`, familyID)
		if err != nil {
			return fmt.Errorf("revoke mcp oauth refresh family: %w", err)
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return mcpoauth.ErrNotFound
	}
	return nil
}

func (s *Store) RevokeOAuthRefreshToken(ctx context.Context, tokenHash [32]byte, clientID string) error {
	if err := s.ensureMCPOAuthTables(ctx); err != nil {
		return err
	}
	err := s.runInTx(ctx, func(tx *sql.Tx) error {
		familyID, err := lookupMCPOAuthRefreshFamilyForClient(ctx, tx, tokenHash, clientID)
		if errors.Is(err, mcpoauth.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := lockMCPOAuthRefreshFamily(ctx, tx, familyID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
UPDATE mcp_oauth_refresh_tokens
SET family_revoked = TRUE
WHERE family_id = $1`, familyID)
		return err
	})
	if err != nil {
		return fmt.Errorf("revoke mcp oauth refresh token: %w", err)
	}
	return nil
}

func lookupMCPOAuthRefreshFamily(ctx context.Context, tx *sql.Tx, tokenHash [32]byte) (string, error) {
	var familyID string
	if err := tx.QueryRowContext(ctx, `SELECT family_id FROM mcp_oauth_refresh_tokens WHERE token_hash = $1`, tokenHash[:]).Scan(&familyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", mcpoauth.ErrNotFound
		}
		return "", fmt.Errorf("lookup mcp oauth refresh family: %w", err)
	}
	return strings.TrimSpace(familyID), nil
}

func lookupMCPOAuthRefreshFamilyForClient(ctx context.Context, tx *sql.Tx, tokenHash [32]byte, clientID string) (string, error) {
	var familyID string
	if err := tx.QueryRowContext(ctx, `SELECT family_id FROM mcp_oauth_refresh_tokens WHERE token_hash = $1 AND client_id = $2`, tokenHash[:], strings.TrimSpace(clientID)).Scan(&familyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", mcpoauth.ErrNotFound
		}
		return "", fmt.Errorf("lookup mcp oauth refresh family: %w", err)
	}
	return strings.TrimSpace(familyID), nil
}

func lockMCPOAuthRefreshFamily(ctx context.Context, tx *sql.Tx, familyID string) error {
	left, right := mcpOAuthRefreshFamilyLockKeys(familyID)
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1, $2)`, left, right); err != nil {
		return fmt.Errorf("lock mcp oauth refresh family: %w", err)
	}
	return nil
}

func mcpOAuthRefreshFamilyLockKeys(familyID string) (int32, int32) {
	sum := sha256.Sum256([]byte(strings.TrimSpace(familyID)))
	return int32(binary.BigEndian.Uint32(sum[0:4])), int32(binary.BigEndian.Uint32(sum[4:8]))
}

func (s *Store) ensureMCPOAuthTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.mcpOAuthTablesReady, "mcp_oauth", ensureMCPOAuthStatements)
}
