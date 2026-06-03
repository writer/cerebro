package postgres

import (
	"context"
	"database/sql"
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
  code_challenge TEXT NOT NULL,
  nonce TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
)`,
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
  groups_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  code_challenge TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
)`,
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
  groups_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  family_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  family_revoked BOOLEAN NOT NULL DEFAULT FALSE
)`,
	`CREATE INDEX IF NOT EXISTS mcp_oauth_refresh_tokens_client_idx ON mcp_oauth_refresh_tokens (client_id)`,
	`CREATE INDEX IF NOT EXISTS mcp_oauth_refresh_tokens_family_idx ON mcp_oauth_refresh_tokens (family_id)`,
	`CREATE INDEX IF NOT EXISTS mcp_oauth_refresh_tokens_expires_idx ON mcp_oauth_refresh_tokens (expires_at)`,
}

func (s *Store) SaveOAuthClient(ctx context.Context, client mcpoauth.OAuthClient) error {
	if err := s.ensureMCPOAuthTables(ctx); err != nil {
		return err
	}
	redirectURIs, err := stringSliceJSON(client.RedirectURIs)
	if err != nil {
		return fmt.Errorf("marshal mcp oauth client redirect URIs: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO mcp_oauth_clients (
  client_id, client_secret, client_name, redirect_uris_json, public, created_at
) VALUES ($1,$2,$3,$4::jsonb,$5,$6)`,
		strings.TrimSpace(client.ClientID),
		strings.TrimSpace(client.ClientSecret),
		strings.TrimSpace(client.Name),
		redirectURIs,
		client.Public,
		nullableUTC(client.CreatedAt),
	)
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
  state_hash, client_id, redirect_uri, client_state, resource, scopes_json,
  code_challenge, nonce, created_at, expires_at
) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10)`,
		state.StateHash[:],
		strings.TrimSpace(state.ClientID),
		strings.TrimSpace(state.RedirectURI),
		strings.TrimSpace(state.ClientState),
		strings.TrimSpace(state.Resource),
		scopes,
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
SELECT client_id, redirect_uri, client_state, resource, scopes_json::text,
       code_challenge, nonce, created_at, expires_at, consumed_at
FROM mcp_oauth_login_states
WHERE state_hash = $1
FOR UPDATE`, stateHash[:])
		var scopesJSON string
		var consumedAt sql.NullTime
		if err := row.Scan(&result.ClientID, &result.RedirectURI, &result.ClientState, &result.Resource, &scopesJSON, &result.CodeChallenge, &result.Nonce, &result.CreatedAt, &result.ExpiresAt, &consumedAt); err != nil {
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
	groups, err := stringSliceJSON(code.Groups)
	if err != nil {
		return fmt.Errorf("marshal groups: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO mcp_oauth_authorization_codes (
  code_hash, client_id, redirect_uri, resource, subject, email, tenant_id,
  allowed_tenants_json, scopes_json, groups_json, code_challenge, created_at, expires_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb,$11,$12,$13)`,
		code.CodeHash[:],
		strings.TrimSpace(code.ClientID),
		strings.TrimSpace(code.RedirectURI),
		strings.TrimSpace(code.Resource),
		strings.TrimSpace(code.Subject),
		strings.TrimSpace(code.Email),
		strings.TrimSpace(code.TenantID),
		allowedTenants,
		scopes,
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
       scopes_json::text, groups_json::text, code_challenge, created_at, expires_at, consumed_at
FROM mcp_oauth_authorization_codes
WHERE code_hash = $1
FOR UPDATE`, codeHash[:])
		var allowedJSON, scopesJSON, groupsJSON string
		var consumedAt sql.NullTime
		if err := row.Scan(&result.ClientID, &result.RedirectURI, &result.Resource, &result.Subject, &result.Email, &result.TenantID, &allowedJSON, &scopesJSON, &groupsJSON, &result.CodeChallenge, &result.CreatedAt, &result.ExpiresAt, &consumedAt); err != nil {
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
	groups, err := stringSliceJSON(token.Groups)
	if err != nil {
		return fmt.Errorf("marshal groups: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO mcp_oauth_refresh_tokens (
  token_hash, client_id, resource, subject, email, tenant_id, allowed_tenants_json,
  scopes_json, groups_json, family_id, generation, created_at, expires_at, family_revoked
) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11,$12,$13,
  EXISTS (SELECT 1 FROM mcp_oauth_refresh_tokens WHERE family_id = $10 AND family_revoked)
)`,
		token.TokenHash[:],
		strings.TrimSpace(token.ClientID),
		strings.TrimSpace(token.Resource),
		strings.TrimSpace(token.Subject),
		strings.TrimSpace(token.Email),
		strings.TrimSpace(token.TenantID),
		allowedTenants,
		scopes,
		groups,
		strings.TrimSpace(token.FamilyID),
		token.Generation,
		nullableUTC(token.CreatedAt),
		nullableUTC(token.ExpiresAt),
	)
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
		row := tx.QueryRowContext(ctx, `
SELECT client_id, resource, subject, email, tenant_id, allowed_tenants_json::text,
       scopes_json::text, groups_json::text, family_id, generation, created_at,
       expires_at, consumed_at, family_revoked
FROM mcp_oauth_refresh_tokens
WHERE token_hash = $1
FOR UPDATE`, tokenHash[:])
		var allowedJSON, scopesJSON, groupsJSON string
		var consumedAt sql.NullTime
		if err := row.Scan(&result.ClientID, &result.Resource, &result.Subject, &result.Email, &result.TenantID, &allowedJSON, &scopesJSON, &groupsJSON, &result.FamilyID, &result.Generation, &result.CreatedAt, &result.ExpiresAt, &consumedAt, &result.FamilyRevoked); err != nil {
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
		var err error
		if result.AllowedTenants, err = stringSliceFromJSON(allowedJSON); err != nil {
			return err
		}
		if result.Scopes, err = stringSliceFromJSON(scopesJSON); err != nil {
			return err
		}
		if result.Groups, err = stringSliceFromJSON(groupsJSON); err != nil {
			return err
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
	res, err := s.db.ExecContext(ctx, `UPDATE mcp_oauth_refresh_tokens SET family_revoked = TRUE WHERE family_id = $1`, strings.TrimSpace(familyID))
	if err != nil {
		return fmt.Errorf("revoke mcp oauth refresh family: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return mcpoauth.ErrNotFound
	}
	return nil
}

func (s *Store) ensureMCPOAuthTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.mcpOAuthTablesReady, "mcp_oauth", ensureMCPOAuthStatements)
}
