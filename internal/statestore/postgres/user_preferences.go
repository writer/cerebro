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

var _ ports.UserPreferenceStore = (*Store)(nil)

var ensureUserPreferenceStatements = []string{
	`CREATE TABLE IF NOT EXISTS user_preferences (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  preferences_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, user_id)
)`,
	`CREATE INDEX IF NOT EXISTS user_preferences_updated_idx ON user_preferences (tenant_id, updated_at DESC)`,
}

const userPreferenceColumns = `tenant_id, user_id, preferences_json::text, created_at, updated_at`

func (s *Store) ensureUserPreferenceTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.userPreferencesReady, "user preferences", ensureUserPreferenceStatements)
}

// PutUserPreferences upserts one tenant/user preference document.
func (s *Store) PutUserPreferences(ctx context.Context, preferences *ports.UserPreferences) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if preferences == nil {
		return errors.New("user preferences are required")
	}
	tenantID := strings.TrimSpace(preferences.TenantID)
	userID := strings.TrimSpace(preferences.UserID)
	payload := strings.TrimSpace(preferences.PreferencesJSON)
	if tenantID == "" || userID == "" {
		return errors.New("user preferences tenant_id and user_id are required")
	}
	if payload == "" {
		payload = "{}"
	}
	if !json.Valid([]byte(payload)) {
		return errors.New("user preferences JSON is invalid")
	}
	if err := s.ensureUserPreferenceTable(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO user_preferences (tenant_id, user_id, preferences_json)
VALUES ($1, $2, $3::jsonb)
ON CONFLICT (tenant_id, user_id) DO UPDATE SET
  preferences_json = EXCLUDED.preferences_json,
  updated_at = NOW()`, tenantID, userID, payload); err != nil {
		return fmt.Errorf("upsert user preferences for tenant %q user %q: %w", tenantID, userID, err)
	}
	return nil
}

// GetUserPreferences loads one tenant/user preference document.
func (s *Store) GetUserPreferences(ctx context.Context, key ports.UserPreferenceKey) (*ports.UserPreferences, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	tenantID := strings.TrimSpace(key.TenantID)
	userID := strings.TrimSpace(key.UserID)
	if tenantID == "" || userID == "" {
		return nil, errors.New("user preferences tenant_id and user_id are required")
	}
	if err := s.ensureUserPreferenceTable(ctx); err != nil {
		return nil, err
	}
	// #nosec G201 -- column list is fixed and lookup values remain parameterized.
	row := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT %s FROM user_preferences WHERE tenant_id = $1 AND user_id = $2", userPreferenceColumns), tenantID, userID)
	preferences, err := scanUserPreferences(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s/%s", ports.ErrUserPreferencesNotFound, tenantID, userID)
		}
		return nil, fmt.Errorf("query user preferences for tenant %q user %q: %w", tenantID, userID, err)
	}
	return preferences, nil
}

func scanUserPreferences(row scanner) (*ports.UserPreferences, error) {
	var preferences ports.UserPreferences
	if err := row.Scan(
		&preferences.TenantID,
		&preferences.UserID,
		&preferences.PreferencesJSON,
		&preferences.CreatedAt,
		&preferences.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &preferences, nil
}
