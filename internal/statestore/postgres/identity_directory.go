package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var _ ports.IdentityDirectoryStore = (*Store)(nil)

var ensureIdentityDirectoryStatements = []string{
	`CREATE TABLE IF NOT EXISTS identity_organizations (
  tenant_id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL DEFAULT '',
  domain TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  external_id TEXT NOT NULL DEFAULT '',
  user_count INTEGER NOT NULL DEFAULT 0,
  last_synced_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, org_id)
)`,
	`CREATE INDEX IF NOT EXISTS identity_organizations_updated_idx ON identity_organizations (tenant_id, updated_at DESC)`,
	`CREATE TABLE IF NOT EXISTS identity_users (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  org_id TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  display_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  provider TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  roles_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  groups_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  last_seen_at TIMESTAMPTZ,
  last_synced_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, user_id)
)`,
	`CREATE INDEX IF NOT EXISTS identity_users_org_updated_idx ON identity_users (tenant_id, org_id, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS identity_users_email_idx ON identity_users (tenant_id, email) WHERE email <> ''`,
}

const identityOrganizationColumns = `tenant_id, org_id, name, slug, domain, provider, source, external_id, GREATEST(user_count, (SELECT COUNT(*)::INTEGER FROM identity_users WHERE identity_users.tenant_id = identity_organizations.tenant_id AND identity_users.org_id = identity_organizations.org_id)) AS user_count, last_synced_at, created_at, updated_at`
const identityUserColumns = `tenant_id, user_id, org_id, subject, email, display_name, status, provider, source, roles_json::text, groups_json::text, last_seen_at, last_synced_at, created_at, updated_at`

func (s *Store) ensureIdentityDirectoryTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.identity.directory, "identity directory", ensureIdentityDirectoryStatements)
}

func (s *Store) UpsertIdentityOrganization(ctx context.Context, org *ports.IdentityOrganization) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if org == nil {
		return errors.New("identity organization is required")
	}
	tenantID := strings.TrimSpace(org.TenantID)
	orgID := strings.TrimSpace(org.OrgID)
	name := strings.TrimSpace(org.Name)
	if tenantID == "" || orgID == "" || name == "" {
		return errors.New("identity organization tenant_id, org_id, and name are required")
	}
	if err := s.ensureIdentityDirectoryTables(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO identity_organizations (
  tenant_id, org_id, name, slug, domain, provider, source, external_id, user_count, last_synced_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (tenant_id, org_id) DO UPDATE SET
  name = EXCLUDED.name,
  slug = EXCLUDED.slug,
  domain = EXCLUDED.domain,
  provider = EXCLUDED.provider,
  source = EXCLUDED.source,
  external_id = EXCLUDED.external_id,
  user_count = GREATEST(identity_organizations.user_count, EXCLUDED.user_count),
  last_synced_at = COALESCE(EXCLUDED.last_synced_at, identity_organizations.last_synced_at),
  updated_at = NOW()`,
		tenantID,
		orgID,
		name,
		strings.TrimSpace(org.Slug),
		strings.TrimSpace(org.Domain),
		strings.TrimSpace(org.Provider),
		strings.TrimSpace(org.Source),
		strings.TrimSpace(org.ExternalID),
		org.UserCount,
		nullableUTC(org.LastSyncedAt),
	); err != nil {
		return fmt.Errorf("upsert identity organization %q/%q: %w", tenantID, orgID, err)
	}
	return nil
}

func (s *Store) UpsertIdentityUser(ctx context.Context, user *ports.IdentityUser) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if user == nil {
		return errors.New("identity user is required")
	}
	tenantID := strings.TrimSpace(user.TenantID)
	userID := strings.TrimSpace(user.UserID)
	displayName := strings.TrimSpace(user.DisplayName)
	if tenantID == "" || userID == "" || displayName == "" {
		return errors.New("identity user tenant_id, user_id, and display_name are required")
	}
	roles, err := stringSliceJSON(normalizedNonEmptyStrings(user.Roles))
	if err != nil {
		return fmt.Errorf("marshal identity user roles: %w", err)
	}
	groups, err := stringSliceJSON(normalizedNonEmptyStrings(user.Groups))
	if err != nil {
		return fmt.Errorf("marshal identity user groups: %w", err)
	}
	if err := s.ensureIdentityDirectoryTables(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO identity_users (
  tenant_id, user_id, org_id, subject, email, display_name, status, provider, source,
  roles_json, groups_json, last_seen_at, last_synced_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13)
ON CONFLICT (tenant_id, user_id) DO UPDATE SET
  org_id = EXCLUDED.org_id,
  subject = EXCLUDED.subject,
  email = EXCLUDED.email,
  display_name = EXCLUDED.display_name,
  status = EXCLUDED.status,
  provider = EXCLUDED.provider,
  source = EXCLUDED.source,
  roles_json = EXCLUDED.roles_json,
  groups_json = EXCLUDED.groups_json,
  last_seen_at = COALESCE(EXCLUDED.last_seen_at, identity_users.last_seen_at),
  last_synced_at = COALESCE(EXCLUDED.last_synced_at, identity_users.last_synced_at),
  updated_at = NOW()`,
		tenantID,
		userID,
		strings.TrimSpace(user.OrgID),
		strings.TrimSpace(user.Subject),
		strings.ToLower(strings.TrimSpace(user.Email)),
		displayName,
		identityUserStatus(user.Status),
		strings.TrimSpace(user.Provider),
		strings.TrimSpace(user.Source),
		roles,
		groups,
		nullableUTC(user.LastSeenAt),
		nullableUTC(user.LastSyncedAt),
	); err != nil {
		return fmt.Errorf("upsert identity user %q/%q: %w", tenantID, userID, err)
	}
	return nil
}

func (s *Store) ListIdentityOrganizations(ctx context.Context, filter ports.IdentityOrganizationFilter) ([]*ports.IdentityOrganization, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureIdentityDirectoryTables(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1=1"}
	args := []any{}
	addIdentityStringClause(&clauses, &args, "tenant_id", filter.TenantID)
	addIdentityStringClause(&clauses, &args, "org_id", filter.OrgID)
	if query := strings.TrimSpace(filter.Query); query != "" {
		args = append(args, "%"+strings.ToLower(query)+"%")
		clauses = append(clauses, fmt.Sprintf("(LOWER(org_id) LIKE $%d OR LOWER(name) LIKE $%d OR LOWER(domain) LIKE $%d)", len(args), len(args), len(args)))
	}
	args = append(args, identityDirectoryLimit(filter.Limit))
	// #nosec G201 -- clauses and selected columns are fixed identifiers; values remain query parameters.
	query := fmt.Sprintf("SELECT %s FROM identity_organizations WHERE %s ORDER BY updated_at DESC, name ASC, org_id ASC LIMIT $%d", identityOrganizationColumns, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list identity organizations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var organizations []*ports.IdentityOrganization
	for rows.Next() {
		item, err := scanIdentityOrganization(rows)
		if err != nil {
			return nil, err
		}
		organizations = append(organizations, item)
	}
	return organizations, rows.Err()
}

func (s *Store) ListIdentityUsers(ctx context.Context, filter ports.IdentityUserFilter) ([]*ports.IdentityUser, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureIdentityDirectoryTables(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1=1"}
	args := []any{}
	addIdentityStringClause(&clauses, &args, "tenant_id", filter.TenantID)
	addIdentityStringClause(&clauses, &args, "org_id", filter.OrgID)
	addIdentityStringClause(&clauses, &args, "user_id", filter.UserID)
	if query := strings.TrimSpace(filter.Query); query != "" {
		args = append(args, "%"+strings.ToLower(query)+"%")
		clauses = append(clauses, fmt.Sprintf("(LOWER(user_id) LIKE $%d OR LOWER(email) LIKE $%d OR LOWER(display_name) LIKE $%d)", len(args), len(args), len(args)))
	}
	args = append(args, identityDirectoryLimit(filter.Limit))
	// #nosec G201 -- clauses and selected columns are fixed identifiers; values remain query parameters.
	query := fmt.Sprintf("SELECT %s FROM identity_users WHERE %s ORDER BY updated_at DESC, display_name ASC, user_id ASC LIMIT $%d", identityUserColumns, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list identity users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var users []*ports.IdentityUser
	for rows.Next() {
		item, err := scanIdentityUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, item)
	}
	return users, rows.Err()
}

func scanIdentityOrganization(row scanner) (*ports.IdentityOrganization, error) {
	org := &ports.IdentityOrganization{}
	var lastSynced sql.NullTime
	if err := row.Scan(
		&org.TenantID,
		&org.OrgID,
		&org.Name,
		&org.Slug,
		&org.Domain,
		&org.Provider,
		&org.Source,
		&org.ExternalID,
		&org.UserCount,
		&lastSynced,
		&org.CreatedAt,
		&org.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if lastSynced.Valid {
		org.LastSyncedAt = lastSynced.Time.UTC()
	}
	return org, nil
}

func scanIdentityUser(row scanner) (*ports.IdentityUser, error) {
	user := &ports.IdentityUser{}
	var rolesJSON, groupsJSON string
	var lastSeen, lastSynced sql.NullTime
	if err := row.Scan(
		&user.TenantID,
		&user.UserID,
		&user.OrgID,
		&user.Subject,
		&user.Email,
		&user.DisplayName,
		&user.Status,
		&user.Provider,
		&user.Source,
		&rolesJSON,
		&groupsJSON,
		&lastSeen,
		&lastSynced,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return nil, err
	}
	var err error
	if user.Roles, err = stringSliceFromJSON(rolesJSON); err != nil {
		return nil, err
	}
	if user.Groups, err = stringSliceFromJSON(groupsJSON); err != nil {
		return nil, err
	}
	if lastSeen.Valid {
		user.LastSeenAt = lastSeen.Time.UTC()
	}
	if lastSynced.Valid {
		user.LastSyncedAt = lastSynced.Time.UTC()
	}
	return user, nil
}

func addIdentityStringClause(clauses *[]string, args *[]any, column string, value string) {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		*args = append(*args, trimmed)
		// #nosec G201 -- column is supplied by package-local callers with fixed identifiers.
		*clauses = append(*clauses, fmt.Sprintf("%s = $%d", column, len(*args)))
	}
}

func identityDirectoryLimit(limit uint32) uint32 {
	const (
		defaultLimit uint32 = 100
		maxLimit     uint32 = 500
	)
	switch {
	case limit == 0:
		return defaultLimit
	case limit > maxLimit:
		return maxLimit
	default:
		return limit
	}
}

func identityUserStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "inactive", "suspended", "disabled":
		return strings.ToLower(strings.TrimSpace(status))
	default:
		return "active"
	}
}
