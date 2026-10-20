package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// CreateSCIMToken stores a hashed SCIM token.
func (s *Store) CreateSCIMToken(ctx context.Context, token *ports.SCIMToken) error {
	if token == nil {
		return errors.New("scim token is required")
	}
	tenantID, err := s.identityTenant(ctx, token.TenantID)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO identity_scim_tokens (tenant_id, token_id, connection_id, name, prefix, token_hash, created_at, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, tenantID, token.ID, token.ConnectionID, token.Name, token.Prefix, token.TokenHash, token.CreatedAt.UTC(), token.CreatedBy); err != nil {
		return fmt.Errorf("insert scim token: %w", err)
	}
	return nil
}

const identitySCIMTokenColumns = `tenant_id, token_id, connection_id, name, prefix, token_hash, created_at, created_by, last_used_at`

func scanSCIMToken(scanner riskScoringConfigScanner) (*ports.SCIMToken, error) {
	var token ports.SCIMToken
	var lastUsed sql.NullTime
	if err := scanner.Scan(&token.TenantID, &token.ID, &token.ConnectionID, &token.Name, &token.Prefix, &token.TokenHash, &token.CreatedAt, &token.CreatedBy, &lastUsed); err != nil {
		return nil, err
	}
	token.CreatedAt = token.CreatedAt.UTC()
	token.LastUsedAt = nullTimePointer(lastUsed)
	return &token, nil
}

// ListSCIMTokens lists a tenant's SCIM tokens, newest first.
func (s *Store) ListSCIMTokens(ctx context.Context, tenantID string) ([]ports.SCIMToken, error) {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+identitySCIMTokenColumns+` FROM identity_scim_tokens WHERE tenant_id = $1 ORDER BY created_at DESC, token_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list scim tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	tokens := []ports.SCIMToken{}
	for rows.Next() {
		token, err := scanSCIMToken(rows)
		if err != nil {
			return nil, fmt.Errorf("scan scim token: %w", err)
		}
		tokens = append(tokens, *token)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list scim tokens: %w", err)
	}
	return tokens, nil
}

// GetSCIMTokenByHash looks up a SCIM token by its SHA-256 hash.
func (s *Store) GetSCIMTokenByHash(ctx context.Context, tenantID string, tokenHash string) (*ports.SCIMToken, error) {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+identitySCIMTokenColumns+` FROM identity_scim_tokens WHERE tenant_id = $1 AND token_hash = $2`, tenantID, tokenHash)
	token, err := scanSCIMToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrSCIMTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get scim token: %w", err)
	}
	return token, nil
}

// TouchSCIMToken records SCIM token use.
func (s *Store) TouchSCIMToken(ctx context.Context, tenantID string, tokenID string, usedAt time.Time) error {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE identity_scim_tokens SET last_used_at = $3 WHERE tenant_id = $1 AND token_id = $2`, tenantID, tokenID, usedAt.UTC()); err != nil {
		return fmt.Errorf("touch scim token: %w", err)
	}
	return nil
}

// DeleteSCIMToken removes a SCIM token.
func (s *Store) DeleteSCIMToken(ctx context.Context, tenantID string, tokenID string) error {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM identity_scim_tokens WHERE tenant_id = $1 AND token_id = $2`, tenantID, tokenID)
	if err != nil {
		return fmt.Errorf("delete scim token: %w", err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return ports.ErrSCIMTokenNotFound
	}
	return nil
}

const ssoDirectoryUserColumns = `tenant_id, user_id, connection_id, source, user_name, external_id, subject, email, display_name, given_name, family_name, active, jit_groups_json::text, created_at, updated_at, last_login_at`

func scanDirectoryUser(scanner riskScoringConfigScanner) (*ports.DirectoryUser, error) {
	var user ports.DirectoryUser
	var jitGroups string
	var lastLogin sql.NullTime
	if err := scanner.Scan(&user.TenantID, &user.ID, &user.ConnectionID, &user.Source, &user.UserName, &user.ExternalID, &user.Subject,
		&user.Email, &user.DisplayName, &user.GivenName, &user.FamilyName, &user.Active, &jitGroups, &user.CreatedAt, &user.UpdatedAt, &lastLogin); err != nil {
		return nil, err
	}
	var err error
	if user.JITGroups, err = decodeIdentityList(jitGroups); err != nil {
		return nil, fmt.Errorf("decode directory user groups: %w", err)
	}
	user.CreatedAt = user.CreatedAt.UTC()
	user.UpdatedAt = user.UpdatedAt.UTC()
	user.LastLoginAt = nullTimePointer(lastLogin)
	return &user, nil
}

func identityLikePattern(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + replacer.Replace(strings.ToLower(strings.TrimSpace(value))) + "%"
}

const ssoDirectoryUserFilter = `tenant_id = $1
  AND ($2 = '' OR connection_id = $2)
  AND ($3 = '' OR lower(user_name) = lower($3))
  AND ($4 = '' OR lower(email) = lower($4) OR lower(user_name) = lower($4))
  AND ($5 = '' OR lower(user_name) LIKE $6 OR lower(email) LIKE $6 OR lower(display_name) LIKE $6)`

// ListDirectoryUsers returns one page of users and the total match count.
func (s *Store) ListDirectoryUsers(ctx context.Context, query ports.DirectoryUserQuery) ([]ports.DirectoryUser, int, error) {
	tenantID, err := s.identityTenant(ctx, query.TenantID)
	if err != nil {
		return nil, 0, err
	}
	search := strings.TrimSpace(query.Search)
	args := []any{tenantID, strings.TrimSpace(query.ConnectionID), strings.TrimSpace(query.UserName), strings.TrimSpace(query.Email), search, identityLikePattern(search)}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_directory_users WHERE `+ssoDirectoryUserFilter, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count directory users: %w", err)
	}
	if query.Limit <= 0 {
		return []ports.DirectoryUser{}, total, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+ssoDirectoryUserColumns+` FROM identity_directory_users WHERE `+ssoDirectoryUserFilter+`
ORDER BY lower(user_name), user_id OFFSET $7 LIMIT $8`, append(args, max(query.Offset, 0), query.Limit)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list directory users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	users := []ports.DirectoryUser{}
	for rows.Next() {
		user, err := scanDirectoryUser(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan directory user: %w", err)
		}
		users = append(users, *user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list directory users: %w", err)
	}
	if err := s.attachUserGroups(ctx, tenantID, users); err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

func (s *Store) attachUserGroups(ctx context.Context, tenantID string, users []ports.DirectoryUser) error {
	if len(users) == 0 {
		return nil
	}
	ids := make([]string, 0, len(users))
	index := make(map[string]int, len(users))
	for i, user := range users {
		ids = append(ids, user.ID)
		index[user.ID] = i
	}
	rows, err := s.db.QueryContext(ctx, `SELECT m.user_id, g.group_id, g.display_name
FROM identity_directory_memberships m
JOIN identity_directory_groups g ON g.tenant_id = m.tenant_id AND g.group_id = m.group_id
WHERE m.tenant_id = $1 AND m.user_id IN (SELECT jsonb_array_elements_text($2::jsonb))
ORDER BY lower(g.display_name), g.group_id`, tenantID, identityJSONList(ids))
	if err != nil {
		return fmt.Errorf("list directory user groups: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var userID string
		var ref ports.DirectoryGroupRef
		if err := rows.Scan(&userID, &ref.ID, &ref.DisplayName); err != nil {
			return fmt.Errorf("scan directory user group: %w", err)
		}
		if i, ok := index[userID]; ok {
			users[i].Groups = append(users[i].Groups, ref)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list directory user groups: %w", err)
	}
	return nil
}

// GetDirectoryUser loads one user. Empty connectionID matches any connection.
func (s *Store) GetDirectoryUser(ctx context.Context, tenantID string, connectionID string, userID string) (*ports.DirectoryUser, error) {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+ssoDirectoryUserColumns+` FROM identity_directory_users WHERE tenant_id = $1 AND user_id = $2 AND ($3 = '' OR connection_id = $3)`, tenantID, userID, strings.TrimSpace(connectionID))
	user, err := scanDirectoryUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrDirectoryUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get directory user: %w", err)
	}
	users := []ports.DirectoryUser{*user}
	if err := s.attachUserGroups(ctx, tenantID, users); err != nil {
		return nil, err
	}
	return &users[0], nil
}

// CreateDirectoryUser inserts a user. A duplicate userName within the
// connection returns ErrDirectoryConflict.
func (s *Store) CreateDirectoryUser(ctx context.Context, user *ports.DirectoryUser) error {
	if user == nil {
		return errors.New("directory user is required")
	}
	tenantID, err := s.identityTenant(ctx, user.TenantID)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO identity_directory_users (tenant_id, user_id, connection_id, source, user_name, external_id, subject, email, display_name, given_name, family_name, active, jit_groups_json, created_at, updated_at, last_login_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15, $16)`,
		tenantID, user.ID, user.ConnectionID, user.Source, user.UserName, user.ExternalID, user.Subject, user.Email, user.DisplayName,
		user.GivenName, user.FamilyName, user.Active, identityJSONList(user.JITGroups), user.CreatedAt.UTC(), user.UpdatedAt.UTC(), nullTimeValue(user.LastLoginAt)); err != nil {
		if identityUniqueViolation(err) {
			return ports.ErrDirectoryConflict
		}
		return fmt.Errorf("insert directory user: %w", err)
	}
	return nil
}

// UpdateDirectoryUser replaces a user's mutable attributes.
func (s *Store) UpdateDirectoryUser(ctx context.Context, user *ports.DirectoryUser) error {
	if user == nil {
		return errors.New("directory user is required")
	}
	tenantID, err := s.identityTenant(ctx, user.TenantID)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE identity_directory_users SET source = $3, user_name = $4, external_id = $5, subject = $6, email = $7, display_name = $8,
  given_name = $9, family_name = $10, active = $11, jit_groups_json = $12::jsonb, updated_at = $13, last_login_at = $14
WHERE tenant_id = $1 AND user_id = $2`,
		tenantID, user.ID, user.Source, user.UserName, user.ExternalID, user.Subject, user.Email, user.DisplayName,
		user.GivenName, user.FamilyName, user.Active, identityJSONList(user.JITGroups), user.UpdatedAt.UTC(), nullTimeValue(user.LastLoginAt))
	if err != nil {
		if identityUniqueViolation(err) {
			return ports.ErrDirectoryConflict
		}
		return fmt.Errorf("update directory user: %w", err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return ports.ErrDirectoryUserNotFound
	}
	return nil
}

// DeleteDirectoryUser removes a user and its group memberships.
func (s *Store) DeleteDirectoryUser(ctx context.Context, tenantID string, connectionID string, userID string) error {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM identity_directory_users WHERE tenant_id = $1 AND user_id = $2 AND ($3 = '' OR connection_id = $3)`, tenantID, userID, strings.TrimSpace(connectionID))
	if err != nil {
		return fmt.Errorf("delete directory user: %w", err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return ports.ErrDirectoryUserNotFound
	}
	return nil
}

const ssoDirectoryGroupFilter = `g.tenant_id = $1
  AND ($2 = '' OR g.connection_id = $2)
  AND ($3 = '' OR lower(g.display_name) = lower($3))`

// ListDirectoryGroups returns one page of groups, with member IDs, and the total match count.
func (s *Store) ListDirectoryGroups(ctx context.Context, query ports.DirectoryGroupQuery) ([]ports.DirectoryGroup, int, error) {
	tenantID, err := s.identityTenant(ctx, query.TenantID)
	if err != nil {
		return nil, 0, err
	}
	args := []any{tenantID, strings.TrimSpace(query.ConnectionID), strings.TrimSpace(query.DisplayName)}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_directory_groups g WHERE `+ssoDirectoryGroupFilter, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count directory groups: %w", err)
	}
	if query.Limit <= 0 {
		return []ports.DirectoryGroup{}, total, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT g.tenant_id, g.group_id, g.connection_id, g.display_name, g.external_id, g.created_at, g.updated_at,
  (SELECT COUNT(*) FROM identity_directory_memberships m WHERE m.tenant_id = g.tenant_id AND m.group_id = g.group_id)::int
FROM identity_directory_groups g WHERE `+ssoDirectoryGroupFilter+`
ORDER BY lower(g.display_name), g.group_id OFFSET $4 LIMIT $5`, append(args, max(query.Offset, 0), query.Limit)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list directory groups: %w", err)
	}
	defer func() { _ = rows.Close() }()
	groups := []ports.DirectoryGroup{}
	for rows.Next() {
		group, err := scanDirectoryGroup(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan directory group: %w", err)
		}
		groups = append(groups, *group)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list directory groups: %w", err)
	}
	if err := s.attachGroupMembers(ctx, tenantID, groups); err != nil {
		return nil, 0, err
	}
	return groups, total, nil
}

func scanDirectoryGroup(scanner riskScoringConfigScanner) (*ports.DirectoryGroup, error) {
	var group ports.DirectoryGroup
	if err := scanner.Scan(&group.TenantID, &group.ID, &group.ConnectionID, &group.DisplayName, &group.ExternalID, &group.CreatedAt, &group.UpdatedAt, &group.MemberCount); err != nil {
		return nil, err
	}
	group.CreatedAt = group.CreatedAt.UTC()
	group.UpdatedAt = group.UpdatedAt.UTC()
	return &group, nil
}

func (s *Store) attachGroupMembers(ctx context.Context, tenantID string, groups []ports.DirectoryGroup) error {
	if len(groups) == 0 {
		return nil
	}
	ids := make([]string, 0, len(groups))
	index := make(map[string]int, len(groups))
	for i, group := range groups {
		ids = append(ids, group.ID)
		index[group.ID] = i
		groups[i].MemberIDs = []string{}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT group_id, user_id FROM identity_directory_memberships
WHERE tenant_id = $1 AND group_id IN (SELECT jsonb_array_elements_text($2::jsonb)) ORDER BY group_id, user_id`, tenantID, identityJSONList(ids))
	if err != nil {
		return fmt.Errorf("list directory group members: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var groupID, userID string
		if err := rows.Scan(&groupID, &userID); err != nil {
			return fmt.Errorf("scan directory group member: %w", err)
		}
		if i, ok := index[groupID]; ok {
			groups[i].MemberIDs = append(groups[i].MemberIDs, userID)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list directory group members: %w", err)
	}
	return nil
}

// GetDirectoryGroup loads one group with its member IDs.
func (s *Store) GetDirectoryGroup(ctx context.Context, tenantID string, connectionID string, groupID string) (*ports.DirectoryGroup, error) {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `SELECT g.tenant_id, g.group_id, g.connection_id, g.display_name, g.external_id, g.created_at, g.updated_at,
  (SELECT COUNT(*) FROM identity_directory_memberships m WHERE m.tenant_id = g.tenant_id AND m.group_id = g.group_id)::int
FROM identity_directory_groups g WHERE g.tenant_id = $1 AND g.group_id = $2 AND ($3 = '' OR g.connection_id = $3)`, tenantID, groupID, strings.TrimSpace(connectionID))
	group, err := scanDirectoryGroup(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrDirectoryGroupNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get directory group: %w", err)
	}
	groups := []ports.DirectoryGroup{*group}
	if err := s.attachGroupMembers(ctx, tenantID, groups); err != nil {
		return nil, err
	}
	return &groups[0], nil
}

// CreateDirectoryGroup inserts a group and its memberships. Member IDs that do
// not name a user in the same connection are skipped.
func (s *Store) CreateDirectoryGroup(ctx context.Context, group *ports.DirectoryGroup) error {
	return s.writeDirectoryGroup(ctx, group, true)
}

// UpdateDirectoryGroup replaces a group's attributes and memberships. Member
// IDs that do not name a user in the same connection are skipped.
func (s *Store) UpdateDirectoryGroup(ctx context.Context, group *ports.DirectoryGroup) error {
	return s.writeDirectoryGroup(ctx, group, false)
}

func (s *Store) writeDirectoryGroup(ctx context.Context, group *ports.DirectoryGroup, create bool) error {
	if group == nil {
		return errors.New("directory group is required")
	}
	tenantID, err := s.identityTenant(ctx, group.TenantID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin directory group write: %w", err)
	}
	defer identityRollback(tx)
	var result sql.Result
	if create {
		result, err = tx.ExecContext(ctx, `INSERT INTO identity_directory_groups (tenant_id, group_id, connection_id, display_name, external_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`, tenantID, group.ID, group.ConnectionID, group.DisplayName, group.ExternalID, group.CreatedAt.UTC(), group.UpdatedAt.UTC())
	} else {
		result, err = tx.ExecContext(ctx, `UPDATE identity_directory_groups SET display_name = $3, external_id = $4, updated_at = $5
WHERE tenant_id = $1 AND group_id = $2`, tenantID, group.ID, group.DisplayName, group.ExternalID, group.UpdatedAt.UTC())
	}
	if err != nil {
		if identityUniqueViolation(err) {
			return ports.ErrDirectoryConflict
		}
		return fmt.Errorf("write directory group: %w", err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return ports.ErrDirectoryGroupNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM identity_directory_memberships WHERE tenant_id = $1 AND group_id = $2`, tenantID, group.ID); err != nil {
		return fmt.Errorf("reset directory group members: %w", err)
	}
	if len(group.MemberIDs) > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO identity_directory_memberships (tenant_id, group_id, user_id)
SELECT u.tenant_id, $2, u.user_id FROM identity_directory_users u
WHERE u.tenant_id = $1 AND u.connection_id = $3 AND u.user_id IN (SELECT jsonb_array_elements_text($4::jsonb))
ON CONFLICT DO NOTHING`, tenantID, group.ID, group.ConnectionID, identityJSONList(group.MemberIDs)); err != nil {
			return fmt.Errorf("write directory group members: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit directory group: %w", err)
	}
	return nil
}

// DeleteDirectoryGroup removes a group and its memberships.
func (s *Store) DeleteDirectoryGroup(ctx context.Context, tenantID string, connectionID string, groupID string) error {
	tenantID, err := s.identityTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM identity_directory_groups WHERE tenant_id = $1 AND group_id = $2 AND ($3 = '' OR connection_id = $3)`, tenantID, groupID, strings.TrimSpace(connectionID))
	if err != nil {
		return fmt.Errorf("delete directory group: %w", err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return ports.ErrDirectoryGroupNotFound
	}
	return nil
}
