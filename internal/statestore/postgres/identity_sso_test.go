package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestCheckSSOConnectionPut(t *testing.T) {
	existing := []ports.SSOConnection{
		{ID: "conn_a", Domains: []string{"example.com"}},
		{ID: "conn_b", Domains: []string{"example.org"}},
	}
	if err := checkSSOConnectionPut(existing, ports.SSOConnection{ID: "conn_a", Domains: []string{"example.com", "example.net"}}, 2); err != nil {
		t.Fatalf("updating a connection with its own domain: %v", err)
	}
	err := checkSSOConnectionPut(existing, ports.SSOConnection{ID: "conn_a", Domains: []string{"example.org"}}, 5)
	if !errors.Is(err, ports.ErrSSODomainConflict) {
		t.Fatalf("domain owned by another connection: %v", err)
	}
	if err := checkSSOConnectionPut(existing, ports.SSOConnection{ID: "conn_c"}, 2); !errors.Is(err, ports.ErrSSOConnectionLimit) {
		t.Fatalf("new connection over the limit: %v", err)
	}
	if err := checkSSOConnectionPut(existing, ports.SSOConnection{ID: "conn_b"}, 2); err != nil {
		t.Fatalf("updates are allowed at the limit: %v", err)
	}
}

func TestIdentityJSONListRoundTrip(t *testing.T) {
	if got := identityJSONList(nil); got != "[]" {
		t.Fatalf("identityJSONList(nil) = %q", got)
	}
	values, err := decodeIdentityList(identityJSONList([]string{"a", "b\"c"}))
	if err != nil || strings.Join(values, ",") != `a,b"c` {
		t.Fatalf("round trip = %v %v", values, err)
	}
	if values, err := decodeIdentityList(" "); err != nil || values == nil || len(values) != 0 {
		t.Fatalf("empty payload = %v %v", values, err)
	}
	if _, err := decodeIdentityList("{"); err == nil {
		t.Fatal("invalid payload should fail")
	}
}

func openIdentitySSOTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run identity SSO persistence integration test")
	}
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	tenantID := "identity-sso-test-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	ctx := context.Background()
	cleanup := func() {
		for _, statement := range []string{
			`DELETE FROM identity_sso_sessions WHERE tenant_id IN ($1, $2)`,
			`DELETE FROM identity_scim_tokens WHERE tenant_id IN ($1, $2)`,
			`DELETE FROM identity_directory_groups WHERE tenant_id IN ($1, $2)`,
			`DELETE FROM identity_directory_users WHERE tenant_id IN ($1, $2)`,
			`DELETE FROM identity_sso_connections WHERE tenant_id IN ($1, $2)`,
			`DELETE FROM identity_sso_policies WHERE tenant_id IN ($1, $2)`,
			`DELETE FROM identity_saml_assertions WHERE tenant_id IN ($1, $2)`,
		} {
			_, _ = store.db.ExecContext(ctx, statement, tenantID, tenantID+"-other")
		}
	}
	if err := store.ensureIdentitySSOTables(ctx); err != nil {
		t.Fatalf("ensureIdentitySSOTables() error = %v", err)
	}
	cleanup()
	t.Cleanup(func() {
		cleanup()
		_ = store.Close()
	})
	return store, tenantID
}

func TestIdentitySSOConnectionsAndPolicyPersistence(t *testing.T) {
	store, tenantID := openIdentitySSOTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	if _, err := store.GetSSOPolicy(ctx, tenantID); !errors.Is(err, ports.ErrSSOPolicyNotFound) {
		t.Fatalf("GetSSOPolicy() before save = %v", err)
	}
	if _, err := store.ListSSOConnections(ctx, " "); !errors.Is(err, errIdentityTenantRequired) {
		t.Fatalf("blank tenant = %v", err)
	}
	conn := ports.SSOConnection{
		TenantID: tenantID, ID: "conn_a", Name: "Okta", Protocol: "oidc", Status: "active",
		Domains:      []string{"example.com"},
		OIDC:         &ports.SSOOIDCConfig{Issuer: "https://example.okta.com", ClientID: "c", ClientSecretRef: "env:X", Scopes: []string{"openid"}, GroupsClaim: "groups"},
		RoleMappings: []ports.SSORoleMapping{{Group: "admins", Roles: []string{"cerebro.admin"}}},
		CreatedAt:    now, UpdatedAt: now,
		LastTest: &ports.SSOConnectionRun{At: now, OK: true, Actor: "a"},
	}
	if err := store.PutSSOConnection(ctx, &conn, 2); err != nil {
		t.Fatalf("PutSSOConnection() error = %v", err)
	}
	got, err := store.GetSSOConnection(ctx, tenantID, "conn_a")
	if err != nil {
		t.Fatalf("GetSSOConnection() error = %v", err)
	}
	if got.TenantID != tenantID || got.OIDC.ClientSecretRef != "env:X" || got.LastTest == nil || !got.LastTest.At.Equal(now) || got.DefaultRoles == nil {
		t.Fatalf("GetSSOConnection() = %+v", got)
	}
	if _, err := store.GetSSOConnection(ctx, tenantID+"-other", "conn_a"); !errors.Is(err, ports.ErrSSOConnectionNotFound) {
		t.Fatalf("cross-tenant GetSSOConnection() = %v", err)
	}
	dup := conn
	dup.ID, dup.Name = "conn_b", "Dup"
	if err := store.PutSSOConnection(ctx, &dup, 2); !errors.Is(err, ports.ErrSSODomainConflict) {
		t.Fatalf("duplicate domain = %v", err)
	}
	dup.Domains = []string{"example.org"}
	if err := store.PutSSOConnection(ctx, &dup, 2); err != nil {
		t.Fatalf("second connection = %v", err)
	}
	third := dup
	third.ID, third.Domains = "conn_c", nil
	if err := store.PutSSOConnection(ctx, &third, 2); !errors.Is(err, ports.ErrSSOConnectionLimit) {
		t.Fatalf("over limit = %v", err)
	}
	other := conn
	other.TenantID = tenantID + "-other"
	if err := store.PutSSOConnection(ctx, &other, 2); err != nil {
		t.Fatalf("same domain in another tenant = %v", err)
	}
	list, err := store.ListSSOConnections(ctx, tenantID)
	if err != nil || len(list) != 2 || list[0].Name != "Dup" {
		t.Fatalf("ListSSOConnections() = %+v %v", list, err)
	}

	policy := ports.SSOPolicy{TenantID: tenantID, Enforced: true, SessionMaxLifetimeMinutes: 480, SessionIdleTimeoutMinutes: 30, UpdatedAt: now, UpdatedBy: "admin"}
	if err := store.PutSSOPolicy(ctx, &policy); err != nil {
		t.Fatalf("PutSSOPolicy() error = %v", err)
	}
	savedPolicy, err := store.GetSSOPolicy(ctx, tenantID)
	if err != nil || !savedPolicy.Enforced || savedPolicy.SessionIdleTimeoutMinutes != 30 || savedPolicy.TenantID != tenantID {
		t.Fatalf("GetSSOPolicy() = %+v %v", savedPolicy, err)
	}

	if err := store.DeleteSSOConnection(ctx, tenantID, "conn_a"); err != nil {
		t.Fatalf("DeleteSSOConnection() error = %v", err)
	}
	if err := store.DeleteSSOConnection(ctx, tenantID, "conn_a"); !errors.Is(err, ports.ErrSSOConnectionNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestIdentitySSOSessionsAndTokensPersistence(t *testing.T) {
	store, tenantID := openIdentitySSOTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	putActiveIdentityConnection(t, store, tenantID, "conn_a", now)
	hash := strings.Repeat("a", 63) + "1"
	session := ports.SSOSession{
		TenantID: tenantID, ID: "sess_1", TokenHash: hash, ConnectionID: "conn_a", Subject: "00u1", Email: "Alice@Example.com",
		Groups: []string{"eng"}, Roles: []string{"cerebro.viewer"}, UserAgent: "ua", CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(time.Hour), IdleTimeoutMinutes: 30,
	}
	if err := store.CreateSSOSession(ctx, &session); err != nil {
		t.Fatalf("CreateSSOSession() error = %v", err)
	}
	if err := store.CreateSSOSession(ctx, &session); !errors.Is(err, ports.ErrSSOSessionExists) {
		t.Fatalf("duplicate session = %v", err)
	}
	got, err := store.GetSSOSession(ctx, tenantID, hash)
	if err != nil || got.Email != "Alice@Example.com" || strings.Join(got.Roles, ",") != "cerebro.viewer" || got.RevokedAt != nil {
		t.Fatalf("GetSSOSession() = %+v %v", got, err)
	}
	if _, err := store.GetSSOSession(ctx, tenantID+"-other", hash); !errors.Is(err, ports.ErrSSOSessionNotFound) {
		t.Fatalf("cross-tenant GetSSOSession() = %v", err)
	}
	seen := now.Add(5 * time.Minute)
	if err := store.TouchSSOSession(ctx, tenantID, hash, seen); err != nil {
		t.Fatalf("TouchSSOSession() error = %v", err)
	}
	if err := store.TouchSSOSession(ctx, tenantID, hash, now); err != nil {
		t.Fatalf("TouchSSOSession(older) error = %v", err)
	}
	if got, _ := store.GetSSOSession(ctx, tenantID, hash); !got.LastSeenAt.Equal(seen) {
		t.Fatalf("lastSeenAt = %v, want %v (touch must not move backwards)", got.LastSeenAt, seen)
	}
	listed, err := store.ListSSOSessions(ctx, tenantID, "alice@example.COM", now, 10)
	if err != nil || len(listed) != 1 {
		t.Fatalf("ListSSOSessions(email) = %+v %v", listed, err)
	}
	if listed, _ := store.ListSSOSessions(ctx, tenantID, "", now.Add(2*time.Hour), 10); len(listed) != 0 {
		t.Fatalf("expired sessions listed: %+v", listed)
	}
	if revoked, err := store.RevokeSSOSessions(ctx, tenantID, ports.SSOSessionMatch{}, now); err != nil || revoked != 0 {
		t.Fatalf("empty match revoked %d %v", revoked, err)
	}
	revoked, err := store.RevokeSSOSessions(ctx, tenantID, ports.SSOSessionMatch{Emails: []string{"ALICE@example.com"}}, now)
	if err != nil || revoked != 1 {
		t.Fatalf("RevokeSSOSessions() = %d %v", revoked, err)
	}
	if got, _ := store.GetSSOSession(ctx, tenantID, hash); got.RevokedAt == nil {
		t.Fatal("session not revoked")
	}
	if revoked, _ := store.RevokeSSOSessions(ctx, tenantID, ports.SSOSessionMatch{Subjects: []string{"00u1"}}, now); revoked != 0 {
		t.Fatalf("already-revoked sessions revoked again: %d", revoked)
	}

	// Creating a session prunes long-dead rows for the tenant.
	later := session
	later.ID, later.TokenHash = "sess_2", strings.Repeat("b", 64)
	later.CreatedAt, later.LastSeenAt, later.ExpiresAt = now.Add(48*time.Hour), now.Add(48*time.Hour), now.Add(49*time.Hour)
	if err := store.CreateSSOSession(ctx, &later); err != nil {
		t.Fatalf("CreateSSOSession(later) error = %v", err)
	}
	if _, err := store.GetSSOSession(ctx, tenantID, hash); !errors.Is(err, ports.ErrSSOSessionNotFound) {
		t.Fatalf("revoked session should be pruned: %v", err)
	}
	if err := store.DeleteSSOSession(ctx, tenantID, later.TokenHash); err != nil {
		t.Fatalf("DeleteSSOSession() error = %v", err)
	}
	if err := store.DeleteSSOSession(ctx, tenantID, later.TokenHash); err != nil {
		t.Fatalf("DeleteSSOSession(missing) error = %v", err)
	}

	token := ports.SCIMToken{TenantID: tenantID, ID: "scim_1", ConnectionID: "conn_a", Name: "okta", Prefix: "cscim_abcdef", TokenHash: strings.Repeat("c", 64), CreatedAt: now, CreatedBy: "admin"}
	if err := store.CreateSCIMToken(ctx, &token); err != nil {
		t.Fatalf("CreateSCIMToken() error = %v", err)
	}
	found, err := store.GetSCIMTokenByHash(ctx, tenantID, token.TokenHash)
	if err != nil || found.ID != "scim_1" || found.LastUsedAt != nil {
		t.Fatalf("GetSCIMTokenByHash() = %+v %v", found, err)
	}
	if _, err := store.GetSCIMTokenByHash(ctx, tenantID+"-other", token.TokenHash); !errors.Is(err, ports.ErrSCIMTokenNotFound) {
		t.Fatalf("cross-tenant token lookup = %v", err)
	}
	if err := store.TouchSCIMToken(ctx, tenantID, "scim_1", now); err != nil {
		t.Fatalf("TouchSCIMToken() error = %v", err)
	}
	tokens, err := store.ListSCIMTokens(ctx, tenantID)
	if err != nil || len(tokens) != 1 || tokens[0].LastUsedAt == nil || !tokens[0].LastUsedAt.Equal(now) {
		t.Fatalf("ListSCIMTokens() = %+v %v", tokens, err)
	}
	if err := store.DeleteSCIMToken(ctx, tenantID, "scim_1"); err != nil {
		t.Fatalf("DeleteSCIMToken() error = %v", err)
	}
	if err := store.DeleteSCIMToken(ctx, tenantID, "scim_1"); !errors.Is(err, ports.ErrSCIMTokenNotFound) {
		t.Fatalf("second DeleteSCIMToken() = %v", err)
	}
}

func TestIdentitySSODirectoryPersistence(t *testing.T) {
	store, tenantID := openIdentitySSOTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	putActiveIdentityConnection(t, store, tenantID, "conn_a", now)
	newUser := func(id string, userName string, source string) ports.DirectoryUser {
		return ports.DirectoryUser{TenantID: tenantID, ID: id, ConnectionID: "conn_a", Source: source, UserName: userName, Email: userName, Active: true, CreatedAt: now, UpdatedAt: now}
	}
	alice := newUser("usr_alice", "Alice@example.com", "scim")
	alice.JITGroups = []string{"eng"}
	bob := newUser("usr_bob", "bob@example.com", "jit")
	at := now
	bob.LastLoginAt = &at
	for _, user := range []*ports.DirectoryUser{&alice, &bob} {
		if err := store.CreateDirectoryUser(ctx, user); err != nil {
			t.Fatalf("CreateDirectoryUser(%s) error = %v", user.ID, err)
		}
	}
	clash := newUser("usr_clash", "ALICE@EXAMPLE.COM", "scim")
	if err := store.CreateDirectoryUser(ctx, &clash); !errors.Is(err, ports.ErrDirectoryConflict) {
		t.Fatalf("duplicate userName = %v", err)
	}
	if _, err := store.MutateDirectoryUser(ctx, tenantID, "conn_a", "usr_bob", func(user *ports.DirectoryUser) error {
		user.UserName = "alice@example.com"
		return nil
	}); !errors.Is(err, ports.ErrDirectoryConflict) {
		t.Fatalf("rename onto existing userName = %v", err)
	}
	if _, err := store.MutateDirectoryUser(ctx, tenantID, "conn_a", "usr_missing", func(*ports.DirectoryUser) error { return nil }); !errors.Is(err, ports.ErrDirectoryUserNotFound) {
		t.Fatalf("update missing user = %v", err)
	}

	users, total, err := store.ListDirectoryUsers(ctx, ports.DirectoryUserQuery{TenantID: tenantID, ConnectionID: "conn_a", UserName: "alice@EXAMPLE.com", Limit: 10})
	if err != nil || total != 1 || len(users) != 1 || users[0].ID != "usr_alice" || strings.Join(users[0].JITGroups, ",") != "eng" {
		t.Fatalf("ListDirectoryUsers(userName) = %+v %d %v", users, total, err)
	}
	users, total, _ = store.ListDirectoryUsers(ctx, ports.DirectoryUserQuery{TenantID: tenantID, Search: "BOB", Limit: 10})
	if total != 1 || users[0].LastLoginAt == nil || !users[0].LastLoginAt.Equal(now) {
		t.Fatalf("ListDirectoryUsers(search) = %+v %d", users, total)
	}
	users, total, _ = store.ListDirectoryUsers(ctx, ports.DirectoryUserQuery{TenantID: tenantID, Offset: 1, Limit: 1})
	if total != 2 || len(users) != 1 || users[0].ID != "usr_bob" {
		t.Fatalf("ListDirectoryUsers(page) = %+v %d", users, total)
	}
	if users, total, _ := store.ListDirectoryUsers(ctx, ports.DirectoryUserQuery{TenantID: tenantID, Search: "%", Limit: 10}); total != 0 || len(users) != 0 {
		t.Fatalf("LIKE wildcards must be escaped: %+v", users)
	}

	group := ports.DirectoryGroup{TenantID: tenantID, ID: "grp_eng", ConnectionID: "conn_a", DisplayName: "Engineering", MemberIDs: []string{"usr_alice", "usr_bob", "usr_unknown"}, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateDirectoryGroup(ctx, &group); err != nil {
		t.Fatalf("CreateDirectoryGroup() error = %v", err)
	}
	dupGroup := group
	dupGroup.ID, dupGroup.DisplayName, dupGroup.MemberIDs = "grp_dup", "engineering", nil
	if err := store.CreateDirectoryGroup(ctx, &dupGroup); !errors.Is(err, ports.ErrDirectoryConflict) {
		t.Fatalf("duplicate displayName = %v", err)
	}
	gotGroup, err := store.GetDirectoryGroup(ctx, tenantID, "conn_a", "grp_eng")
	if err != nil || gotGroup.MemberCount != 2 || len(gotGroup.MemberIDs) != 2 {
		t.Fatalf("GetDirectoryGroup() = %+v %v", gotGroup, err)
	}
	if _, err := store.GetDirectoryGroup(ctx, tenantID, "conn_other", "grp_eng"); !errors.Is(err, ports.ErrDirectoryGroupNotFound) {
		t.Fatalf("cross-connection group = %v", err)
	}
	gotUser, err := store.GetDirectoryUser(ctx, tenantID, "conn_a", "usr_alice")
	if err != nil || len(gotUser.Groups) != 1 || gotUser.Groups[0].DisplayName != "Engineering" {
		t.Fatalf("GetDirectoryUser() groups = %+v %v", gotUser, err)
	}
	if _, err := store.MutateDirectoryGroup(ctx, tenantID, "conn_a", "grp_eng", func(g *ports.DirectoryGroup) error {
		g.MemberIDs = []string{"usr_bob"}
		return nil
	}); err != nil {
		t.Fatalf("MutateDirectoryGroup() error = %v", err)
	}
	groups, total, err := store.ListDirectoryGroups(ctx, ports.DirectoryGroupQuery{TenantID: tenantID, DisplayName: "ENGINEERING", Limit: 10})
	if err != nil || total != 1 || strings.Join(groups[0].MemberIDs, ",") != "usr_bob" || groups[0].MemberCount != 1 {
		t.Fatalf("ListDirectoryGroups() = %+v %d %v", groups, total, err)
	}

	before, err := store.TombstoneDirectoryUser(ctx, tenantID, "conn_a", "usr_bob", now)
	if err != nil || !before.Active || len(before.Groups) != 1 {
		t.Fatalf("TombstoneDirectoryUser() = %+v %v", before, err)
	}
	if gotGroup, _ := store.GetDirectoryGroup(ctx, tenantID, "conn_a", "grp_eng"); gotGroup.MemberCount != 0 {
		t.Fatalf("membership should be removed on tombstone: %+v", gotGroup)
	}
	if _, err := store.TombstoneDirectoryUser(ctx, tenantID, "conn_a", "usr_bob", now); !errors.Is(err, ports.ErrDirectoryUserNotFound) {
		t.Fatalf("second TombstoneDirectoryUser() = %v", err)
	}
	deleted, err := store.DeleteDirectoryGroup(ctx, tenantID, "conn_a", "grp_eng")
	if err != nil || deleted.ID != "grp_eng" {
		t.Fatalf("DeleteDirectoryGroup() = %+v %v", deleted, err)
	}

	if err := store.DeleteSSOConnection(ctx, tenantID, "conn_a"); err != nil {
		t.Fatalf("DeleteSSOConnection() error = %v", err)
	}
	if _, err := store.GetDirectoryUser(ctx, tenantID, "conn_a", "usr_alice"); !errors.Is(err, ports.ErrDirectoryUserNotFound) {
		t.Fatalf("users should be removed with their connection: %v", err)
	}
}

func putActiveIdentityConnection(t *testing.T, store *Store, tenantID string, id string, now time.Time) {
	t.Helper()
	conn := ports.SSOConnection{TenantID: tenantID, ID: id, Name: id, Protocol: "oidc", Status: ports.SSOStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := store.PutSSOConnection(context.Background(), &conn, 20); err != nil {
		t.Fatalf("PutSSOConnection(%s) error = %v", id, err)
	}
}
