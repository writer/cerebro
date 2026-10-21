package postgres

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestIdentitySSOLockoutInvariantUnderConcurrency(t *testing.T) {
	store, tenantID := openIdentitySSOTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	if err := store.PutSSOPolicy(ctx, &ports.SSOPolicy{TenantID: tenantID, Enforced: true, SessionMaxLifetimeMinutes: 60, SessionIdleTimeoutMinutes: 30}); !errors.Is(err, ports.ErrSSONoActiveConnection) {
		t.Fatalf("enforcing without an active connection = %v", err)
	}
	putActiveIdentityConnection(t, store, tenantID, "conn_a", now)
	putActiveIdentityConnection(t, store, tenantID, "conn_b", now)
	if err := store.PutSSOPolicy(ctx, &ports.SSOPolicy{TenantID: tenantID, Enforced: true, SessionMaxLifetimeMinutes: 60, SessionIdleTimeoutMinutes: 30}); err != nil {
		t.Fatalf("PutSSOPolicy() error = %v", err)
	}

	disable := func(conn ports.SSOConnection) (ports.SSOConnectionUpdate, error) {
		conn.Status = "disabled"
		return ports.SSOConnectionUpdate{Connection: conn}, nil
	}
	for round := 0; round < 5; round++ {
		var wg sync.WaitGroup
		results := make([]error, 2)
		for i, id := range []string{"conn_a", "conn_b"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if i == 0 {
					_, results[i] = store.UpdateSSOConnection(ctx, tenantID, id, 20, disable)
				} else {
					results[i] = store.DeleteSSOConnection(ctx, tenantID, id)
				}
			}()
		}
		wg.Wait()
		failures := 0
		for _, err := range results {
			if errors.Is(err, ports.ErrSSOLastActiveConnection) {
				failures++
			} else if err != nil {
				t.Fatalf("round %d: unexpected error %v", round, err)
			}
		}
		if failures != 1 {
			t.Fatalf("round %d: %d writers refused, want exactly 1 (results %v)", round, failures, results)
		}
		conns, err := store.ListSSOConnections(ctx, tenantID)
		if err != nil {
			t.Fatalf("ListSSOConnections() error = %v", err)
		}
		if !slices.ContainsFunc(conns, func(c ports.SSOConnection) bool { return c.Status == ports.SSOStatusActive }) {
			t.Fatalf("round %d: enforced tenant left without an active connection: %+v", round, conns)
		}
		// Reset for the next round.
		for _, id := range []string{"conn_a", "conn_b"} {
			putActiveIdentityConnection(t, store, tenantID, id, now)
		}
	}
	if err := store.PutSSOPolicy(ctx, &ports.SSOPolicy{TenantID: tenantID, Enforced: false, SessionMaxLifetimeMinutes: 60, SessionIdleTimeoutMinutes: 30}); err != nil {
		t.Fatalf("relax policy: %v", err)
	}
	if _, err := store.UpdateSSOConnection(ctx, tenantID, "conn_a", 20, disable); err != nil {
		t.Fatalf("disable without enforcement: %v", err)
	}
}

func identitySession(tenantID string, token string, connectionID string, subject string, email string, now time.Time) ports.SSOSession {
	return ports.SSOSession{
		TenantID: tenantID, ID: "sess_" + token, TokenHash: strings.Repeat(token, 64)[:64], ConnectionID: connectionID, Subject: subject, Email: email,
		Roles: []string{"cerebro.viewer"}, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour), IdleTimeoutMinutes: 30,
	}
}

func TestIdentitySSOSessionLookupChecksConnectionAndUser(t *testing.T) {
	store, tenantID := openIdentitySSOTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	putActiveIdentityConnection(t, store, tenantID, "conn_a", now)
	putActiveIdentityConnection(t, store, tenantID, "conn_b", now)
	user := ports.DirectoryUser{TenantID: tenantID, ID: "usr_a", ConnectionID: "conn_a", Source: "jit", UserName: "a@example.com", Email: "a@example.com", Subject: "sub-a", Active: true, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateDirectoryUser(ctx, &user); err != nil {
		t.Fatalf("CreateDirectoryUser() error = %v", err)
	}
	bySubject := identitySession(tenantID, "1", "conn_a", "sub-a", "", now)
	byEmail := identitySession(tenantID, "2", "conn_a", "other", "A@Example.com", now)
	otherConn := identitySession(tenantID, "3", "conn_b", "sub-a", "a@example.com", now)
	for _, session := range []*ports.SSOSession{&bySubject, &byEmail, &otherConn} {
		if err := store.CreateSSOSession(ctx, session); err != nil {
			t.Fatalf("CreateSSOSession() error = %v", err)
		}
	}
	expect := func(label string, session ports.SSOSession, found bool) {
		t.Helper()
		_, err := store.GetSSOSession(ctx, tenantID, session.TokenHash)
		if found && err != nil {
			t.Fatalf("%s: GetSSOSession(%s) = %v, want found", label, session.ID, err)
		}
		if !found && !errors.Is(err, ports.ErrSSOSessionNotFound) {
			t.Fatalf("%s: GetSSOSession(%s) = %v, want not found", label, session.ID, err)
		}
	}
	expect("live", bySubject, true)
	expect("live", byEmail, true)

	setActive := func(active bool) {
		if _, err := store.MutateDirectoryUser(ctx, tenantID, "conn_a", "usr_a", func(u *ports.DirectoryUser) error {
			u.Active = active
			return nil
		}); err != nil {
			t.Fatalf("MutateDirectoryUser() error = %v", err)
		}
	}
	setActive(false)
	expect("inactive user", bySubject, false)
	expect("inactive user", byEmail, false)
	expect("other connection", otherConn, true)
	setActive(true)
	expect("reactivated user", bySubject, true)

	if _, err := store.TombstoneDirectoryUser(ctx, tenantID, "conn_a", "usr_a", now); err != nil {
		t.Fatalf("TombstoneDirectoryUser() error = %v", err)
	}
	expect("deleted user", bySubject, false)
	expect("deleted user", byEmail, false)

	if _, err := store.UpdateSSOConnection(ctx, tenantID, "conn_b", 20, func(c ports.SSOConnection) (ports.SSOConnectionUpdate, error) {
		c.Status = "disabled"
		return ports.SSOConnectionUpdate{Connection: c}, nil
	}); err != nil {
		t.Fatalf("disable conn_b: %v", err)
	}
	expect("disabled connection", otherConn, false)
}

func TestIdentitySSORevocationScopes(t *testing.T) {
	store, tenantID := openIdentitySSOTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	putActiveIdentityConnection(t, store, tenantID, "conn_a", now)
	putActiveIdentityConnection(t, store, tenantID, "conn_b", now)
	a1 := identitySession(tenantID, "4", "conn_a", "sub-x", "x@example.com", now)
	a2 := identitySession(tenantID, "5", "conn_a", "sub-y", "y@example.com", now)
	b1 := identitySession(tenantID, "6", "conn_b", "sub-x", "x@example.com", now)
	for _, session := range []*ports.SSOSession{&a1, &a2, &b1} {
		if err := store.CreateSSOSession(ctx, session); err != nil {
			t.Fatalf("CreateSSOSession() error = %v", err)
		}
	}
	revoked, err := store.RevokeSSOSessions(ctx, tenantID, ports.SSOSessionMatch{ConnectionID: "conn_a", Subjects: []string{"sub-x"}}, now)
	if err != nil || revoked != 1 {
		t.Fatalf("connection-scoped revoke = %d %v", revoked, err)
	}
	if got, _ := store.GetSSOSession(ctx, tenantID, b1.TokenHash); got.RevokedAt != nil {
		t.Fatal("revocation leaked to another connection")
	}
	if _, err := store.UpdateSSOConnection(ctx, tenantID, "conn_a", 20, func(c ports.SSOConnection) (ports.SSOConnectionUpdate, error) {
		c.DefaultRoles = []string{"cerebro.admin"}
		c.UpdatedAt = now
		return ports.SSOConnectionUpdate{Connection: c, RevokeSessions: true}, nil
	}); err != nil {
		t.Fatalf("UpdateSSOConnection() error = %v", err)
	}
	if got, _ := store.GetSSOSession(ctx, tenantID, a2.TokenHash); got.RevokedAt == nil {
		t.Fatal("connection update with RevokeSessions left a session live")
	}
	if got, _ := store.GetSSOSession(ctx, tenantID, b1.TokenHash); got.RevokedAt != nil {
		t.Fatal("connection update revoked another connection's session")
	}
}

func TestIdentitySAMLAssertionReplay(t *testing.T) {
	store, tenantID := openIdentitySSOTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	use := ports.SAMLAssertionUse{TenantID: tenantID, ConnectionID: "conn_a", AssertionID: "_a1", RequestID: "_r1", ConsumedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := store.ConsumeSAMLAssertion(ctx, use); err != nil {
		t.Fatalf("ConsumeSAMLAssertion() error = %v", err)
	}
	sameAssertion := use
	sameAssertion.RequestID = "_r2"
	sameRequest := use
	sameRequest.ConnectionID, sameRequest.AssertionID = "conn_b", "_a2"
	for name, replay := range map[string]ports.SAMLAssertionUse{"same assertion": sameAssertion, "same request": sameRequest} {
		if err := store.ConsumeSAMLAssertion(ctx, replay); !errors.Is(err, ports.ErrSAMLAssertionReplayed) {
			t.Fatalf("%s: err = %v, want replay", name, err)
		}
	}
	otherConnection := use
	otherConnection.ConnectionID, otherConnection.RequestID = "conn_b", "_r3"
	if err := store.ConsumeSAMLAssertion(ctx, otherConnection); err != nil {
		t.Fatalf("same assertion ID on another connection: %v", err)
	}

	concurrent := ports.SAMLAssertionUse{TenantID: tenantID, ConnectionID: "conn_a", AssertionID: "_race", RequestID: "_race", ConsumedAt: now, ExpiresAt: now.Add(time.Minute)}
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := store.ConsumeSAMLAssertion(ctx, concurrent)
			if err != nil && !errors.Is(err, ports.ErrSAMLAssertionReplayed) {
				t.Errorf("concurrent consume: %v", err)
				return
			}
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("concurrent consumers succeeded %d times, want 1", successes)
	}

	afterExpiry := use
	afterExpiry.ConsumedAt, afterExpiry.ExpiresAt = now.Add(2*time.Minute), now.Add(3*time.Minute)
	if err := store.ConsumeSAMLAssertion(ctx, afterExpiry); err != nil {
		t.Fatalf("expired entry must be pruned: %v", err)
	}
}

func TestIdentityDirectoryWritesDoNotLoseUpdates(t *testing.T) {
	store, tenantID := openIdentitySSOTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	putActiveIdentityConnection(t, store, tenantID, "conn_a", now)
	ids := []string{"usr_0", "usr_1", "usr_2", "usr_3", "usr_4", "usr_5"}
	for _, id := range ids {
		user := ports.DirectoryUser{TenantID: tenantID, ID: id, ConnectionID: "conn_a", Source: "scim", UserName: id + "@example.com", Active: true, CreatedAt: now, UpdatedAt: now}
		if err := store.CreateDirectoryUser(ctx, &user); err != nil {
			t.Fatalf("CreateDirectoryUser() error = %v", err)
		}
	}

	// One writer deactivates while others rename; the deactivation must survive.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := store.MutateDirectoryUser(ctx, tenantID, "conn_a", "usr_0", func(u *ports.DirectoryUser) error {
			u.Active = false
			return nil
		}); err != nil {
			t.Errorf("deactivate: %v", err)
		}
	}()
	for _, suffix := range []string{"a", "b", "c", "d", "e", "f"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.MutateDirectoryUser(ctx, tenantID, "conn_a", "usr_0", func(u *ports.DirectoryUser) error {
				u.DisplayName += suffix
				return nil
			}); err != nil {
				t.Errorf("rename: %v", err)
			}
		}()
	}
	wg.Wait()
	users, _, err := store.ListDirectoryUsers(ctx, ports.DirectoryUserQuery{TenantID: tenantID, IDs: []string{"usr_0"}, Limit: 1})
	if err != nil || len(users) != 1 || users[0].Active || len(users[0].DisplayName) != 6 {
		t.Fatalf("concurrent user writes lost an update: %+v %v", users, err)
	}

	group := ports.DirectoryGroup{TenantID: tenantID, ID: "grp_all", ConnectionID: "conn_a", DisplayName: "All", MemberIDs: ids, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateDirectoryGroup(ctx, &group); err != nil {
		t.Fatalf("CreateDirectoryGroup() error = %v", err)
	}
	for _, id := range ids[:4] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.MutateDirectoryGroup(ctx, tenantID, "conn_a", "grp_all", func(g *ports.DirectoryGroup) error {
				g.MemberIDs = slices.DeleteFunc(g.MemberIDs, func(m string) bool { return m == id })
				return nil
			}); err != nil {
				t.Errorf("remove member: %v", err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := store.TombstoneDirectoryUser(ctx, tenantID, "conn_a", "usr_5", now); err != nil {
			t.Errorf("tombstone: %v", err)
		}
	}()
	wg.Wait()
	got, err := store.GetDirectoryGroup(ctx, tenantID, "conn_a", "grp_all")
	if err != nil || strings.Join(got.MemberIDs, ",") != "usr_4" {
		t.Fatalf("concurrent group writes restored a removed member: %+v %v", got, err)
	}
}

func TestIdentityDirectorySubjectBindingAndTombstones(t *testing.T) {
	store, tenantID := openIdentitySSOTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	putActiveIdentityConnection(t, store, tenantID, "conn_a", now)
	putActiveIdentityConnection(t, store, tenantID, "conn_b", now)
	newUser := func(id string, conn string, subject string) ports.DirectoryUser {
		return ports.DirectoryUser{TenantID: tenantID, ID: id, ConnectionID: conn, Source: "jit", UserName: id + "@example.com", Email: id + "@example.com", Subject: subject, Active: true, CreatedAt: now, UpdatedAt: now}
	}
	first := newUser("usr_1", "conn_a", "sub-1")
	if err := store.CreateDirectoryUser(ctx, &first); err != nil {
		t.Fatalf("CreateDirectoryUser() error = %v", err)
	}
	clash := newUser("usr_2", "conn_a", "sub-1")
	if err := store.CreateDirectoryUser(ctx, &clash); !errors.Is(err, ports.ErrDirectoryConflict) {
		t.Fatalf("duplicate subject binding = %v", err)
	}
	otherConn := newUser("usr_3", "conn_b", "sub-1")
	if err := store.CreateDirectoryUser(ctx, &otherConn); err != nil {
		t.Fatalf("same subject on another connection = %v", err)
	}
	unbound := newUser("usr_4", "conn_a", "")
	unbound2 := newUser("usr_5", "conn_a", "")
	for _, user := range []*ports.DirectoryUser{&unbound, &unbound2} {
		if err := store.CreateDirectoryUser(ctx, user); err != nil {
			t.Fatalf("unbound users must not conflict: %v", err)
		}
	}
	users, _, err := store.ListDirectoryUsers(ctx, ports.DirectoryUserQuery{TenantID: tenantID, ConnectionID: "conn_a", Subject: "sub-1", Limit: 10})
	if err != nil || len(users) != 1 || users[0].ID != "usr_1" {
		t.Fatalf("ListDirectoryUsers(subject) = %+v %v", users, err)
	}

	if _, err := store.TombstoneDirectoryUser(ctx, tenantID, "conn_a", "usr_1", now); err != nil {
		t.Fatalf("TombstoneDirectoryUser() error = %v", err)
	}
	if _, err := store.GetDirectoryUser(ctx, tenantID, "conn_a", "usr_1"); !errors.Is(err, ports.ErrDirectoryUserNotFound) {
		t.Fatalf("tombstone visible to GetDirectoryUser: %v", err)
	}
	if users, total, _ := store.ListDirectoryUsers(ctx, ports.DirectoryUserQuery{TenantID: tenantID, ConnectionID: "conn_a", Subject: "sub-1", Limit: 10}); total != 0 || len(users) != 0 {
		t.Fatalf("tombstone listed by default: %+v", users)
	}
	users, _, _ = store.ListDirectoryUsers(ctx, ports.DirectoryUserQuery{TenantID: tenantID, ConnectionID: "conn_a", Subject: "sub-1", IncludeDeleted: true, Limit: 10})
	if len(users) != 1 || users[0].DeletedAt == nil || users[0].Active {
		t.Fatalf("tombstone with IncludeDeleted = %+v", users)
	}
	revived, err := store.MutateDirectoryUser(ctx, tenantID, "conn_a", "usr_1", func(u *ports.DirectoryUser) error {
		u.DeletedAt, u.Active, u.Source = nil, true, "scim"
		return nil
	})
	if err != nil || revived.DeletedAt != nil || !revived.Active {
		t.Fatalf("revive = %+v %v", revived, err)
	}
	if _, err := store.GetDirectoryUser(ctx, tenantID, "conn_a", "usr_1"); err != nil {
		t.Fatalf("revived user not found: %v", err)
	}
}

func TestIdentitySCIMTokenOnBehalfOf(t *testing.T) {
	store, tenantID := openIdentitySSOTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	token := ports.SCIMToken{TenantID: tenantID, ID: "scim_obo", ConnectionID: "conn_a", Name: "okta", Prefix: "cscim_abcdef", TokenHash: strings.Repeat("d", 64), CreatedAt: now, CreatedBy: "svc-web", CreatedOnBehalfOf: "alice@example.com"}
	if err := store.CreateSCIMToken(ctx, &token); err != nil {
		t.Fatalf("CreateSCIMToken() error = %v", err)
	}
	found, err := store.GetSCIMTokenByHash(ctx, tenantID, token.TokenHash)
	if err != nil || found.CreatedBy != "svc-web" || found.CreatedOnBehalfOf != "alice@example.com" {
		t.Fatalf("token audit = %+v %v", found, err)
	}
}
