package identitysso

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	sso "github.com/writer/cerebro/internal/identitysso"
	"github.com/writer/cerebro/internal/ports"
)

func samlUse(connectionID string, assertionID string, requestID string, notOnOrAfter time.Time) map[string]any {
	return map[string]any{"connectionId": connectionID, "assertionId": assertionID, "requestId": requestID, "notOnOrAfter": notOnOrAfter.Format(time.RFC3339)}
}

func TestSAMLAssertionReplayIsRejected(t *testing.T) {
	h := newHarness(t)
	later := h.now.Add(5 * time.Minute)
	first := h.expect(h.do(http.MethodPost, "/platform/identity/saml/assertions", samlUse("okta", "_a1", "_r1", later)), http.StatusCreated)
	if first.body["consumed"] != true {
		t.Fatalf("first use = %s", first.raw)
	}
	h.expectError(h.do(http.MethodPost, "/platform/identity/saml/assertions", samlUse("okta", "_a1", "_r2", later)), http.StatusConflict, "assertion_replayed")
	h.expectError(h.do(http.MethodPost, "/platform/identity/saml/assertions", samlUse("entra", "_a9", "_r1", later)), http.StatusConflict, "assertion_replayed")
	h.expect(h.do(http.MethodPost, "/platform/identity/saml/assertions", samlUse("entra", "_a1", "_r3", later)), http.StatusCreated)

	for _, bad := range []map[string]any{
		samlUse("okta", "_a2", "_r4", h.now.Add(-time.Second)),
		{"connectionId": "okta", "assertionId": "_a3"},
		samlUse("okta", "", "_r6", later),
	} {
		res := h.expect(h.do(http.MethodPost, "/platform/identity/saml/assertions", bad), http.StatusBadRequest)
		if res.body["code"] != "invalid_request" {
			t.Fatalf("bad assertion = %s", res.raw)
		}
	}

	// The record must outlive the assertion, so validity past the replay window is refused, not clamped.
	h.expect(h.do(http.MethodPost, "/platform/identity/saml/assertions", samlUse("okta", "_a4", "_r5", h.now.Add(sso.MaxSAMLReplayWindow+time.Minute))), http.StatusBadRequest)
}

func TestSessionCreationIsBoundByConnectionAndPolicy(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	other := h.activeConnection("Entra", "example.org")

	// Another connection's IdP cannot sign in an address routed to this one.
	h.expectError(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(other, "x-1", "sub-x", "x@example.com")), http.StatusForbidden, "domain_not_allowed")
	h.expectError(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(other, "sub-x", "x@example.com")), http.StatusForbidden, "domain_not_allowed")

	// Caller-supplied lifetime and idle timeout never exceed the policy.
	h.expect(h.do(http.MethodPut, "/platform/identity/sso/policy", map[string]any{"sessionMaxLifetimeMinutes": 60, "sessionIdleTimeoutMinutes": 15}), http.StatusOK)
	body := sessionBody(conn, "v-1", "sub-v", "v@example.com")
	body["expiresAt"] = h.now.Add(7 * 24 * time.Hour).Format(time.RFC3339)
	body["idleTimeoutMinutes"] = 600
	created := h.expect(h.do(http.MethodPost, "/platform/identity/sessions", body), http.StatusCreated)
	stored := h.store.sessions[sso.HashToken("v-1")]
	if !stored.ExpiresAt.Equal(h.now.Add(time.Hour)) || stored.IdleTimeoutMinutes != 15 {
		t.Fatalf("session not clamped to policy: expiresAt=%s idle=%d (%s)", stored.ExpiresAt, stored.IdleTimeoutMinutes, created.raw)
	}

	// Without JIT, only a provisioned directory user can get a session.
	noJIT := oidcConnection("NoJIT", "example.net")
	noJIT["jitProvisioning"] = false
	noJITID := h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections", noJIT), http.StatusCreated).body["id"].(string)
	h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections/"+noJITID+"/test-result", map[string]any{"ok": true}), http.StatusOK)
	noJIT["status"] = "active"
	h.expect(h.do(http.MethodPut, "/platform/identity/sso/connections/"+noJITID, noJIT), http.StatusOK)
	h.expectError(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(noJITID, "n-1", "sub-n", "n@example.net")), http.StatusConflict, "jit_disabled")
	h.expectError(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(noJITID, "sub-n", "n@example.net")), http.StatusConflict, "jit_disabled")
}

func jitLogin(connectionID string, subject string, email string, groups ...string) map[string]any {
	return map[string]any{"connectionId": connectionID, "subject": subject, "email": email, "groups": groups}
}

func anyStrings(value any) []string {
	items, _ := value.([]any)
	out := []string{}
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestJITSubjectBindingAndGroupReplacement(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")

	created := h.expect(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(conn, "sub-1", "carol@example.com", "admins", "eng")), http.StatusCreated)
	id := created.body["id"].(string)
	again := h.expect(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(conn, "sub-1", "carol@example.com", "eng")), http.StatusOK)
	if got := anyStrings(again.body["jitGroups"]); !slices.Equal(got, []string{"eng"}) {
		t.Fatalf("jitGroups = %v, want the fresh assertion groups only", got)
	}
	if got := anyStrings(again.body["scimGroups"]); len(got) != 0 {
		t.Fatalf("scimGroups = %v, want none", got)
	}

	h.expectError(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(conn, "sub-2", "carol@example.com")), http.StatusConflict, "subject_mismatch")
	user, err := h.store.GetDirectoryUser(context.Background(), "default", conn, id)
	if err != nil || user.Subject != "sub-1" {
		t.Fatalf("binding changed: %+v %v", user, err)
	}

	// An existing user without a binding is bound by its first login.
	headers := scimHeaders(h.scimToken(conn))
	dave := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "dave@example.com"}, headers...), http.StatusCreated).body["id"].(string)
	h.expect(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(conn, "sub-d", "dave@example.com")), http.StatusOK)
	bound, _ := h.store.GetDirectoryUser(context.Background(), "default", conn, dave)
	if bound.Subject != "sub-d" {
		t.Fatalf("subject not bound: %+v", bound)
	}
}

func TestJITNeverWritesActiveOrSource(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	headers := scimHeaders(h.scimToken(conn))
	scimID := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "erin@example.com", "displayName": "Erin"}, headers...), http.StatusCreated).body["id"].(string)
	res := h.expect(h.do(http.MethodPost, "/platform/identity/directory/users/jit", map[string]any{"connectionId": conn, "subject": "sub-e", "email": "erin@example.com", "name": "Mallory", "groups": []string{"admins"}}), http.StatusOK)
	if res.body["source"] != "scim" || res.body["name"] != "Erin" || len(anyStrings(res.body["jitGroups"])) != 0 {
		t.Fatalf("JIT login rewrote a SCIM user: %s", res.raw)
	}
	stored, _ := h.store.GetDirectoryUser(context.Background(), "default", conn, scimID)
	if stored.Source != sso.DirectorySourceSCIM || !stored.Active {
		t.Fatalf("stored = %+v", stored)
	}
}

func TestSCIMAdoptionClearsJITGroupsAndExposesSCIMGroups(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	jitID := h.expect(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(conn, "sub-f", "frank@example.com", "admins")), http.StatusCreated).body["id"].(string)
	headers := scimHeaders(h.scimToken(conn))
	h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "frank@example.com"}, headers...), http.StatusCreated)
	h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Groups", map[string]any{"displayName": "Security", "members": []map[string]any{{"value": jitID}}}, headers...), http.StatusCreated)
	lookup := h.expect(h.do(http.MethodGet, "/platform/identity/directory/users/lookup?connectionId="+conn+"&email=frank@example.com", nil), http.StatusOK)
	if lookup.body["source"] != "scim" || len(anyStrings(lookup.body["jitGroups"])) != 0 || !slices.Equal(anyStrings(lookup.body["scimGroups"]), []string{"Security"}) {
		t.Fatalf("lookup = %s", lookup.raw)
	}
}

func TestSCIMDeleteTombstonesAndBlocksJIT(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	headers := scimHeaders(h.scimToken(conn))
	id := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "gina@example.com"}, headers...), http.StatusCreated).body["id"].(string)
	h.expect(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(conn, "sub-g", "gina@example.com")), http.StatusOK)
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "gina-1", "sub-g", "gina@example.com")), http.StatusCreated)

	h.expect(h.do(http.MethodDelete, "/platform/identity/scim/v2/Users/"+id, nil, headers...), http.StatusNoContent)
	h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Users/"+id, nil, headers...), http.StatusNotFound)
	list := h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Users", nil, headers...), http.StatusOK)
	if list.body["totalResults"] != float64(0) {
		t.Fatalf("tombstone listed: %s", list.raw)
	}
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("gina-1"), nil), http.StatusNotFound)
	tomb := h.store.users[key("default", id)]
	if tomb.DeletedAt == nil || tomb.Active {
		t.Fatalf("user not tombstoned: %+v", tomb)
	}

	h.expectError(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(conn, "sub-g", "gina@example.com")), http.StatusForbidden, "user_deprovisioned")
	h.expectError(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(conn, "sub-new", "gina@example.com")), http.StatusForbidden, "user_deprovisioned")
	h.expectError(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "gina-2", "sub-g", "gina@example.com")), http.StatusForbidden, "user_deprovisioned")
	h.expect(h.do(http.MethodGet, "/platform/identity/directory/users/lookup?connectionId="+conn+"&email=gina@example.com", nil), http.StatusNotFound)
	h.expect(h.do(http.MethodPatch, "/platform/identity/scim/v2/Users/"+id, `{"Operations":[{"op":"replace","path":"active","value":true}]}`, headers...), http.StatusNotFound)

	revived := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "gina@example.com"}, headers...), http.StatusCreated)
	if revived.body["id"] != id || revived.body["active"] != true {
		t.Fatalf("SCIM create should revive the tombstone: %s", revived.raw)
	}
	h.expect(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(conn, "sub-g", "gina@example.com")), http.StatusOK)
}

func TestSessionCreationRefusesInactiveUsers(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	headers := scimHeaders(h.scimToken(conn))
	h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "hank@example.com", "active": false}, headers...), http.StatusCreated)
	h.expectError(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "hank-1", "sub-h", "hank@example.com")), http.StatusForbidden, "user_inactive")
}

func TestGetSessionChecksConnectionAndUser(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	jitID := h.expect(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(conn, "sub-i", "ivy@example.com")), http.StatusCreated).body["id"].(string)
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "ivy-1", "sub-i", "ivy@example.com")), http.StatusCreated)
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("ivy-1"), nil), http.StatusOK)

	// Bypass every revocation path: the lookup itself must refuse.
	user := h.store.users[key("default", jitID)]
	user.Active = false
	h.store.users[key("default", jitID)] = user
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("ivy-1"), nil), http.StatusNotFound)
	user.Active = true
	h.store.users[key("default", jitID)] = user
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("ivy-1"), nil), http.StatusOK)

	stored := h.store.connections[key("default", conn)]
	stored.Status = sso.StatusDisabled
	h.store.connections[key("default", conn)] = stored
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("ivy-1"), nil), http.StatusNotFound)
}

func renamedConnection(name string, clientID string, domain string, status string) map[string]any {
	body := oidcConnection(name, domain)
	body["oidc"].(map[string]any)["clientId"] = clientID
	body["status"] = status
	return body
}

func TestConnectionChangesRevokeConnectionSessions(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	other := h.activeConnection("Entra", "example.org")
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "a-1", "sub-a", "a@example.com")), http.StatusCreated)
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(other, "b-1", "sub-b", "b@example.org")), http.StatusCreated)

	renamed := renamedConnection("Okta Renamed", "client-okta", "example.com", "active")
	h.expect(h.do(http.MethodPut, "/platform/identity/sso/connections/"+conn, renamed), http.StatusOK)
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("a-1"), nil), http.StatusOK)

	remapped := renamedConnection("Okta Renamed", "client-okta", "example.com", "active")
	remapped["roleMappings"] = []map[string]any{{"group": "everyone", "roles": []string{"cerebro.admin"}}}
	h.expect(h.do(http.MethodPut, "/platform/identity/sso/connections/"+conn, remapped), http.StatusOK)
	if h.store.sessions[sso.HashToken("a-1")].RevokedAt == nil {
		t.Fatal("role mapping change must revoke the connection's sessions")
	}
	if h.store.sessions[sso.HashToken("b-1")].RevokedAt != nil {
		t.Fatal("another connection's sessions must survive")
	}

	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "a-2", "sub-a", "a@example.com")), http.StatusCreated)
	disabled := renamedConnection("Okta Renamed", "client-okta", "example.com", "disabled")
	disabled["roleMappings"] = remapped["roleMappings"]
	h.expect(h.do(http.MethodPut, "/platform/identity/sso/connections/"+conn, disabled), http.StatusOK)
	if h.store.sessions[sso.HashToken("a-2")].RevokedAt == nil {
		t.Fatal("disabling a connection must revoke its sessions")
	}
}

func TestSCIMRevocationsAreConnectionScoped(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	other := h.activeConnection("Entra", "example.org")
	headers := scimHeaders(h.scimToken(conn))
	id := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "jo@example.com"}, headers...), http.StatusCreated).body["id"].(string)
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "jo-okta", "sub-j", "jo@example.com")), http.StatusCreated)
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(other, "jo-entra", "sub-j", "jo@example.org")), http.StatusCreated)

	h.expect(h.do(http.MethodPatch, "/platform/identity/scim/v2/Users/"+id, `{"Operations":[{"op":"replace","path":"active","value":false}]}`, headers...), http.StatusOK)
	if h.store.sessions[sso.HashToken("jo-okta")].RevokedAt == nil {
		t.Fatal("deactivation must revoke the user's sessions on the token's connection")
	}
	if h.store.sessions[sso.HashToken("jo-entra")].RevokedAt != nil {
		t.Fatal("deactivation through one connection revoked another connection's session")
	}
}

func TestSCIMAdoptionWithActiveFalseRevokesSessions(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	h.expect(h.do(http.MethodPost, "/platform/identity/directory/users/jit", jitLogin(conn, "sub-k", "kim@example.com")), http.StatusCreated)
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "kim-1", "sub-k", "kim@example.com")), http.StatusCreated)
	headers := scimHeaders(h.scimToken(conn))
	adopted := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "kim@example.com", "active": false}, headers...), http.StatusCreated)
	if adopted.body["active"] != false {
		t.Fatalf("adopted = %s", adopted.raw)
	}
	if h.store.sessions[sso.HashToken("kim-1")].RevokedAt == nil {
		t.Fatal("adopting a user with active:false must revoke its sessions")
	}
}

func TestSCIMGroupMembershipChangesRevokeAffectedMembers(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	headers := scimHeaders(h.scimToken(conn))
	u1 := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "u1@example.com"}, headers...), http.StatusCreated).body["id"].(string)
	u2 := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "u2@example.com"}, headers...), http.StatusCreated).body["id"].(string)
	h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "u3@example.com"}, headers...), http.StatusCreated)
	group := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Groups", map[string]any{"displayName": "Admins", "members": []map[string]any{{"value": u1}, {"value": u2}}}, headers...), http.StatusCreated).body["id"].(string)
	for _, name := range []string{"u1", "u2", "u3"} {
		h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, name+"-1", "sub-"+name, name+"@example.com")), http.StatusCreated)
	}

	h.expect(h.do(http.MethodPatch, "/platform/identity/scim/v2/Groups/"+group,
		`{"Operations":[{"op":"remove","path":"members[value eq \"`+u2+`\"]"}]}`, headers...), http.StatusOK)
	if h.store.sessions[sso.HashToken("u2-1")].RevokedAt == nil {
		t.Fatal("removed member's session must be revoked")
	}
	if h.store.sessions[sso.HashToken("u1-1")].RevokedAt != nil || h.store.sessions[sso.HashToken("u3-1")].RevokedAt != nil {
		t.Fatal("unaffected members' sessions must survive")
	}

	h.expect(h.do(http.MethodDelete, "/platform/identity/scim/v2/Groups/"+group, nil, headers...), http.StatusNoContent)
	if h.store.sessions[sso.HashToken("u1-1")].RevokedAt == nil {
		t.Fatal("deleting a group must revoke its members' sessions")
	}
	if h.store.sessions[sso.HashToken("u3-1")].RevokedAt != nil {
		t.Fatal("non-member session revoked")
	}
}

func TestAdminSessionLifetimeCapped(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	body := sessionBody(conn, "adm-1", "sub-adm", "adm@example.com")
	body["roles"] = []string{"cerebro.admin"}
	body["expiresAt"] = h.now.Add(23 * time.Hour).Format(time.RFC3339)
	h.expect(h.do(http.MethodPut, "/platform/identity/sso/policy", map[string]any{"sessionMaxLifetimeMinutes": 24 * 60, "sessionIdleTimeoutMinutes": 60}), http.StatusOK)
	created := h.expect(h.do(http.MethodPost, "/platform/identity/sessions", body), http.StatusCreated)
	expires, err := time.Parse(time.RFC3339, created.body["expiresAt"].(string))
	if err != nil || !expires.Equal(h.now.Add(sso.AdminSessionMaxLifetime)) {
		t.Fatalf("admin session expiresAt = %v (%v), want %s", created.body["expiresAt"], err, h.now.Add(sso.AdminSessionMaxLifetime))
	}
}

// staleWriteStore applies a concurrent change between the handler's request
// and its locked write, so a handler that wrote back its own earlier read would
// lose that change.
type staleWriteStore struct {
	*fakeStore
	userChange  func(*ports.DirectoryUser)
	groupChange func(*ports.DirectoryGroup)
}

func (s *staleWriteStore) MutateDirectoryUser(ctx context.Context, tenantID string, connectionID string, userID string, mutate func(*ports.DirectoryUser) error) (*ports.DirectoryUser, error) {
	if s.userChange != nil {
		if _, err := s.fakeStore.MutateDirectoryUser(ctx, tenantID, connectionID, userID, func(user *ports.DirectoryUser) error {
			s.userChange(user)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return s.fakeStore.MutateDirectoryUser(ctx, tenantID, connectionID, userID, mutate)
}

func (s *staleWriteStore) MutateDirectoryGroup(ctx context.Context, tenantID string, connectionID string, groupID string, mutate func(*ports.DirectoryGroup) error) (*ports.DirectoryGroup, error) {
	if s.groupChange != nil {
		if _, err := s.fakeStore.MutateDirectoryGroup(ctx, tenantID, connectionID, groupID, func(group *ports.DirectoryGroup) error {
			s.groupChange(group)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return s.fakeStore.MutateDirectoryGroup(ctx, tenantID, connectionID, groupID, mutate)
}

func TestSCIMWritesApplyToLockedCurrentState(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	headers := scimHeaders(h.scimToken(conn))
	id := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "lee@example.com"}, headers...), http.StatusCreated).body["id"].(string)
	u2 := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "max@example.com"}, headers...), http.StatusCreated).body["id"].(string)
	group := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Groups", map[string]any{"displayName": "Admins", "members": []map[string]any{{"value": id}, {"value": u2}}}, headers...), http.StatusCreated).body["id"].(string)

	stale := &staleWriteStore{
		fakeStore:  h.store,
		userChange: func(user *ports.DirectoryUser) { user.Active = false },
		groupChange: func(group *ports.DirectoryGroup) {
			group.MemberIDs = slices.DeleteFunc(group.MemberIDs, func(m string) bool { return m == u2 })
		},
	}
	h.mux = newTestMux(Handler{
		store:   stale,
		resolve: func(_ context.Context, requested string) (string, error) { return requested, nil },
		actor:   func(context.Context) string { return "admin@example.com" },
		now:     func() time.Time { return h.now },
	})

	renamed := h.expect(h.do(http.MethodPatch, "/platform/identity/scim/v2/Users/"+id, `{"Operations":[{"op":"replace","path":"displayName","value":"Lee"}]}`, headers...), http.StatusOK)
	if renamed.body["active"] != false || renamed.body["displayName"] != "Lee" {
		t.Fatalf("a concurrent deactivation was lost: %s", renamed.raw)
	}
	patched := h.expect(h.do(http.MethodPatch, "/platform/identity/scim/v2/Groups/"+group, `{"Operations":[{"op":"replace","path":"displayName","value":"Admins 2"}]}`, headers...), http.StatusOK)
	if members := patched.body["members"].([]any); len(members) != 1 {
		t.Fatalf("a concurrently removed member was restored: %s", patched.raw)
	}
}

func TestStoreEnforcesLockoutInvariant(t *testing.T) {
	h := newHarness(t)
	a := h.activeConnection("Okta", "example.com")
	b := h.activeConnection("Entra", "example.org")
	h.expect(h.do(http.MethodPut, "/platform/identity/sso/policy", map[string]any{"enforced": true}), http.StatusOK)
	disable := func(name string, domain string) map[string]any {
		body := oidcConnection(name, domain)
		body["status"] = "disabled"
		return body
	}
	h.expect(h.do(http.MethodPut, "/platform/identity/sso/connections/"+a, disable("Okta", "example.com")), http.StatusOK)
	h.expectError(h.do(http.MethodPut, "/platform/identity/sso/connections/"+b, disable("Entra", "example.org")), http.StatusConflict, "last_active_connection")
	h.expectError(h.do(http.MethodDelete, "/platform/identity/sso/connections/"+b, nil), http.StatusConflict, "last_active_connection")
	h.expect(h.do(http.MethodDelete, "/platform/identity/sso/connections/"+a, nil), http.StatusNoContent)
}

func TestAuditKeepsPrincipalAndOnBehalfOf(t *testing.T) {
	h := newHarness(t)
	body := oidcConnection("Okta", "example.com")
	body["updatedBy"] = "mallory@example.com"
	created := h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections", body), http.StatusCreated)
	if created.body["updatedBy"] != "admin@example.com" || created.body["updatedOnBehalfOf"] != "mallory@example.com" {
		t.Fatalf("create audit = %s", created.raw)
	}
	id := created.body["id"].(string)
	tested := h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections/"+id+"/test-result", map[string]any{"ok": true, "actor": "mallory@example.com"}), http.StatusOK)
	run := tested.body["lastTest"].(map[string]any)
	if run["actor"] != "admin@example.com" || run["onBehalfOf"] != "mallory@example.com" || tested.body["updatedBy"] != "admin@example.com" {
		t.Fatalf("test-result audit = %s", tested.raw)
	}
	body["status"] = "active"
	updated := h.expect(h.do(http.MethodPut, "/platform/identity/sso/connections/"+id, body), http.StatusOK)
	if updated.body["updatedBy"] != "admin@example.com" || updated.body["updatedOnBehalfOf"] != "mallory@example.com" {
		t.Fatalf("update audit = %s", updated.raw)
	}
	policy := h.expect(h.do(http.MethodPut, "/platform/identity/sso/policy", map[string]any{"enforced": false, "updatedBy": "mallory@example.com"}), http.StatusOK)
	if policy.body["updatedBy"] != "admin@example.com" || policy.body["updatedOnBehalfOf"] != "mallory@example.com" {
		t.Fatalf("policy audit = %s", policy.raw)
	}
	token := h.expect(h.do(http.MethodPost, "/platform/identity/scim/tokens", map[string]any{"name": "okta", "connectionId": id, "createdBy": "mallory@example.com"}), http.StatusCreated)
	if token.body["createdBy"] != "admin@example.com" || token.body["createdOnBehalfOf"] != "mallory@example.com" {
		t.Fatalf("token audit = %s", token.raw)
	}
}

func TestOIDCTrustEmailClaimRoundTrips(t *testing.T) {
	h := newHarness(t)
	body := oidcConnection("Okta", "example.com")
	created := h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections", body), http.StatusCreated)
	if created.body["oidc"].(map[string]any)["trustEmailClaim"] != false {
		t.Fatalf("trustEmailClaim default = %s", created.raw)
	}
	body["oidc"].(map[string]any)["trustEmailClaim"] = true
	updated := h.expect(h.do(http.MethodPut, "/platform/identity/sso/connections/"+created.body["id"].(string), body), http.StatusOK)
	if updated.body["oidc"].(map[string]any)["trustEmailClaim"] != true {
		t.Fatalf("trustEmailClaim not stored: %s", updated.raw)
	}
}
