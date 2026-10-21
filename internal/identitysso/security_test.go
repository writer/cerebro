package identitysso

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestOIDCTrustEmailClaimDefaultsOffAndRoundTrips(t *testing.T) {
	conn, err := NormalizeConnectionInput(oidcInput())
	if err != nil {
		t.Fatalf("NormalizeConnectionInput: %v", err)
	}
	if conn.OIDC.TrustEmailClaim {
		t.Fatal("trustEmailClaim must default to false")
	}
	input := oidcInput()
	input.OIDC.TrustEmailClaim = true
	conn, err = NormalizeConnectionInput(input)
	if err != nil || !conn.OIDC.TrustEmailClaim {
		t.Fatalf("trustEmailClaim not kept: %+v %v", conn.OIDC, err)
	}
}

func TestConnectionUpdateKeepsPrincipalAndOnBehalfOfApart(t *testing.T) {
	input := oidcInput()
	input.UpdatedBy = "alice@example.com"
	conn, err := NormalizeConnectionInput(input)
	if err != nil {
		t.Fatalf("NormalizeConnectionInput: %v", err)
	}
	if conn.UpdatedBy != "" || conn.UpdatedOnBehalfOf != "alice@example.com" {
		t.Fatalf("body actor must be recorded as on-behalf-of only: updatedBy=%q onBehalfOf=%q", conn.UpdatedBy, conn.UpdatedOnBehalfOf)
	}
	if _, err := NormalizePolicy(ports.SSOPolicy{SessionMaxLifetimeMinutes: 60, SessionIdleTimeoutMinutes: 30, UpdatedOnBehalfOf: string(make([]byte, 5000))}); err == nil {
		t.Fatal("oversized updatedOnBehalfOf accepted")
	}
}

func TestConnectionChangeRevokesSessions(t *testing.T) {
	base := ports.SSOConnection{
		Status:       StatusActive,
		Domains:      []string{"example.com"},
		RoleMappings: []ports.SSORoleMapping{{Group: "admins", Roles: []string{"cerebro.admin"}}},
		DefaultRoles: []string{"cerebro.viewer"},
	}
	change := func(edit func(*ports.SSOConnection)) ports.SSOConnection {
		next := base
		next.Domains = slices.Clone(base.Domains)
		next.RoleMappings = slices.Clone(base.RoleMappings)
		next.DefaultRoles = slices.Clone(base.DefaultRoles)
		edit(&next)
		return next
	}
	revoking := map[string]ports.SSOConnection{
		"disabled":      change(func(c *ports.SSOConnection) { c.Status = StatusDisabled }),
		"role mappings": change(func(c *ports.SSOConnection) { c.RoleMappings[0].Group = "everyone" }),
		"default roles": change(func(c *ports.SSOConnection) { c.DefaultRoles = []string{"cerebro.admin"} }),
		"domains":       change(func(c *ports.SSOConnection) { c.Domains = append(c.Domains, "other.com") }),
	}
	for name, next := range revoking {
		if !ConnectionChangeRevokesSessions(base, next) {
			t.Errorf("%s change must revoke sessions", name)
		}
	}
	if ConnectionChangeRevokesSessions(base, change(func(c *ports.SSOConnection) { c.Name = "Renamed" })) {
		t.Error("a rename must not revoke sessions")
	}
}

func TestCheckLoginUser(t *testing.T) {
	deleted := testNow
	cases := []struct {
		name string
		user ports.DirectoryUser
		want error
	}{
		{"active unbound", ports.DirectoryUser{Active: true}, nil},
		{"active bound", ports.DirectoryUser{Active: true, Subject: "sub-1"}, nil},
		{"tombstone", ports.DirectoryUser{Active: true, DeletedAt: &deleted}, ErrUserDeprovisioned},
		{"inactive", ports.DirectoryUser{Subject: "sub-1"}, ErrUserInactive},
		{"other subject", ports.DirectoryUser{Active: true, Subject: "sub-2"}, ErrSubjectMismatch},
	}
	for _, tc := range cases {
		if err := CheckLoginUser(tc.user, "sub-1"); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestApplyJITLoginRefusesAndReplacesGroups(t *testing.T) {
	user := ports.DirectoryUser{Source: DirectorySourceJIT, Active: true, Subject: "sub-1", JITGroups: []string{"admins", "eng"}}
	if err := ApplyJITLogin(&user, JITUserInput{Subject: "sub-1", Groups: []string{"eng"}}, testNow); err != nil {
		t.Fatalf("ApplyJITLogin: %v", err)
	}
	if !slices.Equal(user.JITGroups, []string{"eng"}) {
		t.Fatalf("jitGroups = %v, want fresh groups only", user.JITGroups)
	}
	inactive := ports.DirectoryUser{Source: DirectorySourceJIT, Subject: "sub-1"}
	if err := ApplyJITLogin(&inactive, JITUserInput{Subject: "sub-1"}, testNow); !errors.Is(err, ErrUserInactive) || inactive.Active || inactive.LastLoginAt != nil {
		t.Fatalf("inactive login = %v, user = %+v", err, inactive)
	}
	other := ports.DirectoryUser{Source: DirectorySourceJIT, Active: true, Subject: "sub-1"}
	if err := ApplyJITLogin(&other, JITUserInput{Subject: "sub-2"}, testNow); !errors.Is(err, ErrSubjectMismatch) || other.Subject != "sub-1" {
		t.Fatalf("subject mismatch login = %v, user = %+v", err, other)
	}
}

func TestMatchDirectoryUserRanking(t *testing.T) {
	deleted := testNow
	candidates := []ports.DirectoryUser{
		{ID: "a", Source: DirectorySourceSCIM, Email: "bob@example.com", Active: true},
		{ID: "b", Source: DirectorySourceJIT, Subject: "sub-1", Email: "bob@example.com", Active: true},
		{ID: "c", Source: DirectorySourceSCIM, Subject: "sub-1", Email: "bob@example.com", DeletedAt: &deleted},
		{ID: "d", Source: DirectorySourceSCIM, Email: "carol@example.com", Active: true},
	}
	if got := MatchDirectoryUser(candidates, "sub-1", "bob@example.com"); got == nil || got.ID != "b" {
		t.Fatalf("match = %+v, want live subject-bound user b", got)
	}
	if got := MatchDirectoryUser(candidates, "", "BOB@example.com"); got == nil || got.ID != "a" {
		t.Fatalf("email match = %+v, want SCIM user a", got)
	}
	if got := MatchDirectoryUser(candidates[2:3], "sub-1", ""); got == nil || got.ID != "c" {
		t.Fatalf("tombstone match = %+v, want c", got)
	}
	if got := MatchDirectoryUser(candidates, "sub-9", "nobody@example.com"); got != nil {
		t.Fatalf("unexpected match %+v", got)
	}
}

func TestSessionMatchForUserIsConnectionScoped(t *testing.T) {
	match := SessionMatchForUser(ports.DirectoryUser{ConnectionID: "okta", Subject: "sub-1", Email: "Bob@Example.com"})
	if match.ConnectionID != "okta" || !slices.Equal(match.Subjects, []string{"sub-1"}) || !slices.Equal(match.Emails, []string{"bob@example.com"}) {
		t.Fatalf("match = %+v", match)
	}
}

func TestAffectedGroupMembers(t *testing.T) {
	before := ports.DirectoryGroup{DisplayName: "admins", MemberIDs: []string{"u1", "u2"}}
	after := ports.DirectoryGroup{DisplayName: "admins", MemberIDs: []string{"u2", "u3"}}
	if got := AffectedGroupMembers(before, after); !slices.Equal(got, []string{"u1", "u3"}) {
		t.Fatalf("affected = %v, want added and removed members", got)
	}
	renamed := after
	renamed.DisplayName = "everyone"
	if got := AffectedGroupMembers(before, renamed); !slices.Equal(got, []string{"u1", "u2", "u3"}) {
		t.Fatalf("rename affected = %v, want every member", got)
	}
	if got := AffectedGroupMembers(before, before); len(got) != 0 {
		t.Fatalf("no-op affected = %v", got)
	}
}

func TestAdoptSCIMUserClearsJITGroupsAndTombstone(t *testing.T) {
	deleted := testNow
	user := ports.DirectoryUser{Source: DirectorySourceJIT, JITGroups: []string{"admins"}, DeletedAt: &deleted}
	AdoptSCIMUser(&user, testNow.Add(time.Minute))
	if user.Source != DirectorySourceSCIM || user.JITGroups != nil || user.DeletedAt != nil || !user.UpdatedAt.Equal(testNow.Add(time.Minute)) {
		t.Fatalf("adopted user = %+v", user)
	}
}

func TestCapSessionLifetimeForAdmins(t *testing.T) {
	policy := ports.SSOPolicy{SessionMaxLifetimeMinutes: 24 * 60}
	admin := ports.SSOSession{Roles: []string{"cerebro.admin"}, CreatedAt: testNow, ExpiresAt: testNow.Add(24 * time.Hour)}
	CapSessionLifetime(&admin, policy)
	if !admin.ExpiresAt.Equal(testNow.Add(AdminSessionMaxLifetime)) {
		t.Fatalf("admin expiresAt = %s, want 12h cap", admin.ExpiresAt)
	}
	short := ports.SSOSession{Roles: []string{"cerebro.admin"}, CreatedAt: testNow, ExpiresAt: testNow.Add(24 * time.Hour)}
	CapSessionLifetime(&short, ports.SSOPolicy{SessionMaxLifetimeMinutes: 60})
	if !short.ExpiresAt.Equal(testNow.Add(time.Hour)) {
		t.Fatalf("admin expiresAt = %s, want policy limit", short.ExpiresAt)
	}
	viewer := ports.SSOSession{Roles: []string{"cerebro.viewer"}, CreatedAt: testNow, ExpiresAt: testNow.Add(24 * time.Hour)}
	CapSessionLifetime(&viewer, policy)
	if !viewer.ExpiresAt.Equal(testNow.Add(24 * time.Hour)) {
		t.Fatalf("viewer expiresAt = %s, want unchanged", viewer.ExpiresAt)
	}
}

func TestNormalizeSAMLAssertion(t *testing.T) {
	valid := SAMLAssertionInput{ConnectionID: "okta", AssertionID: "_abc", RequestID: "_req1", NotOnOrAfter: testNow.Add(5 * time.Minute)}
	use, err := NormalizeSAMLAssertion(valid, testNow)
	if err != nil || use.ConnectionID != "okta" || use.AssertionID != "_abc" || use.RequestID != "_req1" || !use.ExpiresAt.Equal(testNow.Add(5*time.Minute)) {
		t.Fatalf("use = %+v err = %v", use, err)
	}
	far := valid
	far.NotOnOrAfter = testNow.Add(30 * 24 * time.Hour)
	if use, err := NormalizeSAMLAssertion(far, testNow); err != nil || !use.ExpiresAt.Equal(testNow.Add(MaxSAMLReplayWindow)) {
		t.Fatalf("far expiry not clamped: %+v %v", use, err)
	}
	bad := map[string]SAMLAssertionInput{
		"missing connection": {AssertionID: "_a", RequestID: "_r", NotOnOrAfter: valid.NotOnOrAfter},
		"missing assertion":  {ConnectionID: "okta", RequestID: "_r", NotOnOrAfter: valid.NotOnOrAfter},
		"missing request":    {ConnectionID: "okta", AssertionID: "_a", NotOnOrAfter: valid.NotOnOrAfter},
		"missing expiry":     {ConnectionID: "okta", AssertionID: "_a", RequestID: "_r"},
		"expired":            {ConnectionID: "okta", AssertionID: "_a", RequestID: "_r", NotOnOrAfter: testNow},
	}
	for name, input := range bad {
		if _, err := NormalizeSAMLAssertion(input, testNow); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}
