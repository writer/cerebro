package identitysso

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

var testNow = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

func testCertificateDER(t *testing.T) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp.example.com"},
		NotBefore:    testNow.Add(-time.Hour),
		NotAfter:     testNow.Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func oidcInput() ConnectionInput {
	return ConnectionInput{
		Name:     "Okta",
		Protocol: "oidc",
		Domains:  []string{"Example.COM", "example.com."},
		OIDC: &OIDCInput{ //nolint:gosec // Secret reference fixture; no credential value is embedded.
			Issuer:          "https://example.okta.com/",
			ClientID:        "client-123",
			ClientSecretRef: "env:OKTA_CLIENT_SECRET",
		},
		RoleMappings: []ports.SSORoleMapping{{Group: "sec-admins", Roles: []string{"cerebro.admin"}}},
		DefaultRoles: []string{"cerebro.viewer"},
	}
}

func TestValidateSecretRef(t *testing.T) {
	valid := []string{
		"env:OKTA_SECRET",
		"env:_x1",
		"aws-sm:us-east-1/cerebro/okta",
		"aws-sm:eu-west-2/prod/sso#client_secret",
		"aws-sm:us-west-2:cerebro/okta",
		"aws-sm:arn:aws:secretsmanager:us-east-1:123456789012:secret:cerebro/okta-AbCdEf",
		"aws-sm:arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:okta#client_secret",
	}
	for _, ref := range valid {
		if err := ValidateSecretRef(ref); err != nil {
			t.Errorf("ValidateSecretRef(%q) = %v, want nil", ref, err)
		}
	}
	invalidRefs := []string{
		"",
		"plain-secret-value",
		"env:",
		"env:1BAD",
		"env:HAS SPACE",
		"aws-sm:us-east-1",
		"aws-sm:notaregion/secret",
		"aws-sm:us-east-1/",
		"aws-sm:us-east-1/secret#bad field",
		"aws-sm:us-east-1/secret#",
		"vault:secret/path",
		"aws-sm:us-east-1:",
		"aws-sm:arn:aws:secretsmanager:us-east-1:123:secret:x",
		"aws-sm:arn:aws:s3:::bucket",
		"env:" + strings.Repeat("A", MaxSecretRefLength),
	}
	for _, ref := range invalidRefs {
		if err := ValidateSecretRef(ref); !errors.Is(err, ErrInvalid) {
			t.Errorf("ValidateSecretRef(%q) = %v, want ErrInvalid", ref, err)
		}
	}
}

func TestNormalizeDomains(t *testing.T) {
	got, err := NormalizeDomains([]string{" Example.COM ", "example.com.", "sub.example.org"})
	if err != nil {
		t.Fatalf("NormalizeDomains: %v", err)
	}
	if strings.Join(got, ",") != "example.com,sub.example.org" {
		t.Fatalf("NormalizeDomains = %v", got)
	}
	for _, bad := range []string{"localhost", "exa mple.com", "-bad.com", "10.0.0.1", "a..com", "@example.com"} {
		if _, err := NormalizeDomain(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizeDomain(%q) = %v, want ErrInvalid", bad, err)
		}
	}
	tooMany := make([]string, MaxDomainsPerConn+1)
	for i := range tooMany {
		tooMany[i] = "d" + strings.Repeat("x", i%5) + ".example.com"
	}
	if _, err := NormalizeDomains(tooMany); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NormalizeDomains over limit = %v, want ErrInvalid", err)
	}
}

func TestValidateIdPURL(t *testing.T) {
	for _, ok := range []string{"https://idp.example.com/sso", "http://localhost:8080/sso", "http://127.0.0.1/sso"} {
		if _, err := ValidateIdPURL("u", ok); err != nil {
			t.Errorf("ValidateIdPURL(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "http://idp.example.com", "ftp://idp.example.com", "https://user:pw@idp.example.com", "https://idp.example.com/#frag", "/relative", "javascript:alert(1)"} {
		if _, err := ValidateIdPURL("u", bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("ValidateIdPURL(%q) = %v, want ErrInvalid", bad, err)
		}
	}
}

func TestNormalizeCertificate(t *testing.T) {
	der := testCertificateDER(t)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	fromPEM, err := NormalizeCertificate(pemText)
	if err != nil {
		t.Fatalf("NormalizeCertificate(PEM): %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(der)
	wrapped := b64[:40] + "\n  " + b64[40:]
	fromBase64, err := NormalizeCertificate(wrapped)
	if err != nil {
		t.Fatalf("NormalizeCertificate(base64): %v", err)
	}
	if fromPEM != fromBase64 {
		t.Fatalf("PEM and base64 forms should normalize identically")
	}
	// Assembled at runtime so the source never carries a literal private-key PEM header.
	keyLabel := "PRIVATE" + " KEY"
	wrongBlock := "-----BEGIN " + keyLabel + "-----\nAAAA\n-----END " + keyLabel + "-----"
	for _, bad := range []string{"", "not-base64!!", base64.StdEncoding.EncodeToString([]byte("garbage")), wrongBlock} {
		if _, err := NormalizeCertificate(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizeCertificate(%q) = %v, want ErrInvalid", bad, err)
		}
	}
}

func TestNormalizeConnectionInputOIDCDefaults(t *testing.T) {
	conn, err := NormalizeConnectionInput(oidcInput())
	if err != nil {
		t.Fatalf("NormalizeConnectionInput: %v", err)
	}
	if conn.Status != StatusDraft {
		t.Errorf("status = %q, want draft", conn.Status)
	}
	if strings.Join(conn.Domains, ",") != "example.com" {
		t.Errorf("domains = %v", conn.Domains)
	}
	if conn.OIDC.Issuer != "https://example.okta.com" {
		t.Errorf("issuer = %q, want trailing slash trimmed", conn.OIDC.Issuer)
	}
	if strings.Join(conn.OIDC.Scopes, " ") != "openid email profile groups" {
		t.Errorf("scopes = %v", conn.OIDC.Scopes)
	}
	if conn.OIDC.GroupsClaim != "groups" {
		t.Errorf("groupsClaim = %q", conn.OIDC.GroupsClaim)
	}
}

func TestNormalizeConnectionInputRejects(t *testing.T) {
	cases := map[string]func(*ConnectionInput){
		"missing name":       func(in *ConnectionInput) { in.Name = "" },
		"bad protocol":       func(in *ConnectionInput) { in.Protocol = "ldap" },
		"missing oidc":       func(in *ConnectionInput) { in.OIDC = nil },
		"both protocols":     func(in *ConnectionInput) { in.SAML = &SAMLInput{} },
		"bad status":         func(in *ConnectionInput) { in.Status = "enabled" },
		"secret value":       func(in *ConnectionInput) { in.OIDC.ClientSecretRef = "s3cr3t" },
		"no openid scope":    func(in *ConnectionInput) { in.OIDC.Scopes = []string{"email"} },
		"unknown role":       func(in *ConnectionInput) { in.DefaultRoles = []string{"root"} },
		"mapping without":    func(in *ConnectionInput) { in.RoleMappings = []ports.SSORoleMapping{{Group: "g"}} },
		"http issuer":        func(in *ConnectionInput) { in.OIDC.Issuer = "http://idp.example.com" },
		"client id spaces":   func(in *ConnectionInput) { in.OIDC.ClientID = "a b" },
		"control characters": func(in *ConnectionInput) { in.Name = "bad\x00name" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := oidcInput()
			oidc := *in.OIDC
			in.OIDC = &oidc
			mutate(&in)
			if _, err := NormalizeConnectionInput(in); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NormalizeConnectionInput = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestNormalizeConnectionInputSAML(t *testing.T) {
	der := testCertificateDER(t)
	in := ConnectionInput{
		Name:     "Entra",
		Protocol: "SAML",
		SAML: &SAMLInput{
			IDPEntityID:     "https://sts.windows.net/tenant/",
			IDPSSOURL:       "https://login.microsoftonline.com/tenant/saml2",
			IDPCertificates: []string{base64.StdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(der)},
		},
	}
	conn, err := NormalizeConnectionInput(in)
	if err != nil {
		t.Fatalf("NormalizeConnectionInput: %v", err)
	}
	if conn.Protocol != ProtocolSAML || conn.SAML == nil {
		t.Fatalf("protocol = %q saml = %v", conn.Protocol, conn.SAML)
	}
	if len(conn.SAML.IDPCertificates) != 1 {
		t.Errorf("duplicate certificates should collapse, got %d", len(conn.SAML.IDPCertificates))
	}
	if !conn.SAML.WantAssertionsSigned {
		t.Errorf("wantAssertionsSigned should default to true")
	}
	if conn.SAML.EmailAttribute != "email" || conn.SAML.NameIDFormat != defaultNameIDFormat {
		t.Errorf("unexpected defaults: %+v", conn.SAML)
	}
	in.SAML.IDPCertificates = nil
	if _, err := NormalizeConnectionInput(in); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing certificates = %v, want ErrInvalid", err)
	}
	in.SAML.IDPCertificates = []string{base64.StdEncoding.EncodeToString(der)}
	in.SAML.NameIDFormat = "email"
	if _, err := NormalizeConnectionInput(in); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad nameIdFormat = %v, want ErrInvalid", err)
	}
}

func TestConnectionLifecycle(t *testing.T) {
	conn, err := NormalizeConnectionInput(oidcInput())
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	active := conn
	active.Status = StatusActive
	if _, err := PrepareCreate(active, "conn_1", testNow); !errors.Is(err, ErrConnectionNotTested) {
		t.Fatalf("create active = %v, want ErrConnectionNotTested", err)
	}
	created, err := PrepareCreate(conn, "conn_1", testNow)
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}

	activate := created
	activate.Status = StatusActive
	if _, err := PrepareUpdate(created, activate, testNow); !errors.Is(err, ErrConnectionNotTested) {
		t.Fatalf("activate untested = %v, want ErrConnectionNotTested", err)
	}

	failed, err := ApplyTestResult(created, TestResultInput{OK: false, Actor: "admin@example.com"}, "svc-web", testNow)
	if err != nil || failed.Status != StatusDraft || failed.LastTest == nil || failed.LastTest.OK {
		t.Fatalf("failed test: status=%q lastTest=%+v err=%v", failed.Status, failed.LastTest, err)
	}
	tested, err := ApplyTestResult(created, TestResultInput{OK: true, Actor: "admin@example.com", Detail: strings.Repeat("x", 3000)}, "svc-web", testNow)
	if err != nil || tested.Status != StatusTested {
		t.Fatalf("passing test: status=%q err=%v", tested.Status, err)
	}
	if len(tested.LastTest.Detail) != maxDetailLength {
		t.Errorf("detail should be truncated to %d, got %d", maxDetailLength, len(tested.LastTest.Detail))
	}
	if tested.UpdatedBy != "svc-web" || tested.UpdatedOnBehalfOf != "admin@example.com" {
		t.Errorf("updatedBy = %q onBehalfOf = %q", tested.UpdatedBy, tested.UpdatedOnBehalfOf)
	}
	if tested.LastTest.Actor != "svc-web" || tested.LastTest.OnBehalfOf != "admin@example.com" {
		t.Errorf("lastTest actor = %q onBehalfOf = %q", tested.LastTest.Actor, tested.LastTest.OnBehalfOf)
	}
	demoted, _ := ApplyTestResult(tested, TestResultInput{OK: false}, "svc-web", testNow)
	if demoted.Status != StatusDraft {
		t.Errorf("failing test on tested connection: status=%q, want draft", demoted.Status)
	}

	activate = tested
	activate.Status = StatusActive
	activated, err := PrepareUpdate(tested, activate, testNow.Add(time.Minute))
	if err != nil || activated.Status != StatusActive || activated.CreatedAt != testNow {
		t.Fatalf("activate tested: %+v err=%v", activated, err)
	}
	stillActive, _ := ApplyTestResult(activated, TestResultInput{OK: false}, "svc-web", testNow)
	if stillActive.Status != StatusActive {
		t.Errorf("a failing test must not change an active connection, got %q", stillActive.Status)
	}

	changed := activated
	oidc := *activated.OIDC
	oidc.ClientID = "rotated-client"
	changed.OIDC = &oidc
	reset, err := PrepareUpdate(activated, changed, testNow)
	if err != nil {
		t.Fatalf("protocol change: %v", err)
	}
	if reset.Status != StatusDraft || reset.LastTest != nil {
		t.Errorf("protocol change: status=%q lastTest=%v, want draft and nil", reset.Status, reset.LastTest)
	}

	disabled := changed
	disabled.Status = StatusDisabled
	kept, err := PrepareUpdate(activated, disabled, testNow)
	if err != nil || kept.Status != StatusDisabled {
		t.Errorf("disabling with protocol change: status=%q err=%v", kept.Status, err)
	}

	renamed := activated
	renamed.Name = "Okta Prod"
	same, err := PrepareUpdate(activated, renamed, testNow)
	if err != nil || same.Status != StatusActive || same.LastTest == nil {
		t.Errorf("rename keeps status and test: status=%q err=%v", same.Status, err)
	}
}

func TestLeavesNoActiveConnection(t *testing.T) {
	conns := []ports.SSOConnection{{ID: "a", Status: StatusActive}, {ID: "b", Status: StatusDraft}}
	if !LeavesNoActiveConnection(conns, "a", nil) {
		t.Error("deleting the only active connection should leave none")
	}
	if !LeavesNoActiveConnection(conns, "a", &ports.SSOConnection{ID: "a", Status: StatusDisabled}) {
		t.Error("disabling the only active connection should leave none")
	}
	if LeavesNoActiveConnection(conns, "a", &ports.SSOConnection{ID: "a", Status: StatusActive}) {
		t.Error("keeping the connection active leaves one")
	}
	conns = append(conns, ports.SSOConnection{ID: "c", Status: StatusActive})
	if LeavesNoActiveConnection(conns, "a", nil) {
		t.Error("another active connection remains")
	}
}

func TestNormalizePolicy(t *testing.T) {
	policy, err := NormalizePolicy(ports.SSOPolicy{})
	if err != nil || policy.SessionMaxLifetimeMinutes != 720 || policy.SessionIdleTimeoutMinutes != 60 {
		t.Fatalf("defaults: %+v err=%v", policy, err)
	}
	for _, bad := range []ports.SSOPolicy{
		{SessionMaxLifetimeMinutes: 10, SessionIdleTimeoutMinutes: 5},
		{SessionMaxLifetimeMinutes: 43201, SessionIdleTimeoutMinutes: 60},
		{SessionMaxLifetimeMinutes: 60, SessionIdleTimeoutMinutes: 4},
		{SessionMaxLifetimeMinutes: 60, SessionIdleTimeoutMinutes: 120},
	} {
		if _, err := NormalizePolicy(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizePolicy(%+v) = %v, want ErrInvalid", bad, err)
		}
	}
}

func validSessionInput() SessionInput {
	return SessionInput{
		TokenHash:          HashToken("cookie-token"),
		ConnectionID:       "conn_abc",
		Subject:            "00u123",
		Email:              "Alice@Example.com",
		Groups:             []string{"eng", "eng", " "},
		Roles:              []string{"Cerebro.Viewer"},
		ExpiresAt:          testNow.Add(12 * time.Hour),
		IdleTimeoutMinutes: 60,
		UserAgent:          "Mozilla/5.0",
	}
}

func TestNormalizeSessionInput(t *testing.T) {
	session, err := NormalizeSessionInput(validSessionInput(), testNow)
	if err != nil {
		t.Fatalf("NormalizeSessionInput: %v", err)
	}
	if strings.Join(session.Groups, ",") != "eng" || strings.Join(session.Roles, ",") != "cerebro.viewer" {
		t.Errorf("groups=%v roles=%v", session.Groups, session.Roles)
	}
	if !session.LastSeenAt.Equal(testNow) {
		t.Errorf("lastSeenAt = %v", session.LastSeenAt)
	}
	cases := map[string]func(*SessionInput){
		"raw token":        func(in *SessionInput) { in.TokenHash = "cookie-token" },
		"uppercase hash":   func(in *SessionInput) { in.TokenHash = strings.ToUpper(in.TokenHash) },
		"bad connection":   func(in *SessionInput) { in.ConnectionID = "../x" },
		"missing subject":  func(in *SessionInput) { in.Subject = "" },
		"unknown role":     func(in *SessionInput) { in.Roles = []string{"superuser"} },
		"expired":          func(in *SessionInput) { in.ExpiresAt = testNow.Add(-time.Second) },
		"beyond lifetime":  func(in *SessionInput) { in.ExpiresAt = testNow.Add(31 * 24 * time.Hour) },
		"idle too small":   func(in *SessionInput) { in.IdleTimeoutMinutes = 1 },
		"ip hash spaces":   func(in *SessionInput) { in.IPHash = "a b" },
		"too many roles":   func(in *SessionInput) { in.Roles = make([]string, maxSessionRoles+1) },
		"control in email": func(in *SessionInput) { in.Email = "a\n@b.com" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := validSessionInput()
			mutate(&in)
			if _, err := NormalizeSessionInput(in, testNow); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NormalizeSessionInput = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestSessionActive(t *testing.T) {
	session := ports.SSOSession{LastSeenAt: testNow, ExpiresAt: testNow.Add(time.Hour), IdleTimeoutMinutes: 10}
	if !SessionActive(session, testNow.Add(5*time.Minute)) {
		t.Error("session within idle window should be active")
	}
	if SessionActive(session, testNow.Add(11*time.Minute)) {
		t.Error("idle session should be inactive")
	}
	if SessionActive(session, testNow.Add(time.Hour)) {
		t.Error("expired session should be inactive")
	}
	revoked := testNow
	session.RevokedAt = &revoked
	if SessionActive(session, testNow) {
		t.Error("revoked session should be inactive")
	}
	if SessionNeedsTouch(session, testNow.Add(30*time.Second)) || !SessionNeedsTouch(session, testNow.Add(time.Minute)) {
		t.Error("touch should be throttled to once per minute")
	}
}

func TestSessionSummaryOmitsHash(t *testing.T) {
	session := ports.SSOSession{TokenHash: HashToken("x"), Subject: "s"}
	summary := NewSessionSummary(session)
	if summary.TokenHashPrefix != session.TokenHash[:8] {
		t.Errorf("prefix = %q", summary.TokenHashPrefix)
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), session.TokenHash) {
		t.Errorf("summary leaks the full token hash: %s", encoded)
	}
	if strings.Contains(string(encoded), "null") {
		t.Errorf("summary should render empty arrays, got %s", encoded)
	}
}

func TestNewSCIMToken(t *testing.T) {
	raw, hash, prefix, err := NewSCIMToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, SCIMTokenPrefix) || !strings.HasPrefix(raw, prefix) || len(prefix) != len(SCIMTokenPrefix)+6 {
		t.Errorf("raw=%q prefix=%q", raw, prefix)
	}
	if hash != HashToken(raw) || !ValidTokenHash(hash) {
		t.Errorf("hash mismatch")
	}
	other, _, _, _ := NewSCIMToken()
	if other == raw {
		t.Error("tokens must be random")
	}
}

func TestParseSCIMFilter(t *testing.T) {
	filter, err := ParseSCIMFilter(`userName eq "alice@example.com"`, SCIMFilterAttrUserName)
	if err != nil || filter.Value != "alice@example.com" {
		t.Fatalf("filter=%+v err=%v", filter, err)
	}
	filter, err = ParseSCIMFilter(`USERNAME EQ "a\"b"`, SCIMFilterAttrUserName)
	if err != nil || filter.Value != `a"b` {
		t.Fatalf("escaped filter=%+v err=%v", filter, err)
	}
	if filter, err := ParseSCIMFilter("  ", SCIMFilterAttrUserName); filter != nil || err != nil {
		t.Fatalf("empty filter = %+v %v", filter, err)
	}
	for _, bad := range []string{`userName co "a"`, `emails eq "a"`, `userName eq "a" and active eq true`, `userName eq a`, `userName pr`} {
		_, err := ParseSCIMFilter(bad, SCIMFilterAttrUserName)
		scimErr, ok := AsSCIMError(err)
		if !ok || scimErr.Status != 400 || scimErr.SCIMType != SCIMTypeInvalidFilter {
			t.Errorf("ParseSCIMFilter(%q) = %v, want invalidFilter", bad, err)
		}
	}
}

func TestParseSCIMPage(t *testing.T) {
	page, err := ParseSCIMPage("", "")
	if err != nil || page.StartIndex != 1 || page.Count != SCIMDefaultCount {
		t.Fatalf("defaults: %+v %v", page, err)
	}
	page, _ = ParseSCIMPage("0", "5000")
	if page.StartIndex != 1 || page.Count != SCIMMaxCount {
		t.Errorf("clamped: %+v", page)
	}
	page, _ = ParseSCIMPage("3", "-1")
	if page.StartIndex != 3 || page.Count != 0 {
		t.Errorf("negative count: %+v", page)
	}
	if _, err := ParseSCIMPage("x", ""); err == nil {
		t.Error("non-integer startIndex should fail")
	}
}

func patch(t *testing.T, body string) SCIMPatchRequest {
	t.Helper()
	var request SCIMPatchRequest
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	return request
}

func TestApplySCIMUserAndPatch(t *testing.T) {
	active := true
	user, err := ApplySCIMUser(ports.DirectoryUser{}, SCIMUser{
		UserName: " alice@example.com ",
		Name:     &SCIMName{GivenName: "Alice", FamilyName: "Smith", Formatted: "Alice Smith"},
		Emails:   []SCIMEmail{{Value: "alt@example.com"}, {Value: "alice@example.com", Primary: true}},
		Active:   &active,
	})
	if err != nil {
		t.Fatalf("ApplySCIMUser: %v", err)
	}
	if user.UserName != "alice@example.com" || user.Email != "alice@example.com" || user.DisplayName != "Alice Smith" || !user.Active {
		t.Fatalf("user = %+v", user)
	}
	if _, err := ApplySCIMUser(ports.DirectoryUser{}, SCIMUser{}); err == nil {
		t.Fatal("missing userName should fail")
	}

	okta := patch(t, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`)
	deactivated, err := ApplySCIMUserPatch(user, okta)
	if err != nil || deactivated.Active {
		t.Fatalf("Okta value-object deactivate: active=%v err=%v", deactivated.Active, err)
	}
	entra := patch(t, `{"Operations":[{"op":"Replace","path":"active","value":"False"},{"op":"replace","path":"emails[type eq \"work\"].value","value":"new@example.com"},{"op":"add","path":"urn:ietf:params:scim:schemas:core:2.0:User:name.givenName","value":"Al"},{"op":"add","path":"title","value":"ignored"}]}`)
	patched, err := ApplySCIMUserPatch(user, entra)
	if err != nil {
		t.Fatalf("Entra patch: %v", err)
	}
	if patched.Active || patched.Email != "new@example.com" || patched.GivenName != "Al" {
		t.Fatalf("patched = %+v", patched)
	}
	for _, bad := range []string{
		`{"Operations":[]}`,
		`{"Operations":[{"op":"move","path":"active","value":true}]}`,
		`{"Operations":[{"op":"remove"}]}`,
		`{"Operations":[{"op":"remove","path":"userName"}]}`,
		`{"Operations":[{"op":"replace","path":"active","value":"maybe"}]}`,
		`{"Operations":[{"op":"replace","value":"not-an-object"}]}`,
		`{"Operations":[{"op":"replace","path":"userName","value":""}]}`,
	} {
		if _, err := ApplySCIMUserPatch(user, patch(t, bad)); err == nil {
			t.Errorf("patch %s should fail", bad)
		} else if scimErr, ok := AsSCIMError(err); !ok || scimErr.Status != 400 {
			t.Errorf("patch %s error = %v, want SCIM 400", bad, err)
		}
	}
}

func TestApplySCIMGroupPatch(t *testing.T) {
	group, err := ApplySCIMGroup(ports.DirectoryGroup{}, SCIMGroup{DisplayName: "Engineering", Members: []SCIMRef{{Value: "u1"}, {Value: "u1"}, {Value: "u2"}}})
	if err != nil || strings.Join(group.MemberIDs, ",") != "u1,u2" {
		t.Fatalf("group=%+v err=%v", group, err)
	}
	steps := []struct {
		body    string
		members string
		name    string
	}{
		{`{"Operations":[{"op":"add","path":"members","value":[{"value":"u3"},{"value":"u1"}]}]}`, "u1,u2,u3", "Engineering"},
		{`{"Operations":[{"op":"remove","path":"members[value eq \"u2\"]"}]}`, "u1,u3", "Engineering"},
		{`{"Operations":[{"op":"remove","path":"members","value":[{"value":"u1"}]}]}`, "u3", "Engineering"},
		{`{"Operations":[{"op":"replace","path":"members","value":[{"value":"u9"}]}]}`, "u9", "Engineering"},
		{`{"Operations":[{"op":"replace","value":{"id":"g1","displayName":"Eng"}}]}`, "u9", "Eng"},
		{`{"Operations":[{"op":"add","path":"members","value":{"value":"u8"}}]}`, "u9,u8", "Eng"},
		{`{"Operations":[{"op":"remove","path":"members"}]}`, "", "Eng"},
	}
	for _, step := range steps {
		group, err = ApplySCIMGroupPatch(group, patch(t, step.body))
		if err != nil {
			t.Fatalf("patch %s: %v", step.body, err)
		}
		if strings.Join(group.MemberIDs, ",") != step.members || group.DisplayName != step.name {
			t.Fatalf("after %s: members=%v name=%q", step.body, group.MemberIDs, group.DisplayName)
		}
	}
	for _, bad := range []string{
		`{"Operations":[{"op":"remove","path":"displayName"}]}`,
		`{"Operations":[{"op":"add","path":"owners","value":"x"}]}`,
		`{"Operations":[{"op":"add","path":"members","value":[{"value":""}]}]}`,
		`{"Operations":[{"op":"replace","path":"displayName","value":""}]}`,
		`{"Operations":[{"op":"remove"}]}`,
	} {
		if _, err := ApplySCIMGroupPatch(group, patch(t, bad)); err == nil {
			t.Errorf("patch %s should fail", bad)
		}
	}
}

func TestSCIMRenderingAndErrors(t *testing.T) {
	user := ports.DirectoryUser{ID: "u1", UserName: "a@example.com", Email: "a@example.com", Active: false, Groups: []ports.DirectoryGroupRef{{ID: "g1", DisplayName: "Eng"}}}
	rendered := NewSCIMUser(user)
	if rendered.Active == nil || *rendered.Active || rendered.Meta.Location != "/scim/v2/Users/u1" || rendered.Groups[0].Value != "g1" {
		t.Fatalf("rendered = %+v", rendered)
	}
	group := NewSCIMGroup(ports.DirectoryGroup{ID: "g1", DisplayName: "Eng", MemberIDs: []string{"u1"}}, false)
	if len(group.Members) != 0 {
		t.Error("members should be excluded when requested")
	}
	list := NewSCIMListResponse[SCIMUser](nil, 0, SCIMPage{StartIndex: 1, Count: 10})
	encoded, _ := json.Marshal(list)
	if !strings.Contains(string(encoded), `"Resources":[]`) {
		t.Errorf("list should render empty Resources array: %s", encoded)
	}
	body := NewSCIMErrorBody(NewSCIMBadRequest(SCIMTypeInvalidValue, "bad %s", "thing"))
	if body.Status != "400" || body.Schemas[0] != SCIMSchemaError || body.Detail != "bad thing" {
		t.Errorf("error body = %+v", body)
	}
	if scimErr, ok := AsSCIMError(Invalid("x")); !ok || scimErr.SCIMType != SCIMTypeInvalidValue {
		t.Errorf("validation errors should map to invalidValue")
	}
	if _, ok := AsSCIMError(errors.New("boom")); ok {
		t.Error("unrelated errors must not map to SCIM 400")
	}
	if ServiceProviderConfig().Patch.Supported != true || len(ResourceTypes()) != 2 || len(Schemas()) != 2 {
		t.Error("static discovery documents changed unexpectedly")
	}
}

func TestDirectoryHelpers(t *testing.T) {
	in, err := NormalizeJITInput(JITUserInput{ConnectionID: "conn_1", Subject: "sub", Email: "bob@example.com", Groups: []string{"a", "a"}})
	if err != nil || strings.Join(in.Groups, ",") != "a" {
		t.Fatalf("NormalizeJITInput: %+v %v", in, err)
	}
	if _, err := NormalizeJITInput(JITUserInput{ConnectionID: "conn_1", Subject: "sub", Email: "bob"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("email without @ should fail: %v", err)
	}
	user := NewJITUser("t1", "usr_1", in, testNow)
	if user.Source != DirectorySourceJIT || !user.Active || user.UserName != "bob@example.com" || user.LastLoginAt == nil {
		t.Fatalf("jit user = %+v", user)
	}
	later := testNow.Add(time.Hour)
	updated := user
	if err := ApplyJITLogin(&updated, JITUserInput{Subject: "sub", Email: "bob2@example.com", Name: "Bob", Groups: []string{"b"}}, later); err != nil {
		t.Fatalf("ApplyJITLogin: %v", err)
	}
	if updated.Email != "bob@example.com" || updated.DisplayName != "" || !updated.LastLoginAt.Equal(later) || strings.Join(updated.JITGroups, ",") != "b" {
		t.Errorf("jit login must write only last-login, subject, and replaced jitGroups: %+v", updated)
	}
	scimUser := ports.DirectoryUser{Source: DirectorySourceSCIM, Active: true, Email: "carol@example.com", UserName: "carol@example.com", ExternalID: "ext-1"}
	scimUpdated := scimUser
	if err := ApplyJITLogin(&scimUpdated, JITUserInput{Subject: "sub-c", Email: "other@example.com", Name: "X", Groups: []string{"g"}}, later); err != nil {
		t.Fatalf("ApplyJITLogin scim: %v", err)
	}
	if scimUpdated.Email != "carol@example.com" || scimUpdated.Subject != "sub-c" || len(scimUpdated.JITGroups) != 0 {
		t.Errorf("SCIM-managed attributes must not change at login: %+v", scimUpdated)
	}
	match := SessionMatchForUser(scimUpdated)
	if strings.Join(match.Subjects, ",") != "sub-c,ext-1" || strings.Join(match.Emails, ",") != "carol@example.com" {
		t.Errorf("match = %+v", match)
	}
	view := NewDirectoryUserView(ports.DirectoryUser{UserName: "dave@example.com", GivenName: "Dave", Groups: []ports.DirectoryGroupRef{{DisplayName: "Eng"}}, JITGroups: []string{"Eng", "Ops"}})
	if view.Email != "dave@example.com" || view.Name != "Dave" || strings.Join(view.Groups, ",") != "Eng,Ops" {
		t.Errorf("view = %+v", view)
	}
}
