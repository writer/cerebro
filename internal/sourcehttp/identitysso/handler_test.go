package identitysso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sso "github.com/writer/cerebro/internal/identitysso"
	"github.com/writer/cerebro/internal/ports"
)

type harness struct {
	t     *testing.T
	store *fakeStore
	mux   *http.ServeMux
	now   time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, store: newFakeStore(), now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	handler := Handler{
		store:   h.store,
		resolve: func(_ context.Context, requested string) (string, error) { return requested, nil },
		actor:   func(context.Context) string { return "admin@example.com" },
		now:     func() time.Time { return h.now },
	}
	h.mux = newTestMux(handler)
	return h
}

func newTestMux(handler Handler) *http.ServeMux {
	mux := http.NewServeMux()
	routes := map[string]http.HandlerFunc{
		"GET /platform/identity/sso/connections":                             handler.ListConnections,
		"POST /platform/identity/sso/connections":                            handler.CreateConnection,
		"GET /platform/identity/sso/connections/{connectionID}":              handler.GetConnection,
		"PUT /platform/identity/sso/connections/{connectionID}":              handler.UpdateConnection,
		"DELETE /platform/identity/sso/connections/{connectionID}":           handler.DeleteConnection,
		"POST /platform/identity/sso/connections/{connectionID}/test-result": handler.RecordTestResult,
		"GET /platform/identity/sso/policy":                                  handler.GetPolicy,
		"PUT /platform/identity/sso/policy":                                  handler.PutPolicy,
		"POST /platform/identity/sessions":                                   handler.CreateSession,
		"GET /platform/identity/sessions":                                    handler.ListSessions,
		"DELETE /platform/identity/sessions":                                 handler.RevokeSessions,
		"GET /platform/identity/sessions/{tokenHash}":                        handler.GetSession,
		"DELETE /platform/identity/sessions/{tokenHash}":                     handler.DeleteSession,
		"GET /platform/identity/scim/tokens":                                 handler.ListSCIMTokens,
		"POST /platform/identity/scim/tokens":                                handler.CreateSCIMToken,
		"DELETE /platform/identity/scim/tokens/{tokenID}":                    handler.DeleteSCIMToken,
		"GET /platform/identity/scim/v2/ServiceProviderConfig":               handler.SCIMServiceProviderConfig,
		"GET /platform/identity/scim/v2/ResourceTypes":                       handler.SCIMResourceTypes,
		"GET /platform/identity/scim/v2/Schemas":                             handler.SCIMSchemas,
		"GET /platform/identity/scim/v2/Users":                               handler.SCIMListUsers,
		"POST /platform/identity/scim/v2/Users":                              handler.SCIMCreateUser,
		"GET /platform/identity/scim/v2/Users/{userID}":                      handler.SCIMGetUser,
		"PUT /platform/identity/scim/v2/Users/{userID}":                      handler.SCIMReplaceUser,
		"PATCH /platform/identity/scim/v2/Users/{userID}":                    handler.SCIMPatchUser,
		"DELETE /platform/identity/scim/v2/Users/{userID}":                   handler.SCIMDeleteUser,
		"GET /platform/identity/scim/v2/Groups":                              handler.SCIMListGroups,
		"POST /platform/identity/scim/v2/Groups":                             handler.SCIMCreateGroup,
		"GET /platform/identity/scim/v2/Groups/{groupID}":                    handler.SCIMGetGroup,
		"PUT /platform/identity/scim/v2/Groups/{groupID}":                    handler.SCIMReplaceGroup,
		"PATCH /platform/identity/scim/v2/Groups/{groupID}":                  handler.SCIMPatchGroup,
		"DELETE /platform/identity/scim/v2/Groups/{groupID}":                 handler.SCIMDeleteGroup,
		"GET /platform/identity/directory/users":                             handler.ListDirectoryUsers,
		"GET /platform/identity/directory/users/lookup":                      handler.LookupDirectoryUser,
		"POST /platform/identity/directory/users/jit":                        handler.UpsertJITUser,
		"GET /platform/identity/directory/groups":                            handler.ListDirectoryGroups,
		"POST /platform/identity/saml/assertions":                            handler.ConsumeSAMLAssertion,
	}
	for pattern, fn := range routes {
		mux.HandleFunc(pattern, fn)
	}
	return mux
}

type response struct {
	status      int
	contentType string
	raw         string
	body        map[string]any
}

func (h *harness) do(method string, path string, body any, headers ...string) response {
	h.t.Helper()
	var reader *bytes.Reader
	switch value := body.(type) {
	case nil:
		reader = bytes.NewReader(nil)
	case string:
		reader = bytes.NewReader([]byte(value))
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			h.t.Fatalf("encode body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, path, reader)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	out := response{status: rec.Code, contentType: rec.Header().Get("Content-Type"), raw: rec.Body.String()}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	}
	return out
}

func (h *harness) expect(res response, status int) response {
	h.t.Helper()
	if res.status != status {
		h.t.Fatalf("status = %d, want %d; body = %s", res.status, status, res.raw)
	}
	return res
}

func (h *harness) expectError(res response, status int, code string) {
	h.t.Helper()
	h.expect(res, status)
	if got, _ := res.body["error"].(string); got != code {
		h.t.Fatalf("error = %q, want %q; body = %s", got, code, res.raw)
	}
	if got, _ := res.body["code"].(string); got != code {
		h.t.Fatalf("code = %q, want %q; body = %s", got, code, res.raw)
	}
}

func oidcConnection(name string, domains ...string) map[string]any {
	return map[string]any{
		"name":     name,
		"protocol": "oidc",
		"domains":  domains,
		"oidc": map[string]any{ //nolint:gosec // Secret reference fixture; no credential value is embedded.
			"issuer":          "https://example.okta.com",
			"clientId":        "client-" + strings.ToLower(name),
			"clientSecretRef": "env:OKTA_SECRET",
		},
		"defaultRoles":    []string{"cerebro.viewer"},
		"jitProvisioning": true,
	}
}

// activeConnection creates, tests, and activates a connection and returns its ID.
func (h *harness) activeConnection(name string, domains ...string) string {
	h.t.Helper()
	created := h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections", oidcConnection(name, domains...)), http.StatusCreated)
	id := created.body["id"].(string)
	h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections/"+id+"/test-result", map[string]any{"ok": true}), http.StatusOK)
	body := oidcConnection(name, domains...)
	body["status"] = "active"
	h.expect(h.do(http.MethodPut, "/platform/identity/sso/connections/"+id, body), http.StatusOK)
	return id
}

func (h *harness) scimToken(connectionID string) string {
	h.t.Helper()
	res := h.expect(h.do(http.MethodPost, "/platform/identity/scim/tokens", map[string]any{"name": "okta", "connectionId": connectionID}), http.StatusCreated)
	return res.body["token"].(string)
}

func TestConnectionLifecycleAndPolicy(t *testing.T) {
	h := newHarness(t)

	policy := h.expect(h.do(http.MethodGet, "/platform/identity/sso/policy", nil), http.StatusOK)
	if policy.body["sessionMaxLifetimeMinutes"] != float64(720) || policy.body["sessionIdleTimeoutMinutes"] != float64(60) || policy.body["enforced"] != false {
		t.Fatalf("default policy = %s", policy.raw)
	}
	h.expectError(h.do(http.MethodPut, "/platform/identity/sso/policy", map[string]any{"enforced": true}), http.StatusConflict, "no_active_connection")

	bad := oidcConnection("Okta", "example.com")
	bad["oidc"].(map[string]any)["clientSecretRef"] = "hunter2"
	h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections", bad), http.StatusBadRequest)
	h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections", "{not json"), http.StatusBadRequest)

	premature := oidcConnection("Okta", "example.com")
	premature["status"] = "active"
	h.expectError(h.do(http.MethodPost, "/platform/identity/sso/connections", premature), http.StatusConflict, "connection_not_tested")

	created := h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections", oidcConnection("Okta", "Example.com")), http.StatusCreated)
	id := created.body["id"].(string)
	if created.body["status"] != "draft" || created.body["updatedBy"] != "admin@example.com" {
		t.Fatalf("created = %s", created.raw)
	}

	activate := oidcConnection("Okta", "example.com")
	activate["status"] = "active"
	h.expectError(h.do(http.MethodPut, "/platform/identity/sso/connections/"+id, activate), http.StatusConflict, "connection_not_tested")

	tested := h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections/"+id+"/test-result", map[string]any{"ok": true, "detail": "ok"}), http.StatusOK)
	if tested.body["status"] != "tested" || tested.body["lastTest"].(map[string]any)["actor"] != "admin@example.com" {
		t.Fatalf("tested = %s", tested.raw)
	}
	h.expect(h.do(http.MethodPut, "/platform/identity/sso/connections/"+id, activate), http.StatusOK)

	h.expectError(h.do(http.MethodPost, "/platform/identity/sso/connections", oidcConnection("Other", "EXAMPLE.com")), http.StatusConflict, "domain_in_use")

	h.expect(h.do(http.MethodPut, "/platform/identity/sso/policy", map[string]any{"enforced": true, "sessionMaxLifetimeMinutes": 480, "sessionIdleTimeoutMinutes": 30}), http.StatusOK)
	h.expect(h.do(http.MethodPut, "/platform/identity/sso/policy", map[string]any{"sessionIdleTimeoutMinutes": 1}), http.StatusBadRequest)

	disable := oidcConnection("Okta", "example.com")
	disable["status"] = "disabled"
	h.expectError(h.do(http.MethodPut, "/platform/identity/sso/connections/"+id, disable), http.StatusConflict, "last_active_connection")
	h.expectError(h.do(http.MethodDelete, "/platform/identity/sso/connections/"+id, nil), http.StatusConflict, "last_active_connection")

	h.expect(h.do(http.MethodPut, "/platform/identity/sso/policy", map[string]any{"enforced": false}), http.StatusOK)
	rotated := oidcConnection("Okta", "example.com")
	rotated["status"] = "active"
	rotated["oidc"].(map[string]any)["clientId"] = "rotated"
	drafted := h.expect(h.do(http.MethodPut, "/platform/identity/sso/connections/"+id, rotated), http.StatusOK)
	if drafted.body["status"] != "draft" || drafted.body["lastTest"] != nil {
		t.Fatalf("protocol change should reset to draft and clear lastTest: %s", drafted.raw)
	}

	list := h.expect(h.do(http.MethodGet, "/platform/identity/sso/connections", nil), http.StatusOK)
	if len(list.body["connections"].([]any)) != 1 {
		t.Fatalf("list = %s", list.raw)
	}
	h.expectError(h.do(http.MethodGet, "/platform/identity/sso/connections/conn_missing", nil), http.StatusNotFound, "not_found")
	h.expectError(h.do(http.MethodGet, "/platform/identity/sso/connections/..%2fx", nil), http.StatusNotFound, "not_found")
	h.expect(h.do(http.MethodDelete, "/platform/identity/sso/connections/"+id, nil), http.StatusNoContent)
	h.expect(h.do(http.MethodGet, "/platform/identity/sso/connections/"+id, nil), http.StatusNotFound)
}

func TestConnectionLimit(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < sso.MaxConnections; i++ {
		h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections", oidcConnection("c"+string(rune('a'+i)))), http.StatusCreated)
	}
	h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections", oidcConnection("overflow")), http.StatusBadRequest)
}

func TestTenantResolution(t *testing.T) {
	h := newHarness(t)
	// Request selectors never change the partition: everything lands in the credential's own tenant.
	h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections?tenant_id=t1", oidcConnection("Okta", "example.com"), "X-Cerebro-Tenant", "t2"), http.StatusCreated)
	for _, path := range []string{"/platform/identity/sso/connections", "/platform/identity/sso/connections?tenant_id=t1", "/platform/identity/sso/connections?tenant_id=t2"} {
		got := h.expect(h.do(http.MethodGet, path, nil, "X-Cerebro-Tenant", "t3"), http.StatusOK)
		if len(got.body["connections"].([]any)) != 1 {
			t.Fatalf("%s list = %s", path, got.raw)
		}
	}
	if conns, _ := h.store.ListSSOConnections(context.Background(), "t1"); len(conns) != 0 {
		t.Fatalf("tenant_id query wrote to t1: %+v", conns)
	}
	if conns, _ := h.store.ListSSOConnections(context.Background(), DefaultTenantID); len(conns) != 1 {
		t.Fatalf("default tenant connections = %+v", conns)
	}

	var requested []string
	scoped := Handler{store: h.store, resolve: func(_ context.Context, req string) (string, error) {
		requested = append(requested, req)
		return "credential-tenant", nil
	}}
	rec := httptest.NewRecorder()
	newTestMux(scoped).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/platform/identity/sso/connections?tenant_id=x", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"connections":[]`) || len(requested) != 1 || requested[0] != "" {
		t.Fatalf("scoped credential = %d %s requested=%q", rec.Code, rec.Body.String(), requested)
	}

	denied := Handler{store: h.store, resolve: func(context.Context, string) (string, error) { return "", errors.New("cross-tenant") }}
	rec = httptest.NewRecorder()
	newTestMux(denied).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/platform/identity/sso/connections", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("resolver rejection = %d", rec.Code)
	}

	unavailable := NewHandler(nil, nil, nil)
	rec = httptest.NewRecorder()
	newTestMux(unavailable).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/platform/identity/sso/policy", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"code":"identity_sso_unavailable"`) {
		t.Fatalf("missing store = %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	newTestMux(unavailable).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/platform/identity/scim/v2/Users", nil))
	if rec.Code != http.StatusNotFound || rec.Header().Get("Content-Type") != sso.SCIMContentType {
		t.Fatalf("missing store on SCIM = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func sessionBody(connectionID string, token string, subject string, email string) map[string]any {
	return map[string]any{
		"tokenHash":          sso.HashToken(token),
		"connectionId":       connectionID,
		"subject":            subject,
		"email":              email,
		"roles":              []string{"cerebro.viewer"},
		"expiresAt":          time.Date(2026, 5, 1, 20, 0, 0, 0, time.UTC).Format(time.RFC3339),
		"idleTimeoutMinutes": 30,
		"userAgent":          "Mozilla/5.0",
	}
}

func TestSessions(t *testing.T) {
	h := newHarness(t)
	draft := h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections", oidcConnection("Draft")), http.StatusCreated).body["id"].(string)
	h.expectError(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(draft, "t0", "s0", "a@example.com")), http.StatusConflict, "connection_not_active")
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody("conn_missing", "t0", "s0", "a@example.com")), http.StatusNotFound)

	conn := h.activeConnection("Okta", "example.com")
	unknownRole := sessionBody(conn, "t0", "s0", "a@example.com")
	unknownRole["roles"] = []string{"root"}
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", unknownRole), http.StatusBadRequest)

	created := h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "tok-1", "00u1", "Alice@Example.com")), http.StatusCreated)
	hash := sso.HashToken("tok-1")
	if strings.Contains(created.raw, hash) || created.body["id"] == "" {
		t.Fatalf("created session leaks the token hash or lacks an id: %s", created.raw)
	}
	h.expectError(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "tok-1", "00u1", "a@example.com")), http.StatusConflict, "session_exists")
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "tok-2", "00u2", "bob@example.com")), http.StatusCreated)

	h.now = h.now.Add(20 * time.Minute)
	got := h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+hash, nil), http.StatusOK)
	if got.body["subject"] != "00u1" || h.store.touches != 1 {
		t.Fatalf("get session = %s touches=%d", got.raw, h.store.touches)
	}
	h.now = h.now.Add(30 * time.Second)
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+hash, nil), http.StatusOK)
	if h.store.touches != 1 {
		t.Fatalf("touch should be throttled, touches=%d", h.store.touches)
	}
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/not-a-hash", nil), http.StatusNotFound)
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("unknown"), nil), http.StatusNotFound)

	list := h.expect(h.do(http.MethodGet, "/platform/identity/sessions?subject=alice@EXAMPLE.com", nil), http.StatusOK)
	sessions := list.body["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("list by email = %s", list.raw)
	}
	summary := sessions[0].(map[string]any)
	if summary["tokenHashPrefix"] != hash[:8] || strings.Contains(list.raw, hash) {
		t.Fatalf("summary = %s", list.raw)
	}
	// tok-2 has been idle for more than 30 minutes by now.
	h.now = h.now.Add(10 * time.Minute)
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("tok-2"), nil), http.StatusNotFound)
	all := h.expect(h.do(http.MethodGet, "/platform/identity/sessions", nil), http.StatusOK)
	if len(all.body["sessions"].([]any)) != 1 {
		t.Fatalf("idle sessions must not be listed: %s", all.raw)
	}

	h.expect(h.do(http.MethodDelete, "/platform/identity/sessions", nil), http.StatusBadRequest)
	h.expect(h.do(http.MethodDelete, "/platform/identity/sessions?subject=a&email=b@example.com", nil), http.StatusBadRequest)
	// An email revocation must not match a session whose subject happens to equal the value.
	byEmail := h.expect(h.do(http.MethodDelete, "/platform/identity/sessions?email=00u1", nil), http.StatusOK)
	if byEmail.body["revoked"] != float64(0) {
		t.Fatalf("email revoke matched a subject: %s", byEmail.raw)
	}
	listByEmail := h.expect(h.do(http.MethodGet, "/platform/identity/sessions?email=ALICE@example.com", nil), http.StatusOK)
	if len(listByEmail.body["sessions"].([]any)) != 1 {
		t.Fatalf("list by email = %s", listByEmail.raw)
	}
	revoked := h.expect(h.do(http.MethodDelete, "/platform/identity/sessions?subject=00u1", nil), http.StatusOK)
	if revoked.body["revoked"] != float64(1) {
		t.Fatalf("revoke = %s", revoked.raw)
	}
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+hash, nil), http.StatusNotFound)

	h.expect(h.do(http.MethodDelete, "/platform/identity/sessions/"+hash, nil), http.StatusNoContent)
	h.expect(h.do(http.MethodDelete, "/platform/identity/sessions/"+hash, nil), http.StatusNoContent)
	h.expect(h.do(http.MethodDelete, "/platform/identity/sessions/bad", nil), http.StatusBadRequest)

	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "tok-3", "00u3", "c@example.com")), http.StatusCreated)
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "tok-4", "00u4", "d@example.com")), http.StatusCreated)
	emailRevoke := h.expect(h.do(http.MethodDelete, "/platform/identity/sessions?email=D@Example.com", nil), http.StatusOK)
	if emailRevoke.body["revoked"] != float64(1) {
		t.Fatalf("revoke by email = %s", emailRevoke.raw)
	}
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("tok-4"), nil), http.StatusNotFound)
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("tok-3"), nil), http.StatusOK)
	h.now = time.Date(2026, 5, 1, 20, 0, 0, 0, time.UTC)
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("tok-3"), nil), http.StatusNotFound)
}

func scimHeaders(token string) []string {
	return []string{SCIMTokenHeader, token, "Content-Type", sso.SCIMContentType}
}

func TestSCIMAuthentication(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	token := h.scimToken(conn)
	if !strings.HasPrefix(token, sso.SCIMTokenPrefix) {
		t.Fatalf("token = %q", token)
	}
	tokens := h.expect(h.do(http.MethodGet, "/platform/identity/scim/tokens", nil), http.StatusOK)
	if strings.Contains(tokens.raw, token) || strings.Contains(tokens.raw, sso.HashToken(token)) {
		t.Fatalf("token list leaks secret material: %s", tokens.raw)
	}
	listed := tokens.body["tokens"].([]any)[0].(map[string]any)
	if listed["prefix"] != token[:len(sso.SCIMTokenPrefix)+6] || listed["createdBy"] != "admin@example.com" {
		t.Fatalf("token metadata = %s", tokens.raw)
	}
	h.expect(h.do(http.MethodPost, "/platform/identity/scim/tokens", map[string]any{"name": "x", "connectionId": "conn_missing"}), http.StatusBadRequest)

	for _, header := range []string{"", "wrong", sso.SCIMTokenPrefix + "unknown", "Basic " + token} {
		res := h.do(http.MethodGet, "/platform/identity/scim/v2/Users", nil, SCIMTokenHeader, header)
		if res.status != http.StatusUnauthorized || res.contentType != sso.SCIMContentType || res.body["status"] != "401" {
			t.Fatalf("header %q: %d %q %s", header, res.status, res.contentType, res.raw)
		}
	}
	h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/ServiceProviderConfig", nil, SCIMTokenHeader, "Bearer "+token), http.StatusOK)
	types := h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/ResourceTypes", nil, scimHeaders(token)...), http.StatusOK)
	if types.body["totalResults"] != float64(2) || types.contentType != sso.SCIMContentType {
		t.Fatalf("resource types = %s", types.raw)
	}
	h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Schemas", nil, scimHeaders(token)...), http.StatusOK)

	// The token is bound to its partition: a credential scoped elsewhere cannot use it.
	elsewhere := Handler{store: h.store, resolve: func(context.Context, string) (string, error) { return "other", nil }, now: func() time.Time { return h.now }}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/platform/identity/scim/v2/Users", nil)
	headers := scimHeaders(token)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	newTestMux(elsewhere).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("token from another partition = %d %s", rec.Code, rec.Body.String())
	}

	id := listed["id"].(string)
	h.expect(h.do(http.MethodDelete, "/platform/identity/scim/tokens/"+id, nil), http.StatusNoContent)
	h.expect(h.do(http.MethodDelete, "/platform/identity/scim/tokens/"+id, nil), http.StatusNotFound)
	h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Users", nil, scimHeaders(token)...), http.StatusUnauthorized)
}

func TestSCIMUsers(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	token := h.scimToken(conn)
	headers := scimHeaders(token)

	alice := map[string]any{
		"schemas":    []string{sso.SCIMSchemaUser},
		"userName":   "alice@example.com",
		"externalId": "00u-alice",
		"name":       map[string]any{"givenName": "Alice", "familyName": "Smith"},
		"emails":     []map[string]any{{"value": "alice@example.com", "primary": true}},
	}
	created := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", alice, headers...), http.StatusCreated)
	if created.contentType != sso.SCIMContentType || created.body["active"] != true {
		t.Fatalf("created = %q %s", created.contentType, created.raw)
	}
	aliceID := created.body["id"].(string)

	alice["userName"] = "ALICE@example.com"
	dup := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", alice, headers...), http.StatusConflict)
	if dup.body["scimType"] != sso.SCIMTypeUniqueness {
		t.Fatalf("duplicate = %s", dup.raw)
	}
	h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"schemas": []string{sso.SCIMSchemaUser}}, headers...), http.StatusBadRequest)
	h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", "{", headers...), http.StatusBadRequest)

	filtered := h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Users?filter="+urlEscape(`userName eq "Alice@Example.com"`), nil, headers...), http.StatusOK)
	if filtered.body["totalResults"] != float64(1) {
		t.Fatalf("filter = %s", filtered.raw)
	}
	empty := h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Users?filter="+urlEscape(`userName eq "nobody@example.com"`), nil, headers...), http.StatusOK)
	if empty.body["totalResults"] != float64(0) || !strings.Contains(empty.raw, `"Resources":[]`) {
		t.Fatalf("empty filter = %s", empty.raw)
	}
	badFilter := h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Users?filter="+urlEscape(`userName sw "a"`), nil, headers...), http.StatusBadRequest)
	if badFilter.body["scimType"] != sso.SCIMTypeInvalidFilter {
		t.Fatalf("bad filter = %s", badFilter.raw)
	}

	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "alice-1", "00u-alice", "alice@example.com")), http.StatusCreated)
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "alice-2", "other-subject", "Alice@Example.com")), http.StatusCreated)
	h.expect(h.do(http.MethodPost, "/platform/identity/sessions", sessionBody(conn, "bob-1", "00u-bob", "bob@example.com")), http.StatusCreated)

	deactivate := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`
	patched := h.expect(h.do(http.MethodPatch, "/platform/identity/scim/v2/Users/"+aliceID, deactivate, headers...), http.StatusOK)
	if patched.body["active"] != false {
		t.Fatalf("patched = %s", patched.raw)
	}
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("alice-1"), nil), http.StatusNotFound)
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("alice-2"), nil), http.StatusNotFound)
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("bob-1"), nil), http.StatusOK)

	replaced := h.expect(h.do(http.MethodPut, "/platform/identity/scim/v2/Users/"+aliceID, map[string]any{"userName": "alice@example.com", "active": true, "displayName": "Alice S"}, headers...), http.StatusOK)
	if replaced.body["active"] != true || replaced.body["displayName"] != "Alice S" {
		t.Fatalf("replaced = %s", replaced.raw)
	}
	h.expect(h.do(http.MethodPatch, "/platform/identity/scim/v2/Users/"+aliceID, `{"Operations":[{"op":"remove","path":"userName"}]}`, headers...), http.StatusBadRequest)
	h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Users/usr_missing", nil, headers...), http.StatusNotFound)

	bob := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "bob@example.com", "externalId": "00u-bob"}, headers...), http.StatusCreated)
	bobID := bob.body["id"].(string)
	h.expect(h.do(http.MethodDelete, "/platform/identity/scim/v2/Users/"+bobID, nil, headers...), http.StatusNoContent)
	h.expect(h.do(http.MethodGet, "/platform/identity/sessions/"+sso.HashToken("bob-1"), nil), http.StatusNotFound)
	h.expect(h.do(http.MethodDelete, "/platform/identity/scim/v2/Users/"+bobID, nil, headers...), http.StatusNotFound)

	// Users provisioned for one connection are invisible to another connection's token.
	other := h.activeConnection("Entra", "example.org")
	otherToken := h.scimToken(other)
	h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Users/"+aliceID, nil, scimHeaders(otherToken)...), http.StatusNotFound)
	page := h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Users", nil, scimHeaders(otherToken)...), http.StatusOK)
	if page.body["totalResults"] != float64(0) {
		t.Fatalf("cross-connection list = %s", page.raw)
	}
}

func TestSCIMGroups(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	headers := scimHeaders(h.scimToken(conn))
	u1 := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "u1@example.com"}, headers...), http.StatusCreated).body["id"].(string)
	u2 := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "u2@example.com"}, headers...), http.StatusCreated).body["id"].(string)

	group := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Groups", map[string]any{
		"schemas":     []string{sso.SCIMSchemaGroup},
		"displayName": "Security",
		"members":     []map[string]any{{"value": u1}, {"value": u2}},
	}, headers...), http.StatusCreated)
	groupID := group.body["id"].(string)
	if len(group.body["members"].([]any)) != 2 {
		t.Fatalf("group = %s", group.raw)
	}
	h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Groups", map[string]any{"displayName": "security"}, headers...), http.StatusConflict)

	removed := h.expect(h.do(http.MethodPatch, "/platform/identity/scim/v2/Groups/"+groupID,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[value eq \"`+u2+`\"]"}]}`, headers...), http.StatusOK)
	if members := removed.body["members"].([]any); len(members) != 1 || members[0].(map[string]any)["value"] != u1 {
		t.Fatalf("after remove = %s", removed.raw)
	}

	user := h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Users/"+u1, nil, headers...), http.StatusOK)
	if groups := user.body["groups"].([]any); len(groups) != 1 || groups[0].(map[string]any)["display"] != "Security" {
		t.Fatalf("user groups = %s", user.raw)
	}

	listed := h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Groups?excludedAttributes=members&filter="+urlEscape(`displayName eq "security"`), nil, headers...), http.StatusOK)
	resources := listed.body["Resources"].([]any)
	if len(resources) != 1 || resources[0].(map[string]any)["members"] != nil {
		t.Fatalf("list groups = %s", listed.raw)
	}

	directory := h.expect(h.do(http.MethodGet, "/platform/identity/directory/groups", nil), http.StatusOK)
	if g := directory.body["groups"].([]any)[0].(map[string]any); g["memberCount"] != float64(1) || g["connectionId"] != conn {
		t.Fatalf("directory groups = %s", directory.raw)
	}

	h.expect(h.do(http.MethodPut, "/platform/identity/scim/v2/Groups/"+groupID, map[string]any{"displayName": "Sec", "members": []map[string]any{}}, headers...), http.StatusOK)
	h.expect(h.do(http.MethodPatch, "/platform/identity/scim/v2/Groups/"+groupID, `{"Operations":[{"op":"remove","path":"displayName"}]}`, headers...), http.StatusBadRequest)
	h.expect(h.do(http.MethodDelete, "/platform/identity/scim/v2/Groups/"+groupID, nil, headers...), http.StatusNoContent)
	h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Groups/"+groupID, nil, headers...), http.StatusNotFound)
}

func TestDirectoryJIT(t *testing.T) {
	h := newHarness(t)
	conn := h.activeConnection("Okta", "example.com")
	noJIT := oidcConnection("NoJIT", "example.net")
	noJIT["jitProvisioning"] = false
	noJITID := h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections", noJIT), http.StatusCreated).body["id"].(string)

	login := map[string]any{"connectionId": noJITID, "subject": "s1", "email": "carol@example.net", "name": "Carol", "groups": []string{"eng"}}
	// Draft connections never record logins; JIT-disabled active connections are covered in security_test.go.
	h.expectError(h.do(http.MethodPost, "/platform/identity/directory/users/jit", login), http.StatusConflict, "connection_not_active")
	h.expect(h.do(http.MethodPost, "/platform/identity/directory/users/jit", map[string]any{"connectionId": conn, "subject": "s1", "email": "nope"}), http.StatusBadRequest)

	login["connectionId"] = conn
	login["email"] = "carol@example.com"
	created := h.expect(h.do(http.MethodPost, "/platform/identity/directory/users/jit", login), http.StatusCreated)
	if created.body["source"] != "jit" || created.body["active"] != true || created.body["lastLoginAt"] == nil {
		t.Fatalf("jit create = %s", created.raw)
	}
	jitID := created.body["id"].(string)
	h.now = h.now.Add(time.Hour)
	login["groups"] = []string{"eng", "ops"}
	again := h.expect(h.do(http.MethodPost, "/platform/identity/directory/users/jit", login), http.StatusOK)
	if again.body["id"] != jitID || len(again.body["groups"].([]any)) != 2 {
		t.Fatalf("jit update = %s", again.raw)
	}

	// A SCIM push for the same userName adopts the just-in-time user.
	headers := scimHeaders(h.scimToken(conn))
	adopted := h.expect(h.do(http.MethodPost, "/platform/identity/scim/v2/Users", map[string]any{"userName": "Carol@example.com", "displayName": "Carol C"}, headers...), http.StatusCreated)
	if adopted.body["id"] != jitID {
		t.Fatalf("SCIM create should adopt the JIT user: %s", adopted.raw)
	}
	lookup := h.expect(h.do(http.MethodGet, "/platform/identity/directory/users/lookup?connectionId="+conn+"&email=CAROL@example.com", nil), http.StatusOK)
	if lookup.body["source"] != "scim" || lookup.body["name"] != "Carol C" {
		t.Fatalf("lookup = %s", lookup.raw)
	}
	h.expect(h.do(http.MethodGet, "/platform/identity/directory/users/lookup?connectionId="+conn+"&email=nobody@example.com", nil), http.StatusNotFound)
	h.expect(h.do(http.MethodGet, "/platform/identity/directory/users/lookup?email=carol@example.com", nil), http.StatusBadRequest)

	h.expect(h.do(http.MethodPatch, "/platform/identity/scim/v2/Users/"+jitID, `{"Operations":[{"op":"replace","path":"active","value":false}]}`, headers...), http.StatusOK)
	h.expectError(h.do(http.MethodPost, "/platform/identity/directory/users/jit", login), http.StatusForbidden, "user_inactive")

	users := h.expect(h.do(http.MethodGet, "/platform/identity/directory/users?query=carol", nil), http.StatusOK)
	if len(users.body["users"].([]any)) != 1 {
		t.Fatalf("directory search = %s", users.raw)
	}
	h.expect(h.do(http.MethodGet, "/platform/identity/directory/users?limit=0", nil), http.StatusBadRequest)

	// Deleting the connection removes its tokens and directory records.
	h.expect(h.do(http.MethodDelete, "/platform/identity/sso/connections/"+conn, nil), http.StatusNoContent)
	h.expect(h.do(http.MethodGet, "/platform/identity/scim/v2/Users", nil, headers...), http.StatusUnauthorized)
	remaining := h.expect(h.do(http.MethodGet, "/platform/identity/directory/users", nil), http.StatusOK)
	if len(remaining.body["users"].([]any)) != 0 {
		t.Fatalf("directory after connection delete = %s", remaining.raw)
	}
}

func TestErrorResponseMapping(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{ports.ErrSSOConnectionLimit, http.StatusBadRequest, ""},
		{ports.ErrDirectoryConflict, http.StatusConflict, "directory_conflict"},
		{ports.ErrSCIMTokenNotFound, http.StatusNotFound, "not_found"},
		{errors.New("database down"), http.StatusInternalServerError, "internal_error"},
	}
	for _, tc := range cases {
		status, body := errorResponse(tc.err)
		if status != tc.status || (tc.code != "" && body.Error != tc.code) {
			t.Errorf("errorResponse(%v) = %d %q", tc.err, status, body.Error)
		}
		if strings.Contains(body.Error, "database") {
			t.Errorf("internal error details leaked: %q", body.Error)
		}
	}
}

func urlEscape(value string) string {
	replacer := strings.NewReplacer(" ", "%20", `"`, "%22", "@", "%40")
	return replacer.Replace(value)
}
