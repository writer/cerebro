package duo_security

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertDuoSignedRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/admin/v1/users":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stat": "OK",
				"response": []map[string]any{{
					"user_id":    "DUUSER1",
					"username":   "user@example.test",
					"realname":   "User One",
					"email":      "user@example.test",
					"status":     "active",
					"created":    1780272000,
					"last_login": 1780272000,
				}},
			})
		case "/admin/v1/groups":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stat": "OK",
				"response": []map[string]any{{
					"group_id": "DGROUP1",
					"name":     "Engineering",
					"desc":     "Engineering users",
					"status":   "active",
				}},
			})
		case "/admin/v1/admins":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stat": "OK",
				"response": []map[string]any{{
					"admin_id": "DADMIN1",
					"name":     "Admin One",
					"email":    "admin@example.test",
					"role":     "Owner",
					"status":   "active",
				}},
			})
		case "/admin/v1/phones":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stat": "OK",
				"response": []map[string]any{{
					"phone_id":   "DPHONE1",
					"name":       "Alice phone",
					"number":     "+15550100",
					"platform":   "Apple iOS",
					"model":      "iPhone",
					"activated":  true,
					"encrypted":  true,
					"screenlock": "locked",
					"tampered":   "not_tampered",
					"user_id":    "DUUSER1",
				}},
			})
		case "/admin/v1/tokens":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stat": "OK",
				"response": []map[string]any{{
					"token_id": "DTOKEN1",
					"serial":   "123456",
					"type":     "h6",
					"user_id":  "DUUSER1",
				}},
			})
		case "/admin/v1/webauthncredentials":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stat": "OK",
				"response": []map[string]any{{
					"webauthnkey": "DWEBAUTHN1",
					"label":       "YubiKey",
					"user_id":     "DUUSER1",
					"last_used":   "2026-06-01T00:00:00Z",
				}},
			})
		case "/admin/v1/bypass_codes":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stat": "OK",
				"response": []map[string]any{{
					"bypass_code_id": "DBYPASS1",
					"user_id":        "DUUSER1",
					"created":        1780272000,
					"expiration":     1780275600,
				}},
			})
		case "/admin/v1/endpoints":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stat": "OK",
				"response": []map[string]any{{
					"epkey":                  "DENDPOINT1",
					"hostname":               "macbook-1",
					"os":                     "macOS",
					"os_version":             "15.0",
					"browser":                "Chrome",
					"disk_encryption_status": "encrypted",
				}},
			})
		case "/admin/v1/admin_roles":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stat": "OK",
				"response": []map[string]any{{
					"role_id":     "owner",
					"name":        "Owner",
					"description": "Can manage the account",
					"in_use":      true,
					"is_custom":   false,
				}},
			})
		case "/admin/v3/integrations":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stat": "OK",
				"response": []map[string]any{{
					"integration_key": "DIAPP1",
					"name":            "Admin API",
					"type":            "adminapi",
				}},
			})
		case "/admin/v2/logs/activity":
			if r.URL.Query().Get("mintime") != "1780271880000" || r.URL.Query().Get("maxtime") != "1780272000000" {
				t.Fatalf("activity query = %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stat": "OK",
				"response": map[string]any{
					"items": []map[string]any{{
						"txid":         "tx-1",
						"event_type":   "integration_update",
						"isotimestamp": "2026-06-01T00:00:00Z",
						"actor":        map[string]any{"key": "DUUSER1", "name": "User One"},
						"target":       map[string]any{"key": "DIAPP1", "name": "Admin API", "type": "integration"},
					}},
					"metadata": map[string]any{},
				},
			})
		case "/admin/v2/logs/authentication":
			if r.URL.Query().Get("mintime") != "1780271880000" || r.URL.Query().Get("maxtime") != "1780272000000" {
				t.Fatalf("authentication query = %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stat": "OK",
				"response": map[string]any{
					"authlogs": []map[string]any{{
						"txid":         "auth-tx-1",
						"event_type":   "authentication",
						"factor":       "duo_push",
						"result":       "SUCCESS",
						"isotimestamp": "2026-06-01T00:00:00Z",
						"username":     "user@example.test",
						"email":        "user@example.test",
						"application":  map[string]any{"key": "DIAPP1", "name": "Admin API", "type": "adminapi"},
					}},
					"metadata": map[string]any{},
				},
			})
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfgValues := map[string]string{
		"tenant_id":     "tenant",
		"base_url":      server.URL,
		"family":        defaultFamily,
		"client_id":     "DIXXXXXXXXXXXXXXXXXX",
		"client_secret": "deadbeefsecret",
		"mintime":       "1780271880000",
		"maxtime":       "1780272000000",
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(cfgValues)); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	for _, family := range []string{familyUsers, familyGroups, familyAdministrators, familyPhones, familyHardwareTokens, familyWebAuthnCredentials, familyBypassCodes, familyEndpoints, familyRoles, familyApplications, familyAuditEvents, familyAuthenticationLogs} {
		cfgValues["family"] = family
		pull, err := source.Read(context.Background(), sourcecdk.NewConfig(cfgValues), nil)
		if err != nil {
			t.Fatalf("Read(%s) error = %v", family, err)
		}
		if len(pull.Events) != 1 {
			t.Fatalf("Read(%s) events = %d, want 1", family, len(pull.Events))
		}
		event := pull.Events[0]
		if event.Kind != "duo_security."+family {
			t.Fatalf("Read(%s) kind = %q", family, event.Kind)
		}
		if strings.TrimSpace(event.Id) == "" {
			t.Fatalf("Read(%s) event id is empty: %#v", family, event)
		}
	}
}

func TestNewFixtureReplaysDuoSecurityFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{
		familyUsers,
		familyGroups,
		familyAdministrators,
		familyPhones,
		familyHardwareTokens,
		familyWebAuthnCredentials,
		familyBypassCodes,
		familyEndpoints,
		familyRoles,
		familyApplications,
		familyAuditEvents,
		familyAuthenticationLogs,
	} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":    family,
			"tenant_id": "tenant",
			"mintime":   "1780271880000",
			"maxtime":   "1780272000000",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
	for _, tt := range []struct {
		family          string
		kind            string
		wantResourceURN string
	}{
		{family: familyUsers, kind: "duo_security.users"},
		{family: familyGroups, kind: "duo_security.groups"},
		{family: familyAdministrators, kind: "duo_security.administrators"},
		{family: familyPhones, kind: "duo_security.phones"},
		{family: familyHardwareTokens, kind: "duo_security.hardware_tokens"},
		{family: familyWebAuthnCredentials, kind: "duo_security.webauthn_credentials"},
		{family: familyBypassCodes, kind: "duo_security.bypass_codes", wantResourceURN: "urn:cerebro:tenant:runtime_bypass_codes:DBYPASS1"},
		{family: familyEndpoints, kind: "duo_security.endpoints"},
		{family: familyRoles, kind: "duo_security.roles"},
		{family: familyApplications, kind: "duo_security.applications", wantResourceURN: "urn:cerebro:tenant:runtime_applications:DIAPP1"},
		{family: familyAuditEvents, kind: "duo_security.audit_events"},
		{family: familyAuthenticationLogs, kind: "duo_security.authentication_logs"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), familyConfigs[tt.family], nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("event kind = %q, want %q", got, tt.kind)
			}
			if tt.wantResourceURN != "" {
				if got := pull.Events[0].Attributes["resource_urn"]; got != tt.wantResourceURN {
					t.Fatalf("resource_urn = %q, want %q", got, tt.wantResourceURN)
				}
			}
		})
	}
}

func assertDuoSignedRequest(t *testing.T, r *http.Request) {
	t.Helper()
	date := r.Header.Get("Date")
	if date == "" {
		t.Fatal("Date header is empty")
	}
	rawAuth := r.Header.Get("Authorization")
	if !strings.HasPrefix(rawAuth, "Basic ") {
		t.Fatalf("Authorization = %q, want Basic", rawAuth)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(rawAuth, "Basic "))
	if err != nil {
		t.Fatalf("decode Authorization: %v", err)
	}
	username, signature, ok := strings.Cut(string(decoded), ":")
	if !ok {
		t.Fatalf("Authorization payload = %q, want username:signature", decoded)
	}
	if username != "DIXXXXXXXXXXXXXXXXXX" {
		t.Fatalf("Duo integration key = %q", username)
	}
	canonical := strings.Join([]string{
		date,
		r.Method,
		strings.ToLower(r.Host),
		r.URL.EscapedPath(),
		r.URL.Query().Encode(),
	}, "\n")
	if r.URL.Path == "/admin/v3/integrations" {
		canonical = strings.Join([]string{
			date,
			r.Method,
			strings.ToLower(r.Host),
			r.URL.EscapedPath(),
			r.URL.Query().Encode(),
			sha512Hex(""),
			sha512Hex(""),
		}, "\n")
	}
	mac := hmac.New(sha512.New, []byte("deadbeefsecret"))
	_, _ = mac.Write([]byte(canonical))
	if want := hex.EncodeToString(mac.Sum(nil)); signature != want {
		t.Fatalf("Duo signature for %s = %q, want %q", r.URL.Path, signature, want)
	}
}

func sha512Hex(value string) string {
	hash := sha512.New()
	_, _ = hash.Write([]byte(value))
	return hex.EncodeToString(hash.Sum(nil))
}
