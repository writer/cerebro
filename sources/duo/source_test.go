package duo

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- Duo Admin API HMAC auth requires HMAC-SHA1.
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	testDuoIntegrationKey = "DIXXXXXXXXXXXXXXXXXX"
	testDuoSecretKey      = "deadbeefsecret"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "duo" {
		t.Fatalf("Spec().Id = %q, want duo", got)
	}
}

func TestReadDuoIdentityAndMFAPostureKinds(t *testing.T) {
	for _, tt := range []struct {
		name           string
		family         string
		kind           string
		path           string
		authV5         bool
		response       map[string]any
		config         map[string]string
		want           map[string]string
		wantOccurredAt time.Time
	}{
		{
			name:   "user",
			family: "user",
			kind:   "duo.user",
			path:   "/admin/v1/users",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"user_id": "user-1", "username": "alice", "email": "alice@writer.com",
				"realname": "Alice Example", "status": "active", "is_enrolled": true,
				"last_login": 1700000000,
			}}},
			want: map[string]string{"user_id": "user-1", "username": "alice", "email": "alice@writer.com", "status": "active", "is_enrolled": "true"},
		},
		{
			name:   "user_bypass_unenrolled",
			family: "user",
			kind:   "duo.user",
			path:   "/admin/v1/users",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"user_id": "user-2", "username": "bob", "status": "bypass", "is_enrolled": false,
			}}},
			want: map[string]string{"user_id": "user-2", "username": "bob", "status": "bypass", "is_enrolled": "false"},
		},
		{
			name:   "administrator",
			family: "administrator",
			kind:   "duo.administrator",
			path:   "/admin/v1/admins",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"admin_id": "admin-1", "name": "Security Admin", "email": "secadmin@writer.com", "role": "Owner", "status": "Active",
			}}},
			want: map[string]string{"admin_id": "admin-1", "user_id": "admin-1", "email": "secadmin@writer.com", "role": "Owner", "status": "Active"},
		},
		{
			name:   "endpoint",
			family: "endpoint",
			kind:   "duo.endpoint",
			path:   "/admin/v1/endpoints",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"endpoint_id": "endpoint-1", "hostname": "macbook-1", "os": "macOS",
				"os_version": "15.5", "browser": "Safari", "disk_encryption_status": "encrypted",
				"last_seen": 1700000000,
			}}},
			want: map[string]string{"endpoint_id": "endpoint-1", "hostname": "macbook-1", "os": "macOS", "os_version": "15.5", "disk_encryption_status": "encrypted"},
		},
		{
			name:   "phone",
			family: "phone",
			kind:   "duo.phone",
			path:   "/admin/v1/phones",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"phone_id": "phone-1", "name": "iPhone", "number": "+15551234567",
				"platform": "Apple iOS", "model": "iPhone 15", "activated": true,
				"encrypted": "Encrypted", "screenlock": "Locked", "tampered": "Not tampered",
			}}},
			want: map[string]string{"phone_id": "phone-1", "platform": "Apple iOS", "model": "iPhone 15", "activated": "true", "encrypted": "Encrypted", "screenlock": "Locked"},
		},
		{
			name:   "token",
			family: "token",
			kind:   "duo.token",
			path:   "/admin/v1/tokens",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"token_id": "token-1", "serial": "SN-123", "type": "h6", "totp_step": 30,
			}}},
			want: map[string]string{"token_id": "token-1", "serial": "SN-123", "type": "h6", "totp_step": "30"},
		},
		{
			name:   "web_authn_credential",
			family: "web_authn_credential",
			kind:   "duo.web_authn_credential",
			path:   "/admin/v1/webauthncredentials",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"webauthnkey": "cred-1", "label": "YubiKey", "credential_name": "yk-5c", "user_id": "user-1",
			}}},
			want: map[string]string{"credential_id": "cred-1", "label": "YubiKey", "credential_name": "yk-5c", "user_id": "user-1"},
		},
		{
			name:   "group",
			family: "group",
			kind:   "duo.group",
			path:   "/admin/v1/groups",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"group_id": "group-1", "name": "Engineering", "desc": "Eng team", "status": "Active",
			}}},
			want: map[string]string{"group_id": "group-1", "name": "Engineering", "description": "Eng team", "status": "Active"},
		},
		{
			name:   "role",
			family: "role",
			kind:   "duo.role",
			path:   "/admin/v1/admin_roles",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"role_id": "owner", "name": "Owner", "description": "Full administrator access",
			}}},
			want: map[string]string{"policy_id": "owner", "policy_name": "Owner", "policy_type": "administrator_role", "description": "Full administrator access"},
		},
		{
			name:   "application",
			family: "application",
			kind:   "duo.application",
			path:   "/admin/v3/integrations",
			authV5: true,
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"integration_key": "DIAPP1", "name": "GitHub Enterprise", "type": "websdk",
			}}},
			want: map[string]string{"integration_key": "DIAPP1", "resource_id": "DIAPP1", "resource_name": "GitHub Enterprise", "resource_type": "websdk"},
		},
		{
			name:   "audit_event",
			family: "audit_event",
			kind:   "duo.audit_event",
			path:   "/admin/v2/logs/activity",
			config: map[string]string{"mintime": "1700000000000", "maxtime": "1700003600000"},
			response: map[string]any{"stat": "OK", "response": map[string]any{"items": []map[string]any{{
				"activity_id": "activity-1", "action": "user_update",
				"actor":  map[string]any{"key": "admin-1", "name": "Security Admin", "type": "admin"},
				"target": map[string]any{"key": "user-1", "name": "Alice", "type": "user"},
				"ts":     "2026-06-01T00:00:00Z",
			}}, "metadata": map[string]any{"next_offset": []string{"1700000000001", "activity-1"}}}},
			want: map[string]string{"event_type": "user_update", "actor_id": "admin-1", "actor_name": "Security Admin", "actor_type": "admin", "resource_id": "user-1", "resource_type": "user"},
		},
		{
			name:   "authentication_log",
			family: "authentication_log",
			kind:   "duo.authentication_log",
			path:   "/admin/v2/logs/authentication",
			config: map[string]string{"mintime": "1700000000000", "maxtime": "1700003600000"},
			response: map[string]any{"stat": "OK", "response": map[string]any{"authlogs": []map[string]any{{
				"txid": "auth-1", "event_type": "authentication", "factor": "duo_push", "result": "SUCCESS",
				"user":         map[string]any{"key": "user-1", "name": "alice"},
				"application":  map[string]any{"key": "DIAPP1", "name": "GitHub Enterprise", "type": "websdk"},
				"isotimestamp": "2023-11-14T22:13:20Z",
				"timestamp":    1700000000000,
			}}}},
			want:           map[string]string{"event_type": "authentication", "actor_id": "user-1", "actor_name": "alice", "resource_id": "DIAPP1", "factor": "duo_push", "result": "SUCCESS"},
			wantOccurredAt: time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("request path = %q, want %s", got, tt.path)
				}
				if tt.authV5 {
					assertDuoHMACV5Auth(t, r)
				} else {
					assertDuoHMACAuth(t, r)
				}
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			config := map[string]string{"base_url": server.URL, "client_id": testDuoIntegrationKey, "client_secret": testDuoSecretKey, "family": tt.family, "tenant_id": "writer"}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %q", event.Kind, tt.kind)
			}
			for key, value := range tt.want {
				if got := event.Attributes[key]; got != value {
					t.Fatalf("attribute %q = %q, want %q", key, got, value)
				}
			}
			if !tt.wantOccurredAt.IsZero() {
				if got := event.OccurredAt.AsTime(); !got.Equal(tt.wantOccurredAt) {
					t.Fatalf("OccurredAt = %s, want %s", got.Format(time.RFC3339), tt.wantOccurredAt.Format(time.RFC3339))
				}
			}
		})
	}
}

func TestReadDuoAcceptsLegacyAdminBaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/admin/v1/users" {
			t.Fatalf("request path = %q, want /admin/v1/users", got)
		}
		assertDuoHMACAuth(t, r)
		_ = json.NewEncoder(w).Encode(map[string]any{"stat": "OK", "response": []map[string]any{{
			"user_id": "user-1", "username": "alice", "status": "active",
		}}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":      server.URL + "/admin/v1",
		"client_id":     testDuoIntegrationKey,
		"client_secret": testDuoSecretKey,
		"family":        "user",
		"tenant_id":     "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
}

func TestReadDuoInventoryUsesOffsetPagination(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.URL.EscapedPath(); got != "/admin/v1/users" {
			t.Fatalf("request path = %q, want /admin/v1/users", got)
		}
		assertDuoHMACAuth(t, r)
		if got := r.URL.Query().Get("limit"); got != "1" {
			t.Fatalf("limit = %q, want 1", got)
		}
		switch requests {
		case 1:
			if got := r.URL.Query().Get("offset"); got != "0" {
				t.Fatalf("first offset = %q, want 0", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"stat": "OK", "response": []map[string]any{{
				"user_id": "user-1", "username": "alice", "status": "active",
			}}})
		case 2:
			if got := r.URL.Query().Get("offset"); got != "1" {
				t.Fatalf("second offset = %q, want 1", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"stat": "OK", "response": []map[string]any{}})
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":      server.URL,
		"client_id":     testDuoIntegrationKey,
		"client_secret": testDuoSecretKey,
		"family":        "user",
		"per_page":      "1",
		"tenant_id":     "writer",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("first events = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "1" {
		t.Fatalf("first NextCursor = %#v, want 1", first.NextCursor)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if len(second.Events) != 0 {
		t.Fatalf("second events = %d, want 0", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestReadDuoAuthenticationLogRoundTripsNextOffset(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.URL.EscapedPath(); got != "/admin/v2/logs/authentication" {
			t.Fatalf("request path = %q, want /admin/v2/logs/authentication", got)
		}
		assertDuoHMACAuth(t, r)
		switch requests {
		case 1:
			if got := r.URL.Query().Get("next_offset"); got != "" {
				t.Fatalf("first next_offset = %q, want empty", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"stat": "OK", "response": map[string]any{
				"authlogs": []map[string]any{{
					"txid":         "auth-1",
					"event_type":   "authentication",
					"user":         map[string]any{"key": "user-1", "name": "alice"},
					"application":  map[string]any{"key": "DIAPP1", "name": "GitHub Enterprise"},
					"isotimestamp": "2023-11-14T22:13:20Z",
					"timestamp":    1700000000000,
				}},
				"metadata": map[string]any{"next_offset": []any{"1751400000000", "0bea1c1e-0000-4000-8000-000000000001"}},
			}})
		case 2:
			if got := r.URL.Query()["next_offset"]; len(got) != 2 || got[0] != "0bea1c1e-0000-4000-8000-000000000001" || got[1] != "1751400000000" {
				t.Fatalf("second next_offset = %#v, want sorted repeated Duo cursor values", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"stat": "OK", "response": map[string]any{"authlogs": []map[string]any{}}})
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":      server.URL,
		"client_id":     testDuoIntegrationKey,
		"client_secret": testDuoSecretKey,
		"family":        "authentication_log",
		"tenant_id":     "writer",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "1751400000000,0bea1c1e-0000-4000-8000-000000000001" {
		t.Fatalf("first NextCursor = %#v, want 1751400000000,0bea1c1e-0000-4000-8000-000000000001", first.NextCursor)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if len(second.Events) != 0 {
		t.Fatalf("second events = %d, want 0", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}

	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range duoFixtureFamilies {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/admin/v1/users" {
			t.Fatalf("request path = %q, want /admin/v1/users", got)
		}
		assertDuoHMACAuth(t, r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "temporarily unavailable", "stat": "FAIL"})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":      server.URL,
		"client_id":     testDuoIntegrationKey,
		"client_secret": testDuoSecretKey,
		"family":        "user",
		"tenant_id":     "writer",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "duo API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func assertDuoHMACAuth(t *testing.T, r *http.Request) {
	t.Helper()
	date := r.Header.Get("Date")
	if date == "" {
		t.Fatal("Date header is empty; Duo HMAC auth requires it")
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		t.Fatalf("Authorization = %q, want Basic auth", auth)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		t.Fatalf("decode Authorization: %v", err)
	}
	username, signature, ok := strings.Cut(string(decoded), ":")
	if !ok {
		t.Fatalf("Authorization payload = %q, want username:signature", decoded)
	}
	if username != testDuoIntegrationKey {
		t.Fatalf("Duo integration key = %q, want %q", username, testDuoIntegrationKey)
	}
	canonical := strings.Join([]string{
		date,
		r.Method,
		r.Host,
		r.URL.EscapedPath(),
		r.URL.Query().Encode(),
	}, "\n")
	mac := hmac.New(sha1.New, []byte(testDuoSecretKey))
	_, _ = mac.Write([]byte(canonical))
	if want := hex.EncodeToString(mac.Sum(nil)); signature != want {
		t.Fatalf("Duo HMAC signature = %q, want %q", signature, want)
	}
}

func assertDuoHMACV5Auth(t *testing.T, r *http.Request) {
	t.Helper()
	date := r.Header.Get("Date")
	if date == "" {
		t.Fatal("Date header is empty; Duo HMAC v5 auth requires it")
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		t.Fatalf("Authorization = %q, want Basic auth", auth)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		t.Fatalf("decode Authorization: %v", err)
	}
	username, signature, ok := strings.Cut(string(decoded), ":")
	if !ok {
		t.Fatalf("Authorization payload = %q, want username:signature", decoded)
	}
	if username != testDuoIntegrationKey {
		t.Fatalf("Duo integration key = %q, want %q", username, testDuoIntegrationKey)
	}
	canonical := strings.Join([]string{
		date,
		r.Method,
		r.Host,
		r.URL.EscapedPath(),
		r.URL.Query().Encode(),
		sha512Hex(""),
		sha512Hex(""),
	}, "\n")
	mac := hmac.New(sha512.New, []byte(testDuoSecretKey))
	_, _ = mac.Write([]byte(canonical))
	if want := hex.EncodeToString(mac.Sum(nil)); signature != want {
		t.Fatalf("Duo HMAC v5 signature = %q, want %q", signature, want)
	}
}

func sha512Hex(value string) string {
	hash := sha512.New()
	_, _ = hash.Write([]byte(value))
	return hex.EncodeToString(hash.Sum(nil))
}
