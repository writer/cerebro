package duo

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
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
		name     string
		family   string
		kind     string
		path     string
		response map[string]any
		want     map[string]string
	}{
		{
			name:   "user",
			family: "user",
			kind:   "duo.user",
			path:   "/users",
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
			path:   "/users",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"user_id": "user-2", "username": "bob", "status": "bypass", "is_enrolled": false,
			}}},
			want: map[string]string{"user_id": "user-2", "username": "bob", "status": "bypass", "is_enrolled": "false"},
		},
		{
			name:   "phone",
			family: "phone",
			kind:   "duo.phone",
			path:   "/phones",
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
			path:   "/tokens",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"token_id": "token-1", "serial": "SN-123", "type": "h6", "totp_step": 30,
			}}},
			want: map[string]string{"token_id": "token-1", "serial": "SN-123", "type": "h6", "totp_step": "30"},
		},
		{
			name:   "web_authn_credential",
			family: "web_authn_credential",
			kind:   "duo.web_authn_credential",
			path:   "/webauthncredentials",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"credential_id": "cred-1", "label": "YubiKey", "credential_name": "yk-5c", "user_id": "user-1",
			}}},
			want: map[string]string{"credential_id": "cred-1", "label": "YubiKey", "credential_name": "yk-5c", "user_id": "user-1"},
		},
		{
			name:   "group",
			family: "group",
			kind:   "duo.group",
			path:   "/groups",
			response: map[string]any{"stat": "OK", "response": []map[string]any{{
				"group_id": "group-1", "name": "Engineering", "desc": "Eng team", "status": "Active",
			}}},
			want: map[string]string{"group_id": "group-1", "name": "Engineering", "description": "Eng team", "status": "Active"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("request path = %q, want %s", got, tt.path)
				}
				assertDuoHMACAuth(t, r, "DIXXXXXXXXXXXXXXXXXX", "deadbeefsecret")
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			config := map[string]string{"base_url": server.URL, "client_id": "DIXXXXXXXXXXXXXXXXXX", "client_secret": "deadbeefsecret", "family": tt.family, "tenant_id": "writer"}
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
		})
	}
}

func assertDuoHMACAuth(t *testing.T, r *http.Request, integrationKey string, secretKey string) {
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
	if username != integrationKey {
		t.Fatalf("Duo integration key = %q, want %q", username, integrationKey)
	}
	canonical := strings.Join([]string{
		date,
		r.Method,
		r.Host,
		r.URL.EscapedPath(),
		r.URL.Query().Encode(),
	}, "\n")
	mac := hmac.New(sha1.New, []byte(secretKey))
	_, _ = mac.Write([]byte(canonical))
	if want := hex.EncodeToString(mac.Sum(nil)); signature != want {
		t.Fatalf("Duo HMAC signature = %q, want %q", signature, want)
	}
}
