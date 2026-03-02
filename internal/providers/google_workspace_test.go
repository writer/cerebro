package providers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonHTTPResponse(status int, payload interface{}) (*http.Response, error) {
	body := []byte("{}")
	if payload != nil {
		switch typed := payload.(type) {
		case string:
			body = []byte(typed)
		default:
			encoded, err := json.Marshal(typed)
			if err != nil {
				return nil, err
			}
			body = encoded
		}
	}

	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func TestGoogleWorkspaceProviderSync_IncludesGroupMembers(t *testing.T) {
	t.Parallel()

	provider := NewGoogleWorkspaceProvider()
	provider.domain = "example.com"
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/admin/directory/v1/users":
			query := req.URL.Query()
			if query.Get("domain") != "example.com" {
				t.Fatalf("unexpected users domain query: %q", query.Get("domain"))
			}
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"users": []map[string]interface{}{
					{
						"id":           "user-1",
						"primaryEmail": "user-1@example.com",
					},
				},
			})
		case "/admin/directory/v1/groups":
			query := req.URL.Query()
			if query.Get("domain") != "example.com" {
				t.Fatalf("unexpected groups domain query: %q", query.Get("domain"))
			}
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"groups": []map[string]interface{}{
					{
						"id":    "group-1",
						"email": "eng@example.com",
						"name":  "Engineering",
					},
				},
			})
		case "/admin/directory/v1/groups/group-1/members":
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"members": []map[string]interface{}{
					{
						"id":     "member-1",
						"email":  "member-1@example.com",
						"role":   "MEMBER",
						"type":   "USER",
						"status": "ACTIVE",
					},
				},
			})
		case "/admin/directory/v1/customer/my_customer/domains":
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"domains": []map[string]interface{}{
					{
						"domainName": "example.com",
						"isPrimary":  true,
						"verified":   true,
					},
				},
			})
		default:
			t.Fatalf("unexpected path %q", req.URL.Path)
			return nil, nil
		}
	})}

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected sync errors: %v", result.Errors)
	}

	rowsByTable := map[string]int64{}
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	if got := rowsByTable["google_workspace_users"]; got != 1 {
		t.Fatalf("google_workspace_users rows = %d, want 1", got)
	}
	if got := rowsByTable["google_workspace_groups"]; got != 1 {
		t.Fatalf("google_workspace_groups rows = %d, want 1", got)
	}
	if got := rowsByTable["google_workspace_group_members"]; got != 1 {
		t.Fatalf("google_workspace_group_members rows = %d, want 1", got)
	}
	if got := rowsByTable["google_workspace_domains"]; got != 1 {
		t.Fatalf("google_workspace_domains rows = %d, want 1", got)
	}
}

func TestGoogleWorkspaceProviderSyncGroupMembers_IgnoresPermissionDeniedGroups(t *testing.T) {
	t.Parallel()

	provider := NewGoogleWorkspaceProvider()
	provider.domain = "example.com"
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/admin/directory/v1/groups":
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"groups": []map[string]interface{}{
					{"id": "group-no-access", "email": "locked@example.com"},
					{"id": "group-ok", "email": "open@example.com"},
				},
			})
		case "/admin/directory/v1/groups/group-no-access/members":
			return jsonHTTPResponse(http.StatusForbidden, map[string]interface{}{"error": "forbidden"})
		case "/admin/directory/v1/groups/group-ok/members":
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"members": []map[string]interface{}{
					{
						"id":     "member-1",
						"email":  "member-1@example.com",
						"role":   "MEMBER",
						"type":   "USER",
						"status": "ACTIVE",
					},
				},
			})
		default:
			t.Fatalf("unexpected path %q", req.URL.Path)
			return nil, nil
		}
	})}

	table, err := provider.syncGroupMembers(context.Background())
	if err != nil {
		t.Fatalf("syncGroupMembers failed: %v", err)
	}
	if table.Rows != 1 {
		t.Fatalf("syncGroupMembers rows = %d, want 1", table.Rows)
	}
	if table.Inserted != 1 {
		t.Fatalf("syncGroupMembers inserted = %d, want 1", table.Inserted)
	}
}

func TestGoogleWorkspaceProviderConfigure_RequiresCredentials(t *testing.T) {
	provider := NewGoogleWorkspaceProvider()

	err := provider.Configure(context.Background(), map[string]interface{}{
		"domain":      "example.com",
		"admin_email": "admin@example.com",
	})
	if err == nil {
		t.Fatal("expected credentials error")
	}
	if !strings.Contains(err.Error(), "google workspace credentials required") {
		t.Fatalf("expected credentials error, got %v", err)
	}
}

func TestGoogleWorkspaceProviderConfigure_RequiresDelegatedSubject(t *testing.T) {
	provider := NewGoogleWorkspaceProvider()

	err := provider.Configure(context.Background(), map[string]interface{}{
		"domain":           "example.com",
		"credentials_json": googleWorkspaceServiceAccountCredentialsJSON(t, "https://oauth2.test/token"),
	})
	if err == nil {
		t.Fatal("expected delegated subject error")
	}
	if !strings.Contains(err.Error(), "requires impersonator_email or admin_email") {
		t.Fatalf("expected delegated subject error, got %v", err)
	}
}

func TestGoogleWorkspaceProviderConfigure_ReadsCredentialsFile(t *testing.T) {
	credentialsJSON := googleWorkspaceServiceAccountCredentialsJSON(t, "https://oauth2.test/token")
	credentialsPath := filepath.Join(t.TempDir(), "workspace-service-account.json")
	if err := os.WriteFile(credentialsPath, []byte(credentialsJSON), 0o600); err != nil {
		t.Fatalf("write credentials file: %v", err)
	}

	provider := NewGoogleWorkspaceProvider()
	err := provider.Configure(context.Background(), map[string]interface{}{
		"domain":           "example.com",
		"admin_email":      "admin@example.com",
		"credentials_file": credentialsPath,
	})
	if err != nil {
		t.Fatalf("configure provider: %v", err)
	}
	if len(provider.credentials) == 0 {
		t.Fatal("expected credentials to be loaded from credentials_file")
	}
	if provider.client == nil {
		t.Fatal("expected OAuth client to be initialized")
	}
}

func TestGoogleWorkspaceProviderConfigure_DomainWideDelegationSubject(t *testing.T) {
	testCases := []struct {
		name              string
		adminEmail        string
		impersonatorEmail string
		expectedSubject   string
	}{
		{
			name:              "uses impersonator when configured",
			adminEmail:        "admin@example.com",
			impersonatorEmail: "delegated-admin@example.com",
			expectedSubject:   "delegated-admin@example.com",
		},
		{
			name:            "falls back to admin email",
			adminEmail:      "admin@example.com",
			expectedSubject: "admin@example.com",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			credentialsJSON := googleWorkspaceServiceAccountCredentialsJSON(t, "https://oauth2.test/token")
			observedSubject := ""

			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch {
				case req.URL.Host == "oauth2.test" && req.URL.Path == "/token":
					if err := req.ParseForm(); err != nil {
						t.Fatalf("parse token form: %v", err)
					}
					assertion := req.PostForm.Get("assertion")
					if assertion == "" {
						t.Fatal("expected JWT assertion in token request")
					}

					subject, err := extractJWTAssertionSubject(assertion)
					if err != nil {
						t.Fatalf("decode JWT assertion subject: %v", err)
					}
					observedSubject = subject

					return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
						"access_token": "test-token",
						"token_type":   "Bearer",
						"expires_in":   3600,
					})
				case req.URL.Host == "admin.googleapis.com" && req.URL.Path == "/admin/directory/v1/users":
					if !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ") {
						t.Fatalf("expected bearer token on admin request, got %q", req.Header.Get("Authorization"))
					}
					return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
						"users": []map[string]interface{}{},
					})
				default:
					t.Fatalf("unexpected request: %s %s", req.Method, req.URL.String())
					return nil, nil
				}
			})

			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: transport})

			provider := NewGoogleWorkspaceProvider()
			err := provider.Configure(ctx, map[string]interface{}{
				"domain":             "example.com",
				"admin_email":        tc.adminEmail,
				"impersonator_email": tc.impersonatorEmail,
				"credentials_json":   credentialsJSON,
			})
			if err != nil {
				t.Fatalf("configure provider: %v", err)
			}

			if err := provider.Test(ctx); err != nil {
				t.Fatalf("provider test failed: %v", err)
			}

			if observedSubject != tc.expectedSubject {
				t.Fatalf("delegated subject = %q, want %q", observedSubject, tc.expectedSubject)
			}
		})
	}
}

func googleWorkspaceServiceAccountCredentialsJSON(t *testing.T, tokenURL string) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test RSA key: %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	credentials := map[string]interface{}{
		"type":                        "service_account",
		"project_id":                  "test-project",
		"private_key_id":              "test-private-key-id",
		"private_key":                 string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		"client_email":                "svc-test@test-project.iam.gserviceaccount.com",
		"client_id":                   "123456789012345678901",
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   tokenURL,
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/svc-test%40test-project.iam.gserviceaccount.com",
	}

	encoded, err := json.Marshal(credentials)
	if err != nil {
		t.Fatalf("marshal service account credentials: %v", err)
	}

	return string(encoded)
}

func extractJWTAssertionSubject(assertion string) (string, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("expected 3 JWT segments, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode JWT payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("unmarshal JWT claims: %w", err)
	}

	subject, _ := claims["sub"].(string)
	if strings.TrimSpace(subject) == "" {
		return "", fmt.Errorf("JWT assertion missing sub claim")
	}

	return subject, nil
}
