package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"log/slog"

	"github.com/writer/cerebro/internal/apiauth"
	"github.com/writer/cerebro/internal/app"
)

type stubAgentSDKAdminService struct {
	authorizationServersFunc func() []string
	supportedScopesFunc      func() []string
	listCredentialsFunc      func() []adminAgentSDKCredentialResponse
	getCredentialFunc        func(string) (adminAgentSDKCredentialResponse, bool)
	createCredentialFunc     func(apiauth.ManagedCredentialSpec, time.Time) (adminAgentSDKCredentialResponse, string, error)
	rotateCredentialFunc     func(string, time.Time) (adminAgentSDKCredentialResponse, string, error)
	revokeCredentialFunc     func(string, string, time.Time) (adminAgentSDKCredentialResponse, error)
}

func (s stubAgentSDKAdminService) AuthorizationServers() []string {
	if s.authorizationServersFunc != nil {
		return s.authorizationServersFunc()
	}
	return nil
}

func (s stubAgentSDKAdminService) SupportedScopes() []string {
	if s.supportedScopesFunc != nil {
		return s.supportedScopesFunc()
	}
	return nil
}

func (s stubAgentSDKAdminService) ListCredentials() []adminAgentSDKCredentialResponse {
	if s.listCredentialsFunc != nil {
		return s.listCredentialsFunc()
	}
	return nil
}

func (s stubAgentSDKAdminService) GetCredential(id string) (adminAgentSDKCredentialResponse, bool) {
	if s.getCredentialFunc != nil {
		return s.getCredentialFunc(id)
	}
	return adminAgentSDKCredentialResponse{}, false
}

func (s stubAgentSDKAdminService) CreateCredential(spec apiauth.ManagedCredentialSpec, now time.Time) (adminAgentSDKCredentialResponse, string, error) {
	if s.createCredentialFunc != nil {
		return s.createCredentialFunc(spec, now)
	}
	return adminAgentSDKCredentialResponse{}, "", nil
}

func (s stubAgentSDKAdminService) RotateCredential(id string, now time.Time) (adminAgentSDKCredentialResponse, string, error) {
	if s.rotateCredentialFunc != nil {
		return s.rotateCredentialFunc(id, now)
	}
	return adminAgentSDKCredentialResponse{}, "", nil
}

func (s stubAgentSDKAdminService) RevokeCredential(id, reason string, now time.Time) (adminAgentSDKCredentialResponse, error) {
	if s.revokeCredentialFunc != nil {
		return s.revokeCredentialFunc(id, reason, now)
	}
	return adminAgentSDKCredentialResponse{}, nil
}

func TestAgentSDKAdminMetadataAndReadHandlersUseServiceInterface(t *testing.T) {
	var (
		authServersCalled bool
		scopesCalled      bool
		listCalled        bool
		getCalled         bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		agentSDKAdmin: stubAgentSDKAdminService{
			authorizationServersFunc: func() []string {
				authServersCalled = true
				return []string{"https://auth.example.com"}
			},
			supportedScopesFunc: func() []string {
				scopesCalled = true
				return []string{"sdk.admin", "sdk.context.read"}
			},
			listCredentialsFunc: func() []adminAgentSDKCredentialResponse {
				listCalled = true
				return []adminAgentSDKCredentialResponse{{ID: "cred-1", Managed: true}}
			},
			getCredentialFunc: func(id string) (adminAgentSDKCredentialResponse, bool) {
				getCalled = true
				if id != "cred-1" {
					t.Fatalf("expected credential id cred-1, got %q", id)
				}
				return adminAgentSDKCredentialResponse{ID: id, Managed: true}, true
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	req.Host = "api.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed protected resource metadata, got %d: %s", resp.Code, resp.Body.String())
	}
	if !authServersCalled || !scopesCalled {
		t.Fatal("expected protected-resource metadata handler to use agent sdk admin service")
	}
	metadata := decodeJSON(t, resp)
	if metadata["resource"] != "https://api.example.com" {
		t.Fatalf("expected resource URL, got %#v", metadata["resource"])
	}
	if got := metadata["authorization_servers"].([]any); len(got) != 1 || got[0] != "https://auth.example.com" {
		t.Fatalf("expected stubbed authorization servers, got %#v", metadata["authorization_servers"])
	}

	if w := do(t, s, http.MethodGet, "/api/v1/admin/agent-sdk/credentials", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed credential list, got %d: %s", w.Code, w.Body.String())
	}
	if !listCalled {
		t.Fatal("expected credential list handler to use agent sdk admin service")
	}

	if w := do(t, s, http.MethodGet, "/api/v1/admin/agent-sdk/credentials/cred-1", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed credential get, got %d: %s", w.Code, w.Body.String())
	}
	if !getCalled {
		t.Fatal("expected credential get handler to use agent sdk admin service")
	}
}

func TestAgentSDKAdminMutationHandlersUseServiceInterface(t *testing.T) {
	var (
		scopesCalled bool
		createCalled bool
		rotateCalled bool
		revokeCalled bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		agentSDKAdmin: stubAgentSDKAdminService{
			supportedScopesFunc: func() []string {
				scopesCalled = true
				return []string{"sdk.admin", "sdk.context.read", "sdk.invoke"}
			},
			createCredentialFunc: func(spec apiauth.ManagedCredentialSpec, now time.Time) (adminAgentSDKCredentialResponse, string, error) {
				createCalled = true
				if now.IsZero() {
					t.Fatal("expected create timestamp")
				}
				if spec.Name != "SDK Worker" {
					t.Fatalf("expected credential name SDK Worker, got %q", spec.Name)
				}
				if len(spec.Scopes) != 2 || spec.Scopes[0] != "sdk.context.read" || spec.Scopes[1] != "sdk.invoke" {
					t.Fatalf("expected normalized scopes to reach service, got %#v", spec.Scopes)
				}
				return adminAgentSDKCredentialResponse{ID: "cred-managed"}, "secret-1", nil
			},
			rotateCredentialFunc: func(id string, now time.Time) (adminAgentSDKCredentialResponse, string, error) {
				rotateCalled = true
				if now.IsZero() {
					t.Fatal("expected rotate timestamp")
				}
				if id != "cred-managed" {
					t.Fatalf("expected rotate cred-managed, got %q", id)
				}
				return adminAgentSDKCredentialResponse{ID: id, Managed: true}, "secret-2", nil
			},
			revokeCredentialFunc: func(id, reason string, now time.Time) (adminAgentSDKCredentialResponse, error) {
				revokeCalled = true
				if now.IsZero() {
					t.Fatal("expected revoke timestamp")
				}
				if id != "cred-managed" || reason != "done" {
					t.Fatalf("unexpected revoke payload: id=%q reason=%q", id, reason)
				}
				return adminAgentSDKCredentialResponse{ID: id, Managed: true}, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	createResp := do(t, s, http.MethodPost, "/api/v1/admin/agent-sdk/credentials", map[string]any{
		"name":   "SDK Worker",
		"scopes": []string{"sdk.invoke", "sdk.context.read", "sdk.invoke"},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 for service-backed create credential, got %d: %s", createResp.Code, createResp.Body.String())
	}
	if !scopesCalled || !createCalled {
		t.Fatal("expected credential create handler to use agent sdk admin service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/admin/agent-sdk/credentials/cred-managed:rotate", map[string]any{}); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed rotate credential, got %d: %s", w.Code, w.Body.String())
	}
	if !rotateCalled {
		t.Fatal("expected credential rotate handler to use agent sdk admin service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/admin/agent-sdk/credentials/cred-managed:revoke", map[string]any{"reason": "done"}); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed revoke credential, got %d: %s", w.Code, w.Body.String())
	}
	if !revokeCalled {
		t.Fatal("expected credential revoke handler to use agent sdk admin service")
	}
}
