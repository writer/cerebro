package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

type deadLetterForcePurgeTestStore struct {
	requests []ports.AppendLogDeadLetterForcePurgeRequest
	err      error
}

func (s *deadLetterForcePurgeTestStore) Ping(context.Context) error { return nil }

func (s *deadLetterForcePurgeTestStore) ForcePurgeAppendLogDeadLetter(_ context.Context, request ports.AppendLogDeadLetterForcePurgeRequest) error {
	s.requests = append(s.requests, request)
	return s.err
}

func TestDeadLetterForcePurgeUsesAuthenticatedAdminActor(t *testing.T) {
	store := &deadLetterForcePurgeTestStore{}
	server := newDeadLetterForcePurgeTestServer(t, store)
	response := doDeadLetterForcePurgeRequest(t, server, "admin-a-key", `{"tenant_id":"tenant-a","reason":"INC-1234 publication recovery"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.StatusCode, readResponseBody(t, response))
	}
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	_ = response.Body.Close()
	if len(store.requests) != 1 {
		t.Fatalf("force purge requests = %d, want 1", len(store.requests))
	}
	request := store.requests[0]
	if request.ID != "apdl-1" || request.TenantID != "tenant-a" || request.Actor != "admin-a@example.test" || request.Reason != "INC-1234 publication recovery" {
		t.Fatalf("force purge request = %#v", request)
	}
	if body["dead_letter_id"] != "apdl-1" || body["outcome"] != "purged" || len(body) != 2 {
		t.Fatalf("response body = %#v, want id and outcome only", body)
	}
}

func TestDeadLetterForcePurgeRejectsSelfAssertedActorAndMissingReason(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "self asserted actor", body: `{"tenant_id":"tenant-a","reason":"INC-1234","actor":"spoofed"}`},
		{name: "missing reason", body: `{"tenant_id":"tenant-a"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &deadLetterForcePurgeTestStore{}
			server := newDeadLetterForcePurgeTestServer(t, store)
			response := doDeadLetterForcePurgeRequest(t, server, "admin-a-key", test.body)
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.StatusCode, readResponseBody(t, response))
			}
			if len(store.requests) != 0 {
				t.Fatalf("force purge requests = %d, want 0", len(store.requests))
			}
		})
	}
}

func TestDeadLetterForcePurgeRequiresTenantAdminAuthorization(t *testing.T) {
	for _, test := range []struct {
		name       string
		credential string
		wantStatus int
	}{
		{name: "tenant reader", credential: "reader-a-key", wantStatus: http.StatusForbidden},
		{name: "admin for another tenant", credential: "admin-b-key", wantStatus: http.StatusForbidden},
		{name: "missing credential", credential: "", wantStatus: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &deadLetterForcePurgeTestStore{}
			server := newDeadLetterForcePurgeTestServer(t, store)
			response := doDeadLetterForcePurgeRequest(t, server, test.credential, `{"tenant_id":"tenant-a","reason":"INC-1234"}`)
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", response.StatusCode, test.wantStatus, readResponseBody(t, response))
			}
			if len(store.requests) != 0 {
				t.Fatalf("force purge requests = %d, want 0", len(store.requests))
			}
		})
	}
}

func TestDeadLetterForcePurgeRejectsWhenAPIAuthIsDisabled(t *testing.T) {
	store := &deadLetterForcePurgeTestStore{}
	app := New(config.Config{}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	response := doDeadLetterForcePurgeRequest(t, server, "unverified-admin", `{"tenant_id":"tenant-a","reason":"INC-1234"}`)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", response.StatusCode, readResponseBody(t, response))
	}
	if len(store.requests) != 0 {
		t.Fatalf("force purge requests = %d, want 0", len(store.requests))
	}
}

func TestDeadLetterForcePurgeMapsStateProtectionWithoutPayloadDisclosure(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "terminal record", err: ports.ErrAppendLogDeadLetterNotPending},
		{name: "active replay claim", err: ports.ErrAppendLogDeadLetterReplayClaimed},
		{name: "dependency error", err: errors.New("event envelope contains payload-secret")},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &deadLetterForcePurgeTestStore{err: test.err}
			server := newDeadLetterForcePurgeTestServer(t, store)
			response := doDeadLetterForcePurgeRequest(t, server, "admin-a-key", `{"tenant_id":"tenant-a","reason":"INC-1234"}`)
			body := readResponseBody(t, response)
			_ = response.Body.Close()
			if test.name == "dependency error" {
				if response.StatusCode != http.StatusInternalServerError {
					t.Fatalf("status = %d, want 500", response.StatusCode)
				}
			} else if response.StatusCode != http.StatusConflict {
				t.Fatalf("status = %d, want 409", response.StatusCode)
			}
			if strings.Contains(body, "payload-secret") || strings.Contains(body, "event envelope") {
				t.Fatalf("response disclosed payload-bearing error: %q", body)
			}
		})
	}
}

func newDeadLetterForcePurgeTestServer(t *testing.T, store *deadLetterForcePurgeTestStore) *httptest.Server {
	t.Helper()
	cfg := config.Config{Auth: config.AuthConfig{
		Enabled: true,
		APICredentials: []config.APICredential{
			{Key: "admin-a-key", Principal: "admin-a@example.test", TenantID: "tenant-a", Roles: []string{roleCerebroAdmin}},
			{Key: "reader-a-key", Principal: "reader-a@example.test", TenantID: "tenant-a", Roles: []string{roleCerebroViewer}},
			{Key: "admin-b-key", Principal: "admin-b@example.test", TenantID: "tenant-b", Roles: []string{roleCerebroAdmin}},
		},
	}}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	t.Cleanup(server.Close)
	return server
}

func doDeadLetterForcePurgeRequest(t *testing.T, server *httptest.Server, credential string, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/platform/append-log/dead-letters/apdl-1/force-purge", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("force purge request: %v", err)
	}
	return response
}

func readResponseBody(t *testing.T, response *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return string(body)
}
