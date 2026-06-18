package accessapprovalsclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphactions"
)

func TestClientSuspendPostsAccessApprovalsRequest(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotRequest graphactions.AccessApprovalsUserActionRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		writeAction(t, w, graphactions.AccessApprovalsUserAction{
			ID:             "act-1",
			Action:         graphactions.AccessApprovalsActionSuspend,
			Status:         "pending",
			Target:         gotRequest.EmailOrUserID,
			IdempotencyKey: gotRequest.IdempotencyKey,
			CreatedAtUnix:  time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC).Unix(),
		})
	}))
	defer server.Close()

	client, err := New(config.AccessApprovalsActionConfig{
		BaseURL:     server.URL + "/root/",
		BearerToken: "token-1",
		Timeout:     time.Second,
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	action, err := client.SuspendOktaUser(context.Background(), graphactions.AccessApprovalsUserActionRequest{
		EmailOrUserID:  "alice@writer.com",
		Reason:         "contain incident",
		Source:         graphactions.Source,
		TicketURL:      "https://tickets.example.com/SEC-1",
		IdempotencyKey: "idem-1",
	})
	if err != nil {
		t.Fatalf("Suspend() error = %v", err)
	}
	if gotPath != "/root/admin/okta-jail/suspend" {
		t.Fatalf("path = %q, want access-approvals suspend path under base", gotPath)
	}
	if gotAuth != "Bearer token-1" {
		t.Fatalf("Authorization = %q, want bearer token", gotAuth)
	}
	if gotRequest.EmailOrUserID != "alice@writer.com" || gotRequest.Source != graphactions.Source || gotRequest.IdempotencyKey != "idem-1" {
		t.Fatalf("request = %#v", gotRequest)
	}
	if action.ID != "act-1" || action.Target != "alice@writer.com" {
		t.Fatalf("action = %#v", action)
	}
	if got := client.ActionURL("act-1"); got != server.URL+"/root/admin/okta-jail/actions/act-1" {
		t.Fatalf("ActionURL() = %q", got)
	}
}

func TestClientUnsuspendUsesUnsuspendPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/okta-jail/unsuspend" {
			t.Fatalf("path = %q, want unsuspend path", r.URL.Path)
		}
		writeAction(t, w, graphactions.AccessApprovalsUserAction{ID: "act-2", Action: graphactions.AccessApprovalsActionUnsuspend, Status: "pending", Target: "00u1"})
	}))
	defer server.Close()

	client, err := New(config.AccessApprovalsActionConfig{BaseURL: server.URL, BearerToken: "token"}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	action, err := client.UnsuspendOktaUser(context.Background(), graphactions.AccessApprovalsUserActionRequest{EmailOrUserID: "00u1"})
	if err != nil {
		t.Fatalf("Unsuspend() error = %v", err)
	}
	if action.Action != graphactions.AccessApprovalsActionUnsuspend {
		t.Fatalf("action = %q, want unsuspend", action.Action)
	}
}

func TestClientConfigurationAndRemoteErrors(t *testing.T) {
	if _, err := New(config.AccessApprovalsActionConfig{}); !errors.Is(err, graphactions.ErrNotConfigured) {
		t.Fatalf("New(empty) error = %v, want ErrNotConfigured", err)
	}
	if _, err := New(config.AccessApprovalsActionConfig{BaseURL: ":", BearerToken: "token"}); !errors.Is(err, graphactions.ErrInvalidRequest) {
		t.Fatalf("New(invalid URL) error = %v, want ErrInvalidRequest", err)
	}
	if _, err := New(config.AccessApprovalsActionConfig{BaseURL: "http://access-approvals.example.com", BearerToken: "token"}); !errors.Is(err, graphactions.ErrInvalidRequest) {
		t.Fatalf("New(plaintext non-loopback URL) error = %v, want ErrInvalidRequest", err)
	}
	if _, err := New(config.AccessApprovalsActionConfig{BaseURL: "https://approvals.example.com", BearerToken: "token"}); err != nil {
		t.Fatalf("New(https URL) error = %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte(`{"error":"missing required scopes"}`)); err != nil {
			t.Fatalf("write response: %v", err)
		}
	}))
	defer server.Close()
	client, err := New(config.AccessApprovalsActionConfig{BaseURL: server.URL, BearerToken: "token"}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = client.SuspendOktaUser(context.Background(), graphactions.AccessApprovalsUserActionRequest{EmailOrUserID: "alice@writer.com"})
	if !errors.Is(err, graphactions.ErrRemote) {
		t.Fatalf("Suspend() error = %v, want ErrRemote", err)
	}
}

func TestClientLimitsSuccessResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"id":"` + strings.Repeat("a", int(defaultMaxSuccessBodyBytes)+1) + `","action":"suspend"}`)); err != nil {
			t.Fatalf("write oversized response: %v", err)
		}
	}))
	defer server.Close()
	client, err := New(config.AccessApprovalsActionConfig{BaseURL: server.URL, BearerToken: "token"}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = client.SuspendOktaUser(context.Background(), graphactions.AccessApprovalsUserActionRequest{EmailOrUserID: "alice@writer.com"})
	if !errors.Is(err, graphactions.ErrRemote) {
		t.Fatalf("Suspend() error = %v, want ErrRemote", err)
	}
}

func writeAction(t *testing.T, w http.ResponseWriter, action graphactions.AccessApprovalsUserAction) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(action); err != nil {
		t.Fatalf("encode action: %v", err)
	}
}
