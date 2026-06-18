package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphactionapi"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
)

func TestHandleExecuteGraphActionQueuesAccessApprovalsAction(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotRequest graphactions.AccessApprovalsUserActionRequest
	accessApprovals := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Fatalf("decode access-approvals request: %v", err)
		}
		writeGraphActionTestAction(t, w, graphactions.AccessApprovalsUserAction{
			ID:             "oja-1",
			Action:         graphactions.AccessApprovalsActionSuspend,
			Status:         "pending",
			Target:         gotRequest.EmailOrUserID,
			OktaUserID:     "00u1",
			OktaUserStatus: "ACTIVE",
			Reason:         gotRequest.Reason,
			Source:         gotRequest.Source,
			TicketURL:      gotRequest.TicketURL,
			IdempotencyKey: gotRequest.IdempotencyKey,
			CreatedAtUnix:  time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC).Unix(),
			UpdatedAtUnix:  time.Date(2026, 6, 18, 12, 1, 0, 0, time.UTC).Unix(),
		})
	}))
	defer accessApprovals.Close()

	store := &stubRuntimeStore{findings: map[string]*ports.FindingRecord{
		"finding-1": {
			ID:        "finding-1",
			TenantID:  "writer",
			RuntimeID: "writer-okta",
			RuleID:    "identity-deprovisioned-okta-active-github",
			Title:     "Deprovisioned Okta user still active in GitHub",
			Status:    "open",
			Attributes: map[string]string{
				"okta_user_urn":   "urn:cerebro:writer:okta.user:alice@writer.com",
				"okta_user_label": "Alice",
			},
		},
	}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		GraphActions: config.GraphActionsConfig{
			AccessApprovals: config.AccessApprovalsActionConfig{
				BaseURL:     accessApprovals.URL,
				BearerToken: "graph-action-token",
				Timeout:     time.Second,
			},
		},
	}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := `{"action":"identity.okta.suspend_user","finding_id":"finding-1","ticket_url":"https://tickets.example.com/SEC-1"}`
	request, err := http.NewRequest(http.MethodPost, server.URL+"/platform/graph/actions", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("POST graph action: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", response.StatusCode)
	}
	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if gotPath != "/admin/okta-jail/suspend" {
		t.Fatalf("access-approvals path = %q, want suspend path", gotPath)
	}
	if gotAuth != "Bearer graph-action-token" {
		t.Fatalf("Authorization = %q, want bearer token", gotAuth)
	}
	if gotRequest.EmailOrUserID != "alice@writer.com" {
		t.Fatalf("email_or_user_id = %q, want derived Okta email", gotRequest.EmailOrUserID)
	}
	if gotRequest.Source != graphactions.Source {
		t.Fatalf("source = %q, want %q", gotRequest.Source, graphactions.Source)
	}
	if !strings.HasPrefix(gotRequest.IdempotencyKey, "cerebro:graph-action:identity.okta.suspend_user:") {
		t.Fatalf("idempotency_key = %q, want stable graph action key", gotRequest.IdempotencyKey)
	}
	updated := store.findings["finding-1"]
	if len(updated.ExternalRefs) != 1 {
		t.Fatalf("external refs = %#v, want one access-approvals ref", updated.ExternalRefs)
	}
	ref := updated.ExternalRefs[0]
	if ref.System != graphactions.ProviderAccessApprovals || ref.Kind != graphactions.RefKind || ref.ExternalID != "oja-1" || ref.ExternalStatus != "pending" {
		t.Fatalf("external ref = %#v", ref)
	}
	action, ok := payload["action"].(map[string]any)
	if !ok || action["id"] != "oja-1" || action["action"] != graphactions.ActionIdentityOktaSuspendUser || action["provider"] != graphactions.ProviderAccessApprovals {
		t.Fatalf("response action = %#v", payload["action"])
	}
}

func TestHandleExecuteGraphActionRejectsTargetOnlyUnsuspend(t *testing.T) {
	var called bool
	accessApprovals := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "unexpected action dispatch", http.StatusInternalServerError)
	}))
	defer accessApprovals.Close()

	store := &stubRuntimeStore{findings: map[string]*ports.FindingRecord{}}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		GraphActions: config.GraphActionsConfig{
			AccessApprovals: config.AccessApprovalsActionConfig{
				BaseURL:     accessApprovals.URL,
				BearerToken: "graph-action-token",
				Timeout:     time.Second,
			},
		},
	}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := `{"action":"identity.okta.unsuspend_user","target":"00u123","idempotency_key":"manual-unsuspend-1"}`
	response, err := server.Client().Post(server.URL+"/platform/graph/actions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST graph action: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.StatusCode)
	}
	if called {
		t.Fatalf("target-only request reached access-approvals")
	}
}

func TestGraphActionTargetForFindingAllowsMatchingExplicitTarget(t *testing.T) {
	finding := &ports.FindingRecord{
		TenantID: "writer",
		Attributes: map[string]string{
			"okta_user_urn": "urn:cerebro:writer:okta.user:alice@writer.com",
		},
	}
	target, err := graphactions.OktaUserTargetForFinding(finding, "Alice Example <alice@writer.com>")
	if err != nil {
		t.Fatalf("OktaUserTargetForFinding() error = %v", err)
	}
	if target != "alice@writer.com" {
		t.Fatalf("target = %q, want normalized explicit target", target)
	}
}

func TestGraphActionNotConfiguredReturnsServiceUnavailable(t *testing.T) {
	store := &stubRuntimeStore{findings: map[string]*ports.FindingRecord{
		"finding-1": {
			ID: "finding-1",
			Attributes: map[string]string{
				"okta_user_urn": "urn:cerebro:writer:okta.user:alice@writer.com",
			},
		},
	}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	response, err := server.Client().Post(server.URL+"/platform/graph/actions", "application/json", strings.NewReader(`{"action":"identity.okta.suspend_user","finding_id":"finding-1"}`))
	if err != nil {
		t.Fatalf("POST graph action: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.StatusCode)
	}
}

func TestGraphActionConnectErrorMapsRemoteToUnavailable(t *testing.T) {
	err := graphactionapi.ConnectError(graphactions.ErrRemote, graphActionErrors)
	if !errors.Is(err, graphactions.ErrRemote) && err == nil {
		t.Fatalf("graphActionConnectError() = %v, want connect error", err)
	}
}

func writeGraphActionTestAction(t *testing.T, w http.ResponseWriter, action graphactions.AccessApprovalsUserAction) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(action); err != nil {
		t.Fatalf("encode action: %v", err)
	}
}
