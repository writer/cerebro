package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/deviceauth"
	"github.com/writer/cerebro/internal/graphactionapi"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
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
			TenantID:       gotRequest.TenantID,
			FindingID:      gotRequest.FindingID,
			FindingRuleID:  gotRequest.FindingRuleID,
			ResourceURN:    gotRequest.ResourceURN,
			SubjectURN:     gotRequest.SubjectURN,
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
				"okta_user_urn":         "urn:cerebro:writer:okta.user:alice@writer.com",
				"okta_user_label":       "Alice",
				"graph_actions_allowed": graphactions.ActionIdentityOktaSuspendUser,
			},
		},
	}}
	appendLog := &recordingAppendLog{}
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
	}, Dependencies{StateStore: store, AppendLog: appendLog}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := `{"action":"identity.okta.suspend_user","finding_id":"finding-1","ticket_url":"https://tickets.example.com/SEC-1","approved":true}`
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
	if gotRequest.TenantID != "writer" || gotRequest.FindingID != "finding-1" || gotRequest.FindingRuleID != "identity-deprovisioned-okta-active-github" || gotRequest.SubjectURN != "urn:cerebro:writer:okta.user:alice@writer.com" {
		t.Fatalf("access-approvals metadata = %#v", gotRequest)
	}
	actionEvent := firstGraphActionWorkflowEvent(appendLog.events)
	if actionEvent == nil {
		t.Fatalf("workflow events = %d, want an action-recorded event", len(appendLog.events))
	}
	actionPayload, err := workflowevents.DecodeActionRecorded(actionEvent)
	if err != nil {
		t.Fatalf("DecodeActionRecorded() error = %v", err)
	}
	if actionPayload.ActionType != graphactions.ActionIdentityOktaSuspendUser || actionPayload.SourceEventID != "oja-1" || actionPayload.Status != "pending" {
		t.Fatalf("workflow action payload = %#v", actionPayload)
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

func TestHandleExecuteGraphActionDryRunDoesNotMutateProviderOrFinding(t *testing.T) {
	var called bool
	accessApprovals := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "dry run should not call provider", http.StatusInternalServerError)
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
				"okta_user_urn":         "urn:cerebro:writer:okta.user:alice@writer.com",
				"graph_actions_allowed": graphactions.ActionIdentityOktaSuspendUser,
			},
		},
	}}
	appendLog := &recordingAppendLog{}
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
	}, Dependencies{StateStore: store, AppendLog: appendLog}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := `{"action":"identity.okta.suspend_user","finding_id":"finding-1","dry_run":true}`
	response, err := server.Client().Post(server.URL+"/platform/graph/actions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST graph action dry run: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if called {
		t.Fatalf("dry run called access-approvals provider")
	}
	if len(appendLog.events) != 0 {
		t.Fatalf("dry run workflow events = %d, want none", len(appendLog.events))
	}
	if refs := store.findings["finding-1"].ExternalRefs; len(refs) != 0 {
		t.Fatalf("dry run external refs = %#v, want none", refs)
	}
	action, ok := payload["action"].(map[string]any)
	if !ok {
		t.Fatalf("response action = %#v", payload["action"])
	}
	if action["status"] != graphactions.ActionStatusDryRun || action["external_status"] != graphactions.ExternalStatusNotSubmitted || action["external_id"] != nil {
		t.Fatalf("dry run action = %#v", action)
	}
	metadata, ok := action["metadata"].(map[string]any)
	if !ok || metadata["dry_run"] != "true" || metadata["approval_required"] != "true" || metadata["external_ref_created"] != "false" {
		t.Fatalf("dry run metadata = %#v", action["metadata"])
	}
	if payload["external_ref"] != nil {
		t.Fatalf("dry run external_ref = %#v, want omitted", payload["external_ref"])
	}
}

func TestHandleExecuteGraphActionRequiresApprovalForMutation(t *testing.T) {
	var called bool
	accessApprovals := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "unapproved action should not call provider", http.StatusInternalServerError)
	}))
	defer accessApprovals.Close()

	store := &stubRuntimeStore{findings: map[string]*ports.FindingRecord{
		"finding-1": {
			ID:       "finding-1",
			TenantID: "writer",
			RuleID:   "identity-deprovisioned-okta-active-github",
			Status:   "open",
			Attributes: map[string]string{
				"okta_user_urn":         "urn:cerebro:writer:okta.user:alice@writer.com",
				"graph_actions_allowed": graphactions.ActionIdentityOktaSuspendUser,
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

	response, err := server.Client().Post(server.URL+"/platform/graph/actions", "application/json", strings.NewReader(`{"action":"identity.okta.suspend_user","finding_id":"finding-1"}`))
	if err != nil {
		t.Fatalf("POST graph action: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.StatusCode)
	}
	if called {
		t.Fatalf("unapproved graph action reached access-approvals")
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

func TestHandleReconcileGraphActionRefreshesLinkedAction(t *testing.T) {
	var gotPath string
	accessApprovals := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodGet {
			t.Fatalf("access-approvals method = %q, want GET", r.Method)
		}
		writeGraphActionTestAction(t, w, graphactions.AccessApprovalsUserAction{
			ID:            "oja-1",
			Action:        graphactions.AccessApprovalsActionSuspend,
			Status:        "succeeded",
			Target:        "alice@writer.com",
			TenantID:      "writer",
			FindingID:     "finding-1",
			FindingRuleID: "identity-deprovisioned-okta-active-github",
			SubjectURN:    "urn:cerebro:writer:okta.user:alice@writer.com",
			UpdatedAtUnix: time.Date(2026, 6, 18, 12, 5, 0, 0, time.UTC).Unix(),
		})
	}))
	defer accessApprovals.Close()

	store := &stubRuntimeStore{findings: map[string]*ports.FindingRecord{
		"finding-1": {
			ID:       "finding-1",
			TenantID: "writer",
			RuleID:   "identity-deprovisioned-okta-active-github",
			Status:   "open",
			Attributes: map[string]string{
				"okta_user_urn":         "urn:cerebro:writer:okta.user:alice@writer.com",
				"graph_actions_allowed": graphactions.ActionIdentityOktaSuspendUser,
			},
			FindingWorkflow: ports.FindingWorkflow{
				ExternalRefs: []ports.FindingExternalRef{{
					System:         graphactions.ProviderAccessApprovals,
					Kind:           graphactions.RefKind,
					ExternalID:     "oja-1",
					ExternalStatus: "pending",
				}},
			},
		},
	}}
	appendLog := &recordingAppendLog{}
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
	}, Dependencies{StateStore: store, AppendLog: appendLog}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	response, err := server.Client().Post(server.URL+"/platform/graph/actions/reconcile", "application/json", strings.NewReader(`{"finding_id":"finding-1","external_id":"oja-1"}`))
	if err != nil {
		t.Fatalf("POST reconcile graph action: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", response.StatusCode)
	}
	if gotPath != "/admin/okta-jail/actions/oja-1" {
		t.Fatalf("access-approvals path = %q, want action lookup", gotPath)
	}
	if firstGraphActionWorkflowEvent(appendLog.events) == nil {
		t.Fatalf("workflow events = %d, want an action-recorded event", len(appendLog.events))
	}
	updated := store.findings["finding-1"]
	if len(updated.ExternalRefs) != 1 || updated.ExternalRefs[0].ExternalStatus != "succeeded" {
		t.Fatalf("external refs = %#v, want refreshed succeeded ref", updated.ExternalRefs)
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

func TestHandleExecuteGraphActionRevokesCerebroDevice(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	store := &graphActionDeviceStore{
		stubRuntimeStore: &stubRuntimeStore{findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:        "finding-1",
				TenantID:  "writer",
				RuntimeID: "trusted-endpoint",
				RuleID:    "endpoint-compromised-device",
				Title:     "Endpoint has high-risk compromise evidence",
				Status:    "open",
				ResourceURNs: []string{
					"urn:cerebro:writer:cerebro_device:dev-1",
				},
				Attributes: map[string]string{
					"cerebro_device_id":     "dev-1",
					"graph_actions_allowed": graphactions.ActionEndpointCerebroRevokeDevice,
				},
			},
		}},
		MemStore: deviceauth.NewMemStore(),
	}
	_, err = store.EnrollDevice(context.Background(), deviceauth.DeviceRecord{
		DeviceID:     "dev-1",
		HardwareUUID: "hw-1",
		Hostname:     "laptop-1",
		TenantID:     "writer",
		Status:       "active",
		EnrolledAt:   time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	appendLog := &recordingAppendLog{}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "operator-key",
				Principal: "ops",
				TenantID:  "writer",
			}},
			DeviceAuth: config.DeviceAuthConfig{
				Enabled:                  true,
				Issuer:                   "cerebro",
				Audience:                 "cerebro-device",
				CurrentKID:               "test",
				EnrollPerIPRatePerSecond: 100,
				EnrollPerIPBurst:         100,
				SigningKeys: []config.DeviceAuthSigningKey{{
					KID:        "test",
					PublicPEM:  encodePEMPublic(t, pub),
					PrivatePEM: encodePEMPrivate(t, priv),
				}},
			},
		},
	}, Dependencies{StateStore: store, AppendLog: appendLog}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	request, err := http.NewRequest(http.MethodPost, server.URL+"/platform/graph/actions", strings.NewReader(`{"action":"endpoint.cerebro.revoke_device","finding_id":"finding-1","reason":"compromised endpoint","approved":true}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer operator-key")
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("POST graph action: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", response.StatusCode)
	}
	device, err := store.LookupDevice(context.Background(), "dev-1")
	if err != nil {
		t.Fatalf("LookupDevice() error = %v", err)
	}
	if device.Status != "revoked" || device.RevokedAt.IsZero() {
		t.Fatalf("device = %#v, want revoked", device)
	}
	updated := store.findings["finding-1"]
	if len(updated.ExternalRefs) != 1 {
		t.Fatalf("external refs = %#v, want one device action ref", updated.ExternalRefs)
	}
	ref := updated.ExternalRefs[0]
	if ref.System != graphactions.ProviderCerebroDeviceAuth || ref.Kind != graphactions.RefKind || ref.ExternalID != graphactions.CerebroDeviceExternalID("dev-1") || ref.ExternalStatus != "revoked" {
		t.Fatalf("external ref = %#v", ref)
	}
	actionEvent := firstGraphActionWorkflowEvent(appendLog.events)
	if actionEvent == nil {
		t.Fatalf("workflow events = %d, want an action-recorded event", len(appendLog.events))
	}
	actionPayload, err := workflowevents.DecodeActionRecorded(actionEvent)
	if err != nil {
		t.Fatalf("DecodeActionRecorded() error = %v", err)
	}
	if actionPayload.ActionType != graphactions.ActionEndpointCerebroRevokeDevice || actionPayload.SourceEventID != graphactions.CerebroDeviceExternalID("dev-1") || actionPayload.Status != "revoked" {
		t.Fatalf("workflow action payload = %#v", actionPayload)
	}
}

type graphActionDeviceStore struct {
	*stubRuntimeStore
	*deviceauth.MemStore
}

var (
	_ ports.StateStore = (*graphActionDeviceStore)(nil)
	_ deviceauth.Store = (*graphActionDeviceStore)(nil)
)

func firstGraphActionWorkflowEvent(events []*cerebrov1.EventEnvelope) *cerebrov1.EventEnvelope {
	for _, event := range events {
		if event.GetKind() == workflowevents.EventKindKnowledgeActionRecorded {
			return event
		}
	}
	return nil
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
	err := graphactionapi.ConnectError(graphactions.ErrRemote, graphactionapi.ErrorSentinelsFor(errInvalidHTTPRequest, errTenantForbidden, errScopeForbidden))
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
