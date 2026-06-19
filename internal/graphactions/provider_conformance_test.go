package graphactions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/deviceauth"
)

func TestActionProvidersConformToAdapterContract(t *testing.T) {
	ctx := context.Background()
	accessClient := &conformanceAccessApprovalsClient{
		suspendAction: &AccessApprovalsUserAction{
			ID:              "approval-1",
			Action:          AccessApprovalsActionSuspend,
			Status:          "pending",
			Target:          "alice@writer.com",
			Reason:          "high-risk sign-in",
			Source:          Source,
			TicketURL:       "https://tickets.example.com/T-1",
			IdempotencyKey:  "idem-1",
			TenantID:        "tenant-a",
			FindingID:       "finding-1",
			FindingRuleID:   "rule-1",
			ResourceURN:     "urn:cerebro:tenant-a:okta_user:00u1",
			SubjectURN:      "urn:cerebro:tenant-a:identity:email:alice@writer.com",
			CreatedAtUnix:   1781798400,
			UpdatedAtUnix:   1781798401,
			CompletedAtUnix: 0,
		},
		getAction: &AccessApprovalsUserAction{
			ID:            "approval-1",
			Action:        AccessApprovalsActionSuspend,
			Status:        "succeeded",
			Target:        "alice@writer.com",
			TenantID:      "tenant-a",
			FindingID:     "finding-1",
			FindingRuleID: "rule-1",
			ResourceURN:   "urn:cerebro:tenant-a:okta_user:00u1",
			SubjectURN:    "urn:cerebro:tenant-a:identity:email:alice@writer.com",
			UpdatedAtUnix: 1781798500,
		},
		baseURL: "https://access-approvals.example.com/actions/",
	}
	deviceService := &conformanceCerebroDeviceService{devices: map[string]deviceauth.DeviceRecord{
		"dev-1": {
			DeviceID:     "dev-1",
			TenantID:     "tenant-a",
			Status:       "active",
			Hostname:     "laptop-1",
			HardwareUUID: "hardware-1",
			SerialNumber: "serial-1",
		},
	}}
	for _, tc := range []struct {
		name           string
		spec           ActionSpec
		request        ProviderActionRequest
		provider       ActionProvider
		externalID     string
		wantAction     string
		wantProvider   string
		wantTarget     string
		wantMetadata   map[string]string
		afterExecute   func(t *testing.T, action *GraphAction)
		afterReconcile func(t *testing.T, action *GraphAction)
	}{
		{
			name: "access approvals okta suspend",
			spec: ActionSpec{
				ID:             ActionIdentityOktaSuspendUser,
				Provider:       ProviderAccessApprovals,
				ProviderAction: AccessApprovalsActionSuspend,
				TargetKind:     TargetKindOktaUser,
			},
			request: ProviderActionRequest{
				Target:         "alice@writer.com",
				Reason:         "high-risk sign-in",
				Source:         Source,
				TicketURL:      "https://tickets.example.com/T-1",
				IdempotencyKey: "idem-1",
				TenantID:       "tenant-a",
				FindingID:      "finding-1",
				FindingRuleID:  "rule-1",
				ResourceURN:    "urn:cerebro:tenant-a:okta_user:00u1",
				SubjectURN:     "urn:cerebro:tenant-a:identity:email:alice@writer.com",
			},
			provider:     AccessApprovalsProvider{Client: accessClient},
			externalID:   "approval-1",
			wantAction:   ActionIdentityOktaSuspendUser,
			wantProvider: ProviderAccessApprovals,
			wantTarget:   "alice@writer.com",
			wantMetadata: map[string]string{
				"tenant_id":       "tenant-a",
				"finding_id":      "finding-1",
				"finding_rule_id": "rule-1",
				"resource_urn":    "urn:cerebro:tenant-a:okta_user:00u1",
				"subject_urn":     "urn:cerebro:tenant-a:identity:email:alice@writer.com",
			},
			afterExecute: func(t *testing.T, action *GraphAction) {
				t.Helper()
				if action.ExternalURL != "https://access-approvals.example.com/actions/approval-1" {
					t.Fatalf("external_url = %q, want access approvals action URL", action.ExternalURL)
				}
				if accessClient.request.EmailOrUserID != "alice@writer.com" ||
					accessClient.request.Reason != "high-risk sign-in" ||
					accessClient.request.Source != Source ||
					accessClient.request.TicketURL != "https://tickets.example.com/T-1" ||
					accessClient.request.IdempotencyKey != "idem-1" ||
					accessClient.request.TenantID != "tenant-a" ||
					accessClient.request.FindingID != "finding-1" ||
					accessClient.request.FindingRuleID != "rule-1" ||
					accessClient.request.ResourceURN != "urn:cerebro:tenant-a:okta_user:00u1" ||
					accessClient.request.SubjectURN != "urn:cerebro:tenant-a:identity:email:alice@writer.com" {
					t.Fatalf("access-approvals request = %#v, want provider request propagated", accessClient.request)
				}
			},
		},
		{
			name: "cerebro device revoke",
			spec: ActionSpec{
				ID:             ActionEndpointCerebroRevokeDevice,
				Provider:       ProviderCerebroDeviceAuth,
				ProviderAction: CerebroDeviceActionRevoke,
				TargetKind:     TargetKindCerebroDevice,
			},
			request: ProviderActionRequest{
				Target:         "dev-1",
				Reason:         "compromised endpoint",
				Source:         Source,
				IdempotencyKey: "idem-device-1",
				TenantID:       "tenant-a",
				FindingID:      "finding-device-1",
				FindingRuleID:  "rule-device-1",
				ResourceURN:    "urn:cerebro:tenant-a:cerebro_device:dev-1",
				SubjectURN:     "urn:cerebro:tenant-a:cerebro_device:dev-1",
			},
			provider: CerebroDeviceProvider{
				Service: deviceService,
				Now:     func() time.Time { return time.Date(2026, 6, 18, 16, 0, 0, 0, time.UTC) },
			},
			externalID:   CerebroDeviceExternalID("dev-1"),
			wantAction:   ActionEndpointCerebroRevokeDevice,
			wantProvider: ProviderCerebroDeviceAuth,
			wantTarget:   "dev-1",
			wantMetadata: map[string]string{
				"tenant_id":       "tenant-a",
				"finding_id":      "finding-device-1",
				"finding_rule_id": "rule-device-1",
				"resource_urn":    "urn:cerebro:tenant-a:cerebro_device:dev-1",
				"subject_urn":     "urn:cerebro:tenant-a:cerebro_device:dev-1",
				"hostname":        "laptop-1",
				"hardware_uuid":   "hardware-1",
				"serial_number":   "serial-1",
			},
			afterExecute: func(t *testing.T, action *GraphAction) {
				t.Helper()
				if action.Status != "succeeded" || action.ExternalStatus != "revoked" || action.CompletedAtUnix == 0 {
					t.Fatalf("execute action lifecycle = %#v, want completed revoke", action)
				}
			},
			afterReconcile: func(t *testing.T, action *GraphAction) {
				t.Helper()
				if action.Status != "succeeded" || action.ExternalStatus != "revoked" {
					t.Fatalf("reconcile action lifecycle = %#v, want succeeded revoked", action)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executed, err := tc.provider.ExecuteGraphAction(ctx, tc.spec, tc.request)
			if err != nil {
				t.Fatalf("ExecuteGraphAction() error = %v", err)
			}
			assertProviderGraphAction(t, executed, tc.wantAction, tc.wantProvider, tc.wantTarget, tc.externalID, tc.wantMetadata)
			if tc.afterExecute != nil {
				tc.afterExecute(t, executed)
			}

			reconciled, err := tc.provider.GetGraphAction(ctx, tc.externalID)
			if err != nil {
				t.Fatalf("GetGraphAction() error = %v", err)
			}
			assertProviderGraphAction(t, reconciled, tc.wantAction, tc.wantProvider, tc.wantTarget, tc.externalID, nil)
			if tc.afterReconcile != nil {
				tc.afterReconcile(t, reconciled)
			}
		})
	}
}

func TestAccessApprovalsProviderDispatchesCatalogActions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		spec        ActionSpec
		wantSuspend bool
	}{
		{
			name: "suspend",
			spec: ActionSpec{
				ID:             ActionIdentityOktaSuspendUser,
				Provider:       ProviderAccessApprovals,
				ProviderAction: AccessApprovalsActionSuspend,
			},
			wantSuspend: true,
		},
		{
			name: "unsuspend",
			spec: ActionSpec{
				ID:             ActionIdentityOktaUnsuspendUser,
				Provider:       ProviderAccessApprovals,
				ProviderAction: AccessApprovalsActionUnsuspend,
			},
			wantSuspend: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &conformanceAccessApprovalsClient{
				suspendAction:   &AccessApprovalsUserAction{ID: "suspend-1", Action: AccessApprovalsActionSuspend},
				unsuspendAction: &AccessApprovalsUserAction{ID: "unsuspend-1", Action: AccessApprovalsActionUnsuspend},
			}
			action, err := (AccessApprovalsProvider{Client: client}).ExecuteGraphAction(context.Background(), tc.spec, ProviderActionRequest{Target: "alice@writer.com"})
			if err != nil {
				t.Fatalf("ExecuteGraphAction() error = %v", err)
			}
			if client.suspendCalled != tc.wantSuspend || client.unsuspendCalled == tc.wantSuspend {
				t.Fatalf("dispatch suspend=%t unsuspend=%t, want suspend=%t", client.suspendCalled, client.unsuspendCalled, tc.wantSuspend)
			}
			if action.Action != tc.spec.ID {
				t.Fatalf("action id = %q, want %q", action.Action, tc.spec.ID)
			}
		})
	}
}

func TestActionProvidersRejectUnsupportedProviderAction(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider ActionProvider
		spec     ActionSpec
		request  ProviderActionRequest
	}{
		{
			name:     "access approvals",
			provider: AccessApprovalsProvider{Client: &conformanceAccessApprovalsClient{}},
			spec: ActionSpec{
				ID:             "identity.okta.disable_user",
				Provider:       ProviderAccessApprovals,
				ProviderAction: "disable",
			},
			request: ProviderActionRequest{Target: "alice@writer.com"},
		},
		{
			name: "cerebro device",
			provider: CerebroDeviceProvider{Service: &conformanceCerebroDeviceService{devices: map[string]deviceauth.DeviceRecord{
				"dev-1": {DeviceID: "dev-1", TenantID: "tenant-a", Status: "active"},
			}}},
			spec: ActionSpec{
				ID:             "endpoint.cerebro.wipe_device",
				Provider:       ProviderCerebroDeviceAuth,
				ProviderAction: "wipe",
			},
			request: ProviderActionRequest{Target: "dev-1", TenantID: "tenant-a"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.provider.ExecuteGraphAction(context.Background(), tc.spec, tc.request)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("ExecuteGraphAction() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func assertProviderGraphAction(t *testing.T, action *GraphAction, wantAction string, wantProvider string, wantTarget string, wantExternalID string, wantMetadata map[string]string) {
	t.Helper()
	if action == nil {
		t.Fatalf("provider returned nil action")
	}
	if action.Action != wantAction || action.Provider != wantProvider || action.Target != wantTarget || action.ExternalID != wantExternalID {
		t.Fatalf("provider action = %#v, want action=%q provider=%q target=%q external_id=%q", action, wantAction, wantProvider, wantTarget, wantExternalID)
	}
	if action.ID == "" {
		t.Fatalf("provider action missing id: %#v", action)
	}
	for key, want := range wantMetadata {
		if got := action.Metadata[key]; got != want {
			t.Fatalf("metadata[%q] = %q, want %q in %#v", key, got, want, action.Metadata)
		}
	}
}

type conformanceAccessApprovalsClient struct {
	suspendCalled   bool
	unsuspendCalled bool
	request         AccessApprovalsUserActionRequest
	suspendAction   *AccessApprovalsUserAction
	unsuspendAction *AccessApprovalsUserAction
	getAction       *AccessApprovalsUserAction
	baseURL         string
}

func (c *conformanceAccessApprovalsClient) SuspendOktaUser(_ context.Context, request AccessApprovalsUserActionRequest) (*AccessApprovalsUserAction, error) {
	c.suspendCalled = true
	c.request = request
	return c.suspendAction, nil
}

func (c *conformanceAccessApprovalsClient) UnsuspendOktaUser(_ context.Context, request AccessApprovalsUserActionRequest) (*AccessApprovalsUserAction, error) {
	c.unsuspendCalled = true
	c.request = request
	return c.unsuspendAction, nil
}

func (c *conformanceAccessApprovalsClient) GetOktaUserAction(context.Context, string) (*AccessApprovalsUserAction, error) {
	return c.getAction, nil
}

func (c *conformanceAccessApprovalsClient) ActionURL(id string) string {
	return c.baseURL + id
}

type conformanceCerebroDeviceService struct {
	devices map[string]deviceauth.DeviceRecord
}

func (s *conformanceCerebroDeviceService) LookupDevice(_ context.Context, deviceID string) (deviceauth.DeviceRecord, error) {
	device, ok := s.devices[deviceID]
	if !ok {
		return deviceauth.DeviceRecord{}, deviceauth.ErrDeviceNotFound
	}
	return device, nil
}

func (s *conformanceCerebroDeviceService) Revoke(_ context.Context, deviceID string, _ string) error {
	device, ok := s.devices[deviceID]
	if !ok {
		return deviceauth.ErrDeviceNotFound
	}
	device.Status = "revoked"
	device.RevokedAt = time.Date(2026, 6, 18, 16, 0, 0, 0, time.UTC)
	s.devices[deviceID] = device
	return nil
}
