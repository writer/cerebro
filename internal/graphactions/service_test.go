package graphactions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/deviceauth"
	"github.com/writer/cerebro/internal/ports"
)

func TestNormalizeTargetExtractsDisplayNameEmailAddress(t *testing.T) {
	target, err := NormalizeTarget(`Alice Example <alice@writer.com>`)
	if err != nil {
		t.Fatalf("NormalizeTarget() error = %v", err)
	}
	if target != "alice@writer.com" {
		t.Fatalf("target = %q, want parsed mailbox", target)
	}
}

func TestNormalizeTargetRejectsDisplayNameWithoutEmail(t *testing.T) {
	_, err := NormalizeTarget("Alice Example")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("NormalizeTarget() error = %v, want ErrInvalidRequest", err)
	}
}

func TestServiceExecuteRequiresFindingID(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	_, err := (Service{Client: client}).Execute(context.Background(), Input{
		Action: ActionIdentityOktaUnsuspendUser,
		Target: "alice@writer.com",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if client.called {
		t.Fatalf("target-only request reached access-approvals client")
	}
}

func TestServiceExecuteRejectsFindingWithoutAllowedAction(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Status:     "open",
		Attributes: map[string]string{"okta_user_email": "alice@tenant-a.example"},
	}}
	_, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionIdentityOktaSuspendUser,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if client.called {
		t.Fatalf("policy-rejected action reached access-approvals client")
	}
}

func TestServiceExecuteRejectsReservedParameters(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Attributes: map[string]string{"okta_user_email": "alice@tenant-a.example"},
	})}
	_, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
		FindingID:  "finding-1",
		Action:     ActionIdentityOktaSuspendUser,
		Parameters: map[string]string{"dry_run": "false"},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if client.called {
		t.Fatalf("parameter-rejected action reached access-approvals client")
	}
}

func TestServiceExecuteDoesNotUseDisplayLabelAsTarget(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		Attributes: map[string]string{
			"okta_user_label": "Alice Example",
		},
	})}
	_, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionIdentityOktaSuspendUser,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if client.called {
		t.Fatalf("label-only target reached access-approvals client")
	}
}

func TestServiceExecuteRejectsExplicitTargetOutsideFinding(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Attributes: map[string]string{"okta_user_email": "alice@tenant-a.example"},
	})}
	_, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionIdentityOktaSuspendUser,
		Target:    "victim@tenant-b.example",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if client.called {
		t.Fatalf("cross-finding explicit target reached access-approvals client")
	}
}

func TestServiceExecuteRejectsExplicitTargetFromCrossTenantURN(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:           "finding-1",
		TenantID:     "tenant-a",
		ResourceURNs: []string{"urn:cerebro:tenant-b:okta_user:00uvictim"},
		Attributes: map[string]string{
			"identity_urns": "urn:cerebro:tenant-b:identity:email:victim@tenant-b.example",
		},
	})}
	for _, target := range []string{"00uvictim", "victim@tenant-b.example"} {
		_, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
			FindingID: "finding-1",
			Action:    ActionIdentityOktaSuspendUser,
			Target:    target,
		})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Execute(%q) error = %v, want ErrInvalidRequest", target, err)
		}
	}
	if client.called {
		t.Fatalf("cross-tenant URN-derived target reached access-approvals client")
	}
}

func TestServiceExecuteDerivesTargetFromOktaUserURN(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:           "finding-1",
		TenantID:     "tenant-a",
		Title:        "User needs action",
		ResourceURNs: []string{"urn:cerebro:tenant-a:okta_user:00u123"},
	})}
	result, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionIdentityOktaSuspendUser,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result == nil || result.Target != "00u123" {
		t.Fatalf("Execute() target = %#v, want Okta user id from URN", result)
	}
	if got := client.request.EmailOrUserID; got != "00u123" {
		t.Fatalf("access-approvals target = %q, want 00u123", got)
	}
	if client.request.TenantID != "tenant-a" || client.request.FindingID != "finding-1" || client.request.FindingRuleID != "rule-1" || client.request.ResourceURN != "urn:cerebro:tenant-a:okta_user:00u123" || client.request.SubjectURN != "urn:cerebro:tenant-a:okta_user:00u123" {
		t.Fatalf("access-approvals metadata = %#v", client.request)
	}
}

func TestServiceExecuteDerivesDelimitedOktaURNWithoutForwardingRawURN(t *testing.T) {
	for _, key := range []string{"okta_user_urn", "identity_urns"} {
		t.Run(key, func(t *testing.T) {
			client := &stubAccessApprovalsClient{}
			workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
				ID:       "finding-1",
				TenantID: "tenant-a",
				Title:    "User needs action",
				Attributes: map[string]string{
					key: "urn:cerebro:tenant-a:okta_user:00u123",
				},
			})}
			result, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
				FindingID: "finding-1",
				Action:    ActionIdentityOktaSuspendUser,
			})
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if result == nil || result.Target != "00u123" {
				t.Fatalf("Execute() target = %#v, want Okta user id from delimited URN", result)
			}
			if got := client.request.EmailOrUserID; got != "00u123" {
				t.Fatalf("access-approvals target = %q, want extracted Okta user id", got)
			}
		})
	}
}

func TestServiceExecuteAllowsExplicitTargetMatchingFinding(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Title:      "User needs action",
		Attributes: map[string]string{"okta_user_email": "alice@tenant-a.example"},
	})}
	result, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionIdentityOktaSuspendUser,
		Target:    "Alice <alice@tenant-a.example>",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result == nil || result.Target != "alice@tenant-a.example" {
		t.Fatalf("Execute() target = %#v, want normalized finding target", result)
	}
	if !client.called {
		t.Fatalf("matching explicit target did not reach access-approvals client")
	}
	if got := client.request.EmailOrUserID; got != "alice@tenant-a.example" {
		t.Fatalf("access-approvals target = %q, want normalized finding target", got)
	}
}

func TestDefaultRegistryComesFromGeneratedCatalogMetadata(t *testing.T) {
	specs := KnownActionSpecs()
	if len(specs) != 3 {
		t.Fatalf("KnownActionSpecs() len = %d, want 3", len(specs))
	}
	spec, err := DefaultRegistry().Lookup(ActionIdentityOktaSuspendUser)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if spec.Provider != ProviderAccessApprovals || spec.ProviderAction != AccessApprovalsActionSuspend || spec.TargetKind != TargetKindOktaUser {
		t.Fatalf("generated suspend spec = %#v, want access-approvals suspend Okta user", spec)
	}
	if spec.Effect != "deny_access" || !spec.Destructive || spec.ReversibleBy != ActionIdentityOktaUnsuspendUser {
		t.Fatalf("generated suspend metadata = %#v, want destructive deny_access with unsuspend reversal", spec)
	}
	deviceSpec, err := DefaultRegistry().Lookup(ActionEndpointCerebroRevokeDevice)
	if err != nil {
		t.Fatalf("Lookup(device) error = %v", err)
	}
	if deviceSpec.Provider != ProviderCerebroDeviceAuth || deviceSpec.ProviderAction != CerebroDeviceActionRevoke || deviceSpec.TargetKind != TargetKindCerebroDevice {
		t.Fatalf("generated device spec = %#v, want cerebro-device-auth revoke Cerebro device", deviceSpec)
	}
	if deviceSpec.Effect != "deny_device_access" || !deviceSpec.Destructive || deviceSpec.ReversibleBy != "" {
		t.Fatalf("generated device metadata = %#v, want destructive deny_device_access without reversal", deviceSpec)
	}
}

func TestTargetForActionSpecUsesProvidedSpec(t *testing.T) {
	target, err := TargetForActionSpec(ActionSpec{
		ID: "custom.unregistered",
		ResolveTarget: func(_ *ports.FindingRecord, explicit string) (string, error) {
			return "resolved:" + explicit, nil
		},
	}, &ports.FindingRecord{ID: "finding-1"}, "target-1")
	if err != nil {
		t.Fatalf("TargetForActionSpec() error = %v", err)
	}
	if target != "resolved:target-1" {
		t.Fatalf("target = %q, want resolved target", target)
	}
}

func TestCerebroDeviceTargetForFindingDerivesTenantScopedDevice(t *testing.T) {
	finding := &ports.FindingRecord{
		TenantID:     "tenant-a",
		ResourceURNs: []string{"urn:cerebro:tenant-a:cerebro_device:dev-1"},
		Attributes: map[string]string{
			"cerebro_device_id": "dev-1",
		},
	}
	target, err := CerebroDeviceTargetForFinding(finding, "")
	if err != nil {
		t.Fatalf("CerebroDeviceTargetForFinding() error = %v", err)
	}
	if target != "dev-1" {
		t.Fatalf("target = %q, want dev-1", target)
	}
	target, err = CerebroDeviceTargetForFinding(finding, "dev-1")
	if err != nil {
		t.Fatalf("CerebroDeviceTargetForFinding(explicit) error = %v", err)
	}
	if target != "dev-1" {
		t.Fatalf("explicit target = %q, want dev-1", target)
	}
}

func TestCerebroDeviceTargetForFindingRejectsCrossFindingTarget(t *testing.T) {
	finding := &ports.FindingRecord{
		TenantID:     "tenant-a",
		ResourceURNs: []string{"urn:cerebro:tenant-b:cerebro_device:dev-2"},
		Attributes: map[string]string{
			"cerebro_device_id": "dev-1",
		},
	}
	_, err := CerebroDeviceTargetForFinding(finding, "dev-2")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("CerebroDeviceTargetForFinding() error = %v, want ErrInvalidRequest", err)
	}
}

func TestServiceExecuteRevokesCerebroDeviceProvider(t *testing.T) {
	now := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)
	deviceService := &stubCerebroDeviceService{devices: map[string]deviceauth.DeviceRecord{
		"dev-1": {DeviceID: "dev-1", TenantID: "tenant-a", Status: "active", Hostname: "laptop-1"},
	}}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		Status:   "open",
		RuleID:   "rule-1",
		Attributes: map[string]string{
			"cerebro_device_id":     "dev-1",
			"graph_actions_allowed": ActionEndpointCerebroRevokeDevice,
		},
	}}
	result, err := (Service{
		Findings: workflow,
		Providers: map[string]ActionProvider{
			ProviderCerebroDeviceAuth: CerebroDeviceProvider{Service: deviceService, Now: func() time.Time { return now }},
		},
	}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionEndpointCerebroRevokeDevice,
		Reason:    "compromised device",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if deviceService.revokedDeviceID != "dev-1" || deviceService.revokeReason != "compromised device" {
		t.Fatalf("revoked device/reason = %q/%q, want dev-1/compromised device", deviceService.revokedDeviceID, deviceService.revokeReason)
	}
	if result == nil || result.Action == nil || result.Action.Provider != ProviderCerebroDeviceAuth || result.Action.ExternalStatus != "revoked" {
		t.Fatalf("Execute() result = %#v, want revoked Cerebro device action", result)
	}
	if result.Action.ExternalID != CerebroDeviceExternalID("dev-1") || workflow.ref.ExternalID != CerebroDeviceExternalID("dev-1") {
		t.Fatalf("external ids = result %q ref %q, want deterministic device action id", result.Action.ExternalID, workflow.ref.ExternalID)
	}
	if workflow.ref.System != ProviderCerebroDeviceAuth || workflow.ref.ExternalStatus != "revoked" {
		t.Fatalf("linked ref = %#v, want cerebro-device-auth revoked ref", workflow.ref)
	}
}

func TestServiceExecuteCerebroDeviceProviderRequiresFindingTenant(t *testing.T) {
	deviceService := &stubCerebroDeviceService{devices: map[string]deviceauth.DeviceRecord{
		"dev-1": {DeviceID: "dev-1", TenantID: "tenant-a", Status: "active"},
	}}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:     "finding-1",
		Status: "open",
		Attributes: map[string]string{
			"cerebro_device_id":     "dev-1",
			"graph_actions_allowed": ActionEndpointCerebroRevokeDevice,
		},
	}}
	_, err := (Service{
		Findings: workflow,
		Providers: map[string]ActionProvider{
			ProviderCerebroDeviceAuth: CerebroDeviceProvider{Service: deviceService},
		},
	}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionEndpointCerebroRevokeDevice,
		Reason:    "compromised device",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if deviceService.revokedDeviceID != "" {
		t.Fatalf("revoked device = %q, want no revoke without finding tenant", deviceService.revokedDeviceID)
	}
}

func TestServiceReconcileRefreshesCerebroDeviceStatus(t *testing.T) {
	deviceService := &stubCerebroDeviceService{devices: map[string]deviceauth.DeviceRecord{
		"dev-1": {DeviceID: "dev-1", TenantID: "tenant-a", Status: "revoked", RevokedAt: time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)},
	}}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		Status:   "open",
		RuleID:   "rule-1",
		FindingWorkflow: ports.FindingWorkflow{
			ExternalRefs: []ports.FindingExternalRef{{
				System:     ProviderCerebroDeviceAuth,
				Kind:       RefKind,
				ExternalID: CerebroDeviceExternalID("dev-1"),
			}},
		},
		Attributes: map[string]string{
			"cerebro_device_id":     "dev-1",
			"graph_actions_allowed": ActionEndpointCerebroRevokeDevice,
		},
	}}
	result, err := (Service{
		Findings: workflow,
		Providers: map[string]ActionProvider{
			ProviderCerebroDeviceAuth: CerebroDeviceProvider{Service: deviceService},
		},
	}).Reconcile(context.Background(), ReconcileInput{
		FindingID:  "finding-1",
		ExternalID: CerebroDeviceExternalID("dev-1"),
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result == nil || result.Action == nil || result.Action.Status != "succeeded" || result.Action.ExternalStatus != "revoked" {
		t.Fatalf("Reconcile() result = %#v, want succeeded revoked action", result)
	}
	if workflow.ref.System != ProviderCerebroDeviceAuth || workflow.ref.ExternalStatus != "revoked" {
		t.Fatalf("linked ref = %#v, want refreshed device ref", workflow.ref)
	}
}

func TestGraphActionFromCerebroDeviceCompletionTimestampTracksRevocation(t *testing.T) {
	pending := GraphActionFromCerebroDevice(
		ActionEndpointCerebroRevokeDevice,
		deviceauth.DeviceRecord{DeviceID: "dev-1", TenantID: "tenant-a", Status: "active"},
		ProviderActionRequest{},
		"needs_attention",
		"active",
		"device is not revoked",
	)
	if pending.CompletedAtUnix != 0 {
		t.Fatalf("pending CompletedAtUnix = %d, want 0", pending.CompletedAtUnix)
	}
	if pending.CreatedAtUnix == 0 || pending.UpdatedAtUnix == 0 {
		t.Fatalf("pending timestamps = created %d updated %d, want non-zero activity timestamps", pending.CreatedAtUnix, pending.UpdatedAtUnix)
	}

	revokedAt := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)
	completed := GraphActionFromCerebroDevice(
		ActionEndpointCerebroRevokeDevice,
		deviceauth.DeviceRecord{DeviceID: "dev-1", TenantID: "tenant-a", Status: "revoked", RevokedAt: revokedAt},
		ProviderActionRequest{},
		"succeeded",
		"revoked",
		"",
	)
	if completed.CompletedAtUnix != revokedAt.Unix() {
		t.Fatalf("completed CompletedAtUnix = %d, want %d", completed.CompletedAtUnix, revokedAt.Unix())
	}
}

func TestServiceExecuteUsesConfiguredActionProvider(t *testing.T) {
	const actionID = "identity.generic.lock_user"
	provider := &stubActionProvider{executeAction: &GraphAction{
		ID:             "provider-action-1",
		Action:         actionID,
		Provider:       "generic-idp",
		ExternalID:     "provider-action-1",
		ExternalStatus: "queued",
	}}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Status:     "open",
		RuleID:     "rule-1",
		Attributes: map[string]string{"graph_actions_allowed": actionID},
	}}
	result, err := (Service{
		Findings: workflow,
		Providers: map[string]ActionProvider{
			"generic-idp": provider,
		},
		Registry: Registry{actions: map[string]ActionSpec{
			actionID: {
				ID:               actionID,
				Provider:         "generic-idp",
				ProviderAction:   "lock",
				TargetKind:       "identity.generic.user",
				ResolveTarget:    fixedTarget("generic-user-1"),
				CheckEligibility: FindingAllowsAction,
			},
		}},
	}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    actionID,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if provider.request.Target != "generic-user-1" || provider.spec.ProviderAction != "lock" {
		t.Fatalf("provider request/spec = %#v %#v, want generic provider target and action", provider.request, provider.spec)
	}
	if result == nil || result.Action == nil || result.Action.Provider != "generic-idp" || result.Target != "generic-user-1" {
		t.Fatalf("Execute() result = %#v, want generic provider action", result)
	}
	if workflow.ref.System != "generic-idp" || workflow.ref.ExternalID != "provider-action-1" {
		t.Fatalf("linked ref = %#v, want generic provider graph action ref", workflow.ref)
	}
}

func TestServiceExecuteRejectsProviderActionWithoutExternalID(t *testing.T) {
	const actionID = "identity.generic.lock_user"
	provider := &stubActionProvider{executeAction: &GraphAction{
		Action:   actionID,
		Provider: "generic-idp",
		Target:   "generic-user-1",
	}}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Status:     "open",
		RuleID:     "rule-1",
		Attributes: map[string]string{"graph_actions_allowed": actionID},
	}}
	_, err := (Service{
		Findings: workflow,
		Providers: map[string]ActionProvider{
			"generic-idp": provider,
		},
		Registry: Registry{actions: map[string]ActionSpec{
			actionID: {
				ID:               actionID,
				Provider:         "generic-idp",
				ProviderAction:   "lock",
				TargetKind:       "identity.generic.user",
				ResolveTarget:    fixedTarget("generic-user-1"),
				CheckEligibility: FindingAllowsAction,
			},
		}},
	}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    actionID,
	})
	if !errors.Is(err, ErrRemote) {
		t.Fatalf("Execute() error = %v, want ErrRemote", err)
	}
	if workflow.ref.ExternalID != "" {
		t.Fatalf("linked ref = %#v, want no unmatchable provider ref", workflow.ref)
	}
}

func TestGraphActionFromAccessApprovalsFallsBackToResolvedTarget(t *testing.T) {
	action := GraphActionFromAccessApprovals(ActionIdentityOktaSuspendUser, &AccessApprovalsUserAction{ID: "action-1"}, "", "00u123")
	if action == nil || action.Target != "00u123" {
		t.Fatalf("GraphActionFromAccessApprovals() = %#v, want fallback target", action)
	}
}

func TestServiceReconcileUsesLinkedActionProvider(t *testing.T) {
	const actionID = "identity.generic.lock_user"
	provider := &stubActionProvider{getAction: &GraphAction{
		ID:             "provider-action-1",
		Action:         actionID,
		Provider:       "generic-idp",
		Target:         "generic-user-1",
		ExternalStatus: "succeeded",
	}}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		Status:   "open",
		RuleID:   "rule-1",
		FindingWorkflow: ports.FindingWorkflow{
			ExternalRefs: []ports.FindingExternalRef{{
				System:     "generic-idp",
				Kind:       RefKind,
				ExternalID: "provider-action-1",
			}},
		},
		Attributes: map[string]string{"graph_actions_allowed": actionID},
	}}
	result, err := (Service{
		Findings: workflow,
		Providers: map[string]ActionProvider{
			"generic-idp": provider,
		},
		Registry: Registry{actions: map[string]ActionSpec{
			actionID: {
				ID:               actionID,
				Provider:         "generic-idp",
				ProviderAction:   "lock",
				TargetKind:       "identity.generic.user",
				ResolveTarget:    echoExplicitTarget,
				CheckEligibility: FindingAllowsAction,
			},
		}},
	}).Reconcile(context.Background(), ReconcileInput{
		FindingID:  "finding-1",
		ExternalID: "provider-action-1",
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result == nil || result.Action == nil || result.Action.Provider != "generic-idp" || result.Action.ExternalStatus != "succeeded" {
		t.Fatalf("Reconcile() result = %#v, want generic provider action", result)
	}
	if workflow.ref.System != "generic-idp" || workflow.ref.ExternalStatus != "succeeded" {
		t.Fatalf("linked ref = %#v, want refreshed generic provider ref", workflow.ref)
	}
}

func TestServiceReconcileRejectsLinkedProviderMismatch(t *testing.T) {
	const actionID = "identity.generic.lock_user"
	provider := &stubActionProvider{getAction: &GraphAction{
		ID:         "provider-action-1",
		Action:     actionID,
		Provider:   "generic-idp",
		Target:     "generic-user-1",
		ExternalID: "provider-action-1",
	}}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		Status:   "open",
		RuleID:   "rule-1",
		FindingWorkflow: ports.FindingWorkflow{
			ExternalRefs: []ports.FindingExternalRef{{
				System:     "generic-idp",
				Kind:       RefKind,
				ExternalID: "provider-action-1",
			}},
		},
		Attributes: map[string]string{"graph_actions_allowed": actionID},
	}}
	_, err := (Service{
		Findings: workflow,
		Providers: map[string]ActionProvider{
			"generic-idp": provider,
		},
		Registry: Registry{actions: map[string]ActionSpec{
			actionID: {
				ID:               actionID,
				Provider:         "different-idp",
				ProviderAction:   "lock",
				TargetKind:       "identity.generic.user",
				ResolveTarget:    echoExplicitTarget,
				CheckEligibility: FindingAllowsAction,
			},
		}},
	}).Reconcile(context.Background(), ReconcileInput{
		FindingID:  "finding-1",
		ExternalID: "provider-action-1",
	})
	if !errors.Is(err, ErrRemote) {
		t.Fatalf("Reconcile() error = %v, want ErrRemote", err)
	}
	if workflow.ref.ExternalID != "" {
		t.Fatalf("reconcile linked ref despite provider mismatch: %#v", workflow.ref)
	}
}

func TestServiceReconcileRejectsProviderTenantMismatch(t *testing.T) {
	const actionID = "identity.generic.lock_user"
	provider := &stubActionProvider{getAction: &GraphAction{
		ID:         "provider-action-1",
		Action:     actionID,
		Provider:   "generic-idp",
		Target:     "generic-user-1",
		ExternalID: "provider-action-1",
		Metadata:   map[string]string{"tenant_id": "tenant-b"},
	}}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		Status:   "open",
		RuleID:   "rule-1",
		FindingWorkflow: ports.FindingWorkflow{
			ExternalRefs: []ports.FindingExternalRef{{
				System:     "generic-idp",
				Kind:       RefKind,
				ExternalID: "provider-action-1",
			}},
		},
		Attributes: map[string]string{"graph_actions_allowed": actionID},
	}}
	_, err := (Service{
		Findings: workflow,
		Providers: map[string]ActionProvider{
			"generic-idp": provider,
		},
		Registry: Registry{actions: map[string]ActionSpec{
			actionID: {
				ID:               actionID,
				Provider:         "generic-idp",
				ProviderAction:   "lock",
				TargetKind:       "identity.generic.user",
				ResolveTarget:    echoExplicitTarget,
				CheckEligibility: FindingAllowsAction,
			},
		}},
	}).Reconcile(context.Background(), ReconcileInput{
		FindingID:  "finding-1",
		ExternalID: "provider-action-1",
	})
	if !errors.Is(err, ErrRemote) {
		t.Fatalf("Reconcile() error = %v, want ErrRemote", err)
	}
	if workflow.ref.ExternalID != "" {
		t.Fatalf("reconcile linked ref despite provider tenant mismatch: %#v", workflow.ref)
	}
}

func TestServiceReconcileRefreshesLinkedExternalRef(t *testing.T) {
	client := &stubAccessApprovalsClient{
		getAction: &AccessApprovalsUserAction{
			ID:     "action-1",
			Action: AccessApprovalsActionSuspend,
			Status: "succeeded",
			Target: "00u123",
		},
	}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		FindingWorkflow: ports.FindingWorkflow{
			ExternalRefs: []ports.FindingExternalRef{{
				System:     ProviderAccessApprovals,
				Kind:       RefKind,
				ExternalID: "action-1",
			}},
		},
		Attributes: map[string]string{"okta_user_urn": "urn:cerebro:tenant-a:okta_user:00u123"},
	})}
	result, err := (Service{Findings: workflow, Client: client}).Reconcile(context.Background(), ReconcileInput{
		FindingID:  "finding-1",
		ExternalID: "action-1",
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result == nil || result.Action == nil || result.Action.ExternalStatus != "succeeded" {
		t.Fatalf("Reconcile() result = %#v, want succeeded action", result)
	}
	if workflow.ref.ExternalStatus != "succeeded" {
		t.Fatalf("linked ref = %#v, want refreshed status", workflow.ref)
	}
}

func TestServiceReconcileRejectsClosedFinding(t *testing.T) {
	client := &stubAccessApprovalsClient{
		getAction: &AccessApprovalsUserAction{
			ID:     "action-1",
			Action: AccessApprovalsActionSuspend,
			Status: "succeeded",
			Target: "00u123",
		},
	}
	finding := eligibleFinding(&ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		FindingWorkflow: ports.FindingWorkflow{
			ExternalRefs: []ports.FindingExternalRef{{
				System:     ProviderAccessApprovals,
				Kind:       RefKind,
				ExternalID: "action-1",
			}},
		},
		Attributes: map[string]string{"okta_user_urn": "urn:cerebro:tenant-a:okta_user:00u123"},
	})
	finding.Status = "resolved"
	workflow := &stubFindingWorkflow{finding: finding}
	_, err := (Service{Findings: workflow, Client: client}).Reconcile(context.Background(), ReconcileInput{
		FindingID:  "finding-1",
		ExternalID: "action-1",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Reconcile() error = %v, want ErrInvalidRequest", err)
	}
	if workflow.ref.ExternalID != "" {
		t.Fatalf("reconcile linked ref despite closed finding: %#v", workflow.ref)
	}
}

func TestServiceReconcileRejectsActionDisallowedByFindingPolicy(t *testing.T) {
	client := &stubAccessApprovalsClient{
		getAction: &AccessApprovalsUserAction{
			ID:     "action-1",
			Action: AccessApprovalsActionUnsuspend,
			Status: "succeeded",
			Target: "00u123",
		},
	}
	finding := eligibleFinding(&ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		FindingWorkflow: ports.FindingWorkflow{
			ExternalRefs: []ports.FindingExternalRef{{
				System:     ProviderAccessApprovals,
				Kind:       RefKind,
				ExternalID: "action-1",
			}},
		},
		Attributes: map[string]string{"okta_user_urn": "urn:cerebro:tenant-a:okta_user:00u123"},
	})
	finding.Attributes["graph_actions_allowed"] = ActionIdentityOktaSuspendUser
	workflow := &stubFindingWorkflow{finding: finding}
	_, err := (Service{Findings: workflow, Client: client}).Reconcile(context.Background(), ReconcileInput{
		FindingID:  "finding-1",
		ExternalID: "action-1",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Reconcile() error = %v, want ErrInvalidRequest", err)
	}
	if workflow.ref.ExternalID != "" {
		t.Fatalf("reconcile linked ref despite disallowed action: %#v", workflow.ref)
	}
}

func TestServiceReconcileRejectsProviderTargetOutsideFinding(t *testing.T) {
	client := &stubAccessApprovalsClient{
		getAction: &AccessApprovalsUserAction{
			ID:     "action-1",
			Action: AccessApprovalsActionSuspend,
			Status: "succeeded",
			Target: "00uvictim",
		},
	}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		FindingWorkflow: ports.FindingWorkflow{
			ExternalRefs: []ports.FindingExternalRef{{
				System:     ProviderAccessApprovals,
				Kind:       RefKind,
				ExternalID: "action-1",
			}},
		},
		Attributes: map[string]string{"okta_user_urn": "urn:cerebro:tenant-a:okta_user:00u123"},
	})}
	_, err := (Service{Findings: workflow, Client: client}).Reconcile(context.Background(), ReconcileInput{
		FindingID:  "finding-1",
		ExternalID: "action-1",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Reconcile() error = %v, want ErrInvalidRequest", err)
	}
	if workflow.ref.ExternalID != "" {
		t.Fatalf("reconcile linked ref despite target mismatch: %#v", workflow.ref)
	}
}

func eligibleFinding(finding *ports.FindingRecord) *ports.FindingRecord {
	if finding.Attributes == nil {
		finding.Attributes = map[string]string{}
	}
	finding.Status = "open"
	finding.RuleID = "rule-1"
	finding.Attributes["graph_actions_allowed"] = ActionIdentityOktaSuspendUser + "," + ActionIdentityOktaUnsuspendUser
	return finding
}

type stubFindingWorkflow struct {
	finding *ports.FindingRecord
	ref     ports.FindingExternalRef
}

func (s *stubFindingWorkflow) GetFinding(context.Context, string) (*ports.FindingRecord, error) {
	return s.finding, nil
}

func (s *stubFindingWorkflow) LinkFindingExternalRef(_ context.Context, _ string, ref ports.FindingExternalRef) (*ports.FindingRecord, error) {
	s.ref = ref
	return s.finding, nil
}

type stubAccessApprovalsClient struct {
	called    bool
	request   AccessApprovalsUserActionRequest
	getAction *AccessApprovalsUserAction
}

func (s *stubAccessApprovalsClient) SuspendOktaUser(_ context.Context, request AccessApprovalsUserActionRequest) (*AccessApprovalsUserAction, error) {
	s.called = true
	s.request = request
	return &AccessApprovalsUserAction{ID: "action-1"}, nil
}

func (s *stubAccessApprovalsClient) UnsuspendOktaUser(_ context.Context, request AccessApprovalsUserActionRequest) (*AccessApprovalsUserAction, error) {
	s.called = true
	s.request = request
	return &AccessApprovalsUserAction{ID: "action-1"}, nil
}

func (s *stubAccessApprovalsClient) GetOktaUserAction(context.Context, string) (*AccessApprovalsUserAction, error) {
	return s.getAction, nil
}

func (s *stubAccessApprovalsClient) ActionURL(string) string {
	return ""
}

type stubActionProvider struct {
	spec          ActionSpec
	request       ProviderActionRequest
	executeAction *GraphAction
	getAction     *GraphAction
}

func (s *stubActionProvider) ExecuteGraphAction(_ context.Context, spec ActionSpec, request ProviderActionRequest) (*GraphAction, error) {
	s.spec = spec
	s.request = request
	return s.executeAction, nil
}

func (s *stubActionProvider) GetGraphAction(context.Context, string) (*GraphAction, error) {
	return s.getAction, nil
}

type stubCerebroDeviceService struct {
	devices         map[string]deviceauth.DeviceRecord
	revokedDeviceID string
	revokeReason    string
}

func (s *stubCerebroDeviceService) LookupDevice(_ context.Context, deviceID string) (deviceauth.DeviceRecord, error) {
	device, ok := s.devices[deviceID]
	if !ok {
		return deviceauth.DeviceRecord{}, deviceauth.ErrDeviceNotFound
	}
	return device, nil
}

func (s *stubCerebroDeviceService) Revoke(_ context.Context, deviceID string, reason string) error {
	device, ok := s.devices[deviceID]
	if !ok {
		return deviceauth.ErrDeviceNotFound
	}
	s.revokedDeviceID = deviceID
	s.revokeReason = reason
	device.Status = "revoked"
	device.RevokedAt = time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)
	s.devices[deviceID] = device
	return nil
}

func fixedTarget(target string) TargetResolver {
	return func(*ports.FindingRecord, string) (string, error) {
		return target, nil
	}
}

func echoExplicitTarget(_ *ports.FindingRecord, explicit string) (string, error) {
	return explicit, nil
}
