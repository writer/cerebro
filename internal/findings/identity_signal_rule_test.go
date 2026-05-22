package findings

import (
	"context"
	"slices"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestIdentitySignalRulesEmitJoinBackedFindings(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "google-workspace-runtime", SourceId: "google_workspace", TenantId: "example"}
	event := &cerebrov1.EventEnvelope{
		Id:       "google-role-assignment-1",
		TenantId: "example",
		SourceId: "google_workspace",
		Kind:     "google_workspace.role_assignment",
		Attributes: map[string]string{
			"domain":       "example.com",
			"role_id":      "super-admin",
			"subject_id":   "1001",
			"subject_type": "user",
		},
	}
	records, err := rules[identityAdminPrivilegeGrantedRuleID].Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:example:google_workspace_user:1001")
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:example:google_workspace_admin_role:super-admin")
	if got := records[0].Attributes["primary_actor_urn"]; got != "urn:cerebro:example:google_workspace_user:1001" {
		t.Fatalf("primary_actor_urn = %q, want google workspace user", got)
	}
}

func TestIdentitySignalRulesJoinExternalGroupMemberToIdentifier(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "okta-runtime", SourceId: "okta", TenantId: "example"}
	event := &cerebrov1.EventEnvelope{
		Id:       "okta-group-member-external",
		TenantId: "example",
		SourceId: "okta",
		Kind:     "okta.group_membership",
		Attributes: map[string]string{
			"domain":         "writer.okta.com",
			"group_id":       "grp-security",
			"member_email":   "external@gmail.com",
			"member_user_id": "00u-external",
			"member_type":    "user",
		},
	}
	records, err := rules[identityExternalGroupMemberRuleID].Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:example:okta_user:00u-external")
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:example:okta_group:grp-security")
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:example:identifier:email:external@gmail.com")
}

func TestIdentitySignalRulesDetectPrivilegedNoMFAUser(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "google-workspace-runtime", SourceId: "google_workspace", TenantId: "example"}
	event := &cerebrov1.EventEnvelope{
		Id:       "google-user-admin-no-mfa",
		TenantId: "example",
		SourceId: "google_workspace",
		Kind:     "google_workspace.user",
		Attributes: map[string]string{
			"domain":        "example.com",
			"email":         "admin@example.com",
			"is_admin":      "true",
			"mfa_enrolled":  "false",
			"primary_email": "admin@example.com",
			"user_id":       "1001",
		},
	}
	records, err := rules[identityPrivilegedAccountWithoutMFARuleID].Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:example:google_workspace_user:1001")
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:example:identifier:email:admin@example.com")

	unknownMFA := &cerebrov1.EventEnvelope{
		Id:       "google-user-admin-unknown-mfa",
		TenantId: "example",
		SourceId: "google_workspace",
		Kind:     "google_workspace.user",
		Attributes: map[string]string{
			"domain":        "example.com",
			"email":         "admin@example.com",
			"is_admin":      "true",
			"primary_email": "admin@example.com",
			"user_id":       "1001",
		},
	}
	records, err = rules[identityPrivilegedAccountWithoutMFARuleID].Evaluate(context.Background(), runtime, unknownMFA)
	if err != nil {
		t.Fatalf("Evaluate(unknownMFA) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(unknownMFA records) = %d, want 0", len(records))
	}

	withMFA := &cerebrov1.EventEnvelope{
		Id:       "google-user-admin-with-mfa",
		TenantId: "example",
		SourceId: "google_workspace",
		Kind:     "google_workspace.user",
		Attributes: map[string]string{
			"domain":        "example.com",
			"email":         "admin@example.com",
			"is_admin":      "true",
			"mfa_enrolled":  "true",
			"primary_email": "admin@example.com",
			"user_id":       "1001",
		},
	}
	records, err = rules[identityPrivilegedAccountWithoutMFARuleID].Evaluate(context.Background(), runtime, withMFA)
	if err != nil {
		t.Fatalf("Evaluate(withMFA) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(withMFA records) = %d, want 0", len(records))
	}
}

func TestIdentitySignalRulesDetectCloudRoleAssignments(t *testing.T) {
	rules := identityRulesByID(t)
	for _, tt := range []struct {
		name        string
		sourceID    string
		kind        string
		attributes  map[string]string
		resourceURN string
	}{
		{
			name:     "aws",
			sourceID: "aws",
			kind:     "aws.iam_role_assignment",
			attributes: map[string]string{
				"domain":        "123456789012",
				"role_id":       "AdministratorAccess",
				"role_name":     "AdministratorAccess",
				"subject_email": "admin@example.com",
				"subject_id":    "AIDAADMIN",
				"subject_type":  "user",
			},
			resourceURN: "urn:cerebro:example:aws_admin_role:AdministratorAccess",
		},
		{
			name:     "gcp",
			sourceID: "gcp",
			kind:     "gcp.iam_role_assignment",
			attributes: map[string]string{
				"domain":        "example-prod",
				"role_id":       "roles/owner",
				"role_name":     "roles/owner",
				"subject_email": "admin@example.com",
				"subject_id":    "admin@example.com",
				"subject_type":  "user",
			},
			resourceURN: "urn:cerebro:example:gcp_admin_role:roles/owner",
		},
		{
			name:     "azure",
			sourceID: "azure",
			kind:     "azure.directory_role_assignment",
			attributes: map[string]string{
				"domain":        "tenant-1",
				"role_id":       "global-admin",
				"role_name":     "Global Administrator",
				"subject_email": "admin@example.com",
				"subject_id":    "user-1",
				"subject_type":  "user",
			},
			resourceURN: "urn:cerebro:example:azure_admin_role:global-admin",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: tt.name + "-runtime", SourceId: tt.sourceID, TenantId: "example"}
			event := &cerebrov1.EventEnvelope{Id: tt.name + "-role-assignment", TenantId: "example", SourceId: tt.sourceID, Kind: tt.kind, Attributes: tt.attributes}
			records, err := rules[identityAdminPrivilegeGrantedRuleID].Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("len(records) = %d, want 1", len(records))
			}
			assertFindingResourceURN(t, records[0].ResourceURNs, tt.resourceURN)
			assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:example:identifier:email:admin@example.com")
		})
	}
}

func TestIdentitySignalRulesIgnoreReadOnlyCloudRoleAssignments(t *testing.T) {
	rules := identityRulesByID(t)
	for _, tt := range []struct {
		name       string
		sourceID   string
		kind       string
		attributes map[string]string
	}{
		{
			name:     "aws-readonly",
			sourceID: "aws",
			kind:     "aws.iam_role_assignment",
			attributes: map[string]string{
				"domain":        "123456789012",
				"is_admin":      "false",
				"role_id":       "ReadOnlyAccess",
				"role_name":     "ReadOnlyAccess",
				"subject_email": "analyst@example.com",
				"subject_id":    "analyst@example.com",
				"subject_type":  "user",
			},
		},
		{
			name:     "gcp-viewer",
			sourceID: "gcp",
			kind:     "gcp.iam_role_assignment",
			attributes: map[string]string{
				"domain":        "example-prod",
				"is_admin":      "false",
				"role_id":       "roles/viewer",
				"role_name":     "roles/viewer",
				"subject_email": "viewer@example.com",
				"subject_id":    "viewer@example.com",
				"subject_type":  "user",
			},
		},
		{
			name:     "azure-reader",
			sourceID: "azure",
			kind:     "azure.iam_role_assignment",
			attributes: map[string]string{
				"domain":        "tenant-1",
				"is_admin":      "false",
				"role_id":       "Reader",
				"role_name":     "Reader",
				"subject_email": "viewer@example.com",
				"subject_id":    "viewer@example.com",
				"subject_type":  "user",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: tt.name + "-runtime", SourceId: tt.sourceID, TenantId: "example"}
			event := &cerebrov1.EventEnvelope{Id: tt.name + "-role-assignment", TenantId: "example", SourceId: tt.sourceID, Kind: tt.kind, Attributes: tt.attributes}
			records, err := rules[identityAdminPrivilegeGrantedRuleID].Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("len(records) = %d, want 0", len(records))
			}
		})
	}
}

func TestIdentitySignalRulesDetectCloudCredentials(t *testing.T) {
	rules := identityRulesByID(t)
	for _, tt := range []struct {
		name        string
		sourceID    string
		kind        string
		attributes  map[string]string
		resourceURN string
	}{
		{
			name:     "aws-access-key",
			sourceID: "aws",
			kind:     "aws.access_key",
			attributes: map[string]string{
				"credential_id":   "AKIAEXAMPLE",
				"credential_type": "aws_access_key",
				"domain":          "123456789012",
				"subject_email":   "admin@example.com",
				"subject_id":      "admin@example.com",
				"subject_type":    "user",
			},
			resourceURN: "urn:cerebro:example:aws_credential:AKIAEXAMPLE",
		},
		{
			name:     "gcp-service-account-key",
			sourceID: "gcp",
			kind:     "gcp.service_account_key",
			attributes: map[string]string{
				"credential_id":   "projects/example-prod/serviceAccounts/sa@example-prod.iam.gserviceaccount.com/keys/key-1",
				"credential_type": "gcp_service_account_key",
				"domain":          "example-prod",
				"subject_email":   "sa@example-prod.iam.gserviceaccount.com",
				"subject_id":      "sa@example-prod.iam.gserviceaccount.com",
				"subject_type":    "service_account",
			},
			resourceURN: "urn:cerebro:example:gcp_credential:projects/example-prod/serviceAccounts/sa@example-prod.iam.gserviceaccount.com/keys/key-1",
		},
		{
			name:     "azure-application-password",
			sourceID: "azure",
			kind:     "azure.credential",
			attributes: map[string]string{
				"credential_id":   "app-password-1",
				"credential_type": "azure_application_password",
				"domain":          "tenant-1",
				"subject_id":      "app-client-1",
				"subject_type":    "application",
			},
			resourceURN: "urn:cerebro:example:azure_credential:app-password-1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: tt.name + "-runtime", SourceId: tt.sourceID, TenantId: "example"}
			event := &cerebrov1.EventEnvelope{Id: tt.name, TenantId: "example", SourceId: tt.sourceID, Kind: tt.kind, Attributes: tt.attributes}
			records, err := rules[identityAPIOrOAuthCredentialCreatedRuleID].Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("len(records) = %d, want 1", len(records))
			}
			assertFindingResourceURN(t, records[0].ResourceURNs, tt.resourceURN)
		})
	}
}

func TestIdentitySignalRulesIgnoreInactiveCloudCredentials(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "aws-runtime", SourceId: "aws", TenantId: "example"}
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-access-key-disabled",
		TenantId: "example",
		SourceId: "aws",
		Kind:     "aws.access_key",
		Attributes: map[string]string{
			"credential_id":   "AKIAEXAMPLE",
			"credential_type": "aws_access_key",
			"domain":          "123456789012",
			"status":          "DISABLED",
			"subject_id":      "admin@example.com",
			"subject_type":    "user",
		},
	}
	records, err := rules[identityAPIOrOAuthCredentialCreatedRuleID].Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(disabled) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(disabled records) = %d, want 0", len(records))
	}

	event.Attributes["status"] = "ACTIVE"
	records, err = rules[identityAPIOrOAuthCredentialCreatedRuleID].Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(active) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(active records) = %d, want 1", len(records))
	}
}

func TestIdentitySignalRulesRespectRuntimeFamily(t *testing.T) {
	rules := identityRulesByID(t)
	rule := rules[identityPrivilegedAccountWithoutMFARuleID]
	if !rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "aws", Config: map[string]string{"family": "iam_user"}}) {
		t.Fatal("SupportsRuntime(iam_user) = false, want true")
	}
	if rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "aws", Config: map[string]string{"family": "public_endpoint"}}) {
		t.Fatal("SupportsRuntime(public_endpoint) = true, want false")
	}
	if rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "aws"}) {
		t.Fatal("SupportsRuntime(default cloudtrail) = true, want false for user rule")
	}
	if !rules[identityControlTamperCredentialChangeRuleID].SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "aws"}) {
		t.Fatal("SupportsRuntime(default cloudtrail) = false, want true for audit rule")
	}
	if !rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "aws", Config: map[string]string{"family": "env:CEREBRO_SOURCE_AWS_FAMILY"}}) {
		t.Fatal("SupportsRuntime(env-backed family) = false, want true until runtime config is resolved")
	}
}

func TestIdentitySignalRulesTreatRoutineOAuthGrantsAsTelemetry(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "example-okta-audit", SourceId: "okta", TenantId: "example"}
	for _, ruleID := range []string{
		identityAPIOrOAuthCredentialCreatedRuleID,
		identityControlTamperCredentialChangeRuleID,
	} {
		t.Run(ruleID, func(t *testing.T) {
			for _, action := range []string{
				"app.oauth2.authorize.code",
				"app.oauth2.as.authorize.code",
				"app.oauth2.token.grant.access_token",
				"app.oauth2.as.token.grant.id_token",
			} {
				event := &cerebrov1.EventEnvelope{
					Id:       strings.ReplaceAll(action, ".", "-"),
					TenantId: "example",
					SourceId: "okta",
					Kind:     "okta.audit",
					Attributes: map[string]string{
						"domain":               "writer.okta.com",
						"event_type":           action,
						"actor_id":             "0oa-client",
						"actor_type":           "PublicClientApp",
						"resource_id":          "00u-user",
						"resource_type":        "User",
						"outcome_result":       "SUCCESS",
						"oauth_event_category": "runtime_grant",
					},
				}
				records, err := rules[ruleID].Evaluate(context.Background(), runtime, event)
				if err != nil {
					t.Fatalf("Evaluate(%s) error = %v", action, err)
				}
				if len(records) != 0 {
					t.Fatalf("Evaluate(%s) returned %d findings, want telemetry-only", action, len(records))
				}
			}
		})
	}
}

func TestIdentitySignalRulesIgnoreRoutineOktaAssignments(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "tenant-okta-audit", SourceId: "okta", TenantId: "tenant"}
	for _, action := range []string{
		"application.user_membership.add",
		"group.application_assignment.add",
		"application.provision.group_push.mapping.created",
	} {
		for _, ruleID := range []string{
			identityAPIOrOAuthCredentialCreatedRuleID,
			identityControlTamperCredentialChangeRuleID,
		} {
			t.Run(action+"/"+ruleID, func(t *testing.T) {
				event := &cerebrov1.EventEnvelope{
					Id:       strings.ReplaceAll(action, ".", "-") + "-" + ruleID,
					TenantId: "tenant",
					SourceId: "okta",
					Kind:     "okta.audit",
					Attributes: map[string]string{
						"domain":         "tenant.example",
						"event_type":     action,
						"actor":          "admin@tenant.example",
						"actor_id":       "00u-admin",
						"resource_id":    "0oa-app",
						"resource_type":  "AppInstance",
						"outcome_result": "SUCCESS",
					},
				}
				records, err := rules[ruleID].Evaluate(context.Background(), runtime, event)
				if err != nil {
					t.Fatalf("Evaluate() error = %v", err)
				}
				if len(records) != 0 {
					t.Fatalf("Evaluate(%s) returned %d findings, want routine assignment suppressed", action, len(records))
				}
			})
		}
	}

	passwordView := &cerebrov1.EventEnvelope{
		Id:       "application-user-membership-show-password",
		TenantId: "tenant",
		SourceId: "okta",
		Kind:     "okta.audit",
		Attributes: map[string]string{
			"domain":         "tenant.example",
			"event_type":     "application.user_membership.show_password",
			"actor":          "admin@tenant.example",
			"actor_id":       "00u-admin",
			"resource_id":    "0oa-app",
			"resource_type":  "AppInstance",
			"outcome_result": "SUCCESS",
		},
	}
	records, err := rules[identityControlTamperCredentialChangeRuleID].Evaluate(context.Background(), runtime, passwordView)
	if err != nil {
		t.Fatalf("Evaluate(passwordView) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(passwordView) returned %d findings, want password access finding", len(records))
	}
}

func TestIdentitySignalRulesStillDetectOAuthCredentialCreation(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "example-okta-audit", SourceId: "okta", TenantId: "example"}
	event := &cerebrov1.EventEnvelope{
		Id:       "okta-api-token-create",
		TenantId: "example",
		SourceId: "okta",
		Kind:     "okta.audit",
		Attributes: map[string]string{
			"domain":        "writer.okta.com",
			"event_type":    "system.api_token.create",
			"actor_id":      "00u-admin",
			"actor_type":    "User",
			"resource_id":   "token-1",
			"resource_type": "ApiToken",
		},
	}
	records, err := rules[identityAPIOrOAuthCredentialCreatedRuleID].Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
}

func TestIdentitySignalRulesIgnoreFailedSensitiveAuditEvents(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "example-okta-audit", SourceId: "okta", TenantId: "example"}
	for _, ruleID := range []string{
		identityMFAFactorResetOrDisabledRuleID,
		identityControlTamperCredentialChangeRuleID,
	} {
		t.Run(ruleID, func(t *testing.T) {
			event := &cerebrov1.EventEnvelope{
				Id:       "okta-failed-mfa-reset-" + ruleID,
				TenantId: "example",
				SourceId: "okta",
				Kind:     "okta.audit",
				Attributes: map[string]string{
					"domain":         "writer.okta.com",
					"event_type":     "user.mfa.factor.reset",
					"outcome_result": "FAILURE",
					"resource_id":    "00u-user",
					"resource_type":  "User",
				},
			}
			records, err := rules[ruleID].Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("len(records) = %d, want 0", len(records))
			}
		})
	}
}

func identityRulesByID(t *testing.T) map[string]Rule {
	t.Helper()
	rules := map[string]Rule{}
	for _, rule := range newIdentitySignalRules() {
		rules[rule.Spec().GetId()] = rule
	}
	return rules
}

func assertFindingResourceURN(t *testing.T, urns []string, expected string) {
	t.Helper()
	if !slices.Contains(urns, expected) {
		t.Fatalf("ResourceURNs missing %q: %v", expected, urns)
	}
}
