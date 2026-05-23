package findings

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestIdentityAdminPrivilegeGranted(t *testing.T) {
	rules := identityRulesByID(t)
	rule := rules[identityAdminPrivilegeGrantedRuleID]
	assertIdentityDurableMetadata(t, rule, []string{"user", "role"})
	if _, ok := rule.(CounterEventRule); !ok {
		t.Fatal("identity-admin-privilege-granted does not implement CounterEventRule")
	}

	runtime := &cerebrov1.SourceRuntime{Id: "example-google-workspace-role-assignment", SourceId: "google_workspace", TenantId: "writer", Config: map[string]string{"family": "role_assignment"}}
	openAttrs := map[string]string{
		"domain":        "writer.com",
		"role_id":       "super-admin",
		"role_name":     "Super Admin",
		"subject_email": "admin@writer.com",
		"subject_id":    "1001",
		"subject_type":  "user",
	}
	first := identitySignalEventAt("google-admin-grant-first", "google_workspace", "google_workspace.role_assignment", openAttrs, identityTrajectoryBaseTime)
	second := identitySignalEventAt("google-admin-grant-second", "google_workspace", "google_workspace.role_assignment", openAttrs, identityTrajectoryBaseTime.Add(time.Minute))
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one finding", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != firstFinding.Fingerprint {
		t.Fatalf("fingerprint = %q, want stable %q for same (user, role)", got, firstFinding.Fingerprint)
	}
	if got := firstFinding.Attributes["user"]; got != "admin@writer.com" {
		t.Fatalf("attributes[user] = %q, want admin@writer.com", got)
	}
	if got := firstFinding.Attributes["role"]; got != "super-admin" {
		t.Fatalf("attributes[role] = %q, want super-admin", got)
	}

	revokedAttrs := cloneIdentitySignalAttributes(openAttrs)
	revokedAttrs["action"] = "admin.role.revoked"
	revokedAttrs["assignment_status"] = "removed"
	revoked := identitySignalEventAt("google-admin-grant-revoked", "google_workspace", "google_workspace.role_assignment", revokedAttrs, identityTrajectoryBaseTime.Add(2*time.Minute))
	records, err = rule.Evaluate(context.Background(), runtime, revoked)
	if err != nil {
		t.Fatalf("Evaluate(revoked) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(revoked) returned %d findings, want 0 after role revocation", len(records))
	}
	assertIdentityRuleRemediationTrajectory(t, rule, first, revoked, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	olderRevoked := identitySignalEventAt("google-admin-grant-revoked-before-open", "google_workspace", "google_workspace.role_assignment", revokedAttrs, identityTrajectoryBaseTime.Add(-time.Minute))
	assertIdentityRuleOlderCloseDoesNotResolveLaterOpen(t, rule, olderRevoked, first)
}

func TestIdentityAuthControlLifecycleTampering(t *testing.T) {
	rules := identityRulesByID(t)
	rule := rules[identityAuthControlLifecycleTamperingRuleID]
	authControlTTL := 7 * 24 * time.Hour
	assertIdentityTTLEvidenceMetadata(t, rule, []string{"idp_id", "policy_id"}, authControlTTL)
	if _, ok := rule.(CounterEventRule); ok {
		t.Fatal("identity-auth-control-lifecycle-tampering must not implement CounterEventRule; TTL expiry resolves it")
	}

	runtime := &cerebrov1.SourceRuntime{Id: "example-okta-audit", SourceId: "okta", TenantId: "writer"}
	policyAttrs := map[string]string{
		"domain":                "writer.okta.com",
		"event_type":            "policy.lifecycle.update",
		"actor_email":           "admin@writer.com",
		"policy_id":             "pol-sign-on",
		"resource_id":           "pol-sign-on",
		"resource_type":         "policy",
		"auth_control_weakened": "true",
		"outcome_result":        "SUCCESS",
	}
	first := identitySignalEventAt("okta-policy-weakened-first", "okta", "okta.audit", policyAttrs, identityTrajectoryBaseTime)
	second := identitySignalEventAt("okta-policy-weakened-second", "okta", "okta.audit", policyAttrs, identityTrajectoryBaseTime.Add(time.Minute))
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first policy) = (%v, %v), want one finding", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second policy) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != firstFinding.Fingerprint {
		t.Fatalf("policy fingerprint = %q, want stable %q", got, firstFinding.Fingerprint)
	}
	if got := firstFinding.Attributes["policy_id"]; got != "pol-sign-on" {
		t.Fatalf("attributes[policy_id] = %q, want pol-sign-on", got)
	}

	idpAttrs := map[string]string{
		"domain":                "writer.okta.com",
		"event_type":            "idp.lifecycle.update",
		"actor_email":           "admin@writer.com",
		"idp_id":                "idp-1",
		"resource_id":           "idp-1",
		"resource_type":         "idp",
		"auth_control_weakened": "true",
		"outcome_result":        "SUCCESS",
	}
	idpFirst := identitySignalEventAt("okta-idp-weakened-first", "okta", "okta.audit", idpAttrs, identityTrajectoryBaseTime)
	idpSecond := identitySignalEventAt("okta-idp-weakened-second", "okta", "okta.audit", idpAttrs, identityTrajectoryBaseTime.Add(time.Minute))
	records, err = rule.Evaluate(context.Background(), runtime, idpFirst)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first idp) = (%v, %v), want one finding", records, err)
	}
	idpFingerprint := records[0].Fingerprint
	if got := records[0].Attributes["idp_id"]; got != "idp-1" {
		t.Fatalf("attributes[idp_id] = %q, want idp-1", got)
	}
	records, err = rule.Evaluate(context.Background(), runtime, idpSecond)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second idp) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != idpFingerprint {
		t.Fatalf("idp fingerprint = %q, want stable %q", got, idpFingerprint)
	}

	restoredAttrs := cloneIdentitySignalAttributes(policyAttrs)
	restoredAttrs["event_type"] = "policy.lifecycle.restore"
	restoredAttrs["auth_control_weakened"] = "false"
	restoredAttrs["auth_control_strengthened"] = "true"
	restored := identitySignalEventAt("okta-policy-restored", "okta", "okta.audit", restoredAttrs, identityTrajectoryBaseTime.Add(2*time.Minute))
	records, err = rule.Evaluate(context.Background(), runtime, restored)
	if err != nil {
		t.Fatalf("Evaluate(restored) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(restored) returned %d findings, want 0 once auth control is strengthened", len(records))
	}
	assertIdentityRuleTTLEvidenceTrajectory(t, rule, runtime, first, authControlTTL)
}

func TestIdentityMfaFactorResetOrDisabled(t *testing.T) {
	rules := identityRulesByID(t)
	rule := rules[identityMFAFactorResetOrDisabledRuleID]
	assertIdentityDurableMetadata(t, rule, []string{"user"})
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("identity-mfa-factor-reset-or-disabled does not implement CounterEventRule")
	}

	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("identity-mfa-factor-reset-or-disabled does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	for _, kind := range []string{"okta.user", "google_workspace.user", "azure.user", "aws.iam_user", "gcp.service_account"} {
		if !slices.Contains(definition.EventKinds, kind) {
			t.Fatalf("EventKinds = %v, want projected identity user kind %q", definition.EventKinds, kind)
		}
	}
	for _, auditKind := range []string{"okta.audit", "google_workspace.audit", "azure.directory_audit", "azure.activity_log", "aws.cloudtrail", "gcp.audit"} {
		if slices.Contains(definition.EventKinds, auditKind) {
			t.Fatalf("EventKinds = %v, want no audit-event primary emit kind %q", definition.EventKinds, auditKind)
		}
	}

	cases := []struct {
		name       string
		sourceID   string
		kind       string
		family     string
		user       string
		attributes map[string]string
	}{
		{
			name:     "okta user",
			sourceID: "okta",
			kind:     "okta.user",
			family:   "user",
			user:     "admin@writer.com",
			attributes: map[string]string{
				"domain":        "writer.okta.com",
				"email":         "admin@writer.com",
				"is_admin":      "true",
				"login":         "admin@writer.com",
				"mfa_enrolled":  "false",
				"primary_email": "admin@writer.com",
				"user_id":       "00u-admin",
			},
		},
		{
			name:     "google workspace user",
			sourceID: "google_workspace",
			kind:     "google_workspace.user",
			family:   "user",
			user:     "admin@writer.com",
			attributes: map[string]string{
				"domain":        "writer.com",
				"email":         "admin@writer.com",
				"is_admin":      "true",
				"mfa_enrolled":  "false",
				"mfa_enforced":  "false",
				"primary_email": "admin@writer.com",
				"user_id":       "1001",
			},
		},
		{
			name:     "azure user",
			sourceID: "azure",
			kind:     "azure.user",
			family:   "user",
			user:     "admin@writer.com",
			attributes: map[string]string{
				"domain":         "tenant-1",
				"email":          "admin@writer.com",
				"is_admin":       "true",
				"mfa_enrolled":   "false",
				"principal_type": "user",
				"user_id":        "azure-user-1",
			},
		},
		{
			name:     "aws iam user",
			sourceID: "aws",
			kind:     "aws.iam_user",
			family:   "iam_user",
			user:     "admin@writer.com",
			attributes: map[string]string{
				"domain":       "123456789012",
				"email":        "admin@writer.com",
				"is_admin":     "true",
				"login":        "admin@writer.com",
				"mfa_enrolled": "false",
				"user_id":      "AIDAADMIN",
			},
		},
		{
			name:     "gcp service account",
			sourceID: "gcp",
			kind:     "gcp.service_account",
			family:   "service_account",
			user:     "sa@writer-prod.iam.gserviceaccount.com",
			attributes: map[string]string{
				"domain":         "writer-prod",
				"email":          "sa@writer-prod.iam.gserviceaccount.com",
				"is_admin":       "true",
				"mfa_enrolled":   "false",
				"principal_type": "service_account",
				"user_id":        "sa@writer-prod.iam.gserviceaccount.com",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: "example-" + tc.sourceID + "-" + tc.family, SourceId: tc.sourceID, TenantId: "writer", Config: map[string]string{"family": tc.family}}
			first := identitySignalEventAt(strings.ReplaceAll(tc.name, " ", "-")+"-mfa-disabled-first", tc.sourceID, tc.kind, tc.attributes, identityTrajectoryBaseTime)
			second := identitySignalEventAt(strings.ReplaceAll(tc.name, " ", "-")+"-mfa-disabled-second", tc.sourceID, tc.kind, tc.attributes, identityTrajectoryBaseTime.Add(time.Minute))
			records, err := rule.Evaluate(context.Background(), runtime, first)
			if err != nil || len(records) != 1 {
				t.Fatalf("Evaluate(first) = (%v, %v), want one finding", records, err)
			}
			firstFinding := records[0]
			records, err = rule.Evaluate(context.Background(), runtime, second)
			if err != nil || len(records) != 1 {
				t.Fatalf("Evaluate(second) = (%v, %v), want one finding", records, err)
			}
			if got := records[0].Fingerprint; got != firstFinding.Fingerprint {
				t.Fatalf("fingerprint = %q, want stable %q for same user", got, firstFinding.Fingerprint)
			}
			if got := firstFinding.Attributes["user"]; got != tc.user {
				t.Fatalf("attributes[user] = %q, want %q", got, tc.user)
			}
			openAnchor := counterRule.OpenAnchor(firstFinding.Attributes)
			if openAnchor == "" {
				t.Fatalf("OpenAnchor(%v) = empty, want user anchor", firstFinding.Attributes)
			}

			enrolledAttrs := cloneIdentitySignalAttributes(tc.attributes)
			enrolledAttrs["mfa_enrolled"] = "true"
			enrolled := identitySignalEventAt(strings.ReplaceAll(tc.name, " ", "-")+"-mfa-enabled", tc.sourceID, tc.kind, enrolledAttrs, identityTrajectoryBaseTime.Add(2*time.Minute))
			records, err = rule.Evaluate(context.Background(), runtime, enrolled)
			if err != nil {
				t.Fatalf("Evaluate(enrolled) error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("Evaluate(enrolled) returned %d findings, want 0 once MFA is enrolled", len(records))
			}
			closeAnchor, closes := counterRule.CloseOnEvent(enrolled)
			if !closes || closeAnchor != openAnchor {
				t.Fatalf("CloseOnEvent(enrolled) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
			}
			assertIdentityRuleRemediationTrajectory(t, rule, first, enrolled, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
			olderEnrolled := identitySignalEventAt(strings.ReplaceAll(tc.name, " ", "-")+"-mfa-enabled-before-open", tc.sourceID, tc.kind, enrolledAttrs, identityTrajectoryBaseTime.Add(-time.Minute))
			assertIdentityRuleOlderCloseDoesNotResolveLaterOpen(t, rule, olderEnrolled, first)
		})
	}

	unknownAttrs := cloneIdentitySignalAttributes(cases[0].attributes)
	unknownAttrs["mfa_enrolled"] = ""
	unknown := identitySignalEventAt("okta-user-mfa-unknown", "okta", "okta.user", unknownAttrs, identityTrajectoryBaseTime)
	records, err := rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "example-okta-user", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "user"}}, unknown)
	if err != nil {
		t.Fatalf("Evaluate(unknown MFA) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(unknown MFA) returned %d findings, want 0 for unknown MFA state", len(records))
	}

	auditAttrs := map[string]string{
		"domain":         "writer.okta.com",
		"event_type":     "user.mfa.factor.reset",
		"actor_email":    "admin@writer.com",
		"resource_id":    "00u-admin",
		"resource_type":  "User",
		"mfa_enrolled":   "false",
		"mfa_state":      "reset",
		"outcome_result": "SUCCESS",
	}
	audit := identitySignalEventAt("okta-mfa-reset-audit-ignored", "okta", "okta.audit", auditAttrs, identityTrajectoryBaseTime)
	records, err = rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "example-okta-audit", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "audit"}}, audit)
	if err != nil {
		t.Fatalf("Evaluate(audit) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(audit) returned %d findings, want 0 because audit events are not primary emit for this rule", len(records))
	}
}

func TestIdentityApiTokenOrOauthAppCreated(t *testing.T) {
	rules := identityRulesByID(t)
	rule := rules[identityAPIOrOAuthCredentialCreatedRuleID]
	assertIdentityDurableMetadata(t, rule, []string{"user", "credential_id", "org", "oauth_app_id"})
	if _, ok := rule.(CounterEventRule); !ok {
		t.Fatal("identity-api-token-or-oauth-app-created does not implement CounterEventRule")
	}

	tokenRuntime := &cerebrov1.SourceRuntime{Id: "example-aws-access-key", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "access_key"}}
	tokenAttrs := map[string]string{
		"credential_id":   "AKIAEXAMPLE",
		"credential_type": "aws_access_key",
		"domain":          "123456789012",
		"status":          "ACTIVE",
		"subject_email":   "dev@writer.com",
		"subject_id":      "AIDADEV",
		"subject_type":    "user",
	}
	tokenFirst := identitySignalEventAt("aws-access-key-created-first", "aws", "aws.access_key", tokenAttrs, identityTrajectoryBaseTime)
	tokenSecond := identitySignalEventAt("aws-access-key-created-second", "aws", "aws.access_key", tokenAttrs, identityTrajectoryBaseTime.Add(time.Minute))
	records, err := rule.Evaluate(context.Background(), tokenRuntime, tokenFirst)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(token first) = (%v, %v), want one finding", records, err)
	}
	tokenFinding := records[0]
	records, err = rule.Evaluate(context.Background(), tokenRuntime, tokenSecond)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(token second) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != tokenFinding.Fingerprint {
		t.Fatalf("token fingerprint = %q, want stable %q for same (user, credential_id)", got, tokenFinding.Fingerprint)
	}
	if got := tokenFinding.Attributes["user"]; got != "dev@writer.com" {
		t.Fatalf("token attributes[user] = %q, want dev@writer.com", got)
	}
	if got := tokenFinding.Attributes["credential_id"]; got != "AKIAEXAMPLE" {
		t.Fatalf("token attributes[credential_id] = %q, want AKIAEXAMPLE", got)
	}

	tokenRevokedAttrs := cloneIdentitySignalAttributes(tokenAttrs)
	tokenRevokedAttrs["action"] = "access_key.revoke"
	tokenRevokedAttrs["status"] = "REVOKED"
	tokenRevoked := identitySignalEventAt("aws-access-key-revoked", "aws", "aws.access_key", tokenRevokedAttrs, identityTrajectoryBaseTime.Add(2*time.Minute))
	records, err = rule.Evaluate(context.Background(), tokenRuntime, tokenRevoked)
	if err != nil {
		t.Fatalf("Evaluate(token revoked) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(token revoked) returned %d findings, want 0 after credential revoke", len(records))
	}
	assertIdentityRuleRemediationTrajectory(t, rule, tokenFirst, tokenRevoked, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	olderTokenRevoked := identitySignalEventAt("aws-access-key-revoked-before-open", "aws", "aws.access_key", tokenRevokedAttrs, identityTrajectoryBaseTime.Add(-time.Minute))
	assertIdentityRuleOlderCloseDoesNotResolveLaterOpen(t, rule, olderTokenRevoked, tokenFirst)
}

func TestIdentityApiTokenOrOauthAppCreated_OAuthTrajectory(t *testing.T) {
	rules := identityRulesByID(t)
	rule := rules[identityAPIOrOAuthCredentialCreatedRuleID]
	assertIdentityDurableMetadata(t, rule, []string{"user", "credential_id", "org", "oauth_app_id"})
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("identity-api-token-or-oauth-app-created does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if !slices.Contains(definition.EventKinds, "okta.application") {
		t.Fatalf("EventKinds = %v, want okta.application for projected OAuth app state", definition.EventKinds)
	}
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("identity-api-token-or-oauth-app-created does not implement CounterEventRule")
	}

	oauthRuntime := &cerebrov1.SourceRuntime{Id: "example-okta-application", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "application"}}
	oauthAttrs := map[string]string{
		"app_id":       "0oa-client",
		"app_name":     "Production Client",
		"domain":       "writer.okta.com",
		"oauth2":       "true",
		"sign_on_mode": "OPENID_CONNECT",
		"status":       "ACTIVE",
	}
	oauthFirst := identitySignalEventAt("okta-oauth-app-active-first", "okta", "okta.application", oauthAttrs, identityTrajectoryBaseTime)
	oauthSecondAttrs := cloneIdentitySignalAttributes(oauthAttrs)
	oauthSecondAttrs["app_name"] = "Production Client Renamed"
	oauthSecond := identitySignalEventAt("okta-oauth-app-active-second", "okta", "okta.application", oauthSecondAttrs, identityTrajectoryBaseTime.Add(time.Minute))
	records, err := rule.Evaluate(context.Background(), oauthRuntime, oauthFirst)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(oauth ACTIVE first) = (%v, %v), want one finding", records, err)
	}
	oauthFinding := records[0]
	records, err = rule.Evaluate(context.Background(), oauthRuntime, oauthSecond)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(oauth ACTIVE second) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != oauthFinding.Fingerprint {
		t.Fatalf("oauth fingerprint = %q, want stable %q for same (org, oauth_app_id)", got, oauthFinding.Fingerprint)
	}
	if got := oauthFinding.Attributes["org"]; got != "writer.okta.com" {
		t.Fatalf("oauth attributes[org] = %q, want writer.okta.com", got)
	}
	if got := oauthFinding.Attributes["oauth_app_id"]; got != "0oa-client" {
		t.Fatalf("oauth attributes[oauth_app_id] = %q, want 0oa-client", got)
	}
	if got := oauthFinding.Attributes["status"]; got != "ACTIVE" {
		t.Fatalf("oauth attributes[status] = %q, want ACTIVE", got)
	}
	if got := oauthFinding.Attributes["sign_on_mode"]; got != "OPENID_CONNECT" {
		t.Fatalf("oauth attributes[sign_on_mode] = %q, want OPENID_CONNECT", got)
	}
	assertFindingResourceURN(t, oauthFinding.ResourceURNs, "urn:cerebro:writer:okta_application:0oa-client")
	openAnchor := counterRule.OpenAnchor(oauthFinding.Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty, want org/oauth_app_id anchor", oauthFinding.Attributes)
	}

	inactiveAttrs := cloneIdentitySignalAttributes(oauthAttrs)
	inactiveAttrs["status"] = "INACTIVE"
	inactive := identitySignalEventAt("okta-oauth-app-inactive", "okta", "okta.application", inactiveAttrs, identityTrajectoryBaseTime.Add(2*time.Minute))
	records, err = rule.Evaluate(context.Background(), oauthRuntime, inactive)
	if err != nil {
		t.Fatalf("Evaluate(oauth INACTIVE) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(oauth INACTIVE) returned %d findings, want 0 after app inactive state", len(records))
	}
	closeAnchor, closes := counterRule.CloseOnEvent(inactive)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(INACTIVE) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}

	deletedAttrs := cloneIdentitySignalAttributes(oauthAttrs)
	deletedAttrs["status"] = "DELETED_PERMANENTLY"
	deleted := identitySignalEventAt("okta-oauth-app-deleted-permanently", "okta", "okta.application", deletedAttrs, identityTrajectoryBaseTime.Add(3*time.Minute))
	records, err = rule.Evaluate(context.Background(), oauthRuntime, deleted)
	if err != nil {
		t.Fatalf("Evaluate(oauth DELETED_PERMANENTLY) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(oauth DELETED_PERMANENTLY) returned %d findings, want 0 after app deleted state", len(records))
	}
	closeAnchor, closes = counterRule.CloseOnEvent(deleted)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(DELETED_PERMANENTLY) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}

	assertIdentityRuleRemediationTrajectory(t, rule, oauthFirst, inactive, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	olderInactive := identitySignalEventAt("okta-oauth-app-inactive-before-open", "okta", "okta.application", inactiveAttrs, identityTrajectoryBaseTime.Add(-time.Minute))
	assertIdentityRuleOlderCloseDoesNotResolveLaterOpen(t, rule, olderInactive, oauthFirst)
}

func TestIdentityPrivilegedAccountWithoutMfa(t *testing.T) {
	rules := identityRulesByID(t)
	rule := rules[identityPrivilegedAccountWithoutMFARuleID]
	assertIdentityDurableMetadata(t, rule, []string{"user"})
	if _, ok := rule.(CounterEventRule); !ok {
		t.Fatal("identity-privileged-account-without-mfa does not implement CounterEventRule")
	}

	runtime := &cerebrov1.SourceRuntime{Id: "example-google-workspace-user", SourceId: "google_workspace", TenantId: "writer", Config: map[string]string{"family": "user"}}
	openAttrs := map[string]string{
		"domain":        "writer.com",
		"email":         "admin@writer.com",
		"is_admin":      "true",
		"mfa_enrolled":  "false",
		"primary_email": "admin@writer.com",
		"user_id":       "1001",
	}
	first := identitySignalEventAt("google-user-admin-no-mfa-first", "google_workspace", "google_workspace.user", openAttrs, identityTrajectoryBaseTime)
	second := identitySignalEventAt("google-user-admin-no-mfa-second", "google_workspace", "google_workspace.user", openAttrs, identityTrajectoryBaseTime.Add(time.Minute))
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one finding", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != firstFinding.Fingerprint {
		t.Fatalf("fingerprint = %q, want stable %q for same privileged user", got, firstFinding.Fingerprint)
	}
	if got := firstFinding.Attributes["user"]; got != "admin@writer.com" {
		t.Fatalf("attributes[user] = %q, want admin@writer.com", got)
	}

	withMFAAttrs := cloneIdentitySignalAttributes(openAttrs)
	withMFAAttrs["mfa_enrolled"] = "true"
	withMFA := identitySignalEventAt("google-user-admin-with-mfa", "google_workspace", "google_workspace.user", withMFAAttrs, identityTrajectoryBaseTime.Add(2*time.Minute))
	records, err = rule.Evaluate(context.Background(), runtime, withMFA)
	if err != nil {
		t.Fatalf("Evaluate(withMFA) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(withMFA) returned %d findings, want 0 once MFA is enrolled", len(records))
	}
	assertIdentityRuleRemediationTrajectory(t, rule, first, withMFA, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	olderWithMFA := identitySignalEventAt("google-user-admin-with-mfa-before-open", "google_workspace", "google_workspace.user", withMFAAttrs, identityTrajectoryBaseTime.Add(-time.Minute))
	assertIdentityRuleOlderCloseDoesNotResolveLaterOpen(t, rule, olderWithMFA, first)

	notPrivilegedAttrs := cloneIdentitySignalAttributes(openAttrs)
	notPrivilegedAttrs["is_admin"] = "false"
	notPrivileged := identitySignalEventAt("google-user-not-privileged-no-mfa", "google_workspace", "google_workspace.user", notPrivilegedAttrs, identityTrajectoryBaseTime.Add(3*time.Minute))
	records, err = rule.Evaluate(context.Background(), runtime, notPrivileged)
	if err != nil {
		t.Fatalf("Evaluate(notPrivileged) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(notPrivileged) returned %d findings, want 0 once privilege is removed", len(records))
	}
	assertIdentityRuleRemediationTrajectory(t, rule, first, notPrivileged, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestIdentityStalePrivilegedAccount(t *testing.T) {
	rules := identityRulesByID(t)
	rule := rules[identityStalePrivilegedAccountRuleID]
	assertIdentityDurableMetadata(t, rule, []string{"user"})
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("identity-stale-privileged-account does not implement CounterEventRule")
	}

	runtime := &cerebrov1.SourceRuntime{Id: "example-google-workspace-user", SourceId: "google_workspace", TenantId: "writer", Config: map[string]string{"family": "user"}}
	staleLogin := time.Now().UTC().Add(-120 * 24 * time.Hour).Format(time.RFC3339Nano)
	freshLogin := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano)
	openAttrs := map[string]string{
		"domain":        "writer.com",
		"email":         "admin@writer.com",
		"is_admin":      "true",
		"last_login_at": staleLogin,
		"primary_email": "admin@writer.com",
		"user_id":       "1001",
	}
	first := identitySignalEventAt("google-stale-admin-first", "google_workspace", "google_workspace.user", openAttrs, identityTrajectoryBaseTime)
	second := identitySignalEventAt("google-stale-admin-second", "google_workspace", "google_workspace.user", openAttrs, identityTrajectoryBaseTime.Add(time.Minute))
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one finding", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != firstFinding.Fingerprint {
		t.Fatalf("fingerprint = %q, want stable %q for same stale privileged user", got, firstFinding.Fingerprint)
	}
	if got := firstFinding.Attributes["user"]; got != "admin@writer.com" {
		t.Fatalf("attributes[user] = %q, want admin@writer.com", got)
	}
	openAnchor := counterRule.OpenAnchor(firstFinding.Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty, want user anchor", firstFinding.Attributes)
	}

	freshLoginAttrs := cloneIdentitySignalAttributes(openAttrs)
	freshLoginAttrs["last_login_at"] = freshLogin
	fresh := identitySignalEventAt("google-stale-admin-fresh-login", "google_workspace", "google_workspace.user", freshLoginAttrs, identityTrajectoryBaseTime.Add(2*time.Minute))
	records, err = rule.Evaluate(context.Background(), runtime, fresh)
	if err != nil {
		t.Fatalf("Evaluate(fresh login) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(fresh login) returned %d findings, want 0 once last_login_at is fresh", len(records))
	}
	closeAnchor, closes := counterRule.CloseOnEvent(fresh)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(fresh login) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}
	assertIdentityRuleRemediationTrajectory(t, rule, first, fresh, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	olderFresh := identitySignalEventAt("google-stale-admin-fresh-login-before-open", "google_workspace", "google_workspace.user", freshLoginAttrs, identityTrajectoryBaseTime.Add(-time.Minute))
	assertIdentityRuleOlderCloseDoesNotResolveLaterOpen(t, rule, olderFresh, first)

	notPrivilegedAttrs := cloneIdentitySignalAttributes(openAttrs)
	notPrivilegedAttrs["is_admin"] = "false"
	notPrivileged := identitySignalEventAt("google-stale-admin-not-privileged", "google_workspace", "google_workspace.user", notPrivilegedAttrs, identityTrajectoryBaseTime.Add(3*time.Minute))
	records, err = rule.Evaluate(context.Background(), runtime, notPrivileged)
	if err != nil {
		t.Fatalf("Evaluate(not privileged) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(not privileged) returned %d findings, want 0 once privilege is removed", len(records))
	}
	closeAnchor, closes = counterRule.CloseOnEvent(notPrivileged)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(not privileged) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}
	assertIdentityRuleRemediationTrajectory(t, rule, first, notPrivileged, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestIdentitySignalRulesEmitJoinBackedFindings(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "google-workspace-runtime", SourceId: "google_workspace", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "google-role-assignment-1",
		TenantId: "writer",
		SourceId: "google_workspace",
		Kind:     "google_workspace.role_assignment",
		Attributes: map[string]string{
			"domain":       "writer.com",
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
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:google_workspace_user:1001")
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:google_workspace_admin_role:super-admin")
	if got := records[0].Attributes["primary_actor_urn"]; got != "urn:cerebro:writer:google_workspace_user:1001" {
		t.Fatalf("primary_actor_urn = %q, want google workspace user", got)
	}
}

func TestIdentitySignalRulesJoinExternalGroupMemberToIdentifier(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "okta-runtime", SourceId: "okta", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "okta-group-member-external",
		TenantId: "writer",
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
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:okta_user:00u-external")
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:okta_group:grp-security")
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:identifier:email:external@gmail.com")
}

func TestIdentityExternalOrPersonalGroupMember(t *testing.T) {
	rules := identityRulesByID(t)
	rule := rules[identityExternalGroupMemberRuleID]
	assertIdentityDurableMetadata(t, rule, []string{"group_urn", "member_email"})
	if _, ok := rule.(CounterEventRule); !ok {
		t.Fatal("identity-external-or-personal-group-member does not implement CounterEventRule")
	}

	runtime := &cerebrov1.SourceRuntime{Id: "example-okta-group-membership", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "group_membership"}}
	openAttrs := map[string]string{
		"domain":         "writer.okta.com",
		"group_id":       "grp-security",
		"group_name":     "Security",
		"member_email":   "external@gmail.com",
		"member_status":  "ACTIVE",
		"member_type":    "user",
		"member_user_id": "00u-external",
	}
	first := identitySignalEventAt("okta-group-member-first", "okta", "okta.group_membership", openAttrs, identityTrajectoryBaseTime)
	second := identitySignalEventAt("okta-group-member-second", "okta", "okta.group_membership", openAttrs, identityTrajectoryBaseTime.Add(time.Minute))
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one finding", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != firstFinding.Fingerprint {
		t.Fatalf("fingerprint = %q, want stable %q for same (group_urn, member_email)", got, firstFinding.Fingerprint)
	}
	if got := firstFinding.Attributes["group_urn"]; got != "urn:cerebro:writer:okta_group:grp-security" {
		t.Fatalf("attributes[group_urn] = %q, want okta group urn", got)
	}
	if got := firstFinding.Attributes["member_email"]; got != "external@gmail.com" {
		t.Fatalf("attributes[member_email] = %q, want external@gmail.com", got)
	}

	otherGroupAttrs := cloneIdentitySignalAttributes(openAttrs)
	otherGroupAttrs["group_id"] = "grp-other"
	otherGroup := identitySignalEventAt("okta-group-member-other-group", "okta", "okta.group_membership", otherGroupAttrs, identityTrajectoryBaseTime.Add(time.Minute))
	records, err = rule.Evaluate(context.Background(), runtime, otherGroup)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(other group) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got == firstFinding.Fingerprint {
		t.Fatalf("fingerprint for same member in different group = %q, want distinct from %q", got, firstFinding.Fingerprint)
	}

	removedAttrs := cloneIdentitySignalAttributes(openAttrs)
	removedAttrs["action"] = "group.user_membership.remove"
	removedAttrs["member_status"] = "removed"
	removed := identitySignalEventAt("okta-group-member-removed", "okta", "okta.group_membership", removedAttrs, identityTrajectoryBaseTime.Add(2*time.Minute))
	records, err = rule.Evaluate(context.Background(), runtime, removed)
	if err != nil {
		t.Fatalf("Evaluate(removed) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(removed) returned %d findings, want 0 after member removal", len(records))
	}
	assertIdentityRuleRemediationTrajectory(t, rule, first, removed, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	olderRemoved := identitySignalEventAt("okta-group-member-removed-before-open", "okta", "okta.group_membership", removedAttrs, identityTrajectoryBaseTime.Add(-time.Minute))
	assertIdentityRuleOlderCloseDoesNotResolveLaterOpen(t, rule, olderRemoved, first)
}

func TestIdentitySignalRulesDetectPrivilegedNoMFAUser(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "google-workspace-runtime", SourceId: "google_workspace", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "google-user-admin-no-mfa",
		TenantId: "writer",
		SourceId: "google_workspace",
		Kind:     "google_workspace.user",
		Attributes: map[string]string{
			"domain":        "writer.com",
			"email":         "admin@writer.com",
			"is_admin":      "true",
			"mfa_enrolled":  "false",
			"primary_email": "admin@writer.com",
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
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:google_workspace_user:1001")
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:identifier:email:admin@writer.com")

	unknownMFA := &cerebrov1.EventEnvelope{
		Id:       "google-user-admin-unknown-mfa",
		TenantId: "writer",
		SourceId: "google_workspace",
		Kind:     "google_workspace.user",
		Attributes: map[string]string{
			"domain":        "writer.com",
			"email":         "admin@writer.com",
			"is_admin":      "true",
			"primary_email": "admin@writer.com",
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
		TenantId: "writer",
		SourceId: "google_workspace",
		Kind:     "google_workspace.user",
		Attributes: map[string]string{
			"domain":        "writer.com",
			"email":         "admin@writer.com",
			"is_admin":      "true",
			"mfa_enrolled":  "true",
			"primary_email": "admin@writer.com",
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
				"subject_email": "admin@writer.com",
				"subject_id":    "AIDAADMIN",
				"subject_type":  "user",
			},
			resourceURN: "urn:cerebro:writer:aws_admin_role:AdministratorAccess",
		},
		{
			name:     "gcp",
			sourceID: "gcp",
			kind:     "gcp.iam_role_assignment",
			attributes: map[string]string{
				"domain":        "writer-prod",
				"role_id":       "roles/owner",
				"role_name":     "roles/owner",
				"subject_email": "admin@writer.com",
				"subject_id":    "admin@writer.com",
				"subject_type":  "user",
			},
			resourceURN: "urn:cerebro:writer:gcp_admin_role:roles/owner",
		},
		{
			name:     "azure",
			sourceID: "azure",
			kind:     "azure.directory_role_assignment",
			attributes: map[string]string{
				"domain":        "tenant-1",
				"role_id":       "global-admin",
				"role_name":     "Global Administrator",
				"subject_email": "admin@writer.com",
				"subject_id":    "user-1",
				"subject_type":  "user",
			},
			resourceURN: "urn:cerebro:writer:azure_admin_role:global-admin",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: tt.name + "-runtime", SourceId: tt.sourceID, TenantId: "writer"}
			event := &cerebrov1.EventEnvelope{Id: tt.name + "-role-assignment", TenantId: "writer", SourceId: tt.sourceID, Kind: tt.kind, Attributes: tt.attributes}
			records, err := rules[identityAdminPrivilegeGrantedRuleID].Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("len(records) = %d, want 1", len(records))
			}
			assertFindingResourceURN(t, records[0].ResourceURNs, tt.resourceURN)
			assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:identifier:email:admin@writer.com")
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
				"subject_email": "analyst@writer.com",
				"subject_id":    "analyst@writer.com",
				"subject_type":  "user",
			},
		},
		{
			name:     "gcp-viewer",
			sourceID: "gcp",
			kind:     "gcp.iam_role_assignment",
			attributes: map[string]string{
				"domain":        "writer-prod",
				"is_admin":      "false",
				"role_id":       "roles/viewer",
				"role_name":     "roles/viewer",
				"subject_email": "viewer@writer.com",
				"subject_id":    "viewer@writer.com",
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
				"subject_email": "viewer@writer.com",
				"subject_id":    "viewer@writer.com",
				"subject_type":  "user",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: tt.name + "-runtime", SourceId: tt.sourceID, TenantId: "writer"}
			event := &cerebrov1.EventEnvelope{Id: tt.name + "-role-assignment", TenantId: "writer", SourceId: tt.sourceID, Kind: tt.kind, Attributes: tt.attributes}
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
				"subject_email":   "admin@writer.com",
				"subject_id":      "admin@writer.com",
				"subject_type":    "user",
			},
			resourceURN: "urn:cerebro:writer:aws_credential:AKIAEXAMPLE",
		},
		{
			name:     "gcp-service-account-key",
			sourceID: "gcp",
			kind:     "gcp.service_account_key",
			attributes: map[string]string{
				"credential_id":   "projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys/key-1",
				"credential_type": "gcp_service_account_key",
				"domain":          "writer-prod",
				"subject_email":   "sa@writer-prod.iam.gserviceaccount.com",
				"subject_id":      "sa@writer-prod.iam.gserviceaccount.com",
				"subject_type":    "service_account",
			},
			resourceURN: "urn:cerebro:writer:gcp_credential:projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys/key-1",
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
			resourceURN: "urn:cerebro:writer:azure_credential:app-password-1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: tt.name + "-runtime", SourceId: tt.sourceID, TenantId: "writer"}
			event := &cerebrov1.EventEnvelope{Id: tt.name, TenantId: "writer", SourceId: tt.sourceID, Kind: tt.kind, Attributes: tt.attributes}
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
	runtime := &cerebrov1.SourceRuntime{Id: "aws-runtime", SourceId: "aws", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-access-key-disabled",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.access_key",
		Attributes: map[string]string{
			"credential_id":   "AKIAEXAMPLE",
			"credential_type": "aws_access_key",
			"domain":          "123456789012",
			"status":          "DISABLED",
			"subject_id":      "admin@writer.com",
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

func TestIdentityControlTamperRetired(t *testing.T) {
	rules := identityRulesByID(t)
	rule := rules[identityControlTamperCredentialChangeRuleID]
	if rule == nil {
		t.Fatalf("identity rule %q is missing", identityControlTamperCredentialChangeRuleID)
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if err := definition.Validate(); err != nil {
		t.Fatalf("RuleDefinition.Validate() error = %v", err)
	}
	if definition.Lifecycle.Kind != LifecycleRetired {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleRetired)
	}
	if definition.Lifecycle.Anchor != AnchorNone {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorNone)
	}
	if definition.Maturity != "retired" {
		t.Fatalf("Maturity = %q, want retired", definition.Maturity)
	}
	retirementRule, ok := rule.(openFindingRetirementRule)
	if !ok || !retirementRule.RetiresOpenFindings() {
		t.Fatalf("RetiresOpenFindings() = false, want true so stale findings under %q are resolved", identityControlTamperCredentialChangeRuleID)
	}

	runtime := &cerebrov1.SourceRuntime{Id: "example-okta-audit", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "audit"}}
	events := []*cerebrov1.EventEnvelope{
		identitySignalEventAt("okta-policy-weakened-retired", "okta", "okta.audit", map[string]string{
			"domain":                "writer.okta.com",
			"event_type":            "policy.lifecycle.update",
			"actor_email":           "admin@writer.com",
			"policy_id":             "pol-sign-on",
			"resource_id":           "pol-sign-on",
			"resource_type":         "policy",
			"auth_control_weakened": "true",
			"outcome_result":        "SUCCESS",
		}, identityTrajectoryBaseTime),
		identitySignalEventAt("okta-api-token-retired", "okta", "okta.audit", map[string]string{
			"domain":         "writer.okta.com",
			"event_type":     "system.api_token.create",
			"actor_id":       "00u-admin",
			"actor_type":     "User",
			"resource_id":    "token-1",
			"resource_type":  "ApiToken",
			"outcome_result": "SUCCESS",
		}, identityTrajectoryBaseTime.Add(time.Minute)),
		identitySignalEventAt("okta-password-view-retired", "okta", "okta.audit", map[string]string{
			"domain":         "writer.okta.com",
			"event_type":     "application.user_membership.show_password",
			"actor":          "admin@writer.com",
			"actor_id":       "00u-admin",
			"resource_id":    "0oa-app",
			"resource_type":  "AppInstance",
			"outcome_result": "SUCCESS",
		}, identityTrajectoryBaseTime.Add(2*time.Minute)),
	}
	for _, event := range events {
		records, err := rule.Evaluate(context.Background(), runtime, event)
		if err != nil {
			t.Fatalf("Evaluate(%q) error = %v", event.GetId(), err)
		}
		if len(records) != 0 {
			t.Fatalf("Evaluate(%q) returned %d findings, want none for retired rule", event.GetId(), len(records))
		}
	}

	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry(%q) error = %v", identityControlTamperCredentialChangeRuleID, err)
	}
	store := &stubFindingStore{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtime.GetId(): runtime}},
		&stubReplayer{events: events},
		store,
		store,
		store,
		store,
		registry,
	)
	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: runtime.GetId(),
		RuleID:    identityControlTamperCredentialChangeRuleID,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if result == nil {
		t.Fatal("EvaluateSourceRuntime() returned nil result")
	}
	if got := len(result.Findings); got != 0 {
		t.Fatalf("replay emitted %d findings, want 0 for retired rule", got)
	}
	if store.upsertCount != 0 {
		t.Fatalf("replay upserted %d findings, want 0 for retired rule", store.upsertCount)
	}
}

func TestIdentitySignalRulesTreatRoutineOAuthGrantsAsTelemetry(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"}
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
					TenantId: "writer",
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
	if len(records) != 0 {
		t.Fatalf("Evaluate(passwordView) returned %d findings, want telemetry-only retired correlation", len(records))
	}
}

func TestIdentitySignalRulesStillDetectOAuthCredentialCreation(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "okta-api-token-create",
		TenantId: "writer",
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
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"}
	for _, ruleID := range []string{
		identityMFAFactorResetOrDisabledRuleID,
		identityControlTamperCredentialChangeRuleID,
	} {
		t.Run(ruleID, func(t *testing.T) {
			event := &cerebrov1.EventEnvelope{
				Id:       "okta-failed-mfa-reset-" + ruleID,
				TenantId: "writer",
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

var identityTrajectoryBaseTime = time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)

func assertIdentityDurableMetadata(t *testing.T, rule Rule, wantFields []string) {
	t.Helper()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if err := definition.Validate(); err != nil {
		t.Fatalf("RuleDefinition.Validate() error = %v", err)
	}
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "event_id" {
			t.Fatalf("FingerprintFields still contains event_id: %v", definition.FingerprintFields)
		}
	}
}

func assertIdentityTTLEvidenceMetadata(t *testing.T, rule Rule, wantFields []string, wantTTL time.Duration) {
	t.Helper()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if err := definition.Validate(); err != nil {
		t.Fatalf("RuleDefinition.Validate() error = %v", err)
	}
	if definition.Lifecycle.Kind != LifecycleTTLEvidence {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleTTLEvidence)
	}
	if definition.Lifecycle.Anchor != AnchorNone {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorNone)
	}
	if definition.Lifecycle.TTL != wantTTL {
		t.Fatalf("Lifecycle.TTL = %v, want %v", definition.Lifecycle.TTL, wantTTL)
	}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "event_id" {
			t.Fatalf("FingerprintFields still contains event_id: %v", definition.FingerprintFields)
		}
	}
}

func assertIdentityRuleTTLEvidenceTrajectory(t *testing.T, rule Rule, runtime *cerebrov1.SourceRuntime, open *cerebrov1.EventEnvelope, ttl time.Duration) {
	t.Helper()
	if rule == nil {
		t.Fatal("rule is required")
	}
	if runtime == nil {
		t.Fatal("runtime is required")
	}
	if open == nil {
		t.Fatal("opening event is required")
	}
	spec := rule.Spec()
	if spec == nil || strings.TrimSpace(spec.GetId()) == "" {
		t.Fatal("rule must expose a non-empty RuleSpec.Id")
	}
	ruleID := strings.TrimSpace(spec.GetId())
	runtimeID := strings.TrimSpace(runtime.GetId())
	openedAt := identityTrajectoryBaseTime
	if open.GetOccurredAt() != nil {
		openedAt = open.GetOccurredAt().AsTime().UTC()
	}

	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry(%q) error = %v", ruleID, err)
	}
	store := &stubFindingStore{}
	replayer := &stubReplayer{events: []*cerebrov1.EventEnvelope{open}}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtimeID: runtime}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(&stubGraphStore{}).
		WithAppendLog(&recordingAppendLog{}).
		WithTTLClock(fixedTTLClock{now: openedAt})

	firstResult, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(%q open) error = %v", ruleID, err)
	}
	if firstResult == nil || len(firstResult.Evaluations) != 1 {
		t.Fatalf("open result evaluations = %#v, want one", firstResult)
	}
	if len(firstResult.Evaluations[0].Findings) != 1 {
		t.Fatalf("open pass emitted %d findings, want one opening finding", len(firstResult.Evaluations[0].Findings))
	}
	opened := firstResult.Evaluations[0].Findings[0]
	if got := strings.TrimSpace(opened.Status); got != findingStatusOpen {
		t.Fatalf("opening finding status = %q, want %q", got, findingStatusOpen)
	}

	service.WithTTLClock(fixedTTLClock{now: openedAt.Add(ttl + time.Hour)})
	if err := service.resolveTTLOpenFindings(context.Background(), ruleID); err != nil {
		t.Fatalf("resolveTTLOpenFindings(%q): %v", ruleID, err)
	}
	finalFindings := githubTrajectoryPersistedFindings(store, ruleID, runtimeID)
	if got := len(finalFindings); got != 1 {
		t.Fatalf("persisted findings for rule %q = %d, want 1", ruleID, got)
	}
	finalFinding := finalFindings[0]
	if got := strings.TrimSpace(finalFinding.Status); got != findingStatusResolved {
		t.Fatalf("final finding status = %q, want %q", got, findingStatusResolved)
	}
	wantReason := ttlResolutionReasonPrefix + formatTTLDuration(ttl)
	if got := strings.TrimSpace(finalFinding.StatusReason); got != wantReason {
		t.Fatalf("final finding resolution_reason = %q, want %q", got, wantReason)
	}
	if finalFinding.Tombstoned {
		t.Fatal("TTL expiry tombstoned the finding; want resolved without tombstone")
	}
	if got := strings.TrimSpace(finalFinding.Fingerprint); got != strings.TrimSpace(opened.Fingerprint) {
		t.Fatalf("final finding fingerprint = %q, want stable %q", got, strings.TrimSpace(opened.Fingerprint))
	}
	if store.updateStatusCallCount != 1 {
		t.Fatalf("UpdateFindingStatus calls = %d, want 1 TTL resolution update", store.updateStatusCallCount)
	}
}

func assertIdentityRuleRemediationTrajectory(t *testing.T, rule Rule, open Event, close Event, expectedFinalStatus FindingStatus) {
	t.Helper()
	if rule == nil {
		t.Fatal("rule is required")
	}
	spec := rule.Spec()
	if spec == nil || strings.TrimSpace(spec.GetId()) == "" {
		t.Fatal("rule must expose a non-empty RuleSpec.Id")
	}
	ruleID := strings.TrimSpace(spec.GetId())
	expectedStatus := githubTrajectoryFindingStatusString(t, expectedFinalStatus)
	runtimeID := identityTrajectoryRuntimeID(open)
	runtime := &cerebrov1.SourceRuntime{
		Id:       runtimeID,
		SourceId: identityTrajectorySourceID(open),
		TenantId: identityTrajectoryTenantID(open),
		Config:   map[string]string{"family": identityTrajectoryFamily(open)},
	}

	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry(%q) error = %v", ruleID, err)
	}
	store := &stubFindingStore{}
	replayer := &stubReplayer{}
	appendLog := &recordingAppendLog{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtimeID: runtime}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(&stubGraphStore{}).WithAppendLog(appendLog)

	replayer.events = []*cerebrov1.EventEnvelope{open}
	firstResult, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("first EvaluateSourceRuntimeRules(%q) error = %v", ruleID, err)
	}
	if firstResult == nil || len(firstResult.Evaluations) != 1 {
		t.Fatalf("first result evaluations = %#v, want one", firstResult)
	}
	if len(firstResult.Evaluations[0].Findings) != 1 {
		t.Fatalf("first pass emitted %d findings, want one opening finding", len(firstResult.Evaluations[0].Findings))
	}
	baseline := firstResult.Evaluations[0].Findings[0]
	baselineFingerprint := strings.TrimSpace(baseline.Fingerprint)
	if baselineFingerprint == "" {
		t.Fatalf("opening finding %q has empty fingerprint", baseline.ID)
	}

	replayer.events = []*cerebrov1.EventEnvelope{close}
	secondResult, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("second EvaluateSourceRuntimeRules(%q) error = %v", ruleID, err)
	}
	if secondResult == nil || len(secondResult.Evaluations) != 1 {
		t.Fatalf("second result evaluations = %#v, want one", secondResult)
	}
	if expectedStatus == findingStatusResolved && len(secondResult.Evaluations[0].Findings) != 0 {
		t.Fatalf("second pass emitted %d findings, want remediation-only pass to emit none", len(secondResult.Evaluations[0].Findings))
	}
	if replayer.calls != 2 {
		t.Fatalf("Replay calls = %d, want 2", replayer.calls)
	}

	finalFindings := githubTrajectoryPersistedFindings(store, ruleID, runtimeID)
	if got := len(finalFindings); got != 1 {
		t.Fatalf("persisted findings for rule %q = %d, want 1", ruleID, got)
	}
	finalFinding := finalFindings[0]
	if got := strings.TrimSpace(finalFinding.Status); got != expectedStatus {
		t.Fatalf("final finding status = %q, want %q", got, expectedStatus)
	}
	if got := strings.TrimSpace(finalFinding.Fingerprint); got != baselineFingerprint {
		t.Fatalf("final finding fingerprint = %q, want stable %q", got, baselineFingerprint)
	}
	assertGitHubTrajectoryAnchorAttributesPreserved(t, rule, baseline, finalFinding)
	assertGitHubTrajectoryWorkflowEvents(t, appendLog.events, finalFinding, baselineFingerprint, expectedStatus)
}

func assertIdentityRuleOlderCloseDoesNotResolveLaterOpen(t *testing.T, rule Rule, olderClose Event, laterOpen Event) {
	t.Helper()
	if rule == nil {
		t.Fatal("rule is required")
	}
	spec := rule.Spec()
	if spec == nil || strings.TrimSpace(spec.GetId()) == "" {
		t.Fatal("rule must expose a non-empty RuleSpec.Id")
	}
	ruleID := strings.TrimSpace(spec.GetId())
	runtimeID := identityTrajectoryRuntimeID(laterOpen)
	runtime := &cerebrov1.SourceRuntime{
		Id:       runtimeID,
		SourceId: identityTrajectorySourceID(laterOpen),
		TenantId: identityTrajectoryTenantID(laterOpen),
		Config:   map[string]string{"family": identityTrajectoryFamily(laterOpen)},
	}

	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry(%q) error = %v", ruleID, err)
	}
	store := &stubFindingStore{}
	replayer := &stubReplayer{events: []*cerebrov1.EventEnvelope{olderClose, laterOpen}}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtimeID: runtime}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(&stubGraphStore{}).WithAppendLog(&recordingAppendLog{})

	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(%q older-close-before-open) error = %v", ruleID, err)
	}
	if result == nil || len(result.Evaluations) != 1 {
		t.Fatalf("result evaluations = %#v, want one", result)
	}
	if got := len(result.Evaluations[0].Findings); got != 1 {
		t.Fatalf("older-close-before-open emitted %d findings, want one later opening finding", got)
	}
	baselineFingerprint := strings.TrimSpace(result.Evaluations[0].Findings[0].Fingerprint)
	if baselineFingerprint == "" {
		t.Fatal("later opening finding has empty fingerprint")
	}

	finalFindings := githubTrajectoryPersistedFindings(store, ruleID, runtimeID)
	if got := len(finalFindings); got != 1 {
		t.Fatalf("persisted findings for rule %q = %d, want 1", ruleID, got)
	}
	finalFinding := finalFindings[0]
	if got := strings.TrimSpace(finalFinding.Status); got != findingStatusOpen {
		t.Fatalf("final finding status after older close before newer open = %q, want %q", got, findingStatusOpen)
	}
	if got := strings.TrimSpace(finalFinding.Fingerprint); got != baselineFingerprint {
		t.Fatalf("final finding fingerprint = %q, want emitted fingerprint %q", got, baselineFingerprint)
	}
}

func identityTrajectoryRuntimeID(event Event) string {
	if event == nil {
		return "example-identity-runtime"
	}
	sourceID := identityTrajectorySourceID(event)
	family := identityTrajectoryFamily(event)
	if sourceID == "" || family == "" {
		return "example-identity-runtime"
	}
	return "example-" + sourceID + "-" + family
}

func identityTrajectoryTenantID(event Event) string {
	if event != nil && strings.TrimSpace(event.GetTenantId()) != "" {
		return strings.TrimSpace(event.GetTenantId())
	}
	return "writer"
}

func identityTrajectorySourceID(event Event) string {
	if event != nil && strings.TrimSpace(event.GetSourceId()) != "" {
		return strings.TrimSpace(event.GetSourceId())
	}
	return "okta"
}

func identityTrajectoryFamily(event Event) string {
	if event == nil {
		return "audit"
	}
	sourceID := identityTrajectorySourceID(event)
	kind := strings.TrimSpace(event.GetKind())
	prefix := sourceID + "."
	if strings.HasPrefix(kind, prefix) {
		return strings.TrimPrefix(kind, prefix)
	}
	return "audit"
}

func identitySignalEventAt(id string, sourceID string, kind string, attributes map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   sourceID,
		Kind:       kind,
		OccurredAt: timestamppb.New(occurredAt),
		Attributes: cloneIdentitySignalAttributes(attributes),
	}
}

func cloneIdentitySignalAttributes(attributes map[string]string) map[string]string {
	cloned := make(map[string]string, len(attributes))
	for key, value := range attributes {
		cloned[key] = value
	}
	return cloned
}
