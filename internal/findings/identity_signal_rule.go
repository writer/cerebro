package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/proto"
)

const (
	identityAdminPrivilegeGrantedRuleID         = "identity-admin-privilege-granted"
	identityAPIOrOAuthCredentialCreatedRuleID   = "identity-api-token-or-oauth-app-created"
	identityAuthControlLifecycleTamperingRuleID = "identity-auth-control-lifecycle-tampering"
	identityControlTamperCredentialChangeRuleID = "identity-control-tamper-followed-by-credential-change"
	identityExternalGroupMemberRuleID           = "identity-external-or-personal-group-member"
	identityMFAFactorResetOrDisabledRuleID      = "identity-mfa-factor-reset-or-disabled"
	identityPrivilegedNoMFAAccessRuleID         = "identity-privileged-no-mfa-plus-sensitive-access"
	identityPrivilegedAccountWithoutMFARuleID   = "identity-privileged-account-without-mfa"
	identityStalePrivilegedAccountRuleID        = "identity-stale-privileged-account"
)

type identitySignalPredicate func(*cerebrov1.EventEnvelope, map[string]string) bool

type identitySignalConfig struct {
	definition RuleDefinition
	sourceIDs  []string
	eventKinds []string
	predicate  identitySignalPredicate
	summary    func(map[string]string) string
}

type identitySignalRule struct {
	config identitySignalConfig
}

func newIdentitySignalRule(config identitySignalConfig) Rule {
	if len(config.eventKinds) != 0 {
		config.definition.EventKinds = append([]string(nil), config.eventKinds...)
	}
	return &identitySignalRule{config: config}
}

func newIdentitySignalRules() []Rule {
	capabilities := builtinIdentityCapabilities
	sourceIDs := capabilities.SourceIDs()
	return []Rule{
		newIdentitySignalRule(identitySignalConfig{
			definition: identityRuleDefinition(
				identityAuthControlLifecycleTamperingRuleID,
				"Identity Auth Control Lifecycle Tampering",
				"Detect identity-provider authentication, policy, network-zone, IdP, and security-setting control changes.",
				"HIGH",
				"finding.identity_auth_control_lifecycle_tampering",
				[]string{"identity", "control-plane", "defense-evasion", "attack.t1562"},
			),
			sourceIDs:  sourceIDs,
			eventKinds: capabilities.EventKinds(identityCapabilityAudit),
			predicate:  matchesIdentityAuthControlTampering,
		}),
		newIdentitySignalRule(identitySignalConfig{
			definition: identityRuleDefinition(
				identityAdminPrivilegeGrantedRuleID,
				"Identity Admin Privilege Granted",
				"Detect admin-role or delegated-admin grants in identity providers.",
				"HIGH",
				"finding.identity_admin_privilege_granted",
				[]string{"identity", "privilege-escalation", "attack.t1098"},
			),
			sourceIDs:  sourceIDs,
			eventKinds: capabilities.EventKinds(identityCapabilityAdminRole, identityCapabilityAudit, identityCapabilityRoleAssignment),
			predicate:  matchesIdentityAdminPrivilegeGranted,
		}),
		newIdentitySignalRule(identitySignalConfig{
			definition: identityRuleDefinition(
				identityMFAFactorResetOrDisabledRuleID,
				"Identity MFA Factor Reset Or Disabled",
				"Detect MFA/2SV resets, unenrollment, disablement, or enforcement changes.",
				"HIGH",
				"finding.identity_mfa_factor_reset_or_disabled",
				[]string{"identity", "mfa", "credential-access", "attack.t1556"},
			),
			sourceIDs:  sourceIDs,
			eventKinds: capabilities.EventKinds(identityCapabilityAudit),
			predicate:  matchesIdentityMFAFactorResetOrDisabled,
		}),
		newIdentitySignalRule(identitySignalConfig{
			definition: identityRuleDefinition(
				identityAPIOrOAuthCredentialCreatedRuleID,
				"Identity API Token Or OAuth App Created",
				"Detect API token creation, OAuth application authorization, or domain-wide delegation changes.",
				"HIGH",
				"finding.identity_api_token_or_oauth_app_created",
				[]string{"identity", "token", "oauth", "persistence", "attack.t1098"},
			),
			sourceIDs:  sourceIDs,
			eventKinds: capabilities.EventKinds(identityCapabilityAudit),
			predicate:  matchesIdentityAPITokenOrOAuthCreated,
		}),
		newIdentitySignalRule(identitySignalConfig{
			definition: identityRuleDefinition(
				identityPrivilegedAccountWithoutMFARuleID,
				"Identity Privileged Account Without MFA",
				"Detect privileged identity accounts that are not enrolled in MFA/2SV.",
				"HIGH",
				"finding.identity_privileged_account_without_mfa",
				[]string{"identity", "mfa", "privileged-access", "attack.t1078"},
			),
			sourceIDs:  sourceIDs,
			eventKinds: capabilities.EventKinds(identityCapabilityUser),
			predicate:  matchesIdentityPrivilegedWithoutMFA,
		}),
		newIdentitySignalRule(identitySignalConfig{
			definition: identityRuleDefinition(
				identityStalePrivilegedAccountRuleID,
				"Identity Stale Privileged Account",
				"Detect privileged identity accounts with stale or missing login activity.",
				"MEDIUM",
				"finding.identity_stale_privileged_account",
				[]string{"identity", "privileged-access", "hygiene"},
			),
			sourceIDs:  sourceIDs,
			eventKinds: capabilities.EventKinds(identityCapabilityUser),
			predicate:  matchesIdentityStalePrivilegedAccount,
		}),
		newIdentitySignalRule(identitySignalConfig{
			definition: identityRuleDefinition(
				identityExternalGroupMemberRuleID,
				"Identity External Or Personal Group Member",
				"Detect group memberships tied to personal or external email domains.",
				"MEDIUM",
				"finding.identity_external_or_personal_group_member",
				[]string{"identity", "group", "external-access"},
			),
			sourceIDs:  sourceIDs,
			eventKinds: capabilities.EventKinds(identityCapabilityGroupMembership),
			predicate:  matchesIdentityExternalGroupMember,
		}),
		newIdentitySignalRule(identitySignalConfig{
			definition: identityRuleDefinition(
				identityControlTamperCredentialChangeRuleID,
				"Identity Control Tamper Or Credential Change",
				"Detect control tampering and sensitive credential changes so exposure analysis can correlate them by actor or resource.",
				"HIGH",
				"finding.identity_control_tamper_or_credential_change",
				[]string{"identity", "correlation", "credential-access", "defense-evasion"},
			),
			sourceIDs:  sourceIDs,
			eventKinds: capabilities.EventKinds(identityCapabilityAudit),
			predicate:  matchesIdentityControlTamperOrCredentialChange,
		}),
		newIdentitySignalRule(identitySignalConfig{
			definition: identityRuleDefinition(
				identityPrivilegedNoMFAAccessRuleID,
				"Identity Privileged No-MFA Account With Sensitive Access",
				"Detect privileged no-MFA identities or sensitive access grants that should be joined through the graph.",
				"HIGH",
				"finding.identity_privileged_no_mfa_sensitive_access",
				[]string{"identity", "graph-join", "privileged-access", "mfa"},
			),
			sourceIDs:  sourceIDs,
			eventKinds: capabilities.EventKinds(identityCapabilityAdminRole, identityCapabilityAppAssignment, identityCapabilityGroupMembership, identityCapabilityRoleAssignment, identityCapabilityUser),
			predicate:  matchesIdentityPrivilegedNoMFAAccess,
		}),
	}
}

func identityRuleDefinition(id string, name string, description string, severity string, outputKind string, tags []string) RuleDefinition {
	return RuleDefinition{
		ID:                 id,
		Name:               name,
		Description:        description,
		SourceID:           "identity",
		EventKinds:         []string{"okta.audit", "okta.user", "google_workspace.audit", "google_workspace.user"},
		OutputKind:         outputKind,
		Severity:           severity,
		Status:             findingStatusOpen,
		Maturity:           "test",
		Tags:               tags,
		References:         []string{"https://help.okta.com/en-us/content/topics/reports/reports_syslog.htm", "https://developers.google.com/admin-sdk/reports/v1/guides/manage-audit-admin"},
		FalsePositives:     []string{"Approved identity administration during a documented change window."},
		Runbook:            "Review the actor, identity target, linked graph identities, and adjacent findings by the same actor or shared identifier.",
		RequiredAttributes: []string{"event_type"},
		FingerprintFields:  []string{"event_id"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.2"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.16"},
		},
	}
}

func (r *identitySignalRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.config.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *identitySignalRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	sourceID := strings.TrimSpace(runtime.GetSourceId())
	for _, candidate := range r.config.sourceIDs {
		if strings.EqualFold(sourceID, candidate) {
			return true
		}
	}
	return false
}

func (r *identitySignalRule) Evaluate(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || event == nil {
		return nil, nil
	}
	if !r.SupportsRuntime(runtime) || !identityKindAllowed(event.GetKind(), r.config.eventKinds) {
		return nil, nil
	}
	attributes := eventAttributes(event)
	if r.config.predicate == nil || !r.config.predicate(event, attributes) {
		return nil, nil
	}
	record, err := r.buildFinding(ctx, runtime, event)
	if err != nil {
		return nil, err
	}
	return []*ports.FindingRecord{record}, nil
}

func (r *identitySignalRule) buildFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
	eventAttrs := eventAttributes(event)
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryRelations:   []string{"acted_on", "assigned_to", "can_admin", "member_of"},
		CollectAllLinkURNs: true,
		ActorFallbacks:     []string{eventAttrs["actor_email"], eventAttrs["actor_alternate_id"], eventAttrs["actor_display_name"], eventAttrs["email"], eventAttrs["member_email"]},
		ResourceFallbacks:  []string{eventAttrs["resource_id"], eventAttrs["target_id"], eventAttrs["user_id"], eventAttrs["group_id"], eventAttrs["role_id"], eventAttrs["app_id"], eventAttrs["client_id"]},
		SkipFallbackEntity: func(entity *ports.ProjectedEntity) bool {
			if entity == nil {
				return true
			}
			return strings.HasPrefix(entity.EntityType, "identifier.") || strings.HasSuffix(entity.EntityType, ".org")
		},
	})
	if err != nil {
		return nil, err
	}
	observedAt := time.Time{}
	if event.GetOccurredAt() != nil {
		observedAt = event.GetOccurredAt().AsTime().UTC()
	}
	attributes := identityFindingAttributes(event, runtime, r.config, projectedContext)
	fingerprint := hashFindingFingerprint(r.config.definition.ID, event.GetId(), projectedContext.PrimaryResourceURN, compoundRiskAction(&ports.FindingRecord{Attributes: attributes}))
	summary := identityFindingSummary(attributes, r.config, projectedContext)
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          strings.TrimSpace(event.GetTenantId()),
		RuntimeID:         strings.TrimSpace(runtime.GetId()),
		RuleID:            r.config.definition.ID,
		Title:             r.config.definition.Name,
		Severity:          r.config.definition.Severity,
		Status:            r.config.definition.Status,
		Summary:           summary,
		ResourceURNs:      projectedContext.ResourceURNs,
		EventIDs:          []string{strings.TrimSpace(event.GetId())},
		ObservedPolicyIDs: githubObservedPolicyIDs(firstNonEmpty(attributes["policy_id"], attributes["resource_id"])),
		PolicyID:          firstNonEmpty(attributes["policy_id"], attributes["resource_id"]),
		PolicyName:        firstNonEmpty(attributes["resource_label"], attributes["resource_id"]),
		CheckID:           r.config.definition.ID,
		CheckName:         r.config.definition.Name,
		ControlRefs:       cloneFindingControlRefs(r.config.definition.ControlRefs),
		Attributes:        attributes,
		FirstObservedAt:   observedAt,
		LastObservedAt:    observedAt,
	}, nil
}

func identityFindingAttributes(event *cerebrov1.EventEnvelope, runtime *cerebrov1.SourceRuntime, config identitySignalConfig, context findingProjectionContext) map[string]string {
	eventAttrs := eventAttributes(event)
	attributes := map[string]string{
		"action":               identityAction(eventAttrs),
		"actor":                firstNonEmpty(eventAttrs["actor_email"], eventAttrs["actor_alternate_id"], eventAttrs["actor_display_name"], eventAttrs["email"], eventAttrs["member_email"]),
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_kind":           strings.TrimSpace(event.GetKind()),
		"event_type":           identityAction(eventAttrs),
		"family":               strings.TrimSpace(eventAttrs["family"]),
		"primary_actor_urn":    context.PrimaryActorURN,
		"primary_resource_urn": context.PrimaryResourceURN,
		"resource_id":          firstNonEmpty(eventAttrs["resource_id"], eventAttrs["user_id"], eventAttrs["group_id"], eventAttrs["role_id"], eventAttrs["app_id"], eventAttrs["client_id"]),
		"resource_label":       context.ResourceLabel,
		"resource_type":        firstNonEmpty(eventAttrs["resource_type"], eventAttrs["target_type"], eventAttrs["family"]),
		"source_family":        strings.TrimSpace(event.GetSourceId()),
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
		"user":                 firstNonEmpty(eventAttrs["email"], eventAttrs["primary_email"], eventAttrs["member_email"], eventAttrs["actor_email"]),
	}
	for key, value := range eventAttrs {
		if _, exists := attributes[key]; !exists {
			attributes[key] = strings.TrimSpace(value)
		}
	}
	for key, value := range config.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	return attributes
}

func identityFindingSummary(attributes map[string]string, config identitySignalConfig, context findingProjectionContext) string {
	if config.summary != nil {
		return config.summary(attributes)
	}
	actor := firstNonEmpty(attributes["actor"], context.ActorLabel, "identity actor")
	resource := firstNonEmpty(context.ResourceLabel, attributes["resource_id"], attributes["user"], "identity resource")
	return fmt.Sprintf("%s triggered %s on %s", actor, attributes["event_type"], resource)
}

func identityKindAllowed(kind string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(kind), strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func identityAction(attributes map[string]string) string {
	return strings.ToLower(firstNonEmpty(attributes["event_type"], attributes["event_name"], attributes["action"], attributes["family"]))
}

func matchesIdentityAuthControlTampering(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	action := identityAction(attributes)
	resourceType := strings.ToLower(firstNonEmpty(attributes["resource_type"], attributes["target_type"]))
	return containsAny(action, "policy", "rule", "network_zone", "zone", "idp", "two_step", "2sv", "saml", "security_setting", "change_two_step") &&
		containsAny(action+" "+resourceType, "update", "delete", "deactivate", "disable", "change", "remove")
}

func matchesIdentityAdminPrivilegeGranted(event *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	if builtinIdentityCapabilities.KindHasCapability(event.GetKind(), identityCapabilityAdminRole, identityCapabilityRoleAssignment) {
		return true
	}
	action := identityAction(attributes)
	return containsAny(action, "privilege.grant", "role.assignment", "assign_role", "grant_admin", "delegated_admin", "super_admin")
}

func matchesIdentityMFAFactorResetOrDisabled(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	action := identityAction(attributes)
	return containsAny(action, "mfa", "factor", "two_step", "2sv", "verification") &&
		containsAny(action, "reset", "disable", "deactivate", "unenroll", "change")
}

func matchesIdentityAPITokenOrOAuthCreated(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	action := identityAction(attributes)
	return containsAny(action, "api_token", "oauth", "api_client", "domain_wide", "client_access", "application") &&
		containsAny(action, "create", "authorize", "grant", "add")
}

func matchesIdentityPrivilegedWithoutMFA(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	return identityPrivileged(attributes) && !identityMFAEnabled(attributes)
}

func matchesIdentityStalePrivilegedAccount(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	if !identityPrivileged(attributes) {
		return false
	}
	lastLogin := firstNonEmpty(attributes["last_login_at"], attributes["last_login_time"])
	if strings.TrimSpace(lastLogin) == "" || strings.HasPrefix(lastLogin, "1970-01-01") {
		return true
	}
	parsed, err := time.Parse(time.RFC3339Nano, lastLogin)
	if err != nil {
		return false
	}
	return time.Since(parsed.UTC()) > 90*24*time.Hour
}

func matchesIdentityExternalGroupMember(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	email := strings.ToLower(firstNonEmpty(attributes["member_email"], attributes["email"], attributes["user_email"]))
	return containsAny(email, "@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com")
}

func matchesIdentityControlTamperOrCredentialChange(event *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	return matchesIdentityAuthControlTampering(event, attributes) ||
		matchesIdentityMFAFactorResetOrDisabled(event, attributes) ||
		matchesIdentityAPITokenOrOAuthCreated(event, attributes) ||
		containsAny(identityAction(attributes), "password", "credential", "recovery", "reset")
}

func matchesIdentityPrivilegedNoMFAAccess(event *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	if matchesIdentityPrivilegedWithoutMFA(event, attributes) {
		return true
	}
	if builtinIdentityCapabilities.KindHasCapability(event.GetKind(), identityCapabilityAdminRole, identityCapabilityRoleAssignment) {
		return true
	}
	action := identityAction(attributes)
	return containsAny(action, "assign", "member", "role", "admin") && identityPrivileged(attributes) && !identityMFAEnabled(attributes)
}

func identityPrivileged(attributes map[string]string) bool {
	return findingAttributeBool(attributes, "is_admin", "is_delegated_admin", "admin", "privileged", "actor_privileged") ||
		containsAny(strings.ToLower(firstNonEmpty(attributes["role"], attributes["role_id"], attributes["role_type"], attributes["role_name"])), "admin", "super")
}

func identityMFAEnabled(attributes map[string]string) bool {
	return findingAttributeBool(attributes, "mfa_enrolled", "mfa_enforced", "is_enrolled_in_2sv", "is_enforced_in_2sv")
}
