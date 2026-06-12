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
	identityExternalGroupMemberRuleID           = "identity-external-or-personal-group-member"
	identityMFAFactorResetOrDisabledRuleID      = "identity-mfa-factor-reset-or-disabled"
	identityPrivilegedNoMFAAccessRuleID         = "identity-privileged-no-mfa-plus-sensitive-access"
	identityPrivilegedAccountWithoutMFARuleID   = "identity-privileged-account-without-mfa"
	identityStalePrivilegedAccountRuleID        = "identity-stale-privileged-account"
)

const identityStalePrivilegedAccountThreshold = 90 * 24 * time.Hour

type identitySignalPredicate func(*cerebrov1.EventEnvelope, map[string]string) bool

type identitySignalFingerprintInputs func(*cerebrov1.EventEnvelope, map[string]string, findingProjectionContext) []string

type identitySignalConfig struct {
	definition  RuleDefinition
	sourceIDs   []string
	eventKinds  []string
	predicate   identitySignalPredicate
	fingerprint identitySignalFingerprintInputs
	summary     func(map[string]string) string
}

type identitySignalRule struct {
	config identitySignalConfig
}

type identitySignalClosePredicate func(Event) (string, bool)

type identitySignalCounterEventRule struct {
	Rule
	definition  RuleDefinition
	openAnchor  func(map[string]string) string
	closeAnchor identitySignalClosePredicate
}

func newIdentitySignalRule(config identitySignalConfig) Rule {
	if len(config.eventKinds) != 0 {
		config.definition.EventKinds = append([]string(nil), config.eventKinds...)
	}
	return &identitySignalRule{config: config}
}

func newIdentitySignalCounterEventRule(config identitySignalConfig, openAnchor func(map[string]string) string, closeAnchor identitySignalClosePredicate) Rule {
	if len(config.eventKinds) != 0 {
		config.definition.EventKinds = append([]string(nil), config.eventKinds...)
	}
	return &identitySignalCounterEventRule{
		Rule:        &identitySignalRule{config: config},
		definition:  config.definition,
		openAnchor:  openAnchor,
		closeAnchor: closeAnchor,
	}
}

func (r *identitySignalCounterEventRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *identitySignalCounterEventRule) OpenAnchor(attributes map[string]string) string {
	if r == nil || r.openAnchor == nil {
		return ""
	}
	return strings.TrimSpace(r.openAnchor(attributes))
}

func (r *identitySignalCounterEventRule) CloseOnEvent(event Event) (string, bool) {
	if r == nil || r.closeAnchor == nil {
		return "", false
	}
	anchor, closes := r.closeAnchor(event)
	anchor = strings.TrimSpace(anchor)
	if anchor == "" || !closes {
		return "", false
	}
	return anchor, true
}

func newIdentitySignalRules() []Rule {
	capabilities := builtinIdentityCapabilities
	sourceIDs := capabilities.SourceIDs()
	return []Rule{
		newIdentitySignalRule(identitySignalConfig{
			definition: identityTTLEvidenceRuleDefinition(identityRuleDefinition(
				identityAuthControlLifecycleTamperingRuleID,
				"Identity Auth Control Lifecycle Tampering",
				"Detect identity-provider authentication, policy, network-zone, IdP, and security-setting control changes.",
				"HIGH",
				"finding.identity_auth_control_lifecycle_tampering",
				[]string{"identity", "control-plane", "defense-evasion", "attack.t1562"},
			), 7*24*time.Hour, "idp_id", "policy_id"),
			sourceIDs:   sourceIDs,
			eventKinds:  capabilities.EventKinds(identityCapabilityAudit),
			predicate:   matchesIdentityAuthControlTampering,
			fingerprint: identityAuthControlFingerprintInputs,
		}),
		newIdentitySignalCounterEventRule(identitySignalConfig{
			definition: identityDurableStateRuleDefinition(identityRuleDefinition(
				identityAdminPrivilegeGrantedRuleID,
				"Identity Admin Privilege Granted",
				"Detect admin-role or delegated-admin grants in identity providers.",
				"HIGH",
				"finding.identity_admin_privilege_granted",
				[]string{"identity", "privilege-escalation", "attack.t1098"},
			), "user", "role"),
			sourceIDs:   sourceIDs,
			eventKinds:  capabilities.EventKinds(identityCapabilityAdminRole, identityCapabilityAudit, identityCapabilityRoleAssignment),
			predicate:   matchesIdentityAdminPrivilegeGranted,
			fingerprint: identityAdminPrivilegeFingerprintInputs,
		}, identityAdminPrivilegeAnchor, identityAdminPrivilegeCloseAnchor),
		newIdentitySignalCounterEventRule(identitySignalConfig{
			definition: identityDurableStateRuleDefinition(identityRuleDefinition(
				identityMFAFactorResetOrDisabledRuleID,
				"Identity MFA Factor Reset Or Disabled",
				"Detect source-backed MFA/2SV posture gaps for Okta, Google Workspace, and GCP service-account identities; AWS IAM and Azure user MFA posture require source-adapter extensions before this rule claims those providers.",
				"HIGH",
				"finding.identity_mfa_factor_reset_or_disabled",
				[]string{"identity", "mfa", "credential-access", "attack.t1556"},
			), "user"),
			sourceIDs:   sourceIDs,
			eventKinds:  identityMFASourceBackedEventKinds,
			predicate:   matchesIdentityMFAFactorResetOrDisabled,
			fingerprint: identityUserFingerprintInputs,
		}, identityUserAnchor, identityMFACloseAnchor),
		newIdentitySignalCounterEventRule(identitySignalConfig{
			definition: identityDurableStateRuleDefinition(identityRuleDefinition(
				identityAPIOrOAuthCredentialCreatedRuleID,
				"Identity API Token Or OAuth App Created",
				"Detect API token creation, OAuth application authorization, or domain-wide delegation changes.",
				"HIGH",
				"finding.identity_api_token_or_oauth_app_created",
				[]string{"identity", "token", "oauth", "persistence", "attack.t1098"},
			), "user", "credential_id", "org", "oauth_app_id"),
			sourceIDs:   sourceIDs,
			eventKinds:  capabilities.EventKinds(identityCapabilityApplication, identityCapabilityAudit, identityCapabilityCredential),
			predicate:   matchesIdentityAPITokenOrOAuthCreated,
			fingerprint: identityAPITokenOrOAuthFingerprintInputs,
		}, identityAPITokenOrOAuthAnchor, identityAPITokenOrOAuthCloseAnchor),
		newIdentitySignalCounterEventRule(identitySignalConfig{
			definition: identityDurableStateRuleDefinition(identityRuleDefinition(
				identityPrivilegedAccountWithoutMFARuleID,
				"Identity Privileged Account Without MFA",
				"Detect source-backed privileged identity accounts that are not enrolled in MFA/2SV; AWS IAM and Azure user MFA posture require source-adapter extensions before this rule claims those users.",
				"HIGH",
				"finding.identity_privileged_account_without_mfa",
				[]string{"identity", "mfa", "privileged-access", "attack.t1078"},
			), "user"),
			sourceIDs:   sourceIDs,
			eventKinds:  identityMFASourceBackedEventKinds,
			predicate:   matchesIdentityPrivilegedWithoutMFA,
			fingerprint: identityUserFingerprintInputs,
		}, identityUserAnchor, identityPrivilegedWithoutMFACloseAnchor),
		newIdentitySignalCounterEventRule(identitySignalConfig{
			definition: identityDurableStateRuleDefinition(identityRuleDefinition(
				identityStalePrivilegedAccountRuleID,
				"Identity Stale Privileged Account",
				"Detect privileged identity accounts with stale or missing login activity.",
				"MEDIUM",
				"finding.identity_stale_privileged_account",
				[]string{"identity", "privileged-access", "hygiene"},
			), "user"),
			sourceIDs:   sourceIDs,
			eventKinds:  capabilities.EventKinds(identityCapabilityUser),
			predicate:   matchesIdentityStalePrivilegedAccount,
			fingerprint: identityUserFingerprintInputs,
		}, identityUserAnchor, identityStalePrivilegedCloseAnchor),
		newIdentitySignalCounterEventRule(identitySignalConfig{
			definition: identityDurableStateRuleDefinition(identityRuleDefinition(
				identityExternalGroupMemberRuleID,
				"Identity External Or Personal Group Member",
				"Detect group memberships tied to personal or external email domains.",
				"MEDIUM",
				"finding.identity_external_or_personal_group_member",
				[]string{"identity", "group", "external-access"},
			), "group_urn", "member_email"),
			sourceIDs:   sourceIDs,
			eventKinds:  capabilities.EventKinds(identityCapabilityGroupMembership),
			predicate:   matchesIdentityExternalGroupMember,
			fingerprint: identityExternalGroupMemberFingerprintInputs,
		}, identityExternalGroupMemberAnchor, identityExternalGroupMemberCloseAnchor),
	}
}

func identityRuleDefinition(id string, name string, description string, severity string, outputKind string, tags []string) RuleDefinition {
	return RuleDefinition{
		ID:                id,
		Name:              name,
		Description:       description,
		SourceID:          "identity",
		EventKinds:        []string{"okta.audit", "okta.user", "google_workspace.audit", "google_workspace.user"},
		OutputKind:        outputKind,
		Severity:          severity,
		Status:            findingStatusOpen,
		Maturity:          "test",
		Tags:              tags,
		References:        []string{"https://help.okta.com/en-us/content/topics/reports/reports_syslog.htm", "https://developers.google.com/admin-sdk/reports/v1/guides/manage-audit-admin"},
		FalsePositives:    []string{"Approved identity administration during a documented change window."},
		Runbook:           "Review the actor, identity target, linked graph identities, and adjacent findings by the same actor or shared identifier.",
		FingerprintFields: []string{"event_id"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.2"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.16"},
		},
	}
}

func identityDurableStateRuleDefinition(definition RuleDefinition, fingerprintFields ...string) RuleDefinition {
	definition.FingerprintFields = uniqueTrimmedStringsPreserveOrder(fingerprintFields)
	definition.Lifecycle = Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored}
	return definition
}

func identityTTLEvidenceRuleDefinition(definition RuleDefinition, ttl time.Duration, fingerprintFields ...string) RuleDefinition {
	definition.FingerprintFields = uniqueTrimmedStringsPreserveOrder(fingerprintFields)
	definition.Lifecycle = Lifecycle{Kind: LifecycleTTLEvidence, Anchor: AnchorNone, TTL: ttl}
	return definition
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
			return runtimeMayEmitEventKind(runtime, r.config.eventKinds)
		}
	}
	return false
}

func (r *identitySignalRule) Evaluate(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || event == nil {
		return nil, nil
	}
	if !identityKindAllowed(event.GetKind(), r.config.eventKinds) {
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
	fingerprintInputs := r.fingerprintInputs(event, attributes, projectedContext)
	if r.config.fingerprint != nil && !identityFingerprintInputsValid(fingerprintInputs) {
		return nil, nil
	}
	if len(fingerprintInputs) == 0 {
		return nil, nil
	}
	fingerprint := hashFindingFingerprint(append([]string{r.config.definition.ID}, fingerprintInputs...)...)
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

func (r *identitySignalRule) fingerprintInputs(event *cerebrov1.EventEnvelope, attributes map[string]string, projection findingProjectionContext) []string {
	if r != nil && r.config.fingerprint != nil {
		return r.config.fingerprint(event, attributes, projection)
	}
	return []string{
		strings.TrimSpace(event.GetId()),
		strings.TrimSpace(projection.PrimaryResourceURN),
		compoundRiskAction(&ports.FindingRecord{Attributes: attributes}),
	}
}

func identityFingerprintInputsValid(inputs []string) bool {
	if len(inputs) == 0 {
		return false
	}
	for _, input := range inputs {
		if strings.TrimSpace(input) == "" {
			return false
		}
	}
	return true
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
		"credential_id":        identityCredentialID(eventAttrs),
		"credential_type":      identityCredentialType(eventAttrs),
		"group_urn":            identityGroupURNValue(eventAttrs, context, event.GetTenantId(), event.GetSourceId()),
		"member_email":         identityMemberEmailValue(eventAttrs),
		"oauth_app_id":         identityOAuthAppID(eventAttrs),
		"org":                  identityOrgValue(eventAttrs),
		"primary_actor_urn":    context.PrimaryActorURN,
		"primary_resource_urn": context.PrimaryResourceURN,
		"resource_id":          firstNonEmpty(eventAttrs["resource_id"], eventAttrs["user_id"], eventAttrs["group_id"], eventAttrs["role_id"], eventAttrs["app_id"], eventAttrs["client_id"]),
		"resource_label":       context.ResourceLabel,
		"resource_type":        firstNonEmpty(eventAttrs["resource_type"], eventAttrs["target_type"], eventAttrs["family"]),
		"idp_id":               identityIDPID(eventAttrs),
		"mfa_state":            identityMFAState(eventAttrs),
		"policy_id":            identityPolicyID(eventAttrs),
		"role":                 identityRoleValue(eventAttrs),
		"source_id":            strings.TrimSpace(event.GetSourceId()),
		"source_family":        strings.TrimSpace(event.GetSourceId()),
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
		"tenant_id":            strings.TrimSpace(event.GetTenantId()),
		"user":                 firstNonEmpty(identityUserValue(eventAttrs), identityCredentialUserValue(eventAttrs)),
		"user_urn":             identityUserURNValue(eventAttrs, context, event.GetTenantId(), event.GetSourceId()),
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

func identityUserFingerprintInputs(event *cerebrov1.EventEnvelope, attributes map[string]string, projection findingProjectionContext) []string {
	return []string{
		strings.TrimSpace(event.GetTenantId()),
		identityUserURNValue(attributes, projection, event.GetTenantId(), event.GetSourceId()),
	}
}

func identityAdminPrivilegeFingerprintInputs(event *cerebrov1.EventEnvelope, attributes map[string]string, projection findingProjectionContext) []string {
	return []string{
		strings.TrimSpace(event.GetTenantId()),
		identityUserURNValue(attributes, projection, event.GetTenantId(), event.GetSourceId()),
		firstNonEmpty(identityRoleValue(attributes), projection.PrimaryResourceURN),
	}
}

func identityAuthControlFingerprintInputs(event *cerebrov1.EventEnvelope, attributes map[string]string, projection findingProjectionContext) []string {
	return []string{
		strings.TrimSpace(event.GetTenantId()),
		firstNonEmpty(identityPolicyID(attributes), identityIDPID(attributes), projection.PrimaryResourceURN),
	}
}

func identityAPITokenOrOAuthFingerprintInputs(event *cerebrov1.EventEnvelope, attributes map[string]string, projection findingProjectionContext) []string {
	tenantID := strings.TrimSpace(event.GetTenantId())
	userURN := identityUserURNValue(attributes, projection, tenantID, event.GetSourceId())
	if tokenID := identityAPITokenCredentialID(attributes); tokenID != "" {
		return []string{
			tenantID,
			firstNonEmpty(userURN, identityCredentialUserValue(attributes)),
			tokenID,
		}
	}
	if oauthAppID := identityOAuthAppID(attributes); oauthAppID != "" {
		return []string{
			tenantID,
			identityOrgValue(attributes),
			oauthAppID,
		}
	}
	return nil
}

func identityExternalGroupMemberFingerprintInputs(event *cerebrov1.EventEnvelope, attributes map[string]string, projection findingProjectionContext) []string {
	return []string{
		strings.TrimSpace(event.GetTenantId()),
		identityGroupURNValue(attributes, projection, event.GetTenantId(), event.GetSourceId()),
		identityMemberEmailValue(attributes),
	}
}

func identityUserAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"source_id": firstNonEmpty(attributes["source_id"], attributes["source_family"]),
		"user_urn":  identityUserURNValue(attributes, findingProjectionContext{}, attributes["tenant_id"], firstNonEmpty(attributes["source_id"], attributes["source_family"])),
	}, "source_id", "user_urn")
}

func identityAPITokenOrOAuthAnchor(attributes map[string]string) string {
	if tokenID := identityAPITokenCredentialID(attributes); tokenID != "" {
		return identityCounterEventAnchor(map[string]string{
			"user":          identityCredentialUserValue(attributes),
			"credential_id": tokenID,
		}, "user", "credential_id")
	}
	if oauthAppID := identityOAuthAppAnchorID(attributes); oauthAppID != "" {
		return identityCounterEventAnchor(map[string]string{
			"org":          identityOrgValue(attributes),
			"oauth_app_id": oauthAppID,
		}, "org", "oauth_app_id")
	}
	return ""
}

func identityExternalGroupMemberAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"group_urn":    strings.TrimSpace(attributes["group_urn"]),
		"member_email": identityMemberEmailValue(attributes),
	}, "group_urn", "member_email")
}

func identityAdminPrivilegeAnchor(attributes map[string]string) string {
	sourceID := firstNonEmpty(attributes["source_id"], attributes["source_family"])
	return identityCounterEventAnchor(map[string]string{
		"source_id": sourceID,
		"user_urn":  identityUserURNValue(attributes, findingProjectionContext{}, attributes["tenant_id"], sourceID),
		"role":      identityRoleValue(attributes),
	}, "source_id", "user_urn", "role")
}

func identityAuthControlAnchor(attributes map[string]string) string {
	if policyID := identityPolicyID(attributes); policyID != "" {
		return identityCounterEventAnchor(map[string]string{"policy_id": policyID}, "policy_id")
	}
	if idpID := identityIDPID(attributes); idpID != "" {
		return identityCounterEventAnchor(map[string]string{"idp_id": idpID}, "idp_id")
	}
	return ""
}

func identityCounterEventAnchor(attributes map[string]string, fields ...string) string {
	if len(fields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			return ""
		}
		value := strings.TrimSpace(attributes[field])
		if value == "" {
			return ""
		}
		parts = append(parts, field+"="+value)
	}
	return strings.Join(parts, "|")
}

func identityAdminPrivilegeCloseAnchor(event Event) (string, bool) {
	attributes := identityCounterEventAttributes(event)
	if !identityRoleAssignmentInactive(attributes) && !identityPrivilegeExplicitlyRemoved(attributes) {
		return "", false
	}
	anchor := identityAdminPrivilegeAnchor(attributes)
	return anchor, anchor != ""
}

func identityMFACloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	if !identityMFAEnabled(attributes) {
		return "", false
	}
	anchor := identityUserAnchor(identityCounterEventAttributes(event))
	return anchor, anchor != ""
}

func identityAPITokenOrOAuthCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	if !identityAPITokenOrOAuthInactive(attributes) {
		return "", false
	}
	anchor := identityAPITokenOrOAuthAnchor(identityCounterEventAttributes(event))
	return anchor, anchor != ""
}

func identityExternalGroupMemberCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	if identityGroupMembershipActiveOrUnknown(attributes) {
		return "", false
	}
	anchor := identityExternalGroupMemberAnchor(identityCounterEventAttributes(event))
	return anchor, anchor != ""
}

func identityPrivilegedWithoutMFACloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	if matchesIdentityPrivilegedWithoutMFA(event, attributes) {
		return "", false
	}
	if !identityMFAEnabled(attributes) && !identityPrivilegeExplicitlyRemoved(attributes) {
		return "", false
	}
	anchor := identityUserAnchor(identityCounterEventAttributes(event))
	return anchor, anchor != ""
}

func identityStalePrivilegedCloseAnchor(event Event) (string, bool) {
	attributes := eventAttributes(event)
	if matchesIdentityStalePrivilegedAccount(event, attributes) {
		return "", false
	}
	if !identityStalePrivilegedRemediated(attributes) {
		return "", false
	}
	anchor := identityUserAnchor(identityCounterEventAttributes(event))
	return anchor, anchor != ""
}

func identityCounterEventAttributes(event Event) map[string]string {
	if event == nil {
		return nil
	}
	attributes := cloneStringMap(eventAttributes(event))
	if attributes == nil {
		attributes = map[string]string{}
	}
	context := findingProjectionContext{}
	if value := identityCredentialID(attributes); value != "" {
		attributes["credential_id"] = value
	}
	if value := identityCredentialType(attributes); value != "" {
		attributes["credential_type"] = value
	}
	if value := identityGroupURNValue(attributes, context, event.GetTenantId(), event.GetSourceId()); value != "" {
		attributes["group_urn"] = value
	}
	if value := identityMemberEmailValue(attributes); value != "" {
		attributes["member_email"] = value
	}
	if value := identityOAuthAppID(attributes); value != "" {
		attributes["oauth_app_id"] = value
	}
	if value := identityOrgValue(attributes); value != "" {
		attributes["org"] = value
	}
	if value := identityCredentialUserValue(attributes); value != "" {
		attributes["user"] = value
	}
	if sourceID := strings.TrimSpace(event.GetSourceId()); sourceID != "" {
		attributes["source_id"] = sourceID
		attributes["source_family"] = sourceID
	}
	if tenantID := strings.TrimSpace(event.GetTenantId()); tenantID != "" {
		attributes["tenant_id"] = tenantID
	}
	if value := identityUserURNValue(attributes, context, event.GetTenantId(), event.GetSourceId()); value != "" {
		attributes["user_urn"] = value
	}
	return attributes
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func identityUserValue(attributes map[string]string) string {
	if user := firstNonEmpty(
		attributes["user"],
		attributes["email"],
		attributes["primary_email"],
		attributes["member_email"],
		attributes["user_email"],
		attributes["subject_email"],
		attributes["login"],
		attributes["assigned_to"],
		attributes["user_id"],
		attributes["subject_id"],
		attributes["member_user_id"],
		attributes["member_id"],
	); user != "" {
		return user
	}
	if identityResourceTypeMatches(attributes, "user", "account", "principal", "service_account", "service_principal") {
		return firstNonEmpty(attributes["resource_id"], attributes["target_id"])
	}
	return firstNonEmpty(attributes["actor_email"], attributes["actor_alternate_id"])
}

func identityUserSignalPresent(attributes map[string]string) bool {
	return firstNonEmpty(
		attributes["user_urn"],
		attributes["primary_actor_urn"],
		attributes["primary_resource_urn"],
		identityUserValue(attributes),
		identityCredentialUserValue(attributes),
	) != ""
}

func identityUserURNValue(attributes map[string]string, projection findingProjectionContext, tenantID string, sourceID string) string {
	if urn := strings.TrimSpace(attributes["user_urn"]); urn != "" {
		return urn
	}
	tenantID = strings.TrimSpace(firstNonEmpty(tenantID, attributes["tenant_id"]))
	sourceID = strings.TrimSpace(firstNonEmpty(sourceID, attributes["source_id"], attributes["source_family"]))
	userID := firstNonEmpty(
		attributes["user_id"],
		attributes["subject_id"],
		attributes["member_user_id"],
		attributes["member_id"],
		attributes["actor_id"],
		attributes["resource_id"],
		identityCredentialUserValue(attributes),
		identityUserValue(attributes),
	)
	if tenantID != "" && sourceID != "" && userID != "" {
		return identityProjectionURN(tenantID, sourceID+"_user", userID)
	}
	if urn := firstNonEmpty(identityProjectionUserURN(projection.PrimaryResourceURN), identityProjectionUserURN(projection.PrimaryActorURN)); urn != "" {
		return urn
	}
	return ""
}

func identityProjectionUserURN(urn string) string {
	urn = strings.TrimSpace(urn)
	if urn == "" {
		return ""
	}
	normalized := strings.ToLower(urn)
	if strings.Contains(normalized, "_user:") ||
		strings.Contains(normalized, ".user:") ||
		strings.Contains(normalized, "_principal:") ||
		strings.Contains(normalized, "_service_account:") ||
		strings.Contains(normalized, "_service_principal:") {
		return urn
	}
	return ""
}

func identityCredentialUserValue(attributes map[string]string) string {
	if user := identityUserValue(attributes); user != "" {
		return user
	}
	actorType := strings.ToLower(firstNonEmpty(attributes["actor_type"], attributes["actor_resource_type"], attributes["actor_entity_type"]))
	if actorType == "" || containsAny(actorType, "user", "person", "principal", "service_account", "serviceprincipal", "service_principal") {
		return firstNonEmpty(attributes["actor_email"], attributes["actor_alternate_id"], attributes["actor_id"], attributes["actor_display_name"])
	}
	return firstNonEmpty(attributes["actor_email"], attributes["actor_alternate_id"])
}

func identityCredentialID(attributes map[string]string) string {
	if credentialID := firstNonEmpty(
		attributes["credential_id"],
		attributes["access_key_id"],
		attributes["key_id"],
		attributes["secret_id"],
		attributes["token_id"],
	); credentialID != "" {
		return credentialID
	}
	if identityCredentialRepresentsOAuthApp(attributes) {
		return ""
	}
	if identityResourceTypeMatches(attributes, "api_token", "access_key", "service_account_key", "credential", "client_secret", "secret", "key", "password") ||
		containsAny(identityAction(attributes), "api_token", "client_secret", "client.secret", "access_key", "service_account_key") {
		return firstNonEmpty(attributes["resource_id"], attributes["target_id"])
	}
	return ""
}

func identityAPITokenCredentialID(attributes map[string]string) string {
	if identityCredentialRepresentsOAuthApp(attributes) {
		return ""
	}
	return identityCredentialID(attributes)
}

func identityCredentialType(attributes map[string]string) string {
	return firstNonEmpty(attributes["credential_type"], attributes["resource_type"], attributes["target_type"])
}

func identityCredentialRepresentsOAuthApp(attributes map[string]string) bool {
	descriptor := strings.ToLower(strings.Join([]string{
		identityCredentialType(attributes),
		identityAction(attributes),
	}, " "))
	if descriptor == "" {
		return false
	}
	if containsAny(descriptor, "api_token", "api token", "access_key", "access key", "service_account_key", "client_secret", "client.secret", "password", "secret", "key") {
		return false
	}
	return containsAny(descriptor, "oauth", "oauth2", "oauth_app", "api_client", "application", "appinstance")
}

func identityOAuthAppID(attributes map[string]string) string {
	if oauthAppID := firstNonEmpty(
		attributes["oauth_app_id"],
		attributes["app_id"],
		attributes["application_id"],
		attributes["oauth_client_id"],
		attributes["oauth2_client_id"],
		attributes["client_id"],
	); oauthAppID != "" {
		return oauthAppID
	}
	if identityCredentialRepresentsOAuthApp(attributes) ||
		identityResourceTypeMatches(attributes, "oauth", "oauth_application", "application", "appinstance", "api_client") ||
		containsAny(identityAction(attributes), "oauth", "oauth2", "api_client", "domain_wide", "domain-wide") {
		return firstNonEmpty(attributes["resource_id"], attributes["target_id"])
	}
	return ""
}

func identityOAuthAppAnchorID(attributes map[string]string) string {
	if oauthAppID := firstNonEmpty(
		attributes["oauth_client_id"],
		attributes["oauth2_client_id"],
		attributes["client_id"],
	); oauthAppID != "" {
		return oauthAppID
	}
	return identityOAuthAppID(attributes)
}

func identityOrgValue(attributes map[string]string) string {
	return firstNonEmpty(
		attributes["org"],
		attributes["org_id"],
		attributes["organization"],
		attributes["organization_id"],
		attributes["domain"],
		attributes["tenant_domain"],
		attributes["account_id"],
	)
}

func identityMemberEmailValue(attributes map[string]string) string {
	return strings.ToLower(firstNonEmpty(attributes["member_email"], attributes["email"], attributes["user_email"], attributes["subject_email"]))
}

func identityGroupURNValue(attributes map[string]string, projection findingProjectionContext, tenantID string, sourceID string) string {
	if groupURN := strings.TrimSpace(attributes["group_urn"]); groupURN != "" {
		return groupURN
	}
	if groupURN := groupURNFromProjection(projection); groupURN != "" {
		return groupURN
	}
	return identityGroupURNFromValues(tenantID, sourceID, firstNonEmpty(attributes["group_id"], attributes["id"]), firstNonEmpty(attributes["group_email"], attributes["email"]))
}

func groupURNFromProjection(projection findingProjectionContext) string {
	if urn := strings.TrimSpace(projection.PrimaryResourceURN); urn != "" && strings.Contains(urn, "_group:") {
		return urn
	}
	for _, entity := range projection.Entities {
		if entity == nil {
			continue
		}
		entityType := strings.ToLower(strings.TrimSpace(entity.EntityType))
		if strings.HasSuffix(entityType, ".group") {
			return strings.TrimSpace(entity.URN)
		}
	}
	return ""
}

func identityGroupURNFromValues(tenantID string, sourceID string, groupID string, groupEmail string) string {
	tenant := strings.TrimSpace(tenantID)
	provider := strings.TrimSpace(sourceID)
	if tenant == "" || provider == "" {
		return ""
	}
	if trimmed := strings.TrimSpace(groupID); trimmed != "" {
		return identityProjectionURN(tenant, provider+"_group", trimmed)
	}
	if email := strings.ToLower(strings.TrimSpace(groupEmail)); email != "" {
		return identityProjectionURN(tenant, provider+"_group", "email", email)
	}
	return ""
}

func identityProjectionURN(tenantID string, kind string, parts ...string) string {
	tenant := strings.TrimSpace(tenantID)
	entityKind := strings.TrimSpace(kind)
	if tenant == "" || entityKind == "" {
		return ""
	}
	values := []string{"urn", "cerebro", tenant, entityKind}
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	return strings.Join(values, ":")
}

func identityRoleValue(attributes map[string]string) string {
	if role := firstNonEmpty(attributes["role"], attributes["role_id"], attributes["role_assignment_id"], attributes["role_name"], attributes["role_type"]); role != "" {
		return role
	}
	if identityResourceTypeMatches(attributes, "role", "admin_role", "directory_role", "iam_policy", "policy") {
		return firstNonEmpty(attributes["resource_id"], attributes["target_id"])
	}
	return ""
}

func identityPolicyID(attributes map[string]string) string {
	if policyID := firstNonEmpty(attributes["policy_id"], attributes["policy_rule_id"], attributes["rule_id"]); policyID != "" {
		return policyID
	}
	if identityResourceTypeMatches(attributes, "policy", "policy_rule", "rule", "sign_on_policy") {
		return firstNonEmpty(attributes["resource_id"], attributes["target_id"])
	}
	return ""
}

func identityIDPID(attributes map[string]string) string {
	if idpID := firstNonEmpty(attributes["idp_id"], attributes["identity_provider_id"], attributes["provider_id"]); idpID != "" {
		return idpID
	}
	if identityResourceTypeMatches(attributes, "idp", "identity_provider", "identityprovider") {
		return firstNonEmpty(attributes["resource_id"], attributes["target_id"])
	}
	return ""
}

func identityMFAState(attributes map[string]string) string {
	return strings.ToLower(firstNonEmpty(attributes["mfa_state"], attributes["factor_state"], attributes["mfa_status"], attributes["status"], attributes["state"], attributes["lifecycle_status"]))
}

func identityResourceTypeMatches(attributes map[string]string, candidates ...string) bool {
	resourceType := strings.ToLower(strings.ReplaceAll(firstNonEmpty(attributes["resource_type"], attributes["target_type"], attributes["subject_type"]), ".", "_"))
	if resourceType == "" {
		return false
	}
	for _, candidate := range candidates {
		normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(candidate), ".", "_"))
		if normalized != "" && strings.Contains(resourceType, normalized) {
			return true
		}
	}
	return false
}

func matchesIdentityAuthControlTampering(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	if !identityOutcomeSuccessfulOrUnknown(attributes) {
		return false
	}
	if identityAuthControlStrengthened(attributes) {
		return false
	}
	if identityAuthControlWeakened(attributes) {
		return identityAuthControlAnchor(attributes) != ""
	}
	action := identityAction(attributes)
	resourceType := strings.ToLower(firstNonEmpty(attributes["resource_type"], attributes["target_type"]))
	return identityAuthControlAnchor(attributes) != "" &&
		containsAny(action, "policy", "rule", "network_zone", "zone", "idp", "two_step", "2sv", "saml", "security_setting", "change_two_step") &&
		containsAny(action+" "+resourceType, "update", "delete", "deactivate", "disable", "change", "remove")
}

func matchesIdentityAdminPrivilegeGranted(event *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	if !identityAssignmentActiveOrUnknown(attributes) {
		return false
	}
	if identityAdminPrivilegeAnchor(identityCounterEventAttributes(event)) == "" {
		return false
	}
	if builtinIdentityCapabilities.KindHasCapability(event.GetKind(), identityCapabilityAdminRole) {
		return true
	}
	if builtinIdentityCapabilities.KindHasCapability(event.GetKind(), identityCapabilityRoleAssignment) {
		return identityPrivileged(attributes)
	}
	if !identityOutcomeSuccessfulOrUnknown(attributes) {
		return false
	}
	action := identityAction(attributes)
	return containsAny(action, "privilege.grant", "role.assignment", "assign_role", "grant_admin", "delegated_admin", "super_admin")
}

func matchesIdentityMFAFactorResetOrDisabled(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	if !identityOutcomeSuccessfulOrUnknown(attributes) {
		return false
	}
	return identityUserSignalPresent(attributes) && identityMFAExplicitlyDisabled(attributes)
}

func identityAssignmentActiveOrUnknown(attributes map[string]string) bool {
	return !identityRoleAssignmentInactive(attributes)
}

func identityRoleAssignmentInactive(attributes map[string]string) bool {
	action := identityAction(attributes)
	if containsAny(action, "remove", "removed", "revoke", "revoked", "unassign", "unassigned", "delete", "deleted", "deactivate", "deactivated") {
		return true
	}
	state := strings.ToLower(firstNonEmpty(attributes["assignment_status"], attributes["role_assignment_status"], attributes["status"], attributes["state"], attributes["lifecycle_status"]))
	switch state {
	case "inactive", "disabled", "deleted", "removed", "revoked", "deactivated", "suspended", "unassigned":
		return true
	default:
		return false
	}
}

func identityAuthControlWeakened(attributes map[string]string) bool {
	if findingAttributeBool(attributes, "auth_control_weakened", "policy_weakened", "idp_weakened", "saml_provider_settings_weakened") {
		return true
	}
	return identityAttributeExplicitlyFalse(
		attributes,
		"auth_control_enabled",
		"auth_control_enforced",
		"oauth_app_restrictions_enabled",
		"oauth_app_restrictions_enforced",
		"saml_enabled",
		"saml_enforced",
		"saml_required",
		"saml_sso_enabled",
		"mfa_required",
		"two_factor_enforced",
		"two_factor_required",
		"two_factor_requirement_enabled",
		"policy_enabled",
		"idp_enabled",
	)
}

func identityAuthControlStrengthened(attributes map[string]string) bool {
	if identityAuthControlWeakened(attributes) {
		return false
	}
	if findingAttributeBool(
		attributes,
		"auth_control_strengthened",
		"auth_control_enabled",
		"auth_control_enforced",
		"oauth_app_restrictions_enabled",
		"oauth_app_restrictions_enforced",
		"saml_enabled",
		"saml_enforced",
		"saml_required",
		"saml_sso_enabled",
		"mfa_required",
		"two_factor_enforced",
		"two_factor_required",
		"two_factor_requirement_enabled",
		"policy_enabled",
		"idp_enabled",
	) {
		return true
	}
	action := identityAction(attributes)
	return containsAny(action, "enable", "enabled", "restore", "restored", "reactivate", "require", "enforce") &&
		!containsAny(action, "disable", "delete", "deactivate", "remove")
}

func identityPrivilegeExplicitlyRemoved(attributes map[string]string) bool {
	return identityAttributeExplicitlyFalse(attributes, "is_admin", "is_delegated_admin", "admin", "privileged", "actor_privileged")
}

func identityAttributeExplicitlyFalse(attributes map[string]string, keys ...string) bool {
	for _, key := range keys {
		switch strings.ToLower(strings.TrimSpace(attributes[key])) {
		case "0", "f", "false", "no", "n", "disabled", "off", "inactive":
			return true
		}
	}
	return false
}

func matchesIdentityAPITokenOrOAuthCreated(event *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	if !identityOutcomeSuccessfulOrUnknown(attributes) {
		return false
	}
	if identityCurrentStateOAuthApplication(event, attributes) {
		return true
	}
	action := identityAction(attributes)
	if routineIdentityAssignmentAction(action) {
		return false
	}
	if identityAPITokenOrOAuthInactive(attributes) {
		return false
	}
	if identityAPITokenCredentialID(attributes) != "" || strings.TrimSpace(attributes["credential_type"]) != "" {
		return identityCredentialActiveOrUnknown(attributes)
	}
	if routineOAuthRuntimeGrant(action) {
		return false
	}
	if containsAny(action, "api_token", "client_secret", "client.secret", "domain_wide", "domain-wide") {
		return containsAny(action, "create", "authorize", "grant", "add", "rotate", "generate")
	}
	return false
}

func identityCurrentStateOAuthApplication(event *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	if event == nil || !strings.EqualFold(strings.TrimSpace(event.GetKind()), "okta.application") {
		return false
	}
	if !identityOAuthApplicationActive(attributes) {
		return false
	}
	if identityOAuthAppID(attributes) == "" || identityOrgValue(attributes) == "" {
		return false
	}
	if findingAttributeBool(attributes, "oauth2", "oauth_enabled", "oidc_enabled") {
		return true
	}
	descriptor := strings.ToLower(strings.Join([]string{
		attributes["sign_on_mode"],
		attributes["app_type"],
		attributes["app_name"],
		attributes["name"],
		attributes["resource_type"],
		identityCredentialType(attributes),
		identityAction(attributes),
	}, " "))
	return containsAny(descriptor, "oauth", "oauth2", "oidc", "openid", "open_id", "open id")
}

func identityOAuthApplicationActive(attributes map[string]string) bool {
	return strings.EqualFold(firstNonEmpty(attributes["status"], attributes["state"], attributes["lifecycle_status"]), "ACTIVE")
}

func routineIdentityAssignmentAction(action string) bool {
	normalized := strings.ToLower(strings.TrimSpace(action))
	switch normalized {
	case "application.user_membership.add",
		"application.user_membership.remove",
		"application.user_membership.update",
		"application.group_membership.add",
		"application.group_membership.remove",
		"application.group_membership.update",
		"group.application_assignment.add",
		"group.application_assignment.remove",
		"group.application_assignment.update",
		"group.user_membership.add",
		"group.user_membership.remove",
		"group.user_membership.update",
		"application.provision.group_push.mapping.created",
		"application.provision.group_push.mapping.deleted",
		"application.provision.group_push.mapping.updated":
		return true
	}
	return false
}

func routineOAuthRuntimeGrant(action string) bool {
	normalized := strings.ToLower(strings.TrimSpace(action))
	switch normalized {
	case "app.oauth2.authorize.code", "app.oauth2.as.authorize.code":
		return true
	}
	return strings.HasPrefix(normalized, "app.oauth2.token.grant.") ||
		strings.HasPrefix(normalized, "app.oauth2.as.token.grant.")
}

func matchesIdentityPrivilegedWithoutMFA(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	return identityUserSignalPresent(attributes) && identityPrivileged(attributes) && identityMFAExplicitlyDisabled(attributes)
}

func matchesIdentityStalePrivilegedAccount(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	if identityPrivilegeExplicitlyRemoved(attributes) {
		return false
	}
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
	return time.Since(parsed.UTC()) > identityStalePrivilegedAccountThreshold
}

func matchesIdentityExternalGroupMember(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	if !identityGroupMembershipActiveOrUnknown(attributes) {
		return false
	}
	email := strings.ToLower(firstNonEmpty(attributes["member_email"], attributes["email"], attributes["user_email"]))
	return containsAny(email, "@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com")
}

func identityPrivileged(attributes map[string]string) bool {
	return findingAttributeBool(attributes, "is_admin", "is_delegated_admin", "admin", "privileged", "actor_privileged") ||
		containsAny(strings.ToLower(firstNonEmpty(attributes["role"], attributes["role_id"], attributes["role_type"], attributes["role_name"])), "admin", "super", "owner", "editor", "contributor", "poweruser", "administratoraccess", "iamfullaccess", "globaladministrator", "privilegedroleadministrator", "applicationadministrator", "cloudapplicationadministrator", "authenticationadministrator", "useraccessadministrator")
}

var identityMFASourceBackedEventKinds = []string{"gcp.service_account", "google_workspace.user", "okta.user"}

var identityMFAStateAttributeKeys = [...]string{"mfa_enrolled", "mfa_enforced", "is_enrolled_in_2sv", "is_enforced_in_2sv"}

func identityMFAEnabled(attributes map[string]string) bool {
	// Source-state MFA findings close only on an explicit positive MFA posture
	// signal. Unknown/missing values are not enough to remediate a finding; any
	// explicit false on enrollment or enforcement keeps it open.
	return !identityMFAExplicitlyDisabled(attributes) && identityMFAExplicitlyEnabled(attributes)
}

func identityMFAExplicitlyEnabled(attributes map[string]string) bool {
	for _, key := range identityMFAStateAttributeKeys {
		value := strings.ToLower(strings.TrimSpace(attributes[key]))
		switch value {
		case "1", "t", "true", "yes", "y", "enabled", "enrolled", "enforced":
			return true
		}
	}
	return false
}

func identityMFAExplicitlyDisabled(attributes map[string]string) bool {
	// Treat enrollment and enforcement independently: a true value on one MFA
	// attribute must not mask an explicit false on another attribute.
	for _, key := range identityMFAStateAttributeKeys {
		value := strings.ToLower(strings.TrimSpace(attributes[key]))
		switch value {
		case "0", "f", "false", "no", "n", "disabled", "unenrolled", "not_enrolled", "not enrolled":
			return true
		}
	}
	return false
}

func identityStalePrivilegedRemediated(attributes map[string]string) bool {
	return identityPrivilegeExplicitlyRemoved(attributes) || identityLastLoginFresh(attributes)
}

func identityLastLoginFresh(attributes map[string]string) bool {
	lastLogin := strings.TrimSpace(firstNonEmpty(attributes["last_login_at"], attributes["last_login_time"]))
	if lastLogin == "" || strings.HasPrefix(lastLogin, "1970-01-01") {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, lastLogin)
	if err != nil {
		return false
	}
	return time.Since(parsed.UTC()) <= identityStalePrivilegedAccountThreshold
}

func identityCredentialActiveOrUnknown(attributes map[string]string) bool {
	status := strings.ToLower(firstNonEmpty(attributes["credential_status"], attributes["status"], attributes["state"], attributes["lifecycle_status"]))
	switch status {
	case "inactive", "disabled", "deleted", "deleted_permanently", "permanently_deleted", "revoked", "expired", "deactivated", "suspended":
		return false
	default:
		return true
	}
}

func identityAPITokenOrOAuthInactive(attributes map[string]string) bool {
	if !identityCredentialActiveOrUnknown(attributes) {
		return true
	}
	action := identityAction(attributes)
	if !containsAny(action, "revoke", "revoked", "delete", "deleted", "disable", "disabled", "deactivate", "deactivated", "suspend", "suspended", "expire", "expired", "uninstall", "remove", "removed") {
		return false
	}
	return identityCredentialID(attributes) != "" ||
		identityOAuthAppID(attributes) != "" ||
		containsAny(action, "api_token", "oauth", "client_secret", "api_client", "application", "app")
}

func identityGroupMembershipActiveOrUnknown(attributes map[string]string) bool {
	action := identityAction(attributes)
	if containsAny(action, "remove", "removed", "delete", "deleted", "revoke", "revoked", "unassign", "unassigned", "leave", "left") {
		return false
	}
	status := strings.ToLower(firstNonEmpty(attributes["member_status"], attributes["membership_status"], attributes["status"], attributes["state"], attributes["lifecycle_status"]))
	switch status {
	case "inactive", "disabled", "deleted", "removed", "revoked", "deactivated", "suspended", "expired", "left", "unassigned":
		return false
	default:
		return true
	}
}

func identityOutcomeSuccessfulOrUnknown(attributes map[string]string) bool {
	outcome := strings.ToLower(firstNonEmpty(attributes["outcome_result"], attributes["result"], attributes["outcome"]))
	switch outcome {
	case "", "success", "succeeded", "allow", "allowed":
		return true
	default:
		return false
	}
}
