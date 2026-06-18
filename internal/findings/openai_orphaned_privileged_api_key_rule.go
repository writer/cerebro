package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	openAIOrphanedPrivilegedAPIKeyRuleID    = "openai-orphaned-privileged-api-key"
	openAIOrphanedPrivilegedAPIKeyTitle     = "OpenAI Orphaned Privileged API Key"
	openAIOrphanedPrivilegedAPIKeySeverity  = "HIGH"
	openAIOrphanedPrivilegedAPIKeyCheckID   = "openai-orphaned-privileged-api-key-current"
	openAIOrphanedPrivilegedAPIKeyCheckName = "OpenAI Orphaned Privileged API Key (current state)"
)

var openAIOrphanedPrivilegedAPIKeyControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC6.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.2"},
}

var openAIPrivilegedKeyRevokedStatuses = map[string]struct{}{
	"deleted":   {},
	"revoked":   {},
	"disabled":  {},
	"inactive":  {},
	"expired":   {},
	"suspended": {},
}

type openAIOrphanedPrivilegedAPIKeyRule struct {
	Rule
	definition RuleDefinition
}

var openAIOrphanedPrivilegedAPIKeyDefinition = RuleDefinition{
	ID:                 openAIOrphanedPrivilegedAPIKeyRuleID,
	Name:               openAIOrphanedPrivilegedAPIKeyTitle,
	Description:        "Detect active OpenAI organization-level admin API keys that have no accountable owner (no owning user or service account), leaving a privileged credential without a responsible identity to govern or revoke it.",
	SourceID:           "openai",
	EventKinds:         []string{"openai.admin_api_key"},
	OutputKind:         "finding.openai_orphaned_privileged_api_key",
	Severity:           openAIOrphanedPrivilegedAPIKeySeverity,
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"openai", "credential", "privileged-access", "ownership", "api-key"},
	References:         []string{"https://platform.openai.com/docs/api-reference/admin-api-keys"},
	FalsePositives:     []string{"Admin keys intentionally owned by a shared break-glass identity that is tracked outside the OpenAI ownership model."},
	Runbook:            "Identify the orphaned OpenAI admin API key, assign an accountable owner (user or service account), or revoke the key if it is no longer required.",
	RequiredAttributes: []string{"api_key_id"},
	FingerprintFields:  []string{"openai_credential_urn"},
	ControlRefs:        openAIOrphanedPrivilegedAPIKeyControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var openAIOrphanedPrivilegedAPIKeyKindMatcher = eventKindMatcher(openAIOrphanedPrivilegedAPIKeyDefinition.EventKinds...)

func newOpenAIOrphanedPrivilegedAPIKeyRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: openAIOrphanedPrivilegedAPIKeyDefinition,
		match:      matchesOpenAIOrphanedPrivilegedAPIKey,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return openAIOrphanedPrivilegedAPIKeyFinding(event, runtime.GetId())
		},
	})
	return &openAIOrphanedPrivilegedAPIKeyRule{
		Rule:       rule,
		definition: openAIOrphanedPrivilegedAPIKeyDefinition,
	}
}

func (r *openAIOrphanedPrivilegedAPIKeyRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *openAIOrphanedPrivilegedAPIKeyRule) OpenAnchor(attributes map[string]string) string {
	return openAIOrphanedPrivilegedAPIKeyAnchor(attributes)
}

// CloseOnEvent resolves an open finding when a later snapshot of the same admin
// API key shows an accountable owner (remediation) or shows the key revoked or
// disabled (no longer an active privileged credential), so resolved keys do not
// leave stale open findings.
func (r *openAIOrphanedPrivilegedAPIKeyRule) CloseOnEvent(event Event) (string, bool) {
	if !openAIOrphanedPrivilegedAPIKeyKindMatcher(event) || !hasRequiredAttributes(event, openAIOrphanedPrivilegedAPIKeyDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !openAIPrivilegedKeyHasOwner(attributes) && !openAIPrivilegedKeyRevoked(attributes) {
		return "", false
	}
	credentialURN := openAICredentialURN(event.GetTenantId(), attributes["api_key_id"])
	anchor := openAIOrphanedPrivilegedAPIKeyAnchor(map[string]string{"openai_credential_urn": credentialURN})
	return anchor, anchor != ""
}

func matchesOpenAIOrphanedPrivilegedAPIKey(event *cerebrov1.EventEnvelope) bool {
	if !openAIOrphanedPrivilegedAPIKeyKindMatcher(event) || !hasRequiredAttributes(event, openAIOrphanedPrivilegedAPIKeyDefinition.RequiredAttributes...) {
		return false
	}
	attributes := eventAttributes(event)
	if openAIPrivilegedKeyRevoked(attributes) {
		return false
	}
	return !openAIPrivilegedKeyHasOwner(attributes)
}

func openAIOrphanedPrivilegedAPIKeyFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	apiKeyID := strings.TrimSpace(attrs["api_key_id"])
	tenantID := strings.TrimSpace(event.GetTenantId())
	credentialURN := openAICredentialURN(tenantID, apiKeyID)
	if credentialURN == "" {
		return nil, nil
	}
	label := firstNonEmpty(strings.TrimSpace(attrs["name"]), apiKeyID)
	attributes := map[string]string{
		"openai_credential_urn": credentialURN,
		"api_key_id":            apiKeyID,
		"name":                  strings.TrimSpace(attrs["name"]),
		"key_class":             firstNonEmpty(strings.TrimSpace(attrs["key_class"]), "admin"),
		"privileged":            "true",
		"owner_id":              strings.TrimSpace(attrs["owner_id"]),
		"owner_type":            strings.TrimSpace(attrs["owner_type"]),
		"created_at":            strings.TrimSpace(attrs["created_at"]),
		"last_used_at":          strings.TrimSpace(attrs["last_used_at"]),
		"event_id":              strings.TrimSpace(event.GetId()),
		"source_runtime_id":     strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn":  credentialURN,
	}
	for key, value := range openAIOrphanedPrivilegedAPIKeyDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(openAIOrphanedPrivilegedAPIKeyRuleID, credentialURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          openAIOrphanedPrivilegedAPIKeyRuleID,
		Title:           openAIOrphanedPrivilegedAPIKeyTitle,
		Severity:        openAIOrphanedPrivilegedAPIKeySeverity,
		Status:          findingStatusOpen,
		Summary:         openAIOrphanedPrivilegedAPIKeySummary(label),
		ResourceURNs:    []string{credentialURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         openAIOrphanedPrivilegedAPIKeyCheckID,
		CheckName:       openAIOrphanedPrivilegedAPIKeyCheckName,
		ControlRefs:     cloneFindingControlRefs(openAIOrphanedPrivilegedAPIKeyDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func openAIPrivilegedKeyHasOwner(attributes map[string]string) bool {
	return strings.TrimSpace(attributes["owner_user_id"]) != "" || strings.TrimSpace(attributes["owner_service_account_id"]) != "" || strings.TrimSpace(attributes["owner_id"]) != ""
}

func openAIPrivilegedKeyRevoked(attributes map[string]string) bool {
	status := strings.ToLower(strings.TrimSpace(attributes["status"]))
	_, revoked := openAIPrivilegedKeyRevokedStatuses[status]
	return revoked
}

func openAICredentialURN(tenantID string, apiKeyID string) string {
	tenantID = strings.TrimSpace(tenantID)
	apiKeyID = strings.TrimSpace(apiKeyID)
	if tenantID == "" || apiKeyID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:openai_credential:%s", tenantID, apiKeyID)
}

func openAIOrphanedPrivilegedAPIKeyAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"openai_credential_urn": strings.TrimSpace(attributes["openai_credential_urn"]),
	}, "openai_credential_urn")
}

func openAIOrphanedPrivilegedAPIKeySummary(label string) string {
	return fmt.Sprintf("OpenAI privileged admin API key %s has no accountable owner", firstNonEmpty(label, "unknown key"))
}
