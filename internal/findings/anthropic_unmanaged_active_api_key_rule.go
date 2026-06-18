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
	anthropicUnmanagedActiveAPIKeyRuleID    = "anthropic-unmanaged-active-api-key" // #nosec G101 -- rule identifier, not a credential.
	anthropicUnmanagedActiveAPIKeyTitle     = "Anthropic Unmanaged Active API Key" // #nosec G101 -- rule display title, not a credential.
	anthropicUnmanagedActiveAPIKeySeverity  = "HIGH"
	anthropicUnmanagedActiveAPIKeyCheckID   = "anthropic-unmanaged-active-api-key-current"         // #nosec G101 -- check identifier, not a credential.
	anthropicUnmanagedActiveAPIKeyCheckName = "Anthropic Unmanaged Active API Key (current state)" // #nosec G101 -- check display name, not a credential.
)

var anthropicUnmanagedActiveAPIKeyControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC6.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.2"},
}

var anthropicAPIKeyRevokedStatuses = map[string]struct{}{
	"deleted":   {},
	"revoked":   {},
	"disabled":  {},
	"inactive":  {},
	"expired":   {},
	"suspended": {},
	"archived":  {},
}

type anthropicUnmanagedActiveAPIKeyRule struct {
	Rule
	definition RuleDefinition
}

var anthropicUnmanagedActiveAPIKeyDefinition = RuleDefinition{
	ID:                 anthropicUnmanagedActiveAPIKeyRuleID,
	Name:               anthropicUnmanagedActiveAPIKeyTitle,
	Description:        "Detect active Anthropic organization API keys that have no accountable owner (no owning user or service account), leaving a live credential without a responsible identity to govern or revoke it.",
	SourceID:           "anthropic",
	EventKinds:         []string{"anthropic.api_key"},
	OutputKind:         "finding.anthropic_unmanaged_active_api_key",
	Severity:           anthropicUnmanagedActiveAPIKeySeverity,
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"anthropic", "credential", "api-key", "ownership", "unmanaged"},
	References:         []string{"https://docs.anthropic.com/en/api/administration-api"},
	FalsePositives:     []string{"Keys intentionally owned by a shared break-glass identity that is tracked outside the Anthropic ownership model."},
	Runbook:            "Identify the unmanaged Anthropic API key, assign an accountable owner, or revoke the key if it is no longer required.",
	RequiredAttributes: []string{"api_key_id"},
	FingerprintFields:  []string{"anthropic_credential_urn"},
	ControlRefs:        anthropicUnmanagedActiveAPIKeyControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var anthropicUnmanagedActiveAPIKeyKindMatcher = eventKindMatcher(anthropicUnmanagedActiveAPIKeyDefinition.EventKinds...)

func newAnthropicUnmanagedActiveAPIKeyRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: anthropicUnmanagedActiveAPIKeyDefinition,
		match:      matchesAnthropicUnmanagedActiveAPIKey,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return anthropicUnmanagedActiveAPIKeyFinding(event, runtime.GetId())
		},
	})
	return &anthropicUnmanagedActiveAPIKeyRule{
		Rule:       rule,
		definition: anthropicUnmanagedActiveAPIKeyDefinition,
	}
}

func (r *anthropicUnmanagedActiveAPIKeyRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *anthropicUnmanagedActiveAPIKeyRule) OpenAnchor(attributes map[string]string) string {
	return anthropicUnmanagedActiveAPIKeyAnchor(attributes)
}

// CloseOnEvent resolves an open finding when a later snapshot of the same API
// key shows an accountable owner (remediation) or shows the key revoked or
// inactive (no longer a live credential), so resolved keys do not leave stale
// open findings.
func (r *anthropicUnmanagedActiveAPIKeyRule) CloseOnEvent(event Event) (string, bool) {
	if !anthropicUnmanagedActiveAPIKeyKindMatcher(event) || !hasRequiredAttributes(event, anthropicUnmanagedActiveAPIKeyDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !anthropicAPIKeyHasOwner(attributes) && !anthropicAPIKeyRevoked(attributes) {
		return "", false
	}
	credentialURN := anthropicCredentialURN(event.GetTenantId(), attributes["api_key_id"])
	anchor := anthropicUnmanagedActiveAPIKeyAnchor(map[string]string{"anthropic_credential_urn": credentialURN})
	return anchor, anchor != ""
}

func matchesAnthropicUnmanagedActiveAPIKey(event *cerebrov1.EventEnvelope) bool {
	if !anthropicUnmanagedActiveAPIKeyKindMatcher(event) || !hasRequiredAttributes(event, anthropicUnmanagedActiveAPIKeyDefinition.RequiredAttributes...) {
		return false
	}
	attributes := eventAttributes(event)
	if anthropicAPIKeyRevoked(attributes) {
		return false
	}
	return !anthropicAPIKeyHasOwner(attributes)
}

func anthropicUnmanagedActiveAPIKeyFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	apiKeyID := strings.TrimSpace(attrs["api_key_id"])
	tenantID := strings.TrimSpace(event.GetTenantId())
	credentialURN := anthropicCredentialURN(tenantID, apiKeyID)
	if credentialURN == "" {
		return nil, nil
	}
	label := firstNonEmpty(strings.TrimSpace(attrs["name"]), apiKeyID)
	attributes := map[string]string{
		"anthropic_credential_urn": credentialURN,
		"api_key_id":               apiKeyID,
		"name":                     strings.TrimSpace(attrs["name"]),
		"status":                   firstNonEmpty(strings.TrimSpace(attrs["status"]), "active"),
		"workspace_id":             strings.TrimSpace(attrs["workspace_id"]),
		"created_at":               strings.TrimSpace(attrs["created_at"]),
		"last_used_at":             strings.TrimSpace(attrs["last_used_at"]),
		"event_id":                 strings.TrimSpace(event.GetId()),
		"source_runtime_id":        strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn":     credentialURN,
	}
	for key, value := range anthropicUnmanagedActiveAPIKeyDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(anthropicUnmanagedActiveAPIKeyRuleID, credentialURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          anthropicUnmanagedActiveAPIKeyRuleID,
		Title:           anthropicUnmanagedActiveAPIKeyTitle,
		Severity:        anthropicUnmanagedActiveAPIKeySeverity,
		Status:          findingStatusOpen,
		Summary:         anthropicUnmanagedActiveAPIKeySummary(label),
		ResourceURNs:    []string{credentialURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         anthropicUnmanagedActiveAPIKeyCheckID,
		CheckName:       anthropicUnmanagedActiveAPIKeyCheckName,
		ControlRefs:     cloneFindingControlRefs(anthropicUnmanagedActiveAPIKeyDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func anthropicAPIKeyHasOwner(attributes map[string]string) bool {
	return strings.TrimSpace(attributes["owner_user_id"]) != "" || strings.TrimSpace(attributes["owner_service_account_id"]) != "" || strings.TrimSpace(attributes["owner_id"]) != ""
}

func anthropicAPIKeyRevoked(attributes map[string]string) bool {
	status := strings.ToLower(strings.TrimSpace(attributes["status"]))
	_, revoked := anthropicAPIKeyRevokedStatuses[status]
	return revoked
}

func anthropicCredentialURN(tenantID string, apiKeyID string) string {
	tenantID = strings.TrimSpace(tenantID)
	apiKeyID = strings.TrimSpace(apiKeyID)
	if tenantID == "" || apiKeyID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:anthropic_credential:%s", tenantID, apiKeyID)
}

func anthropicUnmanagedActiveAPIKeyAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"anthropic_credential_urn": strings.TrimSpace(attributes["anthropic_credential_urn"]),
	}, "anthropic_credential_urn")
}

func anthropicUnmanagedActiveAPIKeySummary(label string) string {
	return fmt.Sprintf("Anthropic API key %s is active with no accountable owner", firstNonEmpty(label, "unknown key"))
}
