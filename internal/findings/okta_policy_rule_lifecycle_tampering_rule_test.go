package findings

import (
	"context"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestIdentityOktaPolicyRuleLifecycleTampering(t *testing.T) {
	rule := newOktaPolicyRuleLifecycleTamperingRule()
	assertIdentityDurableMetadata(t, rule, []string{"okta_policy_rule_urn"})
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("identity-okta-policy-rule-lifecycle-tampering does not expose metadata")
	}
	definition := metadataRule.RuleMetadata()
	if !cloudStringSlicesEqual(definition.EventKinds, []string{"okta.policy_rule"}) {
		t.Fatalf("EventKinds = %v, want [okta.policy_rule]", definition.EventKinds)
	}
	if !cloudStringSlicesEqual(definition.RequiredAttributes, []string{"policy_id", "policy_rule_id", "status"}) {
		t.Fatalf("RequiredAttributes = %v, want [policy_id policy_rule_id status]", definition.RequiredAttributes)
	}
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("identity-okta-policy-rule-lifecycle-tampering does not implement CounterEventRule")
	}

	runtimeA := &cerebrov1.SourceRuntime{Id: "example-okta-policy-rule-a", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "policy_rule"}}
	runtimeB := &cerebrov1.SourceRuntime{Id: "example-okta-policy-rule-b", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "policy_rule"}}
	inactive := oktaPolicyRuleLifecycleStateEvent("okta-policy-rule-inactive", "INACTIVE")
	records, err := rule.Evaluate(context.Background(), runtimeA, inactive)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(inactive) = (%v, %v), want one finding", records, err)
	}
	first := records[0]
	wantURN := "urn:cerebro:writer:okta_policy_rule:pol-1:rul-1"
	wantFingerprint := hashFindingFingerprint(oktaPolicyRuleLifecycleTamperingRuleID, wantURN)
	if got := first.Attributes["okta_policy_rule_urn"]; got != wantURN {
		t.Fatalf("attributes[okta_policy_rule_urn] = %q, want %q", got, wantURN)
	}
	if got := first.Attributes["policy_id"]; got != "pol-1" {
		t.Fatalf("attributes[policy_id] = %q, want pol-1", got)
	}
	if got := first.Attributes["policy_rule_id"]; got != "rul-1" {
		t.Fatalf("attributes[policy_rule_id] = %q, want rul-1", got)
	}
	if got := first.Fingerprint; got != wantFingerprint {
		t.Fatalf("fingerprint = %q, want hash(rule_id, okta_policy_rule_urn) %q", got, wantFingerprint)
	}
	if got := first.ID; got != wantFingerprint {
		t.Fatalf("ID = %q, want durable fingerprint %q", got, wantFingerprint)
	}

	second := oktaPolicyRuleLifecycleStateEvent("okta-policy-rule-inactive-again", "INACTIVE")
	records, err = rule.Evaluate(context.Background(), runtimeB, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second inactive state) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != first.Fingerprint {
		t.Fatalf("fingerprint = %q, want stable %q across event_id/runtime changes", got, first.Fingerprint)
	}

	deleted := oktaPolicyRuleLifecycleStateEvent("okta-policy-rule-deleted", "DELETED_PERMANENTLY")
	records, err = rule.Evaluate(context.Background(), runtimeA, deleted)
	if err != nil {
		t.Fatalf("Evaluate(deleted permanently) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(deleted permanently) returned %d findings, want 0 because DELETED_PERMANENTLY coverage is not source-backed", len(records))
	}

	active := oktaPolicyRuleLifecycleStateEventAt("okta-policy-rule-active", "ACTIVE", identityTrajectoryBaseTime.Add(2*time.Minute))
	records, err = rule.Evaluate(context.Background(), runtimeA, active)
	if err != nil {
		t.Fatalf("Evaluate(active state) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(active state) returned %d findings, want 0 once policy rule is active", len(records))
	}

	auditDeactivate := oktaPolicyRuleLifecycleAuditEvent("okta-policy-rule-audit-deactivate", "policy.rule.deactivate")
	records, err = rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "example-okta-audit", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "audit"}}, auditDeactivate)
	if err != nil {
		t.Fatalf("Evaluate(audit deactivation) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(audit deactivation) returned %d findings, want 0 standalone audit-only findings", len(records))
	}
	openAnchor := counterRule.OpenAnchor(first.Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty, want okta_policy_rule_urn anchor", first.Attributes)
	}
	closeAnchor, closes := counterRule.CloseOnEvent(active)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(active state) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}
	closeAnchor, closes = counterRule.CloseOnEvent(auditDeactivate)
	if closes || closeAnchor != "" {
		t.Fatalf("CloseOnEvent(audit deactivation) = (%q, %v), want (\"\", false)", closeAnchor, closes)
	}
	assertIdentityRuleRemediationTrajectory(t, rule, inactive, active, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	olderActive := oktaPolicyRuleLifecycleStateEventAt("okta-policy-rule-active-before-open", "ACTIVE", identityTrajectoryBaseTime.Add(-time.Minute))
	assertIdentityRuleOlderCloseDoesNotResolveLaterOpen(t, rule, olderActive, inactive)
}

func TestIdentityOktaPolicyRuleLifecycleTampering_CoverageAligned(t *testing.T) {
	rule := newOktaPolicyRuleLifecycleTamperingRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("identity-okta-policy-rule-lifecycle-tampering does not expose RuleMetadata")
	}
	description := strings.ToLower(metadataRule.RuleMetadata().Description)
	for _, unsupportedClaim := range []string{"deleted", "deleted_permanently"} {
		if strings.Contains(description, unsupportedClaim) {
			t.Fatalf("description %q still advertises unsupported %q coverage", metadataRule.RuleMetadata().Description, unsupportedClaim)
		}
	}

	runtime := &cerebrov1.SourceRuntime{Id: "example-okta-policy-rule", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "policy_rule"}}
	deleted := oktaPolicyRuleLifecycleStateEvent("okta-policy-rule-deleted-coverage-drop", "DELETED_PERMANENTLY")
	records, err := rule.Evaluate(context.Background(), runtime, deleted)
	if err != nil {
		t.Fatalf("Evaluate(DELETED_PERMANENTLY) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(DELETED_PERMANENTLY) returned %d findings, want 0 until the Okta source synthesizes vanished policy rules", len(records))
	}
	if matchesOktaPolicyRuleLifecycleTampering(deleted) {
		t.Fatal("matchesOktaPolicyRuleLifecycleTampering(DELETED_PERMANENTLY) = true, want false until source-backed delete synthesis exists")
	}
}

func oktaPolicyRuleLifecycleStateEvent(id string, status string) *cerebrov1.EventEnvelope {
	return oktaPolicyRuleLifecycleStateEventAt(id, status, identityTrajectoryBaseTime)
}

func oktaPolicyRuleLifecycleStateEventAt(id string, status string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	return identitySignalEventAt(id, "okta", "okta.policy_rule", map[string]string{
		"domain":             "writer.okta.com",
		"policy_id":          "pol-1",
		"policy_rule_id":     "rul-1",
		"policy_type":        "OKTA_SIGN_ON",
		"name":               "Require MFA",
		"priority":           "1",
		"resource_id":        "rul-1",
		"resource_type":      "PolicyRule",
		"status":             status,
		"policy_rule_status": status,
		"system":             "false",
	}, occurredAt)
}

func oktaPolicyRuleLifecycleAuditEvent(id string, eventType string) *cerebrov1.EventEnvelope {
	return identitySignalEventAt(id, "okta", "okta.audit", map[string]string{
		"actor_alternate_id": "admin@writer.com",
		"actor_id":           "00u-admin",
		"event_type":         eventType,
		"outcome_result":     "success",
		"policy_id":          "pol-1",
		"policy_rule_id":     "rul-1",
		"resource_id":        "rul-1",
		"resource_type":      "PolicyRule",
		"status":             "INACTIVE",
	}, identityTrajectoryBaseTime)
}
