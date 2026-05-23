package findings

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestIdentityOktaPolicyRuleLifecycleTampering(t *testing.T) {
	rule := newOktaPolicyRuleLifecycleTamperingRule()
	assertIdentityDurableMetadata(t, rule, []string{"okta_policy_rule_urn"})
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("identity-okta-policy-rule-lifecycle-tampering does not implement CounterEventRule")
	}

	runtimeA := &cerebrov1.SourceRuntime{Id: "example-okta-audit-a", SourceId: "okta", TenantId: "writer"}
	runtimeB := &cerebrov1.SourceRuntime{Id: "example-okta-audit-b", SourceId: "okta", TenantId: "writer"}
	deactivated := oktaPolicyRuleLifecycleEvent("okta-policy-rule-deactivated", "policy.rule.deactivate")
	records, err := rule.Evaluate(context.Background(), runtimeA, deactivated)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(deactivated) = (%v, %v), want one finding", records, err)
	}
	first := records[0]
	wantURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	wantFingerprint := hashFindingFingerprint(oktaPolicyRuleLifecycleTamperingRuleID, wantURN)
	if got := first.Attributes["okta_policy_rule_urn"]; got != wantURN {
		t.Fatalf("attributes[okta_policy_rule_urn] = %q, want %q", got, wantURN)
	}
	if got := first.Fingerprint; got != wantFingerprint {
		t.Fatalf("fingerprint = %q, want hash(rule_id, okta_policy_rule_urn) %q", got, wantFingerprint)
	}
	if got := first.ID; got != wantFingerprint {
		t.Fatalf("ID = %q, want durable fingerprint %q", got, wantFingerprint)
	}

	second := oktaPolicyRuleLifecycleEvent("okta-policy-rule-deactivated-again", "policy.rule.deactivate")
	records, err = rule.Evaluate(context.Background(), runtimeB, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second deactivation) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != first.Fingerprint {
		t.Fatalf("fingerprint = %q, want stable %q across event_id/runtime changes", got, first.Fingerprint)
	}

	deleted := oktaPolicyRuleLifecycleEvent("okta-policy-rule-deleted", "policy.rule.delete")
	records, err = rule.Evaluate(context.Background(), runtimeA, deleted)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(deleted) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != first.Fingerprint {
		t.Fatalf("delete fingerprint = %q, want stable %q", got, first.Fingerprint)
	}

	stateRuntime := &cerebrov1.SourceRuntime{Id: "example-okta-policy-rule", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "policy_rule"}}
	projectedDeactivated := identitySignalEventAt("okta-policy-rule-state-deactivated", "okta", "okta.policy_rule", map[string]string{
		"policy_rule_status": "deactivated",
		"resource_id":        "pol-1",
		"resource_type":      "PolicyRule",
	}, identityTrajectoryBaseTime)
	records, err = rule.Evaluate(context.Background(), stateRuntime, projectedDeactivated)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(projected deactivated state) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != first.Fingerprint {
		t.Fatalf("projected state fingerprint = %q, want stable %q", got, first.Fingerprint)
	}

	activeUpdate := oktaPolicyRuleLifecycleEvent("okta-policy-rule-active-update", "policy.rule.update")
	activeUpdate.Attributes["policy_rule_status"] = "ACTIVE"
	records, err = rule.Evaluate(context.Background(), runtimeA, activeUpdate)
	if err != nil {
		t.Fatalf("Evaluate(active update) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(active update) returned %d findings, want 0 for active policy rule", len(records))
	}

	reactivated := oktaPolicyRuleLifecycleEvent("okta-policy-rule-reactivated", "policy.rule.activate")
	records, err = rule.Evaluate(context.Background(), runtimeA, reactivated)
	if err != nil {
		t.Fatalf("Evaluate(reactivated) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(reactivated) returned %d findings, want 0 once policy rule is active", len(records))
	}
	projectedActive := identitySignalEventAt("okta-policy-rule-state-active", "okta", "okta.policy_rule", map[string]string{
		"policy_rule_status": "active",
		"resource_id":        "pol-1",
		"resource_type":      "PolicyRule",
	}, identityTrajectoryBaseTime.Add(time.Minute))
	records, err = rule.Evaluate(context.Background(), stateRuntime, projectedActive)
	if err != nil {
		t.Fatalf("Evaluate(projected active state) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(projected active state) returned %d findings, want 0 once policy rule is active", len(records))
	}
	openAnchor := counterRule.OpenAnchor(first.Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty, want okta_policy_rule_urn anchor", first.Attributes)
	}
	closeAnchor, closes := counterRule.CloseOnEvent(reactivated)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(reactivated) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}
	closeAnchor, closes = counterRule.CloseOnEvent(projectedActive)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(projected active state) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}
	assertIdentityRuleRemediationTrajectory(t, rule, deactivated, reactivated, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	olderReactivated := oktaPolicyRuleLifecycleEventAt("okta-policy-rule-reactivated-before-open", "policy.rule.activate", identityTrajectoryBaseTime.Add(-time.Minute))
	assertIdentityRuleOlderCloseDoesNotResolveLaterOpen(t, rule, olderReactivated, deactivated)
}

func oktaPolicyRuleLifecycleEvent(id string, eventType string) *cerebrov1.EventEnvelope {
	return oktaPolicyRuleLifecycleEventAt(id, eventType, identityTrajectoryBaseTime)
}

func oktaPolicyRuleLifecycleEventAt(id string, eventType string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	return identitySignalEventAt(id, "okta", "okta.audit", map[string]string{
		"actor_alternate_id": "admin@writer.com",
		"actor_id":           "00u-admin",
		"event_type":         eventType,
		"outcome_result":     "success",
		"resource_id":        "pol-1",
		"resource_type":      "PolicyRule",
	}, occurredAt)
}
