package findings

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestOktaPolicyRuleLifecycleTamperingFingerprintIsTenantRuntimeScoped(t *testing.T) {
	event := &cerebrov1.EventEnvelope{
		Id:         "okta-event-1",
		TenantId:   "writer",
		SourceId:   "okta",
		Kind:       "okta.audit",
		OccurredAt: timestamppb.Now(),
		Attributes: map[string]string{
			"actor_alternate_id": "admin@writer.com",
			"actor_id":           "00u-admin",
			"event_type":         "policy.rule.update",
			"outcome_result":     "success",
			"resource_id":        "rule-1",
			"resource_type":      "policy_rule",
		},
	}
	first, err := oktaPolicyRuleLifecycleTamperingFinding(context.Background(), event, "runtime-a")
	if err != nil {
		t.Fatalf("oktaPolicyRuleLifecycleTamperingFinding() error = %v", err)
	}
	second, err := oktaPolicyRuleLifecycleTamperingFinding(context.Background(), event, "runtime-b")
	if err != nil {
		t.Fatalf("oktaPolicyRuleLifecycleTamperingFinding() error = %v", err)
	}
	if first.Fingerprint == second.Fingerprint {
		t.Fatalf("fingerprint = %q for both runtimes, want runtime-scoped values", first.Fingerprint)
	}
}
