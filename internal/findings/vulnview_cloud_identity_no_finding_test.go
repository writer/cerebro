package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// TestVulnViewCloudIdentityFindingsMatchNoRegisteredFindingRule pins the
// cutover contract (C8): VulnView is the sole detection authority for
// cloud-identity excess-privilege and shared-principal posture. The
// vulnview.finding events Cerebro ingests for source=cloud_identity are
// evidence and graph context only -- the full registered finding-rule
// engine must never re-derive a Cerebro finding from them.
func TestVulnViewCloudIdentityFindingsMatchNoRegisteredFindingRule(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-finding-cloud-identity", SourceId: "vulnview", TenantId: "writer", Config: map[string]string{"family": "finding", "source": "cloud_identity"}}
	events := []*cerebrov1.EventEnvelope{
		{
			Id: "event-finding-1", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.finding",
			Payload: []byte(`{}`),
			Attributes: map[string]string{
				"finding_id": "cloud_identity|cloud_identity_excess_privilege|aws|arn:aws:iam::222222222222:role/billing-worker|writer",
				"source":     "cloud_identity", "check_id": "cloud_identity_excess_privilege", "status": "open", "severity": "critical",
				"resource_provider": "aws", "resource_account": "222222222222", "principal_id": "arn:aws:iam::222222222222:role/billing-worker",
				"cohort_scope": "writer", "family": "finding", "version": "1", "updated_at": "2026-11-02T10:00:00Z",
			},
		},
	}

	for _, event := range events {
		t.Run(event.GetKind(), func(t *testing.T) {
			for _, rule := range Builtin().ForRuntime(runtime) {
				records, err := rule.Evaluate(context.Background(), runtime, event)
				if err != nil {
					continue // a rule returning a decode/no-op error for a foreign event shape is not a match.
				}
				if len(records) != 0 {
					t.Fatalf("rule %q emitted %d finding(s) for %s (source=cloud_identity), want 0", rule.Spec().GetId(), len(records), event.GetKind())
				}
			}
		})
	}
}
