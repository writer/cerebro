package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// TestVulnViewCloudIdentityEventsMatchNoRegisteredFindingRule pins the
// cutover contract: VulnView is the sole detection authority for
// cloud-identity excess-privilege and shared-principal posture. The
// vulnview.cloud_identity_finding/_run/_assessment events Cerebro ingests
// are evidence and graph context only -- the full registered finding-rule
// engine must never re-derive a Cerebro finding from them.
func TestVulnViewCloudIdentityEventsMatchNoRegisteredFindingRule(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-cloud-identity", SourceId: "vulnview", TenantId: "writer", Config: map[string]string{"family": "cloud_identity_finding"}}
	events := []*cerebrov1.EventEnvelope{
		{
			Id: "event-finding-1", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.cloud_identity_finding",
			Payload: []byte(`{}`),
			Attributes: map[string]string{
				"finding_id": "cloud_identity|cloud_identity_excess_privilege|aws|arn:aws:iam::222222222222:role/billing-worker|writer",
				"check_id":   "cloud_identity_excess_privilege", "status": "open", "severity": "critical",
				"cloud_provider": "aws", "principal_id": "arn:aws:iam::222222222222:role/billing-worker",
				"cohort_scope": "writer", "family": "cloud_identity_finding",
			},
		},
		{
			Id: "event-run-1", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.cloud_identity_run",
			Payload: []byte(`{}`),
			Attributes: map[string]string{
				"scan_id": "scan-1", "run_id": "run-1", "cohort_scope": "writer", "authoritative": "true",
				"family": "cloud_identity_assessment",
			},
		},
		{
			Id: "event-assessment-1", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.cloud_identity_assessment",
			Payload: []byte(`{}`),
			Attributes: map[string]string{
				"scan_id": "scan-1", "run_id": "run-1", "check_id": "cloud_identity_excess_privilege",
				"status": "supported", "severity": "critical", "cohort_scope": "writer", "family": "cloud_identity_assessment",
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
					t.Fatalf("rule %q emitted %d finding(s) for %s, want 0", rule.Spec().GetId(), len(records), event.GetKind())
				}
			}
		})
	}
}
