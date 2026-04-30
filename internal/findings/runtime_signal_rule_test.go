package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestRuntimeActiveThreatEvidenceRule(t *testing.T) {
	rule := newRuntimeActiveThreatEvidenceRule()
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-prod", SourceId: "runtime", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "runtime-evidence-1",
		TenantId: "writer",
		SourceId: "runtime",
		Kind:     "runtime.evidence",
		Attributes: map[string]string{
			"confidence":    "0.92",
			"evidence_id":   "evidence-1",
			"evidence_type": "credential_use",
			"resource_urn":  "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:workload-1",
			"verdict":       "confirmed",
		},
	}
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:runtime_evidence:evidence-1")

	benign := &cerebrov1.EventEnvelope{Id: "runtime-evidence-benign", TenantId: "writer", SourceId: "runtime", Kind: "runtime.evidence", Attributes: map[string]string{"confidence": "0.2", "evidence_type": "process_exec", "verdict": "benign"}}
	records, err = rule.Evaluate(context.Background(), runtime, benign)
	if err != nil {
		t.Fatalf("Evaluate(benign) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(benign records) = %d, want 0", len(records))
	}
}
