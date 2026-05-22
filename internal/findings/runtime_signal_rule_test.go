package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestRuntimeActiveThreatEvidenceRule(t *testing.T) {
	rule := newRuntimeActiveThreatEvidenceRule()
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-prod", SourceId: "runtime", TenantId: "example"}
	event := &cerebrov1.EventEnvelope{
		Id:       "runtime-evidence-1",
		TenantId: "example",
		SourceId: "runtime",
		Kind:     "runtime.evidence",
		Attributes: map[string]string{
			"confidence":    "0.92",
			"evidence_id":   "evidence-1",
			"evidence_type": "credential_use",
			"resource_urn":  "urn:cerebro:example:kubernetes_workload:prod-cluster:payments:workload-1",
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
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:example:runtime_evidence:evidence-1")

	benign := &cerebrov1.EventEnvelope{Id: "runtime-evidence-benign", TenantId: "example", SourceId: "runtime", Kind: "runtime.evidence", Attributes: map[string]string{"confidence": "0.2", "evidence_type": "process_exec", "verdict": "benign"}}
	records, err = rule.Evaluate(context.Background(), runtime, benign)
	if err != nil {
		t.Fatalf("Evaluate(benign) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(benign records) = %d, want 0", len(records))
	}

	inactive := &cerebrov1.EventEnvelope{Id: "runtime-evidence-inactive", TenantId: "example", SourceId: "runtime", Kind: "runtime.evidence", Attributes: map[string]string{"confidence": "0.2", "evidence_type": "credential_use", "verdict": "inactive"}}
	records, err = rule.Evaluate(context.Background(), runtime, inactive)
	if err != nil {
		t.Fatalf("Evaluate(inactive) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(inactive records) = %d, want 0", len(records))
	}

	activeRisky := &cerebrov1.EventEnvelope{Id: "runtime-evidence-active", TenantId: "example", SourceId: "runtime", Kind: "runtime.evidence", Attributes: map[string]string{"confidence": "0.2", "evidence_type": "credential_use", "verdict": "active"}}
	records, err = rule.Evaluate(context.Background(), runtime, activeRisky)
	if err != nil {
		t.Fatalf("Evaluate(active) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(active records) = %d, want 1", len(records))
	}

	missingEvidenceType := &cerebrov1.EventEnvelope{Id: "runtime-evidence-missing-evidence-type", TenantId: "example", SourceId: "runtime", Kind: "runtime.evidence", Attributes: map[string]string{"confidence": "0.92", "verdict": "malicious"}}
	records, err = rule.Evaluate(context.Background(), runtime, missingEvidenceType)
	if err != nil {
		t.Fatalf("Evaluate(missing evidence_type) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(missing evidence_type records) = %d, want 0", len(records))
	}
}
