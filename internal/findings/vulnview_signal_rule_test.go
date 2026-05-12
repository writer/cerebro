package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestVulnViewActionableExternalFindingRule(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-vulnerability", SourceId: "vulnview", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "vulnview-vuln-1",
		TenantId: "writer",
		SourceId: "vulnview",
		Kind:     "vulnview.vulnerability",
		Attributes: map[string]string{
			"external_id": "scan-1:exposed-panel:admin.writer.com",
			"host":        "admin.writer.com",
			"matched_at":  "https://admin.writer.com",
			"name":        "Exposed Admin Panel",
			"severity":    "high",
			"target_id":   "admin.writer.com",
			"template_id": "exposed-panel",
		},
	}
	findings, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(Evaluate()) = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.RuleID != vulnViewActionableExternalFindingRuleID {
		t.Fatalf("RuleID = %q, want %q", finding.RuleID, vulnViewActionableExternalFindingRuleID)
	}
	if finding.Severity != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH", finding.Severity)
	}
	if finding.PolicyID != "exposed-panel" {
		t.Fatalf("PolicyID = %q, want exposed-panel", finding.PolicyID)
	}
}

func TestVulnViewActionableExternalFindingRuleIgnoresInfo(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	findings, err := rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "writer-vulnview", SourceId: "vulnview", TenantId: "writer"}, &cerebrov1.EventEnvelope{
		Id:       "vulnview-info-1",
		TenantId: "writer",
		SourceId: "vulnview",
		Kind:     "vulnview.vulnerability",
		Attributes: map[string]string{
			"name":     "Technology Detection",
			"severity": "info",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("len(Evaluate()) = %d, want 0", len(findings))
	}
}
