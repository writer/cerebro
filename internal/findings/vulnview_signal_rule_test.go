package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestVulnViewActionableExternalFindingRule(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	runtime := &cerebrov1.SourceRuntime{Id: "example-vulnview-vulnerability", SourceId: "vulnview", TenantId: "example"}
	event := &cerebrov1.EventEnvelope{
		Id:       "vulnview-vuln-1",
		TenantId: "example",
		SourceId: "vulnview",
		Kind:     "vulnview.vulnerability",
		Attributes: map[string]string{
			"external_id": "scan-1:exposed-panel:admin.example.com",
			"host":        "admin.example.com",
			"matched_at":  "https://admin.example.com",
			"name":        "Exposed Admin Panel",
			"severity":    "high",
			"target_id":   "admin.example.com",
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
	if finding.Attributes["target"] != "admin.example.com" {
		t.Fatalf("target = %q, want admin.example.com", finding.Attributes["target"])
	}
	if finding.Attributes["primary_resource_urn"] != "urn:cerebro:example:external_asset:admin.example.com" {
		t.Fatalf("primary_resource_urn = %q, want external asset", finding.Attributes["primary_resource_urn"])
	}
}

func TestVulnViewActionableExternalFindingRuleIgnoresInfo(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	findings, err := rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "example-vulnview", SourceId: "vulnview", TenantId: "example"}, &cerebrov1.EventEnvelope{
		Id:       "vulnview-info-1",
		TenantId: "example",
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

func TestVulnViewActionableExternalFindingRuleSplitsMatchedLocations(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	runtime := &cerebrov1.SourceRuntime{Id: "example-vulnview-vulnerability", SourceId: "vulnview", TenantId: "example"}
	base := &cerebrov1.EventEnvelope{
		Id:       "vulnview-vuln-1",
		TenantId: "example",
		SourceId: "vulnview",
		Kind:     "vulnview.vulnerability",
		Attributes: map[string]string{
			"host":        "app.example.com",
			"matched_at":  "https://app.example.com/login",
			"name":        "Test CVE",
			"severity":    "high",
			"target_id":   "app.example.com",
			"template_id": "cve-2026-1234",
		},
	}
	first, err := rule.Evaluate(context.Background(), runtime, base)
	if err != nil {
		t.Fatalf("Evaluate(first) error = %v", err)
	}
	base.Id = "vulnview-vuln-2"
	base.Attributes["matched_at"] = "https://app.example.com/admin"
	second, err := rule.Evaluate(context.Background(), runtime, base)
	if err != nil {
		t.Fatalf("Evaluate(second) error = %v", err)
	}
	if first[0].ID == second[0].ID {
		t.Fatalf("finding IDs matched for distinct matched_at values: %q", first[0].ID)
	}
}
