package findings

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestCoordinationGraphRuleSupportsRuntime(t *testing.T) {
	rule := newGRCSourceConcentratedOpenFindingsRule()
	if !rule.SupportsRuntime(&cerebrov1.SourceRuntime{TenantId: "writer", SourceId: "grc", Config: map[string]string{"family": "integration"}}) {
		t.Fatal("SupportsRuntime(grc integration) = false, want true")
	}
	if rule.SupportsRuntime(&cerebrov1.SourceRuntime{TenantId: "writer", SourceId: "grc", Config: map[string]string{"family": "document"}}) {
		t.Fatal("SupportsRuntime(grc document) = true, want false")
	}
}

func TestCoordinationGraphRuleQueryRequiresTenant(t *testing.T) {
	rule := newResourceMultipleOpenFindingsRule().(GraphRule)
	if got := rule.QueryFor(&cerebrov1.SourceRuntime{}); got.Query != "" {
		t.Fatalf("QueryFor(runtime without tenant) = %q, want empty", got.Query)
	}
	query := rule.QueryFor(&cerebrov1.SourceRuntime{TenantId: "writer"})
	if query.Query == "" {
		t.Fatal("QueryFor(runtime with tenant) returned empty query")
	}
	if query.Params["tenant_id"] != "writer" {
		t.Fatalf("tenant_id param = %#v, want writer", query.Params["tenant_id"])
	}
	if !strings.Contains(query.Query, "LIMIT $row_limit") {
		t.Fatalf("query missing LIMIT $row_limit: %s", query.Query)
	}
}

func TestCoordinationGraphRuleEvaluateRowsBuildsFinding(t *testing.T) {
	rule := newGRCSourceConcentratedOpenFindingsRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc-integration", TenantId: "writer", SourceId: "grc", Config: map[string]string{"family": "integration"}}

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{{Values: map[string]any{
		"primary_urn":     "urn:cerebro:writer:source:vanta:integration:aws",
		"primary_label":   "AWS",
		"primary_type":    "source",
		"fingerprint_key": "urn:cerebro:writer:source:vanta:integration:aws",
		"severity":        "HIGH",
		"summary":         "Source integration has 5 open finding(s)",
		"action":          "Prioritize remediation at the source integration level",
		"resource_urns": []any{
			"urn:cerebro:writer:source:vanta:integration:aws",
			"urn:cerebro:writer:finding:one",
		},
		"evidence": []any{map[string]any{
			"urn":             "urn:cerebro:writer:finding:one",
			"label":           "Finding One",
			"entity_type":     "finding",
			"relation":        "has_finding",
			"attributes_json": `{"status":"open","rule_id":"example"}`,
		}},
	}}})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.RuleID != "grc-source-integration-concentrated-open-findings" || finding.Severity != "HIGH" || finding.Status != findingStatusOpen {
		t.Fatalf("finding metadata = %#v", finding)
	}
	if finding.Attributes["primary_resource_urn"] != "urn:cerebro:writer:source:vanta:integration:aws" {
		t.Fatalf("primary_resource_urn = %q", finding.Attributes["primary_resource_urn"])
	}
	if len(finding.ResourceURNs) != 2 {
		t.Fatalf("ResourceURNs = %#v, want primary and evidence", finding.ResourceURNs)
	}
	if len(finding.GraphEvidenceRows) != 1 {
		t.Fatalf("len(GraphEvidenceRows) = %d, want 1", len(finding.GraphEvidenceRows))
	}
}

func TestCoordinationGraphRulesAreRegistered(t *testing.T) {
	registry := Builtin()
	for _, id := range []string{
		"grc-source-integration-concentrated-open-findings",
		"grc-failing-control-test-unhealthy-integration",
		"grc-control-missing-evidence-coverage",
		"grc-document-needs-owner-or-upload",
		"grc-isolated-target-enrichment-gap",
		"finding-isolated-open-anchor",
		"graph-resource-multiple-open-findings",
	} {
		if _, ok := registry.Get(id); !ok {
			t.Fatalf("Builtin() missing rule %s", id)
		}
	}
}
