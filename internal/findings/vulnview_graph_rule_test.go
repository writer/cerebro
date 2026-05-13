package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestVulnViewExternalAssetConcentratedSignalGraphRuleAggregatesRepeatedEvidence(t *testing.T) {
	graphRule := newVulnViewExternalAssetConcentratedSignalRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-dns-alert", SourceId: "vulnview", TenantId: "writer"}
	rows := []ports.CypherRow{vulnViewAssetEvidenceRow("urn:cerebro:writer:external_asset:app.writer.com", "app.writer.com", []map[string]string{
		{"urn": "urn:cerebro:writer:vulnview_finding:f1", "entity_type": "vulnview.finding", "label": "open-port", "severity": "info", "template_id": "open-port", "event_id": "e1"},
		{"urn": "urn:cerebro:writer:vulnview_finding:f2", "entity_type": "vulnview.finding", "label": "open-port", "severity": "info", "template_id": "open-port", "event_id": "e2"},
		{"urn": "urn:cerebro:writer:vulnview_finding:f3", "entity_type": "vulnview.finding", "label": "open-port", "severity": "info", "template_id": "open-port", "event_id": "e3"},
		{"urn": "urn:cerebro:writer:vulnview_dns_alert:d1", "entity_type": "vulnview.dns_alert", "label": "stale-a-record", "severity": "info", "alert": "stale-a-record", "event_id": "e4"},
		{"urn": "urn:cerebro:writer:vulnview_dns_alert:d2", "entity_type": "vulnview.dns_alert", "label": "tls-mismatch", "severity": "info", "alert": "tls-mismatch", "event_id": "e5"},
	})}

	findings, err := graphRule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.RuleID != vulnViewExternalAssetConcentratedSignalRuleID {
		t.Fatalf("RuleID = %q", finding.RuleID)
	}
	if finding.Severity != "MEDIUM" {
		t.Fatalf("Severity = %q, want MEDIUM", finding.Severity)
	}
	if got := finding.Attributes["evidence_count"]; got != "5" {
		t.Fatalf("evidence_count = %q, want 5", got)
	}
	if len(finding.EventIDs) != 5 {
		t.Fatalf("len(EventIDs) = %d, want 5", len(finding.EventIDs))
	}
	if len(finding.GraphEvidenceRows) != 5 {
		t.Fatalf("len(GraphEvidenceRows) = %d, want 5", len(finding.GraphEvidenceRows))
	}
}

func TestVulnViewExternalAssetConcentratedSignalGraphRuleSupportsEvidenceRuntimesOnly(t *testing.T) {
	rule := newVulnViewExternalAssetConcentratedSignalRule()
	if !rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "vulnview", Config: map[string]string{"family": "vulnerability"}}) {
		t.Fatal("SupportsRuntime(vulnerability) = false, want true")
	}
	if !rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "vulnview", Config: map[string]string{"family": "dns_alert"}}) {
		t.Fatal("SupportsRuntime(dns_alert) = false, want true")
	}
	if rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "vulnview", Config: map[string]string{"family": "asset"}}) {
		t.Fatal("SupportsRuntime(asset) = true, want false")
	}
	if rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "vulnview", Config: map[string]string{"family": "scan"}}) {
		t.Fatal("SupportsRuntime(scan) = true, want false")
	}
}

func TestVulnViewExternalAssetConcentratedSignalGraphRuleFiltersBeforeLimit(t *testing.T) {
	graphRule := newVulnViewExternalAssetConcentratedSignalRule().(GraphRule)
	request := graphRule.QueryFor(&cerebrov1.SourceRuntime{SourceId: "vulnview", TenantId: "writer", Config: map[string]string{"family": "vulnerability"}})
	if !strings.Contains(request.Query, "WHERE evidence_count >= $evidence_threshold OR max_severity_rank >= $severity_threshold") {
		t.Fatalf("QueryFor() does not qualify rows before LIMIT:\n%s", request.Query)
	}
	if got := request.Params["evidence_threshold"]; got != int64(vulnViewConcentratedEvidenceThreshold) {
		t.Fatalf("evidence_threshold = %v", got)
	}
	if got := request.Params["severity_threshold"]; got != int64(vulnViewSeverityRank("MEDIUM")) {
		t.Fatalf("severity_threshold = %v", got)
	}
}

func TestVulnViewExternalAssetConcentratedSignalGraphRuleEmitsMediumEvidence(t *testing.T) {
	graphRule := newVulnViewExternalAssetConcentratedSignalRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-vulnerability", SourceId: "vulnview", TenantId: "writer"}
	rows := []ports.CypherRow{vulnViewAssetEvidenceRow("urn:cerebro:writer:external_asset:api.writer.com", "api.writer.com", []map[string]string{
		{"urn": "urn:cerebro:writer:vulnview_finding:f1", "entity_type": "vulnview.finding", "label": "open-port", "severity": "medium", "template_id": "open-port", "event_id": "e1"},
	})}

	findings, err := graphRule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Severity != "MEDIUM" {
		t.Fatalf("Severity = %q, want MEDIUM", findings[0].Severity)
	}
}

func TestVulnViewExternalAssetConcentratedSignalGraphRuleSkipsSparseInfoEvidence(t *testing.T) {
	graphRule := newVulnViewExternalAssetConcentratedSignalRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-dns-alert", SourceId: "vulnview", TenantId: "writer"}
	rows := []ports.CypherRow{vulnViewAssetEvidenceRow("urn:cerebro:writer:external_asset:info.writer.com", "info.writer.com", []map[string]string{
		{"urn": "urn:cerebro:writer:vulnview_dns_alert:d1", "entity_type": "vulnview.dns_alert", "label": "ip-geo-info", "severity": "info", "alert": "ip-geo-info", "event_id": "e1"},
	})}

	findings, err := graphRule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestVulnViewExternalAssetConcentratedSignalGraphRuleSkipsMissingSeverity(t *testing.T) {
	graphRule := newVulnViewExternalAssetConcentratedSignalRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-dns-alert", SourceId: "vulnview", TenantId: "writer"}
	rows := []ports.CypherRow{vulnViewAssetEvidenceRow("urn:cerebro:writer:external_asset:unknown.writer.com", "unknown.writer.com", []map[string]string{
		{"urn": "urn:cerebro:writer:vulnview_dns_alert:d1", "entity_type": "vulnview.dns_alert", "label": "unknown-alert", "alert": "unknown-alert", "event_id": "e1"},
	})}

	findings, err := graphRule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func vulnViewAssetEvidenceRow(assetURN string, assetLabel string, evidence []map[string]string) ports.CypherRow {
	items := make([]any, 0, len(evidence))
	for _, item := range evidence {
		attrs := map[string]string{}
		edgeAttrs := map[string]string{}
		for key, value := range item {
			switch key {
			case "urn", "entity_type", "label":
			case "event_id":
				edgeAttrs[key] = value
			default:
				attrs[key] = value
			}
		}
		payload, _ := json.Marshal(attrs)
		edgePayload, _ := json.Marshal(edgeAttrs)
		items = append(items, map[string]any{
			"urn":                      item["urn"],
			"entity_type":              item["entity_type"],
			"label":                    item["label"],
			"attributes_json":          string(payload),
			"evidence_attributes_json": string(edgePayload),
		})
	}
	assetPayload, _ := json.Marshal(map[string]string{"asset_id": assetLabel})
	return ports.CypherRow{Values: map[string]any{
		"asset_urn":             assetURN,
		"asset_label":           assetLabel,
		"asset_attributes_json": string(assetPayload),
		"evidence":              items,
		"debug":                 fmt.Sprintf("%d evidence", len(evidence)),
	}}
}
