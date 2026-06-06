package findings

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestSentinelOneEndpointActiveInfectionGraphRuleAggregatesThreats(t *testing.T) {
	rule := newSentinelOneEndpointActiveInfectionRule()
	graphRule, ok := rule.(GraphRule)
	if !ok {
		t.Fatalf("newSentinelOneEndpointActiveInfectionRule() is not a GraphRule")
	}
	runtime := &cerebrov1.SourceRuntime{Id: "writer-sentinelone-threat", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "threat"}}
	rows := []ports.CypherRow{sentinelOneInfectionRow("agent-1", "mac-1", map[string]string{
		"agent_id":       "agent-1",
		"computer_name":  "mac-1",
		"is_infected":    "true",
		"active_threats": "2",
		"site_id":        "site-1",
		"site_name":      "Default site",
		"group_id":       "group-1",
		"group_name":     "Default Group",
	}, []map[string]string{
		{
			"threat_id":         "threat-1",
			"threat_name":       "malware-a",
			"incident_status":   "unresolved",
			"mitigation_status": "not_mitigated",
			"classification":    "Malware",
			"event_id":          "event-threat-1",
		},
		{
			"threat_id":         "threat-2",
			"threat_name":       "malware-b",
			"incident_status":   "unresolved",
			"mitigation_status": "not_mitigated",
			"classification":    "General",
			"event_id":          "event-threat-2",
		},
	})}
	findings, err := graphRule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if got := len(findings); got != 1 {
		t.Fatalf("len(findings) = %d, want 1", got)
	}
	finding := findings[0]
	if finding.RuleID != sentinelOneEndpointActiveInfectionRuleID {
		t.Fatalf("RuleID = %q", finding.RuleID)
	}
	if finding.Severity != "CRITICAL" {
		t.Fatalf("Severity = %q, want CRITICAL", finding.Severity)
	}
	if got := finding.Attributes["active_threat_count"]; got != "2" {
		t.Fatalf("active_threat_count = %q, want 2", got)
	}
	if got := len(finding.GraphEvidenceRows); got != 2 {
		t.Fatalf("len(GraphEvidenceRows) = %d, want 2", got)
	}
	if !containsString(finding.EventIDs, "event-threat-1") || !containsString(finding.EventIDs, "event-threat-2") {
		t.Fatalf("EventIDs = %#v, want both threat events", finding.EventIDs)
	}
}

func TestSentinelOneEndpointActiveInfectionGraphRuleSkipsCleanMitigatedAgent(t *testing.T) {
	graphRule := newSentinelOneEndpointActiveInfectionRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-sentinelone-threat", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "threat"}}
	rows := []ports.CypherRow{sentinelOneInfectionRow("agent-1", "mac-1", map[string]string{
		"agent_id":       "agent-1",
		"computer_name":  "mac-1",
		"is_infected":    "false",
		"active_threats": "0",
	}, []map[string]string{
		{
			"threat_id":         "threat-1",
			"threat_name":       "malware-a",
			"incident_status":   "resolved",
			"mitigation_status": "mitigated",
			"classification":    "Malware",
		},
	})}
	findings, err := graphRule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestSentinelOneEndpointActiveInfectionGraphRuleRequiresInfectionEvidence(t *testing.T) {
	graphRule := newSentinelOneEndpointActiveInfectionRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-sentinelone-threat", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "threat"}}
	rows := []ports.CypherRow{sentinelOneInfectionRow("agent-1", "mac-1", map[string]string{
		"agent_id":       "agent-1",
		"computer_name":  "mac-1",
		"is_infected":    "false",
		"active_threats": "0",
	}, []map[string]string{
		{
			"threat_id":         "threat-1",
			"threat_name":       "suspicious-a",
			"incident_status":   "unresolved",
			"mitigation_status": "not_mitigated",
			"classification":    "Suspicious",
			"is_infected":       "false",
			"active_threats":    "0",
		},
	})}
	findings, err := graphRule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestSentinelOneEndpointActiveInfectionFingerprintIsStableAcrossRuntimes(t *testing.T) {
	graphRule := newSentinelOneEndpointActiveInfectionRule().(GraphRule)
	rows := []ports.CypherRow{sentinelOneInfectionRow("agent-1", "mac-1", map[string]string{
		"agent_id":       "agent-1",
		"computer_name":  "mac-1",
		"is_infected":    "true",
		"active_threats": "1",
	}, []map[string]string{
		{"threat_id": "threat-1", "threat_name": "malware-a", "incident_status": "unresolved", "mitigation_status": "not_mitigated"},
	})}
	threatRuntime := &cerebrov1.SourceRuntime{Id: "writer-sentinelone-threat", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "threat"}}
	agentRuntime := &cerebrov1.SourceRuntime{Id: "writer-sentinelone-agent", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "agent"}}
	first, err := graphRule.EvaluateRows(context.Background(), threatRuntime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows(threat) error = %v", err)
	}
	second, err := graphRule.EvaluateRows(context.Background(), agentRuntime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows(agent) error = %v", err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("finding counts = %d/%d, want 1/1", len(first), len(second))
	}
	if first[0].ID != second[0].ID {
		t.Fatalf("finding IDs differ across runtimes: %q/%q", first[0].ID, second[0].ID)
	}
	if first[0].RuntimeID == second[0].RuntimeID {
		t.Fatalf("RuntimeID should reflect triggering runtime before store pinning")
	}
}

func TestSentinelOneAgentStaleGraphRuleGroupsByScopeAndBucket(t *testing.T) {
	graphRule := newSentinelOneAgentStaleRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-sentinelone-agent", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "agent"}}
	now := time.Now().UTC()
	rows := []ports.CypherRow{
		sentinelOneStaleAgentRow("agent-1", "mac-1", now.Add(-45*24*time.Hour), map[string]string{"group_id": "group-1", "group_name": "Default Group"}),
		sentinelOneStaleAgentRow("agent-2", "mac-2", now.Add(-60*24*time.Hour), map[string]string{"group_id": "group-1", "group_name": "Default Group"}),
		sentinelOneStaleAgentRow("agent-recent", "mac-recent", now.Add(-2*24*time.Hour), map[string]string{"group_id": "group-1", "group_name": "Default Group"}),
		sentinelOneStaleAgentRow("agent-retired", "mac-retired", now.Add(-80*24*time.Hour), map[string]string{"group_id": "group-1", "group_name": "Default Group", "is_decommissioned": "true"}),
	}
	findings, err := graphRule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if got := len(findings); got != 1 {
		t.Fatalf("len(findings) = %d, want 1", got)
	}
	finding := findings[0]
	if finding.Severity != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH", finding.Severity)
	}
	if got := finding.Attributes["agent_count"]; got != "2" {
		t.Fatalf("agent_count = %q, want 2", got)
	}
	if got := finding.Attributes["staleness_bucket"]; got != "stale_31_90d" {
		t.Fatalf("staleness_bucket = %q, want stale_31_90d", got)
	}
	if got := len(finding.ResourceURNs); got != 1 {
		t.Fatalf("len(ResourceURNs) = %d, want grouped scope only", got)
	}
	if !strings.Contains(finding.ResourceURNs[0], "sentinelone_group:group-1") {
		t.Fatalf("ResourceURNs = %#v, want group scope", finding.ResourceURNs)
	}
	if got := len(finding.GraphEvidenceRows); got != 2 {
		t.Fatalf("len(GraphEvidenceRows) = %d, want 2", got)
	}
}

//nolint:unparam // Helper keeps agent ID explicit in SentinelOne row fixtures.
func sentinelOneInfectionRow(agentID string, agentLabel string, agentAttrs map[string]string, threats []map[string]string) ports.CypherRow {
	threatRows := make([]any, 0, len(threats))
	for _, threat := range threats {
		threatID := threat["threat_id"]
		threatRows = append(threatRows, map[string]any{
			"urn":                      "urn:cerebro:writer:sentinelone_threat:" + threatID,
			"label":                    firstNonEmpty(threat["threat_name"], threatID),
			"entity_type":              sentinelOneThreatEntityType,
			"attributes_json":          sentinelOneTestJSON(threat),
			"affected_attributes_json": sentinelOneTestJSON(threat),
		})
	}
	return ports.CypherRow{Values: map[string]any{
		"agent_urn":             "urn:cerebro:writer:sentinelone_agent:" + agentID,
		"agent_label":           agentLabel,
		"agent_attributes_json": sentinelOneTestJSON(agentAttrs),
		"threats":               threatRows,
	}}
}

func sentinelOneStaleAgentRow(agentID string, label string, lastActive time.Time, overrides map[string]string) ports.CypherRow {
	attrs := map[string]string{
		"agent_id":          agentID,
		"computer_name":     label,
		"last_active_date":  lastActive.UTC().Format(time.RFC3339),
		"is_decommissioned": "false",
		"is_uninstalled":    "false",
	}
	for key, value := range overrides {
		attrs[key] = value
	}
	return ports.CypherRow{Values: map[string]any{
		"agent_urn":             "urn:cerebro:writer:sentinelone_agent:" + agentID,
		"agent_label":           label,
		"agent_attributes_json": sentinelOneTestJSON(attrs),
	}}
}

func sentinelOneTestJSON(values map[string]string) string {
	payload, err := json.Marshal(values)
	if err != nil {
		panic(err)
	}
	return string(payload)
}
