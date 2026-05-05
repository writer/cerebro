package builders

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestBuilderBuildsSentinelOneGraph(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, name, state, account_id, account_name, license_type, total_licenses, active_licenses, created_at FROM sentinelone_sites`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":           "site-1",
			"name":         "Default site",
			"state":        "active",
			"account_id":   "acct-1",
			"account_name": "Acme",
		}},
	})
	source.setResult(`SELECT id, uuid, computer_name, external_ip, internal_ip, os_name, os_type, os_version, agent_version, is_active, is_infected, is_up_to_date, network_status, scan_status, threat_reboot_required, last_active_date, registered_at, site_id, site_name, group_id, group_name, machine_type, domain, encrypted_applications, firewall_enabled FROM sentinelone_agents`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":            "agent-1",
			"uuid":          "uuid-1",
			"computer_name": "host-1",
			"os_name":       "macOS",
			"os_type":       "macos",
			"agent_version": "25.3.1",
			"is_active":     true,
			"is_infected":   false,
			"is_up_to_date": true,
			"site_id":       "site-1",
			"site_name":     "Default site",
		}},
	})
	source.setResult(`SELECT id, agent_id, agent_computer_name, threat_name, classification, classification_source, confidence_level, analyst_verdict, incident_status, mitigation_status, initiated_by, file_path, file_sha256, file_sha1, file_md5, mitre_tactics, mitre_techniques, created_at, updated_at FROM sentinelone_threats`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                "threat-1",
			"agent_id":          "agent-1",
			"threat_name":       "EICAR",
			"classification":    "Malware",
			"mitigation_status": "not_mitigated",
		}},
	})
	source.setResult(`SELECT id, activity_type, activity_description, primary_description, secondary_description, user_id, agent_id, site_id, threat_id, created_at FROM sentinelone_activities`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                  "activity-1",
			"activity_type":       2004,
			"primary_description": "Agent quarantined threat",
			"agent_id":            "agent-1",
			"site_id":             "site-1",
			"threat_id":           "threat-1",
		}},
	})
	source.setResult(`SELECT id, agent_id, name, version, publisher, size, installed_date, type, risk_level FROM sentinelone_applications`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":         "agent-1|Chrome|1.2.3|Google",
			"agent_id":   "agent-1",
			"name":       "Chrome",
			"version":    "1.2.3",
			"publisher":  "Google",
			"risk_level": "low",
		}},
	})
	source.setResult(`SELECT id, cve_id, agent_id, site_id, endpoint_name, application_name, application_version, severity, status, cvss_score, exploited_in_wild, days_since_detection, remediation_action, detected_at FROM sentinelone_vulnerabilities`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                   "agent-1|CVE-2026-0001|Chrome|1.2.3",
			"cve_id":               "CVE-2026-0001",
			"agent_id":             "agent-1",
			"site_id":              "site-1",
			"application_name":     "Chrome",
			"application_version":  "1.2.3",
			"severity":             "HIGH",
			"status":               "Detected",
			"cvss_score":           "7.8",
			"days_since_detection": 31,
		}},
	})
	source.setResult(`SELECT id, site_id, site_name FROM sentinelone_agents`, &DataQueryResult{Rows: []map[string]any{{"id": "agent-1", "site_id": "site-1", "site_name": "Default site"}}})
	source.setResult(`SELECT id, agent_id, name, version FROM sentinelone_applications`, &DataQueryResult{Rows: []map[string]any{{"id": "agent-1|Chrome|1.2.3|Google", "agent_id": "agent-1", "name": "Chrome", "version": "1.2.3"}}})
	source.setResult(`SELECT id, cve_id, agent_id, application_name, application_version, severity, status FROM sentinelone_vulnerabilities`, &DataQueryResult{Rows: []map[string]any{{"id": "agent-1|CVE-2026-0001|Chrome|1.2.3", "cve_id": "CVE-2026-0001", "agent_id": "agent-1", "application_name": "Chrome", "application_version": "1.2.3", "severity": "HIGH", "status": "Detected"}}})
	source.setResult(`SELECT id, agent_id, threat_name, classification, mitigation_status, incident_status FROM sentinelone_threats`, &DataQueryResult{Rows: []map[string]any{{"id": "threat-1", "agent_id": "agent-1", "threat_name": "EICAR", "classification": "Malware", "mitigation_status": "not_mitigated"}}})
	source.setResult(`SELECT id, agent_id, threat_id, site_id, activity_type, created_at FROM sentinelone_activities`, &DataQueryResult{Rows: []map[string]any{{"id": "activity-1", "agent_id": "agent-1", "threat_id": "threat-1", "site_id": "site-1", "activity_type": 2004}}})

	builder := NewBuilder(source, logger)
	if err := builder.Build(ctx); err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	g := builder.Graph()

	siteID := sentinelOneSiteNodeID("site-1")
	agentID := sentinelOneAgentNodeID("agent-1")
	appID := sentinelOneApplicationNodeID("agent-1|Chrome|1.2.3|Google")
	vulnID := sentinelOneVulnerabilityNodeID("agent-1|CVE-2026-0001|Chrome|1.2.3")
	threatID := sentinelOneThreatNodeID("threat-1")
	activityID := sentinelOneActivityNodeID("activity-1")

	for _, expected := range []struct {
		id   string
		kind NodeKind
	}{
		{siteID, NodeKindOrganization},
		{agentID, NodeKindInstance},
		{appID, NodeKindPackage},
		{vulnID, NodeKindVulnerability},
		{threatID, NodeKindIncident},
		{activityID, NodeKindObservation},
	} {
		node, ok := g.GetNode(expected.id)
		if !ok {
			t.Fatalf("expected node %s", expected.id)
		}
		if node.Kind != expected.kind {
			t.Fatalf("node %s kind = %s, want %s", expected.id, node.Kind, expected.kind)
		}
		if node.Provider != "sentinelone" {
			t.Fatalf("node %s provider = %q, want sentinelone", expected.id, node.Provider)
		}
	}

	assertEdgeExists(t, g, siteID, agentID, EdgeKindContains)
	assertEdgeExists(t, g, agentID, appID, EdgeKindContainsPkg)
	assertEdgeExists(t, g, agentID, vulnID, EdgeKindAffectedBy)
	assertEdgeExists(t, g, threatID, agentID, EdgeKindTargets)
	assertEdgeExists(t, g, agentID, threatID, EdgeKindAffectedBy)
	assertEdgeExists(t, g, activityID, agentID, EdgeKindTargets)
	assertEdgeExists(t, g, activityID, threatID, EdgeKindTargets)
}

func TestSentinelOneCDCEventToNode(t *testing.T) {
	node := cdcEventToNode("sentinelone_vulnerabilities", cdcEvent{
		TableName:  "sentinelone_vulnerabilities",
		ResourceID: "agent-1|CVE-2026-0001|Chrome|1.2.3",
		Provider:   "sentinelone",
		Payload: map[string]any{
			"id":                   "agent-1|CVE-2026-0001|Chrome|1.2.3",
			"cve_id":               "CVE-2026-0001",
			"agent_id":             "agent-1",
			"application_name":     "Chrome",
			"application_version":  "1.2.3",
			"severity":             "HIGH",
			"days_since_detection": 31,
		},
	})
	if node == nil {
		t.Fatal("expected SentinelOne vulnerability CDC node")
	}
	if node.ID != sentinelOneVulnerabilityNodeID("agent-1|CVE-2026-0001|Chrome|1.2.3") {
		t.Fatalf("node ID = %q", node.ID)
	}
	if node.Kind != NodeKindVulnerability {
		t.Fatalf("node kind = %s, want vulnerability", node.Kind)
	}
	if node.Risk != RiskHigh {
		t.Fatalf("node risk = %s, want high", node.Risk)
	}
}
