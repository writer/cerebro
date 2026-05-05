package builders

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestBuilderBuildsKandjiVulnerabilityGraph(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT device_id, device_name, serial_number, platform, os_version, last_check_in, user_name, user_email, asset_tag, blueprint_name, mdm_enabled, agent_installed, is_supervised, filevault_enabled, firewall_enabled, remote_desktop_enabled, screen_sharing_enabled, gatekeeper_enabled, sip_enabled FROM kandji_devices`, &DataQueryResult{
		Rows: []map[string]any{{
			"device_id":          "device-1",
			"device_name":        "mac-1",
			"serial_number":      "serial-1",
			"platform":           "macOS",
			"os_version":         "15.1",
			"user_email":         "owner@example.com",
			"mdm_enabled":        true,
			"agent_installed":    true,
			"filevault_enabled":  true,
			"firewall_enabled":   true,
			"gatekeeper_enabled": true,
			"sip_enabled":        true,
		}},
	})
	source.setResult(`SELECT device_id, app_name, bundle_id, version, path FROM kandji_device_apps`, &DataQueryResult{
		Rows: []map[string]any{{
			"device_id": "device-1",
			"app_name":  "Chrome",
			"bundle_id": "com.google.Chrome",
			"version":   "1.2.3",
			"path":      "/Applications/Chrome.app",
		}},
	})
	source.setResult(`SELECT cve_id, device_id, device_name, device_serial_number, software_name, software_version, cvss_score, cvss_severity, first_detection_date, latest_detection_date, cve_link FROM kandji_vulnerabilities`, &DataQueryResult{
		Rows: []map[string]any{{
			"cve_id":               "CVE-2026-0001",
			"device_id":            "device-1",
			"device_name":          "mac-1",
			"device_serial_number": "serial-1",
			"software_name":        "Chrome",
			"software_version":     "1.2.3",
			"cvss_score":           8.8,
			"cvss_severity":        "HIGH",
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(ctx); err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	g := builder.Graph()

	deviceID := kandjiDeviceNodeID("device-1")
	packageID := kandjiPackageNodeID("device-1", "Chrome", "1.2.3")
	vulnID := "vulnerability:cve-2026-0001"

	for _, expected := range []struct {
		id   string
		kind NodeKind
	}{
		{deviceID, NodeKindInstance},
		{packageID, NodeKindPackage},
		{vulnID, NodeKindVulnerability},
	} {
		node, ok := g.GetNode(expected.id)
		if !ok {
			t.Fatalf("expected node %s", expected.id)
		}
		if node.Kind != expected.kind {
			t.Fatalf("node %s kind = %s, want %s", expected.id, node.Kind, expected.kind)
		}
		if node.Provider != "kandji" {
			t.Fatalf("node %s provider = %q, want kandji", expected.id, node.Provider)
		}
	}

	assertEdgeExists(t, g, deviceID, packageID, EdgeKindContainsPkg)
	assertEdgeExists(t, g, deviceID, vulnID, EdgeKindAffectedBy)
	assertEdgeExists(t, g, packageID, vulnID, EdgeKindAffectedBy)
}

func TestKandjiCDCEventToNode(t *testing.T) {
	node := cdcEventToNode("kandji_vulnerabilities", cdcEvent{
		TableName:  "kandji_vulnerabilities",
		ResourceID: "device-1|CVE-2026-0001",
		Provider:   "kandji",
		Payload: map[string]any{
			"cve_id":           "CVE-2026-0001",
			"device_id":        "device-1",
			"software_name":    "Chrome",
			"software_version": "1.2.3",
			"cvss_severity":    "HIGH",
		},
	})
	if node == nil {
		t.Fatal("expected Kandji vulnerability CDC node")
	}
	if node.ID != "vulnerability:cve-2026-0001" {
		t.Fatalf("node ID = %q", node.ID)
	}
	if node.Kind != NodeKindVulnerability {
		t.Fatalf("node kind = %s, want vulnerability", node.Kind)
	}
	if node.Risk != RiskHigh {
		t.Fatalf("node risk = %s, want high", node.Risk)
	}
}
