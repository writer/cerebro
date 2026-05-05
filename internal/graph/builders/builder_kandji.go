package builders

import (
	"context"
	"fmt"
	"strings"
)

func (b *Builder) buildKandjiNodes(ctx context.Context) {
	queries := []nodeQuery{
		{
			table: "kandji_devices",
			query: `SELECT device_id, device_name, serial_number, platform, os_version, last_check_in, user_name, user_email, asset_tag, blueprint_name, mdm_enabled, agent_installed, is_supervised, filevault_enabled, firewall_enabled, remote_desktop_enabled, screen_sharing_enabled, gatekeeper_enabled, sip_enabled FROM kandji_devices`,
			parse: parseKandjiDeviceNodes,
		},
		{
			table: "kandji_device_apps",
			query: `SELECT device_id, app_name, bundle_id, version, path FROM kandji_device_apps`,
			parse: parseKandjiDeviceAppNodes,
		},
		{
			table: "kandji_vulnerabilities",
			query: `SELECT cve_id, device_id, device_name, device_serial_number, software_name, software_version, cvss_score, cvss_severity, first_detection_date, latest_detection_date, cve_link FROM kandji_vulnerabilities`,
			parse: parseKandjiVulnerabilityNodes,
		},
	}

	b.runNodeQueries(ctx, queries)
}

func parseKandjiDeviceNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows))
	for _, row := range rows {
		deviceID := strings.TrimSpace(queryRowString(row, "device_id"))
		if deviceID == "" {
			continue
		}
		nodes = append(nodes, &Node{
			ID:       kandjiDeviceNodeID(deviceID),
			Kind:     NodeKindInstance,
			Name:     firstNonEmpty(queryRowString(row, "device_name"), queryRowString(row, "serial_number"), deviceID),
			Provider: "kandji",
			Account:  firstNonEmpty(queryRowString(row, "blueprint_name"), queryRowString(row, "user_email")),
			Risk:     kandjiDeviceRisk(row),
			Properties: map[string]any{
				"source_table":              "kandji_devices",
				"device_id":                 deviceID,
				"device_name":               queryRow(row, "device_name"),
				"serial_number":             queryRow(row, "serial_number"),
				"platform":                  queryRow(row, "platform"),
				"os_version":                queryRow(row, "os_version"),
				"last_check_in":             queryRow(row, "last_check_in"),
				"user_name":                 queryRow(row, "user_name"),
				"user_email":                queryRow(row, "user_email"),
				"asset_tag":                 queryRow(row, "asset_tag"),
				"blueprint_name":            queryRow(row, "blueprint_name"),
				"mdm_enabled":               queryRow(row, "mdm_enabled"),
				"agent_installed":           queryRow(row, "agent_installed"),
				"is_supervised":             queryRow(row, "is_supervised"),
				"filevault_enabled":         queryRow(row, "filevault_enabled"),
				"firewall_enabled":          queryRow(row, "firewall_enabled"),
				"remote_desktop_enabled":    queryRow(row, "remote_desktop_enabled"),
				"screen_sharing_enabled":    queryRow(row, "screen_sharing_enabled"),
				"gatekeeper_enabled":        queryRow(row, "gatekeeper_enabled"),
				"sip_enabled":               queryRow(row, "sip_enabled"),
				"asset_support_entity_kind": "endpoint",
			},
		})
	}
	return nodes
}

func parseKandjiDeviceAppNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows))
	for _, row := range rows {
		node := kandjiPackageNode(row, "kandji_device_apps")
		if node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func parseKandjiVulnerabilityNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows)*2)
	for _, row := range rows {
		if pkg := kandjiPackageNodeFromVulnerability(row); pkg != nil {
			nodes = append(nodes, pkg)
		}
		node := kandjiVulnerabilityNode(row)
		if node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func kandjiPackageNode(row map[string]any, sourceTable string) *Node {
	deviceID := strings.TrimSpace(queryRowString(row, "device_id"))
	name := strings.TrimSpace(queryRowString(row, "app_name"))
	if name == "" {
		name = strings.TrimSpace(queryRowString(row, "software_name"))
	}
	if deviceID == "" || name == "" {
		return nil
	}
	version := strings.TrimSpace(firstNonEmpty(queryRowString(row, "version"), queryRowString(row, "software_version")))
	return &Node{
		ID:       kandjiPackageNodeID(deviceID, name, version),
		Kind:     NodeKindPackage,
		Name:     firstNonEmpty(name, "unknown"),
		Provider: "kandji",
		Account:  deviceID,
		Risk:     vulnerabilityRiskFromSeverity(queryRowString(row, "cvss_severity")),
		Properties: map[string]any{
			"source_table":              sourceTable,
			"device_id":                 deviceID,
			"package_name":              name,
			"app_name":                  queryRow(row, "app_name"),
			"software_name":             queryRow(row, "software_name"),
			"bundle_id":                 queryRow(row, "bundle_id"),
			"version":                   firstNonEmpty(version, "unknown"),
			"path":                      queryRow(row, "path"),
			"package_manager":           "kandji",
			"asset_support_entity_kind": "package",
		},
	}
}

func kandjiPackageNodeFromVulnerability(row map[string]any) *Node {
	return kandjiPackageNode(row, "kandji_vulnerabilities")
}

func kandjiVulnerabilityNode(row map[string]any) *Node {
	cveID := normalizedVulnerabilityIdentifier(queryRowString(row, "cve_id"))
	nodeID := kandjiVulnerabilityNodeIDForRow(row)
	if nodeID == "" {
		return nil
	}
	return &Node{
		ID:       nodeID,
		Kind:     NodeKindVulnerability,
		Name:     firstNonEmpty(cveID, queryRowString(row, "software_name"), nodeID),
		Provider: "kandji",
		Account:  firstNonEmpty(queryRowString(row, "device_id"), queryRowString(row, "device_serial_number")),
		Risk:     vulnerabilityRiskFromSeverity(queryRowString(row, "cvss_severity")),
		Properties: map[string]any{
			"source_table":                "kandji_vulnerabilities",
			"cve_id":                      cveID,
			"device_id":                   queryRow(row, "device_id"),
			"device_name":                 queryRow(row, "device_name"),
			"device_serial_number":        queryRow(row, "device_serial_number"),
			"software_name":               queryRow(row, "software_name"),
			"software_version":            queryRow(row, "software_version"),
			"cvss_score":                  queryRow(row, "cvss_score"),
			"cvss_severity":               queryRow(row, "cvss_severity"),
			"first_detection_date":        queryRow(row, "first_detection_date"),
			"latest_detection_date":       queryRow(row, "latest_detection_date"),
			"cve_link":                    queryRow(row, "cve_link"),
			"asset_support_finding":       "kandji_vulnerability",
			"canonical_vulnerability_id":  nodeID,
			"vulnerability_observed_from": "kandji",
		},
	}
}

func (b *Builder) buildKandjiEdges(ctx context.Context) {
	b.buildKandjiDeviceAppEdges(ctx)
	b.buildKandjiVulnerabilityEdges(ctx)
}

func (b *Builder) buildKandjiDeviceAppEdges(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "kandji_device_apps", `SELECT device_id, app_name, bundle_id, version, path FROM kandji_device_apps`)
	if err != nil {
		b.logger.Debug("kandji device app edge query failed", "error", err)
		return
	}
	for _, row := range rows.Rows {
		deviceID := strings.TrimSpace(queryRowString(row, "device_id"))
		name := strings.TrimSpace(queryRowString(row, "app_name"))
		if deviceID == "" || name == "" {
			continue
		}
		deviceNodeID := kandjiDeviceNodeID(deviceID)
		packageNodeID := kandjiPackageNodeID(deviceID, name, queryRowString(row, "version"))
		b.addEdgeIfMissing(&Edge{
			ID:     deviceNodeID + "->" + packageNodeID + ":contains_package",
			Source: deviceNodeID,
			Target: packageNodeID,
			Kind:   EdgeKindContainsPkg,
			Effect: EdgeEffectAllow,
			Risk:   RiskNone,
			Properties: map[string]any{
				"source_table": "kandji_device_apps",
				"app_name":     queryRow(row, "app_name"),
				"bundle_id":    queryRow(row, "bundle_id"),
				"version":      queryRow(row, "version"),
				"path":         queryRow(row, "path"),
			},
		})
	}
}

func (b *Builder) buildKandjiVulnerabilityEdges(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "kandji_vulnerabilities", `SELECT cve_id, device_id, device_name, device_serial_number, software_name, software_version, cvss_score, cvss_severity, first_detection_date, latest_detection_date, cve_link FROM kandji_vulnerabilities`)
	if err != nil {
		b.logger.Debug("kandji vulnerability edge query failed", "error", err)
		return
	}
	for _, row := range rows.Rows {
		deviceID := strings.TrimSpace(queryRowString(row, "device_id"))
		vulnNodeID := kandjiVulnerabilityNodeIDForRow(row)
		if deviceID == "" || vulnNodeID == "" {
			continue
		}
		deviceNodeID := kandjiDeviceNodeID(deviceID)
		risk := vulnerabilityRiskFromSeverity(queryRowString(row, "cvss_severity"))
		b.addEdgeIfMissing(&Edge{
			ID:         deviceNodeID + "->" + vulnNodeID + ":affected_by",
			Source:     deviceNodeID,
			Target:     vulnNodeID,
			Kind:       EdgeKindAffectedBy,
			Effect:     EdgeEffectAllow,
			Risk:       risk,
			Properties: kandjiVulnerabilityEdgeProperties(row, "endpoint_vulnerability"),
		})
		if packageName := strings.TrimSpace(queryRowString(row, "software_name")); packageName != "" {
			packageNodeID := kandjiPackageNodeID(deviceID, packageName, queryRowString(row, "software_version"))
			b.addEdgeIfMissing(&Edge{
				ID:         packageNodeID + "->" + vulnNodeID + ":affected_by",
				Source:     packageNodeID,
				Target:     vulnNodeID,
				Kind:       EdgeKindAffectedBy,
				Effect:     EdgeEffectAllow,
				Risk:       risk,
				Properties: kandjiVulnerabilityEdgeProperties(row, "package_vulnerability"),
			})
		}
	}
}

func kandjiVulnerabilityEdgeProperties(row map[string]any, context string) map[string]any {
	return map[string]any{
		"source_table":          "kandji_vulnerabilities",
		"cve_id":                queryRow(row, "cve_id"),
		"software_name":         queryRow(row, "software_name"),
		"software_version":      queryRow(row, "software_version"),
		"cvss_score":            queryRow(row, "cvss_score"),
		"cvss_severity":         queryRow(row, "cvss_severity"),
		"latest_detection_date": queryRow(row, "latest_detection_date"),
		"relationship_context":  context,
	}
}

func kandjiDeviceNodeID(deviceID string) string {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return ""
	}
	return "kandji_device:" + deviceID
}

func kandjiPackageNodeID(deviceID, name, version string) string {
	deviceID = strings.TrimSpace(deviceID)
	name = strings.TrimSpace(name)
	if deviceID == "" || name == "" {
		return ""
	}
	return "kandji_package:" + slugifyKnowledgeKey(fmt.Sprintf("%s|%s|%s", deviceID, name, firstNonEmpty(version, "unknown")))
}

func kandjiVulnerabilityNodeIDForRow(row map[string]any) string {
	deviceID := strings.TrimSpace(queryRowString(row, "device_id"))
	cveID := strings.TrimSpace(queryRowString(row, "cve_id"))
	fallback := ""
	if deviceID != "" && cveID != "" {
		fallback = deviceID + "|" + cveID
	}
	return vulnerabilityNodeIDWithFallback(queryRowString(row, "cve_id"), "kandji_vulnerability", fallback)
}

func kandjiDeviceRisk(row map[string]any) RiskLevel {
	if toBool(queryRow(row, "remote_desktop_enabled")) || toBool(queryRow(row, "screen_sharing_enabled")) {
		return RiskMedium
	}
	for _, key := range []string{"mdm_enabled", "agent_installed", "filevault_enabled", "firewall_enabled", "gatekeeper_enabled", "sip_enabled"} {
		value, ok := queryRowValue(row, key)
		if ok && !toBool(value) {
			return RiskLow
		}
	}
	return RiskNone
}
