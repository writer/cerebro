package builders

import (
	"context"
	"strings"
)

func (b *Builder) buildSentinelOneNodes(ctx context.Context) {
	queries := []nodeQuery{
		{
			table: "sentinelone_sites",
			query: `SELECT id, name, state, account_id, account_name, license_type, total_licenses, active_licenses, created_at FROM sentinelone_sites`,
			parse: parseSentinelOneSiteNodes,
		},
		{
			table: "sentinelone_agents",
			query: `SELECT id, uuid, computer_name, external_ip, internal_ip, os_name, os_type, os_version, agent_version, is_active, is_infected, is_up_to_date, network_status, scan_status, threat_reboot_required, last_active_date, registered_at, site_id, site_name, group_id, group_name, machine_type, domain, encrypted_applications, firewall_enabled FROM sentinelone_agents`,
			parse: parseSentinelOneAgentNodes,
		},
		{
			table: "sentinelone_threats",
			query: `SELECT id, agent_id, agent_computer_name, threat_name, classification, classification_source, confidence_level, analyst_verdict, incident_status, mitigation_status, initiated_by, file_path, file_sha256, file_sha1, file_md5, mitre_tactics, mitre_techniques, created_at, updated_at FROM sentinelone_threats`,
			parse: parseSentinelOneThreatNodes,
		},
		{
			table: "sentinelone_activities",
			query: `SELECT id, activity_type, activity_description, primary_description, secondary_description, user_id, agent_id, site_id, threat_id, created_at FROM sentinelone_activities`,
			parse: parseSentinelOneActivityNodes,
		},
		{
			table: "sentinelone_applications",
			query: `SELECT id, agent_id, name, version, publisher, size, installed_date, type, risk_level FROM sentinelone_applications`,
			parse: parseSentinelOneApplicationNodes,
		},
		{
			table: "sentinelone_vulnerabilities",
			query: `SELECT id, cve_id, agent_id, site_id, endpoint_name, application_name, application_version, severity, status, cvss_score, exploited_in_wild, days_since_detection, remediation_action, detected_at FROM sentinelone_vulnerabilities`,
			parse: parseSentinelOneVulnerabilityNodes,
		},
	}

	b.runNodeQueries(ctx, queries)
}

func parseSentinelOneSiteNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows))
	for _, row := range rows {
		id := strings.TrimSpace(queryRowString(row, "id"))
		if id == "" {
			continue
		}
		name := firstNonEmpty(queryRowString(row, "name"), id)
		nodes = append(nodes, &Node{
			ID:       sentinelOneSiteNodeID(id),
			Kind:     NodeKindOrganization,
			Name:     name,
			Provider: "sentinelone",
			Account:  firstNonEmpty(queryRowString(row, "account_id"), id),
			Risk:     RiskNone,
			Properties: map[string]any{
				"source_table":     "sentinelone_sites",
				"site_id":          id,
				"state":            queryRow(row, "state"),
				"account_id":       queryRow(row, "account_id"),
				"account_name":     queryRow(row, "account_name"),
				"license_type":     queryRow(row, "license_type"),
				"total_licenses":   queryRow(row, "total_licenses"),
				"active_licenses":  queryRow(row, "active_licenses"),
				"provider_created": queryRow(row, "created_at"),
			},
		})
	}
	return nodes
}

func parseSentinelOneAgentNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows))
	for _, row := range rows {
		id := strings.TrimSpace(queryRowString(row, "id"))
		if id == "" {
			continue
		}
		name := firstNonEmpty(queryRowString(row, "computer_name"), queryRowString(row, "uuid"), id)
		nodes = append(nodes, &Node{
			ID:       sentinelOneAgentNodeID(id),
			Kind:     NodeKindInstance,
			Name:     name,
			Provider: "sentinelone",
			Account:  firstNonEmpty(queryRowString(row, "site_id"), queryRowString(row, "group_id")),
			Risk:     sentinelOneAgentRisk(row),
			Properties: map[string]any{
				"source_table":              "sentinelone_agents",
				"agent_id":                  id,
				"uuid":                      queryRow(row, "uuid"),
				"computer_name":             queryRow(row, "computer_name"),
				"external_ip":               queryRow(row, "external_ip"),
				"internal_ip":               queryRow(row, "internal_ip"),
				"os_name":                   queryRow(row, "os_name"),
				"os_type":                   queryRow(row, "os_type"),
				"os_version":                queryRow(row, "os_version"),
				"agent_version":             queryRow(row, "agent_version"),
				"is_active":                 queryRow(row, "is_active"),
				"is_infected":               queryRow(row, "is_infected"),
				"is_up_to_date":             queryRow(row, "is_up_to_date"),
				"network_status":            queryRow(row, "network_status"),
				"scan_status":               queryRow(row, "scan_status"),
				"threat_reboot_required":    queryRow(row, "threat_reboot_required"),
				"last_active_date":          queryRow(row, "last_active_date"),
				"registered_at":             queryRow(row, "registered_at"),
				"site_id":                   queryRow(row, "site_id"),
				"site_name":                 queryRow(row, "site_name"),
				"group_id":                  queryRow(row, "group_id"),
				"group_name":                queryRow(row, "group_name"),
				"machine_type":              queryRow(row, "machine_type"),
				"domain":                    queryRow(row, "domain"),
				"encrypted_applications":    queryRow(row, "encrypted_applications"),
				"firewall_enabled":          queryRow(row, "firewall_enabled"),
				"asset_support_entity_kind": "endpoint",
			},
		})
	}
	return nodes
}

func parseSentinelOneThreatNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows))
	for _, row := range rows {
		id := strings.TrimSpace(queryRowString(row, "id"))
		if id == "" {
			continue
		}
		name := firstNonEmpty(queryRowString(row, "threat_name"), queryRowString(row, "classification"), id)
		nodes = append(nodes, &Node{
			ID:       sentinelOneThreatNodeID(id),
			Kind:     NodeKindIncident,
			Name:     name,
			Provider: "sentinelone",
			Account:  queryRowString(row, "agent_id"),
			Risk:     sentinelOneThreatRisk(row),
			Properties: map[string]any{
				"source_table":          "sentinelone_threats",
				"threat_id":             id,
				"agent_id":              queryRow(row, "agent_id"),
				"agent_computer_name":   queryRow(row, "agent_computer_name"),
				"classification":        queryRow(row, "classification"),
				"classification_source": queryRow(row, "classification_source"),
				"confidence_level":      queryRow(row, "confidence_level"),
				"analyst_verdict":       queryRow(row, "analyst_verdict"),
				"incident_status":       queryRow(row, "incident_status"),
				"mitigation_status":     queryRow(row, "mitigation_status"),
				"initiated_by":          queryRow(row, "initiated_by"),
				"file_path":             queryRow(row, "file_path"),
				"file_sha256":           queryRow(row, "file_sha256"),
				"file_sha1":             queryRow(row, "file_sha1"),
				"file_md5":              queryRow(row, "file_md5"),
				"mitre_tactics":         queryRow(row, "mitre_tactics"),
				"mitre_techniques":      queryRow(row, "mitre_techniques"),
				"created_at":            queryRow(row, "created_at"),
				"updated_at":            queryRow(row, "updated_at"),
			},
		})
	}
	return nodes
}

func parseSentinelOneActivityNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows))
	for _, row := range rows {
		id := strings.TrimSpace(queryRowString(row, "id"))
		if id == "" {
			continue
		}
		name := firstNonEmpty(queryRowString(row, "primary_description"), queryRowString(row, "activity_description"), id)
		nodes = append(nodes, &Node{
			ID:       sentinelOneActivityNodeID(id),
			Kind:     NodeKindObservation,
			Name:     name,
			Provider: "sentinelone",
			Account:  firstNonEmpty(queryRowString(row, "site_id"), queryRowString(row, "agent_id")),
			Risk:     RiskNone,
			Properties: map[string]any{
				"source_table":           "sentinelone_activities",
				"activity_id":            id,
				"activity_type":          queryRow(row, "activity_type"),
				"activity_description":   queryRow(row, "activity_description"),
				"primary_description":    queryRow(row, "primary_description"),
				"secondary_description":  queryRow(row, "secondary_description"),
				"user_id":                queryRow(row, "user_id"),
				"agent_id":               queryRow(row, "agent_id"),
				"site_id":                queryRow(row, "site_id"),
				"threat_id":              queryRow(row, "threat_id"),
				"created_at":             queryRow(row, "created_at"),
				"asset_support_evidence": "sentinelone_activity",
			},
		})
	}
	return nodes
}

func parseSentinelOneApplicationNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows))
	for _, row := range rows {
		id := strings.TrimSpace(queryRowString(row, "id"))
		if id == "" {
			continue
		}
		name := firstNonEmpty(queryRowString(row, "name"), id)
		version := strings.TrimSpace(queryRowString(row, "version"))
		if version != "" {
			name += " " + version
		}
		nodes = append(nodes, &Node{
			ID:       sentinelOneApplicationNodeID(id),
			Kind:     NodeKindPackage,
			Name:     name,
			Provider: "sentinelone",
			Account:  queryRowString(row, "agent_id"),
			Risk:     sentinelOneApplicationRisk(row),
			Properties: map[string]any{
				"source_table":    "sentinelone_applications",
				"application_id":  id,
				"agent_id":        queryRow(row, "agent_id"),
				"name":            queryRow(row, "name"),
				"version":         queryRow(row, "version"),
				"publisher":       queryRow(row, "publisher"),
				"size":            queryRow(row, "size"),
				"installed_date":  queryRow(row, "installed_date"),
				"type":            queryRow(row, "type"),
				"risk_level":      queryRow(row, "risk_level"),
				"package_manager": "sentinelone",
			},
		})
	}
	return nodes
}

func parseSentinelOneVulnerabilityNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows))
	for _, row := range rows {
		id := strings.TrimSpace(queryRowString(row, "id"))
		if id == "" {
			continue
		}
		cveID := strings.ToUpper(strings.TrimSpace(queryRowString(row, "cve_id")))
		nodeID := sentinelOneVulnerabilityNodeIDForRow(row)
		name := firstNonEmpty(cveID, queryRowString(row, "application_name"), id)
		nodes = append(nodes, &Node{
			ID:       nodeID,
			Kind:     NodeKindVulnerability,
			Name:     name,
			Provider: "sentinelone",
			Account:  firstNonEmpty(queryRowString(row, "site_id"), queryRowString(row, "agent_id")),
			Risk:     sentinelOneSeverityRisk(queryRowString(row, "severity")),
			Properties: map[string]any{
				"source_table":          "sentinelone_vulnerabilities",
				"vulnerability_id":      id,
				"cve_id":                cveID,
				"agent_id":              queryRow(row, "agent_id"),
				"site_id":               queryRow(row, "site_id"),
				"endpoint_name":         queryRow(row, "endpoint_name"),
				"application_name":      queryRow(row, "application_name"),
				"application_version":   queryRow(row, "application_version"),
				"severity":              queryRow(row, "severity"),
				"status":                queryRow(row, "status"),
				"cvss_score":            queryRow(row, "cvss_score"),
				"exploited_in_wild":     queryRow(row, "exploited_in_wild"),
				"days_since_detection":  queryRow(row, "days_since_detection"),
				"remediation_action":    queryRow(row, "remediation_action"),
				"detected_at":           queryRow(row, "detected_at"),
				"asset_support_finding": "sentinelone_vulnerability",
			},
		})
	}
	return nodes
}

func (b *Builder) buildSentinelOneEdges(ctx context.Context) {
	b.buildSentinelOneSiteAgentEdges(ctx)
	b.buildSentinelOneAgentApplicationEdges(ctx)
	b.buildSentinelOneAgentVulnerabilityEdges(ctx)
	b.buildSentinelOneApplicationVulnerabilityEdges(ctx)
	b.buildSentinelOneThreatEdges(ctx)
	b.buildSentinelOneActivityEdges(ctx)
}

func (b *Builder) buildSentinelOneSiteAgentEdges(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "sentinelone_agents", `SELECT id, site_id, site_name FROM sentinelone_agents`)
	if err != nil {
		b.logger.Debug("sentinelone agent/site edge query failed", "error", err)
		return
	}
	for _, row := range rows.Rows {
		agentID := strings.TrimSpace(queryRowString(row, "id"))
		siteID := strings.TrimSpace(queryRowString(row, "site_id"))
		if agentID == "" || siteID == "" {
			continue
		}
		siteNodeID := sentinelOneSiteNodeID(siteID)
		if _, ok := b.graph.GetNode(siteNodeID); !ok {
			b.graph.AddNode(&Node{
				ID:       siteNodeID,
				Kind:     NodeKindOrganization,
				Name:     firstNonEmpty(queryRowString(row, "site_name"), siteID),
				Provider: "sentinelone",
				Account:  siteID,
				Risk:     RiskNone,
				Properties: map[string]any{
					"source_table": "sentinelone_sites",
					"site_id":      siteID,
				},
			})
		}
		agentNodeID := sentinelOneAgentNodeID(agentID)
		b.addEdgeIfMissing(&Edge{
			ID:     siteNodeID + "->" + agentNodeID + ":contains",
			Source: siteNodeID,
			Target: agentNodeID,
			Kind:   EdgeKindContains,
			Effect: EdgeEffectAllow,
			Risk:   RiskNone,
			Properties: map[string]any{
				"source_table": "sentinelone_agents",
			},
		})
	}
}

func (b *Builder) buildSentinelOneAgentApplicationEdges(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "sentinelone_applications", `SELECT id, agent_id, name, version FROM sentinelone_applications`)
	if err != nil {
		b.logger.Debug("sentinelone application edge query failed", "error", err)
		return
	}
	for _, row := range rows.Rows {
		agentID := strings.TrimSpace(queryRowString(row, "agent_id"))
		appID := strings.TrimSpace(queryRowString(row, "id"))
		if agentID == "" || appID == "" {
			continue
		}
		agentNodeID := sentinelOneAgentNodeID(agentID)
		appNodeID := sentinelOneApplicationNodeID(appID)
		b.addEdgeIfMissing(&Edge{
			ID:     agentNodeID + "->" + appNodeID + ":contains_package",
			Source: agentNodeID,
			Target: appNodeID,
			Kind:   EdgeKindContainsPkg,
			Effect: EdgeEffectAllow,
			Risk:   RiskNone,
			Properties: map[string]any{
				"source_table": "sentinelone_applications",
				"name":         queryRow(row, "name"),
				"version":      queryRow(row, "version"),
			},
		})
	}
}

func (b *Builder) buildSentinelOneAgentVulnerabilityEdges(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "sentinelone_vulnerabilities", `SELECT id, cve_id, agent_id, application_name, application_version, severity, status FROM sentinelone_vulnerabilities`)
	if err != nil {
		b.logger.Debug("sentinelone vulnerability edge query failed", "error", err)
		return
	}
	for _, row := range rows.Rows {
		agentID := strings.TrimSpace(queryRowString(row, "agent_id"))
		vulnID := strings.TrimSpace(queryRowString(row, "id"))
		if agentID == "" || vulnID == "" {
			continue
		}
		agentNodeID := sentinelOneAgentNodeID(agentID)
		vulnNodeID := sentinelOneVulnerabilityNodeIDForRow(row)
		risk := sentinelOneSeverityRisk(queryRowString(row, "severity"))
		b.addEdgeIfMissing(&Edge{
			ID:     agentNodeID + "->" + vulnNodeID + ":affected_by",
			Source: agentNodeID,
			Target: vulnNodeID,
			Kind:   EdgeKindAffectedBy,
			Effect: EdgeEffectAllow,
			Risk:   risk,
			Properties: map[string]any{
				"source_table":         "sentinelone_vulnerabilities",
				"cve_id":               queryRow(row, "cve_id"),
				"application_name":     queryRow(row, "application_name"),
				"application_version":  queryRow(row, "application_version"),
				"severity":             queryRow(row, "severity"),
				"status":               queryRow(row, "status"),
				"relationship_context": "endpoint_vulnerability",
			},
		})
	}
}

func (b *Builder) buildSentinelOneApplicationVulnerabilityEdges(ctx context.Context) {
	appRows, err := b.queryIfExists(ctx, "sentinelone_applications", `SELECT id, agent_id, name, version FROM sentinelone_applications`)
	if err != nil {
		b.logger.Debug("sentinelone application vulnerability application query failed", "error", err)
		return
	}
	vulnRows, err := b.queryIfExists(ctx, "sentinelone_vulnerabilities", `SELECT id, cve_id, agent_id, application_name, application_version, severity, status FROM sentinelone_vulnerabilities`)
	if err != nil {
		b.logger.Debug("sentinelone application vulnerability query failed", "error", err)
		return
	}
	appIndex := make(map[string]string, len(appRows.Rows))
	for _, row := range appRows.Rows {
		appID := strings.TrimSpace(queryRowString(row, "id"))
		if appID == "" {
			continue
		}
		key := sentinelOneApplicationMatchKey(queryRowString(row, "agent_id"), queryRowString(row, "name"), queryRowString(row, "version"))
		if key != "" {
			appIndex[key] = appID
		}
	}
	for _, row := range vulnRows.Rows {
		key := sentinelOneApplicationMatchKey(queryRowString(row, "agent_id"), queryRowString(row, "application_name"), queryRowString(row, "application_version"))
		appID := appIndex[key]
		if appID == "" {
			continue
		}
		appNodeID := sentinelOneApplicationNodeID(appID)
		vulnNodeID := sentinelOneVulnerabilityNodeIDForRow(row)
		if vulnNodeID == "" {
			continue
		}
		risk := sentinelOneSeverityRisk(queryRowString(row, "severity"))
		b.addEdgeIfMissing(&Edge{
			ID:     appNodeID + "->" + vulnNodeID + ":affected_by",
			Source: appNodeID,
			Target: vulnNodeID,
			Kind:   EdgeKindAffectedBy,
			Effect: EdgeEffectAllow,
			Risk:   risk,
			Properties: map[string]any{
				"source_table":         "sentinelone_vulnerabilities",
				"cve_id":               queryRow(row, "cve_id"),
				"application_name":     queryRow(row, "application_name"),
				"application_version":  queryRow(row, "application_version"),
				"severity":             queryRow(row, "severity"),
				"status":               queryRow(row, "status"),
				"relationship_context": "package_vulnerability",
			},
		})
	}
}

func (b *Builder) buildSentinelOneThreatEdges(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "sentinelone_threats", `SELECT id, agent_id, threat_name, classification, mitigation_status, incident_status FROM sentinelone_threats`)
	if err != nil {
		b.logger.Debug("sentinelone threat edge query failed", "error", err)
		return
	}
	for _, row := range rows.Rows {
		agentID := strings.TrimSpace(queryRowString(row, "agent_id"))
		threatID := strings.TrimSpace(queryRowString(row, "id"))
		if agentID == "" || threatID == "" {
			continue
		}
		agentNodeID := sentinelOneAgentNodeID(agentID)
		threatNodeID := sentinelOneThreatNodeID(threatID)
		risk := sentinelOneThreatRisk(row)
		b.addEdgeIfMissing(&Edge{
			ID:     threatNodeID + "->" + agentNodeID + ":targets",
			Source: threatNodeID,
			Target: agentNodeID,
			Kind:   EdgeKindTargets,
			Effect: EdgeEffectAllow,
			Risk:   risk,
			Properties: map[string]any{
				"source_table":      "sentinelone_threats",
				"threat_name":       queryRow(row, "threat_name"),
				"classification":    queryRow(row, "classification"),
				"mitigation_status": queryRow(row, "mitigation_status"),
				"incident_status":   queryRow(row, "incident_status"),
			},
		})
		b.addEdgeIfMissing(&Edge{
			ID:     agentNodeID + "->" + threatNodeID + ":affected_by",
			Source: agentNodeID,
			Target: threatNodeID,
			Kind:   EdgeKindAffectedBy,
			Effect: EdgeEffectAllow,
			Risk:   risk,
			Properties: map[string]any{
				"source_table": "sentinelone_threats",
			},
		})
	}
}

func (b *Builder) buildSentinelOneActivityEdges(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "sentinelone_activities", `SELECT id, agent_id, threat_id, site_id, activity_type, created_at FROM sentinelone_activities`)
	if err != nil {
		b.logger.Debug("sentinelone activity edge query failed", "error", err)
		return
	}
	for _, row := range rows.Rows {
		activityID := strings.TrimSpace(queryRowString(row, "id"))
		if activityID == "" {
			continue
		}
		activityNodeID := sentinelOneActivityNodeID(activityID)
		if agentID := strings.TrimSpace(queryRowString(row, "agent_id")); agentID != "" {
			agentNodeID := sentinelOneAgentNodeID(agentID)
			b.addEdgeIfMissing(&Edge{
				ID:     activityNodeID + "->" + agentNodeID + ":targets",
				Source: activityNodeID,
				Target: agentNodeID,
				Kind:   EdgeKindTargets,
				Effect: EdgeEffectAllow,
				Risk:   RiskNone,
				Properties: map[string]any{
					"source_table":  "sentinelone_activities",
					"activity_type": queryRow(row, "activity_type"),
					"created_at":    queryRow(row, "created_at"),
				},
			})
		}
		if threatID := strings.TrimSpace(queryRowString(row, "threat_id")); threatID != "" {
			threatNodeID := sentinelOneThreatNodeID(threatID)
			if _, ok := b.graph.GetNode(threatNodeID); ok {
				b.addEdgeIfMissing(&Edge{
					ID:     activityNodeID + "->" + threatNodeID + ":targets",
					Source: activityNodeID,
					Target: threatNodeID,
					Kind:   EdgeKindTargets,
					Effect: EdgeEffectAllow,
					Risk:   RiskNone,
					Properties: map[string]any{
						"source_table": "sentinelone_activities",
					},
				})
			}
		}
	}
}

func sentinelOneSiteNodeID(id string) string {
	return "sentinelone_site:" + strings.TrimSpace(id)
}

func sentinelOneAgentNodeID(id string) string {
	return "sentinelone_agent:" + strings.TrimSpace(id)
}

func sentinelOneThreatNodeID(id string) string {
	return "sentinelone_threat:" + strings.TrimSpace(id)
}

func sentinelOneActivityNodeID(id string) string {
	return "sentinelone_activity:" + strings.TrimSpace(id)
}

func sentinelOneApplicationNodeID(id string) string {
	return "sentinelone_application:" + strings.TrimSpace(id)
}

func sentinelOneVulnerabilityNodeID(id string) string {
	return "sentinelone_vulnerability:" + strings.TrimSpace(id)
}

func sentinelOneVulnerabilityNodeIDForRow(row map[string]any) string {
	return vulnerabilityNodeIDWithFallback(queryRowString(row, "cve_id"), "sentinelone_vulnerability", queryRowString(row, "id"))
}

func sentinelOneApplicationMatchKey(agentID, name, version string) string {
	agentID = strings.ToLower(strings.TrimSpace(agentID))
	name = strings.ToLower(strings.TrimSpace(name))
	version = strings.ToLower(strings.TrimSpace(version))
	if agentID == "" || name == "" || version == "" {
		return ""
	}
	return agentID + "|" + name + "|" + version
}

func sentinelOneAgentRisk(row map[string]any) RiskLevel {
	if toBool(queryRow(row, "is_infected")) || toBool(queryRow(row, "threat_reboot_required")) {
		return RiskHigh
	}
	if !toBool(queryRow(row, "is_active")) {
		return RiskMedium
	}
	if !toBool(queryRow(row, "is_up_to_date")) {
		return RiskLow
	}
	return RiskNone
}

func sentinelOneApplicationRisk(row map[string]any) RiskLevel {
	return vulnerabilityRiskFromSeverity(queryRowString(row, "risk_level"))
}

func sentinelOneThreatRisk(row map[string]any) RiskLevel {
	classification := strings.ToLower(queryRowString(row, "classification"))
	mitigationStatus := strings.ToLower(queryRowString(row, "mitigation_status"))
	if strings.Contains(classification, "ransom") {
		return RiskCritical
	}
	if mitigationStatus != "" && mitigationStatus != "mitigated" && mitigationStatus != "remediated" {
		return RiskHigh
	}
	return RiskMedium
}

func sentinelOneSeverityRisk(severity string) RiskLevel {
	return vulnerabilityRiskFromSeverity(severity)
}
