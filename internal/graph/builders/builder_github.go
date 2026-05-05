package builders

import (
	"context"
	"fmt"
	"strings"
)

func (b *Builder) buildGitHubNodes(ctx context.Context) {
	queries := []nodeQuery{
		{
			table: "github_repositories",
			query: `SELECT id, name, full_name, private, visibility, default_branch, archived, disabled, fork, language, topics, created_at, updated_at, pushed_at FROM github_repositories`,
			parse: parseGitHubRepositoryNodes,
		},
		{
			table: "github_dependabot_alerts",
			query: `SELECT number, repository, state, severity, package_name, package_ecosystem, vulnerable_version_range, patched_version, cve_id, ghsa_id, cvss_score, created_at, updated_at, fixed_at FROM github_dependabot_alerts`,
			parse: parseGitHubDependabotNodes,
		},
	}

	b.runNodeQueries(ctx, queries)
}

func parseGitHubRepositoryNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows))
	for _, row := range rows {
		fullName := strings.TrimSpace(queryRowString(row, "full_name"))
		if fullName == "" {
			fullName = strings.TrimSpace(queryRowString(row, "repository"))
		}
		if fullName == "" {
			continue
		}
		nodes = append(nodes, &Node{
			ID:       githubRepositoryNodeID(fullName),
			Kind:     NodeKindRepository,
			Name:     firstNonEmpty(queryRowString(row, "name"), fullName),
			Provider: "github",
			Account:  githubRepositoryOwner(fullName),
			Risk:     githubRepositoryRisk(row),
			Properties: map[string]any{
				"source_table":   "github_repositories",
				"repository":     fullName,
				"html_url":       githubRepositoryNodeID(fullName),
				"private":        queryRow(row, "private"),
				"visibility":     queryRow(row, "visibility"),
				"default_branch": queryRow(row, "default_branch"),
				"archived":       queryRow(row, "archived"),
				"disabled":       queryRow(row, "disabled"),
				"fork":           queryRow(row, "fork"),
				"language":       queryRow(row, "language"),
				"topics":         queryRow(row, "topics"),
				"created_at":     queryRow(row, "created_at"),
				"updated_at":     queryRow(row, "updated_at"),
				"pushed_at":      queryRow(row, "pushed_at"),
			},
		})
	}
	return nodes
}

func parseGitHubDependabotNodes(rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows)*2)
	for _, row := range rows {
		if pkg := parseGitHubDependabotPackageNode(row); pkg != nil {
			nodes = append(nodes, pkg)
		}
		if vuln := parseGitHubDependabotVulnerabilityNode(row); vuln != nil {
			nodes = append(nodes, vuln)
		}
	}
	return nodes
}

func parseGitHubDependabotPackageNode(row map[string]any) *Node {
	repository := strings.TrimSpace(queryRowString(row, "repository"))
	packageName := strings.TrimSpace(queryRowString(row, "package_name"))
	if repository == "" || packageName == "" {
		return nil
	}
	ecosystem := firstNonEmpty(queryRowString(row, "package_ecosystem"), "unknown")
	versionRange := strings.TrimSpace(queryRowString(row, "vulnerable_version_range"))
	return &Node{
		ID:       githubDependabotPackageNodeID(row),
		Kind:     NodeKindPackage,
		Name:     packageName,
		Provider: "github",
		Account:  githubRepositoryOwner(repository),
		Risk:     githubDependabotRisk(row),
		Properties: map[string]any{
			"source_table":              "github_dependabot_alerts",
			"repository":                repository,
			"package_name":              packageName,
			"ecosystem":                 ecosystem,
			"version":                   firstNonEmpty(versionRange, "unknown"),
			"vulnerable_version_range":  queryRow(row, "vulnerable_version_range"),
			"patched_version":           queryRow(row, "patched_version"),
			"package_manager":           "github_dependabot",
			"asset_support_entity_kind": "package",
		},
	}
}

func parseGitHubDependabotVulnerabilityNode(row map[string]any) *Node {
	nodeID := githubDependabotVulnerabilityNodeIDForRow(row)
	if nodeID == "" {
		return nil
	}
	cveID := strings.ToUpper(strings.TrimSpace(queryRowString(row, "cve_id")))
	ghsaID := strings.ToUpper(strings.TrimSpace(queryRowString(row, "ghsa_id")))
	name := firstNonEmpty(cveID, ghsaID, queryRowString(row, "package_name"), nodeID)
	repository := strings.TrimSpace(queryRowString(row, "repository"))
	return &Node{
		ID:       nodeID,
		Kind:     NodeKindVulnerability,
		Name:     name,
		Provider: "github",
		Account:  githubRepositoryOwner(repository),
		Risk:     githubDependabotRisk(row),
		Properties: map[string]any{
			"source_table":               "github_dependabot_alerts",
			"repository":                 repository,
			"state":                      queryRow(row, "state"),
			"severity":                   queryRow(row, "severity"),
			"package_name":               queryRow(row, "package_name"),
			"package_ecosystem":          queryRow(row, "package_ecosystem"),
			"vulnerable_version_range":   queryRow(row, "vulnerable_version_range"),
			"patched_version":            queryRow(row, "patched_version"),
			"cve_id":                     cveID,
			"ghsa_id":                    ghsaID,
			"cvss_score":                 queryRow(row, "cvss_score"),
			"created_at":                 queryRow(row, "created_at"),
			"updated_at":                 queryRow(row, "updated_at"),
			"fixed_at":                   queryRow(row, "fixed_at"),
			"asset_support_finding":      "github_dependabot_alert",
			"canonical_vulnerability_id": nodeID,
		},
	}
}

func (b *Builder) buildGitHubEdges(ctx context.Context) {
	b.buildGitHubRepositoryPackageEdges(ctx)
	b.buildGitHubDependabotVulnerabilityEdges(ctx)
}

func (b *Builder) buildGitHubRepositoryPackageEdges(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "github_dependabot_alerts", `SELECT number, repository, package_name, package_ecosystem, vulnerable_version_range, patched_version, state, severity, cve_id, ghsa_id FROM github_dependabot_alerts`)
	if err != nil {
		b.logger.Debug("github dependabot repository package edge query failed", "error", err)
		return
	}
	for _, row := range rows.Rows {
		repository := strings.TrimSpace(queryRowString(row, "repository"))
		if repository == "" || strings.TrimSpace(queryRowString(row, "package_name")) == "" {
			continue
		}
		repoNodeID := githubRepositoryNodeID(repository)
		if _, ok := b.graph.GetNode(repoNodeID); !ok {
			b.graph.AddNode(githubRepositoryFallbackNode(repository))
		}
		pkgNodeID := githubDependabotPackageNodeID(row)
		b.addEdgeIfMissing(&Edge{
			ID:     repoNodeID + "->" + pkgNodeID + ":contains_package",
			Source: repoNodeID,
			Target: pkgNodeID,
			Kind:   EdgeKindContainsPkg,
			Effect: EdgeEffectAllow,
			Risk:   githubDependabotRisk(row),
			Properties: map[string]any{
				"source_table":             "github_dependabot_alerts",
				"alert_number":             queryRow(row, "number"),
				"package_name":             queryRow(row, "package_name"),
				"package_ecosystem":        queryRow(row, "package_ecosystem"),
				"vulnerable_version_range": queryRow(row, "vulnerable_version_range"),
				"state":                    queryRow(row, "state"),
			},
		})
	}
}

func (b *Builder) buildGitHubDependabotVulnerabilityEdges(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "github_dependabot_alerts", `SELECT number, repository, state, severity, package_name, package_ecosystem, vulnerable_version_range, patched_version, cve_id, ghsa_id, cvss_score FROM github_dependabot_alerts`)
	if err != nil {
		b.logger.Debug("github dependabot vulnerability edge query failed", "error", err)
		return
	}
	for _, row := range rows.Rows {
		pkgNodeID := githubDependabotPackageNodeID(row)
		vulnNodeID := githubDependabotVulnerabilityNodeIDForRow(row)
		if pkgNodeID == "" || vulnNodeID == "" {
			continue
		}
		b.addEdgeIfMissing(&Edge{
			ID:     pkgNodeID + "->" + vulnNodeID + ":affected_by",
			Source: pkgNodeID,
			Target: vulnNodeID,
			Kind:   EdgeKindAffectedBy,
			Effect: EdgeEffectAllow,
			Risk:   githubDependabotRisk(row),
			Properties: map[string]any{
				"source_table":             "github_dependabot_alerts",
				"alert_number":             queryRow(row, "number"),
				"repository":               queryRow(row, "repository"),
				"state":                    queryRow(row, "state"),
				"severity":                 queryRow(row, "severity"),
				"cve_id":                   queryRow(row, "cve_id"),
				"ghsa_id":                  queryRow(row, "ghsa_id"),
				"cvss_score":               queryRow(row, "cvss_score"),
				"patched_version":          queryRow(row, "patched_version"),
				"relationship_context":     "package_vulnerability",
				"vulnerable_version_range": queryRow(row, "vulnerable_version_range"),
			},
		})
	}
}

func githubRepositoryNodeID(repository string) string {
	repository = strings.TrimSpace(repository)
	if strings.HasPrefix(repository, "http://") || strings.HasPrefix(repository, "https://") {
		return repository
	}
	return "https://github.com/" + repository
}

func githubRepositoryFallbackNode(repository string) *Node {
	return &Node{
		ID:       githubRepositoryNodeID(repository),
		Kind:     NodeKindRepository,
		Name:     repository,
		Provider: "github",
		Account:  githubRepositoryOwner(repository),
		Risk:     RiskNone,
		Properties: map[string]any{
			"source_table": "github_dependabot_alerts",
			"repository":   repository,
			"html_url":     githubRepositoryNodeID(repository),
		},
	}
}

func githubRepositoryOwner(repository string) string {
	repository = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(repository), "https://github.com/"), "http://github.com/")
	parts := strings.Split(repository, "/")
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}
	return ""
}

func githubDependabotPackageNodeID(row map[string]any) string {
	repository := strings.TrimSpace(queryRowString(row, "repository"))
	packageName := strings.TrimSpace(queryRowString(row, "package_name"))
	if repository == "" || packageName == "" {
		return ""
	}
	ecosystem := firstNonEmpty(queryRowString(row, "package_ecosystem"), "unknown")
	return "github_package:" + slugifyKnowledgeKey(fmt.Sprintf("%s|%s|%s", repository, ecosystem, packageName))
}

func githubDependabotVulnerabilityNodeIDForRow(row map[string]any) string {
	identifier := firstNonEmpty(strings.TrimSpace(queryRowString(row, "cve_id")), strings.TrimSpace(queryRowString(row, "ghsa_id")))
	return canonicalVulnerabilityNodeID(identifier)
}

func githubRepositoryRisk(row map[string]any) RiskLevel {
	if toBool(queryRow(row, "disabled")) {
		return RiskMedium
	}
	if toBool(queryRow(row, "archived")) {
		return RiskLow
	}
	return RiskNone
}

func githubDependabotRisk(row map[string]any) RiskLevel {
	return vulnerabilityRiskFromSeverity(queryRowString(row, "severity"))
}
