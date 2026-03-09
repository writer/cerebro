package graph

import (
	"fmt"
	"strings"
)

// MermaidExporter generates Mermaid diagram syntax from graph data
type MermaidExporter struct {
	graph *Graph
}

// NewMermaidExporter creates a new Mermaid exporter
func NewMermaidExporter(g *Graph) *MermaidExporter {
	return &MermaidExporter{graph: g}
}

// ExportAttackPath generates Mermaid flowchart for an attack path
func (m *MermaidExporter) ExportAttackPath(path *ScoredAttackPath) string {
	var sb strings.Builder
	sb.Grow(2048) // Pre-allocate for typical attack path size

	sb.WriteString("```mermaid\n")
	sb.WriteString("flowchart LR\n")

	// Add style classes
	sb.WriteString("    classDef entryPoint fill:#ff6b6b,stroke:#c92a2a,color:white\n")
	sb.WriteString("    classDef target fill:#845ef7,stroke:#5f3dc4,color:white\n")
	sb.WriteString("    classDef intermediate fill:#339af0,stroke:#1864ab,color:white\n")
	sb.WriteString("    classDef critical fill:#f03e3e,stroke:#c92a2a,color:white\n")
	sb.WriteString("\n")

	// Track unique nodes
	seenNodes := make(map[string]bool)

	// Entry point
	if path.EntryPoint != nil {
		entryID := sanitizeMermaidID(path.EntryPoint.ID)
		fmt.Fprintf(&sb, "    %s[\"🚪 %s\"]\n", entryID, escapeLabel(path.EntryPoint.Name))
		fmt.Fprintf(&sb, "    class %s entryPoint\n", entryID)
		seenNodes[path.EntryPoint.ID] = true
	}

	// Steps
	for _, step := range path.Steps {
		fromID := sanitizeMermaidID(step.FromNode)
		toID := sanitizeMermaidID(step.ToNode)

		// Add from node if not seen
		if !seenNodes[step.FromNode] {
			fromNode, _ := m.graph.GetNode(step.FromNode)
			fromLabel := step.FromNode
			if fromNode != nil {
				fromLabel = fromNode.Name
			}
			fmt.Fprintf(&sb, "    %s[\"%s\"]\n", fromID, escapeLabel(fromLabel))
			fmt.Fprintf(&sb, "    class %s intermediate\n", fromID)
			seenNodes[step.FromNode] = true
		}

		// Add to node if not seen
		if !seenNodes[step.ToNode] {
			toNode, _ := m.graph.GetNode(step.ToNode)
			toLabel := step.ToNode
			if toNode != nil {
				toLabel = toNode.Name
			}
			fmt.Fprintf(&sb, "    %s[\"%s\"]\n", toID, escapeLabel(toLabel))
			seenNodes[step.ToNode] = true
		}

		// Add edge with technique
		edgeLabel := step.Technique
		if step.MITREAttackID != "" {
			edgeLabel = step.Technique + "\\n(" + step.MITREAttackID + ")"
		}
		fmt.Fprintf(&sb, "    %s -->|\"%s\"| %s\n", fromID, escapeLabel(edgeLabel), toID)
	}

	// Target styling
	if path.Target != nil {
		targetID := sanitizeMermaidID(path.Target.ID)
		fmt.Fprintf(&sb, "    class %s target\n", targetID)
	}

	sb.WriteString("```\n")
	return sb.String()
}

// ExportAttackPaths generates Mermaid for multiple attack paths
func (m *MermaidExporter) ExportAttackPaths(result *SimulationResult, maxPaths int) string {
	var sb strings.Builder
	sb.Grow(4096) // Pre-allocate for multiple paths

	sb.WriteString("# Attack Path Analysis\n\n")
	fmt.Fprintf(&sb, "**Total Paths:** %d | **Critical Paths:** %d | **Chokepoints:** %d\n\n",
		result.TotalPaths, result.CriticalPaths, len(result.Chokepoints))

	pathCount := maxPaths
	if pathCount > len(result.Paths) {
		pathCount = len(result.Paths)
	}

	for i := 0; i < pathCount; i++ {
		path := result.Paths[i]
		fmt.Fprintf(&sb, "## Attack Path #%d (Score: %.1f)\n\n", i+1, path.TotalScore)

		if path.EntryPoint != nil && path.Target != nil {
			fmt.Fprintf(&sb, "**Entry:** %s → **Target:** %s\n\n", path.EntryPoint.Name, path.Target.Name)
		}

		sb.WriteString(m.ExportAttackPath(path))
		sb.WriteString("\n")
	}

	return sb.String()
}

// ExportToxicCombination generates Mermaid for a toxic combination
func (m *MermaidExporter) ExportToxicCombination(tc *ToxicCombination) string {
	var sb strings.Builder
	sb.Grow(2048) // Pre-allocate for typical toxic combination size

	sb.WriteString("```mermaid\n")
	sb.WriteString("flowchart TB\n")

	// Style definitions
	sb.WriteString("    classDef critical fill:#f03e3e,stroke:#c92a2a,color:white\n")
	sb.WriteString("    classDef high fill:#fd7e14,stroke:#d9480f,color:white\n")
	sb.WriteString("    classDef medium fill:#fab005,stroke:#f59f00,color:black\n")
	sb.WriteString("    classDef factor fill:#868e96,stroke:#495057,color:white\n")
	sb.WriteString("\n")

	// Central node for the toxic combination
	tcID := sanitizeMermaidID(tc.ID)
	severityEmoji := severityToEmoji(tc.Severity)
	fmt.Fprintf(&sb, "    %s{{\"⚠️ %s\\nScore: %.0f\"}}\n", tcID, escapeLabel(tc.Name), tc.Score)
	fmt.Fprintf(&sb, "    class %s %s\n", tcID, strings.ToLower(string(tc.Severity)))

	// Risk factors
	for i, factor := range tc.Factors {
		factorEmoji := factorTypeToEmoji(factor.Type)
		fmt.Fprintf(&sb, "    factor_%d[\"%s %s\"]\n", i, factorEmoji, escapeLabel(factor.Description))
		fmt.Fprintf(&sb, "    class factor_%d factor\n", i)
		fmt.Fprintf(&sb, "    factor_%d --> %s\n", i, tcID)
	}

	// Attack path if present
	if tc.AttackPath != nil && len(tc.AttackPath.Steps) > 0 {
		sb.WriteString("\n    subgraph attack[\"🎯 Attack Path\"]\n")
		for i, step := range tc.AttackPath.Steps {
			fromID := sanitizeMermaidID("step_" + itoa(i) + "_from")
			toID := sanitizeMermaidID("step_" + itoa(i) + "_to")
			fmt.Fprintf(&sb, "        %s[\"%s\"] -->|\"%s\"| %s[\"%s\"]\n",
				fromID, escapeLabel(step.FromNode),
				escapeLabel(step.Technique),
				toID, escapeLabel(step.ToNode))
		}
		sb.WriteString("    end\n")
		fmt.Fprintf(&sb, "    %s -.-> attack\n", tcID)
	}

	// Remediation subgraph
	if len(tc.Remediation) > 0 {
		sb.WriteString("\n    subgraph remediation[\"🔧 Remediation\"]\n")
		for i, step := range tc.Remediation {
			fmt.Fprintf(&sb, "        rem_%d[\"P%d: %s\"]\n", i, step.Priority, escapeLabel(step.Action))
		}
		sb.WriteString("    end\n")
		fmt.Fprintf(&sb, "    %s -.-> remediation\n", tcID)
	}

	sb.WriteString("```\n")

	// Add metadata
	fmt.Fprintf(&sb, "\n%s **Severity:** %s | **Score:** %.1f\n", severityEmoji, tc.Severity, tc.Score)
	fmt.Fprintf(&sb, "\n> %s\n", tc.Description)

	return sb.String()
}

// ExportSecurityReport generates comprehensive Mermaid visualization for a security report
func (m *MermaidExporter) ExportSecurityReport(report *SecurityReport) string {
	var sb strings.Builder

	// Header
	sb.WriteString("# Security Report\n\n")
	fmt.Fprintf(&sb, "**Generated:** %s\n\n", report.GeneratedAt.Format("2006-01-02 15:04:05"))

	// Risk Score Overview
	sb.WriteString("## Risk Overview\n\n")
	sb.WriteString("```mermaid\n")
	sb.WriteString("pie showData\n")
	sb.WriteString("    title Risk Score Distribution\n")

	// Count severity levels
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	for _, tc := range report.ToxicCombinations {
		switch tc.Severity {
		case SeverityCritical:
			criticalCount++
		case SeverityHigh:
			highCount++
		case SeverityMedium:
			mediumCount++
		}
	}
	fmt.Fprintf(&sb, "    \"Critical\" : %d\n", criticalCount)
	fmt.Fprintf(&sb, "    \"High\" : %d\n", highCount)
	fmt.Fprintf(&sb, "    \"Medium\" : %d\n", mediumCount)
	sb.WriteString("```\n\n")

	// Overall Risk Gauge
	sb.WriteString("```mermaid\n")
	sb.WriteString("%%{init: {'theme': 'base', 'themeVariables': { 'pie1': '#f03e3e', 'pie2': '#40c057'}}}%%\n")
	sb.WriteString("pie showData\n")
	sb.WriteString("    title Overall Risk Score\n")
	fmt.Fprintf(&sb, "    \"Risk (%.0f)\" : %.0f\n", report.RiskScore, report.RiskScore)
	fmt.Fprintf(&sb, "    \"Safe\" : %.0f\n", 100-report.RiskScore)
	sb.WriteString("```\n\n")

	// Graph Stats
	if report.GraphStats != nil {
		sb.WriteString("## Graph Statistics\n\n")
		sb.WriteString("```mermaid\n")
		sb.WriteString("mindmap\n")
		sb.WriteString("    root((Security Graph))\n")
		fmt.Fprintf(&sb, "        Nodes: %d\n", report.GraphStats.TotalNodes)
		fmt.Fprintf(&sb, "            Identities: %d\n", report.GraphStats.IdentityCount)
		fmt.Fprintf(&sb, "            Resources: %d\n", report.GraphStats.ResourceCount)
		fmt.Fprintf(&sb, "        Edges: %d\n", report.GraphStats.TotalEdges)
		fmt.Fprintf(&sb, "            Cross-Account: %d\n", report.GraphStats.CrossAccountEdges)
		sb.WriteString("        Risk Indicators\n")
		fmt.Fprintf(&sb, "            Public Exposures: %d\n", report.GraphStats.PublicExposures)
		fmt.Fprintf(&sb, "            Critical Resources: %d\n", report.GraphStats.CriticalResources)
		sb.WriteString("```\n\n")
	}

	// Top Toxic Combinations
	if len(report.ToxicCombinations) > 0 {
		sb.WriteString("## Top Toxic Combinations\n\n")
		maxTC := 5
		if len(report.ToxicCombinations) < maxTC {
			maxTC = len(report.ToxicCombinations)
		}
		for i := 0; i < maxTC; i++ {
			tc := report.ToxicCombinations[i]
			fmt.Fprintf(&sb, "### %d. %s\n\n", i+1, tc.Name)
			sb.WriteString(m.ExportToxicCombination(tc))
			sb.WriteString("\n---\n\n")
		}
	}

	// Attack Paths
	if report.AttackPaths != nil && len(report.AttackPaths.Paths) > 0 {
		sb.WriteString("## Critical Attack Paths\n\n")
		sb.WriteString(m.ExportAttackPaths(report.AttackPaths, 3))
	}

	// Chokepoints
	if len(report.Chokepoints) > 0 {
		sb.WriteString("## Chokepoints (High-Impact Remediation)\n\n")
		sb.WriteString("```mermaid\n")
		sb.WriteString("flowchart LR\n")
		sb.WriteString("    classDef chokepoint fill:#be4bdb,stroke:#862e9c,color:white\n\n")

		maxCP := 5
		if len(report.Chokepoints) < maxCP {
			maxCP = len(report.Chokepoints)
		}
		for i := 0; i < maxCP; i++ {
			cp := report.Chokepoints[i]
			cpID := sanitizeMermaidID(cp.Node.ID)
			fmt.Fprintf(&sb, "    %s{{\"%s\\nBlocks %d paths\"}}\n",
				cpID, escapeLabel(cp.Node.Name), cp.BlockedPaths)
			fmt.Fprintf(&sb, "    class %s chokepoint\n", cpID)
		}
		sb.WriteString("```\n\n")
	}

	// Remediation Plan Summary
	if report.RemediationPlan != nil {
		sb.WriteString("## Remediation Plan\n\n")
		sb.WriteString("```mermaid\n")
		sb.WriteString("gantt\n")
		sb.WriteString("    title Remediation Timeline\n")
		sb.WriteString("    dateFormat  X\n")
		sb.WriteString("    axisFormat %s\n")

		if len(report.RemediationPlan.QuickWins) > 0 {
			sb.WriteString("    section Quick Wins\n")
			for i, qw := range report.RemediationPlan.QuickWins {
				if i >= 3 {
					break
				}
				fmt.Fprintf(&sb, "    %s :a%d, 0, 1\n", escapeLabel(truncate(qw.Action, 30)), i)
			}
		}

		if len(report.RemediationPlan.StrategicFixes) > 0 {
			sb.WriteString("    section Strategic Fixes\n")
			for i, sf := range report.RemediationPlan.StrategicFixes {
				if i >= 3 {
					break
				}
				fmt.Fprintf(&sb, "    %s :b%d, 1, 4\n", escapeLabel(truncate(sf.Action, 30)), i)
			}
		}
		sb.WriteString("```\n\n")
	}

	return sb.String()
}

// ExportBlastRadius generates Mermaid for blast radius analysis
func (m *MermaidExporter) ExportBlastRadius(result *BlastRadiusResult) string {
	var sb strings.Builder

	sb.WriteString("```mermaid\n")
	sb.WriteString("flowchart TD\n")

	// Styles
	sb.WriteString("    classDef source fill:#228be6,stroke:#1864ab,color:white\n")
	sb.WriteString("    classDef critical fill:#f03e3e,stroke:#c92a2a,color:white\n")
	sb.WriteString("    classDef high fill:#fd7e14,stroke:#d9480f,color:white\n")
	sb.WriteString("    classDef medium fill:#fab005,stroke:#f59f00,color:black\n")
	sb.WriteString("    classDef low fill:#40c057,stroke:#2f9e44,color:white\n\n")

	// Source node
	sourceID := sanitizeMermaidID(result.PrincipalID)
	fmt.Fprintf(&sb, "    %s((\"🎯 %s\"))\n", sourceID, escapeLabel(result.PrincipalName))
	fmt.Fprintf(&sb, "    class %s source\n\n", sourceID)

	// Group by depth
	byDepth := make(map[int][]*ReachableNode)
	for _, rn := range result.ReachableNodes {
		byDepth[rn.Depth] = append(byDepth[rn.Depth], rn)
	}

	maxNodes := 20
	nodeCount := 0

	for depth := 1; depth <= result.MaxDepth && nodeCount < maxNodes; depth++ {
		nodes := byDepth[depth]
		if len(nodes) == 0 {
			continue
		}

		fmt.Fprintf(&sb, "    subgraph dist%d[\"Distance %d\"]\n", depth, depth)
		for _, rn := range nodes {
			if nodeCount >= maxNodes {
				break
			}
			nodeID := sanitizeMermaidID(rn.Node.ID)
			emoji := nodeKindToEmoji(rn.Node.Kind)
			fmt.Fprintf(&sb, "        %s[\"%s %s\"]\n", nodeID, emoji, escapeLabel(rn.Node.Name))
			fmt.Fprintf(&sb, "        class %s %s\n", nodeID, strings.ToLower(string(rn.Node.Risk)))
			nodeCount++
		}
		sb.WriteString("    end\n\n")
	}

	// Connect source to first level
	for _, rn := range byDepth[1] {
		if nodeCount > maxNodes {
			break
		}
		nodeID := sanitizeMermaidID(rn.Node.ID)
		edgeLabel := string(rn.EdgeKind)
		fmt.Fprintf(&sb, "    %s -->|\"%s\"| %s\n", sourceID, edgeLabel, nodeID)
	}

	sb.WriteString("```\n")

	// Summary
	fmt.Fprintf(&sb, "\n**Blast Radius:** %d reachable nodes | ", result.TotalCount)
	fmt.Fprintf(&sb, "**Critical:** %d | **High:** %d\n", result.RiskSummary.Critical, result.RiskSummary.High)

	return sb.String()
}

// ExportChokepoints generates Mermaid for chokepoint analysis
func (m *MermaidExporter) ExportChokepoints(chokepoints []*Chokepoint) string {
	var sb strings.Builder

	sb.WriteString("# Chokepoint Analysis\n\n")
	sb.WriteString("Chokepoints are nodes where multiple attack paths converge. Fixing these provides maximum security ROI.\n\n")

	sb.WriteString("```mermaid\n")
	sb.WriteString("flowchart LR\n")
	sb.WriteString("    classDef chokepoint fill:#be4bdb,stroke:#862e9c,color:white,stroke-width:3px\n")
	sb.WriteString("    classDef entry fill:#ff6b6b,stroke:#c92a2a,color:white\n")
	sb.WriteString("    classDef target fill:#845ef7,stroke:#5f3dc4,color:white\n\n")

	for i, cp := range chokepoints {
		if i >= 5 {
			break
		}

		cpID := sanitizeMermaidID(cp.Node.ID)
		fmt.Fprintf(&sb, "    %s{{\"%s\\n🛑 %d paths\\n%.0f%% impact\"}}\n",
			cpID, escapeLabel(cp.Node.Name), cp.PathsThrough, cp.RemediationImpact*100)
		fmt.Fprintf(&sb, "    class %s chokepoint\n", cpID)

		// Show some upstream entries
		for j, entry := range cp.UpstreamEntries {
			if j >= 2 {
				break
			}
			entryID := sanitizeMermaidID(entry)
			fmt.Fprintf(&sb, "    %s([%s]) --> %s\n", entryID, escapeLabel(entry), cpID)
			fmt.Fprintf(&sb, "    class %s entry\n", entryID)
		}

		// Show some downstream targets
		for j, target := range cp.DownstreamTargets {
			if j >= 2 {
				break
			}
			targetID := sanitizeMermaidID(target)
			fmt.Fprintf(&sb, "    %s --> %s([%s])\n", cpID, targetID, escapeLabel(target))
			fmt.Fprintf(&sb, "    class %s target\n", targetID)
		}

		sb.WriteString("\n")
	}

	sb.WriteString("```\n\n")

	// Table summary
	sb.WriteString("| Priority | Node | Paths Blocked | Impact |\n")
	sb.WriteString("|----------|------|---------------|--------|\n")
	for i, cp := range chokepoints {
		if i >= 10 {
			break
		}
		fmt.Fprintf(&sb, "| %d | %s | %d | %.0f%% |\n",
			i+1, cp.Node.Name, cp.BlockedPaths, cp.RemediationImpact*100)
	}

	return sb.String()
}

// Helper functions

func sanitizeMermaidID(id string) string {
	// Replace characters that break Mermaid syntax
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"-", "_",
		".", "_",
		" ", "_",
		"(", "_",
		")", "_",
		"[", "_",
		"]", "_",
		"{", "_",
		"}", "_",
		"<", "_",
		">", "_",
		"*", "_",
		"@", "_",
	)
	return "n_" + replacer.Replace(id)
}

func escapeLabel(s string) string {
	// Escape characters that break Mermaid labels
	s = strings.ReplaceAll(s, "\"", "'")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

func severityToEmoji(s Severity) string {
	switch s {
	case SeverityCritical:
		return "🔴"
	case SeverityHigh:
		return "🟠"
	case SeverityMedium:
		return "🟡"
	case SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

func factorTypeToEmoji(t RiskFactorType) string {
	switch t {
	case RiskFactorExposure:
		return "🌐"
	case RiskFactorVulnerability:
		return "🐛"
	case RiskFactorMisconfiguration:
		return "⚙️"
	case RiskFactorOverPrivilege:
		return "👑"
	case RiskFactorSensitiveData:
		return "📊"
	case RiskFactorWeakAuth:
		return "🔓"
	case RiskFactorCrossAccount:
		return "🔀"
	case RiskFactorPrivEscalation:
		return "📈"
	case RiskFactorLateralMove:
		return "➡️"
	default:
		return "❓"
	}
}

func nodeKindToEmoji(kind NodeKind) string {
	switch kind {
	case NodeKindUser:
		return "👤"
	case NodeKindRole:
		return "🎭"
	case NodeKindGroup:
		return "👥"
	case NodeKindServiceAccount:
		return "🤖"
	case NodeKindInstance:
		return "💻"
	case NodeKindFunction:
		return "λ"
	case NodeKindDatabase:
		return "🗄️"
	case NodeKindBucket:
		return "🪣"
	case NodeKindSecret:
		return "🔐"
	case NodeKindInternet:
		return "🌍"
	case NodeKindNetwork:
		return "🔌"
	default:
		return "📦"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// itoa converts an integer to a string efficiently for small numbers
func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
