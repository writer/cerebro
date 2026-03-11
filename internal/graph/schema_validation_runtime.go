package graph

import "strings"

// SchemaValidationMode controls ingestion behavior on ontology validation issues.
type SchemaValidationMode string

const (
	SchemaValidationOff     SchemaValidationMode = "off"
	SchemaValidationWarn    SchemaValidationMode = "warn"
	SchemaValidationEnforce SchemaValidationMode = "enforce"
)

// SchemaValidationStats captures runtime validation counters since process start.
type SchemaValidationStats struct {
	Mode SchemaValidationMode `json:"mode"`

	NodeWarnings int `json:"node_warnings"`
	EdgeWarnings int `json:"edge_warnings"`
	NodeRejected int `json:"node_rejected"`
	EdgeRejected int `json:"edge_rejected"`

	NodeWarningByCode map[string]int `json:"node_warning_by_code,omitempty"`
	EdgeWarningByCode map[string]int `json:"edge_warning_by_code,omitempty"`
	NodeRejectByCode  map[string]int `json:"node_reject_by_code,omitempty"`
	EdgeRejectByCode  map[string]int `json:"edge_reject_by_code,omitempty"`
}

// ParseSchemaValidationMode normalizes free-form input into one of the known modes.
func ParseSchemaValidationMode(raw string) SchemaValidationMode {
	return normalizeSchemaValidationMode(SchemaValidationMode(raw))
}

func normalizeSchemaValidationMode(mode SchemaValidationMode) SchemaValidationMode {
	switch SchemaValidationMode(strings.ToLower(strings.TrimSpace(string(mode)))) {
	case SchemaValidationOff:
		return SchemaValidationOff
	case SchemaValidationEnforce:
		return SchemaValidationEnforce
	default:
		return SchemaValidationWarn
	}
}

func newSchemaValidationStats(mode SchemaValidationMode) SchemaValidationStats {
	return SchemaValidationStats{
		Mode:              mode,
		NodeWarningByCode: make(map[string]int),
		EdgeWarningByCode: make(map[string]int),
		NodeRejectByCode:  make(map[string]int),
		EdgeRejectByCode:  make(map[string]int),
	}
}

// SetSchemaValidationMode updates runtime validation mode.
func (g *Graph) SetSchemaValidationMode(mode SchemaValidationMode) {
	g.mu.Lock()
	defer g.mu.Unlock()

	mode = normalizeSchemaValidationMode(mode)
	g.schemaValidationMode = mode
	g.schemaValidationStats.Mode = mode
}

// SchemaValidationMode returns current runtime validation mode.
func (g *Graph) SchemaValidationMode() SchemaValidationMode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.schemaValidationMode
}

// SchemaValidationStats returns a copy of current runtime validation counters.
func (g *Graph) SchemaValidationStats() SchemaValidationStats {
	g.mu.RLock()
	defer g.mu.RUnlock()

	stats := g.schemaValidationStats
	stats.NodeWarningByCode = cloneCounterMap(g.schemaValidationStats.NodeWarningByCode)
	stats.EdgeWarningByCode = cloneCounterMap(g.schemaValidationStats.EdgeWarningByCode)
	stats.NodeRejectByCode = cloneCounterMap(g.schemaValidationStats.NodeRejectByCode)
	stats.EdgeRejectByCode = cloneCounterMap(g.schemaValidationStats.EdgeRejectByCode)
	return stats
}

func cloneCounterMap(values map[string]int) map[string]int {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]int, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func (g *Graph) applyNodeSchemaValidationLocked(node *Node) bool {
	mode := normalizeSchemaValidationMode(g.schemaValidationMode)
	if mode == SchemaValidationOff {
		return true
	}

	issues := ValidateNodeAgainstSchema(node)
	if len(issues) == 0 {
		return true
	}

	if mode == SchemaValidationEnforce {
		g.recordNodeSchemaIssuesLocked(issues, true)
		return false
	}
	g.recordNodeSchemaIssuesLocked(issues, false)
	return true
}

func (g *Graph) applyEdgeSchemaValidationLocked(edge *Edge) bool {
	mode := normalizeSchemaValidationMode(g.schemaValidationMode)
	if mode == SchemaValidationOff {
		return true
	}

	var source *Node
	if node, ok := g.nodes[edge.Source]; ok && node != nil && node.DeletedAt == nil {
		source = node
	}
	var target *Node
	if node, ok := g.nodes[edge.Target]; ok && node != nil && node.DeletedAt == nil {
		target = node
	}

	issues := ValidateEdgeAgainstSchema(edge, source, target)
	if len(issues) == 0 {
		return true
	}

	if mode == SchemaValidationEnforce {
		g.recordEdgeSchemaIssuesLocked(issues, true)
		return false
	}
	g.recordEdgeSchemaIssuesLocked(issues, false)
	return true
}

func (g *Graph) recordNodeSchemaIssuesLocked(issues []SchemaValidationIssue, rejected bool) {
	if rejected {
		g.schemaValidationStats.NodeRejected += len(issues)
		for _, issue := range issues {
			g.schemaValidationStats.NodeRejectByCode[string(issue.Code)]++
		}
		return
	}

	g.schemaValidationStats.NodeWarnings += len(issues)
	for _, issue := range issues {
		g.schemaValidationStats.NodeWarningByCode[string(issue.Code)]++
	}
}

func (g *Graph) recordEdgeSchemaIssuesLocked(issues []SchemaValidationIssue, rejected bool) {
	if rejected {
		g.schemaValidationStats.EdgeRejected += len(issues)
		for _, issue := range issues {
			g.schemaValidationStats.EdgeRejectByCode[string(issue.Code)]++
		}
		return
	}

	g.schemaValidationStats.EdgeWarnings += len(issues)
	for _, issue := range issues {
		g.schemaValidationStats.EdgeWarningByCode[string(issue.Code)]++
	}
}
