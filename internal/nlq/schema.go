package nlq

import (
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

// SchemaContext captures the compact graph/query vocabulary used to constrain
// NL-to-query translation.
type SchemaContext struct {
	ContractVersion string                     `json:"contract_version"`
	RegistryVersion int64                      `json:"registry_version"`
	NodeKinds       []graph.NodeKindDefinition `json:"node_kinds"`
	EdgeKinds       []graph.EdgeKindDefinition `json:"edge_kinds"`
	Templates       []graph.GraphQueryTemplate `json:"templates"`
}

// DefaultSchemaContext snapshots the currently registered graph vocabulary.
func DefaultSchemaContext() SchemaContext {
	return SchemaContext{
		ContractVersion: graph.GraphOntologyContractVersion,
		RegistryVersion: graph.SchemaVersion(),
		NodeKinds:       graph.RegisteredNodeKinds(),
		EdgeKinds:       graph.RegisteredEdgeKinds(),
		Templates:       graph.DefaultGraphQueryTemplates(),
	}
}

func (s SchemaContext) hasNodeKind(kind graph.NodeKind) bool {
	for _, candidate := range s.NodeKinds {
		if candidate.Kind == kind {
			return true
		}
	}
	return false
}

// Prompt renders a compact structured prompt describing the allowed read-only
// operations and the graph schema vocabulary.
func (s SchemaContext) Prompt() string {
	var builder strings.Builder

	builder.WriteString("You translate natural-language security questions into read-only Cerebro query plans.\n")
	builder.WriteString("Return JSON only. Never request graph mutations or write operations.\n")
	builder.WriteString("Allowed plan kinds: entity_query, findings_query, entity_findings_query, reverse_access_query, graph_change_diff_query.\n")
	builder.WriteString("Allowed filters: node kinds, node categories, node capabilities, provider, account, region, severity, free-text search, max_depth, temporal since/until windows.\n")
	fmt.Fprintf(&builder, "Graph contract: %s, schema version: %d.\n", s.ContractVersion, s.RegistryVersion)

	builder.WriteString("Node kinds:\n")
	for _, def := range s.NodeKinds {
		builder.WriteString("- ")
		builder.WriteString(string(def.Kind))
		if len(def.Categories) > 0 {
			builder.WriteString(" categories=")
			builder.WriteString(joinNodeCategories(def.Categories))
		}
		if len(def.Capabilities) > 0 {
			builder.WriteString(" capabilities=")
			builder.WriteString(joinNodeCapabilities(def.Capabilities))
		}
		if len(def.Relationships) > 0 {
			builder.WriteString(" relationships=")
			builder.WriteString(joinEdgeKinds(def.Relationships))
		}
		if strings.TrimSpace(def.Description) != "" {
			builder.WriteString(" description=")
			builder.WriteString(strings.TrimSpace(def.Description))
		}
		builder.WriteByte('\n')
	}

	builder.WriteString("Edge kinds:\n")
	for _, def := range s.EdgeKinds {
		builder.WriteString("- ")
		builder.WriteString(string(def.Kind))
		if strings.TrimSpace(def.Description) != "" {
			builder.WriteString(" description=")
			builder.WriteString(strings.TrimSpace(def.Description))
		}
		builder.WriteByte('\n')
	}

	builder.WriteString("Reusable graph templates:\n")
	for _, template := range s.Templates {
		builder.WriteString("- ")
		builder.WriteString(strings.TrimSpace(template.ID))
		builder.WriteString(": ")
		builder.WriteString(strings.TrimSpace(template.Description))
		builder.WriteByte('\n')
	}

	return builder.String()
}

func joinNodeCategories(values []graph.NodeKindCategory) string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(string(value)) == "" {
			continue
		}
		out = append(out, string(value))
	}
	return strings.Join(out, ",")
}

func joinNodeCapabilities(values []graph.NodeKindCapability) string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(string(value)) == "" {
			continue
		}
		out = append(out, string(value))
	}
	return strings.Join(out, ",")
}

func joinEdgeKinds(values []graph.EdgeKind) string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(string(value)) == "" {
			continue
		}
		out = append(out, string(value))
	}
	return strings.Join(out, ",")
}
