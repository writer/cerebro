package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graphingest"
)

const outputPath = "docs/GRAPH_ONTOLOGY_AUTOGEN.md"

type domainCoverage struct {
	Domain         string
	SourcePatterns map[string]struct{}
	NodeKinds      map[string]struct{}
}

func main() {
	nodeDefs := graph.RegisteredNodeKinds()
	edgeDefs := graph.RegisteredEdgeKinds()
	mappingConfig, err := graphingest.LoadDefaultConfig()
	if err != nil {
		fatalf("load default mappings: %v", err)
	}

	content := renderMarkdown(nodeDefs, edgeDefs, mappingConfig)
	if err := os.WriteFile(outputPath, []byte(content), 0o644); err != nil { // #nosec G306 -- generated docs are intended to be repository-readable artifacts.
		fatalf("write %s: %v", outputPath, err)
	}
}

func renderMarkdown(nodeDefs []graph.NodeKindDefinition, edgeDefs []graph.EdgeKindDefinition, mappings graphingest.MappingConfig) string {
	domainRows := collectDomainCoverage(mappings)
	mappedKinds := collectMappedNodeKinds(mappings)
	unmappedKinds := collectUnmappedNodeKinds(nodeDefs, mappedKinds)

	var b strings.Builder
	b.WriteString("# Graph Ontology Auto-Generated Catalog\n\n")
	b.WriteString("Generated from `graph.RegisteredNodeKinds()`, `graph.RegisteredEdgeKinds()`, and `internal/graphingest/mappings.yaml` via `go run ./scripts/generate_graph_ontology_docs/main.go`.\n\n")
	fmt.Fprintf(&b, "- Node kinds: **%d**\n", len(nodeDefs))
	fmt.Fprintf(&b, "- Edge kinds: **%d**\n", len(edgeDefs))
	fmt.Fprintf(&b, "- Mapping rules: **%d**\n", len(mappings.Mappings))
	fmt.Fprintf(&b, "- Source domains: **%d**\n\n", len(domainRows))

	b.WriteString("## Node Kinds\n\n")
	b.WriteString("| Kind | Categories | Required Properties | Relationships |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, def := range nodeDefs {
		categories := make([]string, 0, len(def.Categories))
		for _, category := range def.Categories {
			categories = append(categories, string(category))
		}
		sort.Strings(categories)
		required := append([]string(nil), def.RequiredProperties...)
		sort.Strings(required)
		relationships := make([]string, 0, len(def.Relationships))
		for _, rel := range def.Relationships {
			relationships = append(relationships, string(rel))
		}
		sort.Strings(relationships)

		fmt.Fprintf(&b,
			"| `%s` | %s | %s | %s |\n",
			def.Kind,
			joinOrDash(categories),
			joinCodeOrDash(required),
			joinCodeOrDash(relationships),
		)
	}

	b.WriteString("\n## Node Metadata Profiles\n\n")
	b.WriteString("| Kind | Required Metadata | Optional Metadata | Timestamp Keys | Enum Constraints |\n")
	b.WriteString("|---|---|---|---|---|\n")
	profiled := 0
	for _, def := range nodeDefs {
		profile := def.MetadataProfile
		if len(profile.RequiredKeys) == 0 && len(profile.OptionalKeys) == 0 && len(profile.TimestampKeys) == 0 && len(profile.EnumValues) == 0 {
			continue
		}
		profiled++
		fmt.Fprintf(&b,
			"| `%s` | %s | %s | %s | %s |\n",
			def.Kind,
			joinCodeOrDash(profile.RequiredKeys),
			joinCodeOrDash(profile.OptionalKeys),
			joinCodeOrDash(profile.TimestampKeys),
			renderEnumConstraints(profile.EnumValues),
		)
	}
	if profiled == 0 {
		b.WriteString("| _none_ | - | - | - | - |\n")
	}

	b.WriteString("\n## Edge Kinds\n\n")
	b.WriteString("| Kind | Description |\n")
	b.WriteString("|---|---|\n")
	for _, def := range edgeDefs {
		desc := strings.TrimSpace(def.Description)
		if desc == "" {
			desc = "-"
		}
		fmt.Fprintf(&b, "| `%s` | %s |\n", def.Kind, escapePipes(desc))
	}

	b.WriteString("\n## Source Domain Coverage\n\n")
	b.WriteString("| Domain | Source Patterns | Node Kinds |\n")
	b.WriteString("|---|---|---|\n")
	for _, row := range domainRows {
		patterns := sortedKeys(row.SourcePatterns)
		nodeKinds := sortedKeys(row.NodeKinds)
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", row.Domain, joinCodeOrDash(patterns), joinCodeOrDash(nodeKinds))
	}

	b.WriteString("\n## Unmapped Built-in Node Kinds\n\n")
	fmt.Fprintf(&b, "Total unmapped kinds: **%d**\n\n", len(unmappedKinds))
	if len(unmappedKinds) == 0 {
		b.WriteString("All registered node kinds are represented in declarative mappings.\n")
	} else {
		for _, kind := range unmappedKinds {
			fmt.Fprintf(&b, "- `%s`\n", kind)
		}
	}

	return b.String()
}

func collectDomainCoverage(mappings graphingest.MappingConfig) []domainCoverage {
	byDomain := make(map[string]*domainCoverage)
	for _, mapping := range mappings.Mappings {
		domain := mappingSourceDomain(mapping.Source)
		if domain == "" {
			continue
		}
		row, ok := byDomain[domain]
		if !ok {
			row = &domainCoverage{
				Domain:         domain,
				SourcePatterns: make(map[string]struct{}),
				NodeKinds:      make(map[string]struct{}),
			}
			byDomain[domain] = row
		}
		row.SourcePatterns[strings.TrimSpace(mapping.Source)] = struct{}{}
		for _, node := range mapping.Nodes {
			kind := strings.ToLower(strings.TrimSpace(node.Kind))
			if kind == "" {
				continue
			}
			row.NodeKinds[kind] = struct{}{}
		}
	}
	out := make([]domainCoverage, 0, len(byDomain))
	for _, row := range byDomain {
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

func collectMappedNodeKinds(mappings graphingest.MappingConfig) map[string]struct{} {
	kinds := make(map[string]struct{})
	for _, mapping := range mappings.Mappings {
		for _, node := range mapping.Nodes {
			kind := strings.ToLower(strings.TrimSpace(node.Kind))
			if kind == "" {
				continue
			}
			kinds[kind] = struct{}{}
		}
	}
	return kinds
}

func collectUnmappedNodeKinds(nodeDefs []graph.NodeKindDefinition, mappedKinds map[string]struct{}) []string {
	unmapped := make([]string, 0)
	for _, def := range nodeDefs {
		kind := strings.ToLower(strings.TrimSpace(string(def.Kind)))
		if kind == "" || kind == string(graph.NodeKindAny) {
			continue
		}
		if _, ok := mappedKinds[kind]; ok {
			continue
		}
		unmapped = append(unmapped, kind)
	}
	sort.Strings(unmapped)
	return unmapped
}

func mappingSourceDomain(source string) string {
	parts := strings.Split(strings.TrimSpace(source), ".")
	if len(parts) < 3 {
		return ""
	}
	if parts[0] != "ensemble" || parts[1] != "tap" {
		return ""
	}
	return strings.TrimSpace(parts[2])
}

func joinOrDash(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(escapePipesAll(values), ", ")
}

func joinCodeOrDash(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, "`"+escapePipes(value)+"`")
	}
	return strings.Join(quoted, ", ")
}

func escapePipesAll(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, escapePipes(value))
	}
	return out
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func escapePipes(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}

func renderEnumConstraints(values map[string][]string) string {
	if len(values) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return "-"
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		enumValues := append([]string(nil), values[key]...)
		sort.Strings(enumValues)
		renderedValues := make([]string, 0, len(enumValues))
		for _, enumValue := range enumValues {
			enumValue = strings.TrimSpace(enumValue)
			if enumValue == "" {
				continue
			}
			renderedValues = append(renderedValues, "`"+escapePipes(enumValue)+"`")
		}
		if len(renderedValues) == 0 {
			continue
		}
		parts = append(parts, "`"+escapePipes(key)+"`="+strings.Join(renderedValues, ", "))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "<br>")
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
