package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	entities "github.com/writer/cerebro/internal/graph/entities"
)

const (
	outputMarkdownPath  = "docs/GRAPH_ENTITY_FACETS_AUTOGEN.md"
	outputContractsPath = "docs/GRAPH_ENTITY_FACETS.json"
)

func main() {
	catalog := entities.BuildEntityFacetContractCatalog(time.Time{})
	markdown := renderMarkdown(catalog)
	if err := os.WriteFile(outputMarkdownPath, []byte(markdown), 0o644); err != nil { // #nosec G306 -- generated docs are repository-readable artifacts.
		fatalf("write %s: %v", outputMarkdownPath, err)
	}
	payload, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		fatalf("marshal contract catalog json: %v", err)
	}
	if err := os.WriteFile(outputContractsPath, append(payload, '\n'), 0o644); err != nil { // #nosec G306 -- generated docs are repository-readable artifacts.
		fatalf("write %s: %v", outputContractsPath, err)
	}
}

func renderMarkdown(catalog entities.EntityFacetContractCatalog) string {
	var b strings.Builder
	b.WriteString("# Graph Entity Facet Contract Catalog\n\n")
	b.WriteString("Generated from the built-in entity facet registry via `go run ./scripts/generate_entity_facet_docs/main.go`.\n\n")
	fmt.Fprintf(&b, "- Catalog API version: **%s**\n", escapePipes(catalog.APIVersion))
	fmt.Fprintf(&b, "- Catalog kind: **%s**\n", escapePipes(catalog.Kind))
	fmt.Fprintf(&b, "- Facets: **%d**\n\n", len(catalog.Facets))
	b.WriteString("| ID | Version | Schema Name | Schema URL | Applicable Kinds | Claim Predicates | Source Keys |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, facet := range catalog.Facets {
		kinds := make([]string, 0, len(facet.ApplicableKinds))
		for _, kind := range facet.ApplicableKinds {
			kinds = append(kinds, string(kind))
		}
		predicates := append([]string(nil), facet.ClaimPredicates...)
		sourceKeys := append([]string(nil), facet.SourceKeys...)
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | %s | %s | %s |\n",
			escapePipes(facet.ID),
			escapePipes(facet.Version),
			escapePipes(facet.SchemaName),
			escapePipes(facet.SchemaURL),
			joinCodeOrDash(kinds),
			joinCodeOrDash(predicates),
			joinCodeOrDash(sourceKeys),
		)
	}
	b.WriteString("\n## Fields\n\n")
	for _, facet := range catalog.Facets {
		fmt.Fprintf(&b, "### `%s`\n\n", escapePipes(facet.ID))
		if text := strings.TrimSpace(facet.Description); text != "" {
			b.WriteString(text)
			b.WriteString("\n\n")
		}
		b.WriteString("| Field | Value Type | Description |\n")
		b.WriteString("|---|---|---|\n")
		for _, field := range facet.Fields {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n",
				escapePipes(field.Key),
				escapePipes(field.ValueType),
				textOrDash(field.Description),
			)
		}
		b.WriteString("\n")
	}
	b.WriteString("## Notes\n\n")
	b.WriteString("- `docs/GRAPH_ENTITY_FACETS.json` is the machine-readable facet catalog for compatibility checks and generated tooling.\n")
	b.WriteString("- Facet contract changes must bump the facet version when the semantic surface changes.\n")
	b.WriteString("- Entity detail and entity-summary should bind to facet IDs and schema URLs rather than provider-specific property names.\n")
	return b.String()
}

func joinCodeOrDash(values []string) string {
	clean := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		clean = append(clean, value)
	}
	if len(clean) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(clean))
	for _, value := range clean {
		parts = append(parts, "`"+escapePipes(value)+"`")
	}
	return strings.Join(parts, ", ")
}

func escapePipes(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), "|", "\\|")
}

func textOrDash(value string) string {
	value = escapePipes(value)
	if value == "" {
		return "-"
	}
	return value
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
