package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

const (
	outputMarkdownPath  = "docs/GRAPH_REPORT_CONTRACTS_AUTOGEN.md"
	outputContractsPath = "docs/GRAPH_REPORT_CONTRACTS.json"
)

func main() {
	catalog := graph.BuildReportContractCatalog(time.Time{})
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

func renderMarkdown(catalog graph.ReportContractCatalog) string {
	var b strings.Builder
	b.WriteString("# Graph Report Contract Catalog\n\n")
	b.WriteString("Generated from the built-in report runtime registries via `go run ./scripts/generate_report_contract_docs/main.go`.\n\n")
	fmt.Fprintf(&b, "- Catalog API version: **%s**\n", escapePipes(catalog.APIVersion))
	fmt.Fprintf(&b, "- Catalog kind: **%s**\n", escapePipes(catalog.Kind))
	fmt.Fprintf(&b, "- Reports: **%d**\n", len(catalog.Reports))
	fmt.Fprintf(&b, "- Measures: **%d**\n", len(catalog.Measures))
	fmt.Fprintf(&b, "- Checks: **%d**\n", len(catalog.Checks))
	fmt.Fprintf(&b, "- Section envelopes: **%d**\n", len(catalog.SectionEnvelopes))
	fmt.Fprintf(&b, "- Section fragments: **%d**\n", len(catalog.SectionFragments))
	fmt.Fprintf(&b, "- Benchmark packs: **%d**\n\n", len(catalog.BenchmarkPacks))

	b.WriteString("## Reports\n\n")
	b.WriteString("| ID | Version | Category | Result Schema | Run Path | Measure Count | Check Count | Section Count |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, report := range catalog.Reports {
		runPath := "-"
		if report.Endpoint.RunPathTemplate != "" {
			runPath = "`" + escapePipes(report.Endpoint.RunPathTemplate) + "`"
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | %s | %d | %d | %d |\n",
			escapePipes(report.ID),
			escapePipes(report.Version),
			escapePipes(report.Category),
			escapePipes(report.ResultSchema),
			runPath,
			len(report.Measures),
			len(report.Checks),
			len(report.Sections),
		)
	}

	b.WriteString("\n## Measures\n\n")
	b.WriteString("| ID | Label | Value Type | Unit | Description |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, measure := range catalog.Measures {
		fmt.Fprintf(&b, "| `%s` | %s | `%s` | %s | %s |\n",
			escapePipes(measure.ID),
			codeOrDash(measure.Label),
			escapePipes(measure.ValueType),
			codeOrDash(measure.Unit),
			textOrDash(measure.Description),
		)
	}

	b.WriteString("\n## Checks\n\n")
	b.WriteString("| ID | Title | Severity | Description |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, check := range catalog.Checks {
		fmt.Fprintf(&b, "| `%s` | %s | `%s` | %s |\n",
			escapePipes(check.ID),
			textOrDash(check.Title),
			escapePipes(check.Severity),
			textOrDash(check.Description),
		)
	}

	b.WriteString("\n## Section Envelopes\n\n")
	b.WriteString("| ID | Version | Schema Name | Schema URL | Compatible Section Kinds |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, envelope := range catalog.SectionEnvelopes {
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | %s |\n",
			escapePipes(envelope.ID),
			escapePipes(envelope.Version),
			escapePipes(envelope.SchemaName),
			escapePipes(envelope.SchemaURL),
			joinCodeOrDash(envelope.CompatibleSectionKinds),
		)
	}
	b.WriteString("\n### Envelope Examples\n\n")
	for _, envelope := range catalog.SectionEnvelopes {
		example := buildSchemaExample(envelope.JSONSchema)
		if example == nil {
			continue
		}
		fmt.Fprintf(&b, "#### `%s`\n\n", escapePipes(envelope.ID))
		b.WriteString("```json\n")
		b.WriteString(mustMarshalIndented(example))
		b.WriteString("\n```\n\n")
	}

	b.WriteString("\n## Section Fragments\n\n")
	b.WriteString("| ID | Version | Schema Name | Schema URL | Description |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, fragment := range catalog.SectionFragments {
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | %s |\n",
			escapePipes(fragment.ID),
			escapePipes(fragment.Version),
			escapePipes(fragment.SchemaName),
			escapePipes(fragment.SchemaURL),
			textOrDash(fragment.Description),
		)
	}

	b.WriteString("\n## Benchmark Packs\n\n")
	b.WriteString("| ID | Version | Scope | Schema Name | Schema URL | Bound Measures |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, pack := range catalog.BenchmarkPacks {
		measureIDs := make([]string, 0, len(pack.MeasureBindings))
		for _, binding := range pack.MeasureBindings {
			measureIDs = append(measureIDs, binding.MeasureID)
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | `%s` | %s |\n",
			escapePipes(pack.ID),
			escapePipes(pack.Version),
			escapePipes(pack.Scope),
			escapePipes(pack.SchemaName),
			escapePipes(pack.SchemaURL),
			joinCodeOrDash(measureIDs),
		)
	}

	b.WriteString("\n## Notes\n\n")
	b.WriteString("- `docs/GRAPH_REPORT_CONTRACTS.json` is the machine-readable catalog for compatibility checks and generated tooling.\n")
	b.WriteString("- Section-envelope and benchmark-pack compatibility is version-governed; semantic changes require a version bump.\n")
	b.WriteString("- Report runs, attempts, and events should bind to these contracts by stable IDs rather than handler-local assumptions.\n")
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
	quoted := make([]string, 0, len(clean))
	for _, value := range clean {
		quoted = append(quoted, "`"+escapePipes(value)+"`")
	}
	return strings.Join(quoted, ", ")
}

func codeOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return "`" + escapePipes(value) + "`"
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

func buildSchemaExample(schema map[string]any) any {
	return buildSchemaExampleValue(schema)
}

func buildSchemaExampleValue(schema any) any {
	definition, _ := schema.(map[string]any)
	if len(definition) == 0 {
		return nil
	}
	if oneOf, ok := definition["oneOf"].([]any); ok && len(oneOf) > 0 {
		return buildSchemaExampleValue(oneOf[0])
	}
	if enumValues, ok := definition["enum"].([]string); ok && len(enumValues) > 0 {
		return enumValues[0]
	}
	if enumValues, ok := definition["enum"].([]any); ok && len(enumValues) > 0 {
		return enumValues[0]
	}
	typeName, _ := definition["type"].(string)
	switch strings.TrimSpace(typeName) {
	case "object":
		properties, _ := definition["properties"].(map[string]any)
		required := graph.SchemaRequiredKeys(definition["required"])
		example := make(map[string]any, len(required))
		for _, key := range required {
			example[key] = buildSchemaExampleValue(properties[key])
		}
		return example
	case "array":
		itemSchema := definition["items"]
		if itemSchema == nil {
			return []any{}
		}
		return []any{buildSchemaExampleValue(itemSchema)}
	case "string":
		format, _ := definition["format"].(string)
		if strings.TrimSpace(format) == "date-time" {
			return "2026-03-10T00:00:00Z"
		}
		return "example"
	case "integer":
		return 1
	case "number":
		return 1.0
	case "boolean":
		return true
	default:
		return "example"
	}
}

func mustMarshalIndented(value any) string {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(payload)
}
