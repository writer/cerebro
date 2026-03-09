package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graphingest"
)

const (
	outputMarkdownPath  = "docs/CLOUDEVENTS_AUTOGEN.md"
	outputContractsPath = "docs/CLOUDEVENTS_CONTRACTS.json"
)

func main() {
	config, err := graphingest.LoadDefaultConfig()
	if err != nil {
		fatalf("load default mappings: %v", err)
	}

	catalog := graphingest.BuildContractCatalog(config, time.Time{})
	markdown := renderMarkdown(catalog)
	if err := os.WriteFile(outputMarkdownPath, []byte(markdown), 0o644); err != nil { // #nosec G306 -- generated docs are intended to be repository-readable artifacts.
		fatalf("write %s: %v", outputMarkdownPath, err)
	}

	payload, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		fatalf("marshal contract catalog json: %v", err)
	}
	if err := os.WriteFile(outputContractsPath, append(payload, '\n'), 0o644); err != nil { // #nosec G306 -- generated docs are intended to be repository-readable artifacts.
		fatalf("write %s: %v", outputContractsPath, err)
	}
}

func renderMarkdown(catalog graphingest.ContractCatalog) string {
	totalWildcards := 0
	for _, contract := range catalog.Mappings {
		if contract.WildcardPattern {
			totalWildcards++
		}
	}

	var b strings.Builder
	b.WriteString("# CloudEvents Auto-Generated Contract Catalog\n\n")
	b.WriteString("Generated from `internal/events.CloudEvent` and `internal/graphingest/mappings.yaml` via `go run ./scripts/generate_cloudevents_docs/main.go`.\n\n")
	fmt.Fprintf(&b, "- Contract catalog API version: **%s**\n", escapePipes(catalog.APIVersion))
	fmt.Fprintf(&b, "- Contract catalog kind: **%s**\n", escapePipes(catalog.Kind))
	if !catalog.GeneratedAt.IsZero() {
		fmt.Fprintf(&b, "- Generated at: **%s**\n", catalog.GeneratedAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "- CloudEvent envelope fields: **%d**\n", len(catalog.EnvelopeFields))
	fmt.Fprintf(&b, "- TAP mapping rules: **%d**\n", len(catalog.Mappings))
	fmt.Fprintf(&b, "- Wildcard event patterns: **%d**\n", totalWildcards)
	fmt.Fprintf(&b, "- Distinct required data keys across mappings: **%d**\n", len(catalog.DistinctRequiredData))
	fmt.Fprintf(&b, "- Distinct optional data keys across mappings: **%d**\n\n", len(catalog.DistinctOptionalData))

	b.WriteString("## CloudEvent Envelope\n\n")
	b.WriteString("| Field | Type | Required |\n")
	b.WriteString("|---|---|---|\n")
	for _, field := range catalog.EnvelopeFields {
		required := "no"
		if field.Required {
			required = "yes"
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", field.Name, field.Type, required)
	}

	b.WriteString("\n## Mapping Contracts\n\n")
	b.WriteString("| Mapping | Source Pattern | Domain | Wildcard | apiVersion | contractVersion | schemaURL | Node Kinds | Edge Kinds | Required Data Keys | Optional Data Keys | Resolve Keys |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, contract := range catalog.Mappings {
		wildcard := "no"
		if contract.WildcardPattern {
			wildcard = "yes"
		}
		fmt.Fprintf(&b,
			"| `%s` | `%s` | `%s` | %s | `%s` | `%s` | %s | %s | %s | %s | %s | %s |\n",
			contract.Name,
			escapePipes(contract.SourcePattern),
			escapePipes(contract.Domain),
			wildcard,
			escapePipes(contract.APIVersion),
			escapePipes(contract.ContractVersion),
			joinCodeOrDash([]string{contract.SchemaURL}),
			joinCodeOrDash(contract.NodeKinds),
			joinCodeOrDash(contract.EdgeKinds),
			joinCodeOrDash(contract.RequiredDataKeys),
			joinCodeOrDash(contract.OptionalDataKeys),
			joinCodeOrDash(contract.ResolveKeys),
		)
	}

	b.WriteString("\n## Shared Context Keys Used by Templates\n\n")
	if len(catalog.DistinctContextKeys) == 0 {
		b.WriteString("No non-data context keys are referenced by mapper templates.\n")
	} else {
		for _, key := range catalog.DistinctContextKeys {
			fmt.Fprintf(&b, "- `%s`\n", key)
		}
	}

	b.WriteString("\n## Notes\n\n")
	b.WriteString("- `Required Data Keys` are data paths used in structural template locations (node id/kind, edge source/target/kind).\n")
	b.WriteString("- `Optional Data Keys` are data paths used in non-structural locations (names/properties/providers/effects).\n")
	b.WriteString("- `Resolve Keys` are keys used in `{{resolve(...)}}` expressions for identity canonicalization.\n")
	b.WriteString("- `docs/CLOUDEVENTS_CONTRACTS.json` is the machine-readable contract + data-schema artifact for automation and API surfaces.\n")
	b.WriteString("- Additions or changes to `internal/graphingest/mappings.yaml` should be accompanied by regenerated contract artifacts.\n")

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

func escapePipes(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
