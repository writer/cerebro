package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/writer/cerebro/internal/connectors"
)

const (
	outputMarkdownPath = "docs/CONNECTOR_PROVISIONING_AUTOGEN.md"
	outputCatalogPath  = "docs/CONNECTOR_PROVISIONING_CATALOG.json"
)

func main() {
	catalog := connectors.BuiltInCatalog()
	if err := writeJSON(outputCatalogPath, catalog); err != nil {
		panic(err)
	}
	if err := os.WriteFile(outputMarkdownPath, []byte(renderMarkdown(catalog)), 0o644); err != nil { // #nosec G306 -- generated docs are repository-readable artifacts.
		panic(err)
	}
}

func writeJSON(path string, data any) error {
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(path, encoded, 0o644) // #nosec G306 -- generated docs are repository-readable artifacts.
}

func renderMarkdown(catalog connectors.Catalog) string {
	var b strings.Builder
	b.WriteString("# Connector Provisioning Auto-Generated Catalog\n\n")
	b.WriteString("Generated from `internal/connectors` via `go run ./scripts/generate_connector_docs/main.go`.\n\n")
	b.WriteString("This catalog keeps provider-specific provisioning artifacts, required permissions, and validation expectations in one machine-readable surface.\n\n")
	for _, provider := range catalog.Providers {
		fmt.Fprintf(&b, "## %s\n\n", provider.Title)
		fmt.Fprintf(&b, "%s\n\n", provider.Summary)
		b.WriteString("### Artifacts\n\n")
		for _, artifact := range provider.Artifacts {
			fmt.Fprintf(&b, "- `%s`: %s\n", artifact.Kind, artifact.Summary)
			for _, file := range artifact.Files {
				fmt.Fprintf(&b, "  - `%s`\n", file)
			}
		}
		b.WriteString("\n### Required Permissions\n\n")
		for _, permission := range provider.RequiredPermissions {
			fmt.Fprintf(&b, "- `%s` (`%s`): %s\n", permission.Name, permission.Scope, permission.Summary)
			for _, condition := range permission.Conditions {
				fmt.Fprintf(&b, "  - Condition: %s\n", condition)
			}
			if strings.TrimSpace(permission.ProviderRef) != "" {
				fmt.Fprintf(&b, "  - Reference: %s\n", permission.ProviderRef)
			}
		}
		b.WriteString("\n### Validation Checks\n\n")
		for _, check := range provider.ValidationChecks {
			fmt.Fprintf(&b, "- `%s` (`%s`): %s\n", check.ID, check.Mode, check.Summary)
			if len(check.RequiredInputs) > 0 {
				fmt.Fprintf(&b, "  - Inputs: `%s`\n", strings.Join(check.RequiredInputs, "`, `"))
			}
		}
		b.WriteString("\n### CLI\n\n")
		fmt.Fprintf(&b, "- Scaffold: `cerebro connector scaffold %s --output-dir ./.cerebro/connectors/%s`\n", provider.ID, provider.ID)
		fmt.Fprintf(&b, "- Validate: `cerebro connector validate %s --dry-run`\n\n", provider.ID)
	}
	b.WriteString("## Machine-Readable Catalog\n\n")
	b.WriteString("- `docs/CONNECTOR_PROVISIONING_CATALOG.json` is the machine-readable catalog for code generation and extension tooling.\n")
	return b.String()
}
