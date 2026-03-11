package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/devex"
)

const (
	sourceCatalogPath   = devex.DefaultCodegenCatalogPath
	outputMarkdownPath  = "docs/DEVEX_CODEGEN_AUTOGEN.md"
	outputContractsPath = "docs/DEVEX_CODEGEN_CATALOG.json"
	makefilePath        = "Makefile"
	workflowPath        = ".github/workflows/ci.yml"
)

func main() {
	catalog, err := devex.LoadBuiltInCodegenCatalog()
	if err != nil {
		fatalf("load codegen catalog: %v", err)
	}
	if err := devex.ValidateCodegenCatalogReferences(catalog, makefilePath, workflowPath); err != nil {
		fatalf("validate codegen catalog references: %v", err)
	}

	markdown := renderMarkdown(catalog)
	if err := os.WriteFile(outputMarkdownPath, []byte(markdown), 0o644); err != nil { // #nosec G306 -- generated docs are repository-readable artifacts.
		fatalf("write %s: %v", outputMarkdownPath, err)
	}

	payload, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		fatalf("marshal codegen catalog: %v", err)
	}
	if err := os.WriteFile(outputContractsPath, append(payload, '\n'), 0o644); err != nil { // #nosec G306 -- generated docs are repository-readable artifacts.
		fatalf("write %s: %v", outputContractsPath, err)
	}
}

func renderMarkdown(catalog devex.CodegenCatalog) string {
	var b strings.Builder
	b.WriteString("# DevEx Codegen Catalog\n\n")
	fmt.Fprintf(&b, "Generated from `%s` via `go run ./scripts/generate_devex_codegen_docs/main.go`.\n\n", sourceCatalogPath)
	fmt.Fprintf(&b, "- Catalog API version: **%s**\n", escapePipes(catalog.APIVersion))
	fmt.Fprintf(&b, "- Catalog kind: **%s**\n", escapePipes(catalog.Kind))
	fmt.Fprintf(&b, "- Families: **%d**\n\n", len(catalog.Families))

	b.WriteString("## CI to Local Map\n\n")
	b.WriteString("| Family | Generator | Local Checks | CI Jobs | Outputs |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, family := range catalog.Families {
		generator := "-"
		if family.Generator != nil && strings.TrimSpace(family.Generator.MakeTarget) != "" {
			generator = codeOrDash(family.Generator.MakeTarget)
		}
		checks := make([]string, 0, len(family.Checks))
		for _, check := range family.Checks {
			if strings.TrimSpace(check.MakeTarget) != "" {
				checks = append(checks, check.MakeTarget)
				continue
			}
			checks = append(checks, check.Key)
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
			escapePipes(family.ID),
			generator,
			joinCodeOrDash(checks),
			joinCodeOrDash(family.CIJobs),
			joinCodeOrDash(family.Outputs),
		)
	}

	b.WriteString("\n## Families\n\n")
	for _, family := range catalog.Families {
		fmt.Fprintf(&b, "### `%s`\n\n", escapePipes(family.ID))
		fmt.Fprintf(&b, "%s\n\n", textOrDash(family.Summary))
		fmt.Fprintf(&b, "- Change reason: %s\n", textOrDash(family.ChangeReason))
		if family.Generator != nil {
			fmt.Fprintf(&b, "- Generator: %s\n", stepLine(*family.Generator))
		}
		if len(family.Checks) > 0 {
			b.WriteString("- Checks:\n")
			for _, check := range family.Checks {
				fmt.Fprintf(&b, "  - %s\n", stepLine(check))
			}
		}
		fmt.Fprintf(&b, "- Triggers: %s\n", joinCodeOrDash(family.Triggers))
		fmt.Fprintf(&b, "- Outputs: %s\n", joinCodeOrDash(family.Outputs))
		fmt.Fprintf(&b, "- CI jobs: %s\n\n", joinCodeOrDash(family.CIJobs))
	}

	b.WriteString("## Notes\n\n")
	b.WriteString("- `devex/codegen_catalog.json` is the source of truth for generator families, trigger globs, local checks, and CI job mapping.\n")
	b.WriteString("- `docs/DEVEX_CODEGEN_CATALOG.json` is the machine-readable artifact for editors and external tooling.\n")
	b.WriteString("- `scripts/devex.py` consumes this catalog so new generator families stop requiring handwritten routing branches.\n")
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
	sort.Strings(clean)
	quoted := make([]string, 0, len(clean))
	for _, value := range clean {
		quoted = append(quoted, "`"+escapePipes(value)+"`")
	}
	return strings.Join(quoted, ", ")
}

func stepLine(step devex.CodegenStep) string {
	parts := make([]string, 0, len(step.Command))
	for _, part := range step.Command {
		parts = append(parts, escapePipes(strings.TrimSpace(part)))
	}
	label := step.Key
	if label == "" {
		label = step.MakeTarget
	}
	if label == "" {
		label = "command"
	}
	if step.MakeTarget != "" {
		return fmt.Sprintf("`%s` -> `%s`", escapePipes(label), escapePipes(step.MakeTarget))
	}
	return fmt.Sprintf("`%s` -> `%s`", escapePipes(label), strings.Join(parts, " "))
}

func escapePipes(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), "|", "\\|")
}

func codeOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return "`" + escapePipes(value) + "`"
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
