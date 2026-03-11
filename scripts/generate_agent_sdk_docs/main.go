package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/agentsdk"
	"github.com/writer/cerebro/internal/app"
)

const (
	outputMarkdownPath  = "docs/AGENT_SDK_AUTOGEN.md"
	outputContractsPath = "docs/AGENT_SDK_CONTRACTS.json"
)

func main() {
	catalog := agentsdk.BuildCatalog(agentSDKTools(), agentsdk.ZeroGeneratedAt())
	markdown := renderMarkdown(catalog)
	if err := os.WriteFile(outputMarkdownPath, []byte(markdown), 0o644); err != nil { // #nosec G306 -- generated docs are repository-readable artifacts.
		fatalf("write %s: %v", outputMarkdownPath, err)
	}

	payload, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		fatalf("marshal agent sdk contract catalog: %v", err)
	}
	if err := os.WriteFile(outputContractsPath, append(payload, '\n'), 0o644); err != nil { // #nosec G306 -- generated docs are repository-readable artifacts.
		fatalf("write %s: %v", outputContractsPath, err)
	}
}

func agentSDKTools() []agents.Tool {
	application := &app.App{Config: &app.Config{}}
	return application.AgentSDKTools()
}

func renderMarkdown(catalog agentsdk.Catalog) string {
	var b strings.Builder
	b.WriteString("# Agent SDK Auto-Generated Contract Catalog\n\n")
	b.WriteString("Generated from the shared `App.AgentSDKTools()` registry and `internal/agentsdk` contract metadata via `go run ./scripts/generate_agent_sdk_docs/main.go`.\n\n")
	fmt.Fprintf(&b, "- Catalog API version: **%s**\n", escapePipes(catalog.APIVersion))
	fmt.Fprintf(&b, "- Catalog kind: **%s**\n", escapePipes(catalog.Kind))
	fmt.Fprintf(&b, "- MCP protocol version: **%s**\n", escapePipes(catalog.ProtocolVersion))
	fmt.Fprintf(&b, "- Tools: **%d**\n", len(catalog.Tools))
	fmt.Fprintf(&b, "- Resources: **%d**\n", len(catalog.Resources))
	fmt.Fprintf(&b, "- MCP methods + notifications: **%d**\n\n", len(catalog.Methods))

	b.WriteString("## Tools\n\n")
	b.WriteString("| ID | Version | Internal Name | Method | Category | Execution | Async | Progress | Path | Permission |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|\n")
	for _, tool := range catalog.Tools {
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | %t | %t | `%s %s` | `%s` |\n",
			escapePipes(tool.ID),
			escapePipes(tool.Version),
			escapePipes(tool.ToolName),
			escapePipes(tool.SDKMethod),
			escapePipes(tool.Category),
			escapePipes(tool.ExecutionKind),
			tool.SupportsAsync,
			tool.SupportsProgress,
			escapePipes(tool.HTTPMethod),
			escapePipes(tool.HTTPPath),
			escapePipes(tool.RequiredPermission),
		)
	}

	b.WriteString("\n## Resources\n\n")
	b.WriteString("| URI | Version | Name | Permission |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, resource := range catalog.Resources {
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | `%s` |\n",
			escapePipes(resource.URI),
			escapePipes(resource.Version),
			textOrDash(resource.Name),
			escapePipes(resource.RequiredPermission),
		)
	}

	b.WriteString("\n## MCP Methods\n\n")
	b.WriteString("| Name | Kind | Description |\n")
	b.WriteString("|---|---|---|\n")
	for _, method := range catalog.Methods {
		fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n",
			escapePipes(method.Name),
			escapePipes(method.Kind),
			textOrDash(method.Description),
		)
	}

	b.WriteString("\n## Example Inputs\n\n")
	for _, tool := range catalog.Tools {
		if len(tool.ExampleInput) == 0 {
			continue
		}
		payload, err := json.MarshalIndent(tool.ExampleInput, "", "  ")
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "### `%s`\n\n```json\n%s\n```\n\n", escapePipes(tool.ID), string(payload))
	}

	b.WriteString("## Notes\n\n")
	b.WriteString("- `docs/AGENT_SDK_CONTRACTS.json` is the machine-readable catalog for SDK generation, resource discovery, and compatibility checks.\n")
	b.WriteString("- Public tool IDs are versioned independently from internal tool names so the SDK surface can stay stable while the substrate evolves.\n")
	b.WriteString("- `cerebro_report` is execution-backed by durable `platform.report_run` resources and supports async execution plus MCP progress notifications.\n")
	return b.String()
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
