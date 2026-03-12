package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/apicontractcompat"
)

const (
	openAPIPath         = "api/openapi.yaml"
	outputMarkdownPath  = "docs/API_CONTRACTS_AUTOGEN.md"
	outputContractsPath = "docs/API_CONTRACTS.json"
)

func main() {
	catalog, err := apicontractcompat.BuildCatalogFromFile(openAPIPath, time.Time{})
	if err != nil {
		fatalf("build api contract catalog: %v", err)
	}
	markdown := renderMarkdown(catalog)
	if err := os.WriteFile(outputMarkdownPath, []byte(markdown), 0o644); err != nil { // #nosec G306 -- generated docs are repository-readable artifacts.
		fatalf("write %s: %v", outputMarkdownPath, err)
	}
	payload, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		fatalf("marshal api contract catalog: %v", err)
	}
	if err := os.WriteFile(outputContractsPath, append(payload, '\n'), 0o644); err != nil { // #nosec G306 -- generated docs are repository-readable artifacts.
		fatalf("write %s: %v", outputContractsPath, err)
	}
}

func renderMarkdown(catalog apicontractcompat.Catalog) string {
	var b strings.Builder
	b.WriteString("# HTTP API Contracts\n\n")
	b.WriteString("Generated from `api/openapi.yaml` via `go run ./scripts/generate_api_contract_docs/main.go`.\n\n")
	fmt.Fprintf(&b, "- Catalog API version: **%s**\n", escape(catalog.APIVersion))
	fmt.Fprintf(&b, "- Catalog kind: **%s**\n", escape(catalog.Kind))
	if !catalog.GeneratedAt.IsZero() {
		fmt.Fprintf(&b, "- Generated at: **%s**\n", catalog.GeneratedAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "- Endpoints: **%d**\n\n", catalog.EndpointCount)

	b.WriteString("## Endpoint Summary\n\n")
	b.WriteString("| Endpoint | Query Params | Required Request Fields | Success Status Codes |\n")
	b.WriteString("|---|---:|---:|---|\n")
	for _, endpoint := range catalog.Endpoints {
		codes := make([]string, 0, len(endpoint.SuccessResponses))
		for _, response := range endpoint.SuccessResponses {
			codes = append(codes, response.StatusCode)
		}
		fmt.Fprintf(&b, "| `%s` | %d | %d | %s |\n",
			escape(endpoint.ID),
			len(endpoint.QueryParams),
			requiredFieldCount(endpoint.Request),
			joinCodes(codes),
		)
	}

	b.WriteString("\n## Notes\n\n")
	b.WriteString("- `docs/API_CONTRACTS.json` is the machine-readable baseline used by compatibility checks.\n")
	b.WriteString("- Breaking changes include removed endpoints, removed query parameters, removed success status codes, removed response fields, and request/response field type changes.\n")
	b.WriteString("- Additive endpoints, query parameters, optional request fields, and response fields remain compatible.\n")
	return b.String()
}

func requiredFieldCount(request *apicontractcompat.RequestContract) int {
	if request == nil {
		return 0
	}
	return len(request.RequiredFields)
}

func joinCodes(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return "`" + strings.Join(values, "`, `") + "`"
}

func escape(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), "|", "\\|")
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
