package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/writer/cerebro/internal/connectordefinitions/openapigen"
)

func main() {
	var specPath string
	var outPath string
	var reportPath string
	var sourceID string
	var tenantID string
	var displayName string
	var description string
	var categories string
	var baseURL string
	var authModel string
	var providerAPIReferences string
	var maxFamilies int
	var allFamilies bool
	flag.StringVar(&specPath, "spec", "", "OpenAPI document path")
	flag.StringVar(&outPath, "out", "", "output connector definition JSON path; stdout when empty")
	flag.StringVar(&reportPath, "report-out", "", "optional generation report JSON path")
	flag.StringVar(&sourceID, "source-id", "", "connector source id; inferred from info.title when empty")
	flag.StringVar(&tenantID, "tenant-id", "", "tenant id; defaults to builtin_catalog")
	flag.StringVar(&displayName, "display-name", "", "connector display name; inferred from info.title when empty")
	flag.StringVar(&description, "description", "", "connector description; inferred from info.description when empty")
	flag.StringVar(&categories, "categories", "", "comma-separated connector categories")
	flag.StringVar(&baseURL, "base-url", "", "provider API base URL; inferred from OpenAPI servers when empty")
	flag.StringVar(&authModel, "auth-model", "", "auth model override")
	flag.StringVar(&providerAPIReferences, "provider-api-references", "", "comma-separated provider-owned API spec or reference URLs")
	flag.IntVar(&maxFamilies, "max-families", 4, "maximum selected resource families; ignored when -all-families is set")
	flag.BoolVar(&allFamilies, "all-families", false, "select every sourcegen-ready endpoint instead of proof-gate top families")
	flag.Parse()

	if strings.TrimSpace(specPath) == "" {
		fail(fmt.Errorf("-spec is required"))
	}
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		fail(err)
	}
	definition, report, err := openapigen.Generate(doc, openapigen.Request{
		SourceID:              sourceID,
		TenantID:              tenantID,
		DisplayName:           displayName,
		Description:           description,
		Categories:            splitList(categories),
		BaseURL:               baseURL,
		AuthModel:             authModel,
		ProviderAPIReferences: splitList(providerAPIReferences),
		MaxFamilies:           maxFamilies,
		AllFamilies:           allFamilies,
	})
	if err != nil {
		fail(err)
	}
	if err := writeJSON(outPath, definition); err != nil {
		fail(err)
	}
	if strings.TrimSpace(reportPath) != "" {
		if err := writeJSON(reportPath, report); err != nil {
			fail(err)
		}
	}
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := []string{}
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func writeJSON(path string, value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if strings.TrimSpace(path) == "" {
		_, err = os.Stdout.Write(payload)
		return err
	}
	return os.WriteFile(path, payload, 0o600)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
