// Command connectoronboard orchestrates the full connector onboarding pipeline:
// OpenAPI spec → connector definition → catalog classification → sourcegen dry-run.
//
// It unifies openapidefgen, classifier, catalogcheck, and sourcegen into a
// single command that reduces connector onboarding from multiple manual steps
// to one invocation.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/connectordefinitions/openapigen"
	"github.com/writer/cerebro/internal/sourcegen"
)

// OnboardResult reports the full pipeline outcome.
type OnboardResult struct {
	SourceID         string                          `json:"source_id"`
	DisplayName      string                          `json:"display_name"`
	Stage            string                          `json:"stage"`
	Status           string                          `json:"status"`
	Verdict          string                          `json:"verdict"`
	Generateable     bool                            `json:"generateable"`
	ResourceFamilies int                             `json:"resource_families"`
	AuthModel        string                          `json:"auth_model"`
	BaseURL          string                          `json:"base_url"`
	Selected         []openapigen.Endpoint           `json:"selected_endpoints,omitempty"`
	Skipped          []openapigen.Endpoint           `json:"skipped_endpoints,omitempty"`
	MissingFeatures  []string                        `json:"missing_features,omitempty"`
	SourcegenError   string                          `json:"sourcegen_error,omitempty"`
	SourcegenFiles   []string                        `json:"sourcegen_files,omitempty"`
	Definition       connectordefinitions.Definition `json:"definition"`
	NextSteps        []string                        `json:"next_steps"`
	CatalogPath      string                          `json:"catalog_path,omitempty"`
	DryRun           bool                            `json:"dry_run"`
}

func main() {
	var specPath string
	var sourceID string
	var tenantID string
	var displayName string
	var description string
	var categories string
	var baseURL string
	var authModel string
	var maxFamilies int
	var allFamilies bool
	var outputDir string
	var catalogOut string
	var dryRun bool
	flag.StringVar(&specPath, "spec", "", "OpenAPI document path (required)")
	flag.StringVar(&sourceID, "source-id", "", "connector source id; inferred from spec title when empty")
	flag.StringVar(&tenantID, "tenant-id", "builtin_catalog", "tenant id for the catalog entry")
	flag.StringVar(&displayName, "display-name", "", "connector display name; inferred from spec title when empty")
	flag.StringVar(&description, "description", "", "connector description; inferred from spec description when empty")
	flag.StringVar(&categories, "category", "security", "comma-separated connector categories")
	flag.StringVar(&baseURL, "base-url", "", "provider API base URL; inferred from OpenAPI servers when empty")
	flag.StringVar(&authModel, "auth-model", "", "auth model override")
	flag.IntVar(&maxFamilies, "max-families", 4, "maximum selected resource families")
	flag.BoolVar(&allFamilies, "all-families", false, "select every endpoint")
	flag.StringVar(&outputDir, "output-dir", ".", "output directory for sourcegen files")
	flag.StringVar(&catalogOut, "catalog-out", "", "write catalog entry YAML to this path")
	flag.BoolVar(&dryRun, "dry-run", true, "dry-run mode (default true); set -dry-run=false to write files")
	flag.Parse()

	if strings.TrimSpace(specPath) == "" {
		fail(fmt.Errorf("-spec is required"))
	}

	// Step 1: Load and parse OpenAPI spec.
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		fail(fmt.Errorf("load OpenAPI spec: %w", err))
	}
	fmt.Fprintf(os.Stderr, "onboard: loaded OpenAPI spec from %s\n", specPath)

	// Step 2: Generate connector definition from the spec.
	definition, report, err := openapigen.Generate(doc, openapigen.Request{
		SourceID:    sourceID,
		TenantID:    tenantID,
		DisplayName: displayName,
		Description: description,
		Categories:  splitList(categories),
		BaseURL:     baseURL,
		AuthModel:   authModel,
		MaxFamilies: maxFamilies,
		AllFamilies: allFamilies,
	})
	if err != nil {
		fail(fmt.Errorf("generate definition: %w", err))
	}
	fmt.Fprintf(os.Stderr, "onboard: generated definition for %s (%d endpoints selected, %d skipped)\n",
		definition.SourceID, len(report.Selected), len(report.Skipped))

	// Step 3: Classify against the grammar.
	grammar := connectordefinitions.DefaultGrammar()
	supportReport, err := connectordefinitions.Classify(definition, grammar)
	if err != nil {
		fail(fmt.Errorf("classify definition: %w", err))
	}
	fmt.Fprintf(os.Stderr, "onboard: classifier verdict: %s\n", supportReport.Verdict)

	// Step 4: Dry-run sourcegen if supported.
	result := OnboardResult{
		SourceID:         definition.SourceID,
		DisplayName:      definition.DisplayName,
		Stage:            definition.Stage,
		Status:           supportReport.Verdict,
		Verdict:          supportReport.Verdict,
		ResourceFamilies: len(definition.ResourceFamilies),
		AuthModel:        definition.Auth.Model,
		BaseURL:          report.BaseURL,
		Selected:         report.Selected,
		Skipped:          report.Skipped,
		MissingFeatures:  supportReport.MissingFeatures,
		Definition:       definition,
		DryRun:           dryRun,
	}
	if supportReport.Verdict == connectordefinitions.SupportVerdictSupported {
		genResult, err := sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{
			Definition: definition,
			OutputDir:  outputDir,
			DryRun:     true,
		})
		if err != nil {
			result.SourcegenError = err.Error()
			fmt.Fprintf(os.Stderr, "onboard: sourcegen dry-run failed: %v\n", err)
		} else {
			result.Generateable = true
			result.SourcegenFiles = genResult.Files
			fmt.Fprintf(os.Stderr, "onboard: sourcegen dry-run passed (%d files)\n", len(genResult.Files))
		}
	}

	// Step 5: Build next steps.
	result.NextSteps = buildNextSteps(result)

	// Step 6: Write catalog entry if requested.
	if strings.TrimSpace(catalogOut) != "" && !dryRun {
		if err := writeCatalogEntry(catalogOut, definition, supportReport.Verdict); err != nil {
			fail(fmt.Errorf("write catalog entry: %w", err))
		}
		result.CatalogPath = catalogOut
		fmt.Fprintf(os.Stderr, "onboard: wrote catalog entry to %s\n", catalogOut)
	}

	// Output the full result.
	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fail(err)
	}
	fmt.Println(string(payload))
}

func buildNextSteps(result OnboardResult) []string {
	var steps []string
	switch result.Verdict {
	case connectordefinitions.SupportVerdictSupported:
		if result.Generateable {
			steps = append(steps,
				fmt.Sprintf("Add the definition to the appropriate category file under internal/connectorcatalog/catalog/"),
				"Run: make catalog-check",
				"Run: make sourcegen-check",
				fmt.Sprintf("Generate the source: cerebro source-runtime sdk new %s catalog=true", result.SourceID),
				fmt.Sprintf("Wire the source: cerebro source-runtime sdk wire %s", result.SourceID),
				"Run: make verify",
			)
		} else {
			steps = append(steps,
				"Add the definition to a catalog YAML file under internal/connectorcatalog/catalog/",
				"The catalogruntime can execute this definition directly without sourcegen.",
				fmt.Sprintf("Sourcegen dry-run failed: %s", result.SourcegenError),
				"Run: make catalog-check",
			)
		}
	case connectordefinitions.SupportVerdictExtensionRequired:
		steps = append(steps,
			"This definition needs auth model or feature extensions before it can run.",
			fmt.Sprintf("Missing features: %s", strings.Join(result.MissingFeatures, ", ")),
			"Add the missing features to the CDK grammar, then re-run onboarding.",
		)
	case connectordefinitions.SupportVerdictBespokeRequired:
		steps = append(steps,
			"This definition requires a bespoke (hand-written) source implementation.",
			fmt.Sprintf("Missing features: %s", strings.Join(result.MissingFeatures, ", ")),
			"Use the definition as a starting point and implement a custom source under sources/.",
		)
	}
	return steps
}

func writeCatalogEntry(path string, definition connectordefinitions.Definition, verdict string) error {
	type catalogEntry struct {
		ClassifierOutput string                          `json:"classifier_output" yaml:"classifier_output"`
		Definition       connectordefinitions.Definition `json:"definition" yaml:"definition"`
	}
	entry := catalogEntry{
		ClassifierOutput: verdict,
		Definition:       definition,
	}
	payload, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return os.WriteFile(path, payload, 0o644)
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

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
