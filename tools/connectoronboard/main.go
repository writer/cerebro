// Command connectoronboard orchestrates the full connector onboarding pipeline:
// OpenAPI spec → connector definition → catalog classification → source generation.
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
	"path/filepath"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/connectordefinitions/openapigen"
	"github.com/writer/cerebro/internal/providercontractlock"
	"github.com/writer/cerebro/internal/sourcegen"
)

// OnboardResult reports the full pipeline outcome.
type OnboardResult struct {
	SourceID           string                          `json:"source_id"`
	DisplayName        string                          `json:"display_name"`
	Stage              string                          `json:"stage"`
	Status             string                          `json:"status"`
	Verdict            string                          `json:"verdict"`
	Generateable       bool                            `json:"generateable"`
	ResourceFamilies   int                             `json:"resource_families"`
	AuthModel          string                          `json:"auth_model"`
	BaseURL            string                          `json:"base_url"`
	Selected           []openapigen.Endpoint           `json:"selected_endpoints,omitempty"`
	Skipped            []openapigen.Endpoint           `json:"skipped_endpoints,omitempty"`
	MissingFeatures    []string                        `json:"missing_features,omitempty"`
	SourcegenError     string                          `json:"sourcegen_error,omitempty"`
	SourcegenFiles     []string                        `json:"sourcegen_files,omitempty"`
	GenerationManifest string                          `json:"generation_manifest,omitempty"`
	ProofBundle        string                          `json:"proof_bundle,omitempty"`
	ChangePlan         *sourcegen.ChangePlan           `json:"change_plan,omitempty"`
	ProviderContract   ProviderContractResult          `json:"provider_contract"`
	WiredFiles         []string                        `json:"wired_files,omitempty"`
	Definition         connectordefinitions.Definition `json:"definition"`
	NextSteps          []string                        `json:"next_steps"`
	CatalogPath        string                          `json:"catalog_path,omitempty"`
	DryRun             bool                            `json:"dry_run"`
}

// ProviderContractResult reports the lock and drift decision used by this run.
type ProviderContractResult struct {
	LockPath string                     `json:"lock_path"`
	Lock     providercontractlock.Lock  `json:"lock"`
	Drift    providercontractlock.Drift `json:"drift"`
	Accepted bool                       `json:"accepted"`
	Written  bool                       `json:"written"`
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
	var providerAPIReferences string
	var maxFamilies int
	var allFamilies bool
	var outputDir string
	var catalogOut string
	var contractLock string
	var contractLockOut string
	var dryRun bool
	var wire bool
	var acceptContractChange bool
	flag.StringVar(&specPath, "spec", "", "OpenAPI document path (required)")
	flag.StringVar(&sourceID, "source-id", "", "connector source id; inferred from spec title when empty")
	flag.StringVar(&tenantID, "tenant-id", "builtin_catalog", "tenant id for the catalog entry")
	flag.StringVar(&displayName, "display-name", "", "connector display name; inferred from spec title when empty")
	flag.StringVar(&description, "description", "", "connector description; inferred from spec description when empty")
	flag.StringVar(&categories, "category", "security", "comma-separated connector categories")
	flag.StringVar(&baseURL, "base-url", "", "provider API base URL; inferred from OpenAPI servers when empty")
	flag.StringVar(&authModel, "auth-model", "", "auth model override")
	flag.StringVar(&providerAPIReferences, "provider-api-references", "", "comma-separated provider-owned API spec or reference URLs")
	flag.IntVar(&maxFamilies, "max-families", 4, "maximum selected resource families")
	flag.BoolVar(&allFamilies, "all-families", false, "select every endpoint")
	flag.StringVar(&outputDir, "output-dir", ".", "output directory for sourcegen files")
	flag.StringVar(&catalogOut, "catalog-out", "", "write catalog entry YAML to this path")
	flag.StringVar(&contractLock, "contract-lock", "", "reviewed provider contract lock to compare")
	flag.StringVar(&contractLockOut, "contract-lock-out", "", "provider contract lock output path; defaults to the generated source directory")
	flag.BoolVar(&dryRun, "dry-run", true, "dry-run mode (default true); set -dry-run=false to write files")
	flag.BoolVar(&wire, "wire", true, "wire generated source, projection, and documentation entries when writing")
	flag.BoolVar(&acceptContractChange, "accept-contract-change", false, "record reviewed selected-operation or auth changes in the provider contract lock")
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
		fail(fmt.Errorf("generate definition: %w", err))
	}
	fmt.Fprintf(os.Stderr, "onboard: generated definition for %s (%d endpoints selected, %d skipped)\n",
		definition.SourceID, len(report.Selected), len(report.Skipped))
	currentLock, err := providercontractlock.Build(doc, definition.SourceID, contractSelections(report.Selected))
	if err != nil {
		fail(fmt.Errorf("build provider contract lock: %w", err))
	}
	lockOutputPath := providerContractOutputPath(outputDir, definition.SourceID, contractLock, contractLockOut)
	comparePath := strings.TrimSpace(contractLock)
	if comparePath == "" {
		comparePath = lockOutputPath
	}
	previousLock, err := readProviderContractLock(comparePath)
	if err != nil {
		fail(err)
	}
	contractDrift := providercontractlock.Compare(previousLock, currentLock)
	contractBlocked := contractChangeNeedsReview(contractDrift) && !acceptContractChange
	contractDigest, err := providercontractlock.Digest(currentLock)
	if err != nil {
		fail(fmt.Errorf("hash provider contract lock: %w", err))
	}
	contractReviewAccepted := acceptContractChange && contractDrift.Status != providercontractlock.DriftUnchanged
	contractReviewed := previousLock != nil && (contractDrift.Status == providercontractlock.DriftUnchanged || contractDrift.Status == providercontractlock.DriftAdditive)
	if contractReviewAccepted {
		contractReviewed = true
	}
	fmt.Fprintf(os.Stderr, "onboard: provider contract: %s\n", contractDrift.Status)

	// Step 3: Classify against the grammar.
	grammar := connectordefinitions.DefaultGrammar()
	supportReport, err := connectordefinitions.Classify(definition, grammar)
	if err != nil {
		fail(fmt.Errorf("classify definition: %w", err))
	}
	fmt.Fprintf(os.Stderr, "onboard: classifier verdict: %s\n", supportReport.Verdict)

	// Step 4: Plan or write source files when the definition is supported.
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
		ProviderContract: ProviderContractResult{
			LockPath: lockOutputPath,
			Lock:     currentLock,
			Drift:    contractDrift,
			Accepted: contractReviewAccepted,
		},
	}
	if contractBlocked {
		result.SourcegenError = "Provider contract changes require review before source generation."
	}
	if supportReport.Verdict == connectordefinitions.SupportVerdictSupported && !contractBlocked {
		genResult, err := sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{
			Definition: definition,
			ProviderContract: &sourcegen.ProviderContractEvidence{
				LockDigest:  contractDigest,
				DriftStatus: contractDrift.Status,
				Reviewed:    contractReviewed,
			},
			OutputDir: outputDir,
			DryRun:    dryRun,
		})
		if err != nil {
			result.SourcegenError = err.Error()
			fmt.Fprintf(os.Stderr, "onboard: source generation failed: %v\n", err)
		} else {
			result.Generateable = true
			result.SourcegenFiles = genResult.Files
			result.GenerationManifest = genResult.GenerationManifest
			result.ProofBundle = genResult.ProofBundle
			result.ChangePlan = &genResult.ChangePlan
			if dryRun {
				fmt.Fprintf(os.Stderr, "onboard: sourcegen dry-run passed (%d files)\n", len(genResult.Files))
			} else {
				fmt.Fprintf(os.Stderr, "onboard: sourcegen wrote %d files\n", len(genResult.Files))
				if wire {
					wireResult, err := sourcegen.Wire(sourcegen.WireRequest{SourceID: definition.SourceID, OutputDir: outputDir})
					if err != nil {
						fail(fmt.Errorf("wire generated source: %w", err))
					}
					result.WiredFiles = wireResult.FilesModified
					fmt.Fprintf(os.Stderr, "onboard: wired %d registry and documentation files\n", len(wireResult.FilesModified))
				}
			}
		}
	}
	if result.Generateable && !dryRun {
		if err := providercontractlock.Write(lockOutputPath, currentLock); err != nil {
			fail(fmt.Errorf("write provider contract lock: %w", err))
		}
		result.ProviderContract.Written = true
		fmt.Fprintf(os.Stderr, "onboard: wrote provider contract lock to %s\n", lockOutputPath)
	}

	// Step 5: Build next steps.
	result.NextSteps = buildNextSteps(result)

	// Step 6: Write catalog entry if requested.
	if strings.TrimSpace(catalogOut) != "" && !dryRun && !contractBlocked {
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
	if contractChangeNeedsReview(result.ProviderContract.Drift) && !result.ProviderContract.Accepted {
		return []string{
			fmt.Sprintf("Review provider contract changes: %s", strings.Join(result.ProviderContract.Drift.Changes, ", ")),
			"Re-run with -accept-contract-change after reviewing the selected operations and auth contract.",
		}
	}
	if result.ProviderContract.Drift.Status == providercontractlock.DriftNew && !result.ProviderContract.Accepted {
		steps = append(steps,
			fmt.Sprintf("Review the provider contract lock at %s.", result.ProviderContract.LockPath),
			"Re-run with -accept-contract-change to record the initial contract review in the proof bundle.",
		)
	}
	switch result.Verdict {
	case connectordefinitions.SupportVerdictSupported:
		if result.Generateable {
			if result.DryRun {
				steps = append(steps,
					"Set -dry-run=false after reviewing the selected endpoints and generated file plan.",
					"Set -catalog-out to the reviewed connector catalog path.",
				)
			} else {
				steps = append(steps,
					fmt.Sprintf("Review the generated contract and fixtures under sources/%s.", result.SourceID),
					fmt.Sprintf("Run: cerebro source-runtime sdk validate %s", result.SourceID),
				)
			}
			steps = append(steps, "Run: make catalog-check sourcegen-check", "Run: make verify")
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

func contractSelections(endpoints []openapigen.Endpoint) []providercontractlock.Selection {
	selections := make([]providercontractlock.Selection, 0, len(endpoints))
	for _, endpoint := range endpoints {
		selections = append(selections, providercontractlock.Selection{
			FamilyID:    endpoint.FamilyID,
			Method:      endpoint.Method,
			Path:        endpoint.Path,
			OperationID: endpoint.OperationID,
		})
	}
	return selections
}

func providerContractOutputPath(outputDir string, sourceID string, inputPath string, outputPath string) string {
	if path := strings.TrimSpace(outputPath); path != "" {
		return path
	}
	if path := strings.TrimSpace(inputPath); path != "" {
		return path
	}
	return filepath.Join(outputDir, "sources", sourceID, ".provider-contract-lock.json")
}

func readProviderContractLock(path string) (*providercontractlock.Lock, error) {
	lock, err := providercontractlock.Read(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read provider contract lock: %w", err)
	}
	return &lock, nil
}

func contractChangeNeedsReview(drift providercontractlock.Drift) bool {
	return drift.Status == providercontractlock.DriftBehavioralReview || drift.Status == providercontractlock.DriftBreaking
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
	return os.WriteFile(path, payload, 0o600)
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
