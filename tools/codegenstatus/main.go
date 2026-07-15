// Command codegenstatus reports every registered generator, selects generators
// affected by a diff, and can execute each unique registered staleness check.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/codegencatalog"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/sourcegen/projectionspec"
)

type Status struct {
	Catalog             *CatalogStatus          `json:"catalog"`
	ProjectionTemplates *TemplateStatus         `json:"projection_templates"`
	Generators          []codegencatalog.Family `json:"generators"`
	ChangedFiles        []string                `json:"changed_files,omitempty"`
	Checks              []CheckResult           `json:"checks,omitempty"`
}

type CatalogStatus struct {
	Total               int            `json:"total"`
	CatalogReady        int            `json:"catalog_ready"`
	Generateable        int            `json:"generateable"`
	NeedsAuthExtension  int            `json:"needs_auth_extension"`
	NeedsBespokeRuntime int            `json:"needs_bespoke_runtime"`
	ByAuthModel         map[string]int `json:"by_auth_model,omitempty"`
	ByClassifierOutput  map[string]int `json:"by_classifier_output,omitempty"`
	Issues              int            `json:"issues"`
}

type TemplateStatus struct {
	Count     int      `json:"count"`
	Templates []string `json:"templates"`
}

type CheckResult struct {
	Key     string   `json:"key"`
	Command []string `json:"command"`
	Passed  bool     `json:"passed"`
	Error   string   `json:"error,omitempty"`
}

func main() {
	var catalogPath string
	var changedBase string
	var runChecks bool
	flag.StringVar(&catalogPath, "catalog", "devex/codegen_catalog.json", "codegen registry path")
	flag.StringVar(&changedBase, "changed-base", "", "select generators affected since this Git revision")
	flag.BoolVar(&runChecks, "check", false, "run each unique registered check")
	flag.Parse()

	registry, err := codegencatalog.Load(catalogPath)
	if err != nil {
		fail(err)
	}
	status := Status{Generators: registry.Families}
	if changedBase != "" {
		status.ChangedFiles, err = changedFiles(changedBase)
		if err != nil {
			fail(err)
		}
		if registryChanged(status.ChangedFiles, catalogPath) {
			status.Generators = registry.Families
		} else {
			status.Generators = registry.Select(status.ChangedFiles)
		}
	}
	loadCatalogStatus(&status)
	loadProjectionTemplates(&status)
	if runChecks {
		status.Checks = executeChecks(status.Generators)
	}
	payload, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		fail(err)
	}
	fmt.Println(string(payload))
	for _, result := range status.Checks {
		if !result.Passed {
			os.Exit(1)
		}
	}
}

func registryChanged(files []string, catalogPath string) bool {
	catalogPath = strings.TrimPrefix(strings.TrimSpace(catalogPath), "./")
	for _, file := range files {
		switch {
		case file == catalogPath,
			strings.HasPrefix(file, "internal/codegencatalog/"),
			strings.HasPrefix(file, "tools/codegencatalog/"),
			strings.HasPrefix(file, "tools/codegenstatus/"):
			return true
		}
	}
	return false
}

func loadCatalogStatus(status *Status) {
	analysis, err := connectorcatalog.Builtin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "codegenstatus: catalog analysis: %v\n", err)
		status.Catalog = &CatalogStatus{Issues: -1}
		return
	}
	status.Catalog = &CatalogStatus{
		Total:               analysis.Summary.Total,
		CatalogReady:        analysis.Summary.CatalogReady,
		Generateable:        analysis.Summary.Generateable,
		NeedsAuthExtension:  analysis.Summary.NeedsAuthExtension,
		NeedsBespokeRuntime: analysis.Summary.NeedsBespokeRuntime,
		ByAuthModel:         analysis.Summary.ByAuthModel,
		ByClassifierOutput:  analysis.Summary.ByClassifierOutput,
		Issues:              len(analysis.Issues),
	}
}

func loadProjectionTemplates(status *Status) {
	registry, err := projectionspec.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "codegenstatus: projection templates: %v\n", err)
		return
	}
	status.ProjectionTemplates = &TemplateStatus{Count: len(registry.IDs()), Templates: registry.IDs()}
}

func changedFiles(base string) ([]string, error) {
	filesByPath := map[string]struct{}{}
	probes := [][]string{
		{"diff", "--name-only", "--diff-filter=ACMR", base + "...HEAD"},
		{"diff", "--name-only", "--diff-filter=ACMR"},
		{"diff", "--cached", "--name-only", "--diff-filter=ACMR"},
		{"ls-files", "--others", "--exclude-standard"},
	}
	for index, arguments := range probes {
		command := exec.Command("git", arguments...) // #nosec G204 -- fixed command with operator-provided revision.
		payload, err := command.Output()
		if err != nil && index == 0 {
			command = exec.Command("git", "diff", "--name-only", "--diff-filter=ACMR", base, "HEAD") // #nosec G204 -- fixed command with operator-provided revision.
			payload, err = command.Output()
		}
		if err != nil {
			return nil, fmt.Errorf("list changed files: %w", err)
		}
		for _, file := range strings.Fields(string(payload)) {
			filesByPath[file] = struct{}{}
		}
	}
	files := make([]string, 0, len(filesByPath))
	for file := range filesByPath {
		files = append(files, file)
	}
	sort.Strings(files)
	return files, nil
}

func executeChecks(families []codegencatalog.Family) []CheckResult {
	seen := map[string]struct{}{}
	results := make([]CheckResult, 0)
	for _, family := range families {
		for _, check := range family.Checks {
			key := strings.Join(check.Command, "\x00")
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result := CheckResult{Key: check.Key, Command: check.Command}
			if len(check.Command) == 0 {
				result.Error = "empty command"
				results = append(results, result)
				continue
			}
			fmt.Fprintf(os.Stderr, "codegenstatus: running %s: %s\n", check.Key, strings.Join(check.Command, " "))
			command := exec.Command(check.Command[0], check.Command[1:]...) // #nosec G204 -- command comes from the reviewed repository registry.
			command.Stdout = os.Stderr
			command.Stderr = os.Stderr
			if err := command.Run(); err != nil {
				result.Error = err.Error()
			} else {
				result.Passed = true
			}
			results = append(results, result)
		}
	}
	return results
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "codegenstatus:", err)
	os.Exit(1)
}
