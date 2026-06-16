package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceprojection"
)

type issue struct {
	path    string
	message string
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	issues, err := checkRepository(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalog-check: %v\n", err)
		os.Exit(1)
	}
	if len(issues) != 0 {
		for _, issue := range issues {
			fmt.Fprintf(os.Stderr, "%s: %s\n", issue.path, issue.message)
		}
		os.Exit(1)
	}
}

func checkRepository(root string) ([]issue, error) {
	root = filepath.Clean(root)
	var issues []issue
	policyIssues, err := checkPolicies(root)
	if err != nil {
		return nil, err
	}
	issues = append(issues, policyIssues...)
	sourceIssues, err := checkSourceCatalogs(root)
	if err != nil {
		return nil, err
	}
	issues = append(issues, sourceIssues...)
	coverageIssues, err := checkCloudPolicyCoverage(root)
	if err != nil {
		return nil, err
	}
	issues = append(issues, coverageIssues...)
	issues = append(issues, checkFindingRuleMetadata()...)
	issues = append(issues, checkCorrelationCatalog()...)
	sort.Slice(issues, func(i int, j int) bool {
		if issues[i].path != issues[j].path {
			return issues[i].path < issues[j].path
		}
		return issues[i].message < issues[j].message
	})
	return issues, nil
}

func checkFindingRuleMetadata() []issue {
	var issues []issue
	for _, err := range findinganalysis.ValidateRuleMetadataCompleteness(findinganalysis.BuiltinRuleMetadata()) {
		issues = append(issues, issue{path: "internal/findings", message: err.Error()})
	}
	return issues
}

func checkCorrelationCatalog() []issue {
	knownRuleIDs := map[string]struct{}{}
	for _, metadata := range findinganalysis.BuiltinRuleMetadata() {
		knownRuleIDs[metadata.ID] = struct{}{}
	}
	if err := findinganalysis.ValidateFindingCorrelationPatterns(findinganalysis.BuiltinFindingCorrelationPatterns(), knownRuleIDs); err != nil {
		return []issue{{path: "internal/findings/correlation_patterns/builtin.json", message: err.Error()}}
	}
	return nil
}

func checkPolicies(root string) ([]issue, error) {
	policiesRoot := filepath.Join(root, "policies")
	ids := map[string]string{}
	var issues []issue
	err := filepath.WalkDir(policiesRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		rel := slashRel(root, path)
		if entry.Type()&os.ModeSymlink != 0 {
			issues = append(issues, issue{path: rel, message: "symlinked policy files are not allowed"})
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(content, &raw); err != nil {
			issues = append(issues, issue{path: rel, message: "invalid JSON: " + err.Error()})
			return nil
		}
		if rel == "policies/cerebro/control-mapping.json" {
			issues = append(issues, validateControlMapping(rel, raw)...)
			return nil
		}
		policyID := stringField(raw, "id")
		if existing := ids[policyID]; policyID != "" && existing != "" {
			issues = append(issues, issue{path: rel, message: fmt.Sprintf("duplicate policy id %q also used by %s", policyID, existing)})
		}
		if policyID != "" {
			ids[policyID] = rel
		}
		issues = append(issues, validatePolicy(rel, raw)...)
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("policies directory not found")
		}
		return nil, err
	}
	return issues, nil
}

func validateControlMapping(path string, raw map[string]json.RawMessage) []issue {
	var issues []issue
	if stringField(raw, "version") == "" {
		issues = append(issues, issue{path: path, message: "control mapping version is required"})
	}
	if _, ok := raw["controls"]; !ok {
		issues = append(issues, issue{path: path, message: "control mapping controls object is required"})
	}
	return issues
}

func validatePolicy(path string, raw map[string]json.RawMessage) []issue {
	var issues []issue
	for _, field := range []string{"id", "name", "description", "severity"} {
		if stringField(raw, field) == "" {
			issues = append(issues, issue{path: path, message: field + " is required"})
		}
	}
	if severity := strings.ToUpper(stringField(raw, "severity")); severity != "" && !stringSetContains([]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, severity) {
		issues = append(issues, issue{path: path, message: "severity must be one of info, low, medium, high, critical"})
	}
	hasConditions := hasNonEmptyArray(raw, "conditions")
	hasQuery := stringField(raw, "query") != ""
	if !hasConditions && !hasQuery {
		issues = append(issues, issue{path: path, message: "conditions or query is required"})
	}
	if hasConditions {
		if stringField(raw, "effect") == "" {
			issues = append(issues, issue{path: path, message: "effect is required for CEL policies"})
		}
		if format := stringField(raw, "condition_format"); format != "" && !strings.EqualFold(format, "cel") {
			issues = append(issues, issue{path: path, message: "condition_format must be cel when present"})
		}
	}
	issues = append(issues, validateStringArrayField(path, raw, "tags")...)
	issues = append(issues, validateFrameworks(path, raw)...)
	return issues
}

func validateStringArrayField(path string, raw map[string]json.RawMessage, field string) []issue {
	value, ok := raw[field]
	if !ok {
		return nil
	}
	var values []string
	if err := json.Unmarshal(value, &values); err != nil {
		return []issue{{path: path, message: field + " must be a string array"}}
	}
	for idx, value := range values {
		if strings.TrimSpace(value) == "" {
			return []issue{{path: path, message: fmt.Sprintf("%s[%d] must be non-empty", field, idx)}}
		}
	}
	return nil
}

func validateFrameworks(path string, raw map[string]json.RawMessage) []issue {
	value, ok := raw["frameworks"]
	if !ok {
		return nil
	}
	var frameworks []struct {
		Name     string   `json:"name"`
		Controls []string `json:"controls"`
	}
	if err := json.Unmarshal(value, &frameworks); err != nil {
		return []issue{{path: path, message: "frameworks must be an array of framework objects"}}
	}
	var issues []issue
	for idx, framework := range frameworks {
		if strings.TrimSpace(framework.Name) == "" {
			issues = append(issues, issue{path: path, message: fmt.Sprintf("frameworks[%d].name is required", idx)})
		}
		if len(framework.Controls) == 0 {
			issues = append(issues, issue{path: path, message: fmt.Sprintf("frameworks[%d].controls is required", idx)})
		}
		for controlIdx, control := range framework.Controls {
			if strings.TrimSpace(control) == "" {
				issues = append(issues, issue{path: path, message: fmt.Sprintf("frameworks[%d].controls[%d] is required", idx, controlIdx)})
			}
		}
	}
	return issues
}

func checkSourceCatalogs(root string) ([]issue, error) {
	sourcesRoot := filepath.Join(root, "sources")
	projectedKinds := map[string]struct{}{}
	for _, kind := range sourceprojection.BuiltinRegistry().Kinds() {
		projectedKinds[kind] = struct{}{}
	}
	var issues []issue
	err := filepath.WalkDir(sourcesRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Base(path) != "catalog.yaml" {
			return nil
		}
		rel := slashRel(root, path)
		if entry.Type()&os.ModeSymlink != 0 {
			issues = append(issues, issue{path: rel, message: "symlinked source catalogs are not allowed"})
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		catalog, err := sourcecdk.LoadSourceCatalog(content)
		if err != nil {
			issues = append(issues, issue{path: rel, message: err.Error()})
			return nil
		}
		spec := catalog.Spec
		if catalog.CoverageContract == nil {
			issues = append(issues, issue{path: rel, message: "coverage_contract is required for built-in sources"})
		}
		if spec.GetId() != "sdk" && len(spec.GetEmittedKinds()) == 0 {
			issues = append(issues, issue{path: rel, message: "emitted_kinds is required for built-in pull sources"})
		}
		emittedKinds := map[string]struct{}{}
		for _, kind := range spec.GetEmittedKinds() {
			emittedKinds[kind] = struct{}{}
			if _, ok := projectedKinds[kind]; !ok {
				issues = append(issues, issue{path: rel, message: fmt.Sprintf("emitted kind %q has no source projector", kind)})
			}
		}
		for _, contract := range catalog.EventContracts {
			if _, ok := emittedKinds[contract.Kind]; !ok {
				issues = append(issues, issue{path: rel, message: fmt.Sprintf("event contract kind %q is not an emitted kind", contract.Kind)})
			}
		}
		issues = append(issues, validateFixtureContracts(root, filepath.Dir(path), catalog.EventContracts)...)
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("sources directory not found")
		}
		return nil, err
	}
	return issues, nil
}

func hasSourceDeployManifest(sourceDir string) (bool, error) {
	info, err := os.Lstat(filepath.Join(sourceDir, "deploy.yaml"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat deploy.yaml: %w", err)
	}
	return !info.IsDir(), nil
}

func validateFixtureContracts(root string, sourceDir string, contracts []sourcecdk.EventContract) []issue {
	if len(contracts) == 0 {
		return nil
	}
	testdata := filepath.Join(sourceDir, "testdata")
	var issues []issue
	info, statErr := os.Lstat(testdata)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		return []issue{{path: slashRel(root, testdata), message: "stat testdata: " + statErr.Error()}}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return []issue{{path: slashRel(root, testdata), message: "symlinked testdata directory is not allowed"}}
	}
	if !info.IsDir() {
		return nil
	}
	_ = filepath.WalkDir(testdata, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel := slashRel(root, path)
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			issues = append(issues, issue{path: rel, message: "read fixture: " + readErr.Error()})
			return nil
		}
		if !looksLikeEventFixture(content) {
			return nil
		}
		if _, err := sourcecdk.LoadFixtureEventsWithContracts(os.DirFS(root), rel, contracts); err != nil {
			issues = append(issues, issue{path: rel, message: err.Error()})
		}
		return nil
	})
	return issues
}

func looksLikeEventFixture(content []byte) bool {
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(content, &raw); err != nil {
		return false
	}
	for _, item := range raw {
		if _, ok := item["schema_ref"]; ok {
			return true
		}
		if _, ok := item["occurred_at"]; ok {
			return true
		}
		if _, ok := item["attributes"]; ok {
			return true
		}
		_, hasTenant := item["tenant_id"]
		_, hasSource := item["source_id"]
		_, hasKind := item["kind"]
		_, hasPayload := item["payload"]
		if hasTenant && hasSource && (hasKind || hasPayload) {
			return true
		}
	}
	return false
}

func stringField(raw map[string]json.RawMessage, field string) string {
	value, ok := raw[field]
	if !ok {
		return ""
	}
	var text string
	if err := json.Unmarshal(value, &text); err != nil {
		return ""
	}
	return strings.TrimSpace(text)
}

func hasNonEmptyArray(raw map[string]json.RawMessage, field string) bool {
	value, ok := raw[field]
	if !ok {
		return false
	}
	var values []json.RawMessage
	if err := json.Unmarshal(value, &values); err != nil {
		return false
	}
	return len(values) != 0
}

func stringSetContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func slashRel(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
