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

	"github.com/writer/cerebro/internal/connectorcatalog"
	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceprojection"
	"gopkg.in/yaml.v3"
)

type issue struct {
	path    string
	message string
}

type complianceControlCatalogIndex struct {
	controls map[string]map[string]struct{}
}

type complianceControlCatalog struct {
	Version    string                              `yaml:"version"`
	Frameworks []complianceControlCatalogFramework `yaml:"frameworks"`
}

type complianceControlCatalogFramework struct {
	Name     string                           `yaml:"name"`
	Families []complianceControlCatalogFamily `yaml:"families"`
}

type complianceControlCatalogFamily struct {
	ID       string                            `yaml:"id"`
	Name     string                            `yaml:"name"`
	Controls []complianceControlCatalogControl `yaml:"controls"`
}

type complianceControlCatalogControl struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
}

func main() {
	root := flag.String("root", ".", "repository root")
	summary := flag.Bool("summary", true, "print connector definition catalog summary")
	flag.Parse()
	issues, err := checkRepository(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalog-check: %v\n", err)
		os.Exit(1)
	}
	if *summary {
		if err := printConnectorDefinitionCatalogSummary(*root); err != nil {
			fmt.Fprintf(os.Stderr, "catalog-check: %v\n", err)
			os.Exit(1)
		}
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
	controlCatalog, controlCatalogIssues, err := loadComplianceControlCatalog(root)
	if err != nil {
		return nil, err
	}
	issues = append(issues, controlCatalogIssues...)
	policyIssues, err := checkPolicies(root, controlCatalog)
	if err != nil {
		return nil, err
	}
	issues = append(issues, policyIssues...)
	sourceIssues, err := checkSourceCatalogs(root)
	if err != nil {
		return nil, err
	}
	issues = append(issues, sourceIssues...)
	connectorIssues, err := checkConnectorDefinitionCatalog(root)
	if err != nil {
		return nil, err
	}
	issues = append(issues, connectorIssues...)
	coverageIssues, err := checkCloudPolicyCoverage(root)
	if err != nil {
		return nil, err
	}
	issues = append(issues, coverageIssues...)
	findingControlCatalog := controlCatalog
	if _, err := os.Stat(filepath.Join(root, "internal", "findings")); errors.Is(err, os.ErrNotExist) {
		findingControlCatalog = nil
	}
	issues = append(issues, checkFindingRuleMetadata(findingControlCatalog)...)
	issues = append(issues, checkCorrelationCatalog()...)
	sort.Slice(issues, func(i int, j int) bool {
		if issues[i].path != issues[j].path {
			return issues[i].path < issues[j].path
		}
		return issues[i].message < issues[j].message
	})
	return issues, nil
}

func loadComplianceControlCatalog(root string) (*complianceControlCatalogIndex, []issue, error) {
	path := filepath.Join(root, "internal", "compliance", "control_families.yaml")
	rel := slashRel(root, path)
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, []issue{{path: rel, message: "compliance control family catalog is required"}}, nil
		}
		return nil, nil, fmt.Errorf("read %s: %w", rel, err)
	}
	var catalog complianceControlCatalog
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return nil, []issue{{path: rel, message: "invalid YAML: " + err.Error()}}, nil
	}
	index := &complianceControlCatalogIndex{controls: map[string]map[string]struct{}{}}
	var issues []issue
	if strings.TrimSpace(catalog.Version) == "" {
		issues = append(issues, issue{path: rel, message: "version is required"})
	}
	for frameworkIdx, framework := range catalog.Frameworks {
		frameworkName := strings.TrimSpace(framework.Name)
		if frameworkName == "" {
			issues = append(issues, issue{path: rel, message: fmt.Sprintf("frameworks[%d].name is required", frameworkIdx)})
			continue
		}
		if _, exists := index.controls[frameworkName]; exists {
			issues = append(issues, issue{path: rel, message: fmt.Sprintf("framework %q is duplicated", frameworkName)})
			continue
		}
		index.controls[frameworkName] = map[string]struct{}{}
		if len(framework.Families) == 0 {
			issues = append(issues, issue{path: rel, message: fmt.Sprintf("framework %q requires at least one family", frameworkName)})
		}
		for familyIdx, family := range framework.Families {
			if strings.TrimSpace(family.ID) == "" {
				issues = append(issues, issue{path: rel, message: fmt.Sprintf("framework %q families[%d].id is required", frameworkName, familyIdx)})
			}
			if strings.TrimSpace(family.Name) == "" {
				issues = append(issues, issue{path: rel, message: fmt.Sprintf("framework %q families[%d].name is required", frameworkName, familyIdx)})
			}
			if len(family.Controls) == 0 {
				issues = append(issues, issue{path: rel, message: fmt.Sprintf("framework %q family %q requires at least one control", frameworkName, strings.TrimSpace(family.ID))})
			}
			for controlIdx, control := range family.Controls {
				controlID := strings.TrimSpace(control.ID)
				if controlID == "" {
					issues = append(issues, issue{path: rel, message: fmt.Sprintf("framework %q family %q controls[%d].id is required", frameworkName, strings.TrimSpace(family.ID), controlIdx)})
					continue
				}
				if _, exists := index.controls[frameworkName][controlID]; exists {
					issues = append(issues, issue{path: rel, message: fmt.Sprintf("framework %q control %q is duplicated", frameworkName, controlID)})
				}
				index.controls[frameworkName][controlID] = struct{}{}
			}
		}
	}
	return index, issues, nil
}

func (catalog *complianceControlCatalogIndex) hasControl(frameworkName, controlID string) bool {
	if catalog == nil {
		return true
	}
	controls, ok := catalog.controls[strings.TrimSpace(frameworkName)]
	if !ok {
		return false
	}
	_, ok = controls[strings.TrimSpace(controlID)]
	return ok
}

func checkConnectorDefinitionCatalog(root string) ([]issue, error) {
	catalogRoot, analysis, err := analyzeConnectorDefinitionCatalog(root)
	if err != nil {
		return nil, err
	}
	issues := make([]issue, 0, len(analysis.Issues))
	for _, catalogIssue := range analysis.Issues {
		issues = append(issues, issue{
			path:    slashRel(root, filepath.Join(catalogRoot, filepath.FromSlash(catalogIssue.Path))),
			message: catalogIssue.Message,
		})
	}
	return issues, nil
}

func printConnectorDefinitionCatalogSummary(root string) error {
	_, analysis, err := analyzeConnectorDefinitionCatalog(root)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "connector-definition-catalog: total=%d generateable=%d needs_auth_extension=%d needs_bespoke_runtime=%d catalog_ready=%d\n",
		analysis.Summary.Total,
		analysis.Summary.Generateable,
		analysis.Summary.NeedsAuthExtension,
		analysis.Summary.NeedsBespokeRuntime,
		analysis.Summary.CatalogReady,
	)
	return nil
}

func analyzeConnectorDefinitionCatalog(root string) (string, connectorcatalog.Analysis, error) {
	catalogRoot := filepath.Join(root, "internal", "connectorcatalog", "catalog")
	analysis, err := connectorcatalog.AnalyzeDir(catalogRoot, connectorcatalog.Options{DryRunSourcegen: true})
	return catalogRoot, analysis, err
}

func checkFindingRuleMetadata(controlCatalog *complianceControlCatalogIndex) []issue {
	var issues []issue
	for _, metadata := range findinganalysis.BuiltinRuleMetadata() {
		for _, ref := range metadata.ControlRefs {
			if !controlCatalog.hasControl(ref.FrameworkName, ref.ControlID) {
				issues = append(issues, issue{
					path:    "internal/findings",
					message: fmt.Sprintf("rule %q control ref %s %s is not declared in internal/compliance/control_families.yaml", metadata.ID, ref.FrameworkName, ref.ControlID),
				})
			}
		}
	}
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

func checkPolicies(root string, controlCatalog *complianceControlCatalogIndex) ([]issue, error) {
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
		issues = append(issues, validatePolicy(rel, raw, controlCatalog)...)
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

func validatePolicy(path string, raw map[string]json.RawMessage, controlCatalog *complianceControlCatalogIndex) []issue {
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
	issues = append(issues, validateFrameworks(path, raw, controlCatalog)...)
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

func validateFrameworks(path string, raw map[string]json.RawMessage, controlCatalog *complianceControlCatalogIndex) []issue {
	value, ok := raw["frameworks"]
	if !ok {
		return []issue{{path: path, message: "frameworks is required"}}
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
		frameworkName := strings.TrimSpace(framework.Name)
		if frameworkName == "" {
			issues = append(issues, issue{path: path, message: fmt.Sprintf("frameworks[%d].name is required", idx)})
		}
		if len(framework.Controls) == 0 {
			issues = append(issues, issue{path: path, message: fmt.Sprintf("frameworks[%d].controls is required", idx)})
		}
		for controlIdx, control := range framework.Controls {
			controlID := strings.TrimSpace(control)
			if controlID == "" {
				issues = append(issues, issue{path: path, message: fmt.Sprintf("frameworks[%d].controls[%d] is required", idx, controlIdx)})
				continue
			}
			if frameworkName != "" && !controlCatalog.hasControl(frameworkName, controlID) {
				issues = append(issues, issue{path: path, message: fmt.Sprintf("frameworks[%d].controls[%d] %s %s is not declared in internal/compliance/control_families.yaml", idx, controlIdx, frameworkName, controlID)})
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
		if filepath.Base(filepath.Dir(path)) == "catalogruntime" {
			return nil
		}
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
		var runtimeCatalog struct {
			RuntimeFamilies []string `yaml:"runtime_families"`
		}
		if err := yaml.Unmarshal(content, &runtimeCatalog); err != nil {
			issues = append(issues, issue{path: rel, message: "unmarshal runtime families: " + err.Error()})
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
		issues = append(issues, validateRuntimeFamilyFixtures(root, filepath.Dir(path), runtimeCatalog.RuntimeFamilies)...)
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

func validateRuntimeFamilyFixtures(root string, sourceDir string, runtimeFamilies []string) []issue {
	if len(runtimeFamilies) == 0 {
		return nil
	}
	var issues []issue
	for _, family := range runtimeFamilies {
		family = strings.TrimSpace(family)
		if family == "" {
			continue
		}
		for _, prefix := range []string{"discover", "read"} {
			name := fmt.Sprintf("%s_%s.json", prefix, family)
			path := filepath.Join(sourceDir, "testdata", name)
			info, err := os.Lstat(path)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					issues = append(issues, issue{path: slashRel(root, filepath.Join(sourceDir, "catalog.yaml")), message: fmt.Sprintf("runtime family fixture %q is required", name)})
					continue
				}
				issues = append(issues, issue{path: slashRel(root, path), message: "stat runtime family fixture: " + err.Error()})
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				issues = append(issues, issue{path: slashRel(root, path), message: "symlinked runtime family fixture is not allowed"})
				continue
			}
			if info.IsDir() {
				issues = append(issues, issue{path: slashRel(root, path), message: "runtime family fixture must be a file"})
			}
		}
	}
	return issues
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
