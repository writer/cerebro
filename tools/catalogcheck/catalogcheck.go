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
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/findingdsl"
	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceprojection"
	"gopkg.in/yaml.v3"
)

type issue struct {
	path    string
	message string
}

type repositoryCheckOptions struct {
	requireSourcegenReady bool
}

func main() {
	root := flag.String("root", ".", "repository root")
	summary := flag.Bool("summary", true, "print connector definition catalog summary")
	requireSourcegenReady := flag.Bool("require-sourcegen-ready", false, "fail when any connector definition is not sourcegen-ready")
	flag.Parse()
	issues, err := checkRepositoryWithOptions(*root, repositoryCheckOptions{requireSourcegenReady: *requireSourcegenReady})
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
	return checkRepositoryWithOptions(root, repositoryCheckOptions{})
}

func checkRepositoryWithOptions(root string, options repositoryCheckOptions) ([]issue, error) {
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
	sourceIssues, err := checkSourceCatalogsWithControlCatalog(root, controlCatalog)
	if err != nil {
		return nil, err
	}
	issues = append(issues, sourceIssues...)
	connectorIssues, err := checkConnectorDefinitionCatalogWithOptions(root, options)
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
	issues = append(issues, checkComplianceEvidencePacketContract(controlCatalog)...)
	issues = dedupeIssues(issues)
	sort.Slice(issues, func(i int, j int) bool {
		if issues[i].path != issues[j].path {
			return issues[i].path < issues[j].path
		}
		return issues[i].message < issues[j].message
	})
	return issues, nil
}

func dedupeIssues(issues []issue) []issue {
	seen := map[issue]struct{}{}
	deduped := make([]issue, 0, len(issues))
	for _, issue := range issues {
		if _, ok := seen[issue]; ok {
			continue
		}
		seen[issue] = struct{}{}
		deduped = append(deduped, issue)
	}
	return deduped
}

func loadComplianceControlCatalog(root string) (*compliance.CatalogIndex, []issue, error) {
	path := filepath.Join(root, filepath.FromSlash(compliance.DefaultControlCatalogPath))
	rel := slashRel(root, path)
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, []issue{{path: rel, message: "compliance control family catalog is required"}}, nil
		}
		return nil, nil, fmt.Errorf("read %s: %w", rel, err)
	}
	catalog, err := compliance.LoadControlCatalog(content)
	if err != nil {
		return nil, []issue{{path: rel, message: "invalid YAML: " + err.Error()}}, nil
	}
	index, validationIssues := compliance.BuildCatalogIndex(catalog)
	issues := make([]issue, 0, len(validationIssues))
	for _, validationIssue := range validationIssues {
		issues = append(issues, issue{path: rel, message: validationIssue.Message})
	}
	return index, issues, nil
}

func checkConnectorDefinitionCatalog(root string) ([]issue, error) {
	return checkConnectorDefinitionCatalogWithOptions(root, repositoryCheckOptions{})
}

func checkConnectorDefinitionCatalogWithOptions(root string, options repositoryCheckOptions) ([]issue, error) {
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
	if options.requireSourcegenReady {
		for _, entry := range analysis.Entries {
			if entry.Generateable {
				continue
			}
			message := fmt.Sprintf("connector definition %q is %s, want %s", entry.Definition.SourceID, entry.Status, connectorcatalog.StatusGenerateable)
			if entry.SourcegenError != "" {
				message += ": " + entry.SourcegenError
			}
			issues = append(issues, issue{
				path:    slashRel(root, filepath.Join(catalogRoot, filepath.FromSlash(entry.Path))),
				message: message,
			})
		}
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

func checkFindingRuleMetadata(controlCatalog *compliance.CatalogIndex) []issue {
	var issues []issue
	for _, metadata := range findinganalysis.BuiltinRuleMetadata() {
		for _, ref := range metadata.ControlRefs {
			if controlCatalog != nil && !controlCatalog.HasControl(ref.FrameworkName, ref.ControlID) {
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

func checkComplianceEvidencePacketContract(controlCatalog *compliance.CatalogIndex) []issue {
	if controlCatalog == nil {
		return nil
	}
	resolution, validationIssues := compliance.ResolveControlSelection(controlCatalog, compliance.ControlSelection{ID: "catalog-check-all"})
	issues := make([]issue, 0, len(validationIssues))
	for _, validationIssue := range validationIssues {
		issues = append(issues, issue{path: compliance.DefaultControlCatalogPath, message: "control selection: " + validationIssue.Message})
	}
	if len(resolution.Controls) == 0 {
		return append(issues, issue{path: compliance.DefaultControlCatalogPath, message: "control evidence packet contract requires at least one resolved control"})
	}
	coverage := compliance.ResolveRuleCoverage(resolution, builtinRuleControlMappings())
	packet := compliance.BuildControlEvidencePacket(compliance.ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          time.Unix(0, 0).UTC(),
	})
	if packet.Version == "" {
		issues = append(issues, issue{path: compliance.DefaultControlCatalogPath, message: "control evidence packet version is required"})
	}
	if packet.Summary.Total != len(resolution.Controls) {
		issues = append(issues, issue{path: compliance.DefaultControlCatalogPath, message: fmt.Sprintf("control evidence packet summary total = %d, want %d", packet.Summary.Total, len(resolution.Controls))})
	}
	if len(packet.Controls) != len(resolution.Controls) {
		issues = append(issues, issue{path: compliance.DefaultControlCatalogPath, message: fmt.Sprintf("control evidence packet controls = %d, want %d", len(packet.Controls), len(resolution.Controls))})
	}
	for idx, control := range packet.Controls {
		if control.Control.FrameworkName == "" || control.Control.ControlID == "" {
			issues = append(issues, issue{path: compliance.DefaultControlCatalogPath, message: fmt.Sprintf("control evidence packet controls[%d] is missing framework or control identity", idx)})
		}
		if len(control.Evidence.Expectations) == 0 {
			issues = append(issues, issue{path: compliance.DefaultControlCatalogPath, message: fmt.Sprintf("control evidence packet control %s %s has no evidence expectation posture", control.Control.FrameworkName, control.Control.ControlID)})
		}
	}
	return issues
}

func builtinRuleControlMappings() []compliance.RuleControlMapping {
	metadata := findinganalysis.BuiltinRuleMetadata()
	mappings := make([]compliance.RuleControlMapping, 0, len(metadata))
	for _, rule := range metadata {
		if len(rule.ControlRefs) == 0 {
			continue
		}
		controlRefs := make([]compliance.ControlRef, 0, len(rule.ControlRefs))
		for _, ref := range rule.ControlRefs {
			controlRefs = append(controlRefs, compliance.ControlRef{
				FrameworkName: ref.FrameworkName,
				ControlID:     ref.ControlID,
			})
		}
		mappings = append(mappings, compliance.RuleControlMapping{
			RuleID:      rule.ID,
			ControlRefs: controlRefs,
		})
	}
	return mappings
}

func checkPolicies(root string, controlCatalog *compliance.CatalogIndex) ([]issue, error) {
	policiesRoot := filepath.Join(root, "policies")
	var issues []issue
	err := filepath.WalkDir(policiesRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel := slashRel(root, path)
		if rel != findingdsl.ControlMappingRelPath && filepath.Ext(path) != ".json" {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			issues = append(issues, issue{path: rel, message: "symlinked policy files are not allowed"})
			return nil
		}
		if rel != findingdsl.ControlMappingRelPath {
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
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("policies directory not found")
		}
		return nil, err
	}
	rules, dslIssues, err := findingdsl.LoadPolicyRules(root)
	if err != nil {
		return nil, err
	}
	for _, dslIssue := range dslIssues {
		issues = append(issues, issue{path: dslIssue.Path, message: dslIssue.Message})
	}
	for _, rule := range rules {
		issues = append(issues, validatePolicyRuleControls(rule, controlCatalog)...)
	}
	issues = append(issues, checkPolicyAssetContracts(rules)...)
	return issues, nil
}

func validatePolicyRuleControls(rule findingdsl.PolicyFindingRule, controlCatalog *compliance.CatalogIndex) []issue {
	var issues []issue
	for frameworkIdx, framework := range rule.Spec.Frameworks {
		frameworkName := strings.TrimSpace(framework.Name)
		for controlIdx, control := range framework.Controls {
			controlID := strings.TrimSpace(control)
			if controlCatalog != nil && frameworkName != "" && controlID != "" && !controlCatalog.HasControl(frameworkName, controlID) {
				issues = append(issues, issue{
					path:    rule.RelPath,
					message: fmt.Sprintf("spec.frameworks[%d].controls[%d] %s %s is not declared in internal/compliance/control_families.yaml", frameworkIdx, controlIdx, frameworkName, controlID),
				})
			}
		}
	}
	return issues
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

func checkSourceCatalogs(root string) ([]issue, error) {
	controlCatalog, controlCatalogIssues, err := loadOptionalComplianceControlCatalog(root)
	if err != nil {
		return nil, err
	}
	sourceIssues, err := checkSourceCatalogsWithControlCatalog(root, controlCatalog)
	if err != nil {
		return nil, err
	}
	return append(controlCatalogIssues, sourceIssues...), nil
}

func loadOptionalComplianceControlCatalog(root string) (*compliance.CatalogIndex, []issue, error) {
	path := filepath.Join(root, filepath.FromSlash(compliance.DefaultControlCatalogPath))
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("stat %s: %w", slashRel(root, path), err)
	}
	return loadComplianceControlCatalog(root)
}

func checkSourceCatalogsWithControlCatalog(root string, controlCatalog *compliance.CatalogIndex) ([]issue, error) {
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
		var runtimeCatalog struct {
			RuntimeFamilies  []string                    `yaml:"runtime_families"`
			CoverageContract *sourcecdk.CoverageContract `yaml:"coverage_contract"`
		}
		if err := yaml.Unmarshal(content, &runtimeCatalog); err != nil {
			issues = append(issues, issue{path: rel, message: "unmarshal source catalog fields: " + err.Error()})
			return nil
		}
		catalog, err := sourcecdk.LoadSourceCatalog(content)
		if err != nil {
			issues = append(issues, issue{path: rel, message: err.Error()})
			return nil
		}
		spec := catalog.Spec
		if catalog.CoverageContract == nil {
			issues = append(issues, issue{path: rel, message: "coverage_contract is required for built-in sources"})
		} else {
			issues = append(issues, validateSourceCoverageDeepContract(rel, runtimeCatalog.CoverageContract, controlCatalog)...)
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

func validateSourceCoverageDeepContract(path string, contract *sourcecdk.CoverageContract, controlCatalog *compliance.CatalogIndex) []issue {
	if contract == nil {
		return nil
	}
	var issues []issue
	for _, dimension := range contract.Dimensions {
		if !dimension.HighValue {
			continue
		}
		prefix := fmt.Sprintf("coverage_contract dimension %q", dimension.ID)
		switch strings.ToLower(strings.TrimSpace(dimension.Support)) {
		case sourcecdk.CoverageSupportSupported, sourcecdk.CoverageSupportPartial:
			if len(dimension.EvidenceTypes) == 0 {
				issues = append(issues, issue{path: path, message: prefix + " must declare evidence_types"})
			}
			if len(dimension.ControlDomains) == 0 {
				issues = append(issues, issue{path: path, message: prefix + " must declare control_domains"})
			}
		}
		if controlCatalog == nil {
			continue
		}
		for _, ref := range dimension.ControlRefs {
			framework := strings.TrimSpace(ref.FrameworkName)
			if framework == "" {
				framework = strings.TrimSpace(ref.FrameworkID)
			}
			if framework == "" {
				continue
			}
			_, ok := controlCatalog.Control(compliance.ControlRef{FrameworkID: ref.FrameworkID, FrameworkName: ref.FrameworkName, ControlID: ref.ControlID})
			if !ok {
				issues = append(issues, issue{path: path, message: fmt.Sprintf("%s control ref %s %s is not declared in internal/compliance/control_families.yaml", prefix, framework, ref.ControlID)})
			}
		}
	}
	return issues
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
	if walkErr := filepath.WalkDir(testdata, func(path string, entry fs.DirEntry, err error) error {
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
	}); walkErr != nil {
		issues = append(issues, issue{path: slashRel(root, testdata), message: "walk testdata: " + walkErr.Error()})
	}
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

func slashRel(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
