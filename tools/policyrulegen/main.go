package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/findingdsl"
	"gopkg.in/yaml.v3"
)

const defaultOutputPath = "internal/findings/policy_rule_catalog_gen.go"
const policyRuleExtensionsPath = "internal/compliance/policy_rule_extensions.yaml"
const controlFamiliesPath = "internal/compliance/control_families.yaml"

type policyFile struct {
	ID               string                            `json:"id"`
	Name             string                            `json:"name"`
	Description      string                            `json:"description"`
	References       []string                          `json:"references"`
	Severity         string                            `json:"severity"`
	Category         string                            `json:"category"`
	Resource         string                            `json:"resource"`
	ResourceType     string                            `json:"resource_type"`
	Conditions       []string                          `json:"conditions"`
	ConditionFormat  string                            `json:"condition_format"`
	Query            string                            `json:"query"`
	Tags             []string                          `json:"tags"`
	Remediation      string                            `json:"remediation"`
	RemediationSteps []string                          `json:"remediation_steps"`
	Frameworks       []policyFramework                 `json:"frameworks"`
	Input            findingdsl.PolicyRuleInput        `json:"input"`
	Assert           findingdsl.PolicyRuleAssert       `json:"assert"`
	Context          findingdsl.PolicyRuleContext      `json:"context"`
	Evidence         findingdsl.PolicyRuleEvidence     `json:"evidence"`
	Audit            findingdsl.PolicyRuleAudit        `json:"audit"`
	Verification     findingdsl.PolicyRuleVerification `json:"verification"`
	Actions          findingdsl.PolicyRuleActions      `json:"actions"`
	Graph            findingdsl.PolicyRuleGraphFinding `json:"graph"`
	Enabled          *bool                             `json:"enabled"`
	relPath          string
	domain           string
}

type policyFramework struct {
	Name     string   `json:"name"`
	Controls []string `json:"controls"`
}

type policyRuleExtensions struct {
	Version       string                         `yaml:"version"`
	Defaults      policyRuleExtension            `yaml:"defaults"`
	EvidenceModes map[string]policyRuleExtension `yaml:"evidence_modes"`
	Domains       map[string]policyRuleExtension `yaml:"domains"`
	Policies      map[string]policyRuleExtension `yaml:"policies"`
}

type policyRuleExtension struct {
	EvidenceType      string   `yaml:"evidence_type"`
	AssessmentMethods []string `yaml:"assessment_methods"`
	AuditorGuidance   string   `yaml:"auditor_guidance"`
	RiskStatement     string   `yaml:"risk_statement"`
	RemediationIntent string   `yaml:"remediation_intent"`
	FalsePositives    []string `yaml:"false_positives"`
}

type complianceControlCatalog struct {
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
	ID string `yaml:"id"`
}

func main() {
	root := flag.String("root", ".", "repository root")
	output := flag.String("output", defaultOutputPath, "generated Go output path relative to root")
	write := flag.Bool("write", false, "write the generated policy rule catalog")
	check := flag.Bool("check", false, "check that the generated policy rule catalog is fresh")
	flag.Parse()

	if !*write && !*check {
		fmt.Fprintln(os.Stderr, "policyrulegen: one of --write or --check is required")
		os.Exit(2)
	}
	content, err := generate(filepath.Clean(*root))
	if err != nil {
		fmt.Fprintf(os.Stderr, "policyrulegen: %v\n", err)
		os.Exit(1)
	}
	cleanRoot := filepath.Clean(*root)
	outputRel, err := safeRepoRel(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policyrulegen: %v\n", err)
		os.Exit(1)
	}
	if *write {
		if err := writeRepoFile(cleanRoot, outputRel, content); err != nil {
			fmt.Fprintf(os.Stderr, "policyrulegen: write %s: %v\n", outputRel, err)
			os.Exit(1)
		}
	}
	if *check {
		existing, err := readRepoFile(cleanRoot, outputRel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "policyrulegen: read %s: %v\n", outputRel, err)
			os.Exit(1)
		}
		if !bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(content)) {
			fmt.Fprintf(os.Stderr, "policyrulegen: %s is stale; run `make policy-rule-generate`\n", outputRel)
			os.Exit(1)
		}
	}
}

func readRepoFile(root string, rel string) ([]byte, error) {
	cleanRel, err := safeRepoRel(rel)
	if err != nil {
		return nil, err
	}
	repoRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("open repository root: %w", err)
	}
	defer func() { _ = repoRoot.Close() }()
	if err := rejectSymlink(repoRoot, cleanRel); err != nil {
		return nil, err
	}
	content, err := repoRoot.ReadFile(cleanRel)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func readOptionalRepoFile(root string, rel string) ([]byte, bool, error) {
	content, err := readRepoFile(root, rel)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return content, true, nil
}

func writeRepoFile(root string, rel string, content []byte) error {
	cleanRel, err := safeRepoRel(rel)
	if err != nil {
		return err
	}
	repoRoot, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("open repository root: %w", err)
	}
	defer func() { _ = repoRoot.Close() }()
	dir := filepath.ToSlash(filepath.Dir(cleanRel))
	if dir != "." {
		if err := repoRoot.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := rejectSymlink(repoRoot, cleanRel); err != nil {
		return err
	}
	return repoRoot.WriteFile(cleanRel, content, 0o644)
}

func rejectSymlink(root *os.Root, rel string) error {
	info, err := root.Lstat(rel)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlinked generated files are not allowed")
	}
	return nil
}

func safeRepoRel(rel string) (string, error) {
	cleanRel := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	if strings.HasPrefix(cleanRel, "../") || cleanRel == ".." || filepath.IsAbs(cleanRel) {
		return "", fmt.Errorf("path %q escapes repository root", rel)
	}
	return cleanRel, nil
}

func generate(root string) ([]byte, error) {
	policies, err := loadPolicies(root)
	if err != nil {
		return nil, err
	}
	extensions, err := loadPolicyRuleExtensions(root)
	if err != nil {
		return nil, err
	}
	controlFamilies, err := loadControlFamilyIndex(root)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("// Code generated by go run ./tools/policyrulegen --write; DO NOT EDIT.\n")
	buf.WriteString("package findings\n\n")
	buf.WriteString("import \"github.com/writer/cerebro/internal/ports\"\n\n")
	fmt.Fprintf(&buf, "var generatedPolicyRuleCatalog = []policyRuleConfig{\n")
	for _, policy := range policies {
		extension := extensions.extensionFor(policy)
		writePolicyRuleConfig(&buf, policy, extension, controlFamilies.familiesFor(policy.Frameworks))
	}
	buf.WriteString("}\n")
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format generated Go: %w", err)
	}
	return formatted, nil
}

func loadPolicies(root string) ([]policyFile, error) {
	dslRules, issues, err := findingdsl.LoadPolicyRules(root)
	if err != nil {
		return nil, err
	}
	if len(issues) != 0 {
		messages := make([]string, 0, len(issues))
		for _, issue := range issues {
			messages = append(messages, issue.Path+": "+issue.Message)
		}
		return nil, fmt.Errorf("policy DSL validation failed: %s", strings.Join(messages, "; "))
	}
	var policies []policyFile
	for _, rule := range dslRules {
		policy := policyFromDSL(rule)
		policies = append(policies, policy)
	}
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].ID == policies[j].ID {
			return policies[i].relPath < policies[j].relPath
		}
		return policies[i].ID < policies[j].ID
	})
	return policies, nil
}

func policyFromDSL(rule findingdsl.PolicyFindingRule) policyFile {
	legacy := rule.LegacyPolicy()
	return policyFile{
		ID:               legacy.ID,
		Name:             legacy.Name,
		Description:      legacy.Description,
		References:       rule.Metadata.References,
		Severity:         legacy.Severity,
		Category:         legacy.Category,
		Resource:         legacy.Resource,
		ResourceType:     legacy.ResourceType,
		Conditions:       legacy.Conditions,
		ConditionFormat:  legacy.ConditionFormat,
		Query:            legacy.Query,
		Tags:             legacy.Tags,
		Remediation:      legacy.Remediation,
		RemediationSteps: legacy.RemediationSteps,
		Frameworks:       policyFrameworksFromDSL(legacy.Frameworks),
		Input:            rule.Spec.Input,
		Assert:           rule.Spec.Assert,
		Context:          rule.Spec.Context,
		Evidence:         rule.Spec.Evidence,
		Audit:            rule.Spec.Audit,
		Verification:     rule.Spec.Verification,
		Actions:          rule.Spec.Actions,
		Graph:            rule.Spec.Graph,
		Enabled:          legacy.Enabled,
		relPath:          rule.RelPath,
		domain:           rule.Domain,
	}
}

func policyFrameworksFromDSL(frameworks []findingdsl.PolicyFramework) []policyFramework {
	out := make([]policyFramework, 0, len(frameworks))
	for _, framework := range frameworks {
		out = append(out, policyFramework{
			Name:     framework.Name,
			Controls: append([]string(nil), framework.Controls...),
		})
	}
	return out
}

func loadPolicyRuleExtensions(root string) (policyRuleExtensions, error) {
	content, ok, err := readOptionalRepoFile(root, policyRuleExtensionsPath)
	if err != nil {
		return policyRuleExtensions{}, fmt.Errorf("read %s: %w", policyRuleExtensionsPath, err)
	}
	if !ok {
		return policyRuleExtensions{}, nil
	}
	var extensions policyRuleExtensions
	if err := yaml.Unmarshal(content, &extensions); err != nil {
		return policyRuleExtensions{}, fmt.Errorf("decode %s: %w", policyRuleExtensionsPath, err)
	}
	return extensions, nil
}

type controlFamilyIndex map[string]string

func loadControlFamilyIndex(root string) (controlFamilyIndex, error) {
	content, ok, err := readOptionalRepoFile(root, controlFamiliesPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", controlFamiliesPath, err)
	}
	if !ok {
		return controlFamilyIndex{}, nil
	}
	var catalog complianceControlCatalog
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return nil, fmt.Errorf("decode %s: %w", controlFamiliesPath, err)
	}
	index := controlFamilyIndex{}
	for _, framework := range catalog.Frameworks {
		frameworkName := strings.TrimSpace(framework.Name)
		if frameworkName == "" {
			continue
		}
		for _, family := range framework.Families {
			familyID := strings.TrimSpace(family.ID)
			familyName := strings.TrimSpace(family.Name)
			if familyID == "" {
				continue
			}
			label := frameworkName + " " + familyID
			if familyName != "" {
				label += " " + familyName
			}
			for _, control := range family.Controls {
				controlID := strings.TrimSpace(control.ID)
				if controlID == "" {
					continue
				}
				index[frameworkName+"\x00"+controlID] = label
			}
		}
	}
	return index, nil
}

func (index controlFamilyIndex) familiesFor(frameworks []policyFramework) []string {
	seen := map[string]struct{}{}
	var families []string
	for _, framework := range frameworks {
		frameworkName := strings.TrimSpace(framework.Name)
		for _, control := range framework.Controls {
			if family := strings.TrimSpace(index[frameworkName+"\x00"+strings.TrimSpace(control)]); family != "" {
				if _, ok := seen[family]; ok {
					continue
				}
				seen[family] = struct{}{}
				families = append(families, family)
			}
		}
	}
	sort.Strings(families)
	return families
}

func (extensions policyRuleExtensions) extensionFor(policy policyFile) policyRuleExtension {
	merged := policyRuleExtension{}
	merged = mergePolicyRuleExtension(merged, extensions.Defaults)
	merged = mergePolicyRuleExtension(merged, extensions.EvidenceModes[policyEvidenceMode(policy)])
	merged = mergePolicyRuleExtension(merged, extensions.Domains[policy.domain])
	merged = mergePolicyRuleExtension(merged, extensions.Policies[policy.ID])
	return merged
}

func mergePolicyRuleExtension(base, next policyRuleExtension) policyRuleExtension {
	if value := strings.TrimSpace(next.EvidenceType); value != "" {
		base.EvidenceType = value
	}
	if value := strings.TrimSpace(next.AuditorGuidance); value != "" {
		base.AuditorGuidance = value
	}
	if value := strings.TrimSpace(next.RiskStatement); value != "" {
		base.RiskStatement = value
	}
	if value := strings.TrimSpace(next.RemediationIntent); value != "" {
		base.RemediationIntent = value
	}
	if len(trimStrings(next.AssessmentMethods)) != 0 {
		base.AssessmentMethods = uniqueSorted(next.AssessmentMethods)
	}
	base.FalsePositives = uniqueSorted(append(base.FalsePositives, next.FalsePositives...))
	return base
}

func writePolicyRuleConfig(buf *bytes.Buffer, policy policyFile, extension policyRuleExtension, controlFamilies []string) {
	evidenceMode := policyEvidenceMode(policy)
	evidenceType := policyEvidenceType(policy, extension)
	assessmentMethods := policyAssessmentMethods(policy, extension)
	auditorGuidance := policyAuditorGuidance(policy, extension)
	fmt.Fprintf(buf, "{\n")
	fmt.Fprintf(buf, "Definition: RuleDefinition{\n")
	fmt.Fprintf(buf, "ID: %s,\n", quote(policy.ID))
	fmt.Fprintf(buf, "Name: %s,\n", quote(policy.Name))
	fmt.Fprintf(buf, "Description: %s,\n", quote(policyDescription(policy, extension)))
	fmt.Fprintf(buf, "SourceID: %s,\n", policySourceIDLiteral(policy))
	writePolicyEventKinds(buf, policy)
	fmt.Fprintf(buf, "OutputKind: %s,\n", policyOutputKindLiteral(policy))
	fmt.Fprintf(buf, "Severity: %s,\n", quote(normalizeSeverity(policy.Severity)))
	fmt.Fprintf(buf, "Status: %s,\n", quote(policyStatus(policy)))
	fmt.Fprintf(buf, "Maturity: RuleMaturityCandidate,\n")
	writeStringSlice(buf, "Tags", policyTags(policy, evidenceMode, evidenceType, assessmentMethods))
	writeStringSlice(buf, "References", policyReferences(policy))
	writeStringSlice(buf, "FalsePositives", policyFalsePositives(policy, extension))
	fmt.Fprintf(buf, "Runbook: %s,\n", quote(policyRunbook(policy, extension)))
	writeStringSlice(buf, "RequiredAttributes", policyRequiredAttributes(policy))
	writeStringSliceMap(buf, "RequiredAttributesByKind", policyRequiredAttributesByKind(policy))
	writePolicyFingerprintFields(buf, policy)
	writeControlRefs(buf, policy.Frameworks)
	writePolicyLifecycle(buf, policy)
	fmt.Fprintf(buf, "},\n")
	writeStringSlice(buf, "Conditions", trimStrings(policy.Conditions))
	fmt.Fprintf(buf, "Query: %s,\n", quote(strings.TrimSpace(policy.Query)))
	fmt.Fprintf(buf, "Resource: %s,\n", quote(firstNonEmpty(policy.Resource, policy.ResourceType)))
	fmt.Fprintf(buf, "ResourceType: %s,\n", quote(firstNonEmpty(policy.ResourceType, policy.Resource)))
	fmt.Fprintf(buf, "Category: %s,\n", quote(firstNonEmpty(policy.Category, policy.domain)))
	fmt.Fprintf(buf, "EvidenceMode: %s,\n", quote(evidenceMode))
	fmt.Fprintf(buf, "EvidenceType: %s,\n", quote(evidenceType))
	writeStringSlice(buf, "AssessmentMethods", assessmentMethods)
	fmt.Fprintf(buf, "AuditorGuidance: %s,\n", quote(auditorGuidance))
	fmt.Fprintf(buf, "RiskStatement: %s,\n", quote(policyRiskStatement(policy, extension)))
	fmt.Fprintf(buf, "RemediationIntent: %s,\n", quote(policyRemediationIntent(policy, extension)))
	writeStringSlice(buf, "ExceptionGuidance", policyExceptionGuidance(policy, extension))
	writeStringSlice(buf, "ControlFamilies", controlFamilies)
	writeStringMap(buf, "ContractAttributes", policyContractAttributes(policy))
	writeGraphConfig(buf, policy)
	fmt.Fprintf(buf, "Enabled: %t,\n", policy.Enabled == nil || *policy.Enabled)
	fmt.Fprintf(buf, "},\n")
}

func writeStringSlice(buf *bytes.Buffer, field string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(buf, "%s: []string{", field)
	for _, value := range values {
		fmt.Fprintf(buf, "%s,", quote(value))
	}
	fmt.Fprintf(buf, "},\n")
}

func writeStringSliceMap(buf *bytes.Buffer, field string, values map[string][]string) {
	if len(values) == 0 {
		return
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) != "" && len(trimStrings(values[key])) != 0 {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return
	}
	fmt.Fprintf(buf, "%s: map[string][]string{\n", field)
	for _, key := range keys {
		fmt.Fprintf(buf, "%s: []string{", quote(key))
		for _, value := range uniqueSorted(values[key]) {
			fmt.Fprintf(buf, "%s,", quote(value))
		}
		fmt.Fprintf(buf, "},\n")
	}
	fmt.Fprintf(buf, "},\n")
}

func writeStringMap(buf *bytes.Buffer, field string, values map[string]string) {
	if len(values) == 0 {
		return
	}
	keys := make([]string, 0, len(values))
	for key, value := range values {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return
	}
	fmt.Fprintf(buf, "%s: map[string]string{\n", field)
	for _, key := range keys {
		fmt.Fprintf(buf, "%s: %s,\n", quote(key), quote(values[key]))
	}
	fmt.Fprintf(buf, "},\n")
}

func writeAnyMap(buf *bytes.Buffer, field string, values map[string]any) {
	if len(values) == 0 {
		return
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return
	}
	fmt.Fprintf(buf, "%s: map[string]any{\n", field)
	for _, key := range keys {
		fmt.Fprintf(buf, "%s: %s,\n", quote(key), anyLiteral(values[key]))
	}
	fmt.Fprintf(buf, "},\n")
}

func anyLiteral(value any) string {
	switch typed := value.(type) {
	case nil:
		return "nil"
	case string:
		return quote(typed)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("int64(%d)", typed)
	case int64:
		return fmt.Sprintf("int64(%d)", typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return quote(fmt.Sprintf("%v", typed))
	}
}

func writeGraphConfig(buf *bytes.Buffer, policy policyFile) {
	if strings.TrimSpace(policy.Graph.Query) == "" {
		return
	}
	fmt.Fprintf(buf, "Graph: policyRuleGraphConfig{\n")
	fmt.Fprintf(buf, "Query: %s,\n", quote(strings.TrimSpace(policy.Graph.Query)))
	if policy.Graph.RowLimit > 0 {
		fmt.Fprintf(buf, "RowLimit: %d,\n", policy.Graph.RowLimit)
	}
	writeAnyMap(buf, "Params", policy.Graph.Params)
	writeStringSlice(buf, "SourceKinds", policyGraphSourceKinds(policy))
	writeStringSlice(buf, "RequiredColumns", policy.Graph.RequiredColumns)
	fmt.Fprintf(buf, "},\n")
}

func writePolicyEventKinds(buf *bytes.Buffer, policy policyFile) {
	if eventKinds := uniqueSorted(policy.Input.EventKinds); len(eventKinds) != 0 {
		writeStringSlice(buf, "EventKinds", eventKinds)
		return
	}
	if policyGraphConfigured(policy) {
		fmt.Fprintf(buf, "EventKinds: []string{%s},\n", quote("graph"))
		return
	}
	fmt.Fprintf(buf, "EventKinds: []string{policyRuleEvidenceKind, policyRuleResultEventKind},\n")
}

func writePolicyLifecycle(buf *bytes.Buffer, policy policyFile) {
	if policyGraphConfigured(policy) {
		fmt.Fprintf(buf, "Lifecycle: Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},\n")
		return
	}
	fmt.Fprintf(buf, "Lifecycle: Lifecycle{Kind: LifecycleAuditEvidence, Anchor: AnchorNone},\n")
}

func writePolicyFingerprintFields(buf *bytes.Buffer, policy policyFile) {
	if fields := uniqueStrings(policy.Evidence.FingerprintFields); len(fields) != 0 {
		writeStringSlice(buf, "FingerprintFields", fields)
		return
	}
	fmt.Fprintf(buf, "FingerprintFields: []string{%s, %s, %s, %s},\n", quote("tenant_id"), quote("policy_id"), quote("resource_urn"), quote("resource_id"))
}

func writeControlRefs(buf *bytes.Buffer, frameworks []policyFramework) {
	seen := map[string]struct{}{}
	var refs [][2]string
	for _, framework := range frameworks {
		frameworkName := strings.TrimSpace(framework.Name)
		for _, control := range framework.Controls {
			controlID := strings.TrimSpace(control)
			if frameworkName == "" || controlID == "" {
				continue
			}
			key := frameworkName + "\x00" + controlID
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			refs = append(refs, [2]string{frameworkName, controlID})
		}
	}
	if len(refs) == 0 {
		return
	}
	fmt.Fprintf(buf, "ControlRefs: []ports.FindingControlRef{\n")
	for _, ref := range refs {
		fmt.Fprintf(buf, "{FrameworkName: %s, ControlID: %s},\n", quote(ref[0]), quote(ref[1]))
	}
	fmt.Fprintf(buf, "},\n")
}

func policyEvidenceMode(policy policyFile) string {
	if policyGraphConfigured(policy) {
		return "graph"
	}
	if strings.TrimSpace(policy.Query) != "" {
		return "query"
	}
	if len(trimStrings(policy.Conditions)) != 0 {
		return "cel"
	}
	return "manual"
}

func policyGraphConfigured(policy policyFile) bool {
	return strings.TrimSpace(policy.Graph.Query) != ""
}

func policySourceIDLiteral(policy policyFile) string {
	if !policyGraphConfigured(policy) {
		return "policyRuleSourceID"
	}
	for _, sourceKind := range policyGraphSourceKinds(policy) {
		sourceID, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(sourceKind)), ".")
		if sourceID != "" {
			return quote(sourceID)
		}
	}
	return quote("graph")
}

func policyOutputKindLiteral(policy policyFile) string {
	if policyGraphConfigured(policy) {
		return "policyGraphOutputKind"
	}
	return "policyRuleOutputKind"
}

func policyGraphSourceKinds(policy policyFile) []string {
	if len(trimStrings(policy.Input.SourceKinds)) != 0 {
		return uniqueSorted(policy.Input.SourceKinds)
	}
	return nil
}

func policyStatus(policy policyFile) string {
	if policy.Enabled != nil && !*policy.Enabled {
		return "disabled"
	}
	return "active"
}

func policyEventKinds(policy policyFile) []string {
	if eventKinds := uniqueSorted(policy.Input.EventKinds); len(eventKinds) != 0 {
		return eventKinds
	}
	if policyGraphConfigured(policy) {
		return []string{"graph"}
	}
	return []string{"policy.evidence", "policy.result"}
}

func policyRequiredAttributes(policy policyFile) []string {
	return uniqueSorted(append(policy.Input.RequiredFields, policy.Evidence.RequiredFields...))
}

func policyRequiredAttributesByKind(policy policyFile) map[string][]string {
	if len(policy.Input.RequiredFieldsByKind) == 0 {
		return nil
	}
	out := map[string][]string{}
	for key, values := range policy.Input.RequiredFieldsByKind {
		if trimmed := strings.TrimSpace(key); trimmed != "" {
			if normalized := uniqueSorted(values); len(normalized) != 0 {
				out[trimmed] = normalized
			}
		}
	}
	return out
}

func policyReferences(policy policyFile) []string {
	values := append([]string{}, policy.References...)
	values = append(values, policy.Context.Graph.Anchors...)
	values = append(values, policy.Context.Graph.Enrich...)
	return uniqueSorted(values)
}

func policyEvidenceType(policy policyFile, extension policyRuleExtension) string {
	return firstNonEmpty(policy.Evidence.Type, policy.Audit.EvidenceType, extension.EvidenceType)
}

func policyAssessmentMethods(policy policyFile, extension policyRuleExtension) []string {
	if methods := uniqueSorted(policy.Evidence.AssessmentMethods); len(methods) != 0 {
		return methods
	}
	if methods := uniqueSorted(policy.Audit.AssessmentMethods); len(methods) != 0 {
		return methods
	}
	return uniqueSorted(extension.AssessmentMethods)
}

func policyAuditorGuidance(policy policyFile, extension policyRuleExtension) string {
	return firstNonEmpty(policy.Audit.AuditorGuidance, policy.Audit.AuditorStatement, extension.AuditorGuidance)
}

func policyTags(policy policyFile, evidenceMode string, evidenceType string, assessmentMethods []string) []string {
	values := append([]string{}, policy.Tags...)
	values = append(values, "policy", evidenceMode, policy.domain)
	if evidenceType := strings.TrimSpace(evidenceType); evidenceType != "" {
		values = append(values, "evidence:"+evidenceType)
	}
	for _, method := range assessmentMethods {
		if trimmed := strings.TrimSpace(method); trimmed != "" {
			values = append(values, "assessment:"+trimmed)
		}
	}
	if category := strings.TrimSpace(policy.Category); category != "" {
		values = append(values, category)
	}
	return uniqueSorted(trimStrings(values))
}

func policyDescription(policy policyFile, extension policyRuleExtension) string {
	description := cleanPolicyDescription(policy.Description)
	name := strings.TrimSpace(policy.Name)
	subject := policySubject(policy)
	if description == "" {
		description = "Checks whether " + subject + " is in the expected policy state."
	}
	parts := []string{
		"Flags failed " + policyEvidenceLabel(policyEvidenceMode(policy)) + " evidence for " + subject + ": " + name + ".",
		description,
	}
	if risk := policyRiskStatement(policy, extension); risk != "" {
		parts = append(parts, "Audit impact: "+risk)
	}
	return joinSentences(parts)
}

func cleanPolicyDescription(value string) string {
	description := strings.TrimSpace(value)
	lower := strings.ToLower(description)
	switch {
	case strings.HasPrefix(lower, "ensures "):
		return "Checks whether " + strings.TrimSpace(description[len("ensures "):])
	case strings.HasPrefix(lower, "ensure "):
		return "Checks whether " + strings.TrimSpace(description[len("ensure "):])
	default:
		return description
	}
}

func policyRunbook(policy policyFile, extension policyRuleExtension) string {
	parts := []string{
		"Review the failing evidence, affected resource or subject, owner, assessment period, and mapped controls.",
	}
	if guidance := strings.TrimSpace(policyAuditorGuidance(policy, extension)); guidance != "" {
		parts = append(parts, guidance)
	}
	if remediation := strings.TrimSpace(policy.Remediation); remediation != "" {
		parts = append(parts, remediation)
	} else if steps := trimStrings(policy.RemediationSteps); len(steps) != 0 {
		parts = append(parts, "Complete these remediation steps: "+strings.Join(steps, "; ")+".")
	} else if remediationIntent := policyRemediationIntent(policy, extension); remediationIntent != "" {
		parts = append(parts, remediationIntent)
	}
	if steps := actionStepList(policy.Actions.Remediation.Steps); steps != "" {
		parts = append(parts, "Action plan: "+steps)
	}
	parts = append(parts, "Record the remediation evidence or approved exception, then rerun evidence collection to confirm the policy passes.")
	return joinSentences(parts)
}

func policyRiskStatement(policy policyFile, extension policyRuleExtension) string {
	if value := strings.TrimSpace(policy.Audit.RiskStatement); value != "" {
		return value
	}
	if value := strings.TrimSpace(extension.RiskStatement); value != "" {
		return value
	}
	subject := policySubject(policy)
	return "The mapped control may lack sufficient operating evidence because " + subject + " is outside the expected policy state."
}

func policyRemediationIntent(policy policyFile, extension policyRuleExtension) string {
	if value := strings.TrimSpace(policy.Audit.RemediationIntent); value != "" {
		return value
	}
	if value := strings.TrimSpace(extension.RemediationIntent); value != "" {
		return value
	}
	return "Restore the assessed subject to the expected control state, reduce exposure where applicable, and preserve evidence of the corrective action."
}

func policyFalsePositives(policy policyFile, extension policyRuleExtension) []string {
	values := append([]string{}, extension.FalsePositives...)
	values = append(values, policy.Audit.FalsePositives...)
	if len(values) == 0 {
		values = []string{
			"The subject is outside the assessment scope or has a documented exception for the audit period.",
			"Inventory, ownership, or policy evidence is stale, incomplete, or not yet synchronized.",
			"A compensating control satisfies the mapped control objective and is documented for auditor review.",
		}
	}
	return uniqueSorted(trimStrings(values))
}

func policyExceptionGuidance(policy policyFile, extension policyRuleExtension) []string {
	values := policyFalsePositives(policy, extension)
	values = append(values, policy.Audit.ExceptionGuidance...)
	return uniqueSorted(values)
}

func actionStepList(values []string) string {
	steps := make([]string, 0, len(values))
	for _, value := range values {
		step := strings.TrimSpace(value)
		step = strings.TrimRight(step, ".!?")
		if step != "" {
			steps = append(steps, step)
		}
	}
	return strings.Join(steps, "; ")
}

func policyContractAttributes(policy policyFile) map[string]string {
	attributes := map[string]string{}
	addContractList(attributes, "policy_input_source_kinds", policy.Input.SourceKinds)
	addContractList(attributes, "policy_input_event_kinds", policy.Input.EventKinds)
	addContractList(attributes, "policy_input_required_claims", policy.Input.RequiredClaims)
	addContractList(attributes, "policy_input_required_fields", policy.Input.RequiredFields)
	addContractValue(attributes, "policy_input_freshness_sla", policy.Input.FreshnessSLA)
	addContractList(attributes, "policy_evidence_required_fields", policy.Evidence.RequiredFields)
	addContractList(attributes, "policy_evidence_acceptable_sources", policy.Evidence.AcceptableSources)
	addContractValue(attributes, "policy_evidence_freshness_sla", policy.Evidence.FreshnessSLA)
	if policy.Evidence.RequiredForAudit {
		attributes["policy_evidence_required_for_audit"] = "true"
	}
	addContractValue(attributes, "policy_audit_freshness_sla", policy.Audit.FreshnessSLA)
	addContractList(attributes, "policy_context_graph_anchors", policy.Context.Graph.Anchors)
	addContractList(attributes, "policy_context_graph_enrich", policy.Context.Graph.Enrich)
	addContractList(attributes, "policy_verification_mutation_checks", policy.Verification.MutationChecks)
	addContractValue(attributes, "policy_action_effort", policy.Actions.Effort)
	addContractValue(attributes, "policy_action_owner_from", policy.Actions.Owner.From)
	addContractValue(attributes, "policy_action_owner_fallback", policy.Actions.Owner.Fallback)
	addContractValue(attributes, "policy_action_remediation_type", policy.Actions.Remediation.Type)
	addContractOrderedList(attributes, "policy_action_remediation_steps", policy.Actions.Remediation.Steps)
	addContractValue(attributes, "policy_action_blast_radius_from", policy.Actions.BlastRadius.EstimateFrom)
	if policy.Actions.Verification.RerunPolicy {
		attributes["policy_action_verification_rerun_policy"] = "true"
	}
	addContractValue(attributes, "policy_verification_remediation_rerun_after", policy.Verification.RemediationCheck.RerunAfter)
	addContractValue(attributes, "policy_verification_remediation_expected_status", policy.Verification.RemediationCheck.ExpectedStatus)
	addContractOrderedList(attributes, "policy_assert_all", assertionSummaries(policy.Assert.All))
	addContractOrderedList(attributes, "policy_assert_any", assertionSummaries(policy.Assert.Any))
	addContractOrderedList(attributes, "policy_context_severity_adjustments", severityAdjustmentSummaries(policy.Context.SeverityAdjustments))
	addContractOrderedList(attributes, "policy_audit_acceptable_evidence", acceptableEvidenceSummaries(policy.Audit.AcceptableEvidence))
	addContractValue(attributes, "policy_audit_exception_max_age", policy.Audit.ExceptionPolicy.MaxAge)
	if policy.Audit.ExceptionPolicy.RequiresApproval {
		attributes["policy_audit_exception_requires_approval"] = "true"
	}
	addContractOrderedList(attributes, "policy_verification_fixtures", fixtureSummaries(policy.Verification.Fixtures))
	if len(attributes) == 0 {
		return nil
	}
	return attributes
}

func addContractValue(attributes map[string]string, key string, value string) {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		attributes[key] = trimmed
	}
}

func addContractList(attributes map[string]string, key string, values []string) {
	if normalized := uniqueSorted(values); len(normalized) != 0 {
		attributes[key] = strings.Join(normalized, ",")
	}
}

func addContractOrderedList(attributes map[string]string, key string, values []string) {
	if normalized := uniqueStrings(values); len(normalized) != 0 {
		attributes[key] = strings.Join(normalized, ",")
	}
}

func assertionSummaries(assertions []findingdsl.PolicyRuleAssertion) []string {
	values := make([]string, 0, len(assertions))
	for _, assertion := range assertions {
		field := strings.TrimSpace(assertion.Field)
		op := strings.TrimSpace(assertion.Op)
		if field == "" || op == "" {
			continue
		}
		if value := contractValueString(assertion.Value); value != "" {
			values = append(values, field+" "+op+" "+value)
		} else {
			values = append(values, field+" "+op)
		}
	}
	return values
}

func severityAdjustmentSummaries(adjustments []findingdsl.PolicyRuleSeverityAdjustment) []string {
	values := make([]string, 0, len(adjustments))
	for _, adjustment := range adjustments {
		when := strings.TrimSpace(adjustment.When)
		if when == "" {
			continue
		}
		target := firstNonEmpty(adjustment.Set, adjustment.Delta)
		if target == "" {
			continue
		}
		values = append(values, when+" => "+target)
	}
	return values
}

func acceptableEvidenceSummaries(evidence []findingdsl.PolicyRuleAcceptableEvidence) []string {
	values := make([]string, 0, len(evidence))
	for _, item := range evidence {
		source := strings.TrimSpace(item.Source)
		if source == "" {
			continue
		}
		fields := strings.Join(uniqueSorted(item.Fields), ",")
		if fields == "" {
			values = append(values, source)
		} else {
			values = append(values, source+"["+fields+"]")
		}
	}
	return values
}

func fixtureSummaries(fixtures []findingdsl.PolicyRuleVerificationFixture) []string {
	values := make([]string, 0, len(fixtures))
	for _, fixture := range fixtures {
		name := strings.TrimSpace(fixture.Name)
		expect := strings.TrimSpace(fixture.Expect)
		if name == "" || expect == "" {
			continue
		}
		values = append(values, name+":"+expect)
	}
	return values
}

func contractValueString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := contractValueString(item); value != "" {
				values = append(values, value)
			}
		}
		return strings.Join(values, "|")
	case []string:
		return strings.Join(uniqueStrings(typed), "|")
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func policySubject(policy policyFile) string {
	subject := firstNonEmpty(policy.ResourceType, policy.Resource, policy.Category, policy.domain, "the assessed subject")
	subject = strings.ReplaceAll(subject, "::", " ")
	subject = strings.ReplaceAll(subject, "|", " or ")
	subject = strings.ReplaceAll(subject, "_", " ")
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return "the assessed subject"
	}
	return subject
}

func policyEvidenceLabel(mode string) string {
	switch strings.TrimSpace(mode) {
	case "graph":
		return "graph-state"
	case "query":
		return "query-result"
	case "manual":
		return "manual-attestation"
	default:
		return "resource-state"
	}
}

func joinSentences(parts []string) string {
	sentences := make([]string, 0, len(parts))
	for _, part := range parts {
		if sentence := ensureSentence(part); sentence != "" {
			sentences = append(sentences, sentence)
		}
	}
	return strings.Join(sentences, " ")
}

func ensureSentence(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	switch trimmed[len(trimmed)-1] {
	case '.', '!', '?':
		return trimmed
	default:
		return trimmed + "."
	}
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium", "moderate":
		return "MEDIUM"
	case "low":
		return "LOW"
	case "info", "informational":
		return "INFO"
	default:
		return "MEDIUM"
	}
}

func trimStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func quote(value string) string {
	return strconv.Quote(strings.TrimSpace(value))
}
