package main

import (
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/findingdsl"
	"gopkg.in/yaml.v3"
)

const defaultOutputDir = "docs/reference/policy-compliance-mapping"
const policyRuleExtensionsPath = "internal/compliance/policy_rule_extensions.yaml"
const controlFamiliesPath = "internal/compliance/control_families.yaml"

type policyRuleExtensions struct {
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

type controlFamilyIndex map[string]string

type generatedFile struct {
	Name    string
	Content []byte
}

func main() {
	root := flag.String("root", ".", "repository root")
	output := flag.String("output", defaultOutputDir, "output directory for generated CSV mapping files")
	write := flag.Bool("write", false, "write generated policy compliance mapping CSVs")
	check := flag.Bool("check", false, "check generated policy compliance mapping CSVs are current")
	flag.Parse()

	if !*write && !*check {
		fmt.Fprintln(os.Stderr, "policymappingexport: one of --write or --check is required")
		os.Exit(2)
	}

	cleanRoot := filepath.Clean(*root)
	files, err := generateFiles(cleanRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policymappingexport: %v\n", err)
		os.Exit(1)
	}
	if *write {
		if err := writeFiles(cleanRoot, *output, files); err != nil {
			fmt.Fprintf(os.Stderr, "policymappingexport: write: %v\n", err)
			os.Exit(1)
		}
	}
	if *check {
		stale, err := checkFiles(cleanRoot, *output, files)
		if err != nil {
			fmt.Fprintf(os.Stderr, "policymappingexport: %v\n", err)
			os.Exit(1)
		}
		if stale {
			os.Exit(1)
		}
	}
}

func generateFiles(root string) ([]generatedFile, error) {
	rules, issues, err := findingdsl.LoadPolicyRules(root)
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
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Metadata.ID == rules[j].Metadata.ID {
			return rules[i].RelPath < rules[j].RelPath
		}
		return rules[i].Metadata.ID < rules[j].Metadata.ID
	})

	extensions, err := loadPolicyRuleExtensions(root)
	if err != nil {
		return nil, err
	}
	controlFamilies, err := loadControlFamilyIndex(root)
	if err != nil {
		return nil, err
	}

	var policyRows [][]string
	var controlRows [][]string
	var tagRows [][]string
	domains := map[string]int{}
	frameworks := map[string]int{}
	evidenceModes := map[string]int{}
	uniqueTags := map[string]struct{}{}
	for _, rule := range rules {
		legacy := rule.LegacyPolicy()
		extension := extensions.extensionFor(rule)
		evidenceMode := policyEvidenceMode(rule)
		evidenceType := policyEvidenceType(rule, extension)
		assessmentMethods := policyAssessmentMethods(rule, extension)
		controlRefs := policyControlRefs(rule, controlFamilies)
		controlFamiliesForPolicy := uniqueControlFamilies(controlRefs)
		metadataTags := uniqueSorted(legacy.Tags)
		derivedTags := policyDerivedTags(rule, evidenceMode, evidenceType, assessmentMethods)
		allTags := uniqueSorted(append(append([]string{}, metadataTags...), derivedTags...))

		domains[rule.Domain]++
		evidenceModes[evidenceMode]++
		for _, framework := range legacy.Frameworks {
			name := strings.TrimSpace(framework.Name)
			if name != "" {
				frameworks[name]++
			}
		}
		for _, tag := range allTags {
			uniqueTags[tag] = struct{}{}
		}

		policyRows = append(policyRows, []string{
			legacy.ID,
			legacy.Name,
			rule.Domain,
			rule.RelPath,
			policyStatus(rule),
			strings.ToLower(strings.TrimSpace(legacy.Severity)),
			firstNonEmpty(legacy.Category, rule.Domain),
			legacy.Resource,
			legacy.ResourceType,
			policySourceID(rule),
			evidenceMode,
			evidenceType,
			joinList(assessmentMethods),
			joinList(policyFrameworkNames(rule)),
			joinList(controlRefLabels(controlRefs)),
			joinList(controlFamiliesForPolicy),
			joinList(metadataTags),
			joinList(derivedTags),
			joinList(allTags),
			joinList(legacy.RiskCategories),
			joinList(policyMITRE(rule)),
			legacy.Remediation,
			policyRiskStatement(rule, extension),
			policyRemediationIntent(rule, extension),
			policyAuditorGuidance(rule, extension),
		})

		for _, ref := range controlRefs {
			controlRows = append(controlRows, []string{
				ref.Framework,
				ref.ControlID,
				ref.Label(),
				ref.Family,
				legacy.ID,
				legacy.Name,
				rule.Domain,
				strings.ToLower(strings.TrimSpace(legacy.Severity)),
				evidenceMode,
				evidenceType,
				rule.RelPath,
			})
		}

		metadataTagSet := stringSet(metadataTags)
		for _, tag := range allTags {
			source := "derived"
			if _, ok := metadataTagSet[tag]; ok {
				source = "metadata"
			}
			tagRows = append(tagRows, []string{
				tag,
				tagKind(tag),
				source,
				legacy.ID,
				legacy.Name,
				rule.Domain,
				strings.ToLower(strings.TrimSpace(legacy.Severity)),
				evidenceMode,
				rule.RelPath,
			})
		}
	}

	sort.Slice(controlRows, func(i, j int) bool {
		return strings.Join(controlRows[i], "\x00") < strings.Join(controlRows[j], "\x00")
	})
	sort.Slice(tagRows, func(i, j int) bool {
		return strings.Join(tagRows[i], "\x00") < strings.Join(tagRows[j], "\x00")
	})

	files := []generatedFile{
		{Name: "overview.csv", Content: csvBytes(overviewRows(len(rules), len(controlRows), len(tagRows), len(uniqueTags), domains, frameworks, evidenceModes))},
		{Name: "policy_map.csv", Content: csvBytes(append([][]string{policyMapHeader()}, policyRows...))},
		{Name: "control_map.csv", Content: csvBytes(append([][]string{controlMapHeader()}, controlRows...))},
		{Name: "tag_map.csv", Content: csvBytes(append([][]string{tagMapHeader()}, tagRows...))},
		{Name: "yaml_layers.csv", Content: csvBytes(yamlLayerRows(extensions))},
		{Name: "logic.csv", Content: csvBytes(logicRows())},
	}
	return files, nil
}

func loadPolicyRuleExtensions(root string) (policyRuleExtensions, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(policyRuleExtensionsPath)))
	if err != nil {
		if os.IsNotExist(err) {
			return policyRuleExtensions{}, nil
		}
		return policyRuleExtensions{}, fmt.Errorf("read %s: %w", policyRuleExtensionsPath, err)
	}
	var extensions policyRuleExtensions
	if err := yaml.Unmarshal(content, &extensions); err != nil {
		return policyRuleExtensions{}, fmt.Errorf("decode %s: %w", policyRuleExtensionsPath, err)
	}
	return extensions, nil
}

func loadControlFamilyIndex(root string) (controlFamilyIndex, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(controlFamiliesPath)))
	if err != nil {
		if os.IsNotExist(err) {
			return controlFamilyIndex{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", controlFamiliesPath, err)
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
			if familyID == "" {
				continue
			}
			familyLabel := frameworkName + " " + familyID
			if familyName := strings.TrimSpace(family.Name); familyName != "" {
				familyLabel += " " + familyName
			}
			for _, control := range family.Controls {
				controlID := strings.TrimSpace(control.ID)
				if controlID != "" {
					index[frameworkName+"\x00"+controlID] = familyLabel
				}
			}
		}
	}
	return index, nil
}

func (extensions policyRuleExtensions) extensionFor(rule findingdsl.PolicyFindingRule) policyRuleExtension {
	merged := policyRuleExtension{}
	merged = mergePolicyRuleExtension(merged, extensions.Defaults)
	merged = mergePolicyRuleExtension(merged, extensions.EvidenceModes[policyEvidenceMode(rule)])
	merged = mergePolicyRuleExtension(merged, extensions.Domains[rule.Domain])
	merged = mergePolicyRuleExtension(merged, extensions.Policies[rule.Metadata.ID])
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

type policyControlRef struct {
	Framework string
	ControlID string
	Family    string
}

func (ref policyControlRef) Label() string {
	return strings.TrimSpace(ref.Framework + " " + ref.ControlID)
}

func policyControlRefs(rule findingdsl.PolicyFindingRule, index controlFamilyIndex) []policyControlRef {
	var refs []policyControlRef
	seen := map[string]struct{}{}
	for _, framework := range rule.Spec.Frameworks {
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
			refs = append(refs, policyControlRef{
				Framework: frameworkName,
				ControlID: controlID,
				Family:    index[key],
			})
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Framework == refs[j].Framework {
			return refs[i].ControlID < refs[j].ControlID
		}
		return refs[i].Framework < refs[j].Framework
	})
	return refs
}

func policyEvidenceMode(rule findingdsl.PolicyFindingRule) string {
	switch {
	case strings.TrimSpace(rule.Spec.Graph.Query) != "":
		return "graph"
	case strings.TrimSpace(rule.Spec.Match.Query) != "":
		return "query"
	case len(trimStrings(rule.Spec.Match.Conditions)) != 0:
		return "cel"
	default:
		return "manual"
	}
}

func policyStatus(rule findingdsl.PolicyFindingRule) string {
	if rule.Spec.Enabled != nil && !*rule.Spec.Enabled {
		return "disabled"
	}
	return "active"
}

func policySourceID(rule findingdsl.PolicyFindingRule) string {
	if strings.TrimSpace(rule.Spec.Graph.Query) == "" {
		return "policy"
	}
	for _, sourceKind := range uniqueSorted(rule.Spec.Input.SourceKinds) {
		sourceID, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(sourceKind)), ".")
		if sourceID != "" {
			return sourceID
		}
	}
	return "graph"
}

func policyEvidenceType(rule findingdsl.PolicyFindingRule, extension policyRuleExtension) string {
	return firstNonEmpty(rule.Spec.Evidence.Type, rule.Spec.Audit.EvidenceType, extension.EvidenceType)
}

func policyAssessmentMethods(rule findingdsl.PolicyFindingRule, extension policyRuleExtension) []string {
	if methods := uniqueSorted(rule.Spec.Evidence.AssessmentMethods); len(methods) != 0 {
		return methods
	}
	if methods := uniqueSorted(rule.Spec.Audit.AssessmentMethods); len(methods) != 0 {
		return methods
	}
	return uniqueSorted(extension.AssessmentMethods)
}

func policyAuditorGuidance(rule findingdsl.PolicyFindingRule, extension policyRuleExtension) string {
	return firstNonEmpty(rule.Spec.Audit.AuditorGuidance, rule.Spec.Audit.AuditorStatement, extension.AuditorGuidance)
}

func policyRiskStatement(rule findingdsl.PolicyFindingRule, extension policyRuleExtension) string {
	if value := strings.TrimSpace(rule.Spec.Audit.RiskStatement); value != "" {
		return value
	}
	if value := strings.TrimSpace(extension.RiskStatement); value != "" {
		return value
	}
	return "The mapped control may lack sufficient operating evidence because the assessed subject is outside the expected policy state."
}

func policyRemediationIntent(rule findingdsl.PolicyFindingRule, extension policyRuleExtension) string {
	if value := strings.TrimSpace(rule.Spec.Audit.RemediationIntent); value != "" {
		return value
	}
	if value := strings.TrimSpace(extension.RemediationIntent); value != "" {
		return value
	}
	return "Restore the assessed subject to the expected control state, reduce exposure where applicable, and preserve evidence of the corrective action."
}

func policyDerivedTags(rule findingdsl.PolicyFindingRule, evidenceMode string, evidenceType string, assessmentMethods []string) []string {
	values := []string{"policy", evidenceMode, rule.Domain}
	if evidenceType := strings.TrimSpace(evidenceType); evidenceType != "" {
		values = append(values, "evidence:"+evidenceType)
	}
	for _, method := range assessmentMethods {
		if method := strings.TrimSpace(method); method != "" {
			values = append(values, "assessment:"+method)
		}
	}
	if category := strings.TrimSpace(rule.Spec.Category); category != "" {
		values = append(values, category)
	}
	return uniqueSorted(values)
}

func policyFrameworkNames(rule findingdsl.PolicyFindingRule) []string {
	var names []string
	for _, framework := range rule.Spec.Frameworks {
		if name := strings.TrimSpace(framework.Name); name != "" {
			names = append(names, name)
		}
	}
	return uniqueSorted(names)
}

func policyMITRE(rule findingdsl.PolicyFindingRule) []string {
	var values []string
	for _, item := range rule.Spec.MITREAttack {
		tactic := strings.TrimSpace(item.Tactic)
		technique := strings.TrimSpace(item.Technique)
		switch {
		case tactic != "" && technique != "":
			values = append(values, tactic+":"+technique)
		case tactic != "":
			values = append(values, tactic)
		case technique != "":
			values = append(values, technique)
		}
	}
	return uniqueSorted(values)
}

func controlRefLabels(refs []policyControlRef) []string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		values = append(values, ref.Label())
	}
	return uniqueSorted(values)
}

func uniqueControlFamilies(refs []policyControlRef) []string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		if family := strings.TrimSpace(ref.Family); family != "" {
			values = append(values, family)
		}
	}
	return uniqueSorted(values)
}

func overviewRows(policyCount int, controlCount int, tagCount int, uniqueTagCount int, domains map[string]int, frameworks map[string]int, evidenceModes map[string]int) [][]string {
	rows := [][]string{
		{"metric", "value"},
		{"policy finding rules", fmt.Sprint(policyCount)},
		{"policy-control rows", fmt.Sprint(controlCount)},
		{"tag rows", fmt.Sprint(tagCount)},
		{"unique tags", fmt.Sprint(uniqueTagCount)},
		{"domains", fmt.Sprint(len(domains))},
		{"frameworks", fmt.Sprint(len(frameworks))},
		{},
		{"evidence mode", "rules"},
	}
	rows = appendCountRows(rows, evidenceModes)
	rows = append(rows, []string{}, []string{"domain", "rules"})
	rows = appendCountRows(rows, domains)
	rows = append(rows, []string{}, []string{"framework", "rules"})
	rows = appendCountRows(rows, frameworks)
	return rows
}

func appendCountRows(rows [][]string, counts map[string]int) [][]string {
	type pair struct {
		Name  string
		Count int
	}
	var pairs []pair
	for name, count := range counts {
		if strings.TrimSpace(name) != "" {
			pairs = append(pairs, pair{Name: name, Count: count})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count == pairs[j].Count {
			return pairs[i].Name < pairs[j].Name
		}
		return pairs[i].Count > pairs[j].Count
	})
	for _, item := range pairs {
		rows = append(rows, []string{item.Name, fmt.Sprint(item.Count)})
	}
	return rows
}

func yamlLayerRows(extensions policyRuleExtensions) [][]string {
	rows := [][]string{{"scope_type", "scope", "evidence_type", "assessment_methods", "auditor_guidance", "risk_statement", "remediation_intent", "false_positives"}}
	rows = append(rows, extensionRow("defaults", "global", extensions.Defaults))
	for _, key := range sortedKeys(extensions.EvidenceModes) {
		rows = append(rows, extensionRow("evidence_mode", key, extensions.EvidenceModes[key]))
	}
	for _, key := range sortedKeys(extensions.Domains) {
		rows = append(rows, extensionRow("domain", key, extensions.Domains[key]))
	}
	for _, key := range sortedKeys(extensions.Policies) {
		rows = append(rows, extensionRow("policy", key, extensions.Policies[key]))
	}
	return rows
}

func extensionRow(scopeType string, scope string, extension policyRuleExtension) []string {
	return []string{
		scopeType,
		scope,
		extension.EvidenceType,
		joinList(extension.AssessmentMethods),
		extension.AuditorGuidance,
		extension.RiskStatement,
		extension.RemediationIntent,
		joinList(extension.FalsePositives),
	}
}

func logicRows() [][]string {
	return [][]string{
		{"step", "layer", "definition"},
		{"1", "defaults", "Start with shared audit defaults from internal/compliance/policy_rule_extensions.yaml."},
		{"2", "evidence mode", "Apply mode-specific defaults for cel, query, graph, or manual policies."},
		{"3", "domain", "Apply the domain block keyed by the policy folder under policies/."},
		{"4", "policy override", "Apply any explicit policy ID override when a rule needs different audit language."},
		{"5", "policy YAML", "Use each PolicyFindingRule YAML file for controls, tags, severity, resource, remediation, risk categories, and MITRE references."},
		{"6", "spreadsheet", "Generate CSV rows from YAML and derived layers. Do not edit spreadsheet rows back into source by hand."},
	}
}

func policyMapHeader() []string {
	return []string{
		"rule_id", "name", "domain", "path", "status", "severity", "category", "resource", "resource_type",
		"source_id", "evidence_mode", "evidence_type", "assessment_methods", "frameworks", "control_refs",
		"control_families", "metadata_tags", "derived_tags", "all_tags", "risk_categories", "mitre",
		"remediation", "risk_statement", "remediation_intent", "auditor_guidance",
	}
}

func controlMapHeader() []string {
	return []string{"framework", "control_id", "control_ref", "control_family", "rule_id", "name", "domain", "severity", "evidence_mode", "evidence_type", "path"}
}

func tagMapHeader() []string {
	return []string{"tag", "tag_kind", "tag_source", "rule_id", "name", "domain", "severity", "evidence_mode", "path"}
}

func writeFiles(root string, output string, files []generatedFile) error {
	dir := outputDir(root, output)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	for _, file := range files {
		path := filepath.Join(dir, file.Name)
		if err := os.WriteFile(path, file.Content, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

func checkFiles(root string, output string, files []generatedFile) (bool, error) {
	dir := outputDir(root, output)
	stale := false
	for _, file := range files {
		path := filepath.Join(dir, file.Name)
		existing, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "policymappingexport: %s is missing; run `make policy-mapping-export`\n", path)
				stale = true
				continue
			}
			return false, fmt.Errorf("read %s: %w", path, err)
		}
		if !bytes.Equal(existing, file.Content) {
			fmt.Fprintf(os.Stderr, "policymappingexport: %s is stale; run `make policy-mapping-export`\n", path)
			stale = true
		}
	}
	return stale, nil
}

func outputDir(root string, output string) string {
	if filepath.IsAbs(output) {
		return filepath.Clean(output)
	}
	return filepath.Join(root, filepath.Clean(output))
}

func csvBytes(rows [][]string) []byte {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			panic(err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func tagKind(tag string) string {
	normalized := strings.ToLower(strings.TrimSpace(tag))
	switch {
	case strings.HasPrefix(normalized, "evidence:"):
		return "evidence"
	case strings.HasPrefix(normalized, "assessment:"):
		return "assessment"
	case normalized == "policy" || normalized == "cel" || normalized == "query" || normalized == "graph" || normalized == "manual":
		return "generated"
	case strings.Contains(normalized, "soc") || strings.Contains(normalized, "nist") || strings.Contains(normalized, "iso") || strings.Contains(normalized, "pci") || strings.Contains(normalized, "hipaa") || strings.Contains(normalized, "cis") || strings.Contains(normalized, "gdpr") || strings.Contains(normalized, "ccpa") || strings.Contains(normalized, "compliance"):
		return "compliance"
	case strings.Contains(normalized, "risk") || strings.Contains(normalized, "threat") || strings.Contains(normalized, "attack") || strings.Contains(normalized, "vulnerability") || strings.Contains(normalized, "exposure") || strings.Contains(normalized, "secret") || strings.Contains(normalized, "privilege"):
		return "risk"
	default:
		return "routing"
	}
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func stringSet(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out[trimmed] = struct{}{}
		}
	}
	return out
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

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			seen[trimmed] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func joinList(values []string) string {
	return strings.Join(uniqueSorted(values), "; ")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
