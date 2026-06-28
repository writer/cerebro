package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/writer/cerebro/internal/findingdsl"
	"gopkg.in/yaml.v3"
)

const defaultOutputDir = "docs/reference/policy-compliance-mapping"
const policyRuleExtensionsPath = "internal/compliance/policy_rule_extensions.yaml"
const controlFamiliesPath = "internal/compliance/control_families.yaml"
const publicDetectionCatalogPath = "internal/findings/public_detection_catalog.json"

type policyRuleExtensions struct {
	Defaults       policyRuleExtension            `yaml:"defaults"`
	EvidenceModes  map[string]policyRuleExtension `yaml:"evidence_modes"`
	Domains        map[string]policyRuleExtension `yaml:"domains"`
	Policies       map[string]policyRuleExtension `yaml:"policies"`
	FindingDomains findingDomainAliases           `yaml:"finding_domains"`
	Findings       map[string]policyRuleExtension `yaml:"findings"`
}

type policyRuleExtension struct {
	EvidenceType      string   `yaml:"evidence_type"`
	AssessmentMethods []string `yaml:"assessment_methods"`
	AuditorGuidance   string   `yaml:"auditor_guidance"`
	RiskStatement     string   `yaml:"risk_statement"`
	RemediationIntent string   `yaml:"remediation_intent"`
	FalsePositives    []string `yaml:"false_positives"`
}

type findingDomainAliases struct {
	Packs    map[string]string `yaml:"packs"`
	Sources  map[string]string `yaml:"sources"`
	Tags     map[string]string `yaml:"tags"`
	Findings map[string]string `yaml:"findings"`
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

type publicDetectionCatalog struct {
	Version    string            `json:"version"`
	Detections []publicDetection `json:"detections"`
}

type publicDetection struct {
	ID                 string                             `json:"id"`
	PackID             string                             `json:"pack_id"`
	PackName           string                             `json:"pack_name"`
	Name               string                             `json:"name"`
	SourceID           string                             `json:"source_id"`
	EvaluationMode     string                             `json:"evaluation_mode"`
	OutputKind         string                             `json:"output_kind"`
	Severity           string                             `json:"severity"`
	Status             string                             `json:"status"`
	Maturity           string                             `json:"maturity"`
	Tags               []string                           `json:"tags"`
	ControlRefs        []publicDetectionControlRef        `json:"control_refs"`
	SourceCoverageRefs []publicDetectionSourceCoverageRef `json:"source_coverage_refs"`
	EvidenceType       string                             `json:"evidence_type"`
	AssessmentMethods  []string                           `json:"assessment_methods"`
	AuditorGuidance    string                             `json:"auditor_guidance"`
	RiskStatement      string                             `json:"risk_statement"`
	RemediationIntent  string                             `json:"remediation_intent"`
}

type publicDetectionControlRef struct {
	FrameworkName string `json:"framework_name"`
	ControlID     string `json:"control_id"`
}

type publicDetectionSourceCoverageRef struct {
	SourceID           string                      `json:"source_id"`
	DimensionID        string                      `json:"dimension_id"`
	DimensionType      string                      `json:"dimension_type"`
	SupportLevel       string                      `json:"support_level"`
	HighValue          bool                        `json:"high_value"`
	Families           []string                    `json:"families"`
	EvidenceTypes      []string                    `json:"evidence_types"`
	ControlDomains     []string                    `json:"control_domains"`
	MatchedControlRefs []publicDetectionControlRef `json:"matched_control_refs"`
}

type findingExportSummary struct {
	FindingCount                  int
	NonPolicyFindingCount         int
	ControlRowCount               int
	TagRowCount                   int
	SourceCoverageRowCount        int
	ComplianceReviewRowCount      int
	UniqueReviewTagCount          int
	MissingCatalogTagCount        int
	MissingControlRefCount        int
	MissingAuditDepthCount        int
	MissingSourceCoverageRefCount int
	SourceBackedFindingCount      int
	PartialSourceBackedCount      int
	ControlOnlyFindingCount       int
	Packs                         map[string]int
	Sources                       map[string]int
	EvaluationModes               map[string]int
	Frameworks                    map[string]int
	AuditDomains                  map[string]int
}

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
	catalog, err := loadPublicDetectionCatalog(root)
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

	findingRows, findingControlRows, findingTagRows, sourceCoverageRows, findingComplianceRows, findingSummary := findingReviewRows(catalog, controlFamilies, extensions)

	files := []generatedFile{
		{Name: "overview.csv", Content: csvBytes(overviewRows(len(rules), len(controlRows), len(tagRows), len(uniqueTags), domains, frameworks, evidenceModes, findingSummary))},
		{Name: "policy_map.csv", Content: csvBytes(append([][]string{policyMapHeader()}, policyRows...))},
		{Name: "control_map.csv", Content: csvBytes(append([][]string{controlMapHeader()}, controlRows...))},
		{Name: "tag_map.csv", Content: csvBytes(append([][]string{tagMapHeader()}, tagRows...))},
		{Name: "finding_map.csv", Content: csvBytes(append([][]string{findingMapHeader()}, findingRows...))},
		{Name: "finding_control_map.csv", Content: csvBytes(append([][]string{findingControlMapHeader()}, findingControlRows...))},
		{Name: "finding_tag_map.csv", Content: csvBytes(append([][]string{findingTagMapHeader()}, findingTagRows...))},
		{Name: "source_coverage_map.csv", Content: csvBytes(append([][]string{sourceCoverageMapHeader()}, sourceCoverageRows...))},
		{Name: "finding_compliance_review_map.csv", Content: csvBytes(append([][]string{findingComplianceReviewMapHeader()}, findingComplianceRows...))},
		{Name: "finding_domain_aliases.csv", Content: csvBytes(append([][]string{findingDomainAliasesHeader()}, findingDomainAliasRows(extensions)...))},
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

func loadPublicDetectionCatalog(root string) (publicDetectionCatalog, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(publicDetectionCatalogPath)))
	if err != nil {
		return publicDetectionCatalog{}, fmt.Errorf("read %s: %w", publicDetectionCatalogPath, err)
	}
	var catalog publicDetectionCatalog
	if err := json.Unmarshal(content, &catalog); err != nil {
		return publicDetectionCatalog{}, fmt.Errorf("decode %s: %w", publicDetectionCatalogPath, err)
	}
	sort.Slice(catalog.Detections, func(i, j int) bool {
		return catalog.Detections[i].ID < catalog.Detections[j].ID
	})
	return catalog, nil
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

type controlRef struct {
	Framework string
	ControlID string
	Family    string
}

func (ref controlRef) Label() string {
	return strings.TrimSpace(ref.Framework + " " + ref.ControlID)
}

type resolvedFindingAuditDepth struct {
	EvidenceType      string
	AssessmentMethods []string
	AuditorGuidance   string
	RiskStatement     string
	RemediationIntent string
	Domain            string
	FieldSources      []string
	fieldSources      map[string]string
}

type findingComplianceReview struct {
	SourceMatchedControlRefs       []controlRef
	SourceBackedControlRefs        []controlRef
	ControlRefsWithoutSourceMatch  []controlRef
	SourceCoverageSupportLevels    []string
	SourceCoverageHighValueCount   int
	ComplianceEvidenceStatus       string
	SourceCoverageRefsByControlKey map[string][]string
}

func policyControlRefs(rule findingdsl.PolicyFindingRule, index controlFamilyIndex) []controlRef {
	var refs []controlRef
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
			refs = append(refs, controlRef{
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

func findingReviewRows(catalog publicDetectionCatalog, index controlFamilyIndex, extensions policyRuleExtensions) ([][]string, [][]string, [][]string, [][]string, [][]string, findingExportSummary) {
	var findingRows [][]string
	var findingControlRows [][]string
	var findingTagRows [][]string
	var sourceCoverageRows [][]string
	var findingComplianceRows [][]string
	summary := findingExportSummary{
		FindingCount:    len(catalog.Detections),
		Packs:           map[string]int{},
		Sources:         map[string]int{},
		EvaluationModes: map[string]int{},
		Frameworks:      map[string]int{},
		AuditDomains:    map[string]int{},
	}
	uniqueReviewTags := map[string]struct{}{}

	for _, detection := range catalog.Detections {
		controlRefs := publicDetectionControlRefs(detection.ControlRefs, index)
		controlFamilies := uniqueControlFamilies(controlRefs)
		catalogTags := uniqueSorted(detection.Tags)
		complianceTags := complianceReviewTags(controlRefs)
		allReviewTags := uniqueSorted(append(append([]string{}, catalogTags...), complianceTags...))
		sourceCoverageRefs := sourceCoverageRefLabels(detection.SourceCoverageRefs)
		auditDepth := resolveFindingAuditDepth(detection, extensions)
		complianceReview := findingComplianceReviewFor(detection, index, controlRefs)
		reviewFlags := findingReviewFlags(controlRefs, catalogTags, sourceCoverageRefs, auditDepth, complianceReview)

		summary.Packs[strings.TrimSpace(detection.PackID)]++
		summary.Sources[strings.TrimSpace(detection.SourceID)]++
		summary.EvaluationModes[strings.TrimSpace(detection.EvaluationMode)]++
		summary.AuditDomains[firstNonEmpty(auditDepth.Domain, "unresolved")]++
		if strings.TrimSpace(detection.PackID) != "policy" {
			summary.NonPolicyFindingCount++
		}
		if len(catalogTags) == 0 {
			summary.MissingCatalogTagCount++
		}
		if len(controlRefs) == 0 {
			summary.MissingControlRefCount++
		}
		if len(findingAuditDepthFlags(auditDepth)) != 0 {
			summary.MissingAuditDepthCount++
		}
		if len(sourceCoverageRefs) == 0 {
			summary.MissingSourceCoverageRefCount++
		}
		switch complianceReview.ComplianceEvidenceStatus {
		case "source_backed":
			summary.SourceBackedFindingCount++
		case "partial_source_backed":
			summary.PartialSourceBackedCount++
		case "control_only":
			summary.ControlOnlyFindingCount++
		}
		for _, ref := range controlRefs {
			summary.Frameworks[ref.Framework]++
		}
		for _, tag := range allReviewTags {
			uniqueReviewTags[tag] = struct{}{}
		}

		findingRows = append(findingRows, []string{
			detection.ID,
			detection.Name,
			detection.PackID,
			detection.PackName,
			detection.SourceID,
			detection.EvaluationMode,
			detection.OutputKind,
			normalizedSeverity(detection.Severity),
			detection.Status,
			detection.Maturity,
			auditDepth.Domain,
			joinList(auditDepth.FieldSources),
			joinList(controlFrameworkNames(controlRefs)),
			joinList(controlRefLabels(controlRefs)),
			joinList(controlFamilies),
			joinList(catalogTags),
			joinList(complianceTags),
			joinList(allReviewTags),
			auditDepth.EvidenceType,
			joinList(auditDepth.AssessmentMethods),
			auditDepth.AuditorGuidance,
			auditDepth.RiskStatement,
			auditDepth.RemediationIntent,
			fmt.Sprint(len(detection.SourceCoverageRefs)),
			joinList(sourceCoverageRefs),
			joinList(sourceCoverageEvidenceTypes(detection.SourceCoverageRefs)),
			joinList(sourceCoverageControlDomains(detection.SourceCoverageRefs)),
			joinList(controlRefLabels(complianceReview.SourceMatchedControlRefs)),
			joinList(controlRefLabels(complianceReview.SourceBackedControlRefs)),
			joinList(controlRefLabels(complianceReview.ControlRefsWithoutSourceMatch)),
			joinList(complianceReview.SourceCoverageSupportLevels),
			fmt.Sprint(complianceReview.SourceCoverageHighValueCount),
			complianceReview.ComplianceEvidenceStatus,
			joinList(reviewFlags),
		})

		for _, ref := range controlRefs {
			sourceCoverageLabels := complianceReview.SourceCoverageRefsByControlKey[controlRefKey(ref)]
			matchSource := "finding_control_ref"
			if len(sourceCoverageLabels) != 0 {
				matchSource = "finding_control_ref+source_coverage_ref"
			}
			findingControlRows = append(findingControlRows, []string{
				ref.Framework,
				ref.ControlID,
				ref.Label(),
				ref.Family,
				matchSource,
				joinList(sourceCoverageLabels),
				detection.ID,
				detection.Name,
				detection.PackID,
				detection.SourceID,
				detection.EvaluationMode,
				normalizedSeverity(detection.Severity),
				detection.Status,
				detection.Maturity,
			})
		}

		catalogTagSet := stringSet(catalogTags)
		complianceTagSet := stringSet(complianceTags)
		for _, tag := range allReviewTags {
			source := "catalog"
			_, catalogTag := catalogTagSet[tag]
			_, complianceTag := complianceTagSet[tag]
			switch {
			case catalogTag && complianceTag:
				source = "catalog+control_ref"
			case complianceTag:
				source = "control_ref"
			}
			findingTagRows = append(findingTagRows, []string{
				tag,
				tagKind(tag),
				source,
				detection.ID,
				detection.Name,
				detection.PackID,
				detection.SourceID,
				detection.EvaluationMode,
				normalizedSeverity(detection.Severity),
				detection.Status,
				detection.Maturity,
			})
		}

		for _, coverageRef := range detection.SourceCoverageRefs {
			matchedControlRefs := publicDetectionControlRefs(coverageRef.MatchedControlRefs, index)
			matchedFindingControlRefs := intersectControlRefs(matchedControlRefs, controlRefs)
			sourceOnlyControlRefs := differenceControlRefs(matchedControlRefs, controlRefs)
			sourceCoverageRows = append(sourceCoverageRows, []string{
				coverageRef.SourceID,
				coverageRef.DimensionID,
				coverageRef.DimensionType,
				coverageRef.SupportLevel,
				fmt.Sprint(coverageRef.HighValue),
				joinList(coverageRef.Families),
				joinList(coverageRef.EvidenceTypes),
				joinList(coverageRef.ControlDomains),
				joinList(controlRefLabels(matchedControlRefs)),
				joinList(uniqueControlFamilies(matchedControlRefs)),
				sourceCoverageMatchStatus(matchedControlRefs, matchedFindingControlRefs, sourceOnlyControlRefs),
				joinList(controlRefLabels(matchedFindingControlRefs)),
				joinList(controlRefLabels(sourceOnlyControlRefs)),
				detection.ID,
				detection.Name,
				detection.PackID,
				detection.SourceID,
				detection.EvaluationMode,
				normalizedSeverity(detection.Severity),
				detection.Status,
				detection.Maturity,
			})
		}

		findingComplianceRows = append(findingComplianceRows, []string{
			detection.ID,
			detection.Name,
			detection.PackID,
			detection.SourceID,
			detection.EvaluationMode,
			normalizedSeverity(detection.Severity),
			detection.Status,
			detection.Maturity,
			auditDepth.Domain,
			joinList(auditDepth.FieldSources),
			auditDepth.EvidenceType,
			joinList(auditDepth.AssessmentMethods),
			fmt.Sprint(len(controlRefs)),
			fmt.Sprint(len(complianceReview.SourceMatchedControlRefs)),
			fmt.Sprint(len(complianceReview.SourceBackedControlRefs)),
			fmt.Sprint(len(complianceReview.ControlRefsWithoutSourceMatch)),
			joinList(controlRefLabels(complianceReview.ControlRefsWithoutSourceMatch)),
			fmt.Sprint(len(detection.SourceCoverageRefs)),
			joinList(complianceReview.SourceCoverageSupportLevels),
			fmt.Sprint(complianceReview.SourceCoverageHighValueCount),
			complianceReview.ComplianceEvidenceStatus,
			joinList(reviewFlags),
		})
	}

	summary.ControlRowCount = len(findingControlRows)
	summary.TagRowCount = len(findingTagRows)
	summary.SourceCoverageRowCount = len(sourceCoverageRows)
	summary.ComplianceReviewRowCount = len(findingComplianceRows)
	summary.UniqueReviewTagCount = len(uniqueReviewTags)

	sortRows(findingRows)
	sortRows(findingControlRows)
	sortRows(findingTagRows)
	sortRows(sourceCoverageRows)
	sortRows(findingComplianceRows)
	return findingRows, findingControlRows, findingTagRows, sourceCoverageRows, findingComplianceRows, summary
}

func publicDetectionControlRefs(raw []publicDetectionControlRef, index controlFamilyIndex) []controlRef {
	var refs []controlRef
	seen := map[string]struct{}{}
	for _, item := range raw {
		frameworkName := strings.TrimSpace(item.FrameworkName)
		controlID := strings.TrimSpace(item.ControlID)
		if frameworkName == "" || controlID == "" {
			continue
		}
		key := frameworkName + "\x00" + controlID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, controlRef{
			Framework: frameworkName,
			ControlID: controlID,
			Family:    index[key],
		})
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Framework == refs[j].Framework {
			return refs[i].ControlID < refs[j].ControlID
		}
		return refs[i].Framework < refs[j].Framework
	})
	return refs
}

func resolveFindingAuditDepth(detection publicDetection, extensions policyRuleExtensions) resolvedFindingAuditDepth {
	resolved := resolvedFindingAuditDepth{fieldSources: map[string]string{}}
	mergeResolvedFindingAuditDepth(&resolved, extensions.Defaults, "yaml:defaults")
	if mode := strings.TrimSpace(detection.EvaluationMode); mode != "" {
		mergeResolvedFindingAuditDepth(&resolved, extensions.EvidenceModes[mode], "yaml:evidence_mode:"+mode)
	}
	domain := resolveFindingAuditDomain(detection, extensions)
	if domain != "" {
		mergeResolvedFindingAuditDepth(&resolved, extensions.Domains[domain], "yaml:domain:"+domain)
	}
	if extension, ok := lookupPolicyExtension(extensions.Findings, detection.ID); ok {
		mergeResolvedFindingAuditDepth(&resolved, extension, "yaml:finding:"+detection.ID)
	}
	mergeResolvedFindingAuditDepth(&resolved, policyRuleExtension{
		EvidenceType:      detection.EvidenceType,
		AssessmentMethods: detection.AssessmentMethods,
		AuditorGuidance:   detection.AuditorGuidance,
		RiskStatement:     detection.RiskStatement,
		RemediationIntent: detection.RemediationIntent,
	}, "catalog")
	resolved.Domain = domain
	for _, source := range resolved.fieldSources {
		resolved.FieldSources = append(resolved.FieldSources, source)
	}
	resolved.FieldSources = uniqueSorted(resolved.FieldSources)
	return resolved
}

func mergeResolvedFindingAuditDepth(resolved *resolvedFindingAuditDepth, next policyRuleExtension, source string) {
	if resolved == nil {
		return
	}
	if resolved.fieldSources == nil {
		resolved.fieldSources = map[string]string{}
	}
	if value := strings.TrimSpace(next.EvidenceType); value != "" {
		resolved.EvidenceType = value
		resolved.fieldSources["evidence_type"] = source
	}
	if values := uniqueSorted(next.AssessmentMethods); len(values) != 0 {
		resolved.AssessmentMethods = values
		resolved.fieldSources["assessment_methods"] = source
	}
	if value := strings.TrimSpace(next.AuditorGuidance); value != "" {
		resolved.AuditorGuidance = value
		resolved.fieldSources["auditor_guidance"] = source
	}
	if value := strings.TrimSpace(next.RiskStatement); value != "" {
		resolved.RiskStatement = value
		resolved.fieldSources["risk_statement"] = source
	}
	if value := strings.TrimSpace(next.RemediationIntent); value != "" {
		resolved.RemediationIntent = value
		resolved.fieldSources["remediation_intent"] = source
	}
}

func resolveFindingAuditDomain(detection publicDetection, extensions policyRuleExtensions) string {
	if domain := lookupDomainAlias(extensions.FindingDomains.Findings, detection.ID, extensions); domain != "" {
		return domain
	}
	if domain := lookupDomainAlias(extensions.FindingDomains.Packs, detection.PackID, extensions); domain != "" {
		return domain
	}
	if domain := lookupDomainAlias(extensions.FindingDomains.Sources, detection.SourceID, extensions); domain != "" {
		return domain
	}
	for _, tag := range uniqueSorted(detection.Tags) {
		if domain := lookupDomainAlias(extensions.FindingDomains.Tags, tag, extensions); domain != "" {
			return domain
		}
	}
	for _, candidate := range []string{detection.PackID, detection.SourceID} {
		if domain := existingAuditDomain(candidate, extensions); domain != "" {
			return domain
		}
	}
	for _, tag := range uniqueSorted(detection.Tags) {
		if domain := existingAuditDomain(tag, extensions); domain != "" {
			return domain
		}
	}
	return ""
}

func lookupDomainAlias(aliases map[string]string, key string, extensions policyRuleExtensions) string {
	value, ok := lookupStringMap(aliases, key)
	if !ok {
		return ""
	}
	return existingAuditDomain(value, extensions)
}

func existingAuditDomain(value string, extensions policyRuleExtensions) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for domain := range extensions.Domains {
		if strings.EqualFold(strings.TrimSpace(domain), value) {
			return strings.TrimSpace(domain)
		}
	}
	return ""
}

func lookupPolicyExtension(extensions map[string]policyRuleExtension, key string) (policyRuleExtension, bool) {
	if len(extensions) == 0 {
		return policyRuleExtension{}, false
	}
	for candidate, extension := range extensions {
		if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(key)) {
			return extension, true
		}
	}
	return policyRuleExtension{}, false
}

func lookupStringMap(values map[string]string, key string) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	key = strings.TrimSpace(key)
	for candidate, value := range values {
		if strings.EqualFold(strings.TrimSpace(candidate), key) {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

func findingComplianceReviewFor(detection publicDetection, index controlFamilyIndex, directControlRefs []controlRef) findingComplianceReview {
	sourceMatchedControlRefs := sourceCoverageMatchedControlRefs(detection.SourceCoverageRefs, index)
	sourceBackedControlRefs := intersectControlRefs(directControlRefs, sourceMatchedControlRefs)
	controlRefsWithoutSourceMatch := differenceControlRefs(directControlRefs, sourceMatchedControlRefs)
	refsByControlKey := sourceCoverageRefsByControlKey(detection.SourceCoverageRefs, index)
	return findingComplianceReview{
		SourceMatchedControlRefs:       sourceMatchedControlRefs,
		SourceBackedControlRefs:        sourceBackedControlRefs,
		ControlRefsWithoutSourceMatch:  controlRefsWithoutSourceMatch,
		SourceCoverageSupportLevels:    sourceCoverageSupportLevels(detection.SourceCoverageRefs),
		SourceCoverageHighValueCount:   sourceCoverageHighValueCount(detection.SourceCoverageRefs),
		ComplianceEvidenceStatus:       complianceEvidenceStatus(directControlRefs, sourceMatchedControlRefs, controlRefsWithoutSourceMatch),
		SourceCoverageRefsByControlKey: refsByControlKey,
	}
}

func sourceCoverageMatchedControlRefs(refs []publicDetectionSourceCoverageRef, index controlFamilyIndex) []controlRef {
	var values []controlRef
	for _, ref := range refs {
		values = append(values, publicDetectionControlRefs(ref.MatchedControlRefs, index)...)
	}
	return uniqueControlRefs(values)
}

func sourceCoverageRefsByControlKey(refs []publicDetectionSourceCoverageRef, index controlFamilyIndex) map[string][]string {
	values := map[string][]string{}
	for _, coverageRef := range refs {
		label := sourceCoverageRefLabel(coverageRef)
		if label == "" {
			continue
		}
		for _, ref := range publicDetectionControlRefs(coverageRef.MatchedControlRefs, index) {
			key := controlRefKey(ref)
			values[key] = append(values[key], label)
		}
	}
	for key, labels := range values {
		values[key] = uniqueSorted(labels)
	}
	return values
}

func sourceCoverageSupportLevels(refs []publicDetectionSourceCoverageRef) []string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		if value := strings.TrimSpace(ref.SupportLevel); value != "" {
			values = append(values, value)
		}
	}
	return uniqueSorted(values)
}

func sourceCoverageHighValueCount(refs []publicDetectionSourceCoverageRef) int {
	count := 0
	for _, ref := range refs {
		if ref.HighValue {
			count++
		}
	}
	return count
}

func complianceEvidenceStatus(directControlRefs []controlRef, sourceMatchedControlRefs []controlRef, controlRefsWithoutSourceMatch []controlRef) string {
	switch {
	case len(directControlRefs) == 0 && len(sourceMatchedControlRefs) == 0:
		return "missing_controls"
	case len(directControlRefs) == 0:
		return "source_only"
	case len(sourceMatchedControlRefs) == 0:
		return "control_only"
	case len(controlRefsWithoutSourceMatch) == 0:
		return "source_backed"
	default:
		return "partial_source_backed"
	}
}

func sourceCoverageMatchStatus(matchedControlRefs []controlRef, matchedFindingControlRefs []controlRef, sourceOnlyControlRefs []controlRef) string {
	switch {
	case len(matchedControlRefs) == 0:
		return "no_matched_control_refs"
	case len(sourceOnlyControlRefs) == 0:
		return "matched_to_finding_control_refs"
	case len(matchedFindingControlRefs) == 0:
		return "source_only_control_refs"
	default:
		return "partial_finding_control_match"
	}
}

func uniqueControlRefs(refs []controlRef) []controlRef {
	seen := map[string]struct{}{}
	values := make([]controlRef, 0, len(refs))
	for _, ref := range refs {
		if strings.TrimSpace(ref.Framework) == "" || strings.TrimSpace(ref.ControlID) == "" {
			continue
		}
		key := controlRefKey(ref)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		values = append(values, ref)
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Framework == values[j].Framework {
			return values[i].ControlID < values[j].ControlID
		}
		return values[i].Framework < values[j].Framework
	})
	return values
}

func intersectControlRefs(left []controlRef, right []controlRef) []controlRef {
	rightSet := controlRefSet(right)
	var values []controlRef
	for _, ref := range left {
		if _, ok := rightSet[controlRefKey(ref)]; ok {
			values = append(values, ref)
		}
	}
	return uniqueControlRefs(values)
}

func differenceControlRefs(left []controlRef, right []controlRef) []controlRef {
	rightSet := controlRefSet(right)
	var values []controlRef
	for _, ref := range left {
		if _, ok := rightSet[controlRefKey(ref)]; !ok {
			values = append(values, ref)
		}
	}
	return uniqueControlRefs(values)
}

func controlRefSet(refs []controlRef) map[string]struct{} {
	values := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		values[controlRefKey(ref)] = struct{}{}
	}
	return values
}

func controlRefKey(ref controlRef) string {
	return strings.TrimSpace(ref.Framework) + "\x00" + strings.TrimSpace(ref.ControlID)
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

func controlRefLabels(refs []controlRef) []string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		values = append(values, ref.Label())
	}
	return uniqueSorted(values)
}

func uniqueControlFamilies(refs []controlRef) []string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		if family := strings.TrimSpace(ref.Family); family != "" {
			values = append(values, family)
		}
	}
	return uniqueSorted(values)
}

func controlFrameworkNames(refs []controlRef) []string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		if framework := strings.TrimSpace(ref.Framework); framework != "" {
			values = append(values, framework)
		}
	}
	return uniqueSorted(values)
}

func complianceReviewTags(refs []controlRef) []string {
	values := make([]string, 0, len(refs)*3)
	for _, ref := range refs {
		frameworkSlug := tagSlug(ref.Framework)
		controlSlug := tagSlug(ref.ControlID)
		if frameworkSlug != "" {
			values = append(values, "framework:"+frameworkSlug)
		}
		if frameworkSlug != "" && controlSlug != "" {
			values = append(values, "control:"+frameworkSlug+":"+controlSlug)
		}
		if familySlug := tagSlug(ref.Family); familySlug != "" {
			values = append(values, "control-family:"+familySlug)
		}
	}
	return uniqueSorted(values)
}

func tagSlug(value string) string {
	var builder strings.Builder
	previousDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			builder.WriteRune(r)
			previousDash = false
		default:
			if builder.Len() != 0 && !previousDash {
				builder.WriteByte('-')
				previousDash = true
			}
		}
	}
	return strings.Trim(builder.String(), "-")
}

func sourceCoverageRefLabels(refs []publicDetectionSourceCoverageRef) []string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		if label := sourceCoverageRefLabel(ref); label != "" {
			values = append(values, label)
		}
	}
	return uniqueSorted(values)
}

func sourceCoverageRefLabel(ref publicDetectionSourceCoverageRef) string {
	sourceID := strings.TrimSpace(ref.SourceID)
	dimensionID := strings.TrimSpace(ref.DimensionID)
	switch {
	case sourceID != "" && dimensionID != "":
		return sourceID + "/" + dimensionID
	case sourceID != "":
		return sourceID
	case dimensionID != "":
		return dimensionID
	default:
		return ""
	}
}

func sourceCoverageEvidenceTypes(refs []publicDetectionSourceCoverageRef) []string {
	var values []string
	for _, ref := range refs {
		values = append(values, ref.EvidenceTypes...)
	}
	return uniqueSorted(values)
}

func sourceCoverageControlDomains(refs []publicDetectionSourceCoverageRef) []string {
	var values []string
	for _, ref := range refs {
		values = append(values, ref.ControlDomains...)
	}
	return uniqueSorted(values)
}

func findingReviewFlags(controlRefs []controlRef, catalogTags []string, sourceCoverageRefs []string, auditDepth resolvedFindingAuditDepth, complianceReview findingComplianceReview) []string {
	flags := []string{}
	if len(catalogTags) == 0 {
		flags = append(flags, "missing_catalog_tags")
	}
	if len(controlRefs) == 0 {
		flags = append(flags, "missing_control_refs")
	}
	flags = append(flags, findingAuditDepthFlags(auditDepth)...)
	if strings.TrimSpace(auditDepth.Domain) == "" {
		flags = append(flags, "unresolved_audit_domain")
	}
	if len(sourceCoverageRefs) == 0 {
		flags = append(flags, "missing_source_coverage_refs")
	}
	switch complianceReview.ComplianceEvidenceStatus {
	case "control_only":
		flags = append(flags, "control_refs_not_source_backed")
	case "partial_source_backed":
		flags = append(flags, "partial_source_backed_control_refs")
	case "source_only":
		flags = append(flags, "source_only_control_refs")
	}
	return uniqueSorted(flags)
}

func findingAuditDepthFlags(depth resolvedFindingAuditDepth) []string {
	flags := []string{}
	if strings.TrimSpace(depth.EvidenceType) == "" {
		flags = append(flags, "missing_evidence_type")
	}
	if len(uniqueSorted(depth.AssessmentMethods)) == 0 {
		flags = append(flags, "missing_assessment_methods")
	}
	if strings.TrimSpace(depth.AuditorGuidance) == "" {
		flags = append(flags, "missing_auditor_guidance")
	}
	if strings.TrimSpace(depth.RiskStatement) == "" {
		flags = append(flags, "missing_risk_statement")
	}
	if strings.TrimSpace(depth.RemediationIntent) == "" {
		flags = append(flags, "missing_remediation_intent")
	}
	return uniqueSorted(flags)
}

func normalizedSeverity(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func sortRows(rows [][]string) {
	sort.Slice(rows, func(i, j int) bool {
		return strings.Join(rows[i], "\x00") < strings.Join(rows[j], "\x00")
	})
}

func overviewRows(policyCount int, controlCount int, tagCount int, uniqueTagCount int, domains map[string]int, frameworks map[string]int, evidenceModes map[string]int, findingSummary findingExportSummary) [][]string {
	rows := [][]string{
		{"metric", "value"},
		{"policy finding rules", fmt.Sprint(policyCount)},
		{"policy-control rows", fmt.Sprint(controlCount)},
		{"tag rows", fmt.Sprint(tagCount)},
		{"unique tags", fmt.Sprint(uniqueTagCount)},
		{"domains", fmt.Sprint(len(domains))},
		{"frameworks", fmt.Sprint(len(frameworks))},
		{},
		{"all finding metric", "value"},
		{"public detections", fmt.Sprint(findingSummary.FindingCount)},
		{"non-policy detections", fmt.Sprint(findingSummary.NonPolicyFindingCount)},
		{"finding-control rows", fmt.Sprint(findingSummary.ControlRowCount)},
		{"finding-tag rows", fmt.Sprint(findingSummary.TagRowCount)},
		{"source-coverage rows", fmt.Sprint(findingSummary.SourceCoverageRowCount)},
		{"finding compliance review rows", fmt.Sprint(findingSummary.ComplianceReviewRowCount)},
		{"unique finding review tags", fmt.Sprint(findingSummary.UniqueReviewTagCount)},
		{"detections missing catalog tags", fmt.Sprint(findingSummary.MissingCatalogTagCount)},
		{"detections missing control refs", fmt.Sprint(findingSummary.MissingControlRefCount)},
		{"detections missing audit depth", fmt.Sprint(findingSummary.MissingAuditDepthCount)},
		{"detections missing source coverage refs", fmt.Sprint(findingSummary.MissingSourceCoverageRefCount)},
		{"detections source-backed", fmt.Sprint(findingSummary.SourceBackedFindingCount)},
		{"detections partial source-backed", fmt.Sprint(findingSummary.PartialSourceBackedCount)},
		{"detections control-only", fmt.Sprint(findingSummary.ControlOnlyFindingCount)},
		{},
		{"evidence mode", "rules"},
	}
	rows = appendCountRows(rows, evidenceModes)
	rows = append(rows, []string{}, []string{"domain", "rules"})
	rows = appendCountRows(rows, domains)
	rows = append(rows, []string{}, []string{"framework", "rules"})
	rows = appendCountRows(rows, frameworks)
	rows = append(rows, []string{}, []string{"finding evaluation mode", "detections"})
	rows = appendCountRows(rows, findingSummary.EvaluationModes)
	rows = append(rows, []string{}, []string{"finding pack", "detections"})
	rows = appendCountRows(rows, findingSummary.Packs)
	rows = append(rows, []string{}, []string{"finding source", "detections"})
	rows = appendCountRows(rows, findingSummary.Sources)
	rows = append(rows, []string{}, []string{"finding framework", "control rows"})
	rows = appendCountRows(rows, findingSummary.Frameworks)
	rows = append(rows, []string{}, []string{"finding audit domain", "detections"})
	rows = appendCountRows(rows, findingSummary.AuditDomains)
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
	for _, key := range sortedKeys(extensions.Findings) {
		rows = append(rows, extensionRow("finding", key, extensions.Findings[key]))
	}
	return rows
}

func findingDomainAliasRows(extensions policyRuleExtensions) [][]string {
	var rows [][]string
	rows = appendFindingDomainAliasRows(rows, "finding", extensions.FindingDomains.Findings)
	rows = appendFindingDomainAliasRows(rows, "pack", extensions.FindingDomains.Packs)
	rows = appendFindingDomainAliasRows(rows, "source", extensions.FindingDomains.Sources)
	rows = appendFindingDomainAliasRows(rows, "tag", extensions.FindingDomains.Tags)
	sortRows(rows)
	return rows
}

func appendFindingDomainAliasRows(rows [][]string, matchType string, aliases map[string]string) [][]string {
	for _, key := range sortedKeys(aliases) {
		rows = append(rows, []string{matchType, key, strings.TrimSpace(aliases[key])})
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
		{"2", "evidence mode", "Apply mode-specific defaults for cel, query, graph, manual, or event detections."},
		{"3", "policy domain", "Apply the domain block keyed by the policy folder under policies/ for policy rules."},
		{"4", "finding domain aliases", "Resolve non-policy detections to YAML domains by finding ID, pack, source, or tag."},
		{"5", "policy or finding override", "Apply any explicit policy ID or finding ID override when a rule needs different audit language."},
		{"6", "source catalog fields", "Use policy YAML and public detection catalog fields as the strongest direct source for controls, tags, severity, evidence, and audit language."},
		{"7", "source coverage reconciliation", "Compare finding control_refs with source coverage matched_control_refs so direct, source-backed, and control-only mappings are visible."},
		{"8", "compliance review tags", "Derive framework:, control:, and control-family: tags from control_refs for spreadsheet review. These do not replace runtime finding tags."},
		{"9", "spreadsheet", "Generate CSV rows from YAML, the public catalog, and derived review layers. Do not edit spreadsheet rows back into source by hand."},
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

func findingMapHeader() []string {
	return []string{
		"finding_id", "name", "pack_id", "pack_name", "source_id", "evaluation_mode", "output_kind",
		"severity", "status", "maturity", "resolved_audit_domain", "audit_language_source",
		"frameworks", "control_refs", "control_families",
		"catalog_tags", "compliance_review_tags", "all_review_tags", "evidence_type",
		"assessment_methods", "auditor_guidance", "risk_statement", "remediation_intent",
		"source_coverage_ref_count", "source_coverage_refs", "coverage_evidence_types",
		"coverage_control_domains", "source_matched_control_refs", "source_backed_control_refs",
		"control_refs_without_source_match", "source_coverage_support_levels",
		"source_coverage_high_value_count", "compliance_evidence_status", "review_flags",
	}
}

func findingControlMapHeader() []string {
	return []string{
		"framework", "control_id", "control_ref", "control_family", "control_match_source",
		"source_coverage_refs", "finding_id", "name", "pack_id", "source_id", "evaluation_mode",
		"severity", "status", "maturity",
	}
}

func findingTagMapHeader() []string {
	return []string{"tag", "tag_kind", "tag_source", "finding_id", "name", "pack_id", "source_id", "evaluation_mode", "severity", "status", "maturity"}
}

func sourceCoverageMapHeader() []string {
	return []string{
		"coverage_source_id", "coverage_dimension_id", "coverage_dimension_type", "support_level",
		"high_value", "families", "evidence_types", "control_domains", "matched_control_refs",
		"matched_control_families", "finding_control_match_status", "matched_finding_control_refs",
		"source_only_control_refs", "finding_id", "name", "pack_id", "finding_source_id",
		"evaluation_mode", "severity", "status", "maturity",
	}
}

func findingComplianceReviewMapHeader() []string {
	return []string{
		"finding_id", "name", "pack_id", "source_id", "evaluation_mode", "severity", "status",
		"maturity", "resolved_audit_domain", "audit_language_source", "evidence_type",
		"assessment_methods", "control_ref_count", "source_matched_control_ref_count",
		"source_backed_control_ref_count", "control_refs_without_source_match_count",
		"control_refs_without_source_match", "source_coverage_ref_count",
		"source_coverage_support_levels", "source_coverage_high_value_count",
		"compliance_evidence_status", "review_flags",
	}
}

func findingDomainAliasesHeader() []string {
	return []string{"match_type", "match_value", "resolved_domain"}
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
	case strings.HasPrefix(normalized, "framework:") || strings.HasPrefix(normalized, "control:") || strings.HasPrefix(normalized, "control-family:"):
		return "compliance"
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
