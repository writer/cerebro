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
	"unicode/utf8"

	"github.com/writer/cerebro/internal/findingdsl"
	"gopkg.in/yaml.v3"
)

const defaultOutputDir = "docs/reference/policy-compliance-mapping"
const policyRuleExtensionsPath = "internal/compliance/policy_rule_extensions.yaml"
const controlFamiliesPath = "internal/compliance/control_families.yaml"
const frameworkReviewAreasPath = "internal/compliance/framework_review_areas.yaml"
const controlRelationshipsPath = "internal/compliance/control_relationships.yaml"
const evidenceCapabilitiesPath = "internal/compliance/evidence_capabilities.yaml"
const controlEvidenceRequirementsPath = "internal/compliance/control_evidence_requirements.yaml"
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

type frameworkReviewAreaCatalog struct {
	ReviewAreas []frameworkReviewArea `yaml:"review_areas"`
}

type frameworkReviewArea struct {
	Framework   string   `yaml:"framework"`
	AreaID      string   `yaml:"area_id"`
	Name        string   `yaml:"name"`
	EvidenceUse string   `yaml:"evidence_use"`
	Purpose     string   `yaml:"purpose"`
	ControlRefs []string `yaml:"control_refs"`
}

type controlRelationshipCatalog struct {
	Relationships []controlRelationship `yaml:"relationships"`
}

type controlRelationship struct {
	Framework       string                       `yaml:"framework"`
	ControlID       string                       `yaml:"control_id"`
	RelatedControls []relatedControlRelationship `yaml:"related_controls"`
}

type relatedControlRelationship struct {
	Framework    string `yaml:"framework"`
	ControlID    string `yaml:"control_id"`
	Relationship string `yaml:"relationship"`
	EvidenceUse  string `yaml:"evidence_use"`
	Rationale    string `yaml:"rationale"`
}

type evidenceCapabilityCatalog struct {
	Sources []evidenceCapabilitySource `yaml:"sources"`
}

type evidenceCapabilitySource struct {
	SourceID   string                        `yaml:"source_id"`
	Name       string                        `yaml:"name"`
	Purpose    string                        `yaml:"purpose"`
	Dimensions []evidenceCapabilityDimension `yaml:"dimensions"`
}

type evidenceCapabilityDimension struct {
	DimensionID    string           `yaml:"dimension_id"`
	DimensionType  string           `yaml:"dimension_type"`
	SupportLevel   string           `yaml:"support_level"`
	HighValue      bool             `yaml:"high_value"`
	Families       []string         `yaml:"families"`
	EvidenceTypes  []string         `yaml:"evidence_types"`
	ControlDomains []string         `yaml:"control_domains"`
	ControlRefs    []yamlControlRef `yaml:"control_refs"`
}

type controlEvidenceRequirementCatalog struct {
	Defaults controlEvidenceRequirementDefaults  `yaml:"defaults"`
	Profiles []controlEvidenceRequirementProfile `yaml:"profiles"`
}

type controlEvidenceRequirementDefaults struct {
	SourceID             string   `yaml:"source_id"`
	EntityType           string   `yaml:"entity_type"`
	RequiredFields       []string `yaml:"required_fields"`
	FreshnessWindow      string   `yaml:"freshness_window"`
	AssessmentMethods    []string `yaml:"assessment_methods"`
	AuditorGradeEvidence string   `yaml:"auditor_grade_evidence"`
}

type controlEvidenceRequirementProfile struct {
	ProfileID          string                             `yaml:"profile_id"`
	Name               string                             `yaml:"name"`
	Fallback           bool                               `yaml:"fallback"`
	AppliesTo          controlEvidenceRequirementSelector `yaml:"applies_to"`
	SourceRequirements []controlEvidenceSourceRequirement `yaml:"source_requirements"`
}

type controlEvidenceRequirementSelector struct {
	Frameworks        []string `yaml:"frameworks"`
	FamilyKeywords    []string `yaml:"family_keywords"`
	ControlIDPrefixes []string `yaml:"control_id_prefixes"`
}

type controlEvidenceSourceRequirement struct {
	SourceID             string   `yaml:"source_id"`
	EntityType           string   `yaml:"entity_type"`
	RequiredFields       []string `yaml:"required_fields"`
	FreshnessWindow      string   `yaml:"freshness_window"`
	AssessmentMethods    []string `yaml:"assessment_methods"`
	AuditorGradeEvidence string   `yaml:"auditor_grade_evidence"`
}

type yamlControlRef struct {
	Framework string `yaml:"framework"`
	ControlID string `yaml:"control_id"`
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
	ID                   string                                 `yaml:"id"`
	Title                string                                 `yaml:"title"`
	EvidenceExpectations []complianceControlEvidenceExpectation `yaml:"evidence_expectations"`
	FreshnessSLA         string                                 `yaml:"freshness_sla"`
	AssessmentMethods    []string                               `yaml:"assessment_methods"`
}

type complianceControlEvidenceExpectation struct {
	ID                string   `yaml:"id"`
	Title             string   `yaml:"title"`
	Type              string   `yaml:"type"`
	Required          *bool    `yaml:"required"`
	AssessmentMethods []string `yaml:"assessment_methods"`
	FreshnessSLA      string   `yaml:"freshness_sla"`
	AcceptedFrom      []string `yaml:"accepted_from"`
}

type controlFamilyIndex map[string]controlFamilyEntry

type controlFamilyEntry struct {
	Ref    controlRef
	Family string
}

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
	controlCatalog, err := loadControlCatalog(root)
	if err != nil {
		return nil, err
	}
	controlFamilies := controlFamilyIndexFromCatalog(controlCatalog)
	reviewAreas, err := loadFrameworkReviewAreas(root)
	if err != nil {
		return nil, err
	}
	controlRelationships, err := loadControlRelationships(root)
	if err != nil {
		return nil, err
	}
	evidenceCapabilities, err := loadEvidenceCapabilities(root)
	if err != nil {
		return nil, err
	}
	controlEvidenceRequirements, err := loadControlEvidenceRequirements(root)
	if err != nil {
		return nil, err
	}
	if err := validateControlEvidenceRequirements(controlEvidenceRequirements); err != nil {
		return nil, err
	}
	if err := validateMappingCatalogs(controlFamilies, reviewAreas, controlRelationships, evidenceCapabilities); err != nil {
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

	findingRows, findingControlRows, findingTagRows, sourceCoverageRows, findingComplianceRows, qualityIssueRows, findingSummary := findingReviewRows(catalog, controlFamilies, extensions, reviewAreas, controlRelationships, evidenceCapabilities)
	reviewAreaRows := frameworkReviewAreaRows(reviewAreas, controlFamilies)
	relationshipRows := controlRelationshipRows(controlRelationships, controlFamilies)
	findingAreaRows := findingReviewAreaRows(catalog, controlFamilies, reviewAreas)
	findingRelationshipRows := findingControlRelationshipRows(catalog, controlFamilies, controlRelationships)
	evidenceCapabilityRows := evidenceCapabilityRows(evidenceCapabilities, controlFamilies)
	sourceCapabilityReviewRows := sourceCapabilityReviewRows(catalog, controlFamilies, evidenceCapabilities)
	frameworkControlEnrichmentRows := frameworkControlEnrichmentRows(catalog, controlFamilies, reviewAreas, controlRelationships, evidenceCapabilities)
	frameworkControlGapRows := frameworkControlGapRows(catalog, controlFamilies, reviewAreas, controlRelationships, evidenceCapabilities)
	controlRequirementItems := expandedControlEvidenceRequirements(controlCatalog, controlEvidenceRequirements, catalog, controlFamilies, reviewAreas, controlRelationships, evidenceCapabilities)
	controlRequirementRows := controlEvidenceRequirementRows(controlRequirementItems)
	findingRequirementRows := findingEvidenceRequirementRows(catalog, controlFamilies, evidenceCapabilities, controlRequirementItems)
	coverageCandidateRows := frameworkCoverageCandidateRows(catalog, controlFamilies, reviewAreas, controlRelationships, evidenceCapabilities, controlRequirementItems)
	if err := validateControlEvidenceRequirementCoverage(controlCatalogRefs(controlCatalog), controlRequirementItems); err != nil {
		return nil, err
	}
	if err := enforceComplianceQuality(qualityIssueRows, frameworkControlGapRows); err != nil {
		return nil, err
	}

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
		{Name: "compliance_quality_issues.csv", Content: csvBytes(append([][]string{complianceQualityIssuesHeader()}, qualityIssueRows...))},
		{Name: "finding_domain_aliases.csv", Content: csvBytes(append([][]string{findingDomainAliasesHeader()}, findingDomainAliasRows(extensions)...))},
		{Name: "framework_review_areas.csv", Content: csvBytes(append([][]string{frameworkReviewAreasHeader()}, reviewAreaRows...))},
		{Name: "control_relationships.csv", Content: csvBytes(append([][]string{controlRelationshipsHeader()}, relationshipRows...))},
		{Name: "finding_review_area_map.csv", Content: csvBytes(append([][]string{findingReviewAreaMapHeader()}, findingAreaRows...))},
		{Name: "finding_control_relationship_map.csv", Content: csvBytes(append([][]string{findingControlRelationshipMapHeader()}, findingRelationshipRows...))},
		{Name: "evidence_capabilities.csv", Content: csvBytes(append([][]string{evidenceCapabilitiesHeader()}, evidenceCapabilityRows...))},
		{Name: "source_capability_review_map.csv", Content: csvBytes(append([][]string{sourceCapabilityReviewMapHeader()}, sourceCapabilityReviewRows...))},
		{Name: "framework_control_enrichment_map.csv", Content: csvBytes(append([][]string{frameworkControlEnrichmentMapHeader()}, frameworkControlEnrichmentRows...))},
		{Name: "framework_control_gap_map.csv", Content: csvBytes(append([][]string{frameworkControlGapMapHeader()}, frameworkControlGapRows...))},
		{Name: "control_evidence_requirements.csv", Content: csvBytes(append([][]string{controlEvidenceRequirementsHeader()}, controlRequirementRows...))},
		{Name: "finding_evidence_requirement_map.csv", Content: csvBytes(append([][]string{findingEvidenceRequirementMapHeader()}, findingRequirementRows...))},
		{Name: "framework_coverage_candidates.csv", Content: csvBytes(append([][]string{frameworkCoverageCandidatesHeader()}, coverageCandidateRows...))},
		{Name: "workbook_manifest.csv", Content: csvBytes(workbookManifestRows())},
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

func loadFrameworkReviewAreas(root string) ([]frameworkReviewArea, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(frameworkReviewAreasPath)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", frameworkReviewAreasPath, err)
	}
	var catalog frameworkReviewAreaCatalog
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return nil, fmt.Errorf("decode %s: %w", frameworkReviewAreasPath, err)
	}
	return catalog.ReviewAreas, nil
}

func loadControlRelationships(root string) ([]controlRelationship, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(controlRelationshipsPath)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", controlRelationshipsPath, err)
	}
	var catalog controlRelationshipCatalog
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return nil, fmt.Errorf("decode %s: %w", controlRelationshipsPath, err)
	}
	return catalog.Relationships, nil
}

func loadEvidenceCapabilities(root string) ([]evidenceCapabilitySource, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(evidenceCapabilitiesPath)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", evidenceCapabilitiesPath, err)
	}
	var catalog evidenceCapabilityCatalog
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return nil, fmt.Errorf("decode %s: %w", evidenceCapabilitiesPath, err)
	}
	return catalog.Sources, nil
}

func loadControlEvidenceRequirements(root string) (controlEvidenceRequirementCatalog, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(controlEvidenceRequirementsPath)))
	if err != nil {
		return controlEvidenceRequirementCatalog{}, fmt.Errorf("read %s: %w", controlEvidenceRequirementsPath, err)
	}
	var catalog controlEvidenceRequirementCatalog
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return controlEvidenceRequirementCatalog{}, fmt.Errorf("decode %s: %w", controlEvidenceRequirementsPath, err)
	}
	return catalog, nil
}

func loadControlCatalog(root string) (complianceControlCatalog, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(controlFamiliesPath)))
	if err != nil {
		if os.IsNotExist(err) {
			return complianceControlCatalog{}, nil
		}
		return complianceControlCatalog{}, fmt.Errorf("read %s: %w", controlFamiliesPath, err)
	}
	var catalog complianceControlCatalog
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return complianceControlCatalog{}, fmt.Errorf("decode %s: %w", controlFamiliesPath, err)
	}
	return catalog, nil
}

func loadControlFamilyIndex(root string) (controlFamilyIndex, error) {
	catalog, err := loadControlCatalog(root)
	if err != nil {
		return nil, err
	}
	return controlFamilyIndexFromCatalog(catalog), nil
}

func controlFamilyIndexFromCatalog(catalog complianceControlCatalog) controlFamilyIndex {
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
					ref := controlRef{Framework: frameworkName, ControlID: controlID, Family: familyLabel}
					index[controlRefKey(ref)] = controlFamilyEntry{Ref: ref, Family: familyLabel}
				}
			}
		}
	}
	return index
}

func controlCatalogRefs(catalog complianceControlCatalog) []controlRef {
	var refs []controlRef
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
				if controlID == "" {
					continue
				}
				refs = append(refs, controlRef{
					Framework: frameworkName,
					ControlID: controlID,
					Family:    familyLabel,
					Title:     strings.TrimSpace(control.Title),
				})
			}
		}
	}
	return uniqueControlRefs(refs)
}

func controlFamilyForRef(index controlFamilyIndex, ref controlRef) string {
	return index[controlRefKey(ref)].Family
}

func validateMappingCatalogs(index controlFamilyIndex, reviewAreas []frameworkReviewArea, relationships []controlRelationship, capabilitySources []evidenceCapabilitySource) error {
	var issues []string
	areaKeys := map[string]struct{}{}
	for _, area := range reviewAreas {
		framework := strings.TrimSpace(area.Framework)
		areaID := strings.TrimSpace(area.AreaID)
		key := framework + "\x00" + areaID
		switch {
		case framework == "":
			issues = append(issues, frameworkReviewAreasPath+": review area missing framework")
		case areaID == "":
			issues = append(issues, frameworkReviewAreasPath+": review area for "+framework+" missing area_id")
		case strings.TrimSpace(area.Name) == "":
			issues = append(issues, frameworkReviewAreasPath+": review area "+framework+" "+areaID+" missing name")
		case strings.TrimSpace(area.EvidenceUse) == "":
			issues = append(issues, frameworkReviewAreasPath+": review area "+framework+" "+areaID+" missing evidence_use")
		case strings.TrimSpace(area.Purpose) == "":
			issues = append(issues, frameworkReviewAreasPath+": review area "+framework+" "+areaID+" missing purpose")
		case len(trimStrings(area.ControlRefs)) == 0:
			issues = append(issues, frameworkReviewAreasPath+": review area "+framework+" "+areaID+" missing control_refs")
		}
		if _, ok := areaKeys[key]; ok && framework != "" && areaID != "" {
			issues = append(issues, frameworkReviewAreasPath+": duplicate review area "+framework+" "+areaID)
		}
		areaKeys[key] = struct{}{}
		for _, ref := range frameworkReviewAreaControlRefs(area, index) {
			if !knownControlRef(index, ref) {
				issues = append(issues, frameworkReviewAreasPath+": review area "+framework+" "+areaID+" references unknown control "+ref.Label())
			}
		}
	}

	relationshipKeys := map[string]struct{}{}
	for _, item := range relationships {
		control := controlRef{Framework: strings.TrimSpace(item.Framework), ControlID: strings.TrimSpace(item.ControlID)}
		if control.Framework == "" || control.ControlID == "" {
			issues = append(issues, controlRelationshipsPath+": relationship missing framework or control_id")
			continue
		}
		if !knownControlRef(index, control) {
			issues = append(issues, controlRelationshipsPath+": relationship references unknown control "+control.Label())
		}
		if len(item.RelatedControls) == 0 {
			issues = append(issues, controlRelationshipsPath+": relationship "+control.Label()+" missing related_controls")
		}
		for _, related := range item.RelatedControls {
			relatedRef := controlRef{Framework: firstNonEmpty(related.Framework, control.Framework), ControlID: strings.TrimSpace(related.ControlID)}
			if relatedRef.Framework == "" || relatedRef.ControlID == "" {
				issues = append(issues, controlRelationshipsPath+": relationship "+control.Label()+" has related control missing framework or control_id")
				continue
			}
			if !knownControlRef(index, relatedRef) {
				issues = append(issues, controlRelationshipsPath+": relationship "+control.Label()+" references unknown related control "+relatedRef.Label())
			}
			if controlRefKey(control) == controlRefKey(relatedRef) {
				issues = append(issues, controlRelationshipsPath+": relationship "+control.Label()+" points to itself")
			}
			if strings.TrimSpace(related.Relationship) == "" {
				issues = append(issues, controlRelationshipsPath+": relationship "+control.Label()+" -> "+relatedRef.Label()+" missing relationship")
			}
			if strings.TrimSpace(related.EvidenceUse) == "" {
				issues = append(issues, controlRelationshipsPath+": relationship "+control.Label()+" -> "+relatedRef.Label()+" missing evidence_use")
			}
			if strings.TrimSpace(related.Rationale) == "" {
				issues = append(issues, controlRelationshipsPath+": relationship "+control.Label()+" -> "+relatedRef.Label()+" missing rationale")
			}
			key := strings.Join([]string{control.Framework, control.ControlID, relatedRef.Framework, relatedRef.ControlID, strings.TrimSpace(related.Relationship), strings.TrimSpace(related.EvidenceUse)}, "\x00")
			if _, ok := relationshipKeys[key]; ok {
				issues = append(issues, controlRelationshipsPath+": duplicate relationship "+control.Label()+" -> "+relatedRef.Label())
			}
			relationshipKeys[key] = struct{}{}
		}
	}

	capabilityKeys := map[string]struct{}{}
	for _, source := range capabilitySources {
		sourceID := strings.TrimSpace(source.SourceID)
		if sourceID == "" {
			issues = append(issues, evidenceCapabilitiesPath+": source missing source_id")
			continue
		}
		if strings.TrimSpace(source.Name) == "" {
			issues = append(issues, evidenceCapabilitiesPath+": source "+sourceID+" missing name")
		}
		if strings.TrimSpace(source.Purpose) == "" {
			issues = append(issues, evidenceCapabilitiesPath+": source "+sourceID+" missing purpose")
		}
		if len(source.Dimensions) == 0 {
			issues = append(issues, evidenceCapabilitiesPath+": source "+sourceID+" missing dimensions")
		}
		for _, dimension := range source.Dimensions {
			dimensionID := strings.TrimSpace(dimension.DimensionID)
			key := sourceID + "\x00" + dimensionID
			if dimensionID == "" {
				issues = append(issues, evidenceCapabilitiesPath+": source "+sourceID+" has dimension missing dimension_id")
				continue
			}
			if _, ok := capabilityKeys[key]; ok {
				issues = append(issues, evidenceCapabilitiesPath+": duplicate capability "+sourceID+"/"+dimensionID)
			}
			capabilityKeys[key] = struct{}{}
			if strings.TrimSpace(dimension.DimensionType) == "" {
				issues = append(issues, evidenceCapabilitiesPath+": capability "+sourceID+"/"+dimensionID+" missing dimension_type")
			}
			if strings.TrimSpace(dimension.SupportLevel) == "" {
				issues = append(issues, evidenceCapabilitiesPath+": capability "+sourceID+"/"+dimensionID+" missing support_level")
			}
			if len(dimension.ControlRefs) == 0 {
				issues = append(issues, evidenceCapabilitiesPath+": capability "+sourceID+"/"+dimensionID+" missing control_refs")
			}
			for _, ref := range evidenceCapabilityControlRefs(dimension, index) {
				if !knownControlRef(index, ref) {
					issues = append(issues, evidenceCapabilitiesPath+": capability "+sourceID+"/"+dimensionID+" references unknown control "+ref.Label())
				}
			}
		}
	}
	if len(issues) != 0 {
		sort.Strings(issues)
		return fmt.Errorf("compliance mapping catalog validation failed: %s", strings.Join(issues, "; "))
	}
	return nil
}

func validateControlEvidenceRequirements(catalog controlEvidenceRequirementCatalog) error {
	var issues []string
	if len(catalog.Profiles) == 0 {
		issues = append(issues, controlEvidenceRequirementsPath+": profiles is empty")
	}
	profileIDs := map[string]struct{}{}
	hasFallback := false
	for _, profile := range catalog.Profiles {
		profileID := strings.TrimSpace(profile.ProfileID)
		if profileID == "" {
			issues = append(issues, controlEvidenceRequirementsPath+": profile missing profile_id")
		} else if _, ok := profileIDs[profileID]; ok {
			issues = append(issues, controlEvidenceRequirementsPath+": duplicate profile "+profileID)
		}
		profileIDs[profileID] = struct{}{}
		if strings.TrimSpace(profile.Name) == "" {
			issues = append(issues, controlEvidenceRequirementsPath+": profile "+profileID+" missing name")
		}
		if profile.Fallback {
			hasFallback = true
		} else if selectorIsEmpty(profile.AppliesTo) {
			issues = append(issues, controlEvidenceRequirementsPath+": profile "+profileID+" has no selector")
		}
		if len(profile.SourceRequirements) == 0 {
			issues = append(issues, controlEvidenceRequirementsPath+": profile "+profileID+" missing source_requirements")
		}
		for _, requirement := range profile.SourceRequirements {
			merged := mergeControlEvidenceRequirementDefaults(catalog.Defaults, requirement)
			label := profileID + "/" + firstNonEmpty(requirement.SourceID, catalog.Defaults.SourceID)
			if strings.TrimSpace(merged.SourceID) == "" {
				issues = append(issues, controlEvidenceRequirementsPath+": requirement "+label+" missing source_id")
			}
			if strings.TrimSpace(merged.EntityType) == "" {
				issues = append(issues, controlEvidenceRequirementsPath+": requirement "+label+" missing entity_type")
			}
			if len(trimStrings(merged.RequiredFields)) == 0 {
				issues = append(issues, controlEvidenceRequirementsPath+": requirement "+label+" missing required_fields")
			}
			if strings.TrimSpace(merged.FreshnessWindow) == "" {
				issues = append(issues, controlEvidenceRequirementsPath+": requirement "+label+" missing freshness_window")
			}
			if len(trimStrings(merged.AssessmentMethods)) == 0 {
				issues = append(issues, controlEvidenceRequirementsPath+": requirement "+label+" missing assessment_methods")
			}
			if strings.TrimSpace(merged.AuditorGradeEvidence) == "" {
				issues = append(issues, controlEvidenceRequirementsPath+": requirement "+label+" missing auditor_grade_evidence")
			}
		}
	}
	if !hasFallback {
		issues = append(issues, controlEvidenceRequirementsPath+": at least one fallback profile is required")
	}
	if len(issues) != 0 {
		sort.Strings(issues)
		return fmt.Errorf("control evidence requirement validation failed: %s", strings.Join(issues, "; "))
	}
	return nil
}

func selectorIsEmpty(selector controlEvidenceRequirementSelector) bool {
	return len(trimStrings(selector.Frameworks)) == 0 &&
		len(trimStrings(selector.FamilyKeywords)) == 0 &&
		len(trimStrings(selector.ControlIDPrefixes)) == 0
}

func mergeControlEvidenceRequirementDefaults(defaults controlEvidenceRequirementDefaults, requirement controlEvidenceSourceRequirement) controlEvidenceSourceRequirement {
	merged := controlEvidenceSourceRequirement{
		SourceID:             strings.TrimSpace(defaults.SourceID),
		EntityType:           strings.TrimSpace(defaults.EntityType),
		RequiredFields:       uniqueSorted(defaults.RequiredFields),
		FreshnessWindow:      strings.TrimSpace(defaults.FreshnessWindow),
		AssessmentMethods:    uniqueSorted(defaults.AssessmentMethods),
		AuditorGradeEvidence: strings.TrimSpace(defaults.AuditorGradeEvidence),
	}
	if value := strings.TrimSpace(requirement.SourceID); value != "" {
		merged.SourceID = value
	}
	if value := strings.TrimSpace(requirement.EntityType); value != "" {
		merged.EntityType = value
	}
	if values := uniqueSorted(requirement.RequiredFields); len(values) != 0 {
		merged.RequiredFields = values
	}
	if value := strings.TrimSpace(requirement.FreshnessWindow); value != "" {
		merged.FreshnessWindow = value
	}
	if values := uniqueSorted(requirement.AssessmentMethods); len(values) != 0 {
		merged.AssessmentMethods = values
	}
	if value := strings.TrimSpace(requirement.AuditorGradeEvidence); value != "" {
		merged.AuditorGradeEvidence = value
	}
	return merged
}

func knownControlRef(index controlFamilyIndex, ref controlRef) bool {
	_, ok := index[controlRefKey(ref)]
	return ok
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
	Title     string
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

type findingControlMappingReview struct {
	Confidence string
	Rationale  string
}

type controlRelationshipEdge struct {
	Control      controlRef
	Related      controlRef
	Relationship string
	EvidenceUse  string
	Rationale    string
}

type expandedControlEvidenceRequirement struct {
	Ref                  controlRef
	ProfileID            string
	ProfileName          string
	SourceRequirement    controlEvidenceSourceRequirement
	SourceCapabilityRefs []string
	CatalogEvidenceRefs  []string
	CoverageStatus       string
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
			key := controlRefKey(controlRef{Framework: frameworkName, ControlID: controlID})
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			refs = append(refs, controlRef{
				Framework: frameworkName,
				ControlID: controlID,
				Family:    index[key].Family,
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

func findingReviewRows(catalog publicDetectionCatalog, index controlFamilyIndex, extensions policyRuleExtensions, reviewAreas []frameworkReviewArea, relationships []controlRelationship, capabilities []evidenceCapabilitySource) ([][]string, [][]string, [][]string, [][]string, [][]string, [][]string, findingExportSummary) {
	var findingRows [][]string
	var findingControlRows [][]string
	var findingTagRows [][]string
	var sourceCoverageRows [][]string
	var findingComplianceRows [][]string
	var qualityIssueRows [][]string
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
		frameworkReviewAreas := frameworkReviewAreaLabelsForControlRefs(controlRefs, reviewAreas, index)
		controlRelationshipHints := controlRelationshipLabelsForControlRefs(controlRefs, relationships, index)
		sourceCapabilityRefs := sourceCapabilityLabelsForDetection(detection, capabilities)
		sourceCapabilityStatus := sourceCapabilityStatusForDetection(detection, capabilities)
		auditDepth := resolveFindingAuditDepth(detection, extensions)
		complianceReview := findingComplianceReviewFor(detection, index, controlRefs)
		reviewFlags := findingReviewFlags(controlRefs, catalogTags, sourceCoverageRefs, auditDepth, complianceReview)
		qualityIssueRows = append(qualityIssueRows, findingQualityIssueRows(detection, controlRefs, complianceTags, auditDepth, sourceCapabilityStatus)...)

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
			joinList(frameworkReviewAreas),
			joinList(controlRelationshipHints),
			joinList(sourceCapabilityRefs),
			sourceCapabilityStatus,
		})

		for _, ref := range controlRefs {
			sourceCoverageLabels := complianceReview.SourceCoverageRefsByControlKey[controlRefKey(ref)]
			matchSource := "finding_control_ref"
			if len(sourceCoverageLabels) != 0 {
				matchSource = "finding_control_ref+source_coverage_ref"
			}
			mappingReview := findingControlMappingReviewFor(sourceCoverageLabels, sourceCapabilityStatus)
			findingControlRows = append(findingControlRows, []string{
				ref.Framework,
				ref.ControlID,
				ref.Label(),
				ref.Family,
				matchSource,
				mappingReview.Confidence,
				mappingReview.Rationale,
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
			sourceCapabilityStatus,
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
	sortRows(qualityIssueRows)
	return findingRows, findingControlRows, findingTagRows, sourceCoverageRows, findingComplianceRows, qualityIssueRows, summary
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
		key := controlRefKey(controlRef{Framework: frameworkName, ControlID: controlID})
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, controlRef{
			Framework: frameworkName,
			ControlID: controlID,
			Family:    index[key].Family,
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
	catalogAuditDepth := policyRuleExtension{
		EvidenceType:      detection.EvidenceType,
		AssessmentMethods: detection.AssessmentMethods,
		AuditorGuidance:   detection.AuditorGuidance,
		RiskStatement:     detection.RiskStatement,
		RemediationIntent: detection.RemediationIntent,
	}
	if !policySourceDetection(detection) {
		mergeResolvedFindingAuditDepth(&resolved, catalogAuditDepth, "catalog")
	}
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
	if policySourceDetection(detection) {
		mergeResolvedFindingAuditDepth(&resolved, catalogAuditDepth, "catalog")
	}
	resolved.Domain = domain
	for _, source := range resolved.fieldSources {
		resolved.FieldSources = append(resolved.FieldSources, source)
	}
	resolved.FieldSources = uniqueSorted(resolved.FieldSources)
	return resolved
}

func policySourceDetection(detection publicDetection) bool {
	return strings.EqualFold(strings.TrimSpace(detection.SourceID), "policy")
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

func findingControlMappingReviewFor(sourceCoverageLabels []string, sourceCapabilityStatus string) findingControlMappingReview {
	if len(uniqueSorted(sourceCoverageLabels)) != 0 {
		if sourceCapabilityStatus == "source_capability_defined" {
			return findingControlMappingReview{
				Confidence: "high",
				Rationale:  "Direct control ref is backed by matched source coverage with a declared YAML capability.",
			}
		}
		return findingControlMappingReview{
			Confidence: "medium",
			Rationale:  "Direct control ref is backed by matched source coverage, but source capability YAML needs review.",
		}
	}
	switch sourceCapabilityStatus {
	case "no_source_coverage":
		return findingControlMappingReview{
			Confidence: "medium",
			Rationale:  "Direct control ref is mapped from catalog metadata; no source coverage is attached to this finding.",
		}
	case "source_capability_defined", "source_coverage_unkeyed", "missing_yaml_source_capability", "partial_yaml_source_capability":
		return findingControlMappingReview{
			Confidence: "review",
			Rationale:  "Finding has source coverage, but it does not currently back this control with complete YAML capability context.",
		}
	default:
		return findingControlMappingReview{
			Confidence: "medium",
			Rationale:  "Direct control ref is mapped from catalog metadata and should be reviewed with the requirement table.",
		}
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
	return normalizeControlFramework(ref.Framework) + "\x00" + normalizeControlID(ref.ControlID)
}

func normalizeControlFramework(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func normalizeControlID(value string) string {
	normalized := strings.ToUpper(strings.Join(strings.Fields(strings.TrimSpace(value)), ""))
	if normalized == "" {
		return ""
	}
	return normalizeGDPRArticleControlID(normalized)
}

func normalizeGDPRArticleControlID(value string) string {
	for _, prefix := range []string{"ART.", "ART-"} {
		if suffix := strings.TrimPrefix(value, prefix); suffix != value && suffix != "" {
			return "ARTICLE" + suffix
		}
	}
	if len(value) > len("ART") && strings.HasPrefix(value, "ART") {
		suffix := value[len("ART"):]
		first, _ := utf8.DecodeRuneInString(suffix)
		if unicode.IsDigit(first) {
			return "ARTICLE" + suffix
		}
	}
	return value
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

func findingQualityIssueRows(detection publicDetection, controlRefs []controlRef, complianceTags []string, auditDepth resolvedFindingAuditDepth, sourceCapabilityStatus string) [][]string {
	var rows [][]string
	add := func(gate string, detail string) {
		rows = append(rows, []string{
			"finding",
			strings.TrimSpace(detection.ID),
			gate,
			"blocker",
			"fail",
			detail,
		})
	}
	if !hasPrefixedValue(complianceTags, "framework:") {
		add("finding_framework_tags_required", "No framework tag was derived from control_refs.")
	}
	if len(controlRefs) == 0 {
		add("finding_control_refs_required", "No framework control reference is mapped to this finding.")
	}
	if strings.TrimSpace(detection.EvaluationMode) == "" {
		add("finding_evidence_mode_required", "evaluation_mode is empty.")
	}
	if strings.TrimSpace(auditDepth.EvidenceType) == "" {
		add("finding_evidence_type_required", "evidence_type is empty after YAML and catalog resolution.")
	}
	if len(uniqueSorted(auditDepth.AssessmentMethods)) == 0 {
		add("finding_assessment_methods_required", "assessment_methods is empty after YAML and catalog resolution.")
	}
	if strings.TrimSpace(auditDepth.AuditorGuidance) == "" {
		add("finding_auditor_guidance_required", "auditor_guidance is empty after YAML and catalog resolution.")
	}
	if strings.TrimSpace(auditDepth.RiskStatement) == "" {
		add("finding_rationale_required", "risk_statement is empty after YAML and catalog resolution.")
	}
	if strings.TrimSpace(auditDepth.RemediationIntent) == "" {
		add("finding_remediation_intent_required", "remediation_intent is empty after YAML and catalog resolution.")
	}
	if strings.TrimSpace(sourceCapabilityStatus) == "" {
		add("finding_source_capability_status_required", "source_capability_status was not derived.")
	}
	return rows
}

func hasPrefixedValue(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(strings.TrimSpace(value), prefix) {
			return true
		}
	}
	return false
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

func frameworkReviewAreaRows(reviewAreas []frameworkReviewArea, index controlFamilyIndex) [][]string {
	var rows [][]string
	for _, area := range reviewAreas {
		framework := strings.TrimSpace(area.Framework)
		areaID := strings.TrimSpace(area.AreaID)
		if framework == "" || areaID == "" {
			continue
		}
		controlRefs := frameworkReviewAreaControlRefs(area, index)
		rows = append(rows, []string{
			framework,
			areaID,
			strings.TrimSpace(area.Name),
			strings.TrimSpace(area.EvidenceUse),
			joinList(controlRefLabels(controlRefs)),
			joinList(uniqueControlFamilies(controlRefs)),
			strings.TrimSpace(area.Purpose),
		})
	}
	sortRows(rows)
	return rows
}

func frameworkControlEnrichmentRows(catalog publicDetectionCatalog, index controlFamilyIndex, reviewAreas []frameworkReviewArea, relationships []controlRelationship, capabilitySources []evidenceCapabilitySource) [][]string {
	enrichments := frameworkControlEnrichments(catalog, index, reviewAreas, relationships, capabilitySources)
	keys := sortedKeys(enrichments)
	rows := make([][]string, 0, len(keys))
	for _, key := range keys {
		item := enrichments[key]
		rows = append(rows, []string{
			item.Ref.Framework,
			item.Ref.ControlID,
			item.Ref.Label(),
			item.Ref.Family,
			fmt.Sprint(len(uniqueSorted(item.DirectFindingIDs))),
			fmt.Sprint(len(uniqueSorted(item.SourceBackedFindingIDs))),
			fmt.Sprint(len(uniqueSorted(item.SourceMatchedFindingIDs))),
			joinList(item.SourceCapabilityRefs),
			joinList(item.ReviewAreaRefs),
			joinList(item.OutboundRelationshipRefs),
			joinList(item.InboundRelationshipRefs),
			frameworkControlEnrichmentStatus(item),
			joinLimitedStrings(item.DirectFindingIDs, 25),
			joinLimitedStrings(item.SourceBackedFindingIDs, 25),
		})
	}
	sortRows(rows)
	return rows
}

type frameworkControlEnrichment struct {
	Ref                      controlRef
	DirectFindingIDs         []string
	SourceBackedFindingIDs   []string
	SourceMatchedFindingIDs  []string
	SourceCapabilityRefs     []string
	ReviewAreaRefs           []string
	OutboundRelationshipRefs []string
	InboundRelationshipRefs  []string
}

func frameworkControlEnrichments(catalog publicDetectionCatalog, index controlFamilyIndex, reviewAreas []frameworkReviewArea, relationships []controlRelationship, capabilitySources []evidenceCapabilitySource) map[string]frameworkControlEnrichment {
	enrichments := map[string]frameworkControlEnrichment{}
	ensure := func(ref controlRef) frameworkControlEnrichment {
		ref.Framework = strings.TrimSpace(ref.Framework)
		ref.ControlID = strings.TrimSpace(ref.ControlID)
		if ref.Family == "" {
			ref.Family = controlFamilyForRef(index, ref)
		}
		key := controlRefKey(ref)
		item := enrichments[key]
		if strings.TrimSpace(item.Ref.Framework) == "" {
			item.Ref = ref
		}
		return item
	}
	store := func(item frameworkControlEnrichment) {
		enrichments[controlRefKey(item.Ref)] = item
	}

	for _, entry := range index {
		ref := entry.Ref
		ref.Family = entry.Family
		item := ensure(ref)
		store(item)
	}

	for _, detection := range catalog.Detections {
		controlRefs := publicDetectionControlRefs(detection.ControlRefs, index)
		complianceReview := findingComplianceReviewFor(detection, index, controlRefs)
		for _, ref := range controlRefs {
			item := ensure(ref)
			item.DirectFindingIDs = append(item.DirectFindingIDs, detection.ID)
			store(item)
		}
		for _, ref := range complianceReview.SourceBackedControlRefs {
			item := ensure(ref)
			item.SourceBackedFindingIDs = append(item.SourceBackedFindingIDs, detection.ID)
			store(item)
		}
		for _, ref := range complianceReview.SourceMatchedControlRefs {
			item := ensure(ref)
			item.SourceMatchedFindingIDs = append(item.SourceMatchedFindingIDs, detection.ID)
			store(item)
		}
	}

	for _, area := range reviewAreas {
		label := frameworkReviewAreaLabel(area)
		for _, ref := range frameworkReviewAreaControlRefs(area, index) {
			item := ensure(ref)
			item.ReviewAreaRefs = append(item.ReviewAreaRefs, label)
			store(item)
		}
	}

	for _, edge := range controlRelationshipEdges(relationships, index) {
		outbound := strings.TrimSpace(edge.Related.Label() + " [" + edge.Relationship + "/" + edge.EvidenceUse + "]")
		outboundItem := ensure(edge.Control)
		outboundItem.OutboundRelationshipRefs = append(outboundItem.OutboundRelationshipRefs, outbound)
		store(outboundItem)

		inbound := strings.TrimSpace(edge.Control.Label() + " [" + edge.Relationship + "/" + edge.EvidenceUse + "]")
		inboundItem := ensure(edge.Related)
		inboundItem.InboundRelationshipRefs = append(inboundItem.InboundRelationshipRefs, inbound)
		store(inboundItem)
	}

	for _, source := range capabilitySources {
		sourceID := strings.TrimSpace(source.SourceID)
		for _, dimension := range source.Dimensions {
			label := sourceCapabilityLabel(sourceID, dimension)
			for _, ref := range evidenceCapabilityControlRefs(dimension, index) {
				item := ensure(ref)
				item.SourceCapabilityRefs = append(item.SourceCapabilityRefs, label)
				store(item)
			}
		}
	}

	for key, item := range enrichments {
		item.DirectFindingIDs = uniqueSorted(item.DirectFindingIDs)
		item.SourceBackedFindingIDs = uniqueSorted(item.SourceBackedFindingIDs)
		item.SourceMatchedFindingIDs = uniqueSorted(item.SourceMatchedFindingIDs)
		item.SourceCapabilityRefs = uniqueSorted(item.SourceCapabilityRefs)
		item.ReviewAreaRefs = uniqueSorted(item.ReviewAreaRefs)
		item.OutboundRelationshipRefs = uniqueSorted(item.OutboundRelationshipRefs)
		item.InboundRelationshipRefs = uniqueSorted(item.InboundRelationshipRefs)
		enrichments[key] = item
	}
	return enrichments
}

func frameworkControlEnrichmentStatus(item frameworkControlEnrichment) string {
	switch {
	case len(item.DirectFindingIDs) != 0 && len(item.SourceBackedFindingIDs) == len(item.DirectFindingIDs):
		return "direct_source_backed"
	case len(item.DirectFindingIDs) != 0 && len(item.SourceBackedFindingIDs) != 0:
		return "partial_source_backed"
	case len(item.DirectFindingIDs) != 0 && len(item.SourceMatchedFindingIDs) != 0:
		return "direct_with_source_context"
	case len(item.DirectFindingIDs) != 0:
		return "direct_control_only"
	case len(item.SourceCapabilityRefs) != 0:
		return "source_capability_only"
	case len(item.ReviewAreaRefs) != 0 || len(item.OutboundRelationshipRefs) != 0 || len(item.InboundRelationshipRefs) != 0:
		return "review_context_only"
	default:
		return "framework_catalog_only"
	}
}

func frameworkControlGapRows(catalog publicDetectionCatalog, index controlFamilyIndex, reviewAreas []frameworkReviewArea, relationships []controlRelationship, capabilitySources []evidenceCapabilitySource) [][]string {
	enrichments := frameworkControlEnrichments(catalog, index, reviewAreas, relationships, capabilitySources)
	keys := sortedKeys(enrichments)
	rows := make([][]string, 0, len(keys))
	for _, key := range keys {
		item := enrichments[key]
		status := frameworkControlEnrichmentStatus(item)
		reviewContextRefs := append([]string{}, item.ReviewAreaRefs...)
		reviewContextRefs = append(reviewContextRefs, item.OutboundRelationshipRefs...)
		reviewContextRefs = append(reviewContextRefs, item.InboundRelationshipRefs...)
		reviewContextCount := len(uniqueSorted(reviewContextRefs))
		rows = append(rows, []string{
			item.Ref.Framework,
			item.Ref.ControlID,
			item.Ref.Label(),
			item.Ref.Family,
			status,
			frameworkControlCoverageLane(status),
			frameworkControlGapType(status),
			fmt.Sprint(len(uniqueSorted(item.DirectFindingIDs))),
			fmt.Sprint(len(uniqueSorted(item.SourceBackedFindingIDs))),
			fmt.Sprint(len(uniqueSorted(item.SourceMatchedFindingIDs))),
			fmt.Sprint(len(uniqueSorted(item.SourceCapabilityRefs))),
			fmt.Sprint(reviewContextCount),
			frameworkControlNextAction(status),
		})
	}
	sortRows(rows)
	return rows
}

func frameworkControlCoverageLane(status string) string {
	switch status {
	case "direct_source_backed", "partial_source_backed", "direct_with_source_context", "direct_control_only":
		return "direct"
	case "source_capability_only", "review_context_only":
		return "indirect"
	default:
		return "none"
	}
}

func frameworkControlGapType(status string) string {
	switch status {
	case "direct_source_backed":
		return "none"
	case "partial_source_backed":
		return "partial_source_backing"
	case "direct_with_source_context":
		return "source_context_review"
	case "direct_control_only":
		return "missing_source_backing"
	case "source_capability_only":
		return "missing_finding_mapping"
	case "review_context_only":
		return "review_context_without_evidence"
	default:
		return "no_mapping_or_evidence"
	}
}

func frameworkControlNextAction(status string) string {
	switch status {
	case "direct_source_backed":
		return "Maintain evidence collection and sampling."
	case "partial_source_backed":
		return "Add source backing for direct findings that still rely on control-only mapping."
	case "direct_with_source_context":
		return "Review source-matched controls and promote valid evidence links."
	case "direct_control_only":
		return "Add source capability or evidence requirements for mapped findings."
	case "source_capability_only":
		return "Map source-backed findings to this control or document why the capability is preparatory."
	case "review_context_only":
		return "Map findings or source capabilities before claiming control coverage."
	default:
		return "Decide whether this control is in scope, then add findings, evidence, or an exclusion."
	}
}

func frameworkCoverageCandidateRows(catalog publicDetectionCatalog, index controlFamilyIndex, reviewAreas []frameworkReviewArea, relationships []controlRelationship, capabilitySources []evidenceCapabilitySource, requirements []expandedControlEvidenceRequirement) [][]string {
	enrichments := frameworkControlEnrichments(catalog, index, reviewAreas, relationships, capabilitySources)
	requirementsByControl := expandedRequirementsByControl(requirements)
	keys := sortedKeys(enrichments)
	var rows [][]string
	for _, key := range keys {
		item := enrichments[key]
		status := frameworkControlEnrichmentStatus(item)
		candidateType := frameworkCoverageCandidateType(status)
		if candidateType == "" {
			continue
		}
		controlRequirements := requirementsByControl[key]
		rows = append(rows, frameworkCoverageCandidateRow(item, status, controlRequirements))
	}
	sortRows(rows)
	return rows
}

func frameworkCoverageCandidateRow(item frameworkControlEnrichment, status string, controlRequirements []expandedControlEvidenceRequirement) []string {
	reviewContextRefs := append([]string{}, item.ReviewAreaRefs...)
	reviewContextRefs = append(reviewContextRefs, item.OutboundRelationshipRefs...)
	reviewContextRefs = append(reviewContextRefs, item.InboundRelationshipRefs...)
	return []string{
		item.Ref.Framework,
		item.Ref.ControlID,
		item.Ref.Label(),
		item.Ref.Family,
		status,
		frameworkControlGapType(status),
		frameworkCoverageCandidatePriority(status),
		frameworkCoverageCandidateType(status),
		suggestedFindingDomain(controlRequirements),
		suggestedEvidenceType(controlRequirements),
		joinList(requirementProfileIDs(controlRequirements)),
		joinList(requirementSourceIDs(controlRequirements)),
		joinList(item.SourceCapabilityRefs),
		joinList(reviewContextRefs),
		frameworkCoverageCandidateAction(status),
	}
}

func expandedRequirementsByControl(requirements []expandedControlEvidenceRequirement) map[string][]expandedControlEvidenceRequirement {
	out := map[string][]expandedControlEvidenceRequirement{}
	for _, requirement := range requirements {
		key := controlRefKey(requirement.Ref)
		out[key] = append(out[key], requirement)
	}
	for key, values := range out {
		sort.Slice(values, func(i, j int) bool {
			left := []string{values[i].ProfileID, values[i].SourceRequirement.SourceID, values[i].SourceRequirement.EntityType}
			right := []string{values[j].ProfileID, values[j].SourceRequirement.SourceID, values[j].SourceRequirement.EntityType}
			return strings.Join(left, "\x00") < strings.Join(right, "\x00")
		})
		out[key] = values
	}
	return out
}

func frameworkCoverageCandidateType(status string) string {
	switch status {
	case "direct_with_source_context":
		return "source_link_review_candidate"
	case "direct_control_only":
		return "source_backing_candidate"
	case "source_capability_only":
		return "missing_finding_candidate"
	case "review_context_only":
		return "mapping_review_candidate"
	case "framework_catalog_only":
		return "scope_or_exclusion_candidate"
	default:
		return ""
	}
}

func frameworkCoverageCandidatePriority(status string) string {
	switch status {
	case "source_capability_only", "direct_control_only":
		return "high"
	case "direct_with_source_context", "review_context_only":
		return "medium"
	default:
		return "low"
	}
}

func frameworkCoverageCandidateAction(status string) string {
	switch status {
	case "direct_with_source_context":
		return "Review source-matched controls and promote valid links to the mapped finding."
	case "direct_control_only":
		return "Add source coverage or evidence requirements that support the mapped finding-control edge."
	case "source_capability_only":
		return "Create or map a source-backed finding for the declared source capability."
	case "review_context_only":
		return "Decide whether the review context should become a finding, relationship, or documented non-finding."
	default:
		return "Decide in-scope status, then add a finding, source capability, or documented exclusion."
	}
}

func suggestedFindingDomain(requirements []expandedControlEvidenceRequirement) string {
	for _, profileID := range orderedRequirementProfileIDs(requirements) {
		if domain := domainForRequirementProfile(profileID); domain != "" {
			return domain
		}
	}
	return "compliance_review"
}

func suggestedEvidenceType(requirements []expandedControlEvidenceRequirement) string {
	for _, profileID := range orderedRequirementProfileIDs(requirements) {
		if evidenceType := evidenceTypeForRequirementProfile(profileID); evidenceType != "" {
			return evidenceType
		}
	}
	return "control_review"
}

func domainForRequirementProfile(profileID string) string {
	switch strings.TrimSpace(profileID) {
	case "ai-governance":
		return "ai_governance"
	case "availability-resilience":
		return "availability"
	case "change-configuration":
		return "change_management"
	case "data-protection":
		return "data_protection"
	case "governance-risk":
		return "governance_risk"
	case "identity-access":
		return "identity"
	case "logging-monitoring":
		return "logging_monitoring"
	case "network-exposure":
		return "network_security"
	case "payment-card-security":
		return "payment_security"
	case "privacy-rights":
		return "privacy"
	case "vulnerability-remediation":
		return "vulnerability_management"
	default:
		return ""
	}
}

func evidenceTypeForRequirementProfile(profileID string) string {
	switch strings.TrimSpace(profileID) {
	case "ai-governance":
		return "ai_risk_evaluation"
	case "availability-resilience":
		return "availability_monitoring"
	case "change-configuration":
		return "change_record"
	case "data-protection":
		return "data_protection"
	case "governance-risk":
		return "governance_review"
	case "identity-access":
		return "identity_configuration"
	case "logging-monitoring":
		return "logging_configuration"
	case "network-exposure":
		return "network_exposure"
	case "payment-card-security":
		return "payment_security"
	case "privacy-rights":
		return "privacy_request"
	case "vulnerability-remediation":
		return "vulnerability_management"
	default:
		return ""
	}
}

func requirementProfileIDs(requirements []expandedControlEvidenceRequirement) []string {
	values := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		values = append(values, requirement.ProfileID)
	}
	return uniqueSorted(values)
}

func orderedRequirementProfileIDs(requirements []expandedControlEvidenceRequirement) []string {
	values := requirementProfileIDs(requirements)
	sort.Slice(values, func(i, j int) bool {
		leftPriority := requirementProfilePriority(values[i])
		rightPriority := requirementProfilePriority(values[j])
		if leftPriority == rightPriority {
			return values[i] < values[j]
		}
		return leftPriority < rightPriority
	})
	return values
}

func requirementProfilePriority(profileID string) int {
	switch strings.TrimSpace(profileID) {
	case "identity-access":
		return 10
	case "privacy-rights":
		return 20
	case "ai-governance":
		return 30
	case "payment-card-security":
		return 40
	case "vulnerability-remediation":
		return 50
	case "network-exposure":
		return 60
	case "data-protection":
		return 70
	case "logging-monitoring":
		return 80
	case "availability-resilience":
		return 90
	case "change-configuration":
		return 100
	case "governance-risk":
		return 110
	case "baseline-control-review":
		return 120
	default:
		return 1000
	}
}

func requirementSourceIDs(requirements []expandedControlEvidenceRequirement) []string {
	values := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		values = append(values, requirement.SourceRequirement.SourceID)
	}
	return uniqueSorted(values)
}

func expandedControlEvidenceRequirements(controlCatalog complianceControlCatalog, requirements controlEvidenceRequirementCatalog, catalog publicDetectionCatalog, index controlFamilyIndex, reviewAreas []frameworkReviewArea, relationships []controlRelationship, capabilitySources []evidenceCapabilitySource) []expandedControlEvidenceRequirement {
	refs := controlCatalogRefs(controlCatalog)
	enrichments := frameworkControlEnrichments(catalog, index, reviewAreas, relationships, capabilitySources)
	catalogEvidenceRefs := catalogEvidenceRefsByControl(controlCatalog)
	items := make([]expandedControlEvidenceRequirement, 0, len(refs))
	for _, ref := range refs {
		profiles := controlEvidenceProfilesForRef(requirements.Profiles, ref)
		enrichment := enrichments[controlRefKey(ref)]
		for _, profile := range profiles {
			for _, sourceRequirement := range profile.SourceRequirements {
				items = append(items, expandedControlEvidenceRequirement{
					Ref:                  ref,
					ProfileID:            strings.TrimSpace(profile.ProfileID),
					ProfileName:          strings.TrimSpace(profile.Name),
					SourceRequirement:    mergeControlEvidenceRequirementDefaults(requirements.Defaults, sourceRequirement),
					SourceCapabilityRefs: uniqueSorted(enrichment.SourceCapabilityRefs),
					CatalogEvidenceRefs:  catalogEvidenceRefs[controlRefKey(ref)],
					CoverageStatus:       frameworkControlEnrichmentStatus(enrichment),
				})
			}
		}
	}
	sort.Slice(items, func(i, j int) bool {
		left := []string{items[i].Ref.Framework, items[i].Ref.ControlID, items[i].ProfileID, items[i].SourceRequirement.SourceID, items[i].SourceRequirement.EntityType}
		right := []string{items[j].Ref.Framework, items[j].Ref.ControlID, items[j].ProfileID, items[j].SourceRequirement.SourceID, items[j].SourceRequirement.EntityType}
		return strings.Join(left, "\x00") < strings.Join(right, "\x00")
	})
	return items
}

func controlEvidenceProfilesForRef(profiles []controlEvidenceRequirementProfile, ref controlRef) []controlEvidenceRequirementProfile {
	var matched []controlEvidenceRequirementProfile
	var fallback []controlEvidenceRequirementProfile
	for _, profile := range profiles {
		if profile.Fallback {
			fallback = append(fallback, profile)
			continue
		}
		if controlEvidenceProfileApplies(profile, ref) {
			matched = append(matched, profile)
		}
	}
	if len(matched) != 0 {
		return matched
	}
	return fallback
}

func controlEvidenceProfileApplies(profile controlEvidenceRequirementProfile, ref controlRef) bool {
	selector := profile.AppliesTo
	searchText := strings.TrimSpace(ref.Family + " " + ref.Title)
	if selectorIsEmpty(selector) {
		return false
	}
	if values := trimStrings(selector.Frameworks); len(values) != 0 {
		if !containsFold(values, ref.Framework) {
			return false
		}
		if len(trimStrings(selector.FamilyKeywords)) == 0 && len(trimStrings(selector.ControlIDPrefixes)) == 0 {
			return true
		}
	}
	if values := trimStrings(selector.FamilyKeywords); len(values) != 0 && containsAnyFold(searchText, values) {
		return true
	}
	if values := trimStrings(selector.ControlIDPrefixes); len(values) != 0 && hasAnyPrefixFold(ref.ControlID, values) {
		return true
	}
	return false
}

func catalogEvidenceRefsByControl(catalog complianceControlCatalog) map[string][]string {
	out := map[string][]string{}
	for _, framework := range catalog.Frameworks {
		frameworkName := strings.TrimSpace(framework.Name)
		if frameworkName == "" {
			continue
		}
		for _, family := range framework.Families {
			for _, control := range family.Controls {
				controlID := strings.TrimSpace(control.ID)
				if controlID == "" {
					continue
				}
				ref := controlRef{Framework: frameworkName, ControlID: controlID}
				for _, expectation := range control.EvidenceExpectations {
					if label := catalogEvidenceExpectationLabel(expectation, control); label != "" {
						out[controlRefKey(ref)] = append(out[controlRefKey(ref)], label)
					}
				}
			}
		}
	}
	for key, labels := range out {
		out[key] = uniqueSorted(labels)
	}
	return out
}

func catalogEvidenceExpectationLabel(expectation complianceControlEvidenceExpectation, control complianceControlCatalogControl) string {
	id := firstNonEmpty(expectation.ID, expectation.Type, strings.TrimSpace(control.ID))
	if id == "" {
		return ""
	}
	parts := []string{id}
	if value := strings.TrimSpace(expectation.Type); value != "" && value != id {
		parts = append(parts, "type="+value)
	}
	if value := firstNonEmpty(expectation.FreshnessSLA, control.FreshnessSLA); value != "" {
		parts = append(parts, "freshness="+value)
	}
	if methods := firstNonEmptyList(expectation.AssessmentMethods, control.AssessmentMethods); len(methods) != 0 {
		parts = append(parts, "methods="+joinList(methods))
	}
	return strings.Join(parts, " ")
}

func controlEvidenceRequirementRows(items []expandedControlEvidenceRequirement) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Ref.Framework,
			item.Ref.ControlID,
			item.Ref.Label(),
			item.Ref.Family,
			item.ProfileID,
			item.ProfileName,
			item.SourceRequirement.SourceID,
			item.SourceRequirement.EntityType,
			joinList(item.SourceRequirement.RequiredFields),
			item.SourceRequirement.FreshnessWindow,
			joinList(item.SourceRequirement.AssessmentMethods),
			item.SourceRequirement.AuditorGradeEvidence,
			joinList(item.SourceCapabilityRefs),
			joinList(item.CatalogEvidenceRefs),
			item.CoverageStatus,
		})
	}
	sortRows(rows)
	return rows
}

func findingEvidenceRequirementRows(catalog publicDetectionCatalog, index controlFamilyIndex, capabilitySources []evidenceCapabilitySource, items []expandedControlEvidenceRequirement) [][]string {
	byControl := map[string][]expandedControlEvidenceRequirement{}
	for _, item := range items {
		byControl[controlRefKey(item.Ref)] = append(byControl[controlRefKey(item.Ref)], item)
	}
	var rows [][]string
	for _, detection := range catalog.Detections {
		controlRefs := publicDetectionControlRefs(detection.ControlRefs, index)
		complianceReview := findingComplianceReviewFor(detection, index, controlRefs)
		sourceCapabilityStatus := sourceCapabilityStatusForDetection(detection, capabilitySources)
		for _, ref := range controlRefs {
			for _, item := range byControl[controlRefKey(ref)] {
				rows = append(rows, []string{
					detection.ID,
					detection.Name,
					detection.PackID,
					detection.SourceID,
					detection.EvaluationMode,
					ref.Framework,
					ref.ControlID,
					ref.Label(),
					ref.Family,
					item.ProfileID,
					item.ProfileName,
					item.SourceRequirement.SourceID,
					item.SourceRequirement.EntityType,
					item.SourceRequirement.FreshnessWindow,
					sourceCapabilityStatus,
					complianceReview.ComplianceEvidenceStatus,
					findingRequirementMatchStatus(detection, item),
				})
			}
		}
	}
	sortRows(rows)
	return rows
}

func findingRequirementMatchStatus(detection publicDetection, item expandedControlEvidenceRequirement) string {
	requiredSource := strings.TrimSpace(item.SourceRequirement.SourceID)
	if requiredSource == "" {
		return "requirement_unkeyed"
	}
	if strings.EqualFold(strings.TrimSpace(detection.SourceID), requiredSource) {
		return "finding_source_matches_requirement"
	}
	for _, coverageRef := range detection.SourceCoverageRefs {
		if strings.EqualFold(strings.TrimSpace(coverageRef.SourceID), requiredSource) {
			return "source_coverage_matches_requirement"
		}
	}
	return "requirement_defined"
}

func validateControlEvidenceRequirementCoverage(refs []controlRef, items []expandedControlEvidenceRequirement) error {
	covered := map[string]struct{}{}
	for _, item := range items {
		covered[controlRefKey(item.Ref)] = struct{}{}
	}
	var missing []string
	for _, ref := range refs {
		if _, ok := covered[controlRefKey(ref)]; !ok {
			missing = append(missing, ref.Label())
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("control evidence requirements missing %d control(s): %s", len(missing), joinLimitedStrings(missing, 10))
	}
	return nil
}

func controlRelationshipRows(relationships []controlRelationship, index controlFamilyIndex) [][]string {
	var rows [][]string
	for _, edge := range controlRelationshipEdges(relationships, index) {
		rows = append(rows, []string{
			edge.Control.Framework,
			edge.Control.ControlID,
			edge.Control.Label(),
			edge.Control.Family,
			edge.Related.Framework,
			edge.Related.ControlID,
			edge.Related.Label(),
			edge.Related.Family,
			edge.Relationship,
			edge.EvidenceUse,
			edge.Rationale,
		})
	}
	sortRows(rows)
	return rows
}

func frameworkReviewAreaLabelsForControlRefs(controlRefs []controlRef, reviewAreas []frameworkReviewArea, index controlFamilyIndex) []string {
	var labels []string
	for _, area := range reviewAreas {
		if len(intersectControlRefs(controlRefs, frameworkReviewAreaControlRefs(area, index))) != 0 {
			labels = append(labels, frameworkReviewAreaLabel(area))
		}
	}
	return uniqueSorted(labels)
}

func controlRelationshipLabelsForControlRefs(controlRefs []controlRef, relationships []controlRelationship, index controlFamilyIndex) []string {
	relationshipIndex := controlRelationshipIndex(relationships, index)
	var labels []string
	for _, ref := range controlRefs {
		for _, edge := range relationshipIndex[controlRefKey(ref)] {
			labels = append(labels, edge.Control.Label()+" -> "+edge.Related.Label()+" ["+edge.Relationship+"/"+edge.EvidenceUse+"]")
		}
	}
	return uniqueSorted(labels)
}

func sourceCapabilityLabelsForDetection(detection publicDetection, sources []evidenceCapabilitySource) []string {
	capabilities := evidenceCapabilityKeySet(sources)
	var labels []string
	for _, coverageRef := range detection.SourceCoverageRefs {
		sourceID := strings.TrimSpace(coverageRef.SourceID)
		dimensionID := strings.TrimSpace(coverageRef.DimensionID)
		if sourceID == "" || dimensionID == "" {
			continue
		}
		if _, ok := capabilities[sourceID+"\x00"+dimensionID]; ok {
			labels = append(labels, sourceID+"/"+dimensionID)
		}
	}
	return uniqueSorted(labels)
}

func sourceCapabilityStatusForDetection(detection publicDetection, sources []evidenceCapabilitySource) string {
	if len(detection.SourceCoverageRefs) == 0 {
		return "no_source_coverage"
	}
	capabilities := evidenceCapabilityKeySet(sources)
	total := 0
	matched := 0
	for _, coverageRef := range detection.SourceCoverageRefs {
		sourceID := strings.TrimSpace(coverageRef.SourceID)
		dimensionID := strings.TrimSpace(coverageRef.DimensionID)
		if sourceID == "" || dimensionID == "" {
			continue
		}
		total++
		if _, ok := capabilities[sourceID+"\x00"+dimensionID]; ok {
			matched++
		}
	}
	switch {
	case total == 0:
		return "source_coverage_unkeyed"
	case matched == total:
		return "source_capability_defined"
	case matched == 0:
		return "missing_yaml_source_capability"
	default:
		return "partial_yaml_source_capability"
	}
}

func evidenceCapabilityKeySet(sources []evidenceCapabilitySource) map[string]struct{} {
	out := map[string]struct{}{}
	for _, source := range sources {
		sourceID := strings.TrimSpace(source.SourceID)
		for _, dimension := range source.Dimensions {
			dimensionID := strings.TrimSpace(dimension.DimensionID)
			if sourceID != "" && dimensionID != "" {
				out[sourceID+"\x00"+dimensionID] = struct{}{}
			}
		}
	}
	return out
}

func frameworkReviewAreaLabel(area frameworkReviewArea) string {
	framework := strings.TrimSpace(area.Framework)
	areaID := strings.TrimSpace(area.AreaID)
	switch {
	case framework != "" && areaID != "":
		return framework + "/" + areaID
	case framework != "":
		return framework
	default:
		return areaID
	}
}

func sourceCapabilityLabel(sourceID string, dimension evidenceCapabilityDimension) string {
	label := strings.TrimSpace(sourceID) + "/" + strings.TrimSpace(dimension.DimensionID)
	support := strings.TrimSpace(dimension.SupportLevel)
	if support != "" {
		label += " [" + support + "]"
	}
	return label
}

func findingReviewAreaRows(catalog publicDetectionCatalog, index controlFamilyIndex, reviewAreas []frameworkReviewArea) [][]string {
	var rows [][]string
	for _, detection := range catalog.Detections {
		controlRefs := publicDetectionControlRefs(detection.ControlRefs, index)
		for _, area := range reviewAreas {
			areaRefs := frameworkReviewAreaControlRefs(area, index)
			matchedRefs := intersectControlRefs(controlRefs, areaRefs)
			if len(matchedRefs) == 0 {
				continue
			}
			rows = append(rows, []string{
				strings.TrimSpace(area.Framework),
				strings.TrimSpace(area.AreaID),
				strings.TrimSpace(area.Name),
				strings.TrimSpace(area.EvidenceUse),
				joinList(controlRefLabels(areaRefs)),
				joinList(controlRefLabels(matchedRefs)),
				detection.ID,
				detection.Name,
				detection.PackID,
				detection.SourceID,
				detection.EvaluationMode,
				normalizedSeverity(detection.Severity),
				detection.Status,
				detection.Maturity,
				strings.TrimSpace(area.Purpose),
			})
		}
	}
	sortRows(rows)
	return rows
}

func findingControlRelationshipRows(catalog publicDetectionCatalog, index controlFamilyIndex, relationships []controlRelationship) [][]string {
	relationshipIndex := controlRelationshipIndex(relationships, index)
	var rows [][]string
	for _, detection := range catalog.Detections {
		for _, ref := range publicDetectionControlRefs(detection.ControlRefs, index) {
			for _, edge := range relationshipIndex[controlRefKey(ref)] {
				rows = append(rows, []string{
					edge.Control.Framework,
					edge.Control.ControlID,
					edge.Control.Label(),
					edge.Control.Family,
					edge.Related.Framework,
					edge.Related.ControlID,
					edge.Related.Label(),
					edge.Related.Family,
					edge.Relationship,
					edge.EvidenceUse,
					detection.ID,
					detection.Name,
					detection.PackID,
					detection.SourceID,
					detection.EvaluationMode,
					normalizedSeverity(detection.Severity),
					detection.Status,
					detection.Maturity,
					edge.Rationale,
				})
			}
		}
	}
	sortRows(rows)
	return rows
}

func frameworkReviewAreaControlRefs(area frameworkReviewArea, index controlFamilyIndex) []controlRef {
	framework := strings.TrimSpace(area.Framework)
	var refs []controlRef
	for _, controlID := range area.ControlRefs {
		ref := controlRef{
			Framework: framework,
			ControlID: strings.TrimSpace(controlID),
		}
		if ref.Framework == "" || ref.ControlID == "" {
			continue
		}
		ref.Family = controlFamilyForRef(index, ref)
		refs = append(refs, ref)
	}
	return uniqueControlRefs(refs)
}

func controlRelationshipIndex(relationships []controlRelationship, index controlFamilyIndex) map[string][]controlRelationshipEdge {
	edges := controlRelationshipEdges(relationships, index)
	out := make(map[string][]controlRelationshipEdge, len(edges))
	for _, edge := range edges {
		key := controlRefKey(edge.Control)
		out[key] = append(out[key], edge)
	}
	for key := range out {
		sort.Slice(out[key], func(i, j int) bool {
			return strings.Join(controlRelationshipEdgeSortKey(out[key][i]), "\x00") < strings.Join(controlRelationshipEdgeSortKey(out[key][j]), "\x00")
		})
	}
	return out
}

func controlRelationshipEdges(relationships []controlRelationship, index controlFamilyIndex) []controlRelationshipEdge {
	var edges []controlRelationshipEdge
	seen := map[string]struct{}{}
	for _, item := range relationships {
		control := controlRef{
			Framework: strings.TrimSpace(item.Framework),
			ControlID: strings.TrimSpace(item.ControlID),
		}
		if control.Framework == "" || control.ControlID == "" {
			continue
		}
		control.Family = controlFamilyForRef(index, control)
		for _, related := range item.RelatedControls {
			relatedRef := controlRef{
				Framework: firstNonEmpty(related.Framework, control.Framework),
				ControlID: strings.TrimSpace(related.ControlID),
			}
			if relatedRef.Framework == "" || relatedRef.ControlID == "" {
				continue
			}
			relatedRef.Family = controlFamilyForRef(index, relatedRef)
			edge := controlRelationshipEdge{
				Control:      control,
				Related:      relatedRef,
				Relationship: strings.TrimSpace(related.Relationship),
				EvidenceUse:  strings.TrimSpace(related.EvidenceUse),
				Rationale:    strings.TrimSpace(related.Rationale),
			}
			key := strings.Join(controlRelationshipEdgeSortKey(edge), "\x00")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			edges = append(edges, edge)
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		return strings.Join(controlRelationshipEdgeSortKey(edges[i]), "\x00") < strings.Join(controlRelationshipEdgeSortKey(edges[j]), "\x00")
	})
	return edges
}

func controlRelationshipEdgeSortKey(edge controlRelationshipEdge) []string {
	return []string{
		edge.Control.Framework,
		edge.Control.ControlID,
		edge.Related.Framework,
		edge.Related.ControlID,
		edge.Relationship,
		edge.EvidenceUse,
		edge.Rationale,
	}
}

func evidenceCapabilityRows(sources []evidenceCapabilitySource, index controlFamilyIndex) [][]string {
	var rows [][]string
	for _, source := range sources {
		sourceID := strings.TrimSpace(source.SourceID)
		for _, dimension := range source.Dimensions {
			dimensionID := strings.TrimSpace(dimension.DimensionID)
			if sourceID == "" || dimensionID == "" {
				continue
			}
			controlRefs := evidenceCapabilityControlRefs(dimension, index)
			rows = append(rows, []string{
				sourceID,
				strings.TrimSpace(source.Name),
				dimensionID,
				strings.TrimSpace(dimension.DimensionType),
				strings.TrimSpace(dimension.SupportLevel),
				fmt.Sprint(dimension.HighValue),
				joinList(dimension.Families),
				joinList(dimension.EvidenceTypes),
				joinList(dimension.ControlDomains),
				joinList(controlRefLabels(controlRefs)),
				joinList(uniqueControlFamilies(controlRefs)),
				strings.TrimSpace(source.Purpose),
			})
		}
	}
	sortRows(rows)
	return rows
}

func sourceCapabilityReviewRows(catalog publicDetectionCatalog, index controlFamilyIndex, sources []evidenceCapabilitySource) [][]string {
	capabilities := evidenceCapabilityIndex(sources, index)
	coverage := sourceCoverageAggregate(catalog, index)
	keys := map[string]struct{}{}
	for key := range capabilities {
		keys[key] = struct{}{}
	}
	for key := range coverage {
		keys[key] = struct{}{}
	}
	var sorted []string
	for key := range keys {
		sorted = append(sorted, key)
	}
	sort.Strings(sorted)

	var rows [][]string
	for _, key := range sorted {
		sourceID, dimensionID, _ := strings.Cut(key, "\x00")
		capability := capabilities[key]
		observed := coverage[key]
		capabilityRefs := evidenceCapabilityControlRefs(capability.Dimension, index)
		catalogRefs := observed.ControlRefs
		rows = append(rows, []string{
			sourceID,
			dimensionID,
			firstNonEmpty(capability.Dimension.DimensionType, observed.DimensionType),
			firstNonEmpty(capability.Dimension.SupportLevel, joinList(observed.SupportLevels)),
			fmt.Sprint(capability.Dimension.HighValue || observed.HighValue),
			joinList(firstNonEmptyList(capability.Dimension.Families, observed.Families)),
			joinList(firstNonEmptyList(capability.Dimension.EvidenceTypes, observed.EvidenceTypes)),
			joinList(firstNonEmptyList(capability.Dimension.ControlDomains, observed.ControlDomains)),
			joinList(controlRefLabels(capabilityRefs)),
			joinList(controlRefLabels(catalogRefs)),
			joinList(controlRefLabels(differenceControlRefs(capabilityRefs, catalogRefs))),
			joinList(controlRefLabels(differenceControlRefs(catalogRefs, capabilityRefs))),
			sourceCapabilityMatchStatus(capability.Exists, observed.Exists, capabilityRefs, catalogRefs),
			fmt.Sprint(observed.FindingCount),
			joinLimitedStrings(observed.FindingIDs, 25),
		})
	}
	sortRows(rows)
	return rows
}

type indexedEvidenceCapability struct {
	Exists    bool
	Source    evidenceCapabilitySource
	Dimension evidenceCapabilityDimension
}

type sourceCoverageAggregateRow struct {
	Exists         bool
	DimensionType  string
	SupportLevels  []string
	HighValue      bool
	Families       []string
	EvidenceTypes  []string
	ControlDomains []string
	ControlRefs    []controlRef
	FindingCount   int
	FindingIDs     []string
}

func evidenceCapabilityIndex(sources []evidenceCapabilitySource, index controlFamilyIndex) map[string]indexedEvidenceCapability {
	out := map[string]indexedEvidenceCapability{}
	for _, source := range sources {
		sourceID := strings.TrimSpace(source.SourceID)
		if sourceID == "" {
			continue
		}
		for _, dimension := range source.Dimensions {
			dimensionID := strings.TrimSpace(dimension.DimensionID)
			if dimensionID == "" {
				continue
			}
			key := sourceID + "\x00" + dimensionID
			dimension.ControlRefs = yamlControlRefs(evidenceCapabilityControlRefs(dimension, index))
			out[key] = indexedEvidenceCapability{Exists: true, Source: source, Dimension: dimension}
		}
	}
	return out
}

func sourceCoverageAggregate(catalog publicDetectionCatalog, index controlFamilyIndex) map[string]sourceCoverageAggregateRow {
	out := map[string]sourceCoverageAggregateRow{}
	for _, detection := range catalog.Detections {
		for _, coverageRef := range detection.SourceCoverageRefs {
			sourceID := strings.TrimSpace(coverageRef.SourceID)
			dimensionID := strings.TrimSpace(coverageRef.DimensionID)
			if sourceID == "" || dimensionID == "" {
				continue
			}
			key := sourceID + "\x00" + dimensionID
			row := out[key]
			row.Exists = true
			row.DimensionType = firstNonEmpty(row.DimensionType, coverageRef.DimensionType)
			if coverageRef.HighValue {
				row.HighValue = true
			}
			row.SupportLevels = append(row.SupportLevels, coverageRef.SupportLevel)
			row.Families = append(row.Families, coverageRef.Families...)
			row.EvidenceTypes = append(row.EvidenceTypes, coverageRef.EvidenceTypes...)
			row.ControlDomains = append(row.ControlDomains, coverageRef.ControlDomains...)
			row.ControlRefs = append(row.ControlRefs, publicDetectionControlRefs(coverageRef.MatchedControlRefs, index)...)
			if strings.TrimSpace(detection.ID) != "" {
				row.FindingIDs = append(row.FindingIDs, detection.ID)
			}
			out[key] = row
		}
	}
	for key, row := range out {
		row.SupportLevels = uniqueSorted(row.SupportLevels)
		row.Families = uniqueSorted(row.Families)
		row.EvidenceTypes = uniqueSorted(row.EvidenceTypes)
		row.ControlDomains = uniqueSorted(row.ControlDomains)
		row.ControlRefs = uniqueControlRefs(row.ControlRefs)
		row.FindingIDs = uniqueSorted(row.FindingIDs)
		row.FindingCount = len(row.FindingIDs)
		out[key] = row
	}
	return out
}

func evidenceCapabilityControlRefs(dimension evidenceCapabilityDimension, index controlFamilyIndex) []controlRef {
	var refs []controlRef
	for _, item := range dimension.ControlRefs {
		ref := controlRef{Framework: strings.TrimSpace(item.Framework), ControlID: strings.TrimSpace(item.ControlID)}
		if ref.Framework == "" || ref.ControlID == "" {
			continue
		}
		ref.Family = controlFamilyForRef(index, ref)
		refs = append(refs, ref)
	}
	return uniqueControlRefs(refs)
}

func yamlControlRefs(refs []controlRef) []yamlControlRef {
	out := make([]yamlControlRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, yamlControlRef{Framework: ref.Framework, ControlID: ref.ControlID})
	}
	return out
}

func sourceCapabilityMatchStatus(capabilityExists bool, catalogExists bool, capabilityRefs []controlRef, catalogRefs []controlRef) string {
	switch {
	case !capabilityExists && catalogExists:
		return "missing_yaml_capability"
	case capabilityExists && !catalogExists:
		return "yaml_only_capability"
	case !capabilityExists && !catalogExists:
		return "no_capability_or_catalog_coverage"
	}
	missingCatalogRefs := differenceControlRefs(capabilityRefs, catalogRefs)
	catalogOnlyRefs := differenceControlRefs(catalogRefs, capabilityRefs)
	switch {
	case len(missingCatalogRefs) == 0 && len(catalogOnlyRefs) == 0:
		return "matched"
	case len(missingCatalogRefs) == 0:
		return "catalog_extends_yaml"
	case len(catalogOnlyRefs) == 0:
		return "yaml_extends_catalog"
	case len(intersectControlRefs(capabilityRefs, catalogRefs)) != 0:
		return "partial_overlap"
	default:
		return "no_control_overlap"
	}
}

func firstNonEmptyList(values ...[]string) []string {
	for _, value := range values {
		if trimmed := uniqueSorted(value); len(trimmed) != 0 {
			return trimmed
		}
	}
	return nil
}

func limitStrings(values []string, limit int) []string {
	values = uniqueSorted(values)
	if limit <= 0 || len(values) <= limit {
		return values
	}
	limited := append([]string{}, values[:limit]...)
	limited = append(limited, fmt.Sprintf("... %d more", len(values)-limit))
	return limited
}

func joinLimitedStrings(values []string, limit int) string {
	return strings.Join(limitStrings(values, limit), "; ")
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

func workbookManifestRows() [][]string {
	rows := [][]string{workbookManifestHeader()}
	rows = append(rows,
		workbookManifestRow(1, "Overview", "overview.csv", "metric", "metric", "What changed and where should review start?", "generated summary", true),
		workbookManifestRow(2, "Logic", "logic.csv", "generation step", "step", "What logic produced these review tables?", "tools/policymappingexport", true),
		workbookManifestRow(3, "Quality Issues", "compliance_quality_issues.csv", "blocking quality issue", "scope; scope_id; quality_gate", "What must be fixed before claiming mapping quality?", "tools/policymappingexport", true),
		workbookManifestRow(4, "Framework Gaps", "framework_control_gap_map.csv", "framework control", "framework; control_id", "Which controls are direct, indirect, or uncovered?", "internal/compliance/control_families.yaml", true),
		workbookManifestRow(5, "Coverage Candidates", "framework_coverage_candidates.csv", "framework control work item", "framework; control_id; candidate_type", "What author or evidence work should happen next?", "derived from framework control enrichment", true),
		workbookManifestRow(6, "Control Requirements", "control_evidence_requirements.csv", "control evidence requirement", "framework; control_id; requirement_profile; requirement_source_id", "What evidence does each control require?", "internal/compliance/control_evidence_requirements.yaml", true),
		workbookManifestRow(7, "Finding Requirements", "finding_evidence_requirement_map.csv", "finding-control-requirement link", "finding_id; framework; control_id; requirement_profile; requirement_source_id", "Which requirement source does each mapped finding point toward?", "public catalog plus control evidence requirements", true),
		workbookManifestRow(8, "Finding Map", "finding_map.csv", "public finding", "finding_id", "What controls, tags, evidence, and review signals attach to each finding?", "internal/findings/public_detection_catalog.json", true),
		workbookManifestRow(9, "Finding Controls", "finding_control_map.csv", "finding-control link", "finding_id; framework; control_id", "Which control links are source-backed, direct-only, or review-needed?", "public catalog source coverage refs", true),
		workbookManifestRow(10, "Finding Review", "finding_compliance_review_map.csv", "public finding review row", "finding_id", "Which findings need audit-language, source, or control review?", "policy_rule_extensions.yaml plus public catalog", true),
		workbookManifestRow(11, "Source Coverage", "source_coverage_map.csv", "finding source coverage ref", "finding_id; coverage_source_id; coverage_dimension_id", "Which source coverage refs support or extend finding controls?", "public catalog source coverage refs", true),
		workbookManifestRow(12, "Source Capability Review", "source_capability_review_map.csv", "source capability", "source_id; dimension_id", "Where do YAML capabilities and catalog coverage differ?", "internal/compliance/evidence_capabilities.yaml", true),
		workbookManifestRow(13, "Evidence Capabilities", "evidence_capabilities.csv", "YAML source capability", "source_id; dimension_id", "What can each source and dimension support?", "internal/compliance/evidence_capabilities.yaml", true),
		workbookManifestRow(14, "Framework Enrichment", "framework_control_enrichment_map.csv", "framework control", "framework; control_id", "What direct findings, source capabilities, and review context enrich each control?", "derived from all mapping layers", true),
		workbookManifestRow(15, "Review Areas", "framework_review_areas.csv", "framework review area", "framework; area_id", "How should controls be grouped for reviewer queues?", "internal/compliance/framework_review_areas.yaml", false),
		workbookManifestRow(16, "Control Relationships", "control_relationships.csv", "control relationship", "framework; control_id; related_framework; related_control_id", "Which controls should be reviewed together?", "internal/compliance/control_relationships.yaml", false),
		workbookManifestRow(17, "Finding Review Areas", "finding_review_area_map.csv", "finding review-area link", "finding_id; framework; area_id", "Which findings enter each framework review queue?", "review areas plus direct control refs", false),
		workbookManifestRow(18, "Finding Relationships", "finding_control_relationship_map.csv", "finding control relationship link", "finding_id; framework; control_id; related_control_id", "Which related controls should be inspected with each finding?", "control relationships plus direct control refs", false),
		workbookManifestRow(19, "Policy Map", "policy_map.csv", "policy rule", "rule_id", "What YAML policy metadata, controls, tags, and audit language exist?", "policies/**/*.yaml", false),
		workbookManifestRow(20, "Policy Controls", "control_map.csv", "policy-control link", "rule_id; framework; control_id", "Which policy rules map to each framework control?", "policies/**/*.yaml", false),
		workbookManifestRow(21, "Policy Tags", "tag_map.csv", "policy-tag link", "rule_id; tag", "Which metadata and derived tags route each policy?", "policies/**/*.yaml", false),
		workbookManifestRow(22, "Finding Tags", "finding_tag_map.csv", "finding-tag link", "finding_id; tag", "Which catalog and derived review tags attach to each finding?", "public catalog plus control refs", false),
		workbookManifestRow(23, "Domain Aliases", "finding_domain_aliases.csv", "finding domain alias", "match_type; match_value", "How are non-policy findings assigned audit domains?", "internal/compliance/policy_rule_extensions.yaml", false),
		workbookManifestRow(24, "YAML Layers", "yaml_layers.csv", "audit language layer", "scope_type; scope", "Which YAML layer supplied default audit language?", "internal/compliance/policy_rule_extensions.yaml", false),
	)
	return rows
}

func workbookManifestRow(order int, worksheet string, csvFile string, rowGrain string, primaryKey string, reviewQuestion string, sourceAuthority string, includeByDefault bool) []string {
	return []string{
		fmt.Sprint(order),
		worksheet,
		csvFile,
		rowGrain,
		primaryKey,
		reviewQuestion,
		sourceAuthority,
		fmt.Sprint(includeByDefault),
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
		{"8", "mapping confidence", "Classify each finding-control edge as high, medium, or review using matched source coverage and YAML source capability status."},
		{"9", "compliance review tags", "Derive framework:, control:, and control-family: tags from control_refs for spreadsheet review. These do not replace runtime finding tags."},
		{"10", "framework review areas", "Group direct control refs from internal/compliance/framework_review_areas.yaml so reviewers can see management-system, safeguard, privacy, AI, and payment-card work queues without changing finding evidence."},
		{"11", "control relationships", "Add alias, child requirement, sibling scope, and evidence dependency hints from internal/compliance/control_relationships.yaml. These links do not make a finding source-backed."},
		{"12", "evidence capabilities", "Compare source and dimension capabilities from internal/compliance/evidence_capabilities.yaml with observed source coverage refs so YAML coverage gaps are visible."},
		{"13", "quality gates", "Fail generation when a finding lacks framework tags, control refs, evidence mode, resolved audit language, rationale, or source capability status."},
		{"14", "control gap status", "Classify each framework control as direct, indirect, or no coverage so mapped controls and review-only gaps are visible."},
		{"15", "control evidence requirements", "Expand first-class evidence requirements from internal/compliance/control_evidence_requirements.yaml across every framework control, then join them with source capabilities and catalog evidence expectations."},
		{"16", "coverage candidates", "Create author review rows for controls that need source backing, source-backed findings, mapping review, or scope decisions before coverage can be claimed."},
		{"17", "workbook manifest", "Emit a sheet-order manifest with row grain, primary keys, review questions, source authority, and default workbook inclusion for every generated table."},
		{"18", "spreadsheet", "Generate CSV rows from YAML, the public catalog, and derived review layers. Do not edit spreadsheet rows back into source by hand."},
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
		"framework_review_areas", "control_relationship_hints", "source_capability_refs",
		"source_capability_status",
	}
}

func findingControlMapHeader() []string {
	return []string{
		"framework", "control_id", "control_ref", "control_family", "control_match_source",
		"mapping_confidence", "mapping_rationale", "source_coverage_refs", "finding_id", "name",
		"pack_id", "source_id", "evaluation_mode", "severity", "status", "maturity",
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
		"compliance_evidence_status", "source_capability_status", "review_flags",
	}
}

func complianceQualityIssuesHeader() []string {
	return []string{"scope", "scope_id", "quality_gate", "severity", "status", "detail"}
}

func findingDomainAliasesHeader() []string {
	return []string{"match_type", "match_value", "resolved_domain"}
}

func frameworkReviewAreasHeader() []string {
	return []string{
		"framework", "area_id", "area_name", "evidence_use", "control_refs",
		"control_families", "purpose",
	}
}

func controlRelationshipsHeader() []string {
	return []string{
		"framework", "control_id", "control_ref", "control_family",
		"related_framework", "related_control_id", "related_control_ref",
		"related_control_family", "relationship", "evidence_use", "rationale",
	}
}

func findingReviewAreaMapHeader() []string {
	return []string{
		"framework", "area_id", "area_name", "evidence_use", "area_control_refs",
		"matched_control_refs", "finding_id", "finding_name", "pack_id", "source_id",
		"evaluation_mode", "severity", "status", "maturity", "purpose",
	}
}

func findingControlRelationshipMapHeader() []string {
	return []string{
		"framework", "control_id", "control_ref", "control_family",
		"related_framework", "related_control_id", "related_control_ref",
		"related_control_family", "relationship", "evidence_use", "finding_id",
		"finding_name", "pack_id", "source_id", "evaluation_mode", "severity",
		"status", "maturity", "rationale",
	}
}

func evidenceCapabilitiesHeader() []string {
	return []string{
		"source_id", "source_name", "dimension_id", "dimension_type", "support_level",
		"high_value", "families", "evidence_types", "control_domains", "control_refs",
		"control_families", "purpose",
	}
}

func sourceCapabilityReviewMapHeader() []string {
	return []string{
		"source_id", "dimension_id", "dimension_type", "support_level", "high_value",
		"families", "evidence_types", "control_domains", "yaml_capability_control_refs",
		"catalog_matched_control_refs", "yaml_only_control_refs", "catalog_only_control_refs",
		"capability_match_status", "finding_count", "sample_finding_ids",
	}
}

func frameworkControlEnrichmentMapHeader() []string {
	return []string{
		"framework", "control_id", "control_ref", "control_family",
		"direct_finding_count", "source_backed_finding_count", "source_matched_finding_count",
		"source_capability_refs", "review_area_refs", "outbound_relationship_refs",
		"inbound_relationship_refs", "enrichment_status", "sample_direct_finding_ids",
		"sample_source_backed_finding_ids",
	}
}

func frameworkControlGapMapHeader() []string {
	return []string{
		"framework", "control_id", "control_ref", "control_family",
		"coverage_status", "coverage_lane", "gap_type", "direct_finding_count",
		"source_backed_finding_count", "source_matched_finding_count",
		"source_capability_count", "review_context_count", "next_action",
	}
}

func controlEvidenceRequirementsHeader() []string {
	return []string{
		"framework", "control_id", "control_ref", "control_family",
		"requirement_profile", "requirement_name", "requirement_source_id",
		"entity_type", "required_fields", "freshness_window", "assessment_methods",
		"auditor_grade_evidence", "source_capability_refs", "catalog_evidence_refs",
		"coverage_status",
	}
}

func findingEvidenceRequirementMapHeader() []string {
	return []string{
		"finding_id", "name", "pack_id", "source_id", "evaluation_mode",
		"framework", "control_id", "control_ref", "control_family",
		"requirement_profile", "requirement_name", "requirement_source_id",
		"entity_type", "freshness_window", "source_capability_status",
		"compliance_evidence_status", "requirement_match_status",
	}
}

func frameworkCoverageCandidatesHeader() []string {
	return []string{
		"framework", "control_id", "control_ref", "control_family",
		"coverage_status", "gap_type", "candidate_priority", "candidate_type",
		"suggested_finding_domain", "suggested_evidence_type", "requirement_profiles",
		"requirement_sources", "source_capability_refs", "review_context_refs",
		"next_action",
	}
}

func workbookManifestHeader() []string {
	return []string{
		"sheet_order", "worksheet_name", "csv_file", "row_grain", "primary_key",
		"review_question", "source_authority", "include_by_default",
	}
}

func enforceComplianceQuality(qualityIssueRows [][]string, controlGapRows [][]string) error {
	if len(qualityIssueRows) != 0 {
		var samples []string
		for _, row := range qualityIssueRows {
			if len(row) >= 6 {
				samples = append(samples, row[0]+":"+row[1]+" "+row[2]+" "+row[5])
			}
			if len(samples) >= 10 {
				break
			}
		}
		return fmt.Errorf("compliance quality gates failed with %d issue(s): %s", len(qualityIssueRows), strings.Join(samples, "; "))
	}
	for _, row := range controlGapRows {
		if len(row) < len(frameworkControlGapMapHeader()) {
			return fmt.Errorf("framework control gap map produced a short row: %v", row)
		}
		if strings.TrimSpace(row[4]) == "" || strings.TrimSpace(row[5]) == "" || strings.TrimSpace(row[6]) == "" {
			return fmt.Errorf("framework control gap map row missing coverage status: %v", row)
		}
	}
	return nil
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

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func containsAnyFold(value string, needles []string) bool {
	value = normalizeKeywordText(value)
	for _, needle := range needles {
		needle = normalizeKeywordText(needle)
		if needle != "" && strings.Contains(" "+value+" ", " "+needle+" ") {
			return true
		}
	}
	return false
}

func normalizeKeywordText(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			continue
		}
		b.WriteRune(' ')
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func hasAnyPrefixFold(value string, prefixes []string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range prefixes {
		if prefix = strings.ToLower(strings.TrimSpace(prefix)); prefix != "" && strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
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
