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

	coverageops "github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/findingdsl"
	"gopkg.in/yaml.v3"
)

const defaultOutputDir = "docs/reference/policy-compliance-mapping"
const policyRuleExtensionsPath = "internal/compliance/policy_rule_extensions.yaml"
const controlFamiliesPath = "internal/compliance/control_families.yaml"
const frameworkSourcesPath = "internal/compliance/framework_sources.yaml"
const frameworkReviewAreasPath = "internal/compliance/framework_review_areas.yaml"
const controlRelationshipsPath = "internal/compliance/control_relationships.yaml"
const evidenceCapabilitiesPath = "internal/compliance/evidence_capabilities.yaml"
const controlEvidenceRequirementsPath = "internal/compliance/control_evidence_requirements.yaml"
const coverageControlDomainRefsPath = "internal/findings/coverage_control_domain_refs.yaml"
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

type frameworkSourceCatalog struct {
	Sources []frameworkSource `yaml:"sources"`
}

type frameworkSource struct {
	Framework       string `yaml:"framework"`
	FrameworkID     string `yaml:"framework_id"`
	Version         string `yaml:"version"`
	Lifecycle       string `yaml:"lifecycle"`
	Authority       string `yaml:"authority"`
	SourceType      string `yaml:"source_type"`
	SourceURL       string `yaml:"source_url"`
	SourceStatus    string `yaml:"source_status"`
	ControlModel    string `yaml:"control_model"`
	EvidenceModel   string `yaml:"evidence_model"`
	AssessmentNotes string `yaml:"assessment_notes"`
}

type frameworkSourceIndex map[string]frameworkSource

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
	Defaults   controlEvidenceRequirementDefaults  `yaml:"defaults"`
	ClaimRules []controlEvidenceClaimRule          `yaml:"claim_rules"`
	Profiles   []controlEvidenceRequirementProfile `yaml:"profiles"`
}

type controlEvidenceRequirementDefaults struct {
	SourceID                 string   `yaml:"source_id"`
	EntityType               string   `yaml:"entity_type"`
	RequiredFields           []string `yaml:"required_fields"`
	FreshnessWindow          string   `yaml:"freshness_window"`
	AssessmentMethods        []string `yaml:"assessment_methods"`
	AuditorGradeEvidence     string   `yaml:"auditor_grade_evidence"`
	ClaimStrength            string   `yaml:"claim_strength"`
	SufficiencyRule          string   `yaml:"sufficiency_rule"`
	CoverageClaim            string   `yaml:"coverage_claim"`
	OverclaimGuard           string   `yaml:"overclaim_guard"`
	AdjacentControlRationale string   `yaml:"adjacent_control_rationale"`
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
	SourceID                 string   `yaml:"source_id"`
	EntityType               string   `yaml:"entity_type"`
	RequiredFields           []string `yaml:"required_fields"`
	FreshnessWindow          string   `yaml:"freshness_window"`
	AssessmentMethods        []string `yaml:"assessment_methods"`
	AuditorGradeEvidence     string   `yaml:"auditor_grade_evidence"`
	ClaimStrength            string   `yaml:"claim_strength"`
	SufficiencyRule          string   `yaml:"sufficiency_rule"`
	CoverageClaim            string   `yaml:"coverage_claim"`
	OverclaimGuard           string   `yaml:"overclaim_guard"`
	AdjacentControlRationale string   `yaml:"adjacent_control_rationale"`
}

type controlEvidenceClaimRule struct {
	RuleID                   string                             `yaml:"rule_id"`
	AppliesTo                controlEvidenceRequirementSelector `yaml:"applies_to"`
	ClaimStrength            string                             `yaml:"claim_strength"`
	SufficiencyRule          string                             `yaml:"sufficiency_rule"`
	CoverageClaim            string                             `yaml:"coverage_claim"`
	OverclaimGuard           string                             `yaml:"overclaim_guard"`
	AdjacentControlRationale string                             `yaml:"adjacent_control_rationale"`
}

type yamlControlRef struct {
	Framework string `yaml:"framework"`
	ControlID string `yaml:"control_id"`
}

type coverageControlDomainRefCatalog struct {
	ControlDomains map[string][]coverageControlDomainRef `yaml:"control_domains"`
}

type coverageControlDomainRef struct {
	FrameworkName string `yaml:"framework_name"`
	ControlID     string `yaml:"control_id"`
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
	frameworkSources, err := loadFrameworkSources(root)
	if err != nil {
		return nil, err
	}
	if err := validateFrameworkSources(controlCatalog, frameworkSources); err != nil {
		return nil, err
	}
	frameworkSourceIndex := frameworkSourceIndexByFramework(frameworkSources)
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
	domainControlRefs, err := loadCoverageControlDomainRefs(root)
	if err != nil {
		return nil, err
	}
	evidenceCapabilities = enrichEvidenceCapabilitiesWithDomainRefs(evidenceCapabilities, domainControlRefs)
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

	reviewAreaRows := frameworkReviewAreaRows(reviewAreas, controlFamilies)
	relationshipRows := controlRelationshipRows(controlRelationships, controlFamilies)
	findingAreaRows := findingReviewAreaRows(catalog, controlFamilies, reviewAreas)
	findingRelationshipRows := findingControlRelationshipRows(catalog, controlFamilies, controlRelationships)
	evidenceCapabilityRows := evidenceCapabilityRows(evidenceCapabilities, controlFamilies)
	sourceCapabilityReviewRows := sourceCapabilityReviewRows(catalog, controlFamilies, evidenceCapabilities)
	frameworkSourceCSVRows := frameworkSourceRows(frameworkSources)
	frameworkControlEnrichmentRows := frameworkControlEnrichmentRows(catalog, controlFamilies, reviewAreas, controlRelationships, evidenceCapabilities, frameworkSourceIndex)
	frameworkControlGapRows := frameworkControlGapRows(catalog, controlFamilies, reviewAreas, controlRelationships, evidenceCapabilities, frameworkSourceIndex)
	controlRequirementItems := expandedControlEvidenceRequirements(controlCatalog, controlEvidenceRequirements, catalog, controlFamilies, reviewAreas, controlRelationships, evidenceCapabilities)
	findingRows, findingControlRows, findingTagRows, sourceCoverageRows, findingComplianceRows, qualityIssueRows, findingSummary := findingReviewRows(catalog, controlFamilies, extensions, reviewAreas, controlRelationships, evidenceCapabilities, controlRequirementItems)
	controlRequirementRows := controlEvidenceRequirementRows(controlRequirementItems, frameworkSourceIndex)
	findingRequirementRows := findingEvidenceRequirementRows(catalog, controlFamilies, evidenceCapabilities, controlRequirementItems, frameworkSourceIndex)
	findingTagContractRows := findingComplianceTagContractRows(catalog, controlFamilies, evidenceCapabilities, controlRequirementItems, frameworkSourceIndex)
	coverageExplanationRows := coverageGapExplanationRows(catalog, controlFamilies, evidenceCapabilities, controlRequirementItems)
	coverageCandidateRows := frameworkCoverageCandidateRows(catalog, controlFamilies, reviewAreas, controlRelationships, evidenceCapabilities, controlRequirementItems, frameworkSourceIndex)
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
		{Name: "finding_compliance_tag_contract.csv", Content: csvBytes(append([][]string{findingComplianceTagContractHeader()}, findingTagContractRows...))},
		{Name: "source_coverage_map.csv", Content: csvBytes(append([][]string{sourceCoverageMapHeader()}, sourceCoverageRows...))},
		{Name: "finding_compliance_review_map.csv", Content: csvBytes(append([][]string{findingComplianceReviewMapHeader()}, findingComplianceRows...))},
		{Name: "compliance_quality_issues.csv", Content: csvBytes(append([][]string{complianceQualityIssuesHeader()}, qualityIssueRows...))},
		{Name: "finding_domain_aliases.csv", Content: csvBytes(append([][]string{findingDomainAliasesHeader()}, findingDomainAliasRows(extensions)...))},
		{Name: "framework_sources.csv", Content: csvBytes(append([][]string{frameworkSourcesHeader()}, frameworkSourceCSVRows...))},
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
		{Name: "coverage_gap_explanations.csv", Content: csvBytes(append([][]string{coverageGapExplanationsHeader()}, coverageExplanationRows...))},
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

func loadFrameworkSources(root string) ([]frameworkSource, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(frameworkSourcesPath)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", frameworkSourcesPath, err)
	}
	var catalog frameworkSourceCatalog
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return nil, fmt.Errorf("decode %s: %w", frameworkSourcesPath, err)
	}
	return catalog.Sources, nil
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

func loadCoverageControlDomainRefs(root string) (map[string][]yamlControlRef, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(coverageControlDomainRefsPath)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", coverageControlDomainRefsPath, err)
	}
	var catalog coverageControlDomainRefCatalog
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return nil, fmt.Errorf("decode %s: %w", coverageControlDomainRefsPath, err)
	}
	refs := map[string][]yamlControlRef{}
	for domain, domainRefs := range catalog.ControlDomains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		for _, ref := range domainRefs {
			framework := strings.TrimSpace(ref.FrameworkName)
			controlID := strings.TrimSpace(ref.ControlID)
			if framework == "" || controlID == "" {
				continue
			}
			refs[domain] = append(refs[domain], yamlControlRef{Framework: framework, ControlID: controlID})
		}
	}
	return refs, nil
}

func enrichEvidenceCapabilitiesWithDomainRefs(sources []evidenceCapabilitySource, domainRefs map[string][]yamlControlRef) []evidenceCapabilitySource {
	enriched := append([]evidenceCapabilitySource(nil), sources...)
	for sourceIndex, source := range enriched {
		source.Dimensions = append([]evidenceCapabilityDimension(nil), source.Dimensions...)
		for dimensionIndex, dimension := range source.Dimensions {
			nextRefs := append([]yamlControlRef(nil), dimension.ControlRefs...)
			for _, domain := range dimension.ControlDomains {
				nextRefs = append(nextRefs, domainRefs[strings.TrimSpace(domain)]...)
			}
			dimension.ControlRefs = uniqueYAMLControlRefs(nextRefs)
			source.Dimensions[dimensionIndex] = dimension
		}
		enriched[sourceIndex] = source
	}
	return enriched
}

func uniqueYAMLControlRefs(refs []yamlControlRef) []yamlControlRef {
	seen := map[string]struct{}{}
	var unique []yamlControlRef
	for _, ref := range refs {
		ref.Framework = strings.TrimSpace(ref.Framework)
		ref.ControlID = strings.TrimSpace(ref.ControlID)
		if ref.Framework == "" || ref.ControlID == "" {
			continue
		}
		key := strings.ToLower(ref.Framework) + "\x00" + strings.ToUpper(ref.ControlID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, ref)
	}
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Framework != unique[j].Framework {
			return unique[i].Framework < unique[j].Framework
		}
		return unique[i].ControlID < unique[j].ControlID
	})
	return unique
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

func controlCatalogFrameworkNames(catalog complianceControlCatalog) []string {
	names := make([]string, 0, len(catalog.Frameworks))
	for _, framework := range catalog.Frameworks {
		if name := strings.TrimSpace(framework.Name); name != "" {
			names = append(names, name)
		}
	}
	return uniqueSorted(names)
}

func validateFrameworkSources(catalog complianceControlCatalog, sources []frameworkSource) error {
	var issues []string
	catalogFrameworks := stringSet(controlCatalogFrameworkNames(catalog))
	sourceFrameworks := map[string]struct{}{}
	for _, source := range sources {
		framework := strings.TrimSpace(source.Framework)
		label := firstNonEmpty(framework, "<missing-framework>")
		if framework == "" {
			issues = append(issues, frameworkSourcesPath+": source missing framework")
		} else {
			if _, ok := catalogFrameworks[framework]; !ok {
				issues = append(issues, frameworkSourcesPath+": source references unknown framework "+framework)
			}
			if _, ok := sourceFrameworks[framework]; ok {
				issues = append(issues, frameworkSourcesPath+": duplicate source for "+framework)
			}
			sourceFrameworks[framework] = struct{}{}
		}
		if strings.TrimSpace(source.FrameworkID) == "" {
			issues = append(issues, frameworkSourcesPath+": source "+label+" missing framework_id")
		}
		if strings.TrimSpace(source.Version) == "" {
			issues = append(issues, frameworkSourcesPath+": source "+label+" missing version")
		}
		if strings.TrimSpace(source.Lifecycle) == "" {
			issues = append(issues, frameworkSourcesPath+": source "+label+" missing lifecycle")
		}
		if strings.TrimSpace(source.Authority) == "" {
			issues = append(issues, frameworkSourcesPath+": source "+label+" missing authority")
		}
		if strings.TrimSpace(source.SourceType) == "" {
			issues = append(issues, frameworkSourcesPath+": source "+label+" missing source_type")
		}
		sourceURL := strings.TrimSpace(source.SourceURL)
		if sourceURL == "" {
			issues = append(issues, frameworkSourcesPath+": source "+label+" missing source_url")
		} else if !strings.HasPrefix(sourceURL, "https://") && !strings.HasPrefix(sourceURL, "internal/") {
			issues = append(issues, frameworkSourcesPath+": source "+label+" source_url must be https:// or internal/")
		}
		if strings.TrimSpace(source.SourceStatus) == "" {
			issues = append(issues, frameworkSourcesPath+": source "+label+" missing source_status")
		}
		if strings.TrimSpace(source.ControlModel) == "" {
			issues = append(issues, frameworkSourcesPath+": source "+label+" missing control_model")
		}
		if strings.TrimSpace(source.EvidenceModel) == "" {
			issues = append(issues, frameworkSourcesPath+": source "+label+" missing evidence_model")
		}
		if strings.TrimSpace(source.AssessmentNotes) == "" {
			issues = append(issues, frameworkSourcesPath+": source "+label+" missing assessment_notes")
		}
	}
	for _, framework := range sortedKeys(catalogFrameworks) {
		if _, ok := sourceFrameworks[framework]; !ok {
			issues = append(issues, frameworkSourcesPath+": missing source for "+framework)
		}
	}
	if len(issues) != 0 {
		sort.Strings(issues)
		return fmt.Errorf("framework source validation failed: %s", strings.Join(issues, "; "))
	}
	return nil
}

func frameworkSourceIndexByFramework(sources []frameworkSource) frameworkSourceIndex {
	index := frameworkSourceIndex{}
	for _, source := range sources {
		if framework := strings.TrimSpace(source.Framework); framework != "" {
			index[framework] = frameworkSource{
				Framework:       framework,
				FrameworkID:     strings.TrimSpace(source.FrameworkID),
				Version:         strings.TrimSpace(source.Version),
				Lifecycle:       strings.TrimSpace(source.Lifecycle),
				Authority:       strings.TrimSpace(source.Authority),
				SourceType:      strings.TrimSpace(source.SourceType),
				SourceURL:       strings.TrimSpace(source.SourceURL),
				SourceStatus:    strings.TrimSpace(source.SourceStatus),
				ControlModel:    strings.TrimSpace(source.ControlModel),
				EvidenceModel:   strings.TrimSpace(source.EvidenceModel),
				AssessmentNotes: strings.TrimSpace(source.AssessmentNotes),
			}
		}
	}
	return index
}

func frameworkSourceExportCells(index frameworkSourceIndex, framework string) []string {
	source := index[strings.TrimSpace(framework)]
	return []string{
		source.Version,
		source.Lifecycle,
		source.Authority,
		source.SourceType,
		source.SourceStatus,
		source.SourceURL,
		source.EvidenceModel,
	}
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
	claimRuleIDs := map[string]struct{}{}
	for _, rule := range catalog.ClaimRules {
		ruleID := strings.TrimSpace(rule.RuleID)
		if ruleID == "" {
			issues = append(issues, controlEvidenceRequirementsPath+": claim rule missing rule_id")
		} else if _, ok := claimRuleIDs[ruleID]; ok {
			issues = append(issues, controlEvidenceRequirementsPath+": duplicate claim rule "+ruleID)
		}
		claimRuleIDs[ruleID] = struct{}{}
		if selectorIsEmpty(rule.AppliesTo) {
			issues = append(issues, controlEvidenceRequirementsPath+": claim rule "+ruleID+" has no selector")
		}
		issues = append(issues, validateControlEvidenceClaimFields("claim rule "+ruleID, controlEvidenceClaimFields{
			ClaimStrength:            rule.ClaimStrength,
			SufficiencyRule:          rule.SufficiencyRule,
			CoverageClaim:            rule.CoverageClaim,
			OverclaimGuard:           rule.OverclaimGuard,
			AdjacentControlRationale: rule.AdjacentControlRationale,
		})...)
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
			issues = append(issues, validateControlEvidenceClaimFields("requirement "+label, controlEvidenceClaimFields{
				ClaimStrength:            merged.ClaimStrength,
				SufficiencyRule:          merged.SufficiencyRule,
				CoverageClaim:            merged.CoverageClaim,
				OverclaimGuard:           merged.OverclaimGuard,
				AdjacentControlRationale: merged.AdjacentControlRationale,
			})...)
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

type controlEvidenceClaimFields struct {
	ClaimStrength            string
	SufficiencyRule          string
	CoverageClaim            string
	OverclaimGuard           string
	AdjacentControlRationale string
}

func validateControlEvidenceClaimFields(label string, claim controlEvidenceClaimFields) []string {
	var issues []string
	if strings.TrimSpace(claim.ClaimStrength) == "" {
		issues = append(issues, controlEvidenceRequirementsPath+": "+label+" missing claim_strength")
	}
	if strings.TrimSpace(claim.SufficiencyRule) == "" {
		issues = append(issues, controlEvidenceRequirementsPath+": "+label+" missing sufficiency_rule")
	}
	if strings.TrimSpace(claim.CoverageClaim) == "" {
		issues = append(issues, controlEvidenceRequirementsPath+": "+label+" missing coverage_claim")
	}
	if strings.TrimSpace(claim.OverclaimGuard) == "" {
		issues = append(issues, controlEvidenceRequirementsPath+": "+label+" missing overclaim_guard")
	}
	if strings.TrimSpace(claim.AdjacentControlRationale) == "" {
		issues = append(issues, controlEvidenceRequirementsPath+": "+label+" missing adjacent_control_rationale")
	}
	return issues
}

func selectorIsEmpty(selector controlEvidenceRequirementSelector) bool {
	return len(trimStrings(selector.Frameworks)) == 0 &&
		len(trimStrings(selector.FamilyKeywords)) == 0 &&
		len(trimStrings(selector.ControlIDPrefixes)) == 0
}

func mergeControlEvidenceRequirementDefaults(defaults controlEvidenceRequirementDefaults, requirement controlEvidenceSourceRequirement) controlEvidenceSourceRequirement {
	merged := controlEvidenceSourceRequirement{
		SourceID:                 strings.TrimSpace(defaults.SourceID),
		EntityType:               strings.TrimSpace(defaults.EntityType),
		RequiredFields:           uniqueSorted(defaults.RequiredFields),
		FreshnessWindow:          strings.TrimSpace(defaults.FreshnessWindow),
		AssessmentMethods:        uniqueSorted(defaults.AssessmentMethods),
		AuditorGradeEvidence:     strings.TrimSpace(defaults.AuditorGradeEvidence),
		ClaimStrength:            strings.TrimSpace(defaults.ClaimStrength),
		SufficiencyRule:          strings.TrimSpace(defaults.SufficiencyRule),
		CoverageClaim:            strings.TrimSpace(defaults.CoverageClaim),
		OverclaimGuard:           strings.TrimSpace(defaults.OverclaimGuard),
		AdjacentControlRationale: strings.TrimSpace(defaults.AdjacentControlRationale),
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
	if value := strings.TrimSpace(requirement.ClaimStrength); value != "" {
		merged.ClaimStrength = value
	}
	if value := strings.TrimSpace(requirement.SufficiencyRule); value != "" {
		merged.SufficiencyRule = value
	}
	if value := strings.TrimSpace(requirement.CoverageClaim); value != "" {
		merged.CoverageClaim = value
	}
	if value := strings.TrimSpace(requirement.OverclaimGuard); value != "" {
		merged.OverclaimGuard = value
	}
	if value := strings.TrimSpace(requirement.AdjacentControlRationale); value != "" {
		merged.AdjacentControlRationale = value
	}
	return merged
}

func mergeControlEvidenceClaimRule(requirement controlEvidenceSourceRequirement, rule controlEvidenceClaimRule) controlEvidenceSourceRequirement {
	if value := strings.TrimSpace(rule.ClaimStrength); value != "" {
		requirement.ClaimStrength = value
	}
	if value := strings.TrimSpace(rule.SufficiencyRule); value != "" {
		requirement.SufficiencyRule = value
	}
	if value := strings.TrimSpace(rule.CoverageClaim); value != "" {
		requirement.CoverageClaim = value
	}
	if value := strings.TrimSpace(rule.OverclaimGuard); value != "" {
		requirement.OverclaimGuard = value
	}
	if value := strings.TrimSpace(rule.AdjacentControlRationale); value != "" {
		requirement.AdjacentControlRationale = value
	}
	return requirement
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
	ClaimRuleID          string
	SourceRequirement    controlEvidenceSourceRequirement
	SourceCapabilityRefs []string
	CatalogEvidenceRefs  []string
	CoverageStatus       string
}

type findingOperationalReview struct {
	SourceFreshnessRequirements []string
	SourceFreshnessStatus       string
	RequiredMissingDimensions   []string
	ManualReviewOwner           string
	EvidencePacketReadiness     string
	NextRemediationAction       string
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

func findingReviewRows(catalog publicDetectionCatalog, index controlFamilyIndex, extensions policyRuleExtensions, reviewAreas []frameworkReviewArea, relationships []controlRelationship, capabilities []evidenceCapabilitySource, requirements []expandedControlEvidenceRequirement) ([][]string, [][]string, [][]string, [][]string, [][]string, [][]string, findingExportSummary) {
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
	requirementsByControl := expandedRequirementsByControl(requirements)
	capabilityIndex := evidenceCapabilityIndex(capabilities, index)

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
		evidenceBackingLevel := findingEvidenceBackingLevel(complianceReview, sourceCapabilityStatus, auditDepth)
		evidenceBackingGaps := findingEvidenceBackingGaps(controlRefs, detection.SourceCoverageRefs, complianceReview, sourceCapabilityStatus, auditDepth)
		operationalReview := findingOperationalReviewFromExplanations(detection, controlRefs, complianceReview, sourceCapabilityStatus, requirementsByControl, capabilityIndex)
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
			evidenceBackingLevel,
			joinList(evidenceBackingGaps),
			joinList(reviewFlags),
			joinList(operationalReview.SourceFreshnessRequirements),
			operationalReview.SourceFreshnessStatus,
			joinList(operationalReview.RequiredMissingDimensions),
			operationalReview.ManualReviewOwner,
			operationalReview.EvidencePacketReadiness,
			operationalReview.NextRemediationAction,
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
			evidenceBackingLevel,
			joinList(evidenceBackingGaps),
			joinList(reviewFlags),
			sourceCapabilityStatus,
			joinList(operationalReview.SourceFreshnessRequirements),
			operationalReview.SourceFreshnessStatus,
			joinList(operationalReview.RequiredMissingDimensions),
			operationalReview.ManualReviewOwner,
			operationalReview.EvidencePacketReadiness,
			operationalReview.NextRemediationAction,
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

func findingOperationalReviewFor(detection publicDetection, controlRefs []controlRef, review findingComplianceReview, sourceCapabilityStatus string, evidenceBackingLevel string, requirementsByControl map[string][]expandedControlEvidenceRequirement) findingOperationalReview {
	requirements := requirementsForControlRefs(controlRefs, requirementsByControl)
	missingDimensions := findingRequiredMissingDimensions(detection, requirements)
	freshnessRequirements := requirementFreshnessWindows(requirements)
	return findingOperationalReview{
		SourceFreshnessRequirements: freshnessRequirements,
		SourceFreshnessStatus:       sourceFreshnessStatus(evidenceBackingLevel, freshnessRequirements, sourceCapabilityStatus),
		RequiredMissingDimensions:   missingDimensions,
		ManualReviewOwner:           manualReviewOwner(requirements, review.ComplianceEvidenceStatus),
		EvidencePacketReadiness:     evidencePacketReadiness(evidenceBackingLevel, missingDimensions),
		NextRemediationAction:       nextRemediationAction(review.ComplianceEvidenceStatus, sourceCapabilityStatus, evidenceBackingLevel, missingDimensions),
	}
}

func findingOperationalReviewFromExplanations(detection publicDetection, controlRefs []controlRef, review findingComplianceReview, sourceCapabilityStatus string, requirementsByControl map[string][]expandedControlEvidenceRequirement, capabilityIndex map[string]indexedEvidenceCapability) findingOperationalReview {
	var explanations []coverageops.CoverageGapExplanation
	for _, ref := range controlRefs {
		requirements := requirementsByControl[controlRefKey(ref)]
		if len(requirements) == 0 {
			explanations = append(explanations, coverageops.BuildCoverageGapExplanation(coverageops.CoverageGapExplanationInput{
				CoverageFindingContext: coverageops.CoverageFindingContext{
					FindingID:             strings.TrimSpace(detection.ID),
					FindingName:           strings.TrimSpace(detection.Name),
					FindingSourceID:       strings.TrimSpace(detection.SourceID),
					FindingEvaluationMode: strings.TrimSpace(detection.EvaluationMode),
					FindingPackID:         strings.TrimSpace(detection.PackID),
					Control:               coverageControlRef(ref),
					ControlFamily:         strings.TrimSpace(ref.Family),
				},
				CoverageClaimContext: coverageops.CoverageClaimContext{
					ComplianceEvidenceStatus: strings.TrimSpace(review.ComplianceEvidenceStatus),
					SourceCapabilityStatus:   strings.TrimSpace(sourceCapabilityStatus),
					ClaimStatus:              "requirement_missing",
				},
				CoverageEvidenceContext: coverageops.CoverageEvidenceContext{
					SourceFacts: coverageSourceFactsForRequirement(detection.SourceCoverageRefs, ref, expandedControlEvidenceRequirement{}, capabilityIndex),
				},
			}))
			continue
		}
		for _, requirement := range requirements {
			matchStatus := findingRequirementMatchStatus(detection, requirement)
			claimStatus := findingRequirementClaimStatus(review.ComplianceEvidenceStatus, matchStatus, sourceCapabilityStatus)
			explanations = append(explanations, coverageExplanationForRequirement(detection, ref, requirement, review, sourceCapabilityStatus, claimStatus, capabilityIndex))
		}
	}
	return operationalReviewFromCoverageExplanations(explanations)
}

func operationalReviewFromCoverageExplanations(explanations []coverageops.CoverageGapExplanation) findingOperationalReview {
	if len(explanations) == 0 {
		return findingOperationalReview{
			SourceFreshnessStatus:   "freshness_requirement_missing",
			ManualReviewOwner:       "control_owner",
			EvidencePacketReadiness: "manual_packet_required",
			NextRemediationAction:   "Map source facts, evidence packets, policy documents, exceptions, or remediation before claiming coverage.",
		}
	}
	var freshnessRequirements []string
	var missingDimensions []string
	owner := ""
	ownerProfilePriority := 1000
	freshnessStatus := ""
	readiness := ""
	nextAction := ""
	for _, explanation := range explanations {
		if explanation.Freshness.Requirement != "" {
			label := explanation.Freshness.Requirement
			if explanation.RequirementSourceID != "" {
				label = explanation.RequirementSourceID + "=" + label
			}
			freshnessRequirements = append(freshnessRequirements, label)
		}
		missingDimensions = append(missingDimensions, coverageMissingDimensionLabels(explanation.MissingDimensions)...)
		if explanation.RequirementProfile != "" && strings.TrimSpace(explanation.Owner) != "" && requirementProfilePriority(explanation.RequirementProfile) < ownerProfilePriority {
			owner = explanation.Owner
			ownerProfilePriority = requirementProfilePriority(explanation.RequirementProfile)
		}
		freshnessStatus = worseFreshnessStatus(freshnessStatus, explanation.Freshness.Status)
		readiness = worsePacketReadiness(readiness, explanation.EvidencePacketReadiness)
		if nextAction == "" || readiness == explanation.EvidencePacketReadiness {
			nextAction = explanation.NextAction
		}
	}
	return findingOperationalReview{
		SourceFreshnessRequirements: uniqueSorted(freshnessRequirements),
		SourceFreshnessStatus:       firstNonEmpty(freshnessStatus, "freshness_requirement_missing"),
		RequiredMissingDimensions:   uniqueSorted(missingDimensions),
		ManualReviewOwner:           firstNonEmpty(owner, "control_owner"),
		EvidencePacketReadiness:     firstNonEmpty(readiness, "manual_packet_required"),
		NextRemediationAction:       nextAction,
	}
}

func worseFreshnessStatus(current string, next string) string {
	rank := map[string]int{
		"stale_source":                  0,
		"freshness_review_required":     1,
		"freshness_requirement_missing": 2,
		"freshness_requirement_defined": 3,
	}
	current = strings.TrimSpace(current)
	next = strings.TrimSpace(next)
	if current == "" {
		return next
	}
	if next == "" {
		return current
	}
	if rank[next] < rank[current] {
		return next
	}
	return current
}

func worsePacketReadiness(current string, next string) string {
	rank := map[string]int{
		"missing_required_source_dimensions": 0,
		"manual_packet_required":             1,
		"needs_source_review":                2,
		"ready_for_packet":                   3,
	}
	current = strings.TrimSpace(current)
	next = strings.TrimSpace(next)
	if current == "" {
		return next
	}
	if next == "" {
		return current
	}
	if rank[next] < rank[current] {
		return next
	}
	return current
}

func requirementsForControlRefs(controlRefs []controlRef, requirementsByControl map[string][]expandedControlEvidenceRequirement) []expandedControlEvidenceRequirement {
	var requirements []expandedControlEvidenceRequirement
	seen := map[string]struct{}{}
	for _, ref := range controlRefs {
		for _, requirement := range requirementsByControl[controlRefKey(ref)] {
			key := strings.Join([]string{
				requirement.Ref.Framework,
				requirement.Ref.ControlID,
				requirement.ProfileID,
				requirement.SourceRequirement.SourceID,
				requirement.SourceRequirement.EntityType,
			}, "\x00")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			requirements = append(requirements, requirement)
		}
	}
	sort.Slice(requirements, func(i, j int) bool {
		left := []string{requirements[i].ProfileID, requirements[i].SourceRequirement.SourceID, requirements[i].SourceRequirement.EntityType, requirements[i].Ref.Label()}
		right := []string{requirements[j].ProfileID, requirements[j].SourceRequirement.SourceID, requirements[j].SourceRequirement.EntityType, requirements[j].Ref.Label()}
		return strings.Join(left, "\x00") < strings.Join(right, "\x00")
	})
	return requirements
}

func findingRequiredMissingDimensions(detection publicDetection, requirements []expandedControlEvidenceRequirement) []string {
	observedSources := map[string]struct{}{}
	if sourceID := strings.TrimSpace(detection.SourceID); sourceID != "" {
		observedSources[strings.ToLower(sourceID)] = struct{}{}
	}
	for _, ref := range detection.SourceCoverageRefs {
		if sourceID := strings.TrimSpace(ref.SourceID); sourceID != "" {
			observedSources[strings.ToLower(sourceID)] = struct{}{}
		}
	}
	var missing []string
	for _, requirement := range requirements {
		sourceID := strings.TrimSpace(requirement.SourceRequirement.SourceID)
		if sourceID == "" {
			continue
		}
		if _, ok := observedSources[strings.ToLower(sourceID)]; ok {
			continue
		}
		parts := []string{sourceID}
		if entityType := strings.TrimSpace(requirement.SourceRequirement.EntityType); entityType != "" {
			parts = append(parts, entityType)
		}
		if fields := uniqueSorted(requirement.SourceRequirement.RequiredFields); len(fields) != 0 {
			parts = append(parts, "fields="+joinList(fields))
		}
		missing = append(missing, strings.Join(parts, " "))
	}
	return uniqueSorted(missing)
}

func requirementFreshnessWindows(requirements []expandedControlEvidenceRequirement) []string {
	var values []string
	for _, requirement := range requirements {
		sourceID := strings.TrimSpace(requirement.SourceRequirement.SourceID)
		freshness := strings.TrimSpace(requirement.SourceRequirement.FreshnessWindow)
		if freshness == "" {
			continue
		}
		if sourceID == "" {
			values = append(values, freshness)
			continue
		}
		values = append(values, sourceID+"="+freshness)
	}
	return uniqueSorted(values)
}

func sourceFreshnessStatus(evidenceBackingLevel string, freshnessRequirements []string, sourceCapabilityStatus string) string {
	if len(freshnessRequirements) == 0 {
		return "freshness_requirement_missing"
	}
	switch strings.TrimSpace(evidenceBackingLevel) {
	case "runtime_source_evidence_ready":
		return "freshness_requirement_defined"
	case "partial_runtime_evidence", "source_evidence_review_required":
		return "freshness_review_required"
	case "control_reference_only":
		return "freshness_source_missing"
	}
	if strings.TrimSpace(sourceCapabilityStatus) != "source_capability_defined" {
		return "freshness_capability_review_required"
	}
	return "freshness_review_required"
}

func sourceFreshnessStatusForClaimStatus(claimStatus string, freshnessRequirements []string, sourceCapabilityStatus string) string {
	if len(freshnessRequirements) == 0 {
		return "freshness_requirement_missing"
	}
	switch strings.TrimSpace(claimStatus) {
	case "source_evidence_claim":
		return "freshness_requirement_defined"
	case "partial_source_evidence_claim", "requirement_source_available":
		return "freshness_review_required"
	case "control_ref_review_claim", "requirement_missing":
		return "freshness_source_missing"
	}
	if strings.TrimSpace(sourceCapabilityStatus) != "source_capability_defined" {
		return "freshness_capability_review_required"
	}
	return "freshness_review_required"
}

func manualReviewOwner(requirements []expandedControlEvidenceRequirement, complianceEvidenceStatus string) string {
	if strings.TrimSpace(complianceEvidenceStatus) == "source_backed" {
		return "control_owner"
	}
	for _, profileID := range orderedRequirementProfileIDs(requirements) {
		if owner := manualReviewOwnerForProfile(profileID); owner != "" {
			return owner
		}
	}
	return "compliance_operations"
}

func manualReviewOwnerForProfile(profileID string) string {
	switch strings.TrimSpace(profileID) {
	case "identity-access":
		return "identity_owner"
	case "privacy-rights":
		return "privacy_owner"
	case "ai-governance":
		return "ai_governance_owner"
	case "payment-card-security":
		return "payment_owner"
	case "vulnerability-remediation":
		return "vulnerability_owner"
	case "network-exposure":
		return "network_owner"
	case "data-protection":
		return "data_owner"
	case "email-authentication":
		return "email_security_owner"
	case "logging-monitoring":
		return "security_operations_owner"
	case "availability-resilience":
		return "resilience_owner"
	case "change-configuration":
		return "change_owner"
	case "governance-risk":
		return "risk_owner"
	case "baseline-control-review":
		return "control_owner"
	default:
		return ""
	}
}

func evidencePacketReadiness(evidenceBackingLevel string, missingDimensions []string) string {
	if len(missingDimensions) != 0 {
		return "missing_required_source_dimensions"
	}
	switch strings.TrimSpace(evidenceBackingLevel) {
	case "runtime_source_evidence_ready":
		return "ready_for_packet"
	case "partial_runtime_evidence":
		return "needs_source_review"
	case "source_capability_review_required", "source_evidence_review_required", "audit_language_review_required":
		return "needs_mapping_review"
	case "control_reference_only":
		return "manual_packet_required"
	case "control_mapping_required", "mapping_required":
		return "mapping_required"
	default:
		return "review_required"
	}
}

func evidencePacketReadinessForClaimStatus(claimStatus string, missingDimensions []string) string {
	if len(missingDimensions) != 0 {
		return "missing_required_source_dimensions"
	}
	switch strings.TrimSpace(claimStatus) {
	case "source_evidence_claim":
		return "ready_for_packet"
	case "partial_source_evidence_claim", "requirement_source_available":
		return "needs_source_review"
	case "control_ref_review_claim":
		return "manual_packet_required"
	case "requirement_missing":
		return "mapping_required"
	default:
		return "review_required"
	}
}

func nextRemediationAction(complianceEvidenceStatus string, sourceCapabilityStatus string, evidenceBackingLevel string, missingDimensions []string) string {
	if len(missingDimensions) != 0 {
		return "Connect the required source dimension or document a manual evidence owner."
	}
	switch strings.TrimSpace(complianceEvidenceStatus) {
	case "missing_controls":
		return "Map the finding to an in-scope control before using it for coverage."
	case "source_only":
		return "Add the matching control reference or mark the source signal out of scope."
	case "control_only":
		return "Add source coverage or prepare a manual evidence packet for the mapped control."
	case "partial_source_backed":
		return "Close the unbacked control refs or split them into separate review items."
	}
	switch strings.TrimSpace(sourceCapabilityStatus) {
	case "missing_yaml_source_capability", "partial_yaml_source_capability", "source_coverage_unkeyed":
		return "Update YAML source capability coverage for the observed source dimension."
	}
	switch strings.TrimSpace(evidenceBackingLevel) {
	case "runtime_source_evidence_ready":
		return "Package runtime evidence and keep freshness within the stated window."
	case "source_evidence_review_required":
		return "Review source evidence against the control requirement before packet export."
	default:
		return "Review the mapping, source evidence, and owner before claiming coverage."
	}
}

func nextRemediationActionForClaimStatus(claimStatus string, sourceCapabilityStatus string, missingDimensions []string) string {
	if len(missingDimensions) != 0 {
		return "Connect the required source dimension or document a manual evidence owner."
	}
	switch strings.TrimSpace(claimStatus) {
	case "source_evidence_claim":
		return "Package runtime evidence and keep freshness within the stated window."
	case "partial_source_evidence_claim":
		return "Review the partial source evidence and close any unbacked control refs."
	case "requirement_source_available":
		return "Attach the available source capability to this finding-control requirement."
	case "control_ref_review_claim":
		return "Prepare a manual evidence packet or add source coverage for this control ref."
	case "requirement_missing":
		return "Add a control evidence requirement before claiming coverage."
	}
	switch strings.TrimSpace(sourceCapabilityStatus) {
	case "missing_yaml_source_capability", "partial_yaml_source_capability", "source_coverage_unkeyed":
		return "Update YAML source capability coverage for the observed source dimension."
	default:
		return "Review the requirement, source evidence, and owner before claiming coverage."
	}
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

func findingEvidenceBackingLevel(review findingComplianceReview, sourceCapabilityStatus string, auditDepth resolvedFindingAuditDepth) string {
	switch strings.TrimSpace(review.ComplianceEvidenceStatus) {
	case "missing_controls":
		return "mapping_required"
	case "source_only":
		return "control_mapping_required"
	case "control_only":
		return "control_reference_only"
	}
	if strings.TrimSpace(sourceCapabilityStatus) != "source_capability_defined" {
		return "source_capability_review_required"
	}
	if len(findingAuditDepthFlags(auditDepth)) != 0 {
		return "audit_language_review_required"
	}
	if strings.TrimSpace(review.ComplianceEvidenceStatus) == "partial_source_backed" {
		return "partial_runtime_evidence"
	}
	if hasValue(review.SourceCoverageSupportLevels, "partial") || hasValue(review.SourceCoverageSupportLevels, "planned") {
		return "partial_runtime_evidence"
	}
	if strings.TrimSpace(review.ComplianceEvidenceStatus) == "source_backed" && review.SourceCoverageHighValueCount > 0 {
		return "runtime_source_evidence_ready"
	}
	return "source_evidence_review_required"
}

func findingEvidenceBackingGaps(controlRefs []controlRef, coverageRefs []publicDetectionSourceCoverageRef, review findingComplianceReview, sourceCapabilityStatus string, auditDepth resolvedFindingAuditDepth) []string {
	var gaps []string
	if len(controlRefs) == 0 {
		gaps = append(gaps, "missing_control_refs")
	}
	if len(coverageRefs) == 0 {
		gaps = append(gaps, "missing_source_coverage_refs")
	}
	if len(review.ControlRefsWithoutSourceMatch) != 0 {
		gaps = append(gaps, "control_refs_without_source_match")
	}
	switch strings.TrimSpace(sourceCapabilityStatus) {
	case "source_capability_defined", "":
	default:
		gaps = append(gaps, "source_capability_yaml_review")
	}
	for _, supportLevel := range review.SourceCoverageSupportLevels {
		switch strings.TrimSpace(supportLevel) {
		case "partial":
			gaps = append(gaps, "partial_source_coverage")
		case "planned":
			gaps = append(gaps, "planned_source_coverage")
		case "unsupported":
			gaps = append(gaps, "unsupported_source_coverage")
		}
	}
	if len(coverageRefs) != 0 && review.SourceCoverageHighValueCount == 0 {
		gaps = append(gaps, "no_high_value_source_dimension")
	}
	gaps = append(gaps, findingAuditDepthFlags(auditDepth)...)
	return uniqueSorted(gaps)
}

func hasValue(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
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

func frameworkSourceRows(sources []frameworkSource) [][]string {
	rows := make([][]string, 0, len(sources))
	for _, source := range sources {
		rows = append(rows, []string{
			strings.TrimSpace(source.Framework),
			strings.TrimSpace(source.FrameworkID),
			strings.TrimSpace(source.Version),
			strings.TrimSpace(source.Lifecycle),
			strings.TrimSpace(source.Authority),
			strings.TrimSpace(source.SourceType),
			strings.TrimSpace(source.SourceURL),
			strings.TrimSpace(source.SourceStatus),
			strings.TrimSpace(source.ControlModel),
			strings.TrimSpace(source.EvidenceModel),
			strings.TrimSpace(source.AssessmentNotes),
		})
	}
	sortRows(rows)
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

func frameworkControlEnrichmentRows(catalog publicDetectionCatalog, index controlFamilyIndex, reviewAreas []frameworkReviewArea, relationships []controlRelationship, capabilitySources []evidenceCapabilitySource, sourceIndex frameworkSourceIndex) [][]string {
	enrichments := frameworkControlEnrichments(catalog, index, reviewAreas, relationships, capabilitySources)
	keys := sortedKeys(enrichments)
	rows := make([][]string, 0, len(keys))
	for _, key := range keys {
		item := enrichments[key]
		row := []string{
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
		}
		row = append(row, frameworkSourceExportCells(sourceIndex, item.Ref.Framework)...)
		rows = append(rows, row)
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

func frameworkControlGapRows(catalog publicDetectionCatalog, index controlFamilyIndex, reviewAreas []frameworkReviewArea, relationships []controlRelationship, capabilitySources []evidenceCapabilitySource, sourceIndex frameworkSourceIndex) [][]string {
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
		row := []string{
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
		}
		row = append(row, frameworkSourceExportCells(sourceIndex, item.Ref.Framework)...)
		rows = append(rows, row)
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

func frameworkCoverageCandidateRows(catalog publicDetectionCatalog, index controlFamilyIndex, reviewAreas []frameworkReviewArea, relationships []controlRelationship, capabilitySources []evidenceCapabilitySource, requirements []expandedControlEvidenceRequirement, sourceIndex frameworkSourceIndex) [][]string {
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
		rows = append(rows, frameworkCoverageCandidateRow(item, status, controlRequirements, sourceIndex))
	}
	sortRows(rows)
	return rows
}

func frameworkCoverageCandidateRow(item frameworkControlEnrichment, status string, controlRequirements []expandedControlEvidenceRequirement, sourceIndex frameworkSourceIndex) []string {
	reviewContextRefs := append([]string{}, item.ReviewAreaRefs...)
	reviewContextRefs = append(reviewContextRefs, item.OutboundRelationshipRefs...)
	reviewContextRefs = append(reviewContextRefs, item.InboundRelationshipRefs...)
	row := []string{
		item.Ref.Framework,
		item.Ref.ControlID,
		item.Ref.Label(),
		item.Ref.Family,
		status,
		frameworkControlGapType(status),
		frameworkCoverageCandidatePriority(status),
		frameworkCoverageCandidateType(status),
		controlRequirementClaimStatus(status),
		suggestedFindingDomain(controlRequirements),
		suggestedEvidenceType(controlRequirements),
		joinList(requirementClaimRuleIDs(controlRequirements)),
		joinList(requirementClaimStrengths(controlRequirements)),
		joinList(requirementSufficiencyRules(controlRequirements)),
		joinList(requirementCoverageClaims(controlRequirements)),
		joinList(requirementProfileIDs(controlRequirements)),
		joinList(requirementSourceIDs(controlRequirements)),
		joinList(item.SourceCapabilityRefs),
		joinList(reviewContextRefs),
		joinList(requirementOverclaimGuards(controlRequirements)),
		joinList(requirementAdjacentControlRationales(controlRequirements)),
		frameworkCoverageCandidateAction(status),
	}
	row = append(row, frameworkSourceExportCells(sourceIndex, item.Ref.Framework)...)
	return row
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
	case "email-authentication":
		return "email_security"
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
	case "email-authentication":
		return "email_authentication_control"
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
	case "email-authentication":
		return 80
	case "logging-monitoring":
		return 90
	case "availability-resilience":
		return 100
	case "change-configuration":
		return 110
	case "governance-risk":
		return 120
	case "baseline-control-review":
		return 130
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

func requirementClaimRuleIDs(requirements []expandedControlEvidenceRequirement) []string {
	values := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		values = append(values, requirement.ClaimRuleID)
	}
	return uniqueSorted(values)
}

func requirementClaimStrengths(requirements []expandedControlEvidenceRequirement) []string {
	values := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		values = append(values, requirement.SourceRequirement.ClaimStrength)
	}
	return uniqueSorted(values)
}

func requirementSufficiencyRules(requirements []expandedControlEvidenceRequirement) []string {
	values := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		values = append(values, requirement.SourceRequirement.SufficiencyRule)
	}
	return uniqueSorted(values)
}

func requirementCoverageClaims(requirements []expandedControlEvidenceRequirement) []string {
	values := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		values = append(values, requirement.SourceRequirement.CoverageClaim)
	}
	return uniqueSorted(values)
}

func requirementOverclaimGuards(requirements []expandedControlEvidenceRequirement) []string {
	values := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		values = append(values, requirement.SourceRequirement.OverclaimGuard)
	}
	return uniqueSorted(values)
}

func requirementAdjacentControlRationales(requirements []expandedControlEvidenceRequirement) []string {
	values := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		values = append(values, requirement.SourceRequirement.AdjacentControlRationale)
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
		claimRule := controlEvidenceClaimRuleForRef(requirements.ClaimRules, ref)
		enrichment := enrichments[controlRefKey(ref)]
		for _, profile := range profiles {
			for _, sourceRequirement := range profile.SourceRequirements {
				mergedRequirement := mergeControlEvidenceRequirementDefaults(requirements.Defaults, sourceRequirement)
				mergedRequirement = mergeControlEvidenceClaimRule(mergedRequirement, claimRule)
				items = append(items, expandedControlEvidenceRequirement{
					Ref:                  ref,
					ProfileID:            strings.TrimSpace(profile.ProfileID),
					ProfileName:          strings.TrimSpace(profile.Name),
					ClaimRuleID:          strings.TrimSpace(claimRule.RuleID),
					SourceRequirement:    mergedRequirement,
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

func controlEvidenceClaimRuleForRef(rules []controlEvidenceClaimRule, ref controlRef) controlEvidenceClaimRule {
	for _, rule := range rules {
		if controlEvidenceProfileApplies(controlEvidenceRequirementProfile{AppliesTo: rule.AppliesTo}, ref) {
			return rule
		}
	}
	return controlEvidenceClaimRule{}
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

func controlEvidenceRequirementRows(items []expandedControlEvidenceRequirement, sourceIndex frameworkSourceIndex) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		row := []string{
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
			item.ClaimRuleID,
			item.SourceRequirement.ClaimStrength,
			item.SourceRequirement.SufficiencyRule,
			item.SourceRequirement.CoverageClaim,
			controlRequirementClaimStatus(item.CoverageStatus),
			item.SourceRequirement.OverclaimGuard,
			item.SourceRequirement.AdjacentControlRationale,
			joinList(item.SourceCapabilityRefs),
			joinList(item.CatalogEvidenceRefs),
			item.CoverageStatus,
		}
		row = append(row, frameworkSourceExportCells(sourceIndex, item.Ref.Framework)...)
		rows = append(rows, row)
	}
	sortRows(rows)
	return rows
}

func findingEvidenceRequirementRows(catalog publicDetectionCatalog, index controlFamilyIndex, capabilitySources []evidenceCapabilitySource, items []expandedControlEvidenceRequirement, sourceIndex frameworkSourceIndex) [][]string {
	byControl := map[string][]expandedControlEvidenceRequirement{}
	for _, item := range items {
		byControl[controlRefKey(item.Ref)] = append(byControl[controlRefKey(item.Ref)], item)
	}
	capabilityIndex := evidenceCapabilityIndex(capabilitySources, index)
	var rows [][]string
	for _, detection := range catalog.Detections {
		controlRefs := publicDetectionControlRefs(detection.ControlRefs, index)
		complianceReview := findingComplianceReviewFor(detection, index, controlRefs)
		sourceCapabilityStatus := sourceCapabilityStatusForDetection(detection, capabilitySources)
		for _, ref := range controlRefs {
			for _, item := range byControl[controlRefKey(ref)] {
				requirementMatchStatus := findingRequirementMatchStatus(detection, item)
				claimStatus := findingRequirementClaimStatus(complianceReview.ComplianceEvidenceStatus, requirementMatchStatus, sourceCapabilityStatus)
				explanation := coverageExplanationForRequirement(detection, ref, item, complianceReview, sourceCapabilityStatus, claimStatus, capabilityIndex)
				row := []string{
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
					joinList(item.SourceRequirement.RequiredFields),
					item.SourceRequirement.FreshnessWindow,
					explanation.Freshness.Status,
					joinList(coverageMissingDimensionLabels(explanation.MissingDimensions)),
					explanation.Owner,
					item.ClaimRuleID,
					item.SourceRequirement.ClaimStrength,
					item.SourceRequirement.SufficiencyRule,
					item.SourceRequirement.CoverageClaim,
					sourceCapabilityStatus,
					complianceReview.ComplianceEvidenceStatus,
					requirementMatchStatus,
					claimStatus,
					findingRequirementEvidenceBasis(requirementMatchStatus, complianceReview.ComplianceEvidenceStatus, sourceCapabilityStatus),
					explanation.EvidencePacketReadiness,
					explanation.NextAction,
					item.SourceRequirement.OverclaimGuard,
					item.SourceRequirement.AdjacentControlRationale,
				}
				row = append(row, frameworkSourceExportCells(sourceIndex, ref.Framework)...)
				rows = append(rows, row)
			}
		}
	}
	sortRows(rows)
	return rows
}

func findingComplianceTagContractRows(catalog publicDetectionCatalog, index controlFamilyIndex, capabilitySources []evidenceCapabilitySource, items []expandedControlEvidenceRequirement, sourceIndex frameworkSourceIndex) [][]string {
	byControl := expandedRequirementsByControl(items)
	capabilityIndex := evidenceCapabilityIndex(capabilitySources, index)
	var rows [][]string
	for _, detection := range catalog.Detections {
		controlRefs := publicDetectionControlRefs(detection.ControlRefs, index)
		complianceReview := findingComplianceReviewFor(detection, index, controlRefs)
		sourceCapabilityStatus := sourceCapabilityStatusForDetection(detection, capabilitySources)
		catalogTagSet := stringSet(uniqueSorted(detection.Tags))
		for _, ref := range controlRefs {
			requirements := byControl[controlRefKey(ref)]
			claimStatus := bestFindingRequirementClaimStatus(detection, requirements, complianceReview, sourceCapabilityStatus)
			sourceCoverageLabels := complianceReview.SourceCoverageRefsByControlKey[controlRefKey(ref)]
			explanation := bestCoverageExplanationForRequirements(detection, ref, requirements, complianceReview, sourceCapabilityStatus, capabilityIndex)
			for _, tag := range complianceReviewTags([]controlRef{ref}) {
				tagSource := "control_ref"
				if _, ok := catalogTagSet[tag]; ok {
					tagSource = "catalog+control_ref"
				}
				row := []string{
					detection.ID,
					detection.Name,
					detection.PackID,
					detection.SourceID,
					detection.EvaluationMode,
					tag,
					tagKind(tag),
					tagSource,
					runtimeTagExportPolicy(claimStatus),
					ref.Label(),
					ref.Family,
					joinList(requirementClaimRuleIDs(requirements)),
					joinList(requirementClaimStrengths(requirements)),
					claimStatus,
					complianceTagBasis(tag),
					joinList(sourceCoverageLabels),
					sourceCapabilityStatus,
					complianceReview.ComplianceEvidenceStatus,
					joinList(requirementProfileIDs(requirements)),
					joinList(requirementSourceIDs(requirements)),
					joinList(requirementFreshnessWindows(requirements)),
					explanation.Freshness.Status,
					joinList(coverageMissingDimensionLabels(explanation.MissingDimensions)),
					explanation.Owner,
					explanation.EvidencePacketReadiness,
					explanation.NextAction,
					joinList(requirementOverclaimGuards(requirements)),
					joinList(requirementAdjacentControlRationales(requirements)),
				}
				row = append(row, frameworkSourceExportCells(sourceIndex, ref.Framework)...)
				rows = append(rows, row)
			}
		}
	}
	sortRows(rows)
	return rows
}

func coverageGapExplanationRows(catalog publicDetectionCatalog, index controlFamilyIndex, capabilitySources []evidenceCapabilitySource, items []expandedControlEvidenceRequirement) [][]string {
	byControl := expandedRequirementsByControl(items)
	capabilityIndex := evidenceCapabilityIndex(capabilitySources, index)
	var rows [][]string
	for _, detection := range catalog.Detections {
		controlRefs := publicDetectionControlRefs(detection.ControlRefs, index)
		complianceReview := findingComplianceReviewFor(detection, index, controlRefs)
		sourceCapabilityStatus := sourceCapabilityStatusForDetection(detection, capabilitySources)
		for _, ref := range controlRefs {
			for _, item := range byControl[controlRefKey(ref)] {
				requirementMatchStatus := findingRequirementMatchStatus(detection, item)
				claimStatus := findingRequirementClaimStatus(complianceReview.ComplianceEvidenceStatus, requirementMatchStatus, sourceCapabilityStatus)
				explanation := coverageExplanationForRequirement(detection, ref, item, complianceReview, sourceCapabilityStatus, claimStatus, capabilityIndex)
				rows = append(rows, coverageGapExplanationRow(explanation, requirementMatchStatus))
			}
		}
	}
	sortRows(rows)
	return rows
}

func coverageGapExplanationRow(explanation coverageops.CoverageGapExplanation, requirementMatchStatus string) []string {
	return []string{
		explanation.FindingID,
		explanation.FindingName,
		explanation.FindingPackID,
		explanation.FindingSourceID,
		explanation.FindingEvaluationMode,
		explanation.ControlRef,
		explanation.ControlFamily,
		explanation.RequirementProfile,
		explanation.RequirementSourceID,
		explanation.RequirementEntityType,
		string(explanation.CoverageState),
		explanation.ClaimStatus,
		requirementMatchStatus,
		explanation.ComplianceEvidenceStatus,
		explanation.SourceCapabilityStatus,
		abbreviateCSVCell(explanation.Explanation, 96),
		joinLimitedStrings(coverageGraphFactLabels(explanation.GraphEvidence), 3),
		joinLimitedStrings(coverageEvidenceFactLabels(explanation.BoundedEvidence), 2),
		joinLimitedStrings(coverageCitationLabels(explanation.SourceCitations), 2),
		joinLimitedStrings(coverageCitationLabels(explanation.PolicyCitations), 2),
		joinList(coverageMissingDimensionLabels(explanation.MissingDimensions)),
		coverageFreshnessLabel(explanation.Freshness),
		joinLimitedStrings(coverageProvenanceLabels(explanation.Provenance), 1),
		explanation.Confidence,
		joinList(explanation.UnsupportedClaims),
		explanation.Owner,
		explanation.ManualReviewState,
		explanation.EvidencePacketReadiness,
		explanation.NextAction,
		abbreviateCSVCell(explanation.OverclaimGuard, 96),
		abbreviateCSVCell(explanation.AdjacentControlRationale, 96),
		explanation.LLMContext.Question,
		joinList(explanation.LLMContext.AnswerBasis),
		joinList(explanation.LLMContext.MissingDimensions),
		abbreviateCSVCell(explanation.LLMContext.NextAction, 96),
		abbreviateCSVCell(explanation.LLMContext.OverclaimGuard, 96),
		joinList(explanation.PolicyDocumentRefs),
		joinList(explanation.ExceptionRefs),
		joinList(explanation.RemediationRefs),
	}
}

func coverageExplanationForRequirement(detection publicDetection, ref controlRef, item expandedControlEvidenceRequirement, review findingComplianceReview, sourceCapabilityStatus string, claimStatus string, capabilityIndex map[string]indexedEvidenceCapability) coverageops.CoverageGapExplanation {
	return coverageops.BuildCoverageGapExplanation(coverageops.CoverageGapExplanationInput{
		CoverageFindingContext: coverageops.CoverageFindingContext{
			FindingID:             strings.TrimSpace(detection.ID),
			FindingName:           strings.TrimSpace(detection.Name),
			FindingSourceID:       strings.TrimSpace(detection.SourceID),
			FindingEvaluationMode: strings.TrimSpace(detection.EvaluationMode),
			FindingPackID:         strings.TrimSpace(detection.PackID),
			Control:               coverageControlRef(ref),
			ControlFamily:         strings.TrimSpace(ref.Family),
		},
		CoverageRequirementContext: coverageops.CoverageRequirementContext{
			RequirementProfile:      strings.TrimSpace(item.ProfileID),
			RequirementSourceID:     strings.TrimSpace(item.SourceRequirement.SourceID),
			RequirementEntityType:   strings.TrimSpace(item.SourceRequirement.EntityType),
			RequiredFields:          item.SourceRequirement.RequiredFields,
			FreshnessWindow:         strings.TrimSpace(item.SourceRequirement.FreshnessWindow),
			PolicyDocumentRequired:  policyDocumentRequiredForRequirement(item),
			ManualReviewRequired:    manualReviewRequiredForRequirement(item),
			ExceptionReviewRequired: false,
		},
		CoverageClaimContext: coverageops.CoverageClaimContext{
			ClaimRuleID:              strings.TrimSpace(item.ClaimRuleID),
			ClaimStrength:            strings.TrimSpace(item.SourceRequirement.ClaimStrength),
			CoverageClaim:            strings.TrimSpace(item.SourceRequirement.CoverageClaim),
			OverclaimGuard:           strings.TrimSpace(item.SourceRequirement.OverclaimGuard),
			AdjacentControlRationale: strings.TrimSpace(item.SourceRequirement.AdjacentControlRationale),
			ComplianceEvidenceStatus: strings.TrimSpace(review.ComplianceEvidenceStatus),
			SourceCapabilityStatus:   strings.TrimSpace(sourceCapabilityStatus),
			ClaimStatus:              strings.TrimSpace(claimStatus),
		},
		CoverageEvidenceContext: coverageops.CoverageEvidenceContext{
			SourceFacts:        coverageSourceFactsForRequirement(detection.SourceCoverageRefs, ref, item, capabilityIndex),
			PolicyDocumentRefs: policyDocumentRefsForRequirement(detection, item),
		},
	})
}

func bestCoverageExplanationForRequirements(detection publicDetection, ref controlRef, requirements []expandedControlEvidenceRequirement, review findingComplianceReview, sourceCapabilityStatus string, capabilityIndex map[string]indexedEvidenceCapability) coverageops.CoverageGapExplanation {
	var best coverageops.CoverageGapExplanation
	bestRank := 1000
	for _, requirement := range requirements {
		matchStatus := findingRequirementMatchStatus(detection, requirement)
		claimStatus := findingRequirementClaimStatus(review.ComplianceEvidenceStatus, matchStatus, sourceCapabilityStatus)
		explanation := coverageExplanationForRequirement(detection, ref, requirement, review, sourceCapabilityStatus, claimStatus, capabilityIndex)
		rank := claimStatusRank(claimStatus)
		if best.Version == "" || rank < bestRank {
			best = explanation
			bestRank = rank
		}
	}
	if best.Version != "" {
		return best
	}
	return coverageops.BuildCoverageGapExplanation(coverageops.CoverageGapExplanationInput{
		CoverageFindingContext: coverageops.CoverageFindingContext{
			FindingID:             strings.TrimSpace(detection.ID),
			FindingName:           strings.TrimSpace(detection.Name),
			FindingSourceID:       strings.TrimSpace(detection.SourceID),
			FindingEvaluationMode: strings.TrimSpace(detection.EvaluationMode),
			FindingPackID:         strings.TrimSpace(detection.PackID),
			Control:               coverageControlRef(ref),
			ControlFamily:         strings.TrimSpace(ref.Family),
		},
		CoverageClaimContext: coverageops.CoverageClaimContext{
			ComplianceEvidenceStatus: strings.TrimSpace(review.ComplianceEvidenceStatus),
			SourceCapabilityStatus:   strings.TrimSpace(sourceCapabilityStatus),
			ClaimStatus:              "requirement_missing",
		},
		CoverageEvidenceContext: coverageops.CoverageEvidenceContext{
			SourceFacts: coverageSourceFactsForRequirement(detection.SourceCoverageRefs, ref, expandedControlEvidenceRequirement{}, capabilityIndex),
		},
	})
}

func policyDocumentRequiredForRequirement(item expandedControlEvidenceRequirement) bool {
	sourceID := strings.TrimSpace(item.SourceRequirement.SourceID)
	profileID := strings.TrimSpace(item.ProfileID)
	return sourceID == "grc_policy_repository" ||
		strings.Contains(profileID, "governance") ||
		strings.Contains(profileID, "change")
}

func manualReviewRequiredForRequirement(item expandedControlEvidenceRequirement) bool {
	sourceID := strings.TrimSpace(item.SourceRequirement.SourceID)
	return sourceID == "control_owner_review" || sourceID == "manual_review"
}

func policyDocumentRefsForRequirement(detection publicDetection, item expandedControlEvidenceRequirement) []string {
	if !policyDocumentRequiredForRequirement(item) {
		return nil
	}
	if id := strings.TrimSpace(detection.ID); id != "" {
		return []string{"policy-placeholder:" + id}
	}
	return nil
}

func coverageSourceFactsForRequirement(refs []publicDetectionSourceCoverageRef, control controlRef, item expandedControlEvidenceRequirement, capabilityIndex map[string]indexedEvidenceCapability) []coverageops.CoverageSourceFactInput {
	var facts []coverageops.CoverageSourceFactInput
	requiredSource := strings.TrimSpace(item.SourceRequirement.SourceID)
	controlKey := controlRefKey(control)
	for _, ref := range refs {
		sourceID := strings.TrimSpace(ref.SourceID)
		matchedRefs := publicDetectionControlRefs(ref.MatchedControlRefs, nil)
		matchesControl := false
		for _, matched := range matchedRefs {
			if controlRefKey(matched) == controlKey {
				matchesControl = true
				break
			}
		}
		if requiredSource != "" && !strings.EqualFold(sourceID, requiredSource) && !matchesControl {
			continue
		}
		capability := capabilityIndex[sourceID+"\x00"+strings.TrimSpace(ref.DimensionID)]
		facts = append(facts, coverageops.CoverageSourceFactInput{
			SourceID:       sourceID,
			DimensionID:    strings.TrimSpace(ref.DimensionID),
			DimensionType:  firstNonEmpty(strings.TrimSpace(ref.DimensionType), strings.TrimSpace(capability.Dimension.DimensionType)),
			SupportLevel:   firstNonEmpty(strings.TrimSpace(ref.SupportLevel), strings.TrimSpace(capability.Dimension.SupportLevel)),
			HighValue:      ref.HighValue || capability.Dimension.HighValue,
			Families:       uniqueSorted(append(append([]string{}, ref.Families...), capability.Dimension.Families...)),
			EvidenceTypes:  uniqueSorted(append(append([]string{}, ref.EvidenceTypes...), capability.Dimension.EvidenceTypes...)),
			ControlDomains: uniqueSorted(append(append([]string{}, ref.ControlDomains...), capability.Dimension.ControlDomains...)),
			ControlRefs:    coverageControlRefs(matchedRefs),
			ProvenanceURNs: []string{
				"coverage:" + sourceCoverageRefLabel(ref),
			},
		})
	}
	return facts
}

func coverageControlRef(ref controlRef) coverageops.ControlRef {
	return coverageops.ControlRef{FrameworkName: strings.TrimSpace(ref.Framework), ControlID: strings.TrimSpace(ref.ControlID)}
}

func coverageControlRefs(refs []controlRef) []coverageops.ControlRef {
	out := make([]coverageops.ControlRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, coverageControlRef(ref))
	}
	return out
}

func coverageGraphFactLabels(facts []coverageops.CoverageGraphFact) []string {
	labels := make([]string, 0, len(facts))
	for _, fact := range facts {
		label := strings.TrimSpace(shortCoverageNode(fact.From) + ">" + fact.Relation + ">" + shortCoverageNode(fact.To))
		if fact.Basis != "" && len(fact.Basis) <= 48 {
			label += " [" + fact.Basis + "]"
		}
		labels = append(labels, label)
	}
	return uniqueSorted(labels)
}

func shortCoverageNode(node string) string {
	kind, value, ok := strings.Cut(strings.TrimSpace(node), ":")
	if !ok {
		return strings.TrimSpace(node)
	}
	switch kind {
	case "finding":
		return "finding"
	case "control":
		return "control"
	case "requirement":
		return "requirement"
	case "source_fact":
		return "source:" + value
	case "source_requirement":
		return "source_requirement:" + value
	default:
		return kind + ":" + value
	}
}

func coverageEvidenceFactLabels(facts []coverageops.CoverageEvidenceFact) []string {
	labels := make([]string, 0, len(facts))
	for _, fact := range facts {
		parts := []string{strings.TrimSpace(fact.SourceID + "/" + fact.DimensionID)}
		if fact.DimensionType != "" {
			parts = append(parts, "type="+fact.DimensionType)
		}
		if fact.SupportLevel != "" {
			parts = append(parts, "support="+fact.SupportLevel)
		}
		if len(fact.EvidenceTypes) != 0 {
			parts = append(parts, "evidence_types="+fmt.Sprint(len(fact.EvidenceTypes)))
		}
		labels = append(labels, strings.Join(parts, " "))
	}
	return uniqueSorted(labels)
}

func coverageCitationLabels(citations []coverageops.CoverageCitation) []string {
	labels := make([]string, 0, len(citations))
	for _, citation := range citations {
		parts := []string{strings.TrimSpace(citation.Surface + ":" + citation.Reference)}
		if citation.Status != "" {
			parts = append(parts, "status="+citation.Status)
		}
		if len(citation.URNs) != 0 {
			parts = append(parts, "urn_count="+fmt.Sprint(len(citation.URNs)))
		}
		labels = append(labels, strings.TrimSpace(strings.Join(parts, " ")))
	}
	return uniqueSorted(labels)
}

func coverageFreshnessLabel(freshness coverageops.CoverageFreshness) string {
	parts := []string{}
	if freshness.Requirement != "" {
		parts = append(parts, "requirement="+freshness.Requirement)
	}
	if freshness.Status != "" {
		parts = append(parts, "status="+freshness.Status)
	}
	if len(freshness.Signals) != 0 {
		parts = append(parts, "signals="+joinList(freshness.Signals))
	}
	return strings.Join(parts, " ")
}

func coverageMissingDimensionLabels(dimensions []coverageops.CoverageMissingDimension) []string {
	labels := make([]string, 0, len(dimensions))
	for _, dimension := range dimensions {
		parts := []string{strings.TrimSpace(dimension.SourceID + " " + dimension.EntityType)}
		labels = append(labels, strings.TrimSpace(strings.Join(parts, " ")))
	}
	return uniqueSorted(labels)
}

func coverageProvenanceLabels(items []coverageops.CoverageProvenance) []string {
	labels := make([]string, 0, len(items))
	for _, item := range items {
		parts := []string{strings.TrimSpace(item.Surface)}
		if item.Scope != "" {
			parts = append(parts, "scope="+item.Scope)
		}
		if item.Status != "" {
			parts = append(parts, "status="+item.Status)
		}
		if len(item.URNs) != 0 {
			parts = append(parts, "urn_count="+fmt.Sprint(len(item.URNs)))
		}
		labels = append(labels, strings.Join(parts, " "))
	}
	return uniqueSorted(labels)
}

func abbreviateCSVCell(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return strings.TrimSpace(value[:limit-3]) + "..."
}

func bestFindingRequirementClaimStatus(detection publicDetection, requirements []expandedControlEvidenceRequirement, review findingComplianceReview, sourceCapabilityStatus string) string {
	best := ""
	for _, requirement := range requirements {
		matchStatus := findingRequirementMatchStatus(detection, requirement)
		status := findingRequirementClaimStatus(review.ComplianceEvidenceStatus, matchStatus, sourceCapabilityStatus)
		if best == "" || claimStatusRank(status) < claimStatusRank(best) {
			best = status
		}
	}
	if best == "" {
		if strings.TrimSpace(review.ComplianceEvidenceStatus) == "control_only" {
			return "control_ref_review_claim"
		}
		return "requirement_missing"
	}
	return best
}

func claimStatusRank(status string) int {
	switch strings.TrimSpace(status) {
	case "source_evidence_claim":
		return 10
	case "partial_source_evidence_claim":
		return 20
	case "requirement_source_available":
		return 30
	case "requirement_defined":
		return 40
	case "control_ref_review_claim":
		return 50
	case "requirement_missing":
		return 60
	default:
		return 100
	}
}

func runtimeTagExportPolicy(claimStatus string) string {
	switch strings.TrimSpace(claimStatus) {
	case "source_evidence_claim":
		return "runtime_candidate"
	case "partial_source_evidence_claim":
		return "runtime_candidate_with_review"
	default:
		return "review_only"
	}
}

func complianceTagBasis(tag string) string {
	switch {
	case strings.HasPrefix(tag, "framework:"):
		return "framework_from_control_ref"
	case strings.HasPrefix(tag, "control:"):
		return "control_from_control_ref"
	case strings.HasPrefix(tag, "control-family:"):
		return "control_family_from_catalog_index"
	default:
		return "catalog_tag"
	}
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

func controlRequirementClaimStatus(coverageStatus string) string {
	switch strings.TrimSpace(coverageStatus) {
	case "direct_source_backed":
		return "source_evidence_claim"
	case "partial_source_backed":
		return "partial_source_evidence_claim"
	case "direct_with_source_context":
		return "source_link_review_required"
	case "direct_control_only":
		return "source_backing_required"
	case "source_capability_only":
		return "finding_mapping_required"
	case "review_context_only":
		return "mapping_review_required"
	case "framework_catalog_only":
		return "scope_decision_required"
	default:
		return "coverage_review_required"
	}
}

func findingRequirementClaimStatus(complianceEvidenceStatus string, requirementMatchStatus string, sourceCapabilityStatus string) string {
	switch strings.TrimSpace(requirementMatchStatus) {
	case "finding_source_matches_requirement", "source_coverage_matches_requirement":
		if strings.TrimSpace(complianceEvidenceStatus) == "source_backed" {
			return "source_evidence_claim"
		}
		return "partial_source_evidence_claim"
	}
	if strings.TrimSpace(complianceEvidenceStatus) == "control_only" {
		return "control_ref_review_claim"
	}
	if strings.TrimSpace(sourceCapabilityStatus) == "source_capability_defined" {
		return "requirement_source_available"
	}
	return "requirement_defined"
}

func findingRequirementEvidenceBasis(requirementMatchStatus string, complianceEvidenceStatus string, sourceCapabilityStatus string) string {
	switch strings.TrimSpace(requirementMatchStatus) {
	case "finding_source_matches_requirement":
		return "finding_source_matches_requirement_source"
	case "source_coverage_matches_requirement":
		return "source_coverage_matches_requirement_source"
	}
	if strings.TrimSpace(complianceEvidenceStatus) == "control_only" {
		return "direct_control_ref_without_source_coverage"
	}
	if strings.TrimSpace(sourceCapabilityStatus) == "source_capability_defined" {
		return "yaml_source_capability_without_matching_finding_evidence"
	}
	return "requirement_row_without_source_match"
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
	observedCoverage := sourceCoverageAggregate(catalog, index)
	keys := map[string]struct{}{}
	for key := range capabilities {
		keys[key] = struct{}{}
	}
	for key := range observedCoverage {
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
		observed := observedCoverage[key]
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
		workbookManifestRow(4, "Framework Sources", "framework_sources.csv", "framework source", "framework", "Which authority, version, and evidence model governs each framework?", "internal/compliance/framework_sources.yaml", true),
		workbookManifestRow(5, "Framework Gaps", "framework_control_gap_map.csv", "framework control", "framework; control_id", "Which controls are direct, indirect, or uncovered?", "internal/compliance/control_families.yaml plus framework_sources.yaml", true),
		workbookManifestRow(6, "Coverage Candidates", "framework_coverage_candidates.csv", "framework control work item", "framework; control_id; candidate_type", "What author or evidence work should happen next?", "derived from framework control enrichment", true),
		workbookManifestRow(7, "Control Requirements", "control_evidence_requirements.csv", "control evidence requirement", "framework; control_id; requirement_profile; requirement_source_id", "What evidence does each control require?", "internal/compliance/control_evidence_requirements.yaml plus framework_sources.yaml", true),
		workbookManifestRow(8, "Finding Requirements", "finding_evidence_requirement_map.csv", "finding-control-requirement link", "finding_id; framework; control_id; requirement_profile; requirement_source_id", "Which requirement source does each mapped finding point toward?", "public catalog plus control evidence requirements", true),
		workbookManifestRow(9, "Coverage Explanations", "coverage_gap_explanations.csv", "finding-control-requirement explanation", "finding_id; control_ref; requirement_profile; requirement_source_id", "Why is coverage source-backed, partial, or missing, and what bounded evidence can an agent cite?", "internal/compliance coverage explanation contract plus generated mapping layers", true),
		workbookManifestRow(10, "Finding Map", "finding_map.csv", "public finding", "finding_id", "What controls, tags, evidence, and review signals attach to each finding?", "internal/findings/public_detection_catalog.json", true),
		workbookManifestRow(11, "Finding Controls", "finding_control_map.csv", "finding-control link", "finding_id; framework; control_id", "Which control links are source-backed, direct-only, or review-needed?", "public catalog source coverage refs", true),
		workbookManifestRow(12, "Finding Tag Contract", "finding_compliance_tag_contract.csv", "finding-control compliance tag", "finding_id; tag; control_ref", "Which compliance tags can become runtime metadata and which remain review-only?", "public catalog control refs plus control evidence requirements", true),
		workbookManifestRow(13, "Finding Review", "finding_compliance_review_map.csv", "public finding review row", "finding_id", "Which findings need audit-language, source, or control review?", "policy_rule_extensions.yaml plus public catalog", true),
		workbookManifestRow(14, "Source Coverage", "source_coverage_map.csv", "finding source coverage ref", "finding_id; coverage_source_id; coverage_dimension_id", "Which source coverage refs support or extend finding controls?", "public catalog source coverage refs", true),
		workbookManifestRow(15, "Source Capability Review", "source_capability_review_map.csv", "source capability", "source_id; dimension_id", "Where do YAML capabilities and catalog coverage differ?", "internal/compliance/evidence_capabilities.yaml", true),
		workbookManifestRow(16, "Evidence Capabilities", "evidence_capabilities.csv", "YAML source capability", "source_id; dimension_id", "What can each source and dimension support?", "internal/compliance/evidence_capabilities.yaml", true),
		workbookManifestRow(17, "Framework Enrichment", "framework_control_enrichment_map.csv", "framework control", "framework; control_id", "What direct findings, source capabilities, and review context enrich each control?", "derived from all mapping layers", true),
		workbookManifestRow(18, "Review Areas", "framework_review_areas.csv", "framework review area", "framework; area_id", "How should controls be grouped for reviewer queues?", "internal/compliance/framework_review_areas.yaml", false),
		workbookManifestRow(19, "Control Relationships", "control_relationships.csv", "control relationship", "framework; control_id; related_framework; related_control_id", "Which controls should be reviewed together?", "internal/compliance/control_relationships.yaml", false),
		workbookManifestRow(20, "Finding Review Areas", "finding_review_area_map.csv", "finding review-area link", "finding_id; framework; area_id", "Which findings enter each framework review queue?", "review areas plus direct control refs", false),
		workbookManifestRow(21, "Finding Relationships", "finding_control_relationship_map.csv", "finding control relationship link", "finding_id; framework; control_id; related_control_id", "Which related controls should be inspected with each finding?", "control relationships plus direct control refs", false),
		workbookManifestRow(22, "Policy Map", "policy_map.csv", "policy rule", "rule_id", "What YAML policy metadata, controls, tags, and audit language exist?", "policies/**/*.yaml", false),
		workbookManifestRow(23, "Policy Controls", "control_map.csv", "policy-control link", "rule_id; framework; control_id", "Which policy rules map to each framework control?", "policies/**/*.yaml", false),
		workbookManifestRow(24, "Policy Tags", "tag_map.csv", "policy-tag link", "rule_id; tag", "Which metadata and derived tags route each policy?", "policies/**/*.yaml", false),
		workbookManifestRow(25, "Finding Tags", "finding_tag_map.csv", "finding-tag link", "finding_id; tag", "Which catalog and derived review tags attach to each finding?", "public catalog plus control refs", false),
		workbookManifestRow(26, "Domain Aliases", "finding_domain_aliases.csv", "finding domain alias", "match_type; match_value", "How are non-policy findings assigned audit domains?", "internal/compliance/policy_rule_extensions.yaml", false),
		workbookManifestRow(27, "YAML Layers", "yaml_layers.csv", "audit language layer", "scope_type; scope", "Which YAML layer supplied default audit language?", "internal/compliance/policy_rule_extensions.yaml", false),
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
		{"7", "framework source registry", "Require internal/compliance/framework_sources.yaml to define one authority, version, lifecycle, source URL, and evidence model for every cataloged framework."},
		{"8", "source coverage reconciliation", "Compare finding control_refs with source coverage matched_control_refs so direct, source-backed, and control-only mappings are visible."},
		{"9", "mapping confidence", "Classify each finding-control edge as high, medium, or review using matched source coverage and YAML source capability status."},
		{"10", "compliance review tags", "Derive framework:, control:, and control-family: tags from control_refs for spreadsheet review. These do not replace runtime finding tags."},
		{"11", "framework review areas", "Group direct control refs from internal/compliance/framework_review_areas.yaml so reviewers can see management-system, safeguard, privacy, AI, and payment-card work queues without changing finding evidence."},
		{"12", "control relationships", "Add alias, child requirement, sibling scope, and evidence dependency hints from internal/compliance/control_relationships.yaml. These links do not make a finding source-backed."},
		{"13", "evidence capabilities", "Compare source and dimension capabilities from internal/compliance/evidence_capabilities.yaml with observed source coverage refs so YAML coverage gaps are visible."},
		{"14", "quality gates", "Fail generation when a finding lacks framework tags, control refs, evidence mode, resolved audit language, rationale, or source capability status."},
		{"15", "control gap status", "Classify each framework control as direct, indirect, or no coverage so mapped controls and review-only gaps are visible."},
		{"16", "control evidence requirements", "Expand first-class evidence requirements from internal/compliance/control_evidence_requirements.yaml across every framework control, then join them with source capabilities, catalog evidence expectations, and framework source metadata."},
		{"17", "claim rules", "Apply framework-specific claim strength, sufficiency rule, coverage claim, overclaim guard, and adjacent-control rationale before exporting requirement rows."},
		{"18", "claim status", "Compute claim status from source coverage, requirement matches, and framework control coverage instead of letting a control reference imply coverage."},
		{"19", "coverage explanations", "Build internal/compliance CoverageGapExplanation objects with graph path facts, bounded evidence, missing dimensions, freshness, provenance, owner state, next action, and overclaim guard before writing spreadsheet rows."},
		{"20", "tag contract", "Export control-derived compliance tags with runtime export policy, claim status, source basis, and guardrails. Runtime candidates require source evidence or partial source evidence."},
		{"21", "coverage candidates", "Create author review rows for controls that need source backing, source-backed findings, mapping review, or scope decisions before coverage can be claimed."},
		{"22", "workbook manifest", "Emit a sheet-order manifest with row grain, primary keys, review questions, source authority, and default workbook inclusion for every generated table."},
		{"23", "spreadsheet", "Generate CSV rows from YAML, the public catalog, coverage explanations, and derived review layers. Do not edit spreadsheet rows back into source by hand."},
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
		"source_coverage_high_value_count", "compliance_evidence_status",
		"evidence_backing_level", "evidence_backing_gaps", "review_flags",
		"source_freshness_requirements", "source_freshness_status", "required_missing_dimensions",
		"manual_review_owner", "evidence_packet_readiness", "next_remediation_action",
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
		"compliance_evidence_status", "evidence_backing_level",
		"evidence_backing_gaps", "review_flags", "source_capability_status",
		"source_freshness_requirements", "source_freshness_status",
		"required_missing_dimensions", "manual_review_owner",
		"evidence_packet_readiness", "next_remediation_action",
	}
}

func complianceQualityIssuesHeader() []string {
	return []string{"scope", "scope_id", "quality_gate", "severity", "status", "detail"}
}

func findingDomainAliasesHeader() []string {
	return []string{"match_type", "match_value", "resolved_domain"}
}

func frameworkSourcesHeader() []string {
	return []string{
		"framework", "framework_id", "framework_version", "framework_lifecycle",
		"framework_authority", "framework_source_type", "framework_source_url",
		"framework_source_status", "framework_control_model",
		"framework_evidence_model", "assessment_notes",
	}
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
		"sample_source_backed_finding_ids", "framework_version", "framework_lifecycle",
		"framework_authority", "framework_source_type", "framework_source_status",
		"framework_source_url", "framework_evidence_model",
	}
}

func frameworkControlGapMapHeader() []string {
	return []string{
		"framework", "control_id", "control_ref", "control_family",
		"coverage_status", "coverage_lane", "gap_type", "direct_finding_count",
		"source_backed_finding_count", "source_matched_finding_count",
		"source_capability_count", "review_context_count", "next_action",
		"framework_version", "framework_lifecycle", "framework_authority",
		"framework_source_type", "framework_source_status", "framework_source_url",
		"framework_evidence_model",
	}
}

func controlEvidenceRequirementsHeader() []string {
	return []string{
		"framework", "control_id", "control_ref", "control_family",
		"requirement_profile", "requirement_name", "requirement_source_id",
		"entity_type", "required_fields", "freshness_window", "assessment_methods",
		"auditor_grade_evidence", "claim_rule_id", "claim_strength",
		"sufficiency_rule", "coverage_claim", "claim_status", "overclaim_guard",
		"adjacent_control_rationale", "source_capability_refs",
		"catalog_evidence_refs", "coverage_status", "framework_version",
		"framework_lifecycle",
		"framework_authority", "framework_source_type", "framework_source_status",
		"framework_source_url", "framework_evidence_model",
	}
}

func findingEvidenceRequirementMapHeader() []string {
	return []string{
		"finding_id", "name", "pack_id", "source_id", "evaluation_mode",
		"framework", "control_id", "control_ref", "control_family",
		"requirement_profile", "requirement_name", "requirement_source_id",
		"entity_type", "required_fields", "freshness_window",
		"source_freshness_status", "required_missing_dimensions",
		"manual_review_owner", "claim_rule_id", "claim_strength",
		"sufficiency_rule", "coverage_claim", "source_capability_status",
		"compliance_evidence_status", "requirement_match_status", "claim_status",
		"runtime_evidence_basis", "evidence_packet_readiness",
		"next_remediation_action", "overclaim_guard", "adjacent_control_rationale",
		"framework_version", "framework_lifecycle", "framework_authority",
		"framework_source_type", "framework_source_status", "framework_source_url",
		"framework_evidence_model",
	}
}

func coverageGapExplanationsHeader() []string {
	return []string{
		"finding_id", "name", "pack_id", "source_id", "evaluation_mode",
		"control_ref", "control_family", "requirement_profile",
		"requirement_source_id", "requirement_entity_type",
		"coverage_state", "claim_status", "requirement_match_status",
		"compliance_evidence_status", "source_capability_status",
		"explanation", "graph_evidence", "bounded_evidence",
		"source_citations", "policy_citations", "missing_dimensions",
		"freshness", "provenance", "confidence", "unsupported_claims",
		"owner", "manual_review_state",
		"evidence_packet_readiness", "next_action", "overclaim_guard",
		"adjacent_control_rationale", "llm_question", "llm_answer_basis",
		"llm_missing_dimensions", "llm_next_action", "llm_overclaim_guard",
		"policy_document_refs", "exception_refs", "remediation_refs",
	}
}

func findingComplianceTagContractHeader() []string {
	return []string{
		"finding_id", "name", "pack_id", "source_id", "evaluation_mode",
		"tag", "tag_kind", "tag_source", "runtime_export_policy",
		"control_ref", "control_family", "claim_rule_ids", "claim_strengths",
		"claim_status", "tag_basis", "source_coverage_refs",
		"source_capability_status", "compliance_evidence_status",
		"requirement_profiles", "requirement_sources",
		"source_freshness_requirements", "source_freshness_status",
		"required_missing_dimensions", "manual_review_owner",
		"evidence_packet_readiness", "next_remediation_action", "overclaim_guards",
		"adjacent_control_rationales", "framework_version",
		"framework_lifecycle", "framework_authority", "framework_source_type",
		"framework_source_status", "framework_source_url",
		"framework_evidence_model",
	}
}

func frameworkCoverageCandidatesHeader() []string {
	return []string{
		"framework", "control_id", "control_ref", "control_family",
		"coverage_status", "gap_type", "candidate_priority", "candidate_type",
		"claim_status", "suggested_finding_domain", "suggested_evidence_type",
		"claim_rule_ids", "claim_strengths", "sufficiency_rules",
		"coverage_claims", "requirement_profiles", "requirement_sources",
		"source_capability_refs", "review_context_refs", "overclaim_guards",
		"adjacent_control_rationales", "next_action", "framework_version",
		"framework_lifecycle",
		"framework_authority", "framework_source_type", "framework_source_status",
		"framework_source_url", "framework_evidence_model",
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
	rawValue := strings.ToLower(strings.TrimSpace(value))
	normalizedValue := normalizeKeywordText(value)
	for _, needle := range needles {
		rawNeedle := strings.ToLower(strings.TrimSpace(needle))
		normalizedNeedle := normalizeKeywordText(needle)
		if normalizedNeedle != "" && strings.Contains(" "+normalizedValue+" ", " "+normalizedNeedle+" ") {
			return true
		}
		if rawNeedle != "" && containsKeywordPunctuation(rawNeedle) && strings.Contains(rawValue, rawNeedle) {
			return true
		}
	}
	return false
}

func containsKeywordPunctuation(value string) bool {
	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
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
