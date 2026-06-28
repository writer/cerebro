package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateFilesIncludesAllPublicDetections(t *testing.T) {
	root := repoRoot(t)
	catalog, err := loadPublicDetectionCatalog(root)
	if err != nil {
		t.Fatalf("load public detection catalog: %v", err)
	}
	files, err := generateFiles(root)
	if err != nil {
		t.Fatalf("generateFiles() error = %v", err)
	}

	findingRows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_map.csv"))
	if got, want := len(findingRows)-1, len(catalog.Detections); got != want {
		t.Fatalf("finding_map.csv rows = %d, want %d public detections", got, want)
	}

	header := findingRows[0]
	idCol := columnIndex(t, header, "finding_id")
	cerebroRow := findRow(t, findingRows, idCol, "cerebro-high-risk-api-access")
	assertCellContains(t, header, cerebroRow, "pack_id", "cerebro")
	assertCellContains(t, header, cerebroRow, "catalog_tags", "tenant-isolation")
	assertCellContains(t, header, cerebroRow, "control_refs", "SOC 2 CC6.1")
	assertCellContains(t, header, cerebroRow, "compliance_review_tags", "framework:soc-2")
	assertCellContains(t, header, cerebroRow, "compliance_review_tags", "control:soc-2:cc6-1")
	assertCellContains(t, header, cerebroRow, "all_review_tags", "tenant-isolation")
	assertCellContains(t, header, cerebroRow, "framework_review_areas", "SOC 2/access-authorization")
	assertCellContains(t, header, cerebroRow, "control_relationship_hints", "SOC 2 CC6.1 -> SOC 2 CC6.2")
	assertCellContains(t, header, cerebroRow, "resolved_audit_domain", "api")
	assertCellContains(t, header, cerebroRow, "audit_language_source", "yaml:domain:api")
	assertCellContains(t, header, cerebroRow, "evidence_type", "application_access_control")
}

func TestResolveFindingAuditDepthYAMLOverridesCatalogFallback(t *testing.T) {
	resolved := resolveFindingAuditDepth(publicDetection{
		ID:                "api-admin-token",
		PackID:            "cerebro",
		SourceID:          "cerebro",
		EvaluationMode:    "event",
		Tags:              []string{"tenant-isolation"},
		EvidenceType:      "catalog_evidence",
		AssessmentMethods: []string{"catalog_method"},
		AuditorGuidance:   "catalog guidance",
		RiskStatement:     "catalog risk",
		RemediationIntent: "catalog remediation",
	}, policyRuleExtensions{
		Defaults: policyRuleExtension{
			EvidenceType: "default_evidence",
		},
		EvidenceModes: map[string]policyRuleExtension{
			"event": {
				RiskStatement: "mode risk",
			},
		},
		Domains: map[string]policyRuleExtension{
			"api": {
				EvidenceType:      "domain_evidence",
				AssessmentMethods: []string{"domain_method"},
				AuditorGuidance:   "domain guidance",
				RiskStatement:     "domain risk",
			},
		},
		FindingDomains: findingDomainAliases{
			Tags: map[string]string{"tenant-isolation": "api"},
		},
		Findings: map[string]policyRuleExtension{
			"api-admin-token": {
				RemediationIntent: "finding remediation",
			},
		},
	})

	if resolved.Domain != "api" {
		t.Fatalf("Domain = %q, want api", resolved.Domain)
	}
	if resolved.EvidenceType != "domain_evidence" {
		t.Fatalf("EvidenceType = %q, want domain_evidence", resolved.EvidenceType)
	}
	if got := strings.Join(resolved.AssessmentMethods, ","); got != "domain_method" {
		t.Fatalf("AssessmentMethods = %q, want domain_method", got)
	}
	if resolved.AuditorGuidance != "domain guidance" {
		t.Fatalf("AuditorGuidance = %q, want domain guidance", resolved.AuditorGuidance)
	}
	if resolved.RiskStatement != "domain risk" {
		t.Fatalf("RiskStatement = %q, want domain risk", resolved.RiskStatement)
	}
	if resolved.RemediationIntent != "finding remediation" {
		t.Fatalf("RemediationIntent = %q, want finding remediation", resolved.RemediationIntent)
	}
	assertStringSliceContains(t, resolved.FieldSources, "yaml:domain:api")
	assertStringSliceContains(t, resolved.FieldSources, "yaml:finding:api-admin-token")
}

func TestResolveFindingAuditDepthPolicyCatalogRemainsAuthoritative(t *testing.T) {
	resolved := resolveFindingAuditDepth(publicDetection{
		ID:                "api-policy",
		PackID:            "policy",
		SourceID:          "policy",
		EvaluationMode:    "event",
		Tags:              []string{"tenant-isolation"},
		EvidenceType:      "catalog_evidence",
		AssessmentMethods: []string{"catalog_method"},
		AuditorGuidance:   "catalog guidance",
		RiskStatement:     "catalog risk",
		RemediationIntent: "catalog remediation",
	}, policyRuleExtensions{
		Domains: map[string]policyRuleExtension{
			"api": {
				EvidenceType:      "domain_evidence",
				AssessmentMethods: []string{"domain_method"},
				AuditorGuidance:   "domain guidance",
				RiskStatement:     "domain risk",
				RemediationIntent: "domain remediation",
			},
		},
		FindingDomains: findingDomainAliases{
			Tags: map[string]string{"tenant-isolation": "api"},
		},
	})

	if resolved.Domain != "api" {
		t.Fatalf("Domain = %q, want api", resolved.Domain)
	}
	if resolved.EvidenceType != "catalog_evidence" {
		t.Fatalf("EvidenceType = %q, want catalog_evidence", resolved.EvidenceType)
	}
	if got := strings.Join(resolved.AssessmentMethods, ","); got != "catalog_method" {
		t.Fatalf("AssessmentMethods = %q, want catalog_method", got)
	}
	if resolved.AuditorGuidance != "catalog guidance" {
		t.Fatalf("AuditorGuidance = %q, want catalog guidance", resolved.AuditorGuidance)
	}
	if resolved.RiskStatement != "catalog risk" {
		t.Fatalf("RiskStatement = %q, want catalog risk", resolved.RiskStatement)
	}
	if resolved.RemediationIntent != "catalog remediation" {
		t.Fatalf("RemediationIntent = %q, want catalog remediation", resolved.RemediationIntent)
	}
	assertStringSliceContains(t, resolved.FieldSources, "catalog")
}

func TestControlRefSetsNormalizeGDPRArticleAliases(t *testing.T) {
	detectionRefs := []controlRef{
		{Framework: "GDPR", ControlID: "Article 13"},
		{Framework: "SOC 2", ControlID: "CC6.1"},
	}
	coverageRefs := []controlRef{
		{Framework: " gdpr ", ControlID: "Art.13"},
	}

	matched := intersectControlRefs(detectionRefs, coverageRefs)
	if len(matched) != 1 {
		t.Fatalf("intersectControlRefs returned %d refs, want 1", len(matched))
	}
	if matched[0].Label() != "GDPR Article 13" {
		t.Fatalf("matched ref = %q, want GDPR Article 13", matched[0].Label())
	}

	missing := differenceControlRefs(detectionRefs, coverageRefs)
	if len(missing) != 1 {
		t.Fatalf("differenceControlRefs returned %d refs, want 1", len(missing))
	}
	if missing[0].Label() != "SOC 2 CC6.1" {
		t.Fatalf("missing ref = %q, want SOC 2 CC6.1", missing[0].Label())
	}
}

func TestGenerateFilesIncludesFindingTagAndSourceCoverageMaps(t *testing.T) {
	files, err := generateFiles(repoRoot(t))
	if err != nil {
		t.Fatalf("generateFiles() error = %v", err)
	}

	tagRows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_tag_map.csv"))
	tagHeader := tagRows[0]
	tagCol := columnIndex(t, tagHeader, "tag")
	findingCol := columnIndex(t, tagHeader, "finding_id")
	sourceCol := columnIndex(t, tagHeader, "tag_source")
	foundComplianceTag := false
	for _, row := range tagRows[1:] {
		if row[tagCol] == "framework:soc-2" && row[findingCol] == "cerebro-high-risk-api-access" {
			if row[sourceCol] != "control_ref" {
				t.Fatalf("framework:soc-2 tag_source = %q, want control_ref", row[sourceCol])
			}
			foundComplianceTag = true
			break
		}
	}
	if !foundComplianceTag {
		t.Fatal("finding_tag_map.csv missing control-ref compliance tag for cerebro-high-risk-api-access")
	}

	coverageRows := readGeneratedCSV(t, generatedFileByName(t, files, "source_coverage_map.csv"))
	coverageHeader := coverageRows[0]
	coverageFindingCol := columnIndex(t, coverageHeader, "finding_id")
	coverageSourceCol := columnIndex(t, coverageHeader, "coverage_source_id")
	coverageDimensionCol := columnIndex(t, coverageHeader, "coverage_dimension_id")
	for _, row := range coverageRows[1:] {
		if row[coverageFindingCol] == "aws-s3-bucket-no-public-access" && row[coverageSourceCol] == "aws" && row[coverageDimensionCol] == "s3_bucket" {
			return
		}
	}
	t.Fatal("source_coverage_map.csv missing aws/s3_bucket coverage for aws-s3-bucket-no-public-access")
}

func TestGenerateFilesIncludesComplianceReviewMap(t *testing.T) {
	files, err := generateFiles(repoRoot(t))
	if err != nil {
		t.Fatalf("generateFiles() error = %v", err)
	}

	reviewRows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_compliance_review_map.csv"))
	reviewHeader := reviewRows[0]
	reviewFindingCol := columnIndex(t, reviewHeader, "finding_id")
	reviewFlagsCol := columnIndex(t, reviewHeader, "review_flags")
	for _, row := range reviewRows[1:] {
		flags := row[reviewFlagsCol]
		for _, notWant := range []string{
			"missing_evidence_type",
			"missing_assessment_methods",
			"missing_auditor_guidance",
			"missing_risk_statement",
			"missing_remediation_intent",
			"unresolved_audit_domain",
		} {
			if strings.Contains(flags, notWant) {
				t.Fatalf("finding_compliance_review_map.csv row %s has %s in review_flags %q", row[reviewFindingCol], notWant, flags)
			}
		}
	}
	s3Row := findRow(t, reviewRows, reviewFindingCol, "aws-s3-bucket-no-public-access")
	assertCellContains(t, reviewHeader, s3Row, "compliance_evidence_status", "partial_source_backed")
	assertCellEquals(t, reviewHeader, s3Row, "source_matched_control_ref_count", "6")
	assertCellEquals(t, reviewHeader, s3Row, "source_backed_control_ref_count", "6")
	assertCellEquals(t, reviewHeader, s3Row, "control_refs_without_source_match_count", "8")
	assertCellContains(t, reviewHeader, s3Row, "review_flags", "partial_source_backed_control_refs")

	controlRows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_control_map.csv"))
	controlHeader := controlRows[0]
	controlFindingCol := columnIndex(t, controlHeader, "finding_id")
	controlRefCol := columnIndex(t, controlHeader, "control_ref")
	controlMatchSourceCol := columnIndex(t, controlHeader, "control_match_source")
	sourceBackedRows := 0
	for _, row := range controlRows[1:] {
		if row[controlFindingCol] == "aws-s3-bucket-no-public-access" && row[controlMatchSourceCol] == "finding_control_ref+source_coverage_ref" {
			sourceBackedRows++
		}
		if row[controlFindingCol] == "aws-s3-bucket-no-public-access" && row[controlRefCol] == "SOC 2 CC6.6" {
			assertCellEquals(t, controlHeader, row, "control_match_source", "finding_control_ref+source_coverage_ref")
			assertCellContains(t, controlHeader, row, "source_coverage_refs", "aws/s3_bucket")
		}
	}
	if sourceBackedRows != 6 {
		t.Fatalf("source-backed control rows for aws-s3-bucket-no-public-access = %d, want 6", sourceBackedRows)
	}
	cc66Row := findRowByColumns(t, controlRows, map[int]string{
		controlFindingCol: "aws-s3-bucket-no-public-access",
		controlRefCol:     "SOC 2 CC6.6",
	})
	assertCellContains(t, controlHeader, cc66Row, "source_coverage_refs", "aws/s3_bucket")
}

func TestOverviewCapturesExpectedSourceCoverageExpansion(t *testing.T) {
	files, err := generateFiles(repoRoot(t))
	if err != nil {
		t.Fatalf("generateFiles() error = %v", err)
	}

	overviewRows := readGeneratedCSV(t, generatedFileByName(t, files, "overview.csv"))
	assertOverviewMetric(t, overviewRows, "source-coverage rows", "4074")
	assertOverviewMetric(t, overviewRows, "detections missing source coverage refs", "475")
	assertOverviewMetric(t, overviewRows, "detections source-backed", "168")
	assertOverviewMetric(t, overviewRows, "detections partial source-backed", "943")
	assertOverviewMetric(t, overviewRows, "detections control-only", "475")
}

func TestGenerateFilesIncludesFindingDomainAliasMap(t *testing.T) {
	files, err := generateFiles(repoRoot(t))
	if err != nil {
		t.Fatalf("generateFiles() error = %v", err)
	}

	aliasRows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_domain_aliases.csv"))
	header := aliasRows[0]
	matchTypeCol := columnIndex(t, header, "match_type")
	matchValueCol := columnIndex(t, header, "match_value")
	resolvedDomainCol := columnIndex(t, header, "resolved_domain")
	for _, row := range aliasRows[1:] {
		if row[matchTypeCol] == "pack" && row[matchValueCol] == "anthropic" {
			if got := row[resolvedDomainCol]; got != "secrets" {
				t.Fatalf("anthropic resolved_domain = %q, want secrets", got)
			}
			return
		}
	}
	t.Fatal("finding_domain_aliases.csv missing anthropic pack alias")
}

func TestGenerateFilesIncludesYAMLReviewContextMaps(t *testing.T) {
	files, err := generateFiles(repoRoot(t))
	if err != nil {
		t.Fatalf("generateFiles() error = %v", err)
	}

	relationshipRows := readGeneratedCSV(t, generatedFileByName(t, files, "control_relationships.csv"))
	relationshipHeader := relationshipRows[0]
	relationshipFrameworkCol := columnIndex(t, relationshipHeader, "framework")
	relationshipControlCol := columnIndex(t, relationshipHeader, "control_id")
	relationshipRelatedCol := columnIndex(t, relationshipHeader, "related_control_id")
	relationshipUseCol := columnIndex(t, relationshipHeader, "evidence_use")
	foundPCIChildHint := false
	for _, row := range relationshipRows[1:] {
		if row[relationshipFrameworkCol] == "PCI DSS v4.0.1" && row[relationshipControlCol] == "8.3" && row[relationshipRelatedCol] == "8.3.6" {
			if row[relationshipUseCol] != "review_hint" {
				t.Fatalf("PCI DSS 8.3 -> 8.3.6 evidence_use = %q, want review_hint", row[relationshipUseCol])
			}
			foundPCIChildHint = true
			break
		}
	}
	if !foundPCIChildHint {
		t.Fatal("control_relationships.csv missing PCI DSS 8.3 -> 8.3.6 review hint")
	}

	areaRows := readGeneratedCSV(t, generatedFileByName(t, files, "framework_review_areas.csv"))
	areaHeader := areaRows[0]
	areaFrameworkCol := columnIndex(t, areaHeader, "framework")
	areaIDCol := columnIndex(t, areaHeader, "area_id")
	foundAIPlanningArea := false
	for _, row := range areaRows[1:] {
		if row[areaFrameworkCol] == "ISO 42001" && row[areaIDCol] == "ai-management-planning" {
			assertCellContains(t, areaHeader, row, "control_refs", "ISO 42001 6.1")
			foundAIPlanningArea = true
			break
		}
	}
	if !foundAIPlanningArea {
		t.Fatal("framework_review_areas.csv missing ISO 42001 AI planning area")
	}

	findingRelationshipRows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_control_relationship_map.csv"))
	findingRelationshipHeader := findingRelationshipRows[0]
	findingRelationshipFindingCol := columnIndex(t, findingRelationshipHeader, "finding_id")
	findingRelationshipControlCol := columnIndex(t, findingRelationshipHeader, "control_id")
	findingRelationshipRelatedCol := columnIndex(t, findingRelationshipHeader, "related_control_id")
	foundFindingRelationship := false
	for _, row := range findingRelationshipRows[1:] {
		if row[findingRelationshipFindingCol] == "aws-alb-no-authentication" && row[findingRelationshipControlCol] == "8.3" && row[findingRelationshipRelatedCol] == "8.3.6" {
			assertCellContains(t, findingRelationshipHeader, row, "relationship", "child_requirement")
			foundFindingRelationship = true
			break
		}
	}
	if !foundFindingRelationship {
		t.Fatal("finding_control_relationship_map.csv missing aws-alb-no-authentication PCI authentication review hint")
	}

	findingAreaRows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_review_area_map.csv"))
	findingAreaHeader := findingAreaRows[0]
	findingAreaFindingCol := columnIndex(t, findingAreaHeader, "finding_id")
	findingAreaIDCol := columnIndex(t, findingAreaHeader, "area_id")
	foundFindingArea := false
	for _, row := range findingAreaRows[1:] {
		if row[findingAreaFindingCol] == "ai-risk-assessment" && row[findingAreaIDCol] == "ai-management-planning" {
			assertCellContains(t, findingAreaHeader, row, "matched_control_refs", "ISO 42001 6.1")
			foundFindingArea = true
			break
		}
	}
	if !foundFindingArea {
		t.Fatal("finding_review_area_map.csv missing ai-risk-assessment ISO 42001 planning area")
	}

	capabilityRows := readGeneratedCSV(t, generatedFileByName(t, files, "evidence_capabilities.csv"))
	capabilityHeader := capabilityRows[0]
	capabilitySourceCol := columnIndex(t, capabilityHeader, "source_id")
	capabilityDimensionCol := columnIndex(t, capabilityHeader, "dimension_id")
	foundAWSS3Capability := false
	for _, row := range capabilityRows[1:] {
		if row[capabilitySourceCol] == "aws" && row[capabilityDimensionCol] == "s3_bucket" {
			assertCellContains(t, capabilityHeader, row, "control_refs", "SOC 2 CC6.6")
			assertCellContains(t, capabilityHeader, row, "control_refs", "ISO 27001:2022 A.8.24")
			foundAWSS3Capability = true
			break
		}
	}
	if !foundAWSS3Capability {
		t.Fatal("evidence_capabilities.csv missing aws/s3_bucket capability")
	}

	sourceCapabilityRows := readGeneratedCSV(t, generatedFileByName(t, files, "source_capability_review_map.csv"))
	sourceCapabilityHeader := sourceCapabilityRows[0]
	sourceCapabilitySourceCol := columnIndex(t, sourceCapabilityHeader, "source_id")
	sourceCapabilityDimensionCol := columnIndex(t, sourceCapabilityHeader, "dimension_id")
	foundSourceCapability := false
	for _, row := range sourceCapabilityRows[1:] {
		if row[sourceCapabilitySourceCol] == "github" && row[sourceCapabilityDimensionCol] == "code_security_alerts" {
			assertCellContains(t, sourceCapabilityHeader, row, "yaml_capability_control_refs", "SOC 2 CC7.1")
			assertCellContains(t, sourceCapabilityHeader, row, "catalog_matched_control_refs", "SOC 2 CC7.1")
			foundSourceCapability = true
			break
		}
	}
	if !foundSourceCapability {
		t.Fatal("source_capability_review_map.csv missing github/code_security_alerts capability review row")
	}

	frameworkControlRows := readGeneratedCSV(t, generatedFileByName(t, files, "framework_control_enrichment_map.csv"))
	frameworkControlHeader := frameworkControlRows[0]
	frameworkControlFrameworkCol := columnIndex(t, frameworkControlHeader, "framework")
	frameworkControlControlCol := columnIndex(t, frameworkControlHeader, "control_id")
	for _, row := range frameworkControlRows[1:] {
		if row[frameworkControlFrameworkCol] == "SOC 2" && row[frameworkControlControlCol] == "CC6.1" {
			assertCellContains(t, frameworkControlHeader, row, "source_capability_refs", "okta/users")
			assertCellContains(t, frameworkControlHeader, row, "review_area_refs", "SOC 2/access-authorization")
			assertCellContains(t, frameworkControlHeader, row, "outbound_relationship_refs", "SOC 2 CC6.2")
			assertCellContains(t, frameworkControlHeader, row, "enrichment_status", "direct_source_backed")
			return
		}
	}
	t.Fatal("framework_control_enrichment_map.csv missing SOC 2 CC6.1 enrichment row")
}

func TestGenerateFilesIncludesComplianceQualityGates(t *testing.T) {
	files, err := generateFiles(repoRoot(t))
	if err != nil {
		t.Fatalf("generateFiles() error = %v", err)
	}

	qualityRows := readGeneratedCSV(t, generatedFileByName(t, files, "compliance_quality_issues.csv"))
	if len(qualityRows) != 1 {
		t.Fatalf("compliance_quality_issues.csv rows = %d, want only header", len(qualityRows))
	}

	findingRows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_map.csv"))
	findingHeader := findingRows[0]
	findingIDCol := columnIndex(t, findingHeader, "finding_id")
	s3Row := findRow(t, findingRows, findingIDCol, "aws-s3-bucket-no-public-access")
	assertCellContains(t, findingHeader, s3Row, "source_capability_status", "source_capability_defined")

	gapRows := readGeneratedCSV(t, generatedFileByName(t, files, "framework_control_gap_map.csv"))
	gapHeader := gapRows[0]
	frameworkCol := columnIndex(t, gapHeader, "framework")
	controlCol := columnIndex(t, gapHeader, "control_id")
	foundDirect := false
	foundNone := false
	for _, row := range gapRows[1:] {
		if row[frameworkCol] == "SOC 2" && row[controlCol] == "CC6.1" {
			assertCellContains(t, gapHeader, row, "coverage_status", "direct_source_backed")
			assertCellContains(t, gapHeader, row, "coverage_lane", "direct")
			assertCellContains(t, gapHeader, row, "gap_type", "none")
			foundDirect = true
		}
		if row[frameworkCol] == "ISO 27001:2022" && row[controlCol] == "A.7.8" {
			assertCellContains(t, gapHeader, row, "coverage_status", "framework_catalog_only")
			assertCellContains(t, gapHeader, row, "coverage_lane", "none")
			assertCellContains(t, gapHeader, row, "gap_type", "no_mapping_or_evidence")
			foundNone = true
		}
	}
	if !foundDirect {
		t.Fatal("framework_control_gap_map.csv missing SOC 2 CC6.1 direct coverage row")
	}
	if !foundNone {
		t.Fatal("framework_control_gap_map.csv missing ISO 27001:2022 A.7.8 no-coverage row")
	}
}

func TestGenerateFilesIncludesControlEvidenceRequirements(t *testing.T) {
	files, err := generateFiles(repoRoot(t))
	if err != nil {
		t.Fatalf("generateFiles() error = %v", err)
	}

	requirementRows := readGeneratedCSV(t, generatedFileByName(t, files, "control_evidence_requirements.csv"))
	requirementHeader := requirementRows[0]
	frameworkCol := columnIndex(t, requirementHeader, "framework")
	controlCol := columnIndex(t, requirementHeader, "control_id")
	profileCol := columnIndex(t, requirementHeader, "requirement_profile")
	sourceCol := columnIndex(t, requirementHeader, "requirement_source_id")

	socAccessRow := findRequirementRow(t, requirementRows, frameworkCol, controlCol, profileCol, sourceCol, "SOC 2", "CC6.1", "identity-access", "okta")
	assertCellContains(t, requirementHeader, socAccessRow, "required_fields", "factors")
	assertCellContains(t, requirementHeader, socAccessRow, "source_capability_refs", "okta/users")
	assertCellContains(t, requirementHeader, socAccessRow, "coverage_status", "direct_source_backed")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "SOC 2", "CC6.1", "logging-monitoring")

	isoCryptoRow := findRequirementRow(t, requirementRows, frameworkCol, controlCol, profileCol, sourceCol, "ISO 27001:2022", "A.8.24", "data-protection", "aws")
	assertCellContains(t, requirementHeader, isoCryptoRow, "required_fields", "encryption_state")
	assertCellContains(t, requirementHeader, isoCryptoRow, "source_capability_refs", "aws/s3_bucket")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "ISO 27001:2022", "A.8.24", "logging-monitoring")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "DORA", "Art.18", "data-protection")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "DORA", "Art.30", "data-protection")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "SOC 2", "A1.1", "ai-governance")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "SOC 2", "PI1.1", "privacy-rights")

	ccpaPrivacyRow := findRequirementRow(t, requirementRows, frameworkCol, controlCol, profileCol, sourceCol, "CCPA", "1798.100", "privacy-rights", "data_inventory")
	assertCellContains(t, requirementHeader, ccpaPrivacyRow, "required_fields", "legal_basis")

	baselineRow := findRequirementRow(t, requirementRows, frameworkCol, controlCol, profileCol, sourceCol, "ISO 27001:2022", "A.7.8", "baseline-control-review", "control_owner_review")
	assertCellContains(t, requirementHeader, baselineRow, "assessment_methods", "interview")

	findingRequirementRows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_evidence_requirement_map.csv"))
	findingRequirementHeader := findingRequirementRows[0]
	findingCol := columnIndex(t, findingRequirementHeader, "finding_id")
	findingControlCol := columnIndex(t, findingRequirementHeader, "control_id")
	findingProfileCol := columnIndex(t, findingRequirementHeader, "requirement_profile")
	findingRequirementSourceCol := columnIndex(t, findingRequirementHeader, "requirement_source_id")
	foundFindingRequirement := false
	for _, row := range findingRequirementRows[1:] {
		if row[findingCol] == "cerebro-high-risk-api-access" && row[findingControlCol] == "CC6.1" && row[findingProfileCol] == "identity-access" && row[findingRequirementSourceCol] == "okta" {
			assertCellContains(t, findingRequirementHeader, row, "requirement_source_id", "okta")
			assertCellContains(t, findingRequirementHeader, row, "freshness_window", "24h")
			foundFindingRequirement = true
			break
		}
	}
	if !foundFindingRequirement {
		t.Fatal("finding_evidence_requirement_map.csv missing identity requirement for cerebro-high-risk-api-access")
	}
}

func TestRequiredReviewContextLoadersRejectMissingFiles(t *testing.T) {
	cases := []struct {
		name string
		load func(string) error
	}{
		{
			name: "framework review areas",
			load: func(root string) error {
				_, err := loadFrameworkReviewAreas(root)
				return err
			},
		},
		{
			name: "control relationships",
			load: func(root string) error {
				_, err := loadControlRelationships(root)
				return err
			},
		},
		{
			name: "evidence capabilities",
			load: func(root string) error {
				_, err := loadEvidenceCapabilities(root)
				return err
			},
		},
		{
			name: "control evidence requirements",
			load: func(root string) error {
				_, err := loadControlEvidenceRequirements(root)
				return err
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.load(t.TempDir())
			if err == nil {
				t.Fatal("loader error = nil, want missing-file error")
			}
			if !strings.Contains(err.Error(), "read internal/compliance/") {
				t.Fatalf("loader error = %v, want read path context", err)
			}
		})
	}
}

func TestComplianceReviewTagsAreDerivedFromControlRefs(t *testing.T) {
	tags := complianceReviewTags([]controlRef{{
		Framework: "SOC 2",
		ControlID: "CC6.1",
		Family:    "SOC 2 CC6 Logical and Physical Access",
	}})
	joined := strings.Join(tags, "; ")
	for _, want := range []string{"framework:soc-2", "control:soc-2:cc6-1", "control-family:soc-2-cc6-logical-and-physical-access"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("complianceReviewTags() = %q, want %q", joined, want)
		}
		if got := tagKind(want); got != "compliance" {
			t.Fatalf("tagKind(%q) = %q, want compliance", want, got)
		}
	}
}

func TestFindingReviewFlagsUseProcessedMappingValues(t *testing.T) {
	detection := publicDetection{
		Tags:        []string{" identity "},
		ControlRefs: []publicDetectionControlRef{{FrameworkName: " ", ControlID: "CC6.1"}},
		SourceCoverageRefs: []publicDetectionSourceCoverageRef{{
			SourceID:    " ",
			DimensionID: " ",
		}},
	}
	flags := findingReviewFlags(
		publicDetectionControlRefs(detection.ControlRefs, controlFamilyIndex{}),
		uniqueSorted(detection.Tags),
		sourceCoverageRefLabels(detection.SourceCoverageRefs),
		resolvedFindingAuditDepth{},
		findingComplianceReview{ComplianceEvidenceStatus: "missing_controls"},
	)
	joined := strings.Join(flags, "; ")
	for _, want := range []string{"missing_control_refs", "missing_source_coverage_refs"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("findingReviewFlags() = %q, want %q", joined, want)
		}
	}
	if strings.Contains(joined, "missing_catalog_tags") {
		t.Fatalf("findingReviewFlags() = %q, did not expect missing_catalog_tags", joined)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %s missing go.mod: %v", root, err)
	}
	return root
}

func generatedFileByName(t *testing.T, files []generatedFile, name string) generatedFile {
	t.Helper()
	for _, file := range files {
		if file.Name == name {
			return file
		}
	}
	t.Fatalf("generated file %s not found", name)
	return generatedFile{}
}

func readGeneratedCSV(t *testing.T, file generatedFile) [][]string {
	t.Helper()
	rows, err := csv.NewReader(bytes.NewReader(file.Content)).ReadAll()
	if err != nil {
		t.Fatalf("read %s: %v", file.Name, err)
	}
	return rows
}

func columnIndex(t *testing.T, header []string, name string) int {
	t.Helper()
	for i, value := range header {
		if value == name {
			return i
		}
	}
	t.Fatalf("header missing column %s in %#v", name, header)
	return -1
}

func findRow(t *testing.T, rows [][]string, column int, value string) []string {
	t.Helper()
	for _, row := range rows[1:] {
		if row[column] == value {
			return row
		}
	}
	t.Fatalf("row with column %d = %s not found", column, value)
	return nil
}

func findRequirementRow(t *testing.T, rows [][]string, frameworkCol int, controlCol int, profileCol int, sourceCol int, framework string, controlID string, profile string, source string) []string {
	t.Helper()
	for _, row := range rows[1:] {
		if row[frameworkCol] == framework && row[controlCol] == controlID && row[profileCol] == profile && row[sourceCol] == source {
			return row
		}
	}
	t.Fatalf("requirement row not found for %s %s %s %s", framework, controlID, profile, source)
	return nil
}

func assertRequirementRowMissing(t *testing.T, rows [][]string, frameworkCol int, controlCol int, profileCol int, framework string, controlID string, profile string) {
	t.Helper()
	for _, row := range rows[1:] {
		if row[frameworkCol] == framework && row[controlCol] == controlID && row[profileCol] == profile {
			t.Fatalf("unexpected requirement row found for %s %s %s", framework, controlID, profile)
		}
	}
}

func assertCellContains(t *testing.T, header []string, row []string, column string, want string) {
	t.Helper()
	index := columnIndex(t, header, column)
	if !strings.Contains(row[index], want) {
		t.Fatalf("%s = %q, want it to contain %q", column, row[index], want)
	}
}

func assertCellEquals(t *testing.T, header []string, row []string, column string, want string) {
	t.Helper()
	index := columnIndex(t, header, column)
	if row[index] != want {
		t.Fatalf("%s = %q, want %q", column, row[index], want)
	}
}

func assertStringSliceContains(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("%#v does not contain %q", values, want)
}

func findRowByColumns(t *testing.T, rows [][]string, matches map[int]string) []string {
	t.Helper()
	for _, row := range rows[1:] {
		matched := true
		for column, value := range matches {
			if row[column] != value {
				matched = false
				break
			}
		}
		if matched {
			return row
		}
	}
	t.Fatalf("row with columns %#v not found", matches)
	return nil
}

func assertOverviewMetric(t *testing.T, rows [][]string, metric string, want string) {
	t.Helper()
	for _, row := range rows {
		if len(row) >= 2 && row[0] == metric {
			if row[1] != want {
				t.Fatalf("overview metric %q = %q, want %q", metric, row[1], want)
			}
			return
		}
	}
	t.Fatalf("overview metric %q not found", metric)
}
