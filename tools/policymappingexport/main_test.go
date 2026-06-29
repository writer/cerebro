package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var repoGeneratedFilesCache struct {
	once  sync.Once
	files []generatedFile
	err   error
}

func repoGeneratedFiles(t *testing.T) []generatedFile {
	t.Helper()
	repoGeneratedFilesCache.once.Do(func() {
		repoGeneratedFilesCache.files, repoGeneratedFilesCache.err = generateFiles(repoRoot(t))
	})
	if repoGeneratedFilesCache.err != nil {
		t.Fatalf("generateFiles() error = %v", repoGeneratedFilesCache.err)
	}
	return repoGeneratedFilesCache.files
}

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
	files := repoGeneratedFiles(t)

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
	foundAWSCoverage := false
	for _, row := range coverageRows[1:] {
		if row[coverageFindingCol] == "aws-s3-bucket-no-public-access" && row[coverageSourceCol] == "aws" && row[coverageDimensionCol] == "s3_bucket" {
			foundAWSCoverage = true
			break
		}
	}
	if !foundAWSCoverage {
		t.Fatal("source_coverage_map.csv missing aws/s3_bucket coverage for aws-s3-bucket-no-public-access")
	}
	foundEmailCoverage := false
	for _, row := range coverageRows[1:] {
		if row[coverageFindingCol] == "email-domain-authentication-misconfigured" && row[coverageSourceCol] == "email_domain_health" && row[coverageDimensionCol] == "email_authentication_posture" {
			assertCellContains(t, coverageHeader, row, "matched_control_refs", "NIST SP 800-177 TLS-MAIL")
			assertCellContains(t, coverageHeader, row, "evidence_types", "email_authentication_control")
			foundEmailCoverage = true
			break
		}
	}
	if !foundEmailCoverage {
		t.Fatal("source_coverage_map.csv missing email_domain_health/email_authentication_posture coverage for email-domain-authentication-misconfigured")
	}
}

func TestGenerateFilesIncludesFindingComplianceTagContract(t *testing.T) {
	files := repoGeneratedFiles(t)

	rows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_compliance_tag_contract.csv"))
	header := rows[0]
	findingCol := columnIndex(t, header, "finding_id")
	tagCol := columnIndex(t, header, "tag")
	controlRefCol := columnIndex(t, header, "control_ref")

	sourceBackedRow := findRowByColumns(t, rows, map[int]string{
		findingCol:    "aws-s3-bucket-no-public-access",
		tagCol:        "control:soc-2:cc6-6",
		controlRefCol: "SOC 2 CC6.6",
	})
	assertCellEquals(t, header, sourceBackedRow, "runtime_export_policy", "runtime_candidate_with_review")
	assertCellEquals(t, header, sourceBackedRow, "claim_status", "partial_source_evidence_claim")
	assertCellContains(t, header, sourceBackedRow, "source_coverage_refs", "aws/s3_bucket")
	assertCellContains(t, header, sourceBackedRow, "claim_rule_ids", "trust-services-operating-evidence")
	assertCellContains(t, header, sourceBackedRow, "overclaim_guards", "control reference alone")

	reviewOnlyRow := findRowByColumns(t, rows, map[int]string{
		findingCol:    "cerebro-high-risk-api-access",
		tagCol:        "control:soc-2:cc6-1",
		controlRefCol: "SOC 2 CC6.1",
	})
	assertCellEquals(t, header, reviewOnlyRow, "runtime_export_policy", "review_only")
	assertCellContains(t, header, reviewOnlyRow, "tag_basis", "control_from_control_ref")
	assertCellContains(t, header, reviewOnlyRow, "adjacent_control_rationales", "points of focus")

	emailRow := findRowByColumns(t, rows, map[int]string{
		findingCol:    "email-domain-authentication-misconfigured",
		tagCol:        "control:nist-sp-800-177:tls-mail",
		controlRefCol: "NIST SP 800-177 TLS-MAIL",
	})
	assertCellEquals(t, header, emailRow, "runtime_export_policy", "runtime_candidate")
	assertCellEquals(t, header, emailRow, "claim_status", "source_evidence_claim")
	assertCellContains(t, header, emailRow, "claim_rule_ids", "trustworthy-email-authentication-evidence")
	assertCellContains(t, header, emailRow, "source_coverage_refs", "email_domain_health/email_authentication_posture")
	assertCellEquals(t, header, emailRow, "source_capability_status", "source_capability_defined")
	assertCellEquals(t, header, emailRow, "source_freshness_requirements", "email_domain_health=24h")
	assertCellEquals(t, header, emailRow, "source_freshness_status", "freshness_requirement_defined")
	assertCellEquals(t, header, emailRow, "required_missing_dimensions", "")
	assertCellEquals(t, header, emailRow, "manual_review_owner", "email_security_owner")
	assertCellEquals(t, header, emailRow, "evidence_packet_readiness", "ready_for_packet")
	assertCellEquals(t, header, emailRow, "next_remediation_action", "Package runtime evidence and keep freshness within the stated window.")
}

func TestGenerateFilesIncludesComplianceReviewMap(t *testing.T) {
	files := repoGeneratedFiles(t)

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
	assertCellEquals(t, reviewHeader, s3Row, "evidence_backing_level", "partial_runtime_evidence")
	assertCellContains(t, reviewHeader, s3Row, "evidence_backing_gaps", "control_refs_without_source_match")
	assertCellContains(t, reviewHeader, s3Row, "source_freshness_requirements", "aws=24h")
	assertCellEquals(t, reviewHeader, s3Row, "source_freshness_status", "freshness_review_required")
	assertCellContains(t, reviewHeader, s3Row, "required_missing_dimensions", "control_owner_review control_evidence_packet")
	assertCellEquals(t, reviewHeader, s3Row, "manual_review_owner", "identity_owner")
	assertCellEquals(t, reviewHeader, s3Row, "evidence_packet_readiness", "missing_required_source_dimensions")
	assertCellEquals(t, reviewHeader, s3Row, "next_remediation_action", "Connect the required source dimension or document a manual evidence owner.")
	assertCellEquals(t, reviewHeader, s3Row, "source_matched_control_ref_count", "7")
	assertCellEquals(t, reviewHeader, s3Row, "source_backed_control_ref_count", "7")
	assertCellEquals(t, reviewHeader, s3Row, "control_refs_without_source_match_count", "7")
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
			assertCellContains(t, controlHeader, row, "mapping_confidence", "high")
			assertCellContains(t, controlHeader, row, "mapping_rationale", "matched source coverage")
			assertCellContains(t, controlHeader, row, "source_coverage_refs", "aws/s3_bucket")
		}
	}
	if sourceBackedRows != 7 {
		t.Fatalf("source-backed control rows for aws-s3-bucket-no-public-access = %d, want 7", sourceBackedRows)
	}
	cc66Row := findRowByColumns(t, controlRows, map[int]string{
		controlFindingCol: "aws-s3-bucket-no-public-access",
		controlRefCol:     "SOC 2 CC6.6",
	})
	assertCellContains(t, controlHeader, cc66Row, "source_coverage_refs", "aws/s3_bucket")

	unbackedRow := findRowByColumns(t, controlRows, map[int]string{
		controlFindingCol: "aws-s3-bucket-no-public-access",
		controlRefCol:     "CIS AWS Foundations Benchmark v2.0 2.1.5",
	})
	assertCellEquals(t, controlHeader, unbackedRow, "control_match_source", "finding_control_ref")
	assertCellEquals(t, controlHeader, unbackedRow, "mapping_confidence", "review")
	assertCellContains(t, controlHeader, unbackedRow, "mapping_rationale", "does not currently back this control")
}

func TestGenerateFilesIncludesOperationalRequirementActions(t *testing.T) {
	files := repoGeneratedFiles(t)

	rows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_evidence_requirement_map.csv"))
	header := rows[0]
	findingCol := columnIndex(t, header, "finding_id")
	controlRefCol := columnIndex(t, header, "control_ref")
	requirementSourceCol := columnIndex(t, header, "requirement_source_id")

	emailRow := findRowByColumns(t, rows, map[int]string{
		findingCol:           "email-domain-authentication-misconfigured",
		controlRefCol:        "NIST SP 800-177 TLS-MAIL",
		requirementSourceCol: "email_domain_health",
	})
	assertCellContains(t, header, emailRow, "required_fields", "dmarc_policy")
	assertCellEquals(t, header, emailRow, "source_freshness_status", "freshness_requirement_defined")
	assertCellEquals(t, header, emailRow, "required_missing_dimensions", "")
	assertCellEquals(t, header, emailRow, "manual_review_owner", "email_security_owner")
	assertCellEquals(t, header, emailRow, "evidence_packet_readiness", "ready_for_packet")
	assertCellEquals(t, header, emailRow, "next_remediation_action", "Package runtime evidence and keep freshness within the stated window.")

	reviewRow := findRowByColumns(t, rows, map[int]string{
		findingCol:           "email-domain-authentication-misconfigured",
		controlRefCol:        "ISO 27001:2022 A.5.14",
		requirementSourceCol: "control_owner_review",
	})
	assertCellEquals(t, header, reviewRow, "source_freshness_status", "freshness_review_required")
	assertCellContains(t, header, reviewRow, "required_missing_dimensions", "control_owner_review control_evidence_packet")
	assertCellEquals(t, header, reviewRow, "manual_review_owner", "control_owner")
	assertCellEquals(t, header, reviewRow, "evidence_packet_readiness", "missing_required_source_dimensions")
	assertCellEquals(t, header, reviewRow, "next_remediation_action", "Connect the required source dimension or document a manual evidence owner.")
}

func TestGenerateFilesIncludesCoverageGapExplanations(t *testing.T) {
	files := repoGeneratedFiles(t)

	rows := readGeneratedCSV(t, generatedFileByName(t, files, "coverage_gap_explanations.csv"))
	header := rows[0]
	findingCol := columnIndex(t, header, "finding_id")
	controlRefCol := columnIndex(t, header, "control_ref")
	requirementSourceCol := columnIndex(t, header, "requirement_source_id")

	emailRow := findRowByColumns(t, rows, map[int]string{
		findingCol:           "email-domain-authentication-misconfigured",
		controlRefCol:        "NIST SP 800-177 TLS-MAIL",
		requirementSourceCol: "email_domain_health",
	})
	assertCellEquals(t, header, emailRow, "coverage_state", "source_backed")
	assertCellContains(t, header, emailRow, "graph_evidence", "observes_dimension")
	assertCellContains(t, header, emailRow, "graph_evidence", "cites_graph_provenance")
	assertCellContains(t, header, emailRow, "bounded_evidence", "email_domain_health/email_authentication_posture")
	assertCellContains(t, header, emailRow, "source_citations", "source_fact:email_domain_health/email_authentication_posture")
	assertCellContains(t, header, emailRow, "freshness", "status=freshness_requirement_defined")
	assertCellEquals(t, header, emailRow, "confidence", "high")
	assertCellEquals(t, header, emailRow, "unsupported_claims", "")
	assertCellEquals(t, header, emailRow, "evidence_packet_readiness", "ready_for_packet")
	assertCellContains(t, header, emailRow, "adjacent_control_rationale", "mail-domain control")
	assertCellContains(t, header, emailRow, "llm_question", "Why is NIST SP 800-177 TLS-MAIL coverage source_backed")
	assertCellContains(t, header, emailRow, "llm_answer_basis", "bounded_evidence=2")
	assertCellContains(t, header, emailRow, "llm_next_action", "same_as:next_action")
	assertCellContains(t, header, emailRow, "llm_overclaim_guard", "same_as:overclaim_guard")

	reviewRow := findRowByColumns(t, rows, map[int]string{
		findingCol:           "email-domain-authentication-misconfigured",
		controlRefCol:        "ISO 27001:2022 A.5.14",
		requirementSourceCol: "control_owner_review",
	})
	assertCellEquals(t, header, reviewRow, "coverage_state", "partial")
	assertCellContains(t, header, reviewRow, "missing_dimensions", "control_owner_review control_evidence_packet")
	assertCellContains(t, header, reviewRow, "unsupported_claims", "missing_required_source_dimension:control_owner_review/control_evidence_packet")
	assertCellEquals(t, header, reviewRow, "manual_review_state", "owner_review_required")
	assertCellContains(t, header, reviewRow, "llm_missing_dimensions", "control_owner_review/control_evidence_packet")
	assertCellContains(t, header, reviewRow, "overclaim_guard", "Do not claim")
}

func TestGeneratedPolicyMappingCSVsStayBelowGitHubBlobLimit(t *testing.T) {
	files := repoGeneratedFiles(t)

	const maxCSVBlobBytes = 95 * 1024 * 1024
	for _, file := range files {
		if !strings.HasSuffix(file.Name, ".csv") {
			continue
		}
		if got := len(file.Content); got > maxCSVBlobBytes {
			t.Fatalf("%s size = %d bytes, want <= %d bytes", file.Name, got, maxCSVBlobBytes)
		}
	}
}

func TestOverviewCapturesExpectedSourceCoverageExpansion(t *testing.T) {
	files := repoGeneratedFiles(t)

	overviewRows := readGeneratedCSV(t, generatedFileByName(t, files, "overview.csv"))
	assertOverviewMetric(t, overviewRows, "source-coverage rows", "4422")
	assertOverviewMetric(t, overviewRows, "detections missing source coverage refs", "346")
	assertOverviewMetric(t, overviewRows, "detections source-backed", "419")
	assertOverviewMetric(t, overviewRows, "detections partial source-backed", "830")
	assertOverviewMetric(t, overviewRows, "detections control-only", "346")
}

func TestGenerateFilesIncludesFindingDomainAliasMap(t *testing.T) {
	files := repoGeneratedFiles(t)

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
	files := repoGeneratedFiles(t)

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
			assertCellContains(t, frameworkControlHeader, row, "enrichment_status", "partial_source_backed")
			return
		}
	}
	t.Fatal("framework_control_enrichment_map.csv missing SOC 2 CC6.1 enrichment row")
}

func TestFrameworkControlEnrichmentStatusSeparatesPartialSourceBacking(t *testing.T) {
	fullyBacked := frameworkControlEnrichment{
		DirectFindingIDs:       []string{"finding-a", "finding-b"},
		SourceBackedFindingIDs: []string{"finding-a", "finding-b"},
	}
	if got := frameworkControlEnrichmentStatus(fullyBacked); got != "direct_source_backed" {
		t.Fatalf("fully backed status = %q, want direct_source_backed", got)
	}
	if got := frameworkControlGapType("direct_source_backed"); got != "none" {
		t.Fatalf("fully backed gap type = %q, want none", got)
	}

	partial := frameworkControlEnrichment{
		DirectFindingIDs:       []string{"finding-a", "finding-b"},
		SourceBackedFindingIDs: []string{"finding-a"},
	}
	if got := frameworkControlEnrichmentStatus(partial); got != "partial_source_backed" {
		t.Fatalf("partial status = %q, want partial_source_backed", got)
	}
	if got := frameworkControlCoverageLane("partial_source_backed"); got != "direct" {
		t.Fatalf("partial coverage lane = %q, want direct", got)
	}
	if got := frameworkControlGapType("partial_source_backed"); got != "partial_source_backing" {
		t.Fatalf("partial gap type = %q, want partial_source_backing", got)
	}
	if got := frameworkControlNextAction("partial_source_backed"); !strings.Contains(got, "Add source backing") {
		t.Fatalf("partial next action = %q, want source backing action", got)
	}
}

func TestGenerateFilesIncludesComplianceQualityGates(t *testing.T) {
	files := repoGeneratedFiles(t)

	qualityRows := readGeneratedCSV(t, generatedFileByName(t, files, "compliance_quality_issues.csv"))
	if len(qualityRows) != 1 {
		t.Fatalf("compliance_quality_issues.csv rows = %d, want only header", len(qualityRows))
	}

	findingRows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_map.csv"))
	findingHeader := findingRows[0]
	findingIDCol := columnIndex(t, findingHeader, "finding_id")
	s3Row := findRow(t, findingRows, findingIDCol, "aws-s3-bucket-no-public-access")
	assertCellContains(t, findingHeader, s3Row, "source_capability_status", "source_capability_defined")
	assertCellEquals(t, findingHeader, s3Row, "evidence_backing_level", "partial_runtime_evidence")
	assertCellContains(t, findingHeader, s3Row, "evidence_backing_gaps", "control_refs_without_source_match")

	reviewRows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_compliance_review_map.csv"))
	reviewHeader := reviewRows[0]
	if reviewFlagsCol, sourceCapabilityCol := columnIndex(t, reviewHeader, "review_flags"), columnIndex(t, reviewHeader, "source_capability_status"); reviewFlagsCol > sourceCapabilityCol {
		t.Fatalf("finding_compliance_review_map.csv source_capability_status column must append after review_flags")
	}

	gapRows := readGeneratedCSV(t, generatedFileByName(t, files, "framework_control_gap_map.csv"))
	gapHeader := gapRows[0]
	frameworkCol := columnIndex(t, gapHeader, "framework")
	controlCol := columnIndex(t, gapHeader, "control_id")
	foundDirect := false
	foundNone := false
	for _, row := range gapRows[1:] {
		if row[frameworkCol] == "SOC 2" && row[controlCol] == "CC6.1" {
			assertCellContains(t, gapHeader, row, "coverage_status", "partial_source_backed")
			assertCellContains(t, gapHeader, row, "coverage_lane", "direct")
			assertCellContains(t, gapHeader, row, "gap_type", "partial_source_backing")
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

func TestGenerateFilesMapsOktaPolicyFindingsToSourceCoverage(t *testing.T) {
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
	findingHeader := findingRows[0]
	findingIDCol := columnIndex(t, findingHeader, "finding_id")
	for _, findingID := range []string{
		"identity-okta-sign-on-rule-without-mfa",
		"identity-okta-privileged-missing-owner",
		"identity-okta-suspended-user-active-assignment",
		"identity-okta-suspended-user-active-group-membership",
		"identity-okta-external-account-no-owner",
		"identity-okta-dormant-admin-role-assignment",
	} {
		row := findRow(t, findingRows, findingIDCol, findingID)
		assertCellContains(t, findingHeader, row, "source_capability_status", "source_capability_defined")
		assertCellContains(t, findingHeader, row, "source_id", "okta")
		assertCellContains(t, findingHeader, row, "evaluation_mode", "graph")
	}

	signOnRow := findRow(t, findingRows, findingIDCol, "identity-okta-sign-on-rule-without-mfa")
	assertCellContains(t, findingHeader, signOnRow, "source_capability_refs", "okta/policy_rules")
	assertCellContains(t, findingHeader, signOnRow, "control_refs", "NIST 800-53 r5 IA-2")
	assertPublicDetectionEvidenceType(t, catalog, "identity-okta-sign-on-rule-without-mfa", "identity_configuration")
	// finding_map evidence_type is the compliance review class; the public catalog assertion above keeps the rule evidence contract pinned.
	assertCellContains(t, findingHeader, signOnRow, "evidence_type", "identity_governance")

	assignmentRow := findRow(t, findingRows, findingIDCol, "identity-okta-suspended-user-active-assignment")
	assertCellContains(t, findingHeader, assignmentRow, "source_capability_refs", "okta/app_assignments")

	groupRow := findRow(t, findingRows, findingIDCol, "identity-okta-suspended-user-active-group-membership")
	assertCellContains(t, findingHeader, groupRow, "source_capability_refs", "okta/group_memberships")

	ownerRow := findRow(t, findingRows, findingIDCol, "identity-okta-privileged-missing-owner")
	assertCellContains(t, findingHeader, ownerRow, "source_capability_refs", "okta/admin_roles")
}

func TestGenerateFilesIncludesFrameworkSourceRegistry(t *testing.T) {
	files := repoGeneratedFiles(t)

	sourceRows := readGeneratedCSV(t, generatedFileByName(t, files, "framework_sources.csv"))
	sourceHeader := sourceRows[0]
	sourceFrameworkCol := columnIndex(t, sourceHeader, "framework")
	socSourceRow := findRow(t, sourceRows, sourceFrameworkCol, "SOC 2")
	assertCellContains(t, sourceHeader, socSourceRow, "framework_authority", "AICPA")
	assertCellContains(t, sourceHeader, socSourceRow, "framework_version", "Trust Services Criteria 2022")
	assertCellContains(t, sourceHeader, socSourceRow, "framework_source_url", "aicpa-cima.com")

	isoPrivacyRow := findRow(t, sourceRows, sourceFrameworkCol, "ISO 27701:2025")
	assertCellContains(t, sourceHeader, isoPrivacyRow, "framework_source_url", "iso.org/standard/27701")
	assertCellContains(t, sourceHeader, isoPrivacyRow, "framework_lifecycle", "current")

	gapRows := readGeneratedCSV(t, generatedFileByName(t, files, "framework_control_gap_map.csv"))
	gapHeader := gapRows[0]
	gapFrameworkCol := columnIndex(t, gapHeader, "framework")
	gapControlCol := columnIndex(t, gapHeader, "control_id")
	socGapRow := findFrameworkControlRow(t, gapRows, gapFrameworkCol, gapControlCol, "SOC 2", "CC6.1")
	assertCellContains(t, gapHeader, socGapRow, "framework_authority", "AICPA")
	assertCellContains(t, gapHeader, socGapRow, "framework_source_type", "trust_services_criteria")
	assertCellContains(t, gapHeader, socGapRow, "framework_evidence_model", "Control design and operating effectiveness")

	requirementRows := readGeneratedCSV(t, generatedFileByName(t, files, "control_evidence_requirements.csv"))
	requirementHeader := requirementRows[0]
	requirementFrameworkCol := columnIndex(t, requirementHeader, "framework")
	requirementControlCol := columnIndex(t, requirementHeader, "control_id")
	requirementProfileCol := columnIndex(t, requirementHeader, "requirement_profile")
	requirementSourceCol := columnIndex(t, requirementHeader, "requirement_source_id")
	socRequirementRow := findRequirementRow(t, requirementRows, requirementFrameworkCol, requirementControlCol, requirementProfileCol, requirementSourceCol, "SOC 2", "CC6.1", "identity-access", "okta")
	assertCellContains(t, requirementHeader, socRequirementRow, "framework_authority", "AICPA")
	assertCellContains(t, requirementHeader, socRequirementRow, "framework_lifecycle", "current")

	manifestRows := readGeneratedCSV(t, generatedFileByName(t, files, "workbook_manifest.csv"))
	manifestHeader := manifestRows[0]
	manifestCSVCol := columnIndex(t, manifestHeader, "csv_file")
	sourceManifestRow := findRow(t, manifestRows, manifestCSVCol, "framework_sources.csv")
	assertCellContains(t, manifestHeader, sourceManifestRow, "worksheet_name", "Framework Sources")
	assertCellContains(t, manifestHeader, sourceManifestRow, "include_by_default", "true")
}

func TestValidateFrameworkSourcesRequiresCatalogCoverage(t *testing.T) {
	catalog := complianceControlCatalog{
		Frameworks: []complianceControlCatalogFramework{
			{Name: "SOC 2"},
			{Name: "ISO 27001:2022"},
		},
	}
	sources := []frameworkSource{
		{
			Framework:       "SOC 2",
			FrameworkID:     "soc2",
			Version:         "Trust Services Criteria 2022",
			Lifecycle:       "current",
			Authority:       "AICPA",
			SourceType:      "trust_services_criteria",
			SourceURL:       "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
			SourceStatus:    "official_landing",
			ControlModel:    "Trust services criteria.",
			EvidenceModel:   "Control design and operating effectiveness evidence.",
			AssessmentNotes: "Use control evidence.",
		},
		{
			Framework:       "Unknown Framework",
			FrameworkID:     "unknown",
			Version:         "current",
			Lifecycle:       "current",
			Authority:       "Unknown",
			SourceType:      "unknown",
			SourceURL:       "https://example.com",
			SourceStatus:    "placeholder",
			ControlModel:    "Unknown controls.",
			EvidenceModel:   "Unknown evidence.",
			AssessmentNotes: "Unknown notes.",
		},
	}

	err := validateFrameworkSources(catalog, sources)
	if err == nil {
		t.Fatal("validateFrameworkSources() error = nil, want coverage error")
	}
	if !strings.Contains(err.Error(), "missing source for ISO 27001:2022") {
		t.Fatalf("validateFrameworkSources() error = %v, want missing framework source", err)
	}
	if !strings.Contains(err.Error(), "unknown framework Unknown Framework") {
		t.Fatalf("validateFrameworkSources() error = %v, want unknown framework source", err)
	}
}

func TestValidateControlEvidenceRequirementsRequiresClaimFields(t *testing.T) {
	err := validateControlEvidenceRequirements(controlEvidenceRequirementCatalog{
		Defaults: controlEvidenceRequirementDefaults{
			SourceID:             "control_owner_review",
			EntityType:           "control_evidence_packet",
			EvidenceUse:          "operating_effectiveness",
			RequiredFields:       []string{"control_ref"},
			FreshnessWindow:      "90d",
			AssessmentMethods:    []string{"examine"},
			AuditorGradeEvidence: "Evidence identifies the control.",
		},
		Profiles: []controlEvidenceRequirementProfile{{
			ProfileID: "baseline-control-review",
			Name:      "Baseline Control Review Evidence",
			Fallback:  true,
			SourceRequirements: []controlEvidenceSourceRequirement{{
				SourceID:             "control_owner_review",
				EntityType:           "control_evidence_packet",
				EvidenceUse:          "operating_effectiveness",
				RequiredFields:       []string{"control_ref"},
				FreshnessWindow:      "90d",
				AssessmentMethods:    []string{"examine"},
				AuditorGradeEvidence: "Evidence identifies the control.",
			}},
		}},
	})
	if err == nil {
		t.Fatal("validateControlEvidenceRequirements() error = nil, want claim field error")
	}
	for _, want := range []string{"missing claim_strength", "missing sufficiency_rule", "missing coverage_claim", "missing overclaim_guard", "missing adjacent_control_rationale"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("validateControlEvidenceRequirements() error = %v, want %q", err, want)
		}
	}
}

func TestGenerateFilesIncludesControlEvidenceRequirements(t *testing.T) {
	files := repoGeneratedFiles(t)

	requirementRows := readGeneratedCSV(t, generatedFileByName(t, files, "control_evidence_requirements.csv"))
	requirementHeader := requirementRows[0]
	frameworkCol := columnIndex(t, requirementHeader, "framework")
	controlCol := columnIndex(t, requirementHeader, "control_id")
	profileCol := columnIndex(t, requirementHeader, "requirement_profile")
	sourceCol := columnIndex(t, requirementHeader, "requirement_source_id")
	entityCol := columnIndex(t, requirementHeader, "entity_type")

	socAccessRow := findRowByColumns(t, requirementRows, map[int]string{
		frameworkCol: "SOC 2",
		controlCol:   "CC6.1",
		profileCol:   "identity-access",
		sourceCol:    "okta",
		entityCol:    "identity_user",
	})
	assertCellContains(t, requirementHeader, socAccessRow, "required_fields", "factors")
	assertCellEquals(t, requirementHeader, socAccessRow, "evidence_use", "review_context")
	assertCellContains(t, requirementHeader, socAccessRow, "source_capability_refs", "okta/users")
	assertCellContains(t, requirementHeader, socAccessRow, "coverage_status", "partial_source_backed")
	assertCellEquals(t, requirementHeader, socAccessRow, "claim_rule_id", "trust-services-operating-evidence")
	assertCellEquals(t, requirementHeader, socAccessRow, "claim_strength", "source_or_sample_backed")
	assertCellEquals(t, requirementHeader, socAccessRow, "sufficiency_rule", "design_and_operating_effectiveness")
	assertCellEquals(t, requirementHeader, socAccessRow, "claim_status", "partial_source_evidence_claim")
	assertCellContains(t, requirementHeader, socAccessRow, "overclaim_guard", "control reference alone")

	socReviewRow := findRowByColumns(t, requirementRows, map[int]string{
		frameworkCol: "SOC 2",
		controlCol:   "CC6.1",
		profileCol:   "identity-access",
		sourceCol:    "okta",
		entityCol:    "identity_access_review",
	})
	assertCellEquals(t, requirementHeader, socReviewRow, "evidence_use", "operating_effectiveness")
	assertCellContains(t, requirementHeader, socReviewRow, "required_fields", "reviewer_id")
	assertCellContains(t, requirementHeader, socReviewRow, "required_fields", "review_period_end")
	assertCellContains(t, requirementHeader, socReviewRow, "required_fields", "source_observed_at")
	assertCellContains(t, requirementHeader, socReviewRow, "source_capability_refs", "okta/access_review_operations")

	socDormantRow := findRowByColumns(t, requirementRows, map[int]string{
		frameworkCol: "SOC 2",
		controlCol:   "CC6.1",
		profileCol:   "identity-access",
		sourceCol:    "okta",
		entityCol:    "dormant_account_review",
	})
	assertCellEquals(t, requirementHeader, socDormantRow, "evidence_use", "operating_effectiveness")
	assertCellContains(t, requirementHeader, socDormantRow, "source_capability_refs", "okta/dormant_account_reviews")

	socExternalRow := findRowByColumns(t, requirementRows, map[int]string{
		frameworkCol: "SOC 2",
		controlCol:   "CC6.2",
		profileCol:   "identity-access",
		sourceCol:    "okta",
		entityCol:    "external_account_review",
	})
	assertCellEquals(t, requirementHeader, socExternalRow, "evidence_use", "operating_effectiveness")
	assertCellContains(t, requirementHeader, socExternalRow, "required_fields", "sponsor_id")
	assertCellContains(t, requirementHeader, socExternalRow, "source_capability_refs", "okta/external_account_reviews")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "SOC 2", "CC6.1", "logging-monitoring")

	isoCryptoRow := findRequirementRow(t, requirementRows, frameworkCol, controlCol, profileCol, sourceCol, "ISO 27001:2022", "A.8.24", "data-protection", "aws")
	assertCellContains(t, requirementHeader, isoCryptoRow, "required_fields", "encryption_state")
	assertCellContains(t, requirementHeader, isoCryptoRow, "source_capability_refs", "aws/s3_bucket")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "ISO 27001:2022", "A.8.24", "logging-monitoring")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "DORA", "Art.18", "data-protection")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "DORA", "Art.30", "data-protection")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "SOC 2", "CC1.5", "identity-access")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "DORA", "Art.9", "logging-monitoring")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "CIS Controls v8", "11", "data-protection")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "NIST 800-53 r5", "PA-1", "change-configuration")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "SOC 2", "A1.1", "ai-governance")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "SOC 2", "PI1.1", "privacy-rights")

	ccpaPrivacyRow := findRequirementRow(t, requirementRows, frameworkCol, controlCol, profileCol, sourceCol, "CCPA", "1798.100", "privacy-rights", "data_inventory")
	assertCellContains(t, requirementHeader, ccpaPrivacyRow, "required_fields", "legal_basis")
	isoPrivacyRow := findRequirementRow(t, requirementRows, frameworkCol, controlCol, profileCol, sourceCol, "ISO 27701", "7.2.6", "privacy-rights", "data_inventory")
	assertCellContains(t, requirementHeader, isoPrivacyRow, "required_fields", "data_category")
	assertCellContains(t, requirementHeader, isoPrivacyRow, "framework_lifecycle", "withdrawn_replaced_by_2025")

	baselineRow := findRequirementRow(t, requirementRows, frameworkCol, controlCol, profileCol, sourceCol, "ISO 27001:2022", "A.7.8", "baseline-control-review", "control_owner_review")
	assertCellContains(t, requirementHeader, baselineRow, "assessment_methods", "interview")
	assertCellEquals(t, requirementHeader, baselineRow, "claim_rule_id", "iso-management-system-evidence")
	assertCellEquals(t, requirementHeader, baselineRow, "claim_status", "scope_decision_required")
	assertCellContains(t, requirementHeader, baselineRow, "adjacent_control_rationale", "management-system objective")

	emailTrustRow := findRequirementRow(t, requirementRows, frameworkCol, controlCol, profileCol, sourceCol, "NIST SP 800-177", "TLS-MAIL", "email-authentication", "email_domain_health")
	assertCellContains(t, requirementHeader, emailTrustRow, "required_fields", "dmarc_status")
	assertCellContains(t, requirementHeader, emailTrustRow, "required_fields", "observed_at")
	assertCellEquals(t, requirementHeader, emailTrustRow, "claim_rule_id", "trustworthy-email-authentication-evidence")
	assertCellEquals(t, requirementHeader, emailTrustRow, "claim_strength", "email_domain_authentication_evidence_backed")
	assertCellEquals(t, requirementHeader, emailTrustRow, "sufficiency_rule", "domain_dns_authentication_record_state")
	assertCellContains(t, requirementHeader, emailTrustRow, "source_capability_refs", "email_domain_health/email_authentication_posture")
	assertCellContains(t, requirementHeader, emailTrustRow, "framework_source_type", "email_security_guidance")
	assertCellContains(t, requirementHeader, emailTrustRow, "framework_evidence_model", "mail-authentication records")
	assertRequirementRowMissing(t, requirementRows, frameworkCol, controlCol, profileCol, "NIST SP 800-177", "TLS-MAIL", "baseline-control-review")

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
			assertCellEquals(t, findingRequirementHeader, row, "claim_rule_id", "trust-services-operating-evidence")
			assertCellEquals(t, findingRequirementHeader, row, "claim_status", "control_ref_review_claim")
			assertCellEquals(t, findingRequirementHeader, row, "runtime_evidence_basis", "direct_control_ref_without_source_coverage")
			foundFindingRequirement = true
			break
		}
	}
	if !foundFindingRequirement {
		t.Fatal("finding_evidence_requirement_map.csv missing identity requirement for cerebro-high-risk-api-access")
	}
}

func TestIdentityAccessEvidenceRequirementsClassifyPostureAsReviewContext(t *testing.T) {
	catalog, err := loadControlEvidenceRequirements(repoRoot(t))
	if err != nil {
		t.Fatalf("loadControlEvidenceRequirements() error = %v", err)
	}

	requirement := rawControlEvidenceRequirement(t, catalog, "identity-access", "okta", "mfa_posture")
	if requirement.EvidenceUse != "operating_effectiveness" {
		t.Fatalf("okta mfa_posture evidence_use = %q, want operating_effectiveness", requirement.EvidenceUse)
	}
	if requirement.ClaimStrength != "source_or_sample_backed" {
		t.Fatalf("okta mfa_posture claim_strength = %q, want source_or_sample_backed", requirement.ClaimStrength)
	}

	for _, tt := range []struct {
		sourceID   string
		entityType string
	}{
		{sourceID: "microsoft_entra_id", entityType: "directory_identity_posture"},
		{sourceID: "microsoft_365", entityType: "collaboration_identity_access"},
		{sourceID: "google_workspace", entityType: "workspace_identity_posture"},
		{sourceID: "tailscale", entityType: "tailnet_identity_access"},
		{sourceID: "hris_system", entityType: "workforce_identity_record"},
	} {
		requirement := rawControlEvidenceRequirement(t, catalog, "identity-access", tt.sourceID, tt.entityType)
		if requirement.EvidenceUse != "review_context" {
			t.Fatalf("%s/%s evidence_use = %q, want review_context", tt.sourceID, tt.entityType, requirement.EvidenceUse)
		}
		if requirement.ClaimStrength != "source_context_backed" {
			t.Fatalf("%s/%s claim_strength = %q, want source_context_backed", tt.sourceID, tt.entityType, requirement.ClaimStrength)
		}
		if !strings.Contains(requirement.OverclaimGuard, "context") {
			t.Fatalf("%s/%s overclaim_guard = %q, want context guard", tt.sourceID, tt.entityType, requirement.OverclaimGuard)
		}
	}
}

func TestControlEvidenceKeywordMatchingUsesWholeTerms(t *testing.T) {
	if containsAnyFold("SOC 2 A1 Availability", []string{"AI"}) {
		t.Fatal("AI keyword matched Availability")
	}
	if containsAnyFold("SOC 2 CC6 Logical and Physical Access", []string{"Log"}) {
		t.Fatal("Log keyword matched Logical")
	}
	if !containsAnyFold("SOC 2 CC6 Logical and Physical Access", []string{"Access"}) {
		t.Fatal("Access keyword did not match access token")
	}
	if !containsAnyFold("SOC 2 CC6.1 Access Control", []string{"6.1"}) {
		t.Fatal("punctuated keyword did not match control identifier fragment")
	}
	if !containsAnyFold("ISO 27001:2022 A.8 Information Protection", []string{"Information Protection"}) {
		t.Fatal("Information Protection keyword did not match phrase")
	}
}

func TestGenerateFilesIncludesFrameworkCoverageCandidates(t *testing.T) {
	files := repoGeneratedFiles(t)

	rows := readGeneratedCSV(t, generatedFileByName(t, files, "framework_coverage_candidates.csv"))
	header := rows[0]
	frameworkCol := columnIndex(t, header, "framework")
	controlCol := columnIndex(t, header, "control_id")

	privacyRow := findFrameworkControlRow(t, rows, frameworkCol, controlCol, "CCPA", "1798.100")
	assertCellContains(t, header, privacyRow, "coverage_status", "direct_control_only")
	assertCellContains(t, header, privacyRow, "candidate_priority", "high")
	assertCellContains(t, header, privacyRow, "candidate_type", "source_backing_candidate")
	assertCellEquals(t, header, privacyRow, "claim_status", "source_backing_required")
	assertCellContains(t, header, privacyRow, "suggested_finding_domain", "privacy")
	assertCellContains(t, header, privacyRow, "requirement_profiles", "privacy-rights")
	assertCellContains(t, header, privacyRow, "sufficiency_rules", "legal_basis_scope_request_or_safeguard")

	catalogOnlyRow := findFrameworkControlRow(t, rows, frameworkCol, controlCol, "ISO 27001:2022", "A.7.8")
	assertCellContains(t, header, catalogOnlyRow, "coverage_status", "framework_catalog_only")
	assertCellContains(t, header, catalogOnlyRow, "candidate_priority", "low")
	assertCellContains(t, header, catalogOnlyRow, "candidate_type", "scope_or_exclusion_candidate")
	assertCellEquals(t, header, catalogOnlyRow, "claim_status", "scope_decision_required")
	assertCellContains(t, header, catalogOnlyRow, "requirement_profiles", "baseline-control-review")
	assertCellContains(t, header, catalogOnlyRow, "overclaim_guards", "certification readiness")
}

func TestGenerateFilesIncludesWorkbookManifest(t *testing.T) {
	files := repoGeneratedFiles(t)

	rows := readGeneratedCSV(t, generatedFileByName(t, files, "workbook_manifest.csv"))
	header := rows[0]
	csvFileCol := columnIndex(t, header, "csv_file")
	generatedFiles := map[string]struct{}{}
	for _, file := range files {
		generatedFiles[file.Name] = struct{}{}
	}
	manifestFiles := map[string]struct{}{}
	for _, row := range rows[1:] {
		csvFile := row[csvFileCol]
		if _, ok := manifestFiles[csvFile]; ok {
			t.Fatalf("workbook_manifest.csv contains duplicate csv_file %s", csvFile)
		}
		if _, ok := generatedFiles[csvFile]; !ok {
			t.Fatalf("workbook_manifest.csv references unknown generated file %s", csvFile)
		}
		manifestFiles[csvFile] = struct{}{}
	}
	for csvFile := range manifestFiles {
		if _, ok := generatedFiles[csvFile]; !ok {
			t.Fatalf("workbook_manifest.csv references unknown generated file %s", csvFile)
		}
	}
	for _, file := range files {
		if file.Name == "workbook_manifest.csv" {
			continue
		}
		if _, ok := manifestFiles[file.Name]; !ok {
			t.Fatalf("workbook_manifest.csv missing generated file %s", file.Name)
		}
	}

	overviewRow := findRow(t, rows, csvFileCol, "overview.csv")
	assertCellContains(t, header, overviewRow, "sheet_order", "1")
	assertCellContains(t, header, overviewRow, "worksheet_name", "Overview")
	assertCellContains(t, header, overviewRow, "include_by_default", "true")

	requirementsRow := findRow(t, rows, csvFileCol, "control_evidence_requirements.csv")
	assertCellContains(t, header, requirementsRow, "worksheet_name", "Control Requirements")
	assertCellContains(t, header, requirementsRow, "primary_key", "framework; control_id; requirement_profile; requirement_source_id")

	tagContractRow := findRow(t, rows, csvFileCol, "finding_compliance_tag_contract.csv")
	assertCellContains(t, header, tagContractRow, "worksheet_name", "Finding Tag Contract")
	assertCellContains(t, header, tagContractRow, "include_by_default", "true")

	policyRow := findRow(t, rows, csvFileCol, "policy_map.csv")
	assertCellContains(t, header, policyRow, "source_authority", "policies/**/*.yaml")
	assertCellContains(t, header, policyRow, "include_by_default", "false")
}

func TestFrameworkCoverageCandidateClassifiersCoverAllStatuses(t *testing.T) {
	cases := []struct {
		status   string
		kind     string
		priority string
		action   string
	}{
		{
			status:   "direct_with_source_context",
			kind:     "source_link_review_candidate",
			priority: "medium",
			action:   "promote valid links",
		},
		{
			status:   "direct_control_only",
			kind:     "source_backing_candidate",
			priority: "high",
			action:   "Add source coverage",
		},
		{
			status:   "source_capability_only",
			kind:     "missing_finding_candidate",
			priority: "high",
			action:   "Create or map",
		},
		{
			status:   "review_context_only",
			kind:     "mapping_review_candidate",
			priority: "medium",
			action:   "review context",
		},
		{
			status:   "framework_catalog_only",
			kind:     "scope_or_exclusion_candidate",
			priority: "low",
			action:   "in-scope status",
		},
	}
	for _, tt := range cases {
		t.Run(tt.status, func(t *testing.T) {
			if got := frameworkCoverageCandidateType(tt.status); got != tt.kind {
				t.Fatalf("frameworkCoverageCandidateType(%q) = %q, want %q", tt.status, got, tt.kind)
			}
			if got := frameworkCoverageCandidatePriority(tt.status); got != tt.priority {
				t.Fatalf("frameworkCoverageCandidatePriority(%q) = %q, want %q", tt.status, got, tt.priority)
			}
			if got := frameworkCoverageCandidateAction(tt.status); !strings.Contains(got, tt.action) {
				t.Fatalf("frameworkCoverageCandidateAction(%q) = %q, want substring %q", tt.status, got, tt.action)
			}
		})
	}
}

func TestFrameworkCoverageCandidateRowsCoverAllStatuses(t *testing.T) {
	header := frameworkCoverageCandidatesHeader()
	item := frameworkControlEnrichment{
		Ref: controlRef{
			Framework: "test-framework",
			ControlID: "C1",
			Family:    "Test Control Family",
		},
		SourceCapabilityRefs:     []string{"source/dimension"},
		ReviewAreaRefs:           []string{"test-framework/review-area"},
		OutboundRelationshipRefs: []string{"test-framework C2 [sibling_scope/review_hint]"},
		InboundRelationshipRefs:  []string{"test-framework C0 [evidence_dependency/review_hint]"},
	}
	cases := []struct {
		status string
		kind   string
	}{
		{status: "direct_with_source_context", kind: "source_link_review_candidate"},
		{status: "direct_control_only", kind: "source_backing_candidate"},
		{status: "source_capability_only", kind: "missing_finding_candidate"},
		{status: "review_context_only", kind: "mapping_review_candidate"},
		{status: "framework_catalog_only", kind: "scope_or_exclusion_candidate"},
	}
	for _, tt := range cases {
		t.Run(tt.status, func(t *testing.T) {
			row := frameworkCoverageCandidateRow(item, tt.status, nil, frameworkSourceIndex{})
			assertCellEquals(t, header, row, "coverage_status", tt.status)
			assertCellEquals(t, header, row, "candidate_type", tt.kind)
			assertCellContains(t, header, row, "next_action", frameworkCoverageCandidateAction(tt.status))
		})
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
		{
			name: "framework sources",
			load: func(root string) error {
				_, err := loadFrameworkSources(root)
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

func assertPublicDetectionEvidenceType(t *testing.T, catalog publicDetectionCatalog, id string, want string) {
	t.Helper()
	for _, detection := range catalog.Detections {
		if detection.ID == id {
			if detection.EvidenceType != want {
				t.Fatalf("%s public detection evidence_type = %q, want %q", id, detection.EvidenceType, want)
			}
			return
		}
	}
	t.Fatalf("public detection %s not found", id)
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

func rawControlEvidenceRequirement(t *testing.T, catalog controlEvidenceRequirementCatalog, profileID string, sourceID string, entityType string) controlEvidenceSourceRequirement {
	t.Helper()
	for _, profile := range catalog.Profiles {
		if profile.ProfileID != profileID {
			continue
		}
		for _, requirement := range profile.SourceRequirements {
			if requirement.SourceID == sourceID && requirement.EntityType == entityType {
				return requirement
			}
		}
	}
	t.Fatalf("raw control evidence requirement %s/%s/%s not found", profileID, sourceID, entityType)
	return controlEvidenceSourceRequirement{}
}

func findFrameworkControlRow(t *testing.T, rows [][]string, frameworkCol int, controlCol int, framework string, controlID string) []string {
	t.Helper()
	for _, row := range rows[1:] {
		if row[frameworkCol] == framework && row[controlCol] == controlID {
			return row
		}
	}
	t.Fatalf("framework control row not found for %s %s", framework, controlID)
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
