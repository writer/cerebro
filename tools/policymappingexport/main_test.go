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
	assertCellContains(t, header, cerebroRow, "resolved_audit_domain", "api")
	assertCellContains(t, header, cerebroRow, "audit_language_source", "yaml:domain:api")
	assertCellContains(t, header, cerebroRow, "evidence_type", "application_access_control")
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
	assertCellContains(t, reviewHeader, s3Row, "source_backed_control_ref_count", "2")
	assertCellContains(t, reviewHeader, s3Row, "review_flags", "partial_source_backed_control_refs")

	controlRows := readGeneratedCSV(t, generatedFileByName(t, files, "finding_control_map.csv"))
	controlHeader := controlRows[0]
	controlFindingCol := columnIndex(t, controlHeader, "finding_id")
	controlRefCol := columnIndex(t, controlHeader, "control_ref")
	for _, row := range controlRows[1:] {
		if row[controlFindingCol] == "aws-s3-bucket-no-public-access" && row[controlRefCol] == "SOC 2 CC6.6" {
			assertCellContains(t, controlHeader, row, "control_match_source", "source_coverage_ref")
			assertCellContains(t, controlHeader, row, "source_coverage_refs", "aws/s3_bucket")
			return
		}
	}
	t.Fatal("finding_control_map.csv missing SOC 2 CC6.6 row for aws-s3-bucket-no-public-access")
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

func assertCellContains(t *testing.T, header []string, row []string, column string, want string) {
	t.Helper()
	index := columnIndex(t, header, column)
	if !strings.Contains(row[index], want) {
		t.Fatalf("%s = %q, want it to contain %q", column, row[index], want)
	}
}
