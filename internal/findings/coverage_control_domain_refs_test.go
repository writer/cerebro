package findings

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
)

var intentionallyUnmappedCoverageControlDomains = map[string]struct{}{
	"source_operations": {},
}

func TestCoverageControlDomainRefsLoad(t *testing.T) {
	if coverageControlDomainRefSet.Version == "" {
		t.Fatal("coverage control domain refs version is empty")
	}
	refs := controlRefsForControlDomains([]string{"identity_access"})
	if len(refs) == 0 {
		t.Fatal("identity_access produced no control refs")
	}
	found := false
	for _, ref := range refs {
		if ref.FrameworkName == "SOC 2" && ref.ControlID == "CC6.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("identity_access refs missing SOC 2 CC6.1: %+v", refs)
	}
}

func TestEffectiveCoverageControlRefsUnionsDerived(t *testing.T) {
	dimension := sourcecdk.CoverageDimension{
		ID:             "datasets",
		ControlDomains: []string{"data_protection"},
		ControlRefs: []sourcecdk.CoverageControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC1.1"},
		},
	}
	refs := effectiveCoverageControlRefs(dimension)
	var hasDeclared, hasDerived bool
	for _, ref := range refs {
		if ref.FrameworkName == "SOC 2" && ref.ControlID == "CC1.1" {
			hasDeclared = true
		}
		if ref.FrameworkName == "NIST 800-53 r5" && ref.ControlID == "SC-28" {
			hasDerived = true
		}
	}
	if !hasDeclared || !hasDerived {
		t.Fatalf("effectiveCoverageControlRefs union incomplete: declared=%v derived=%v refs=%+v", hasDeclared, hasDerived, refs)
	}
}

func TestSourceCoverageDerivedRefsAreSourceBounded(t *testing.T) {
	detection := PublicDetection{
		ID:                        "gcp-storage-bucket-encryption-disabled",
		SourceID:                  "gcp",
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{EvidenceType: "encryption_configuration"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "NIST 800-53 r5", ControlID: "SC-28"},
		},
	}
	loggingDimension := func(id string) sourcecdk.CoverageDimension {
		return sourcecdk.CoverageDimension{
			ID:             id,
			Type:           "entity_family",
			Title:          id,
			Support:        sourcecdk.CoverageSupportSupported,
			HighValue:      true,
			EvidenceTypes:  []string{"encryption_configuration"},
			ControlDomains: []string{"data_protection"},
		}
	}
	contracts := []sourcecdk.CoverageContract{
		{SourceID: "gcp", Dimensions: []sourcecdk.CoverageDimension{loggingDimension("buckets")}},
		{SourceID: "github", Dimensions: []sourcecdk.CoverageDimension{loggingDimension("repositories")}},
	}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) == 0 {
		t.Fatal("expected derived source coverage for the detection's own source")
	}
	for _, ref := range refs {
		if ref.SourceID != "gcp" {
			t.Fatalf("derived coverage crossed sources: got %q, want only gcp", ref.SourceID)
		}
	}
}

func TestSourceCoverageDerivedRefsRequireDimensionOrEvidenceMatch(t *testing.T) {
	detection := PublicDetection{
		ID:                        "aws-s3-bucket-no-public-access",
		Name:                      "S3 Bucket Public Access",
		SourceID:                  policyRuleSourceID,
		Tags:                      []string{"aws", "policy", "s3"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{EvidenceType: "cloud_configuration"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.6"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "aws",
		Dimensions: []sourcecdk.CoverageDimension{
			{
				ID:             "iam_credential_report",
				Type:           "entity_family",
				Families:       []string{"iam_credential_report"},
				Support:        sourcecdk.CoverageSupportSupported,
				EvidenceTypes:  []string{"identity_configuration"},
				ControlDomains: []string{"identity_access"},
			},
			{
				ID:             "s3_bucket",
				Type:           "entity_family",
				Families:       []string{"s3_bucket"},
				Support:        sourcecdk.CoverageSupportSupported,
				EvidenceTypes:  []string{"network_exposure"},
				ControlDomains: []string{"network_security"},
			},
		},
	}}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 1 {
		t.Fatalf("len(SourceCoverageRefs) = %d, want only the matching S3 dimension: %#v", len(refs), refs)
	}
	if refs[0].DimensionID != "s3_bucket" {
		t.Fatalf("DimensionID = %q, want s3_bucket", refs[0].DimensionID)
	}
}

func TestSourceCoverageExplicitRefsCanMatchSourceWithoutDimensionOrEvidence(t *testing.T) {
	detection := PublicDetection{
		ID:       "aws-access-baseline",
		SourceID: "aws",
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.6"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "aws",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:            "iam_credential_report",
			Type:          "entity_family",
			Families:      []string{"iam_credential_report"},
			Support:       sourcecdk.CoverageSupportSupported,
			EvidenceTypes: []string{"identity_configuration"},
			ControlRefs: []sourcecdk.CoverageControlRef{{
				FrameworkName: "SOC 2",
				ControlID:     "CC6.6",
			}},
		}},
	}}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 1 {
		t.Fatalf("len(SourceCoverageRefs) = %d, want explicit control ref match: %#v", len(refs), refs)
	}
	if refs[0].DimensionID != "iam_credential_report" {
		t.Fatalf("DimensionID = %q, want iam_credential_report", refs[0].DimensionID)
	}
}

func TestCoverageControlIDMatchesGDPRArticleAliases(t *testing.T) {
	for _, legacy := range []string{"Art.5", "Art-5", "Art 5"} {
		matched, exact := coverageControlIDMatches(legacy, "Article 5")
		if !matched || !exact {
			t.Fatalf("coverageControlIDMatches(%q, Article 5) = (%v, %v), want exact match", legacy, matched, exact)
		}
	}

	detectionRefs := []ports.FindingControlRef{{FrameworkName: "GDPR", ControlID: "Art.30"}}
	coverageRefs := []sourcecdk.CoverageControlRef{{FrameworkName: "GDPR", ControlID: "Article 30"}}
	matched, exact := matchingCoverageControlRefs(detectionRefs, coverageRefs)
	if !exact || len(matched) != 1 {
		t.Fatalf("matchingCoverageControlRefs legacy GDPR alias = exact %v refs %#v, want one exact match", exact, matched)
	}
	if matched[0].ControlID != "Article 30" {
		t.Fatalf("matched control ID = %q, want Article 30", matched[0].ControlID)
	}
}

func TestCoverageControlDomainRefsCoverDeclaredSourceDomains(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "sources", "*", "catalog.yaml"))
	if err != nil {
		t.Fatalf("glob source catalogs: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("expected source catalogs")
	}

	var missing []string
	for _, path := range paths {
		payload, err := os.ReadFile(path) // #nosec G304 -- test reads repository source catalog fixtures.
		if err != nil {
			t.Fatalf("read source catalog %q: %v", path, err)
		}
		catalog, err := sourcecdk.LoadSourceCatalog(payload)
		if err != nil {
			t.Fatalf("load source catalog %q: %v", path, err)
		}
		if catalog.CoverageContract == nil {
			continue
		}
		for _, dimension := range catalog.CoverageContract.Dimensions {
			for _, domain := range dimension.ControlDomains {
				domain = strings.TrimSpace(domain)
				if domain == "" {
					continue
				}
				if _, ok := coverageControlDomainRefSet.ControlDomains[domain]; ok {
					continue
				}
				if _, ok := intentionallyUnmappedCoverageControlDomains[domain]; ok {
					continue
				}
				rel, _ := filepath.Rel(filepath.Join("..", ".."), path)
				missing = append(missing, rel+":"+dimension.ID+":"+domain)
			}
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		t.Fatalf("declared control_domains missing coverage mapping or explicit exemption: first=%s count=%d", missing[0], len(missing))
	}
}
