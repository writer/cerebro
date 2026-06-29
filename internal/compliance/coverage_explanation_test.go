package compliance

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildCoverageGapExplanationSourceBacked(t *testing.T) {
	explanation := BuildCoverageGapExplanation(CoverageGapExplanationInput{
		CoverageFindingContext: CoverageFindingContext{
			FindingID:       "email-domain-authentication-misconfigured",
			FindingName:     "Email domain authentication misconfigured",
			FindingSourceID: "email_domain_health",
			Control:         ControlRef{FrameworkName: "NIST SP 800-177", ControlID: "TLS-MAIL"},
		},
		CoverageRequirementContext: CoverageRequirementContext{
			RequirementProfile:    "email-authentication",
			RequirementSourceID:   "email_domain_health",
			RequirementEntityType: "email_authentication_posture",
			RequiredFields:        []string{"domain", "dmarc_policy", "spf_record"},
			FreshnessWindow:       "24h",
		},
		CoverageClaimContext: CoverageClaimContext{
			ClaimRuleID:   "trustworthy-email-authentication-evidence",
			ClaimStrength: "email_domain_authentication_evidence_backed",
			CoverageClaim: "supports_trustworthy_email_domain_authentication",
			ClaimStatus:   "source_evidence_claim",
		},
		CoverageEvidenceContext: CoverageEvidenceContext{SourceFacts: []CoverageSourceFactInput{{
			SourceID:       "email_domain_health",
			DimensionID:    "email_authentication_posture",
			DimensionType:  "entity_family",
			SupportLevel:   "supported",
			HighValue:      true,
			EvidenceTypes:  []string{"email_authentication_control"},
			ControlRefs:    []ControlRef{{FrameworkName: "NIST SP 800-177", ControlID: "TLS-MAIL"}},
			ProvenanceURNs: []string{"urn:cerebro:tenant:source_fact:email_domain_health/example.com"},
			Freshness:      []string{"observed_at=2026-06-29T00:00:00Z"},
		}}},
	})

	if explanation.CoverageState != CoverageExplanationSourceBacked {
		t.Fatalf("CoverageState = %q, want source_backed", explanation.CoverageState)
	}
	if explanation.EvidencePacketReadiness != "ready_for_packet" {
		t.Fatalf("EvidencePacketReadiness = %q, want ready_for_packet", explanation.EvidencePacketReadiness)
	}
	if len(explanation.MissingDimensions) != 0 {
		t.Fatalf("MissingDimensions = %#v, want none", explanation.MissingDimensions)
	}
	if len(explanation.GraphPath) < 4 {
		t.Fatalf("GraphPath = %#v, want finding/source/control/requirement path", explanation.GraphPath)
	}
	if len(explanation.GraphEvidence) != len(explanation.GraphPath) {
		t.Fatalf("GraphEvidence = %#v, want graph path projection", explanation.GraphEvidence)
	}
	if len(explanation.SourceCitations) != 1 {
		t.Fatalf("SourceCitations = %#v, want one citation", explanation.SourceCitations)
	}
	if explanation.Confidence != "high" {
		t.Fatalf("Confidence = %q, want high", explanation.Confidence)
	}
	if len(explanation.UnsupportedClaims) != 0 {
		t.Fatalf("UnsupportedClaims = %#v, want none", explanation.UnsupportedClaims)
	}
	if explanation.Freshness.Status != "freshness_requirement_defined" {
		t.Fatalf("Freshness.Status = %q, want freshness_requirement_defined", explanation.Freshness.Status)
	}
	if explanation.LLMContext.Question == "" || len(explanation.LLMContext.AnswerBasis) == 0 {
		t.Fatalf("LLMContext = %#v, want question and answer basis", explanation.LLMContext)
	}
	content, err := json.Marshal(explanation)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, want := range []string{`"finding_id"`, `"graph_evidence"`, `"source_citations"`, `"freshness"`, `"confidence"`} {
		if !strings.Contains(string(content), want) {
			t.Fatalf("marshaled explanation missing %s: %s", want, content)
		}
	}
}

func TestBuildCoverageGapExplanationMissingRequiredDimension(t *testing.T) {
	explanation := BuildCoverageGapExplanation(CoverageGapExplanationInput{
		CoverageFindingContext: CoverageFindingContext{
			FindingID:       "aws-s3-bucket-no-public-access",
			FindingSourceID: "aws",
			Control:         ControlRef{FrameworkName: "SOC 2", ControlID: "CC6.6"},
		},
		CoverageRequirementContext: CoverageRequirementContext{
			RequirementProfile:    "baseline-control-review",
			RequirementSourceID:   "control_owner_review",
			RequirementEntityType: "control_evidence_packet",
			RequiredFields:        []string{"control_ref", "reviewer", "reviewed_at"},
			FreshnessWindow:       "90d",
		},
		CoverageClaimContext: CoverageClaimContext{
			ClaimRuleID:              "trust-services-operating-evidence",
			OverclaimGuard:           "Do not claim criterion coverage from a control reference alone.",
			ComplianceEvidenceStatus: "partial_source_backed",
			ClaimStatus:              "partial_source_evidence_claim",
		},
		CoverageEvidenceContext: CoverageEvidenceContext{SourceFacts: []CoverageSourceFactInput{{
			SourceID:      "aws",
			DimensionID:   "s3_bucket",
			DimensionType: "entity_family",
			SupportLevel:  "supported",
			ControlRefs:   []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.6"}},
		}}},
	})

	if explanation.CoverageState != CoverageExplanationPartial {
		t.Fatalf("CoverageState = %q, want partial", explanation.CoverageState)
	}
	if explanation.EvidencePacketReadiness != "missing_required_source_dimensions" {
		t.Fatalf("EvidencePacketReadiness = %q, want missing_required_source_dimensions", explanation.EvidencePacketReadiness)
	}
	if len(explanation.MissingDimensions) != 1 || explanation.MissingDimensions[0].Requirement != "control_owner_review/control_evidence_packet" {
		t.Fatalf("MissingDimensions = %#v, want control owner review requirement", explanation.MissingDimensions)
	}
	if explanation.ManualReviewState != "owner_review_required" {
		t.Fatalf("ManualReviewState = %q, want owner_review_required", explanation.ManualReviewState)
	}
	if explanation.OverclaimGuard == "" {
		t.Fatal("OverclaimGuard is empty")
	}
	if len(explanation.LLMContext.MissingDimensions) != 1 {
		t.Fatalf("LLMContext.MissingDimensions = %#v, want one missing dimension", explanation.LLMContext.MissingDimensions)
	}
	content, err := json.Marshal(explanation)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !strings.Contains(string(content), `"unsupported_claims"`) {
		t.Fatalf("marshaled explanation missing unsupported_claims: %s", content)
	}
}

func TestBuildCoverageGapExplanationControlOnly(t *testing.T) {
	explanation := BuildCoverageGapExplanation(CoverageGapExplanationInput{
		CoverageFindingContext: CoverageFindingContext{
			FindingID: "control-only-finding",
			Control:   ControlRef{FrameworkName: "SOC 2", ControlID: "CC6.1"},
		},
		CoverageRequirementContext: CoverageRequirementContext{
			RequirementProfile:    "baseline-control-review",
			RequirementSourceID:   "control_owner_review",
			RequirementEntityType: "control_evidence_packet",
			RequiredFields:        []string{"reviewer"},
			FreshnessWindow:       "90d",
		},
		CoverageClaimContext: CoverageClaimContext{ClaimStatus: "control_ref_review_claim"},
	})

	if explanation.CoverageState != CoverageExplanationMissing {
		t.Fatalf("CoverageState = %q, want missing", explanation.CoverageState)
	}
	if explanation.Confidence != "low" {
		t.Fatalf("Confidence = %q, want low", explanation.Confidence)
	}
	if !containsCoverageString(explanation.UnsupportedClaims, "source_backed_coverage_not_established") {
		t.Fatalf("UnsupportedClaims = %#v, want source backed guard", explanation.UnsupportedClaims)
	}
}

func TestBuildCoverageGapExplanationPolicyDocNeeded(t *testing.T) {
	explanation := BuildCoverageGapExplanation(CoverageGapExplanationInput{
		CoverageFindingContext: CoverageFindingContext{
			FindingID: "policy-doc-needed",
			Control:   ControlRef{FrameworkName: "ISO 27001", ControlID: "A.5.1"},
		},
		CoverageRequirementContext: CoverageRequirementContext{
			RequirementProfile:     "governance-risk",
			RequirementSourceID:    "grc_policy_repository",
			RequirementEntityType:  "policy_document",
			RequiredFields:         []string{"policy_id"},
			PolicyDocumentRequired: true,
		},
		CoverageClaimContext: CoverageClaimContext{ClaimStatus: "partial_source_evidence_claim"},
	})

	if !containsCoverageString(explanation.UnsupportedClaims, "policy_document_not_linked") {
		t.Fatalf("UnsupportedClaims = %#v, want policy document guard", explanation.UnsupportedClaims)
	}
	if len(explanation.PolicyCitations) != 0 {
		t.Fatalf("PolicyCitations = %#v, want none", explanation.PolicyCitations)
	}
	if explanation.NextAction != "Connect the required source dimension or document a manual evidence owner." {
		t.Fatalf("NextAction = %q, want missing dimension action first", explanation.NextAction)
	}
}

func TestBuildCoverageGapExplanationExceptionManualReview(t *testing.T) {
	explanation := BuildCoverageGapExplanation(CoverageGapExplanationInput{
		CoverageFindingContext: CoverageFindingContext{
			FindingID: "exception-review",
			Control:   ControlRef{FrameworkName: "SOC 2", ControlID: "CC7.2"},
		},
		CoverageRequirementContext: CoverageRequirementContext{
			RequirementProfile:      "logging-monitoring",
			ManualReviewRequired:    true,
			ExceptionReviewRequired: true,
		},
		CoverageClaimContext: CoverageClaimContext{ClaimStatus: "partial_source_evidence_claim"},
		CoverageEvidenceContext: CoverageEvidenceContext{
			ExceptionRefs: []string{"exception-123"},
		},
	})

	if explanation.ManualReviewState != "exception_review_required" {
		t.Fatalf("ManualReviewState = %q, want exception_review_required", explanation.ManualReviewState)
	}
	if !containsCoverageString(explanation.UnsupportedClaims, "exception_or_remediation_review_required") {
		t.Fatalf("UnsupportedClaims = %#v, want exception guard", explanation.UnsupportedClaims)
	}
}

func TestBuildCoverageGapExplanationStaleSource(t *testing.T) {
	explanation := BuildCoverageGapExplanation(CoverageGapExplanationInput{
		CoverageFindingContext: CoverageFindingContext{
			FindingID:       "stale-source",
			FindingSourceID: "aws",
			Control:         ControlRef{FrameworkName: "SOC 2", ControlID: "CC6.6"},
		},
		CoverageRequirementContext: CoverageRequirementContext{
			RequirementSourceID:   "aws",
			RequirementEntityType: "s3_bucket",
			FreshnessWindow:       "24h",
			SourceFreshnessStatus: "stale_source",
		},
		CoverageClaimContext: CoverageClaimContext{ClaimStatus: "source_evidence_claim"},
		CoverageEvidenceContext: CoverageEvidenceContext{SourceFacts: []CoverageSourceFactInput{{
			SourceID:    "aws",
			DimensionID: "s3_bucket",
			Freshness:   []string{"observed_at=2026-06-20T00:00:00Z"},
		}}},
	})

	if explanation.Freshness.Status != "stale_source" {
		t.Fatalf("Freshness.Status = %q, want stale_source", explanation.Freshness.Status)
	}
	if explanation.Confidence != "low" {
		t.Fatalf("Confidence = %q, want low", explanation.Confidence)
	}
	if !containsCoverageString(explanation.UnsupportedClaims, "stale_source_freshness") {
		t.Fatalf("UnsupportedClaims = %#v, want stale freshness guard", explanation.UnsupportedClaims)
	}
}

func containsCoverageString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
