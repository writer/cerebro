package grcvendor

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestBuildQuestionnaireReviewEnrichmentUsesVendorEvidence(t *testing.T) {
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	record := NewQuestionnaireReviewRecord(NewQuestionnaireReviewRequest{
		TenantID:           "writer",
		VendorURN:          "urn:cerebro:writer:vendor:vrm:coco",
		VendorID:           "coco",
		UploadID:           "upload-1",
		QuestionnaireURN:   "urn:cerebro:writer:security_questionnaire:cerebro_upload:coco-sig-lite-2026",
		QuestionnaireType:  "SIG Lite",
		Title:              "Coco Co. security questionnaire",
		ReviewerUserID:     "security-reviewer",
		CurrentOwnerUserID: "business-owner",
		Attributes: map[string]string{
			"question_count": "6",
		},
	}, now)
	vendor := Vendor{
		VendorIdentity: VendorIdentity{
			URN:      "urn:cerebro:writer:vendor:vrm:coco",
			VendorID: "coco",
			Name:     "Coco Co.",
			SourceID: "vrm",
		},
		VendorOwnership: VendorOwnership{
			OwnerState: OwnerStateMissing,
		},
		VendorRiskInputs: VendorRiskInputs{
			DataSensitivity: "restricted",
			AccessLevel:     "admin",
			Subprocessor:    "true",
		},
		VendorRiskScoring: VendorRiskScoring{
			RiskScore: 86,
			RiskTier:  "tier_1",
		},
		VendorControlPosture: VendorControlPosture{
			DPAStatus:            FreshnessStateMissing,
			SOC2Status:           FreshnessStateCurrent,
			SecurityReviewStatus: FreshnessStateCurrent,
		},
		VendorFreshnessPosture: VendorFreshnessPosture{
			EvidenceFreshnessState: FreshnessStateStale,
		},
		VendorMonitoringPosture: VendorMonitoringPosture{
			MonitoringState: "alert",
			MonitoringSignals: []VendorMonitoringSignal{
				{ID: "rating", Label: "External rating changed", Severity: "medium", Source: "monitoring"},
			},
		},
	}
	relationships := VendorRelationships{
		SecurityQuestionnaires: []RelatedRecord{
			{URN: "urn:cerebro:writer:security_questionnaire:vrm:linked-questionnaire", Label: "Prior SIG"},
		},
		AssuranceDocuments: []RelatedRecord{
			{URN: "urn:cerebro:writer:assurance_document:vrm:soc2", Label: "SOC 2 Type II"},
		},
		SecurityReviews: []RelatedRecord{
			{URN: "urn:cerebro:writer:security_review:vrm:review-1", Label: "Annual review"},
		},
	}
	findings := []QuestionnaireFindingSignal{
		{ID: "finding-1", Title: "SAML enforcement missing", Severity: "high", Status: "open", ControlID: "CC6.1", EvidenceCount: 1},
	}
	evidence := []QuestionnaireEvidenceSignal{
		{ID: "evidence-1", Title: "SOC 2 control evidence", ControlID: "CC6.1", SourceID: "runtime-1", State: "current"},
	}

	enriched := BuildQuestionnaireReviewEnrichment(record, vendor, relationships, findings, evidence, "Conditional approval needs legal follow-up.", now.Add(time.Hour))

	if enriched.Decision != ports.GRCVendorQuestionnaireDecisionApproveWithConditions || enriched.Status != ports.GRCVendorQuestionnaireStatusNeedsInput {
		t.Fatalf("decision/status = %q/%q", enriched.Decision, enriched.Status)
	}
	if enriched.Confidence != "medium" || enriched.DecisionReason == "" {
		t.Fatalf("decision metadata = %#v", enriched)
	}
	if got := enriched.Attributes["llm_summary"]; got != "Conditional approval needs legal follow-up." {
		t.Fatalf("llm_summary = %q", got)
	}
	for _, want := range []string{
		"questionnaire",
		"questionnaire:urn:cerebro:writer:security_questionnaire:vrm:linked-questionnaire",
		"assurance:urn:cerebro:writer:assurance_document:vrm:soc2",
		"review:urn:cerebro:writer:security_review:vrm:review-1",
		"evidence:evidence-1",
		"finding:finding-1",
	} {
		if !hasQuestionnaireEvidence(enriched.EvidenceMatches, want) {
			t.Fatalf("evidence matches missing %q: %#v", want, enriched.EvidenceMatches)
		}
	}
	for _, want := range []string{"owner", "dpa", "fresh_evidence", "monitoring", "vendor_contact", "open_findings"} {
		if !hasMissingQuestion(enriched.MissingQuestions, want) {
			t.Fatalf("missing questions missing %q: %#v", want, enriched.MissingQuestions)
		}
	}
	for _, want := range []string{"security", "legal", "procurement"} {
		if !hasAssignmentTeam(enriched.Assignments, want) {
			t.Fatalf("assignments missing team %q: %#v", want, enriched.Assignments)
		}
	}
	findingsAnswer := questionnaireAnswerByID(enriched.AnswerSuggestions, "findings")
	if findingsAnswer == nil || findingsAnswer.State != "needs_review" || findingsAnswer.Answer == "" {
		t.Fatalf("findings answer = %#v", findingsAnswer)
	}
	if len(enriched.Timeline) < 2 || enriched.Timeline[len(enriched.Timeline)-1].EventType != ports.GRCVendorQuestionnaireEventProcessed {
		t.Fatalf("timeline = %#v", enriched.Timeline)
	}
}

func TestQuestionnaireEvidenceMatchesPreserveRelationshipURNIdentity(t *testing.T) {
	relationships := VendorRelationships{
		SecurityQuestionnaires: []RelatedRecord{
			{URN: "urn:cerebro:writer:security_questionnaire:vrm:sig-2026", Label: "Imported SIG"},
			{URN: "urn:cerebro:writer:security_questionnaire:manual:sig-2026", Label: "Manual SIG"},
		},
	}

	matches := questionnaireEvidenceMatches(ports.GRCVendorQuestionnaireReviewRecord{}, Vendor{}, relationships, nil, nil)

	for _, want := range []string{
		"questionnaire:urn:cerebro:writer:security_questionnaire:vrm:sig-2026",
		"questionnaire:urn:cerebro:writer:security_questionnaire:manual:sig-2026",
	} {
		if !hasQuestionnaireEvidence(matches, want) {
			t.Fatalf("evidence matches missing %q: %#v", want, matches)
		}
	}
	if len(matches) != 2 {
		t.Fatalf("matches = %#v", matches)
	}
}

func TestBuildQuestionnaireReviewEnrichmentClearsStaleLLMSummary(t *testing.T) {
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	record := NewQuestionnaireReviewRecord(NewQuestionnaireReviewRequest{
		TenantID:  "writer",
		VendorURN: "urn:cerebro:writer:vendor:vrm:coco",
		VendorID:  "coco",
		UploadID:  "upload-1",
		Title:     "Coco Co. security questionnaire",
		Attributes: map[string]string{
			"llm_summary":        "Prior summary",
			"llm_summary_status": "available",
		},
	}, now)
	vendor := Vendor{
		VendorIdentity: VendorIdentity{
			URN:      "urn:cerebro:writer:vendor:vrm:coco",
			VendorID: "coco",
			Name:     "Coco Co.",
		},
		VendorOwnership: VendorOwnership{OwnerState: OwnerStateAssigned},
	}

	enriched := BuildQuestionnaireReviewEnrichment(record, vendor, VendorRelationships{}, nil, nil, "", now.Add(time.Hour))

	if _, ok := enriched.Attributes["llm_summary"]; ok {
		t.Fatalf("llm_summary was not cleared: %#v", enriched.Attributes)
	}
	if got := enriched.Attributes["llm_summary_status"]; got != "not_configured" {
		t.Fatalf("llm_summary_status = %q", got)
	}
	if enriched.Status == ports.GRCVendorQuestionnaireStatusProcessing {
		t.Fatalf("status = %q", enriched.Status)
	}
}

func hasQuestionnaireEvidence(matches []ports.GRCVendorQuestionnaireEvidence, id string) bool {
	for _, match := range matches {
		if match.ID == id {
			return true
		}
	}
	return false
}

func hasMissingQuestion(items []ports.GRCVendorQuestionnaireMissing, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}

func hasAssignmentTeam(items []ports.GRCVendorQuestionnaireAssignment, team string) bool {
	for _, item := range items {
		if item.Team == team {
			return true
		}
	}
	return false
}

func questionnaireAnswerByID(items []ports.GRCVendorQuestionnaireAnswer, id string) *ports.GRCVendorQuestionnaireAnswer {
	for index := range items {
		if items[index].ID == id {
			return &items[index]
		}
	}
	return nil
}
