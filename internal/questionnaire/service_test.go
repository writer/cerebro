package questionnaire

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/evidencepackets"
	"github.com/writer/cerebro/internal/ports"
)

func TestProcessEvidenceAnswersStateMatrix(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name        string
		answer      *evidencepackets.QuestionnaireAnswer
		wantAnswer  string
		wantReview  string
		wantStatus  string
		wantCited   bool
		wantMissing bool
	}{
		{
			name:       "supported current citations",
			answer:     ptrEvidenceAnswer(baseEvidenceAnswer("Do you enforce MFA for users?", "supported", "ready", "current")),
			wantAnswer: ports.QuestionnaireAnswerSupported,
			wantReview: ports.QuestionnaireReviewReady,
			wantStatus: ports.QuestionnaireStatusReadyForApproval,
			wantCited:  true,
		},
		{
			name:       "supported state without citations stays blocked",
			answer:     ptrEvidenceAnswer(noCitationAnswer(baseEvidenceAnswer("Do you enforce MFA for users?", "supported", "ready", "current"))),
			wantAnswer: ports.QuestionnaireAnswerBlocked,
			wantReview: ports.QuestionnaireReviewBlocked,
			wantStatus: ports.QuestionnaireStatusNeedsInput,
		},
		{
			name:       "stale evidence is partial",
			answer:     ptrEvidenceAnswer(withGap(baseEvidenceAnswer("Do you enforce MFA for users?", "supported", "ready", "stale"), "stale_evidence")),
			wantAnswer: ports.QuestionnaireAnswerPartial,
			wantReview: ports.QuestionnaireReviewNeedsReview,
			wantStatus: ports.QuestionnaireStatusReadyForApproval,
			wantCited:  true,
		},
		{
			name:        "partial answer keeps missing evidence visible",
			answer:      ptrEvidenceAnswer(withGap(baseEvidenceAnswer("Do you encrypt customer data?", "partial", "ready", "current"), "key_rotation_record_missing")),
			wantAnswer:  ports.QuestionnaireAnswerPartial,
			wantReview:  ports.QuestionnaireReviewNeedsReview,
			wantStatus:  ports.QuestionnaireStatusReadyForApproval,
			wantCited:   true,
			wantMissing: true,
		},
		{
			name:       "manual review stays needs review",
			answer:     ptrEvidenceAnswer(baseEvidenceAnswer("Do you review access quarterly?", "manual_review", "needs_review", "current")),
			wantAnswer: ports.QuestionnaireAnswerNeedsReview,
			wantReview: ports.QuestionnaireReviewNeedsReview,
			wantStatus: ports.QuestionnaireStatusReadyForApproval,
			wantCited:  true,
		},
		{
			name:       "not required is not applicable",
			answer:     ptrEvidenceAnswer(noCitationAnswer(baseEvidenceAnswer("Is a vendor profile required?", "not_required", "ready", "current"))),
			wantAnswer: ports.QuestionnaireAnswerNotApplicable,
			wantReview: ports.QuestionnaireReviewReady,
			wantStatus: ports.QuestionnaireStatusReadyForApproval,
		},
		{
			name:       "no matching evidence blocks the answer",
			answer:     nil,
			wantAnswer: ports.QuestionnaireAnswerBlocked,
			wantReview: ports.QuestionnaireReviewBlocked,
			wantStatus: ports.QuestionnaireStatusNeedsInput,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			questionText := "Do you enforce MFA for users?"
			if tt.answer != nil {
				questionText = tt.answer.Question
			}
			record := NewRunRecord(NewRunRequest{
				TenantID:  "tenant-1",
				Direction: ports.QuestionnaireDirectionCustomerSecurityReview,
				Title:     "Security questionnaire",
				Questions: []ports.QuestionnaireQuestion{{
					ID:            "q-1",
					Question:      questionText,
					RequiredSlots: slotsForQuestion(questionText, ports.QuestionnaireDirectionCustomerSecurityReview),
				}},
			}, now)
			evidenceAnswers := []evidencepackets.QuestionnaireAnswer{}
			if tt.answer != nil {
				evidenceAnswers = append(evidenceAnswers, *tt.answer)
			}
			record = ProcessEvidenceAnswers(record, evidenceAnswers, now)
			if len(record.Answers) != 1 {
				t.Fatalf("answer count = %d, want 1", len(record.Answers))
			}
			answer := record.Answers[0]
			if answer.AnswerState != tt.wantAnswer || answer.ReviewState != tt.wantReview {
				t.Fatalf("state = %s/%s, want %s/%s", answer.AnswerState, answer.ReviewState, tt.wantAnswer, tt.wantReview)
			}
			if record.Status != tt.wantStatus {
				t.Fatalf("status = %s, want %s", record.Status, tt.wantStatus)
			}
			if tt.wantCited && len(answer.Citations) == 0 {
				t.Fatal("supported answer did not include citations")
			}
			if !tt.wantCited && tt.wantAnswer == ports.QuestionnaireAnswerSupported && len(answer.Citations) == 0 {
				t.Fatal("answer was supported without citations")
			}
			if tt.wantMissing && len(answer.MissingEvidence) == 0 {
				t.Fatal("partial answer did not surface missing evidence")
			}
		})
	}
}

func TestVendorReviewAddsVendorEvidenceSlot(t *testing.T) {
	record := NewRunRecord(NewRunRequest{
		TenantID:  "tenant-1",
		Direction: ports.QuestionnaireDirectionVendorReview,
		VendorURN: "urn:cerebro:tenant-1:vendor:acme",
		Questions: []ports.QuestionnaireQuestion{{
			ID:       "q-1",
			Question: "Is the vendor monitored?",
		}},
	}, time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC))
	record = ProcessEvidenceAnswers(record, nil, record.CreatedAt)
	answer := record.Answers[0]
	if !slotPresent(answer.EvidenceSlots, "vendor_profile") {
		t.Fatalf("vendor_profile slot missing: %#v", answer.EvidenceSlots)
	}
}

func TestProcessEvidenceAnswersDoesNotCreateQuestionRows(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	record := NewRunRecord(NewRunRequest{
		TenantID:  "tenant-1",
		Direction: ports.QuestionnaireDirectionCustomerSecurityReview,
	}, now)

	record = ProcessEvidenceAnswers(record, []evidencepackets.QuestionnaireAnswer{
		baseEvidenceAnswer("Do you enforce MFA for users?", "supported", "ready", "current"),
	}, now)

	if len(record.Questions) != 0 || len(record.Answers) != 0 {
		t.Fatalf("questions/answers = %d/%d, want explicit intake only", len(record.Questions), len(record.Answers))
	}
}

func TestRecordDecisionGlobalConditionalApprovesRun(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	record := NewRunRecord(NewRunRequest{
		TenantID:  "tenant-1",
		Direction: ports.QuestionnaireDirectionCustomerSecurityReview,
		Questions: []ports.QuestionnaireQuestion{{
			ID:       "q-1",
			Question: "Attach the latest SOC 2 report.",
		}},
	}, now)
	record = ProcessEvidenceAnswers(record, nil, now)
	if record.Status != ports.QuestionnaireStatusNeedsInput {
		t.Fatalf("status before decision = %s, want needs_input", record.Status)
	}

	record = RecordDecision(record, ports.QuestionnaireDecision{
		Decision: ports.QuestionnaireDecisionApprovedWithConditions,
		Reason:   "Approved with tracked follow-up.",
		ActorID:  "security@example.com",
	}, now.Add(time.Minute))

	if record.Status != ports.QuestionnaireStatusApproved || record.Decision != ports.QuestionnaireDecisionApprovedWithConditions {
		t.Fatalf("workflow = %s/%s, want approved/approved_with_conditions", record.Status, record.Decision)
	}
}

func TestSummarizeRunCountsPartialAnswersAsReviewWork(t *testing.T) {
	record := SummarizeRun(ports.QuestionnaireRunRecord{
		QuestionnaireRunContent: ports.QuestionnaireRunContent{
			Questions: []ports.QuestionnaireQuestion{{
				ID:       "q-1",
				Question: "Is customer data encrypted?",
			}},
			Answers: []ports.QuestionnaireRunAnswer{{
				ID:          "a-1",
				QuestionID:  "q-1",
				Question:    "Is customer data encrypted?",
				AnswerState: ports.QuestionnaireAnswerPartial,
				ReviewState: ports.QuestionnaireReviewNeedsReview,
			}},
		},
	})

	if record.ReviewAnswerCount != 1 {
		t.Fatalf("review answers = %d, want 1", record.ReviewAnswerCount)
	}
}

func ptrEvidenceAnswer(answer evidencepackets.QuestionnaireAnswer) *evidencepackets.QuestionnaireAnswer {
	return &answer
}

func baseEvidenceAnswer(question string, answerState string, reviewState string, freshness string) evidencepackets.QuestionnaireAnswer {
	return evidencepackets.QuestionnaireAnswer{
		ID:          "answer-" + answerState + "-" + freshness,
		QuestionID:  "source-q-1",
		Question:    question,
		AnswerState: answerState,
		ReviewState: reviewState,
		Reasoning: evidencepackets.QuestionnaireReasoningContract{
			Intent:            "questionnaire_evidence",
			ManualReviewState: reviewState,
		},
		Confidence: evidencepackets.QuestionnaireAnswerConfidence{Level: "high", Score: 90},
		Controls: []evidencepackets.QuestionnaireControlRef{{
			ID:        "control-mfa",
			ControlID: "IAM-01",
			Title:     "MFA required",
		}},
		SourceEvidence: []evidencepackets.QuestionnaireEvidenceRef{{
			ID:               "evidence-1",
			EvidencePacketID: "packet-1",
			EvidenceType:     "control_test",
			SourceID:         "okta",
			Freshness:        evidencepackets.EvidenceFreshness{Status: freshness, ObservedAt: "2026-06-01T00:00:00Z"},
		}},
		EvidencePackets: []string{"packet-1"},
		Citations:       evidencepackets.EvidenceCitations{EvidenceIDs: []string{"evidence-1"}},
		Freshness:       evidencepackets.EvidenceFreshness{Status: freshness, ObservedAt: "2026-06-01T00:00:00Z"},
	}
}

func noCitationAnswer(answer evidencepackets.QuestionnaireAnswer) evidencepackets.QuestionnaireAnswer {
	answer.SourceEvidence = nil
	answer.PolicyDocuments = nil
	answer.EvidencePackets = nil
	answer.Citations = evidencepackets.EvidenceCitations{}
	return answer
}

func withGap(answer evidencepackets.QuestionnaireAnswer, code string) evidencepackets.QuestionnaireAnswer {
	answer.MissingEvidence = append(answer.MissingEvidence, evidencepackets.QuestionnaireEvidenceGap{
		ID:       "gap-" + code,
		Code:     code,
		Reason:   "Evidence must be reviewed.",
		PacketID: "packet-1",
	})
	return answer
}

func slotPresent(slots []ports.QuestionnaireEvidenceSlot, id string) bool {
	for _, slot := range slots {
		if slot.ID == id {
			return true
		}
	}
	return false
}
