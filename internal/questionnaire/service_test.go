package questionnaire

import (
	"strings"
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
					RequiredSlots: requiredSlotsForTestQuestion(questionText),
				}},
			}, now)
			evidenceAnswers := []evidencepackets.QuestionnaireAnswer{}
			if tt.answer != nil {
				answer := *tt.answer
				answer.QuestionID = "q-1"
				evidenceAnswers = append(evidenceAnswers, answer)
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
			if tt.wantAnswer == ports.QuestionnaireAnswerNotApplicable && (len(answer.MissingEvidence) > 0 || record.MissingEvidence != 0) {
				t.Fatalf("not applicable answer carried missing evidence: answer gaps=%d run missing=%d", len(answer.MissingEvidence), record.MissingEvidence)
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

func TestProcessEvidenceAnswersRequiresCitationForRequiredSlot(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name       string
		answer     evidencepackets.QuestionnaireAnswer
		wantAnswer string
		wantSlot   string
	}{
		{
			name:       "unrelated citation does not satisfy audit report",
			answer:     withEvidenceType(baseEvidenceAnswer("Attach the latest SOC 2 report.", "supported", "ready", "current"), "control_test", "okta"),
			wantAnswer: ports.QuestionnaireAnswerBlocked,
			wantSlot:   "missing",
		},
		{
			name:       "source keyword does not satisfy MFA slot without evidence type",
			answer:     withEvidenceType(baseEvidenceAnswer("Attach the latest SOC 2 report.", "supported", "ready", "current"), "control_test", "okta"),
			wantAnswer: ports.QuestionnaireAnswerBlocked,
			wantSlot:   "missing",
		},
		{
			name:       "audit report citation satisfies audit report",
			answer:     withEvidenceType(baseEvidenceAnswer("Attach the latest SOC 2 report.", "supported", "ready", "current"), "audit_report", "trust-center"),
			wantAnswer: ports.QuestionnaireAnswerSupported,
			wantSlot:   "satisfied",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requiredSlots := []string{"audit_report"}
			if tt.name == "source keyword does not satisfy MFA slot without evidence type" {
				requiredSlots = []string{"identity_mfa"}
			}
			record := NewRunRecord(NewRunRequest{
				TenantID:  "tenant-1",
				Direction: ports.QuestionnaireDirectionCustomerSecurityReview,
				Title:     "Security questionnaire",
				Questions: []ports.QuestionnaireQuestion{{
					ID:            "q-1",
					Question:      "Attach the latest SOC 2 report.",
					RequiredSlots: requiredSlots,
				}},
			}, now)

			record = ProcessEvidenceAnswers(record, []evidencepackets.QuestionnaireAnswer{tt.answer}, now)
			if len(record.Answers) != 1 {
				t.Fatalf("answer count = %d, want 1", len(record.Answers))
			}
			answer := record.Answers[0]
			if answer.AnswerState != tt.wantAnswer {
				t.Fatalf("answer state = %s, want %s; slots=%#v gaps=%#v", answer.AnswerState, tt.wantAnswer, answer.EvidenceSlots, answer.MissingEvidence)
			}
			if got := slotState(answer.EvidenceSlots, requiredSlots[0]); got != tt.wantSlot {
				t.Fatalf("%s slot state = %s, want %s; slots=%#v", requiredSlots[0], got, tt.wantSlot, answer.EvidenceSlots)
			}
		})
	}
}

func TestProcessEvidenceAnswersBlocksUnresolvedEvidenceSlot(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	record := NewRunRecord(NewRunRequest{
		TenantID:  "tenant-1",
		Direction: ports.QuestionnaireDirectionCustomerSecurityReview,
		Title:     "Security questionnaire",
		Questions: []ports.QuestionnaireQuestion{{
			ID:       "q-1",
			Question: "Security questionnaire item",
		}},
	}, now)

	record = ProcessEvidenceAnswers(record, []evidencepackets.QuestionnaireAnswer{
		withEvidenceType(baseEvidenceAnswer("Do you enforce MFA for users?", "supported", "ready", "current"), "control_test", "okta"),
	}, now)

	if len(record.Answers) != 1 {
		t.Fatalf("answer count = %d, want 1", len(record.Answers))
	}
	answer := record.Answers[0]
	if answer.AnswerState != ports.QuestionnaireAnswerBlocked || len(answer.EvidenceSlots) != 0 {
		t.Fatalf("answer = %s slots=%#v, want blocked without generic slots", answer.AnswerState, answer.EvidenceSlots)
	}
	if len(answer.MissingEvidence) != 1 || answer.MissingEvidence[0].Code != "unresolved_evidence_slot" {
		t.Fatalf("missing evidence = %#v, want unresolved slot gap", answer.MissingEvidence)
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

func TestRecordDecisionGlobalConditionalDoesNotApproveBlockedRun(t *testing.T) {
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

	if record.Status != ports.QuestionnaireStatusNeedsInput || record.Decision != ports.QuestionnaireDecisionApprovedWithConditions {
		t.Fatalf("workflow = %s/%s, want needs_input/approved_with_conditions", record.Status, record.Decision)
	}
}

func TestRecordDecisionQuestionNeedsInputBlocksRun(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	record := NewRunRecord(NewRunRequest{
		TenantID:  "tenant-1",
		Direction: ports.QuestionnaireDirectionCustomerSecurityReview,
		Questions: []ports.QuestionnaireQuestion{{
			ID:            "q-1",
			Question:      "Do you enforce MFA for users?",
			RequiredSlots: []string{"identity_mfa"},
		}},
	}, now)
	record = ProcessEvidenceAnswers(record, []evidencepackets.QuestionnaireAnswer{
		baseEvidenceAnswer("Do you enforce MFA for users?", "supported", "ready", "current"),
	}, now)
	if record.Status != ports.QuestionnaireStatusReadyForApproval || record.Decision != ports.QuestionnaireDecisionNeedsInput {
		t.Fatalf("workflow before decision = %s/%s, want ready_for_approval/needs_input", record.Status, record.Decision)
	}

	record = RecordDecision(record, ports.QuestionnaireDecision{
		QuestionID: "q-1",
		Decision:   ports.QuestionnaireDecisionNeedsInput,
		Reason:     "Attach a fresh export.",
		ActorID:    "security@example.com",
	}, now.Add(time.Minute))

	if record.Status != ports.QuestionnaireStatusNeedsInput {
		t.Fatalf("status = %s, want needs_input", record.Status)
	}
	if got := record.Answers[0]; got.AnswerState != ports.QuestionnaireAnswerBlocked || got.ReviewState != ports.QuestionnaireReviewBlocked {
		t.Fatalf("answer state = %s/%s, want blocked/blocked", got.AnswerState, got.ReviewState)
	}
}

func TestAddCommentPrependsCommentAndTimeline(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	record := NewRunRecord(NewRunRequest{
		TenantID:  "tenant-1",
		Direction: ports.QuestionnaireDirectionCustomerSecurityReview,
		Questions: []ports.QuestionnaireQuestion{{
			ID:       "q-1",
			Question: "Attach SOC 2 report.",
		}},
	}, now)

	record = AddComment(record, ports.QuestionnaireComment{
		QuestionID: "q-1",
		ActorID:    "attacker@example.com",
		Body:       "Owner asked for the current report.",
	}, "security@example.com", now.Add(time.Minute))

	if len(record.Comments) != 1 || record.Comments[0].ActorID != "security@example.com" {
		t.Fatalf("comments = %#v, want actor-filled comment", record.Comments)
	}
	if len(record.Timeline) < 2 || record.Timeline[len(record.Timeline)-1].EventType != ports.QuestionnaireEventCommented {
		t.Fatalf("timeline = %#v, want comment event", record.Timeline)
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

func TestSummarizeRunIgnoresGapsForNotApplicableAnswers(t *testing.T) {
	record := SummarizeRun(ports.QuestionnaireRunRecord{
		QuestionnaireRunContent: ports.QuestionnaireRunContent{
			Answers: []ports.QuestionnaireRunAnswer{{
				ID:          "a-1",
				QuestionID:  "q-1",
				AnswerState: ports.QuestionnaireAnswerNotApplicable,
				ReviewState: ports.QuestionnaireReviewReady,
				MissingEvidence: []ports.QuestionnaireEvidenceGap{{
					Code: "missing_required_evidence",
				}},
			}},
		},
	})

	if record.MissingEvidence != 0 || record.StaleEvidence != 0 {
		t.Fatalf("gap counts = missing %d stale %d, want 0/0", record.MissingEvidence, record.StaleEvidence)
	}
}

func ptrEvidenceAnswer(answer evidencepackets.QuestionnaireAnswer) *evidencepackets.QuestionnaireAnswer {
	return &answer
}

func baseEvidenceAnswer(question string, answerState string, reviewState string, freshness string) evidencepackets.QuestionnaireAnswer {
	evidenceType, sourceID := evidenceRefForQuestion(question)
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
			EvidenceType:     evidenceType,
			SourceID:         sourceID,
			Freshness:        evidencepackets.EvidenceFreshness{Status: freshness, ObservedAt: "2026-06-01T00:00:00Z"},
		}},
		EvidencePackets: []string{"packet-1"},
		Citations:       evidencepackets.EvidenceCitations{EvidenceIDs: []string{"evidence-1"}},
		Freshness:       evidencepackets.EvidenceFreshness{Status: freshness, ObservedAt: "2026-06-01T00:00:00Z"},
	}
}

func evidenceRefForQuestion(question string) (string, string) {
	slots := requiredSlotsForTestQuestion(question)
	if len(slots) == 0 {
		return "control_test", "okta"
	}
	switch slots[0] {
	case "access_review":
		return "access_review", "okta"
	case "audit_report":
		return "audit_report", "trust-center"
	case "encryption":
		return "encryption_evidence", "kms"
	case "identity_mfa":
		return "identity_mfa", "okta"
	case "incident_response":
		return "incident_response", "pagerduty"
	case "policy":
		return "policy_document", "policy-library"
	case "subprocessors":
		return "subprocessor_list", "trust-center"
	case "ai_data_use":
		return "ai_data_use", "legal"
	default:
		return "control_test", "okta"
	}
}

func requiredSlotsForTestQuestion(question string) []string {
	normalized := strings.ToLower(question)
	switch {
	case strings.Contains(normalized, "mfa") || strings.Contains(normalized, "multi-factor"):
		return []string{"identity_mfa"}
	case strings.Contains(normalized, "access"):
		return []string{"access_review"}
	case strings.Contains(normalized, "audit") || strings.Contains(normalized, "soc"):
		return []string{"audit_report"}
	case strings.Contains(normalized, "encrypt"):
		return []string{"encryption"}
	case strings.Contains(normalized, "incident"):
		return []string{"incident_response"}
	case strings.Contains(normalized, "policy"):
		return []string{"policy"}
	case strings.Contains(normalized, "vendor") || strings.Contains(normalized, "subprocessor"):
		return []string{"subprocessors"}
	case strings.Contains(normalized, "ai") || strings.Contains(normalized, "training"):
		return []string{"ai_data_use"}
	default:
		return nil
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

func withEvidenceType(answer evidencepackets.QuestionnaireAnswer, evidenceType string, sourceID string) evidencepackets.QuestionnaireAnswer {
	for index := range answer.SourceEvidence {
		answer.SourceEvidence[index].EvidenceType = evidenceType
		answer.SourceEvidence[index].SourceID = sourceID
	}
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

func slotState(slots []ports.QuestionnaireEvidenceSlot, id string) string {
	for _, slot := range slots {
		if slot.ID == id {
			return slot.State
		}
	}
	return ""
}
