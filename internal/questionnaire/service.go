package questionnaire

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/evidencepackets"
	"github.com/writer/cerebro/internal/ports"
)

type NewRunRequest struct {
	TenantID       string
	Direction      string
	Title          string
	Requester      string
	CustomerName   string
	VendorURN      string
	VendorID       string
	SourceID       string
	RuntimeID      string
	UploadID       string
	SourceFilename string
	SourceFormat   string
	OwnerID        string
	AssignedTeam   string
	DueAt          *time.Time
	Questions      []ports.QuestionnaireQuestion
	Attributes     map[string]string
}

type UpdateQuestionRequest struct {
	QuestionID     string
	RequiredSlots  []string
	MappedControls []string
	OwnerID        string
	AnswerState    string
	ReviewState    string
	UpdatedBy      string
	UpdateReason   string
	ClearOwner     bool
	ClearSlots     bool
	ClearControls  bool
}

func NewRunRecord(request NewRunRequest, now time.Time) ports.QuestionnaireRunRecord {
	now = normalizeNow(now)
	direction := strings.TrimSpace(request.Direction)
	title := strings.TrimSpace(request.Title)
	questions := normalizeQuestions(request.Questions)
	record := ports.QuestionnaireRunRecord{
		QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{
			TenantID: strings.TrimSpace(request.TenantID),
			RunID: stableID("questionnaire-run",
				request.TenantID,
				direction,
				request.Requester,
				request.CustomerName,
				request.VendorURN,
				request.UploadID,
				request.SourceFilename,
				title,
			),
			Title: strings.TrimSpace(title),
		},
		QuestionnaireRunSource: ports.QuestionnaireRunSource{
			Direction:      direction,
			Requester:      strings.TrimSpace(request.Requester),
			CustomerName:   strings.TrimSpace(request.CustomerName),
			VendorURN:      strings.TrimSpace(request.VendorURN),
			VendorID:       strings.TrimSpace(request.VendorID),
			SourceID:       strings.TrimSpace(request.SourceID),
			RuntimeID:      strings.TrimSpace(request.RuntimeID),
			UploadID:       strings.TrimSpace(request.UploadID),
			SourceFilename: strings.TrimSpace(request.SourceFilename),
			SourceFormat:   strings.TrimSpace(request.SourceFormat),
		},
		QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{
			Status:       ports.QuestionnaireStatusIntake,
			OwnerID:      strings.TrimSpace(request.OwnerID),
			AssignedTeam: strings.TrimSpace(request.AssignedTeam),
			Decision:     ports.QuestionnaireDecisionNeedsInput,
		},
		QuestionnaireRunContent: ports.QuestionnaireRunContent{
			Questions: questions,
		},
		QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{
			Attributes: copyStringMap(request.Attributes),
			DueAt:      request.DueAt,
			CreatedAt:  now,
			UpdatedAt:  now,
		},
	}
	record.Timeline = append(record.Timeline, Timeline(ports.QuestionnaireEventCreated, firstNonEmpty(record.OwnerID, record.AssignedTeam), "Questionnaire run created", nil, now))
	return SummarizeRun(record)
}

func ProcessEvidenceAnswers(record ports.QuestionnaireRunRecord, evidenceAnswers []evidencepackets.QuestionnaireAnswer, now time.Time) ports.QuestionnaireRunRecord {
	now = normalizeNow(now)
	previousStatus := record.Status
	previousDecision := record.Decision
	previousDecisionReason := record.DecisionReason
	previousAnswers := questionnaireAnswersByQuestionID(record.Answers)
	record.UpdatedAt = now
	record.Questions = normalizeQuestions(record.Questions)
	answers := make([]ports.QuestionnaireRunAnswer, 0, len(record.Questions))
	usedEvidenceAnswerIDs := map[string]struct{}{}
	for _, question := range record.Questions {
		match := bestEvidenceAnswerForQuestion(question, evidenceAnswers, usedEvidenceAnswerIDs)
		if match != nil {
			usedEvidenceAnswerIDs[match.ID] = struct{}{}
		}
		answer := compileAnswer(record, question, match)
		if previous, ok := previousAnswers[answer.QuestionID]; ok {
			answer = preserveAnswerReviewDecision(answer, previous)
		}
		answers = append(answers, answer)
	}
	sort.Slice(answers, func(i, j int) bool { return answers[i].QuestionID < answers[j].QuestionID })
	record.Answers = answers
	if terminalQuestionnaireDecision(previousStatus, previousDecision) {
		record.Status = previousStatus
		record.Decision = previousDecision
		record.DecisionReason = previousDecisionReason
	} else {
		record.Status = statusFromAnswers(answers)
		record.Decision = decisionFromStatus(record.Status)
	}
	record.Timeline = append(record.Timeline, Timeline(ports.QuestionnaireEventProcessed, firstNonEmpty(record.OwnerID, record.AssignedTeam), "Questionnaire answers refreshed from evidence", map[string]string{
		"answer_count": fmt.Sprint(len(answers)),
		"status":       record.Status,
	}, now))
	return SummarizeRun(record)
}

func SummarizeRun(record ports.QuestionnaireRunRecord) ports.QuestionnaireRunRecord {
	ready, blocked, review, missing, stale, unassigned := 0, 0, 0, 0, 0, 0
	assignedQuestions := map[string]struct{}{}
	for _, assignment := range record.Assignments {
		if (assignment.Status == "" || assignment.Status == "open") && firstNonEmpty(assignment.OwnerID, assignment.Team) != "" {
			assignedQuestions[assignment.QuestionID] = struct{}{}
		}
	}
	for _, answer := range record.Answers {
		switch answer.AnswerState {
		case ports.QuestionnaireAnswerSupported:
			ready++
		case ports.QuestionnaireAnswerBlocked:
			blocked++
		case ports.QuestionnaireAnswerNeedsReview, ports.QuestionnaireAnswerPartial:
			review++
		}
		if answer.AnswerState != ports.QuestionnaireAnswerNotApplicable {
			for _, gap := range answer.MissingEvidence {
				if gap.Code == "stale_evidence" {
					stale++
				} else {
					missing++
				}
			}
		}
	}
	for _, question := range record.Questions {
		if question.OwnerID != "" {
			continue
		}
		if _, ok := assignedQuestions[question.ID]; !ok {
			unassigned++
		}
	}
	record.ReadyAnswerCount = ready
	record.BlockedAnswerCount = blocked
	record.ReviewAnswerCount = review
	record.MissingEvidence = missing
	record.StaleEvidence = stale
	record.UnassignedCount = unassigned
	return record
}

func NormalizeQuestionsForIntake(questions []ports.QuestionnaireQuestion) []ports.QuestionnaireQuestion {
	return normalizeQuestions(questions)
}

func AddAssignment(record ports.QuestionnaireRunRecord, assignment ports.QuestionnaireAssignment, actorID string, now time.Time) ports.QuestionnaireRunRecord {
	now = normalizeNow(now)
	assignment.ID = firstNonEmpty(assignment.ID, stableID("questionnaire-assignment", record.RunID, assignment.QuestionID, assignment.OwnerID, assignment.Team, fmt.Sprint(len(record.Assignments)+1)))
	assignment.Status = firstNonEmpty(assignment.Status, "open")
	if assignment.CreatedAt == nil {
		assignment.CreatedAt = &now
	}
	record.Assignments = append(record.Assignments, assignment)
	for index := range record.Questions {
		if record.Questions[index].ID == assignment.QuestionID {
			record.Questions[index].OwnerID = firstNonEmpty(record.Questions[index].OwnerID, assignment.OwnerID)
			if record.Questions[index].ReviewState == ports.QuestionnaireReviewBlocked {
				record.Questions[index].ReviewState = ports.QuestionnaireReviewNeedsReview
			}
		}
	}
	record.UpdatedAt = now
	record.Timeline = append(record.Timeline, Timeline(ports.QuestionnaireEventAssigned, actorID, "Questionnaire answer assigned", map[string]string{"question_id": assignment.QuestionID, "owner_id": assignment.OwnerID}, now))
	return SummarizeRun(record)
}

func AddComment(record ports.QuestionnaireRunRecord, comment ports.QuestionnaireComment, actorID string, now time.Time) ports.QuestionnaireRunRecord {
	now = normalizeNow(now)
	comment.ActorID = strings.TrimSpace(actorID)
	comment.ID = firstNonEmpty(comment.ID, stableID("questionnaire-comment", record.RunID, comment.QuestionID, comment.ActorID, comment.Body, now.Format(time.RFC3339Nano)))
	if comment.CreatedAt == nil {
		comment.CreatedAt = &now
	}
	record.Comments = append([]ports.QuestionnaireComment{comment}, record.Comments...)
	record.UpdatedAt = now
	record.Timeline = append(record.Timeline, Timeline(ports.QuestionnaireEventCommented, comment.ActorID, "Questionnaire comment added", map[string]string{"question_id": comment.QuestionID}, now))
	return SummarizeRun(record)
}

func UpdateQuestion(record ports.QuestionnaireRunRecord, request UpdateQuestionRequest, now time.Time) ports.QuestionnaireRunRecord {
	now = normalizeNow(now)
	questionID := strings.TrimSpace(request.QuestionID)
	for index := range record.Questions {
		if record.Questions[index].ID != questionID {
			continue
		}
		if request.ClearSlots {
			record.Questions[index].RequiredSlots = nil
		} else if request.RequiredSlots != nil {
			record.Questions[index].RequiredSlots = uniqueSorted(request.RequiredSlots)
		}
		if request.ClearControls {
			record.Questions[index].MappedControls = nil
		} else if request.MappedControls != nil {
			record.Questions[index].MappedControls = uniqueSorted(request.MappedControls)
		}
		if request.ClearOwner {
			record.Questions[index].OwnerID = ""
		} else if strings.TrimSpace(request.OwnerID) != "" {
			record.Questions[index].OwnerID = strings.TrimSpace(request.OwnerID)
		}
		record.Questions[index].AnswerState = firstNonEmpty(request.AnswerState, record.Questions[index].AnswerState, ports.QuestionnaireAnswerNeedsReview)
		record.Questions[index].ReviewState = firstNonEmpty(request.ReviewState, record.Questions[index].ReviewState, ports.QuestionnaireReviewNeedsReview)
		break
	}
	record.Questions = normalizeQuestions(record.Questions)
	record.UpdatedAt = now
	record.Timeline = append(record.Timeline, Timeline(ports.QuestionnaireEventUpdated, request.UpdatedBy, "Questionnaire question updated", map[string]string{
		"question_id": questionID,
		"reason":      strings.TrimSpace(request.UpdateReason),
	}, now))
	return SummarizeRun(record)
}

func RecordDecision(record ports.QuestionnaireRunRecord, decision ports.QuestionnaireDecision, now time.Time) ports.QuestionnaireRunRecord {
	now = normalizeNow(now)
	decision.ID = firstNonEmpty(decision.ID, stableID("questionnaire-decision", record.RunID, decision.QuestionID, decision.Decision, decision.ActorID, now.Format(time.RFC3339Nano)))
	if decision.CreatedAt == nil {
		decision.CreatedAt = &now
	}
	record.Decisions = append(record.Decisions, decision)
	for index := range record.Answers {
		if decision.QuestionID == "" || record.Answers[index].QuestionID == decision.QuestionID {
			record.Answers[index].ReviewerDecision = decision.Decision
			record.Answers[index].ReviewerReason = decision.Reason
			switch decision.Decision {
			case ports.QuestionnaireDecisionApproved, ports.QuestionnaireDecisionApprovedWithConditions:
				record.Answers[index].ReviewState = ports.QuestionnaireReviewApproved
			case ports.QuestionnaireDecisionNeedsInput:
				record.Answers[index].ReviewState = ports.QuestionnaireReviewBlocked
				record.Answers[index].AnswerState = ports.QuestionnaireAnswerBlocked
			case ports.QuestionnaireDecisionRejected:
				record.Answers[index].ReviewState = ports.QuestionnaireReviewRejected
				record.Answers[index].AnswerState = ports.QuestionnaireAnswerBlocked
			}
		}
	}
	record.Status = statusFromAnswers(record.Answers)
	if decision.QuestionID == "" {
		switch decision.Decision {
		case ports.QuestionnaireDecisionApproved, ports.QuestionnaireDecisionApprovedWithConditions:
			if blockedAnswerCount(record.Answers) == 0 {
				record.Status = ports.QuestionnaireStatusApproved
			}
		case ports.QuestionnaireDecisionNeedsInput:
			record.Status = ports.QuestionnaireStatusNeedsInput
		case ports.QuestionnaireDecisionRejected:
			record.Status = ports.QuestionnaireStatusRejected
		}
		record.Decision = decision.Decision
		record.DecisionReason = decision.Reason
	}
	record.UpdatedAt = now
	record.Timeline = append(record.Timeline, Timeline(ports.QuestionnaireEventDecided, decision.ActorID, "Questionnaire decision recorded", map[string]string{"question_id": decision.QuestionID, "decision": decision.Decision}, now))
	return SummarizeRun(record)
}

func Timeline(eventType string, actorID string, summary string, attrs map[string]string, at time.Time) ports.QuestionnaireTimeline {
	at = normalizeNow(at)
	return ports.QuestionnaireTimeline{
		ID:         stableID("questionnaire-timeline", eventType, actorID, summary, at.Format(time.RFC3339Nano)),
		EventType:  strings.TrimSpace(eventType),
		ActorID:    strings.TrimSpace(actorID),
		Summary:    strings.TrimSpace(summary),
		Attributes: copyStringMap(attrs),
		CreatedAt:  &at,
	}
}

func Event(record ports.QuestionnaireRunRecord, eventType string, actorID string, summary string, payload map[string]string, at time.Time) ports.QuestionnaireRunEventRecord {
	at = normalizeNow(at)
	return ports.QuestionnaireRunEventRecord{
		ID:        stableID("questionnaire-event", record.TenantID, record.RunID, eventType, actorID, summary, at.Format(time.RFC3339Nano)),
		TenantID:  strings.TrimSpace(record.TenantID),
		RunID:     strings.TrimSpace(record.RunID),
		EventType: strings.TrimSpace(eventType),
		ActorID:   strings.TrimSpace(actorID),
		Summary:   strings.TrimSpace(summary),
		Payload:   copyStringMap(payload),
		CreatedAt: at,
	}
}

func compileAnswer(record ports.QuestionnaireRunRecord, question ports.QuestionnaireQuestion, evidenceAnswer *evidencepackets.QuestionnaireAnswer) ports.QuestionnaireRunAnswer {
	requiredSlots := uniqueSorted(append([]string(nil), question.RequiredSlots...))
	if record.Direction == ports.QuestionnaireDirectionVendorReview {
		requiredSlots = uniqueSorted(append(requiredSlots, "vendor_profile"))
	}
	answer := ports.QuestionnaireRunAnswer{
		ID:          stableID("questionnaire-answer", record.RunID, question.ID),
		QuestionID:  question.ID,
		Question:    question.Question,
		AnswerState: ports.QuestionnaireAnswerBlocked,
		ReviewState: ports.QuestionnaireReviewBlocked,
		Confidence:  "low",
		Freshness:   ports.QuestionnaireFreshness{Status: "missing"},
	}
	if len(requiredSlots) == 0 {
		answer.MissingEvidence = []ports.QuestionnaireEvidenceGap{{
			ID:     stableID("questionnaire-gap", question.ID, "unresolved_slot"),
			Code:   "unresolved_evidence_slot",
			Reason: "No required evidence slot could be resolved for this question.",
		}}
		answer.DraftAnswer = "No answer is ready. No required evidence slot could be resolved."
		return answer
	}
	if evidenceAnswer == nil {
		answer.EvidenceSlots = missingSlots(requiredSlots, "No matching evidence answer was found.")
		answer.MissingEvidence = gapsForMissingSlots(question.ID, requiredSlots, "No matching evidence answer was found.")
		answer.DraftAnswer = "No answer is ready. Required evidence is missing."
		return answer
	}
	answer.SourceAnswerID = evidenceAnswer.ID
	answer.Controls = controlIDs(evidenceAnswer.Controls)
	answer.Citations = citationsFromEvidenceAnswer(*evidenceAnswer)
	answer.Freshness = freshnessFromEvidenceAnswer(*evidenceAnswer)
	answer.EvidenceSlots = slotsFromEvidenceAnswer(requiredSlots, *evidenceAnswer)
	answer.MissingEvidence = gapsFromEvidenceAnswer(question.ID, requiredSlots, *evidenceAnswer, answer.EvidenceSlots)
	answer.Conflicts = conflictsFromEvidenceAnswer(question.ID, *evidenceAnswer)
	answer.Confidence = evidenceAnswer.Confidence.Level
	answer.ConfidenceScore = evidenceAnswer.Confidence.Score
	answer.DraftAnswer = draftAnswer(*evidenceAnswer, answer.Citations)
	answer.AnswerState, answer.ReviewState = answerStatesFromEvidence(*evidenceAnswer, answer.EvidenceSlots, answer.MissingEvidence, answer.Conflicts, answer.Freshness)
	if answer.AnswerState == ports.QuestionnaireAnswerNotApplicable {
		answer.EvidenceSlots = nil
		answer.MissingEvidence = nil
		answer.Conflicts = nil
	}
	return answer
}

func questionnaireAnswersByQuestionID(answers []ports.QuestionnaireRunAnswer) map[string]ports.QuestionnaireRunAnswer {
	byID := make(map[string]ports.QuestionnaireRunAnswer, len(answers))
	for _, answer := range answers {
		if answer.QuestionID != "" {
			byID[answer.QuestionID] = answer
		}
	}
	return byID
}

func preserveAnswerReviewDecision(answer ports.QuestionnaireRunAnswer, previous ports.QuestionnaireRunAnswer) ports.QuestionnaireRunAnswer {
	if previous.ReviewerDecision == "" {
		return answer
	}
	answer.ReviewerDecision = previous.ReviewerDecision
	answer.ReviewerReason = previous.ReviewerReason
	switch previous.ReviewerDecision {
	case ports.QuestionnaireDecisionApproved, ports.QuestionnaireDecisionApprovedWithConditions:
		answer.ReviewState = ports.QuestionnaireReviewApproved
	case ports.QuestionnaireDecisionRejected:
		answer.ReviewState = ports.QuestionnaireReviewRejected
	case ports.QuestionnaireDecisionNeedsInput:
		answer.ReviewState = ports.QuestionnaireReviewBlocked
	}
	return answer
}

func terminalQuestionnaireDecision(status string, decision string) bool {
	switch status {
	case ports.QuestionnaireStatusApproved, ports.QuestionnaireStatusRejected:
		return true
	}
	switch decision {
	case ports.QuestionnaireDecisionApproved, ports.QuestionnaireDecisionApprovedWithConditions, ports.QuestionnaireDecisionRejected:
		return true
	default:
		return false
	}
}

func answerStatesFromEvidence(evidenceAnswer evidencepackets.QuestionnaireAnswer, slots []ports.QuestionnaireEvidenceSlot, gaps []ports.QuestionnaireEvidenceGap, conflicts []ports.QuestionnaireEvidenceGap, freshness ports.QuestionnaireFreshness) (string, string) {
	if strings.EqualFold(evidenceAnswer.AnswerState, "not_required") {
		return ports.QuestionnaireAnswerNotApplicable, ports.QuestionnaireReviewReady
	}
	if len(conflicts) > 0 {
		return ports.QuestionnaireAnswerNeedsReview, ports.QuestionnaireReviewNeedsReview
	}
	if requiredSlotMissing(slots) || gapWithCode(gaps, "missing_required_evidence") {
		return ports.QuestionnaireAnswerBlocked, ports.QuestionnaireReviewBlocked
	}
	if freshness.Status == "stale" || gapWithCode(gaps, "stale_evidence") {
		return ports.QuestionnaireAnswerPartial, ports.QuestionnaireReviewNeedsReview
	}
	if evidenceAnswer.ReviewState == "needs_review" || evidenceAnswer.AnswerState == "manual_review" || gapWithCode(gaps, "manual_review_required") {
		return ports.QuestionnaireAnswerNeedsReview, ports.QuestionnaireReviewNeedsReview
	}
	if len(gaps) > 0 || strings.EqualFold(evidenceAnswer.AnswerState, "partial") {
		return ports.QuestionnaireAnswerPartial, ports.QuestionnaireReviewNeedsReview
	}
	if len(evidenceAnswer.Citations.EvidenceIDs) == 0 && len(evidenceAnswer.EvidencePackets) == 0 {
		return ports.QuestionnaireAnswerBlocked, ports.QuestionnaireReviewBlocked
	}
	return ports.QuestionnaireAnswerSupported, ports.QuestionnaireReviewReady
}

func slotsFromEvidenceAnswer(requiredSlots []string, evidenceAnswer evidencepackets.QuestionnaireAnswer) []ports.QuestionnaireEvidenceSlot {
	slots := make([]ports.QuestionnaireEvidenceSlot, 0, len(requiredSlots))
	for _, slotID := range requiredSlots {
		matches := matchingSlotEvidence(slotID, evidenceAnswer)
		slot := ports.QuestionnaireEvidenceSlot{
			ID:       slotID,
			Label:    slotLabel(slotID),
			State:    "missing",
			Required: true,
		}
		if len(matches) > 0 {
			slot.State = "satisfied"
			slot.CitationIDs = matches
		} else {
			slot.MissingReasons = []string{"No current citation matched the required evidence slot."}
		}
		if slot.State == "satisfied" && slotEvidenceState(slotID, evidenceAnswer, "stale") {
			slot.State = "stale"
		}
		if slot.State == "satisfied" && (evidenceAnswer.AnswerState == "manual_review" || slotEvidenceState(slotID, evidenceAnswer, "needs_review")) {
			slot.State = "needs_review"
		}
		slots = append(slots, slot)
	}
	return slots
}

func matchingSlotEvidence(slotID string, answer evidencepackets.QuestionnaireAnswer) []string {
	ids := []string{}
	for _, ref := range questionnaireEvidenceRefs(answer) {
		if evidenceRefMatchesSlot(slotID, ref) {
			ids = append(ids, firstNonEmpty(ref.ID, ref.EvidencePacketID))
		}
	}
	return uniqueSorted(ids)
}

func slotEvidenceState(slotID string, answer evidencepackets.QuestionnaireAnswer, state string) bool {
	for _, ref := range questionnaireEvidenceRefs(answer) {
		if !evidenceRefMatchesSlot(slotID, ref) {
			continue
		}
		if strings.EqualFold(ref.Freshness.Status, state) || strings.EqualFold(ref.ReviewState, state) {
			return true
		}
	}
	return false
}

func questionnaireEvidenceRefs(answer evidencepackets.QuestionnaireAnswer) []evidencepackets.QuestionnaireEvidenceRef {
	refs := append([]evidencepackets.QuestionnaireEvidenceRef{}, answer.SourceEvidence...)
	refs = append(refs, answer.PolicyDocuments...)
	return refs
}

func evidenceRefMatchesSlot(slotID string, ref evidencepackets.QuestionnaireEvidenceRef) bool {
	for _, value := range []string{ref.EvidenceType, ref.ID, ref.EvidencePacketID} {
		if evidenceTypeSatisfiesSlot(slotID, value) {
			return true
		}
	}
	return false
}

func evidenceTypeSatisfiesSlot(slotID string, value string) bool {
	slotID = normalizeEvidenceToken(slotID)
	value = normalizeEvidenceToken(value)
	if slotID == "" || value == "" {
		return false
	}
	if value == slotID {
		return true
	}
	for _, allowed := range evidenceTypesForSlot(slotID) {
		if value == normalizeEvidenceToken(allowed) {
			return true
		}
	}
	return false
}

func evidenceTypesForSlot(slotID string) []string {
	switch normalizeEvidenceToken(slotID) {
	case "identity_mfa":
		return []string{"identity_configuration", "identity_governance", "multi_factor_authentication", "mfa_configuration"}
	case "access_review":
		return []string{"access_review", "identity_governance", "user_access_review", "access_governance"}
	case "encryption":
		return []string{"encryption_configuration", "encryption_evidence", "data_protection", "key_management"}
	case "incident_response":
		return []string{"incident_response", "incident_management", "incident_response_plan"}
	case "subprocessors":
		return []string{"subprocessor_list", "third_party_risk", "vendor_diligence", "dpa"}
	case "audit_report":
		return []string{"assurance_document", "audit_report", "soc_2", "soc2", "iso_27001"}
	case "policy":
		return []string{"policy", "policy_document", "procedure_document", "standard_document"}
	case "ai_data_use":
		return []string{"ai_data_use", "ai_governance", "model_governance", "data_use"}
	case "vendor_profile":
		return []string{"vendor_profile", "third_party_risk", "vendor_diligence", "subprocessor_list"}
	default:
		return nil
	}
}

func missingSlots(requiredSlots []string, reason string) []ports.QuestionnaireEvidenceSlot {
	slots := make([]ports.QuestionnaireEvidenceSlot, 0, len(requiredSlots))
	for _, slotID := range requiredSlots {
		slots = append(slots, ports.QuestionnaireEvidenceSlot{
			ID:             slotID,
			Label:          slotLabel(slotID),
			State:          "missing",
			Required:       true,
			MissingReasons: []string{reason},
		})
	}
	return slots
}

func gapsForMissingSlots(questionID string, requiredSlots []string, reason string) []ports.QuestionnaireEvidenceGap {
	gaps := make([]ports.QuestionnaireEvidenceGap, 0, len(requiredSlots))
	for _, slotID := range requiredSlots {
		gaps = append(gaps, ports.QuestionnaireEvidenceGap{
			ID:     stableID("questionnaire-gap", questionID, slotID, "missing"),
			Code:   "missing_required_evidence",
			Reason: reason,
			SlotID: slotID,
		})
	}
	return gaps
}

func gapsFromEvidenceAnswer(questionID string, requiredSlots []string, evidenceAnswer evidencepackets.QuestionnaireAnswer, slots []ports.QuestionnaireEvidenceSlot) []ports.QuestionnaireEvidenceGap {
	gaps := []ports.QuestionnaireEvidenceGap{}
	for _, gap := range evidenceAnswer.MissingEvidence {
		slotID := slotForGap(gap.Code, requiredSlots)
		gaps = append(gaps, ports.QuestionnaireEvidenceGap{
			ID:        firstNonEmpty(gap.ID, stableID("questionnaire-gap", questionID, gap.Code, gap.PacketID)),
			Code:      gap.Code,
			Reason:    gap.Reason,
			SlotID:    slotID,
			ControlID: gap.ControlID,
			PacketID:  gap.PacketID,
		})
	}
	for _, slot := range slots {
		if slot.Required && slot.State == "missing" {
			gaps = append(gaps, ports.QuestionnaireEvidenceGap{
				ID:     stableID("questionnaire-gap", questionID, slot.ID, "missing"),
				Code:   "missing_required_evidence",
				Reason: firstNonEmpty(strings.Join(slot.MissingReasons, "; "), "Required evidence is missing."),
				SlotID: slot.ID,
			})
		}
	}
	return dedupeGaps(gaps)
}

func conflictsFromEvidenceAnswer(questionID string, evidenceAnswer evidencepackets.QuestionnaireAnswer) []ports.QuestionnaireEvidenceGap {
	conflicts := []ports.QuestionnaireEvidenceGap{}
	for _, unsupported := range evidenceAnswer.Reasoning.UnsupportedClaims {
		if strings.TrimSpace(unsupported) == "" {
			continue
		}
		conflicts = append(conflicts, ports.QuestionnaireEvidenceGap{
			ID:     stableID("questionnaire-conflict", questionID, unsupported),
			Code:   "unsupported_claim",
			Reason: unsupported,
		})
	}
	return conflicts
}

func citationsFromEvidenceAnswer(answer evidencepackets.QuestionnaireAnswer) []ports.QuestionnaireCitation {
	citations := []ports.QuestionnaireCitation{}
	for _, ref := range append(append([]evidencepackets.QuestionnaireEvidenceRef{}, answer.SourceEvidence...), answer.PolicyDocuments...) {
		citationID := firstNonEmpty(ref.ID, ref.EvidencePacketID)
		if citationID == "" {
			continue
		}
		citations = append(citations, ports.QuestionnaireCitation{
			ID:               citationID,
			Label:            firstNonEmpty(ref.EvidenceType, ref.Source, ref.SourceID, ref.RuntimeID, citationID),
			Source:           firstNonEmpty(ref.SourceID, ref.Source, ref.RuntimeID),
			EvidencePacketID: ref.EvidencePacketID,
			EvidenceID:       ref.ID,
			FreshnessStatus:  ref.Freshness.Status,
			ObservedAt:       ref.Freshness.ObservedAt,
			ExpiresAt:        ref.Freshness.ExpiresAt,
		})
	}
	for _, packetID := range answer.EvidencePackets {
		if packetID == "" || hasCitation(citations, packetID) {
			continue
		}
		citations = append(citations, ports.QuestionnaireCitation{ID: packetID, Label: "Evidence packet", EvidencePacketID: packetID, FreshnessStatus: answer.Freshness.Status, ObservedAt: answer.Freshness.ObservedAt, ExpiresAt: answer.Freshness.ExpiresAt})
	}
	sort.Slice(citations, func(i, j int) bool { return citations[i].ID < citations[j].ID })
	return citations
}

func freshnessFromEvidenceAnswer(answer evidencepackets.QuestionnaireAnswer) ports.QuestionnaireFreshness {
	return ports.QuestionnaireFreshness{
		Status:     firstNonEmpty(answer.Freshness.Status, "missing"),
		ObservedAt: answer.Freshness.ObservedAt,
		ExpiresAt:  answer.Freshness.ExpiresAt,
		Reason:     answer.Freshness.Reason,
	}
}

func draftAnswer(answer evidencepackets.QuestionnaireAnswer, citations []ports.QuestionnaireCitation) string {
	if text := strings.TrimSpace(answer.Answer); text != "" {
		return text
	}
	if answer.AnswerState == "not_required" {
		return "No answer is required for this question."
	}
	if len(citations) == 0 {
		return "No answer is ready. Supporting evidence is missing."
	}
	return "Evidence is available, but no approved answer text is attached to the evidence record."
}

func bestEvidenceAnswerForQuestion(question ports.QuestionnaireQuestion, answers []evidencepackets.QuestionnaireAnswer, used map[string]struct{}) *evidencepackets.QuestionnaireAnswer {
	var best *evidencepackets.QuestionnaireAnswer
	bestScore := -1
	for index := range answers {
		answer := &answers[index]
		if _, ok := used[answer.ID]; ok {
			continue
		}
		score := evidenceAnswerMatchScore(question, *answer)
		if score > bestScore {
			bestScore = score
			best = answer
		}
	}
	if bestScore <= 0 {
		return nil
	}
	return best
}

func evidenceAnswerMatchScore(question ports.QuestionnaireQuestion, answer evidencepackets.QuestionnaireAnswer) int {
	if strings.TrimSpace(question.ID) != "" {
		if strings.EqualFold(question.ID, answer.QuestionID) || strings.EqualFold(question.ID, answer.ID) {
			return 100
		}
	}
	controlMatches := 0
	for _, control := range answer.Controls {
		for _, mapped := range question.MappedControls {
			if strings.EqualFold(control.ControlID, mapped) || strings.EqualFold(control.ID, mapped) {
				controlMatches++
			}
		}
	}
	if controlMatches > 0 {
		return 80 + controlMatches
	}
	if len(question.RequiredSlots) > 0 {
		matchedSlots := 0
		for _, slot := range question.RequiredSlots {
			if len(matchingSlotEvidence(slot, answer)) > 0 {
				matchedSlots++
			}
		}
		if matchedSlots == len(question.RequiredSlots) {
			return 60 + matchedSlots
		}
	}
	return 0
}

func normalizeQuestions(questions []ports.QuestionnaireQuestion) []ports.QuestionnaireQuestion {
	result := make([]ports.QuestionnaireQuestion, 0, len(questions))
	for index, question := range questions {
		question.Question = strings.TrimSpace(question.Question)
		if question.Question == "" {
			continue
		}
		question.ID = firstNonEmpty(question.ID, stableID("questionnaire-question", question.Question, fmt.Sprint(index)))
		question.NormalizedQuestion = firstNonEmpty(question.NormalizedQuestion, normalizedQuestion(question.Question))
		question.RequiredSlots = uniqueSorted(append([]string(nil), question.RequiredSlots...))
		question.MappedControls = uniqueSorted(question.MappedControls)
		question.AnswerState = firstNonEmpty(question.AnswerState, ports.QuestionnaireAnswerBlocked)
		question.ReviewState = firstNonEmpty(question.ReviewState, ports.QuestionnaireReviewBlocked)
		result = append(result, question)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func statusFromAnswers(answers []ports.QuestionnaireRunAnswer) string {
	if len(answers) == 0 {
		return ports.QuestionnaireStatusIntake
	}
	blocked := false
	review := false
	for _, answer := range answers {
		switch answer.AnswerState {
		case ports.QuestionnaireAnswerBlocked:
			blocked = true
		case ports.QuestionnaireAnswerNeedsReview, ports.QuestionnaireAnswerPartial:
			review = true
		}
		switch answer.ReviewState {
		case ports.QuestionnaireReviewBlocked, ports.QuestionnaireReviewRejected:
			blocked = true
		case ports.QuestionnaireReviewNeedsReview:
			review = true
		}
	}
	if blocked {
		return ports.QuestionnaireStatusNeedsInput
	}
	if review {
		return ports.QuestionnaireStatusReadyForApproval
	}
	return ports.QuestionnaireStatusReadyForApproval
}

func blockedAnswerCount(answers []ports.QuestionnaireRunAnswer) int {
	count := 0
	for _, answer := range answers {
		if answer.AnswerState == ports.QuestionnaireAnswerBlocked || answer.ReviewState == ports.QuestionnaireReviewBlocked || answer.ReviewState == ports.QuestionnaireReviewRejected {
			count++
		}
	}
	return count
}

func decisionFromStatus(status string) string {
	switch status {
	case ports.QuestionnaireStatusApproved:
		return ports.QuestionnaireDecisionApproved
	case ports.QuestionnaireStatusRejected:
		return ports.QuestionnaireDecisionRejected
	default:
		return ports.QuestionnaireDecisionNeedsInput
	}
}

func slotLabel(slot string) string {
	switch slot {
	case "identity_mfa":
		return "MFA evidence"
	case "access_review":
		return "Access review evidence"
	case "encryption":
		return "Encryption evidence"
	case "incident_response":
		return "Incident response evidence"
	case "subprocessors":
		return "Subprocessor evidence"
	case "audit_report":
		return "Audit report"
	case "policy":
		return "Policy document"
	case "ai_data_use":
		return "AI and data-use evidence"
	case "vendor_profile":
		return "Vendor profile"
	default:
		return "Unresolved evidence slot"
	}
}

func slotForGap(code string, slots []string) string {
	switch code {
	case "stale_evidence":
		for _, slot := range slots {
			if slot == "audit_report" || slot == "policy" {
				return slot
			}
		}
	case "manual_review_required":
		if len(slots) > 0 {
			return slots[0]
		}
	}
	if len(slots) > 0 {
		return slots[0]
	}
	return "unresolved_evidence_slot"
}

func controlIDs(controls []evidencepackets.QuestionnaireControlRef) []string {
	ids := make([]string, 0, len(controls))
	for _, control := range controls {
		ids = append(ids, firstNonEmpty(control.ControlID, control.ID))
	}
	return uniqueSorted(ids)
}

func requiredSlotMissing(slots []ports.QuestionnaireEvidenceSlot) bool {
	for _, slot := range slots {
		if slot.Required && slot.State == "missing" {
			return true
		}
	}
	return false
}

func gapWithCode(gaps []ports.QuestionnaireEvidenceGap, code string) bool {
	for _, gap := range gaps {
		if gap.Code == code {
			return true
		}
	}
	return false
}

func hasCitation(citations []ports.QuestionnaireCitation, id string) bool {
	for _, citation := range citations {
		if citation.ID == id || citation.EvidencePacketID == id {
			return true
		}
	}
	return false
}

func dedupeGaps(gaps []ports.QuestionnaireEvidenceGap) []ports.QuestionnaireEvidenceGap {
	seen := map[string]struct{}{}
	result := make([]ports.QuestionnaireEvidenceGap, 0, len(gaps))
	for _, gap := range gaps {
		key := firstNonEmpty(gap.ID, gap.Code+"\x00"+gap.SlotID+"\x00"+gap.PacketID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, gap)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func normalizedQuestion(value string) string {
	return strings.Join(termList(value), " ")
}

func termList(value string) []string {
	value = strings.ToLower(strings.NewReplacer("-", " ", "_", " ", "/", " ").Replace(value))
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	terms := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) > 1 {
			terms = append(terms, part)
		}
	}
	return terms
}

func normalizeEvidenceToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer(".", "_", "-", "_", " ", "_", "/", "_", ":", "_").Replace(value)
	return strings.Trim(value, "_")
}

func stableID(prefix string, values ...string) string {
	hash := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return prefix + "-" + hex.EncodeToString(hash[:])[:18]
}

func normalizeNow(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}

func copyStringMap(values map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			out[key] = value
		}
	}
	return out
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	unique := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
