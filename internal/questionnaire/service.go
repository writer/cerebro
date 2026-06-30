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

func NewRunRecord(request NewRunRequest, now time.Time) ports.QuestionnaireRunRecord {
	now = normalizeNow(now)
	direction := firstNonEmpty(request.Direction, ports.QuestionnaireDirectionCustomerSecurityReview)
	if !ports.IsQuestionnaireDirection(direction) {
		direction = ports.QuestionnaireDirectionCustomerSecurityReview
	}
	title := firstNonEmpty(request.Title, defaultTitle(direction))
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
			SourceFormat:   firstNonEmpty(request.SourceFormat, sourceFormat(request.SourceFilename), "json"),
		},
		QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{
			Status:       ports.QuestionnaireStatusIntake,
			OwnerID:      strings.TrimSpace(request.OwnerID),
			AssignedTeam: firstNonEmpty(request.AssignedTeam, "security"),
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
	record.UpdatedAt = now
	record.Questions = normalizeQuestions(record.Questions)
	if len(record.Questions) == 0 {
		record.Questions = questionsFromEvidenceAnswers(evidenceAnswers)
	}
	answers := make([]ports.QuestionnaireRunAnswer, 0, len(record.Questions))
	usedEvidenceAnswerIDs := map[string]struct{}{}
	for _, question := range record.Questions {
		match := bestEvidenceAnswerForQuestion(question, evidenceAnswers, usedEvidenceAnswerIDs)
		if match != nil {
			usedEvidenceAnswerIDs[match.ID] = struct{}{}
		}
		answer := compileAnswer(record, question, match)
		answers = append(answers, answer)
	}
	for _, evidenceAnswer := range evidenceAnswers {
		if _, ok := usedEvidenceAnswerIDs[evidenceAnswer.ID]; ok {
			continue
		}
		question := questionFromEvidenceAnswer(evidenceAnswer)
		answers = append(answers, compileAnswer(record, question, &evidenceAnswer))
		record.Questions = append(record.Questions, question)
	}
	sort.Slice(answers, func(i, j int) bool { return answers[i].QuestionID < answers[j].QuestionID })
	record.Answers = answers
	record.Status = statusFromAnswers(answers)
	record.Decision = decisionFromStatus(record.Status)
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
		if assignment.Status == "" || assignment.Status == "open" {
			assignedQuestions[assignment.QuestionID] = struct{}{}
		}
	}
	for _, answer := range record.Answers {
		switch answer.AnswerState {
		case ports.QuestionnaireAnswerSupported:
			ready++
		case ports.QuestionnaireAnswerBlocked:
			blocked++
		case ports.QuestionnaireAnswerNeedsReview:
			review++
		}
		for _, gap := range answer.MissingEvidence {
			if gap.Code == "stale_evidence" {
				stale++
			} else {
				missing++
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
			case ports.QuestionnaireDecisionRejected:
				record.Answers[index].ReviewState = ports.QuestionnaireReviewRejected
				record.Answers[index].AnswerState = ports.QuestionnaireAnswerNeedsReview
			}
		}
	}
	record.Status = statusFromAnswers(record.Answers)
	if decision.QuestionID == "" {
		switch decision.Decision {
		case ports.QuestionnaireDecisionApproved:
			record.Status = ports.QuestionnaireStatusApproved
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
	requiredSlots := uniqueSorted(append(append([]string(nil), question.RequiredSlots...), slotsForQuestion(question.Question, record.Direction)...))
	answer := ports.QuestionnaireRunAnswer{
		ID:          stableID("questionnaire-answer", record.RunID, question.ID),
		QuestionID:  question.ID,
		Question:    question.Question,
		AnswerState: ports.QuestionnaireAnswerBlocked,
		ReviewState: ports.QuestionnaireReviewBlocked,
		Confidence:  "low",
		Freshness:   ports.QuestionnaireFreshness{Status: "missing"},
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
	answer.EvidenceSlots = slotsFromEvidenceAnswer(requiredSlots, answer.Citations, *evidenceAnswer)
	answer.MissingEvidence = gapsFromEvidenceAnswer(question.ID, requiredSlots, *evidenceAnswer, answer.EvidenceSlots)
	answer.Conflicts = conflictsFromEvidenceAnswer(question.ID, *evidenceAnswer)
	answer.Confidence = evidenceAnswer.Confidence.Level
	answer.ConfidenceScore = evidenceAnswer.Confidence.Score
	answer.DraftAnswer = draftAnswer(question, *evidenceAnswer, answer.Citations)
	answer.AnswerState, answer.ReviewState = answerStatesFromEvidence(*evidenceAnswer, answer.EvidenceSlots, answer.MissingEvidence, answer.Conflicts, answer.Freshness)
	return answer
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

func slotsForQuestion(question string, direction string) []string {
	normalized := normalizedQuestion(question)
	terms := normalizedTerms(question)
	slots := []string{}
	add := func(slot string) {
		for _, existing := range slots {
			if existing == slot {
				return
			}
		}
		slots = append(slots, slot)
	}
	switch {
	case hasAny(terms, "mfa", "multifactor") || hasPhrase(normalized, "multi factor"):
		add("identity_mfa")
	case hasAny(terms, "access", "sso", "permission", "permissions", "deprovision", "provision", "user", "users"):
		add("access_review")
	case hasAny(terms, "encrypt", "encryption", "encrypted", "key", "keys"):
		add("encryption")
	case hasAny(terms, "incident", "breach", "response"):
		add("incident_response")
	case hasAny(terms, "subprocessor", "subprocessors", "third", "vendor", "vendors") || hasPhrase(normalized, "third party"):
		add("subprocessors")
	case hasAny(terms, "soc", "iso", "audit", "assurance"):
		add("audit_report")
	case hasAny(terms, "policy", "policies", "document", "documents"):
		add("policy")
	case hasAny(terms, "ai", "model", "training", "data", "retention"):
		add("ai_data_use")
	}
	if direction == ports.QuestionnaireDirectionVendorReview {
		add("vendor_profile")
	}
	if len(slots) == 0 {
		add("control_evidence")
	}
	sort.Strings(slots)
	return slots
}

func slotsFromEvidenceAnswer(requiredSlots []string, citations []ports.QuestionnaireCitation, evidenceAnswer evidencepackets.QuestionnaireAnswer) []ports.QuestionnaireEvidenceSlot {
	citationIDs := make([]string, 0, len(citations))
	for _, citation := range citations {
		citationIDs = append(citationIDs, citation.ID)
	}
	slots := make([]ports.QuestionnaireEvidenceSlot, 0, len(requiredSlots))
	for _, slotID := range requiredSlots {
		slot := ports.QuestionnaireEvidenceSlot{
			ID:          slotID,
			Label:       slotLabel(slotID),
			State:       "missing",
			Required:    true,
			CitationIDs: append([]string(nil), citationIDs...),
		}
		if len(citations) > 0 {
			slot.State = "satisfied"
		}
		if evidenceAnswer.Freshness.Status == "stale" {
			slot.State = "stale"
		}
		if evidenceAnswer.AnswerState == "manual_review" {
			slot.State = "needs_review"
		}
		slots = append(slots, slot)
	}
	return slots
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

func draftAnswer(question ports.QuestionnaireQuestion, answer evidencepackets.QuestionnaireAnswer, citations []ports.QuestionnaireCitation) string {
	if answer.AnswerState == "not_required" {
		return "No answer is required for this question."
	}
	citationLabels := make([]string, 0, len(citations))
	for _, citation := range citations {
		citationLabels = append(citationLabels, firstNonEmpty(citation.Label, citation.ID))
	}
	if len(citationLabels) == 0 {
		return "No draft answer is ready because supporting evidence is missing."
	}
	status := firstNonEmpty(answer.Freshness.Status, "unknown")
	return fmt.Sprintf("Evidence is available for %q from %s. Freshness is %s. Keep the cited records with any answer sent outside the operating team.", answerQuestion(question, answer), strings.Join(uniqueSorted(citationLabels), ", "), status)
}

func bestEvidenceAnswerForQuestion(question ports.QuestionnaireQuestion, answers []evidencepackets.QuestionnaireAnswer, used map[string]struct{}) *evidencepackets.QuestionnaireAnswer {
	var best *evidencepackets.QuestionnaireAnswer
	bestScore := -1
	questionTerms := normalizedTerms(question.Question + " " + strings.Join(question.RequiredSlots, " ") + " " + strings.Join(question.MappedControls, " "))
	for index := range answers {
		answer := &answers[index]
		if _, ok := used[answer.ID]; ok {
			continue
		}
		score := overlapScore(questionTerms, normalizedTerms(answer.Question+" "+strings.Join(controlIDs(answer.Controls), " ")))
		for _, control := range answer.Controls {
			for _, mapped := range question.MappedControls {
				if strings.EqualFold(control.ControlID, mapped) || strings.EqualFold(control.ID, mapped) {
					score += 5
				}
			}
		}
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

func questionsFromEvidenceAnswers(answers []evidencepackets.QuestionnaireAnswer) []ports.QuestionnaireQuestion {
	questions := make([]ports.QuestionnaireQuestion, 0, len(answers))
	for _, answer := range answers {
		questions = append(questions, questionFromEvidenceAnswer(answer))
	}
	return questions
}

func questionFromEvidenceAnswer(answer evidencepackets.QuestionnaireAnswer) ports.QuestionnaireQuestion {
	question := ports.QuestionnaireQuestion{
		ID:                 firstNonEmpty(answer.QuestionID, stableID("questionnaire-question", answer.ID)),
		Question:           answer.Question,
		NormalizedQuestion: normalizedQuestion(answer.Question),
		MappedControls:     controlIDs(answer.Controls),
		RequiredSlots:      slotsForQuestion(answer.Question, ""),
		AnswerState:        ports.QuestionnaireAnswerBlocked,
		ReviewState:        ports.QuestionnaireReviewBlocked,
	}
	if answer.AnswerState != "" {
		question.AnswerState = answer.AnswerState
	}
	if answer.ReviewState != "" {
		question.ReviewState = answer.ReviewState
	}
	return question
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
		if len(question.RequiredSlots) == 0 {
			question.RequiredSlots = slotsForQuestion(question.Question, "")
		}
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
	}
	if blocked {
		return ports.QuestionnaireStatusNeedsInput
	}
	if review {
		return ports.QuestionnaireStatusReadyForApproval
	}
	return ports.QuestionnaireStatusReadyForApproval
}

func decisionFromStatus(status string) string {
	switch status {
	case ports.QuestionnaireStatusReadyForApproval:
		return ports.QuestionnaireDecisionApprovedWithConditions
	case ports.QuestionnaireStatusApproved:
		return ports.QuestionnaireDecisionApproved
	case ports.QuestionnaireStatusRejected:
		return ports.QuestionnaireDecisionRejected
	default:
		return ports.QuestionnaireDecisionNeedsInput
	}
}

func defaultTitle(direction string) string {
	if direction == ports.QuestionnaireDirectionVendorReview {
		return "Vendor questionnaire"
	}
	return "Security questionnaire"
}

func sourceFormat(filename string) string {
	filename = strings.ToLower(strings.TrimSpace(filename))
	for _, suffix := range []string{".csv", ".json", ".xlsx", ".xls", ".pdf"} {
		if strings.HasSuffix(filename, suffix) {
			return strings.TrimPrefix(suffix, ".")
		}
	}
	return ""
}

func answerQuestion(question ports.QuestionnaireQuestion, answer evidencepackets.QuestionnaireAnswer) string {
	return firstNonEmpty(question.Question, answer.Question, answer.QuestionID)
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
		return "Control evidence"
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
	return "control_evidence"
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

func normalizedTerms(value string) map[string]struct{} {
	terms := map[string]struct{}{}
	for _, term := range termList(value) {
		terms[term] = struct{}{}
	}
	return terms
}

func termList(value string) []string {
	value = strings.ToLower(strings.NewReplacer("-", " ", "_", " ", "/", " ").Replace(value))
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	})
	terms := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) > 1 {
			terms = append(terms, part)
		}
	}
	return terms
}

func hasAny(terms map[string]struct{}, values ...string) bool {
	for _, value := range values {
		if _, ok := terms[value]; ok {
			return true
		}
	}
	return false
}

func hasPhrase(normalized string, phrase string) bool {
	return strings.Contains(" "+normalized+" ", " "+normalizedQuestion(phrase)+" ")
}

func overlapScore(left map[string]struct{}, right map[string]struct{}) int {
	score := 0
	for term := range left {
		if _, ok := right[term]; ok {
			score++
		}
	}
	return score
}

func keys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
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
