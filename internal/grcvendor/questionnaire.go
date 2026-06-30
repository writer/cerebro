package grcvendor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

type QuestionnaireFindingSignal struct {
	ID            string
	Title         string
	Severity      string
	Status        string
	ControlID     string
	ResourceURN   string
	EvidenceCount int
}

type QuestionnaireEvidenceSignal struct {
	ID        string
	Title     string
	Type      string
	ControlID string
	SourceID  string
	State     string
}

type QuestionnaireReviewSummary struct {
	TotalReviews     int `json:"total_reviews"`
	NeedsInput       int `json:"needs_input"`
	ReadyForApproval int `json:"ready_for_approval"`
	Approved         int `json:"approved"`
	Rejected         int `json:"rejected"`
}

type NewQuestionnaireReviewRequest struct {
	TenantID           string
	VendorURN          string
	VendorID           string
	SourceID           string
	RuntimeID          string
	UploadID           string
	QuestionnaireURN   string
	QuestionnaireType  string
	Title              string
	Status             string
	ReviewerUserID     string
	CurrentOwnerUserID string
	AssignedTeam       string
	Attributes         map[string]string
}

func NewQuestionnaireReviewRecord(request NewQuestionnaireReviewRequest, now time.Time) ports.GRCVendorQuestionnaireReviewRecord {
	now = normalizedNow(now)
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.VendorURN = strings.TrimSpace(request.VendorURN)
	request.VendorID = strings.TrimSpace(request.VendorID)
	request.SourceID = strings.TrimSpace(request.SourceID)
	request.RuntimeID = strings.TrimSpace(request.RuntimeID)
	request.UploadID = strings.TrimSpace(request.UploadID)
	request.QuestionnaireURN = strings.TrimSpace(request.QuestionnaireURN)
	request.QuestionnaireType = firstNonEmpty(request.QuestionnaireType, "security")
	request.Title = firstNonEmpty(request.Title, "Security questionnaire")
	request.Status = firstNonEmpty(request.Status, ports.GRCVendorQuestionnaireStatusIntake)
	record := ports.GRCVendorQuestionnaireReviewRecord{
		GRCVendorQuestionnaireReviewIdentity: ports.GRCVendorQuestionnaireReviewIdentity{
			TenantID:  request.TenantID,
			ReviewID:  stableQuestionnaireReviewID(request),
			VendorURN: request.VendorURN,
			VendorID:  request.VendorID,
			Title:     strings.TrimSpace(request.Title),
		},
		GRCVendorQuestionnaireReviewSource: ports.GRCVendorQuestionnaireReviewSource{
			SourceID:          request.SourceID,
			RuntimeID:         request.RuntimeID,
			UploadID:          request.UploadID,
			QuestionnaireURN:  request.QuestionnaireURN,
			QuestionnaireType: strings.TrimSpace(request.QuestionnaireType),
		},
		GRCVendorQuestionnaireReviewWorkflow: ports.GRCVendorQuestionnaireReviewWorkflow{
			Status:             strings.TrimSpace(request.Status),
			Decision:           ports.GRCVendorQuestionnaireDecisionNeedsReview,
			Confidence:         "low",
			ReviewerUserID:     strings.TrimSpace(request.ReviewerUserID),
			CurrentOwnerUserID: strings.TrimSpace(request.CurrentOwnerUserID),
			AssignedTeam:       firstNonEmpty(request.AssignedTeam, "security"),
		},
		GRCVendorQuestionnaireReviewMetadata: ports.GRCVendorQuestionnaireReviewMetadata{
			Attributes: copyStringMap(request.Attributes),
			CreatedAt:  now,
			UpdatedAt:  now,
		},
	}
	record.Timeline = append(record.Timeline, QuestionnaireTimeline(ports.GRCVendorQuestionnaireEventCreated, firstNonEmpty(record.ReviewerUserID, record.CurrentOwnerUserID), "Questionnaire review created", nil, now))
	return record
}

func BuildQuestionnaireReviewEnrichment(record ports.GRCVendorQuestionnaireReviewRecord, vendor Vendor, relationships VendorRelationships, findings []QuestionnaireFindingSignal, evidence []QuestionnaireEvidenceSignal, llmSummary string, now time.Time) ports.GRCVendorQuestionnaireReviewRecord {
	now = normalizedNow(now)
	record.UpdatedAt = now
	record.Attributes = copyStringMap(record.Attributes)
	if strings.TrimSpace(llmSummary) != "" {
		record.Attributes["llm_summary"] = strings.TrimSpace(llmSummary)
		record.Attributes["llm_summary_status"] = "available"
	} else {
		delete(record.Attributes, "llm_summary")
		record.Attributes["llm_summary_status"] = "not_configured"
	}
	matches := questionnaireEvidenceMatches(record, vendor, relationships, findings, evidence)
	missing := questionnaireMissingQuestions(vendor, findings)
	answers := questionnaireAnswerSuggestions(vendor, matches, missing, findings)
	assignments := questionnaireAssignments(record, vendor, missing, now)
	record.EvidenceMatches = matches
	record.MissingQuestions = missing
	record.AnswerSuggestions = answers
	record.Assignments = mergeAssignments(record.Assignments, assignments)
	record.Decision, record.Status, record.Confidence, record.DecisionReason = questionnaireDecision(vendor, missing, findings, matches)
	record.Timeline = append(record.Timeline, QuestionnaireTimeline(ports.GRCVendorQuestionnaireEventProcessed, firstNonEmpty(record.ReviewerUserID, record.CurrentOwnerUserID), "Questionnaire answers refreshed from vendor evidence", map[string]string{
		"evidence_matches":  fmt.Sprint(len(matches)),
		"missing_questions": fmt.Sprint(len(missing)),
		"decision":          record.Decision,
	}, now))
	return record
}

func SummarizeQuestionnaireReviews(records []*ports.GRCVendorQuestionnaireReviewRecord) QuestionnaireReviewSummary {
	var summary QuestionnaireReviewSummary
	summary.TotalReviews = len(records)
	for _, record := range records {
		if record == nil {
			continue
		}
		switch record.Status {
		case ports.GRCVendorQuestionnaireStatusNeedsInput:
			summary.NeedsInput++
		case ports.GRCVendorQuestionnaireStatusReadyForApproval:
			summary.ReadyForApproval++
		case ports.GRCVendorQuestionnaireStatusApproved, ports.GRCVendorQuestionnaireStatusConditional:
			summary.Approved++
		case ports.GRCVendorQuestionnaireStatusRejected:
			summary.Rejected++
		}
	}
	return summary
}

func QuestionnaireTimeline(eventType string, actorID string, summary string, attrs map[string]string, at time.Time) ports.GRCVendorQuestionnaireTimeline {
	at = normalizedNow(at)
	return ports.GRCVendorQuestionnaireTimeline{
		ID:         "timeline-" + hashString(eventType, actorID, summary, at.Format(time.RFC3339Nano))[:16],
		EventType:  strings.TrimSpace(eventType),
		ActorID:    strings.TrimSpace(actorID),
		Summary:    strings.TrimSpace(summary),
		CreatedAt:  &at,
		Attributes: copyStringMap(attrs),
	}
}

func QuestionnaireEvent(record ports.GRCVendorQuestionnaireReviewRecord, eventType string, actorID string, summary string, payload map[string]string, at time.Time) ports.GRCVendorQuestionnaireReviewEventRecord {
	at = normalizedNow(at)
	return ports.GRCVendorQuestionnaireReviewEventRecord{
		ID:        "grc-vendor-questionnaire-" + hashString(record.TenantID, record.ReviewID, eventType, actorID, summary, at.Format(time.RFC3339Nano))[:24],
		TenantID:  strings.TrimSpace(record.TenantID),
		ReviewID:  strings.TrimSpace(record.ReviewID),
		EventType: strings.TrimSpace(eventType),
		ActorID:   strings.TrimSpace(actorID),
		Summary:   strings.TrimSpace(summary),
		Payload:   copyStringMap(payload),
		CreatedAt: at,
	}
}

func questionnaireEvidenceMatches(record ports.GRCVendorQuestionnaireReviewRecord, vendor Vendor, relationships VendorRelationships, findings []QuestionnaireFindingSignal, evidence []QuestionnaireEvidenceSignal) []ports.GRCVendorQuestionnaireEvidence {
	matches := []ports.GRCVendorQuestionnaireEvidence{}
	add := func(match ports.GRCVendorQuestionnaireEvidence) {
		match.ID = strings.TrimSpace(match.ID)
		match.Label = strings.TrimSpace(match.Label)
		if match.ID == "" || match.Label == "" {
			return
		}
		if match.Confidence == "" {
			match.Confidence = "medium"
		}
		matches = append(matches, match)
	}
	if record.QuestionnaireURN != "" {
		add(ports.GRCVendorQuestionnaireEvidence{ID: "questionnaire", Label: firstNonEmpty(record.Title, "Security questionnaire"), Source: "questionnaire", URN: record.QuestionnaireURN, Confidence: "high", Reason: "Uploaded questionnaire artifact"})
	}
	for _, related := range relationships.SecurityQuestionnaires {
		add(ports.GRCVendorQuestionnaireEvidence{ID: "questionnaire:" + urnTail(related.URN), Label: firstNonEmpty(related.Label, "Security questionnaire"), Source: "graph", URN: related.URN, Confidence: "high", Reason: "Linked questionnaire"})
	}
	for _, related := range relationships.AssuranceDocuments {
		add(ports.GRCVendorQuestionnaireEvidence{ID: "assurance:" + urnTail(related.URN), Label: firstNonEmpty(related.Label, "Assurance document"), Source: "graph", URN: related.URN, Confidence: "high", Reason: "Linked assurance document"})
	}
	for _, related := range relationships.SecurityReviews {
		add(ports.GRCVendorQuestionnaireEvidence{ID: "review:" + urnTail(related.URN), Label: firstNonEmpty(related.Label, "Security review"), Source: "graph", URN: related.URN, Confidence: "high", Reason: "Linked security review"})
	}
	for _, item := range evidence {
		add(ports.GRCVendorQuestionnaireEvidence{ID: "evidence:" + item.ID, Label: firstNonEmpty(item.Title, item.ID), Source: firstNonEmpty(item.SourceID, "finding_evidence"), ControlID: item.ControlID, Confidence: confidenceFromEvidenceState(item.State), Reason: firstNonEmpty(item.State, item.Type)})
	}
	for _, finding := range findings {
		if finding.Status != "open" && finding.Status != "" {
			continue
		}
		add(ports.GRCVendorQuestionnaireEvidence{ID: "finding:" + finding.ID, Label: firstNonEmpty(finding.Title, finding.ID), Source: "finding", ControlID: finding.ControlID, Confidence: confidenceFromSeverity(finding.Severity), Reason: firstNonEmpty(finding.Severity, "open finding")})
	}
	if vendor.OwnerState == OwnerStateAssigned {
		add(ports.GRCVendorQuestionnaireEvidence{ID: "owner", Label: "Vendor owner assigned", Source: "vendor", Confidence: "high", Reason: "Owner is projected on vendor record"})
	}
	if vendor.DPAStatus == FreshnessStateCurrent {
		add(ports.GRCVendorQuestionnaireEvidence{ID: "dpa", Label: "DPA current", Source: "vendor", Confidence: "high", Reason: "DPA status is current"})
	}
	sort.SliceStable(matches, func(i, j int) bool { return matches[i].ID < matches[j].ID })
	return dedupeQuestionnaireEvidence(matches)
}

func questionnaireMissingQuestions(vendor Vendor, findings []QuestionnaireFindingSignal) []ports.GRCVendorQuestionnaireMissing {
	missing := []ports.GRCVendorQuestionnaireMissing{}
	add := func(id string, question string, reason string, team string, requiredBefore string) {
		missing = append(missing, ports.GRCVendorQuestionnaireMissing{ID: id, Question: question, Reason: reason, AssignedTeam: team, RequiredBefore: requiredBefore})
	}
	if vendor.OwnerState == OwnerStateMissing {
		add("owner", "Who owns the vendor review?", "No security or business owner is projected.", "security", "approval")
	}
	if vendor.DPAStatus == FreshnessStateMissing || vendor.DPAStatus == FreshnessStateExpired {
		add("dpa", "Is a current DPA or equivalent data-processing agreement attached?", "DPA status is "+vendor.DPAStatus+".", "legal", "approval")
	}
	if vendor.EvidenceFreshnessState == FreshnessStateMissing || vendor.EvidenceFreshnessState == FreshnessStateStale || vendor.EvidenceFreshnessState == FreshnessStateExpired {
		add("fresh_evidence", "Which current evidence supports the answers?", "Vendor evidence is "+vendor.EvidenceFreshnessState+".", "security", "approval")
	}
	if vendor.MonitoringState == "alert" || vendor.MonitoringState == "critical" {
		add("monitoring", "Were active monitoring signals reviewed?", "Vendor monitoring state is "+vendor.MonitoringState+".", "security", "approval")
	}
	if vendor.PrimaryContact == "" && (vendor.RiskTier == "tier_1" || vendor.RiskTier == "tier_2") {
		add("vendor_contact", "Who can answer follow-up questions at the vendor?", "Tier 1 or Tier 2 vendor is missing a primary contact.", "procurement", "send")
	}
	if hasCriticalOrHighFinding(findings) {
		add("open_findings", "Are open high-severity findings accepted or remediated?", "Open high-severity findings are linked to this vendor.", "security", "approval")
	}
	return missing
}

func questionnaireAnswerSuggestions(vendor Vendor, matches []ports.GRCVendorQuestionnaireEvidence, missing []ports.GRCVendorQuestionnaireMissing, findings []QuestionnaireFindingSignal) []ports.GRCVendorQuestionnaireAnswer {
	missingByID := map[string]struct{}{}
	for _, item := range missing {
		missingByID[item.ID] = struct{}{}
	}
	sourceIDs := make([]string, 0, len(matches))
	for _, match := range matches {
		sourceIDs = append(sourceIDs, match.ID)
	}
	answers := []ports.GRCVendorQuestionnaireAnswer{
		{
			ID:         "access",
			Question:   "What access does the vendor have?",
			Answer:     vendorAccessAnswer(vendor),
			State:      answerState(missingByID, "owner"),
			Confidence: confidenceFromVendorInputs(vendor.AccessLevel, vendor.OwnerState),
			SourceIDs:  sourceIDsForPrefix(sourceIDs, "owner"),
		},
		{
			ID:         "data",
			Question:   "What data does the vendor process?",
			Answer:     vendorDataAnswer(vendor),
			State:      answerState(missingByID, "dpa"),
			Confidence: confidenceFromVendorInputs(vendor.DataSensitivity, vendor.DPAStatus),
			SourceIDs:  sourceIDsForPrefix(sourceIDs, "dpa"),
		},
		{
			ID:         "assurance",
			Question:   "Which assurance artifacts support the review?",
			Answer:     vendorAssuranceAnswer(vendor, matches),
			State:      answerState(missingByID, "fresh_evidence"),
			Confidence: confidenceFromEvidenceCount(matches),
			SourceIDs:  sourceIDsForPrefix(sourceIDs, "assurance", "review", "questionnaire", "evidence"),
		},
		{
			ID:         "findings",
			Question:   "Are there open security findings?",
			Answer:     vendorFindingAnswer(findings),
			State:      answerState(missingByID, "open_findings"),
			Confidence: confidenceFromFindingSignals(findings),
			SourceIDs:  sourceIDsForPrefix(sourceIDs, "finding"),
		},
		{
			ID:         "monitoring",
			Question:   "Is monitoring clear?",
			Answer:     vendorMonitoringAnswer(vendor),
			State:      answerState(missingByID, "monitoring"),
			Confidence: confidenceFromVendorInputs(vendor.MonitoringState),
			SourceIDs:  sourceIDsForPrefix(sourceIDs, "finding", "evidence"),
		},
	}
	return answers
}

func questionnaireAssignments(record ports.GRCVendorQuestionnaireReviewRecord, vendor Vendor, missing []ports.GRCVendorQuestionnaireMissing, now time.Time) []ports.GRCVendorQuestionnaireAssignment {
	now = normalizedNow(now)
	assignments := []ports.GRCVendorQuestionnaireAssignment{}
	for _, item := range missing {
		team := firstNonEmpty(item.AssignedTeam, "security")
		ownerID := ""
		switch team {
		case "security":
			ownerID = firstNonEmpty(record.ReviewerUserID, vendor.SecurityOwnerUserID, vendor.BusinessOwnerUserID)
		case "legal", "privacy":
			ownerID = record.CurrentOwnerUserID
		default:
			ownerID = firstNonEmpty(vendor.BusinessOwnerUserID, record.CurrentOwnerUserID)
		}
		assignments = append(assignments, ports.GRCVendorQuestionnaireAssignment{
			ID:        "assignment-" + hashString(record.ReviewID, item.ID, team)[:12],
			Team:      team,
			OwnerID:   ownerID,
			Reason:    item.Question,
			Status:    "open",
			CreatedAt: &now,
		})
	}
	return assignments
}

func mergeAssignments(existing []ports.GRCVendorQuestionnaireAssignment, incoming []ports.GRCVendorQuestionnaireAssignment) []ports.GRCVendorQuestionnaireAssignment {
	if len(existing) == 0 {
		return incoming
	}
	seen := map[string]struct{}{}
	merged := append([]ports.GRCVendorQuestionnaireAssignment{}, existing...)
	for _, assignment := range existing {
		seen[assignment.ID] = struct{}{}
	}
	for _, assignment := range incoming {
		if _, ok := seen[assignment.ID]; ok {
			continue
		}
		merged = append(merged, assignment)
	}
	return merged
}

func questionnaireDecision(vendor Vendor, missing []ports.GRCVendorQuestionnaireMissing, findings []QuestionnaireFindingSignal, matches []ports.GRCVendorQuestionnaireEvidence) (string, string, string, string) {
	if hasCriticalFinding(findings) {
		return ports.GRCVendorQuestionnaireDecisionNeedsReview, ports.GRCVendorQuestionnaireStatusNeedsInput, "medium", "Critical vendor findings require security review before approval."
	}
	if len(missing) > 0 {
		return ports.GRCVendorQuestionnaireDecisionApproveWithConditions, ports.GRCVendorQuestionnaireStatusNeedsInput, "medium", fmt.Sprintf("%d questionnaire gaps need owner follow-up.", len(missing))
	}
	if vendor.RiskScore >= 80 || vendor.RiskTier == "tier_1" {
		return ports.GRCVendorQuestionnaireDecisionApproveWithConditions, ports.GRCVendorQuestionnaireStatusReadyForApproval, "high", "Tier 1 vendor can proceed with security approval and review cadence."
	}
	if len(matches) == 0 {
		return ports.GRCVendorQuestionnaireDecisionNeedsReview, ports.GRCVendorQuestionnaireStatusNeedsInput, "low", "No supporting evidence was found for auto-filled answers."
	}
	return ports.GRCVendorQuestionnaireDecisionApprove, ports.GRCVendorQuestionnaireStatusReadyForApproval, "high", "Current vendor evidence supports the questionnaire answers."
}

func stableQuestionnaireReviewID(request NewQuestionnaireReviewRequest) string {
	seed := strings.Join([]string{
		request.TenantID,
		request.VendorURN,
		request.VendorID,
		request.UploadID,
		request.QuestionnaireURN,
		request.QuestionnaireType,
		request.Title,
	}, "\x00")
	return "qrev-" + hashString(seed)[:18]
}

func hashString(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:])
}

func normalizedNow(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}

func copyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	copy := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			copy[key] = value
		}
	}
	return copy
}

func dedupeQuestionnaireEvidence(matches []ports.GRCVendorQuestionnaireEvidence) []ports.GRCVendorQuestionnaireEvidence {
	seen := map[string]struct{}{}
	result := make([]ports.GRCVendorQuestionnaireEvidence, 0, len(matches))
	for _, match := range matches {
		if _, ok := seen[match.ID]; ok {
			continue
		}
		seen[match.ID] = struct{}{}
		result = append(result, match)
	}
	return result
}

func hasCriticalOrHighFinding(findings []QuestionnaireFindingSignal) bool {
	for _, finding := range findings {
		switch strings.ToLower(strings.TrimSpace(finding.Severity)) {
		case "critical", "high":
			if finding.Status == "" || finding.Status == "open" {
				return true
			}
		}
	}
	return false
}

func hasCriticalFinding(findings []QuestionnaireFindingSignal) bool {
	for _, finding := range findings {
		if strings.ToLower(strings.TrimSpace(finding.Severity)) == "critical" && (finding.Status == "" || finding.Status == "open") {
			return true
		}
	}
	return false
}

func confidenceFromEvidenceState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "current", "fresh":
		return "high"
	case "stale", "expired":
		return "low"
	default:
		return "medium"
	}
}

func confidenceFromSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return "high"
	case "":
		return "low"
	default:
		return "medium"
	}
}

func confidenceFromVendorInputs(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) == FreshnessStateMissing || strings.TrimSpace(value) == FreshnessStateUnknown {
			return "low"
		}
	}
	return "high"
}

func confidenceFromEvidenceCount(matches []ports.GRCVendorQuestionnaireEvidence) string {
	if len(matches) >= 3 {
		return "high"
	}
	if len(matches) > 0 {
		return "medium"
	}
	return "low"
}

func confidenceFromFindingSignals(findings []QuestionnaireFindingSignal) string {
	if len(findings) == 0 {
		return "medium"
	}
	return "high"
}

func sourceIDsForPrefix(sourceIDs []string, prefixes ...string) []string {
	result := []string{}
	for _, sourceID := range sourceIDs {
		for _, prefix := range prefixes {
			if strings.HasPrefix(sourceID, prefix) {
				result = append(result, sourceID)
				break
			}
		}
	}
	return dedupeStrings(result)
}

func answerState(missing map[string]struct{}, blockers ...string) string {
	for _, blocker := range blockers {
		if _, ok := missing[blocker]; ok {
			return "needs_review"
		}
	}
	return "supported"
}

func vendorAccessAnswer(vendor Vendor) string {
	parts := []string{}
	if vendor.AccessLevel != "" {
		parts = append(parts, "Access level: "+vendor.AccessLevel)
	}
	if vendor.OwnerState == OwnerStateAssigned {
		parts = append(parts, "Owner assigned")
	}
	if vendor.SystemDependency != "" {
		parts = append(parts, "Dependency: "+vendor.SystemDependency)
	}
	return firstNonEmpty(strings.Join(parts, "; "), "Access level is not projected.")
}

func vendorDataAnswer(vendor Vendor) string {
	parts := []string{}
	if vendor.DataSensitivity != "" {
		parts = append(parts, "Data: "+vendor.DataSensitivity)
	}
	if vendor.Subprocessor != "" {
		parts = append(parts, "Subprocessor: "+vendor.Subprocessor)
	}
	if vendor.DPAStatus != "" {
		parts = append(parts, "DPA: "+vendor.DPAStatus)
	}
	return firstNonEmpty(strings.Join(parts, "; "), "Data handling is not projected.")
}

func vendorAssuranceAnswer(vendor Vendor, matches []ports.GRCVendorQuestionnaireEvidence) string {
	parts := []string{}
	if vendor.SOC2Status != "" {
		parts = append(parts, "SOC 2: "+vendor.SOC2Status)
	}
	if vendor.ISO27001Status != "" {
		parts = append(parts, "ISO 27001: "+vendor.ISO27001Status)
	}
	if vendor.SecurityReviewStatus != "" {
		parts = append(parts, "Security review: "+vendor.SecurityReviewStatus)
	}
	if len(matches) > 0 {
		parts = append(parts, fmt.Sprintf("%d supporting records", len(matches)))
	}
	return firstNonEmpty(strings.Join(parts, "; "), "No assurance artifacts are linked.")
}

func vendorFindingAnswer(findings []QuestionnaireFindingSignal) string {
	if len(findings) == 0 {
		return "No open vendor findings are linked."
	}
	counts := map[string]int{}
	for _, finding := range findings {
		counts[strings.ToLower(strings.TrimSpace(firstNonEmpty(finding.Severity, "unknown")))]++
	}
	parts := []string{}
	for _, key := range []string{"critical", "high", "medium", "low", "unknown"} {
		if counts[key] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[key], key))
		}
	}
	return "Open findings: " + strings.Join(parts, ", ")
}

func vendorMonitoringAnswer(vendor Vendor) string {
	if vendor.MonitoringState == "" {
		return "Monitoring state is not projected."
	}
	if len(vendor.MonitoringSignals) == 0 {
		return "Monitoring state: " + vendor.MonitoringState
	}
	return fmt.Sprintf("Monitoring state: %s with %d signal(s)", vendor.MonitoringState, len(vendor.MonitoringSignals))
}
