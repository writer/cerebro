package graphagent

type AskQualityScore struct {
	Passed             bool     `json:"passed"`
	QueryPlanStatus    string   `json:"query_plan_status"`
	GroundingStatus    string   `json:"grounding_status"`
	CitationStatus     string   `json:"citation_status"`
	RecoveryStatus     string   `json:"recovery_status"`
	UnsupportedStatus  string   `json:"unsupported_status"`
	RowsReturned       int      `json:"rows_returned"`
	ReferencedURNCount int      `json:"referenced_urn_count"`
	Failures           []string `json:"failures,omitempty"`
}

func ScoreAskEvents(events []Event) AskQualityScore {
	score := AskQualityScore{
		QueryPlanStatus:   "missing",
		GroundingStatus:   "missing",
		CitationStatus:    "missing",
		RecoveryStatus:    "not_attempted",
		UnsupportedStatus: "not_refused",
	}
	for _, event := range events {
		switch data := event.Data.(type) {
		case QueryPlanEvent:
			score.QueryPlanStatus = "pass"
		case RowsEvent:
			score.RowsReturned += len(data.Rows)
			if len(data.Rows) > 0 {
				score.GroundingStatus = "pass"
			}
		case RecoveryEvent:
			if data.RowsAfter > 0 {
				score.RecoveryStatus = "pass"
			} else {
				score.RecoveryStatus = "attempted"
			}
		case SummaryEvent:
			score = scoreSummaryEvent(score, data)
		}
	}
	score.Failures = askQualityFailures(score)
	score.Passed = len(score.Failures) == 0
	return score
}

func scoreSummaryEvent(score AskQualityScore, summary SummaryEvent) AskQualityScore {
	if summary.UnsupportedQuery != nil {
		score.UnsupportedStatus = "safe_refusal"
		score.CitationStatus = "not_required"
		score.GroundingStatus = "not_required"
		return score
	}
	if summary.CitationValidation == nil {
		score.CitationStatus = "missing"
		return score
	}
	score.ReferencedURNCount = summary.CitationValidation.ReferencedURNCount
	if summary.CitationValidation.OK {
		score.CitationStatus = "pass"
		return score
	}
	score.CitationStatus = "warning"
	return score
}

func askQualityFailures(score AskQualityScore) []string {
	failures := []string{}
	if score.QueryPlanStatus != "pass" {
		failures = append(failures, "missing query plan")
	}
	if score.UnsupportedStatus == "safe_refusal" {
		return failures
	}
	if score.GroundingStatus != "pass" {
		failures = append(failures, "missing grounded rows")
	}
	if score.CitationStatus != "pass" {
		failures = append(failures, "citation validation did not pass")
	}
	return failures
}
