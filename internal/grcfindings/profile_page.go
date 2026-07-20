package grcfindings

type ProfilePage struct {
	Items          []FindingItem
	Limit          uint32
	Truncated      bool
	ProfileSummary *ProfileSummary
}

type ProfileSummary struct {
	ProfileID             string `json:"profile_id"`
	ProfileName           string `json:"profile_name"`
	CoverageIndexVersion  string `json:"coverage_index_version"`
	CoverageIndexRevision string `json:"coverage_index_revision"`
	MatchedFindings       int    `json:"matched_findings"`
	OpenFindings          int    `json:"open_findings"`
	CriticalFindings      int    `json:"critical_findings"`
	HighFindings          int    `json:"high_findings"`
	UnassignedFindings    int    `json:"unassigned_findings"`
	EvidenceItems         int    `json:"evidence_items"`
	EvaluatedFindings     int    `json:"evaluated_findings"`
	EvaluationLimit       uint32 `json:"evaluation_limit"`
	EvaluationTruncated   bool   `json:"evaluation_truncated"`
	HasMoreMatches        bool   `json:"has_more_matches"`
	ScanTruncated         bool   `json:"scan_truncated"`
}

func PageForProfile(profile ProfileRef, items []FindingItem, evaluated int, evaluationLimit, pageLimit uint32) ProfilePage {
	matched := make([]FindingItem, 0, len(items))
	for _, item := range items {
		if findingHasProfile(item, profile.ID) {
			matched = append(matched, item)
		}
	}
	hasMoreMatches := pageLimit > 0 && len(matched) > int(pageLimit)
	if hasMoreMatches {
		matched = matched[:pageLimit]
	}
	summary := buildProfileSummary(profile, matched, evaluated, evaluationLimit)
	summary.HasMoreMatches = hasMoreMatches
	page := ProfilePage{
		Items:          matched,
		Limit:          pageLimit,
		Truncated:      hasMoreMatches,
		ProfileSummary: summary,
	}
	return page
}

func findingHasProfile(item FindingItem, profileID string) bool {
	for _, profile := range item.Profiles {
		if profile.ID == profileID {
			return true
		}
	}
	return false
}

func buildProfileSummary(profile ProfileRef, items []FindingItem, evaluated int, evaluationLimit uint32) *ProfileSummary {
	summary := &ProfileSummary{
		ProfileID:             profile.ID,
		ProfileName:           profile.Name,
		CoverageIndexVersion:  profile.CoverageIndexVersion,
		CoverageIndexRevision: profile.CoverageIndexRevision,
		MatchedFindings:       len(items),
		EvaluatedFindings:     evaluated,
		EvaluationLimit:       evaluationLimit,
		// The store applies the immutable profile predicate before its row limit.
		// A bounded result can have more matches, but the returned rows were not
		// produced by scanning and discarding unrelated findings.
		EvaluationTruncated: false,
		ScanTruncated:       false,
	}
	for _, item := range items {
		if item.Status == "OPEN" {
			summary.OpenFindings++
		}
		switch item.Severity {
		case "CRITICAL":
			summary.CriticalFindings++
		case "HIGH":
			summary.HighFindings++
		}
		if item.Owner == "Unassigned" {
			summary.UnassignedFindings++
		}
		summary.EvidenceItems += item.EvidenceCount
	}
	return summary
}
