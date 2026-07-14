package grcfindings

import "testing"

func TestPageForProfileFiltersBeforeLimitAndReportsBoundary(t *testing.T) {
	profile := ProfileRef{ID: "access-audit", Name: "Access Audit", CoverageIndexVersion: "2026-07-14"}
	items := []FindingItem{
		{ID: "unmatched", Status: "OPEN"},
		{ID: "critical", Status: "OPEN", Severity: "CRITICAL", Owner: "Unassigned", EvidenceCount: 2, Profiles: []ProfileRef{profile}},
		{ID: "high", Status: "OPEN", Severity: "HIGH", EvidenceCount: 1, Profiles: []ProfileRef{profile}},
	}
	page := PageForProfile(profile, items, 500, 500, 1)
	if len(page.Items) != 1 || page.Items[0].ID != "critical" {
		t.Fatalf("page items = %#v", page.Items)
	}
	if !page.Truncated || page.ProfileSummary == nil || !page.ProfileSummary.EvaluationTruncated {
		t.Fatalf("page boundary = %#v", page)
	}
	if page.ProfileSummary.MatchedFindings != 2 || page.ProfileSummary.OpenFindings != 2 || page.ProfileSummary.CriticalFindings != 1 || page.ProfileSummary.HighFindings != 1 || page.ProfileSummary.UnassignedFindings != 1 || page.ProfileSummary.EvidenceItems != 3 {
		t.Fatalf("profile summary = %#v", page.ProfileSummary)
	}
}
