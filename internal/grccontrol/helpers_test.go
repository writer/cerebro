package grccontrol

import (
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFilterPacketControlsNoFilters(t *testing.T) {
	controls := []compliance.ControlEvidencePacketControl{
		{Control: compliance.ControlPostureControl{FrameworkName: "SOC2", ControlID: "CC1.1"}},
		{Control: compliance.ControlPostureControl{FrameworkName: "ISO27001", ControlID: "A.5.1"}},
	}
	result := FilterPacketControls(controls, "", "")
	if len(result) != 2 {
		t.Fatalf("FilterPacketControls(no filter) len = %d, want 2", len(result))
	}
}

func TestFilterPacketControlsByFramework(t *testing.T) {
	controls := []compliance.ControlEvidencePacketControl{
		{Control: compliance.ControlPostureControl{FrameworkName: "SOC2", ControlID: "CC1.1"}},
		{Control: compliance.ControlPostureControl{FrameworkName: "ISO27001", ControlID: "A.5.1"}},
		{Control: compliance.ControlPostureControl{FrameworkName: "SOC2", ControlID: "CC2.1"}},
	}
	result := FilterPacketControls(controls, "SOC2", "")
	if len(result) != 2 {
		t.Fatalf("FilterPacketControls(SOC2) len = %d, want 2", len(result))
	}
}

func TestFilterPacketControlsByControlID(t *testing.T) {
	controls := []compliance.ControlEvidencePacketControl{
		{Control: compliance.ControlPostureControl{FrameworkName: "SOC2", ControlID: "CC1.1"}},
		{Control: compliance.ControlPostureControl{FrameworkName: "SOC2", ControlID: "CC2.1"}},
		{Control: compliance.ControlPostureControl{FrameworkName: "SOC2", ControlID: "CC1.2"}},
	}
	result := FilterPacketControls(controls, "", "CC1")
	if len(result) != 2 {
		t.Fatalf("FilterPacketControls(CC1) len = %d, want 2", len(result))
	}
}

func TestFilterPacketControlsByBoth(t *testing.T) {
	controls := []compliance.ControlEvidencePacketControl{
		{Control: compliance.ControlPostureControl{FrameworkName: "SOC2", ControlID: "CC1.1"}},
		{Control: compliance.ControlPostureControl{FrameworkName: "ISO27001", ControlID: "CC1.1"}},
		{Control: compliance.ControlPostureControl{FrameworkName: "SOC2", ControlID: "CC2.1"}},
	}
	result := FilterPacketControls(controls, "SOC2", "CC1")
	if len(result) != 1 {
		t.Fatalf("FilterPacketControls(SOC2, CC1) len = %d, want 1", len(result))
	}
}

func TestFilterPacketControlsCaseInsensitiveFramework(t *testing.T) {
	controls := []compliance.ControlEvidencePacketControl{
		{Control: compliance.ControlPostureControl{FrameworkName: "SOC2", ControlID: "CC1.1"}},
	}
	result := FilterPacketControls(controls, "soc2", "")
	if len(result) != 1 {
		t.Fatalf("FilterPacketControls(soc2) len = %d, want 1", len(result))
	}
}

func TestFilterPacketControlsByFrameworkID(t *testing.T) {
	controls := []compliance.ControlEvidencePacketControl{
		{Control: compliance.ControlPostureControl{FrameworkName: "SOC2", FrameworkID: "soc2-type2", ControlID: "CC1.1"}},
	}
	result := FilterPacketControls(controls, "soc2-type2", "")
	if len(result) != 1 {
		t.Fatalf("FilterPacketControls(frameworkID) len = %d, want 1", len(result))
	}
}

func TestSummarizePacketCounts(t *testing.T) {
	controls := []compliance.ControlEvidencePacketControl{
		{Status: compliance.ControlPosturePassing},
		{Status: compliance.ControlPostureFailing},
		{Status: compliance.ControlPosturePassing},
	}
	summary := SummarizePacket("profile-1", controls)
	if summary.Total != 3 {
		t.Fatalf("Total = %d, want 3", summary.Total)
	}
	if summary.ByStatus[compliance.ControlPosturePassing] != 2 {
		t.Fatalf("passing = %d, want 2", summary.ByStatus[compliance.ControlPosturePassing])
	}
	if summary.ByStatus[compliance.ControlPostureFailing] != 1 {
		t.Fatalf("failing = %d, want 1", summary.ByStatus[compliance.ControlPostureFailing])
	}
	if summary.SelectionID != "profile-1" {
		t.Fatalf("SelectionID = %q, want profile-1", summary.SelectionID)
	}
}

func TestSummarizePacketEmpty(t *testing.T) {
	summary := SummarizePacket("", nil)
	if summary.Total != 0 {
		t.Fatalf("Total = %d, want 0", summary.Total)
	}
}

func TestPacketReadinessNoControlsBlocked(t *testing.T) {
	r := PacketReadiness(nil)
	if r.Status != "blocked" {
		t.Fatalf("Status = %q, want blocked", r.Status)
	}
	if r.Score != 0 {
		t.Fatalf("Score = %d, want 0", r.Score)
	}
	if len(r.Blockers) != 1 || r.Blockers[0].Code != "no_controls" {
		t.Fatalf("Blockers = %v, want no_controls", r.Blockers)
	}
}

func TestPacketReadinessAllPassing(t *testing.T) {
	controls := []compliance.ControlEvidencePacketControl{
		{Status: compliance.ControlPosturePassing, Readiness: compliance.ControlEvidencePacketReadiness{Score: 100}},
		{Status: compliance.ControlPosturePassing, Readiness: compliance.ControlEvidencePacketReadiness{Score: 80}},
	}
	r := PacketReadiness(controls)
	if r.Status != "ready" {
		t.Fatalf("Status = %q, want ready", r.Status)
	}
	if r.Score != 90 {
		t.Fatalf("Score = %d, want 90", r.Score)
	}
	if len(r.Blockers) != 0 {
		t.Fatalf("Blockers = %v, want empty", r.Blockers)
	}
}

func TestPacketReadinessOpenFindingsBlocked(t *testing.T) {
	controls := []compliance.ControlEvidencePacketControl{
		{
			Status:    compliance.ControlPostureFailing,
			Readiness: compliance.ControlEvidencePacketReadiness{Score: 20},
			Findings: []compliance.ControlEvidencePacketFinding{
				{ID: "f1"}, {ID: "f2"},
			},
		},
	}
	r := PacketReadiness(controls)
	if r.Status != "blocked" {
		t.Fatalf("Status = %q, want blocked", r.Status)
	}
	found := false
	for _, b := range r.Blockers {
		if b.Code == "open_findings" {
			found = true
			if b.Count != 2 {
				t.Fatalf("open_findings count = %d, want 2", b.Count)
			}
		}
	}
	if !found {
		t.Fatal("missing open_findings blocker")
	}
}

func TestPacketReadinessMissingEvidenceBlocked(t *testing.T) {
	controls := []compliance.ControlEvidencePacketControl{
		{
			Status: compliance.ControlPostureMissingEvidence,
			Readiness: compliance.ControlEvidencePacketReadiness{
				Score:           30,
				MissingEvidence: 3,
			},
		},
	}
	r := PacketReadiness(controls)
	if r.Status != "blocked" {
		t.Fatalf("Status = %q, want blocked", r.Status)
	}
}

func TestPacketReadinessStaleEvidenceNeedsAttention(t *testing.T) {
	controls := []compliance.ControlEvidencePacketControl{
		{
			Status: compliance.ControlPostureStaleEvidence,
			Readiness: compliance.ControlEvidencePacketReadiness{
				Score:         60,
				StaleEvidence: 2,
			},
		},
	}
	r := PacketReadiness(controls)
	if r.Status != "needs_attention" {
		t.Fatalf("Status = %q, want needs_attention", r.Status)
	}
}

func TestPacketReadinessManualReviewNeedsAttention(t *testing.T) {
	controls := []compliance.ControlEvidencePacketControl{
		{
			Status:    compliance.ControlPostureManualReview,
			Readiness: compliance.ControlEvidencePacketReadiness{Score: 50},
		},
	}
	r := PacketReadiness(controls)
	if r.Status != "needs_attention" {
		t.Fatalf("Status = %q, want needs_attention", r.Status)
	}
}

func TestControlItemsFromPacketSortsCorrectly(t *testing.T) {
	packetControls := []compliance.ControlEvidencePacketControl{
		{
			Control: compliance.ControlPostureControl{FrameworkName: "SOC2", ControlID: "CC9.1"},
			Status:  compliance.ControlPosturePassing,
		},
		{
			Control: compliance.ControlPostureControl{FrameworkName: "SOC2", ControlID: "CC1.1"},
			Status:  compliance.ControlPostureFailing,
			Findings: []compliance.ControlEvidencePacketFinding{
				{ID: "f1", Severity: "high", Status: "open"},
			},
		},
	}
	items := ControlItemsFromPacket(packetControls, nil, nil)
	if len(items) != 2 {
		t.Fatalf("len = %d, want 2", len(items))
	}
	if items[0].ControlID != "CC1.1" {
		t.Fatalf("first control = %q, want CC1.1 (failing should sort first)", items[0].ControlID)
	}
}

func TestControlItemsFromPacketCountsOpenFindings(t *testing.T) {
	packetControls := []compliance.ControlEvidencePacketControl{
		{
			Control: compliance.ControlPostureControl{FrameworkName: "SOC2", ControlID: "CC1.1"},
			Status:  compliance.ControlPostureFailing,
			Findings: []compliance.ControlEvidencePacketFinding{
				{ID: "f1", Severity: "CRITICAL", Status: "open"},
				{ID: "f2", Severity: "HIGH", Status: "open"},
				{ID: "f3", Severity: "LOW", Status: "resolved"},
			},
		},
	}
	items := ControlItemsFromPacket(packetControls, nil, nil)
	if items[0].OpenFindings != 2 {
		t.Fatalf("OpenFindings = %d, want 2", items[0].OpenFindings)
	}
	if items[0].CriticalFindings != 1 {
		t.Fatalf("CriticalFindings = %d, want 1", items[0].CriticalFindings)
	}
	if items[0].HighFindings != 1 {
		t.Fatalf("HighFindings = %d, want 1", items[0].HighFindings)
	}
}

func TestBuildReportMetadataDefaults(t *testing.T) {
	meta := BuildReportMetadata(ReportMetadataInput{
		Profile:       Profile{ID: "p1", Name: "Profile 1"},
		PacketVersion: "v1",
		ControlCount:  5,
		FindingCount:  3,
		EvidenceCount: 10,
	})
	if meta.Provenance.ReportType != "packet" {
		t.Fatalf("ReportType = %q, want packet", meta.Provenance.ReportType)
	}
	if meta.Provenance.ProfileID != "p1" {
		t.Fatalf("ProfileID = %q, want p1", meta.Provenance.ProfileID)
	}
	if meta.Provenance.GeneratedAt.IsZero() {
		t.Fatal("GeneratedAt should not be zero")
	}
	if meta.Redaction.DefaultMode != "share_safe" {
		t.Fatalf("DefaultMode = %q, want share_safe", meta.Redaction.DefaultMode)
	}
}

func TestBuildReportMetadataWithRuntimes(t *testing.T) {
	runtimes := []*cerebrov1.SourceRuntime{
		{Id: "r1", SourceId: "aws"},
		{Id: "r2", SourceId: "aws"},
		{Id: "r3", SourceId: "github"},
	}
	meta := BuildReportMetadata(ReportMetadataInput{
		Runtimes: runtimes,
	})
	if len(meta.Scope.SourceIDs) != 2 {
		t.Fatalf("SourceIDs count = %d, want 2 (deduped)", len(meta.Scope.SourceIDs))
	}
	if len(meta.Scope.RuntimeIDs) != 3 {
		t.Fatalf("RuntimeIDs count = %d, want 3", len(meta.Scope.RuntimeIDs))
	}
}

func TestReportScopeFromRuntimesWithExclusions(t *testing.T) {
	policyJSON := `{"excluded_families":["s3_bucket"]}`
	runtimes := []*cerebrov1.SourceRuntime{
		{Id: "r1", SourceId: "aws", Config: map[string]string{
			"cerebro_resource_scope_policy": policyJSON,
		}},
	}
	scope := ReportScopeFromRuntimes(runtimes)
	if scope.Exclusions.Total != 1 {
		t.Fatalf("Exclusions.Total = %d, want 1", scope.Exclusions.Total)
	}
	if scope.IncrementalFetch.Status != "exclusions_applied" {
		t.Fatalf("IncrementalFetch.Status = %q, want exclusions_applied", scope.IncrementalFetch.Status)
	}
}

func TestReportScopeFromRuntimesNoExclusions(t *testing.T) {
	runtimes := []*cerebrov1.SourceRuntime{
		{Id: "r1", SourceId: "aws"},
	}
	scope := ReportScopeFromRuntimes(runtimes)
	if scope.Exclusions.Total != 0 {
		t.Fatalf("Exclusions.Total = %d, want 0", scope.Exclusions.Total)
	}
	if scope.IncrementalFetch.Status != "all_collected" {
		t.Fatalf("IncrementalFetch.Status = %q, want all_collected", scope.IncrementalFetch.Status)
	}
}

func TestFallbackString(t *testing.T) {
	tests := []struct {
		values []string
		want   string
	}{
		{[]string{"", "  ", "hello"}, "hello"},
		{[]string{"first", "second"}, "first"},
		{[]string{""}, ""},
		{nil, ""},
		{[]string{"  trimmed  "}, "trimmed"},
	}
	for _, tt := range tests {
		got := fallbackString(tt.values...)
		if got != tt.want {
			t.Errorf("fallbackString(%v) = %q, want %q", tt.values, got, tt.want)
		}
	}
}

func TestFindingStatusOpenValues(t *testing.T) {
	for _, status := range []string{"open", "OPEN", "  Open  "} {
		if !findingStatusOpen(status) {
			t.Errorf("findingStatusOpen(%q) = false, want true", status)
		}
	}
	for _, status := range []string{"resolved", "suppressed", ""} {
		if findingStatusOpen(status) {
			t.Errorf("findingStatusOpen(%q) = true, want false", status)
		}
	}
}

func TestNormalizedFindingStatus(t *testing.T) {
	if got := normalizedFindingStatus("open"); got != "OPEN" {
		t.Fatalf("normalizedFindingStatus(open) = %q, want OPEN", got)
	}
	if got := normalizedFindingStatus(""); got != "UNKNOWN" {
		t.Fatalf("normalizedFindingStatus(\"\") = %q, want UNKNOWN", got)
	}
	if got := normalizedFindingStatus("  resolved  "); got != "RESOLVED" {
		t.Fatalf("normalizedFindingStatus(trimmed) = %q, want RESOLVED", got)
	}
}

func TestControlStatusRankOrder(t *testing.T) {
	rankings := []compliance.ControlPostureStatus{
		compliance.ControlPostureFailing,
		compliance.ControlPostureMissingEvidence,
		compliance.ControlPostureStaleEvidence,
		compliance.ControlPostureManualReview,
		compliance.ControlPostureException,
		compliance.ControlPosturePassing,
		compliance.ControlPostureNotApplicable,
	}
	for i := 1; i < len(rankings); i++ {
		if controlStatusRank(string(rankings[i-1])) >= controlStatusRank(string(rankings[i])) {
			t.Errorf("controlStatusRank(%q) >= controlStatusRank(%q)", rankings[i-1], rankings[i])
		}
	}
	if controlStatusRank("unknown") != 7 {
		t.Fatalf("controlStatusRank(unknown) = %d, want 7", controlStatusRank("unknown"))
	}
}

func TestParseEvidenceTimeValid(t *testing.T) {
	ts := parseEvidenceTime("2026-01-15T10:00:00Z")
	if ts.Year() != 2026 || ts.Month() != 1 {
		t.Fatalf("parseEvidenceTime = %v", ts)
	}
}

func TestParseEvidenceTimeEmptyReturnsZero(t *testing.T) {
	if !parseEvidenceTime("").IsZero() {
		t.Fatal("parseEvidenceTime(\"\") should be zero")
	}
}

func TestParseEvidenceTimeInvalidReturnsZero(t *testing.T) {
	if !parseEvidenceTime("invalid").IsZero() {
		t.Fatal("parseEvidenceTime(invalid) should be zero")
	}
}

func TestMarkdownHelpers(t *testing.T) {
	if got := markdownHeading(""); got != "Control" {
		t.Fatalf("markdownHeading(\"\") = %q, want Control", got)
	}
	if got := markdownCell(""); got != "-" {
		t.Fatalf("markdownCell(\"\") = %q, want -", got)
	}
	if got := markdownValue(""); got != "Not specified" {
		t.Fatalf("markdownValue(\"\") = %q, want Not specified", got)
	}
	if got := markdownTime(time.Time{}); got != "-" {
		t.Fatalf("markdownTime(zero) = %q, want -", got)
	}
}

func TestEscapeMarkdownText(t *testing.T) {
	escaped := escapeMarkdownText("[link](url) **bold** ~tilde~ <tag> |pipe|")
	for _, ch := range []string{"[link]", "**bold**", "~tilde~", "<tag>", "|pipe|"} {
		if strings.Contains(escaped, ch) {
			t.Errorf("escapeMarkdownText did not escape %q: %s", ch, escaped)
		}
	}
}

func TestUniqueSortedStrings(t *testing.T) {
	result := uniqueSortedStrings([]string{"b", "a", "B", " ", "c", "a"})
	if len(result) != 3 {
		t.Fatalf("len = %d, want 3", len(result))
	}
	if result[0] != "a" || result[1] != "b" || result[2] != "c" {
		t.Fatalf("result = %v, want [a b c]", result)
	}
}

func TestUniqueSortedStringsEmpty(t *testing.T) {
	result := uniqueSortedStrings(nil)
	if len(result) != 0 {
		t.Fatalf("len = %d, want 0", len(result))
	}
}

func TestMaxInt(t *testing.T) {
	if got := maxInt(3, 5); got != 5 {
		t.Fatalf("maxInt(3,5) = %d, want 5", got)
	}
	if got := maxInt(5, 3); got != 5 {
		t.Fatalf("maxInt(5,3) = %d, want 5", got)
	}
}

func TestTimePtr(t *testing.T) {
	if timePtr(time.Time{}) != nil {
		t.Fatal("timePtr(zero) should be nil")
	}
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ptr := timePtr(ts)
	if ptr == nil || !ptr.Equal(ts) {
		t.Fatalf("timePtr(%v) = %v", ts, ptr)
	}
}

func TestFindingSignalsFiltersNil(t *testing.T) {
	findings := []*ports.FindingRecord{
		{ID: "f1", RuleID: "r1", Status: "open", Severity: "HIGH"},
		nil,
		{ID: "f2", RuleID: "r2", Status: "resolved", Severity: "LOW"},
	}
	signals := findingSignals(findings)
	if len(signals) != 2 {
		t.Fatalf("len = %d, want 2", len(signals))
	}
	if signals[0].ID != "f1" {
		t.Fatalf("signals[0].ID = %q, want f1", signals[0].ID)
	}
}

func TestEvidenceSignalsFiltersNilAndLinks(t *testing.T) {
	ts := timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	evidence := []*cerebrov1.FindingEvidence{
		{Id: "e1", RuleId: "r1", FindingId: "f1", LastObservedAt: ts},
		nil,
	}
	findings := []*ports.FindingRecord{
		{ID: "f1", ControlRefs: []ports.FindingControlRef{{FrameworkName: "SOC2", ControlID: "CC1.1"}}},
	}
	signals := evidenceSignals(evidence, findings, map[string]string{})
	if len(signals) != 1 {
		t.Fatalf("len = %d, want 1", len(signals))
	}
	if len(signals[0].ControlRefs) != 1 {
		t.Fatalf("ControlRefs count = %d, want 1", len(signals[0].ControlRefs))
	}
}

func TestControlRefsFiltersIncomplete(t *testing.T) {
	refs := []ports.FindingControlRef{
		{FrameworkName: "SOC2", ControlID: "CC1.1"},
		{FrameworkName: "", ControlID: "CC2.1"},
		{FrameworkName: "SOC2", ControlID: ""},
	}
	result := controlRefs(refs)
	if len(result) != 1 {
		t.Fatalf("len = %d, want 1", len(result))
	}
}

func TestFindingItemFromNilRecord(t *testing.T) {
	pf := compliance.ControlEvidencePacketFinding{
		ID: "f1", Severity: "high", Status: "open", RuleID: "r1", Title: "Test",
	}
	item := findingItem(nil, pf, nil)
	if item.ID != "f1" {
		t.Fatalf("ID = %q, want f1", item.ID)
	}
	if item.Owner != "Unassigned" {
		t.Fatalf("Owner = %q, want Unassigned", item.Owner)
	}
	if item.Status != "OPEN" {
		t.Fatalf("Status = %q, want OPEN", item.Status)
	}
}

func TestFindingItemFromRecord(t *testing.T) {
	record := &ports.FindingRecord{
		ID:        "f1",
		RuleID:    "r1",
		Title:     "Test Finding",
		Status:    "open",
		Severity:  "high",
		TenantID:  "t1",
		RuntimeID: "rt1",
		FindingWorkflow: ports.FindingWorkflow{
			Assignee: "alice",
		},
	}
	pf := compliance.ControlEvidencePacketFinding{ID: "f1"}
	sourceIDs := map[string]string{"rt1": "aws"}
	item := findingItem(record, pf, sourceIDs)
	if item.SourceID != "aws" {
		t.Fatalf("SourceID = %q, want aws", item.SourceID)
	}
	if item.Owner != "alice" {
		t.Fatalf("Owner = %q, want alice", item.Owner)
	}
}

func TestRenderCustomMarkdownDelegates(t *testing.T) {
	result := CustomPacketResult{
		Profile: Profile{ID: "test", Name: "Test Profile"},
		Packet: compliance.ControlEvidencePacket{
			GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Summary: compliance.ControlPostureSummary{
				Total:    0,
				ByStatus: map[compliance.ControlPostureStatus]int{},
			},
		},
		ProfileFindingMatches: []ProfileFindingMatch{{
			FindingID:             "finding-1",
			FindingTitle:          "Privileged access review",
			RuleID:                "privileged-access",
			Status:                "open",
			MappingBasis:          compliance.FindingProfileMappingDirect,
			CoverageIndexVersion:  "2026-07-14",
			CoverageIndexRevision: "sha256:content-revision-1",
			MatchedControls:       []compliance.ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
		}},
		ProfileMatchEvaluation: ProfileMatchEvaluation{EvaluatedFindings: 5, MatchedFindings: 1, EvaluationLimit: 500, ScanTruncated: true},
	}
	md := RenderCustomMarkdown(result)
	for _, want := range []string{"Test Profile", "## Profile Findings", "Privileged access review", "direct", "| Privileged access review | privileged-access | open | direct | SOC 2 CC6.1 | sha256:content-revision-1 |", "Scan truncated: true"} {
		if !strings.Contains(md, want) {
			t.Fatalf("RenderCustomMarkdown() missing %q:\n%s", want, md)
		}
	}
}
