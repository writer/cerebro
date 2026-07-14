package grcfindings

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
)

func TestFindingItemsNormalizeRiskInboxRows(t *testing.T) {
	dueAt := time.Now().UTC().Add(48 * time.Hour)
	statusUpdatedAt := time.Now().UTC().Add(-time.Hour)
	findings := []*ports.FindingRecord{{
		ID:           "finding-1",
		TenantID:     "tenant-1",
		RuntimeID:    "runtime-1",
		RuleID:       "rule-1",
		Title:        "Privileged access needs review",
		Severity:     "high",
		Status:       "open",
		Summary:      "Privileged access lacks review evidence.",
		ResourceURNs: []string{"urn:cerebro:tenant-1:identity:user-1"},
		PolicyID:     "policy-1",
		PolicyName:   "Access review",
		ControlRefs:  []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
		FindingRisk: ports.FindingRisk{
			RiskScore:        72,
			LikelihoodScore:  70,
			ImpactScore:      80,
			ConfidenceScore:  90,
			LikelihoodLevel:  "high",
			ImpactLevel:      "high",
			RiskReasons:      []string{"privileged access"},
			RiskModelVersion: "risk-v1",
		},
		FindingWorkflow: ports.FindingWorkflow{
			Assignee:        "security-owner",
			DueAt:           dueAt,
			StatusReason:    "triaged",
			StatusUpdatedAt: statusUpdatedAt,
			Notes:           []ports.FindingNote{{ID: "note-1", Body: "Owner confirmed.", CreatedAt: statusUpdatedAt}},
		},
	}}
	items := FindingItems(findings, map[string]string{"runtime-1": "okta"}, map[string]int{"finding-1": 3})
	if len(items) != 1 {
		t.Fatalf("len(FindingItems) = %d, want 1", len(items))
	}
	item := items[0]
	if item.Severity != "HIGH" || item.Status != "OPEN" {
		t.Fatalf("normalized severity/status = %q/%q, want HIGH/OPEN", item.Severity, item.Status)
	}
	if item.SourceID != "okta" || item.Entity != "urn:cerebro:tenant-1:identity:user-1" {
		t.Fatalf("source/entity = %q/%q", item.SourceID, item.Entity)
	}
	if item.RiskScore != 72 || item.RiskModel != "risk-v1" {
		t.Fatalf("risk fields = score %d model %q", item.RiskScore, item.RiskModel)
	}
	if item.Owner != "security-owner" || item.SLAStatus != "due_soon" || item.EvidenceCount != 3 {
		t.Fatalf("workflow fields owner=%q sla=%q evidence=%d", item.Owner, item.SLAStatus, item.EvidenceCount)
	}
	if item.DueAt == nil || !item.DueAt.Equal(dueAt) {
		t.Fatalf("DueAt = %v, want %v", item.DueAt, dueAt)
	}
	if len(item.Controls) != 1 || item.Controls[0].ControlID != "CC6.1" {
		t.Fatalf("Controls = %#v, want SOC 2 CC6.1", item.Controls)
	}
	if len(item.Profiles) == 0 {
		t.Fatal("ComplianceProfiles is empty, want profiles linked through SOC 2 CC6.1")
	}
}

func TestFindingProfileIndexLinksRulesAndMappedControlsWithoutDuplicates(t *testing.T) {
	target := compliance.ControlRef{FrameworkName: "Custom Framework", ControlID: "IAM-1"}
	source := compliance.ControlRef{
		FrameworkName:      "SOC 2",
		ControlID:          "CC6.1",
		Relationship:       compliance.ControlMappingRelationshipSupersetOf,
		MatchingRationale:  compliance.ControlMappingRationaleFunctional,
		MappingDescription: "The selected profile control covers the finding control.",
		MappingAuthority:   "Compliance mapping review",
		MappingSource:      "https://example.invalid/mappings/access-program",
		ReviewStatus:       compliance.ControlMappingReviewStatusComplete,
		ReviewedAt:         "2026-07-14",
		MappingVersion:     "v1",
	}
	match := compliance.FindingProfileMatch{
		ProfileID:             "access-program",
		ProfileName:           "Access Program",
		MappingBasis:          compliance.FindingProfileMappingCatalog,
		MatchedControls:       []compliance.ControlRef{target},
		CatalogMappedControls: []compliance.ControlRef{target},
		MappingPaths:          []compliance.FindingProfileMappingPath{{Source: source, Target: target}},
	}
	index := buildFindingProfileIndex(compliance.FindingProfileIndex{
		Version:          "2026-07-14",
		ContentRevision:  "sha256:test-revision",
		MatchesByRuleID:  map[string][]compliance.FindingProfileMatch{"privileged-mfa": {match}},
		MatchesByControl: map[string][]compliance.FindingProfileMatch{compliance.ControlKey(source): {match}},
	})

	profiles := index.profilesForFinding("privileged-mfa", []ControlRef{{
		FrameworkName: "SOC 2",
		ControlID:     "CC6.1",
	}})
	if len(profiles) != 1 {
		t.Fatalf("len(profiles) = %d, want 1: %#v", len(profiles), profiles)
	}
	if profiles[0].ID != "access-program" || len(profiles[0].MatchedControls) != 1 {
		t.Fatalf("profiles[0] = %#v, want one access-program IAM-1 match", profiles[0])
	}
	if profiles[0].CoverageIndexVersion != "2026-07-14" {
		t.Fatalf("coverage index version = %q, want 2026-07-14", profiles[0].CoverageIndexVersion)
	}
	if got := profiles[0].MappingBasis; got != compliance.FindingProfileMappingCatalog {
		t.Fatalf("mapping basis = %q, want catalog mapping provenance", got)
	}
	if got := profiles[0].MatchedFindingControls; len(got) != 1 || got[0].FrameworkName != "SOC 2" || got[0].ControlID != "CC6.1" {
		t.Fatalf("matched finding controls = %#v, want SOC 2 CC6.1", got)
	}
	if got := profiles[0].MatchedControls[0]; got.FrameworkName != "Custom Framework" || got.ControlID != "IAM-1" {
		t.Fatalf("matched control = %#v, want Custom Framework IAM-1", got)
	}
	path := profiles[0].MappingPaths[0]
	if path.MatchDirection != "finding_control_to_profile_control" || path.Source.ControlID != "CC6.1" || path.Target.ControlID != "IAM-1" {
		t.Fatalf("match traversal = %#v, want finding control to profile control", path)
	}
	if path.DeclaredSource.ControlID != "IAM-1" || path.DeclaredTarget.ControlID != "CC6.1" || path.Relationship != compliance.ControlMappingRelationshipSupersetOf || path.CoverageCredit != "reviewed_catalog_mapping" {
		t.Fatalf("declared relationship = %#v, want IAM-1 superset-of CC6.1 with reviewed credit", path)
	}
	profiles = index.profilesForFinding("unknown-rule", []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}})
	if len(profiles) != 1 || profiles[0].ID != "access-program" {
		t.Fatalf("control fallback profiles = %#v, want access-program", profiles)
	}
	if profiles := index.profilesForFinding("unknown-rule", []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC7.1"}}); len(profiles) != 0 {
		t.Fatalf("unrelated control profiles = %#v, want none", profiles)
	}
}

func TestFindingProfileIndexValidationRejectsMissingRevisionAndProfiles(t *testing.T) {
	if err := (findingProfileIndex{}).validate(); err == nil {
		t.Fatal("validate() error = nil, want missing coverage index version")
	}
	index := findingProfileIndex{version: "2026-07-14", contentRevision: "sha256:test-revision", profiles: map[string]ProfileRef{}}
	if err := index.validate(); err == nil {
		t.Fatal("validate() error = nil, want missing profiles")
	}
}

func TestFindingProfileIndexRejectsEmptyAssociationsAndVersionDrift(t *testing.T) {
	profileSet := compliance.ControlProfileSet{
		Version:  "2026-07-14",
		Profiles: []compliance.ControlSelection{{ID: "access-program", Name: "Access Program"}},
	}
	empty := findingProfileIndex{
		version:         "2026-07-14",
		contentRevision: "sha256:test-revision",
		byRuleID:        map[string][]findingProfileMatch{},
		byControlID:     map[string][]findingProfileMatch{},
		profiles:        map[string]ProfileRef{},
	}
	if err := empty.applyProfiles(profileSet); err == nil {
		t.Fatal("applyProfiles() error = nil, want empty serving index rejection")
	}
	matched := findingProfileMatch{profileID: "access-program", profileName: "Access Program"}
	index := findingProfileIndex{
		version:         "2026-07-13",
		contentRevision: "sha256:test-revision",
		byRuleID:        map[string][]findingProfileMatch{"rule": {matched}},
		byControlID:     map[string][]findingProfileMatch{},
		profiles:        map[string]ProfileRef{"access-program": {ID: "access-program", Name: "Access Program"}},
	}
	if err := index.applyProfiles(profileSet); err == nil {
		t.Fatal("applyProfiles() error = nil, want profile/index version drift rejection")
	}
}

func TestControlItemsGroupOpenFindingsByControl(t *testing.T) {
	items := ControlItems([]FindingItem{
		{ID: "critical", Severity: "CRITICAL", Status: "OPEN", EvidenceCount: 2, Controls: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}}},
		{ID: "high", Severity: "HIGH", Status: "OPEN", EvidenceCount: 1, Controls: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}}},
		{ID: "resolved", Severity: "LOW", Status: "RESOLVED", Controls: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.2"}}},
	}, nil)
	if len(items) != 2 {
		t.Fatalf("len(ControlItems) = %d, want 2", len(items))
	}
	control := items[0]
	if control.FrameworkName != "SOC 2" || control.ControlID != "CC6.1" {
		t.Fatalf("first control = %s %s, want SOC 2 CC6.1", control.FrameworkName, control.ControlID)
	}
	if control.Status != "failing" || control.OpenFindings != 2 || control.CriticalFindings != 1 || control.HighFindings != 1 || control.EvidenceItems != 3 {
		t.Fatalf("control posture = %#v", control)
	}
}
