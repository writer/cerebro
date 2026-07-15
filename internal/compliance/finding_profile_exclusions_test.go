package compliance

import (
	"errors"
	"strings"
	"testing"

	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

func TestLoadFindingProfileExclusionLedgerIsStrict(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "unknown field",
			content: `version: "2026-07-14"
catalog_version: "2026-05-21"
unexpected: true
exclusions: []
`,
		},
		{
			name: "multiple documents",
			content: `version: "2026-07-14"
catalog_version: "2026-05-21"
exclusions: []
---
version: "2026-07-15"
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadFindingProfileExclusionLedger([]byte(tt.content))
			if !errors.Is(err, ErrInvalidFindingProfileExclusionLedger) {
				t.Fatalf("LoadFindingProfileExclusionLedger() error = %v, want ErrInvalidFindingProfileExclusionLedger", err)
			}
		})
	}
}

func TestValidateFindingProfileCoverageAcceptsRuleControlAndReviewedExclusion(t *testing.T) {
	index, ledger, catalog := validFindingProfileCoverageFixture()
	if issues := ValidateFindingProfileCoverage(index, ledger, catalog); len(issues) != 0 {
		t.Fatalf("ValidateFindingProfileCoverage() issues = %#v", issues)
	}
}

func TestValidateFindingProfileCoverageRejectsInvalidCoverage(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*FindingProfileIndex, *FindingProfileExclusionLedger, *findinganalysis.PublicDetectionCatalog)
		wantErr string
	}{
		{
			name: "catalog version mismatch",
			mutate: func(_ *FindingProfileIndex, ledger *FindingProfileExclusionLedger, _ *findinganalysis.PublicDetectionCatalog) {
				ledger.CatalogVersion = "2026-05-20"
			},
			wantErr: "does not match public catalog version",
		},
		{
			name: "duplicate public finding id",
			mutate: func(_ *FindingProfileIndex, _ *FindingProfileExclusionLedger, catalog *findinganalysis.PublicDetectionCatalog) {
				catalog.Detections = append(catalog.Detections, catalog.Detections[0])
			},
			wantErr: "public finding id \"rule-linked\" is duplicated",
		},
		{
			name: "duplicate exclusion",
			mutate: func(_ *FindingProfileIndex, ledger *FindingProfileExclusionLedger, _ *findinganalysis.PublicDetectionCatalog) {
				ledger.Exclusions = append(ledger.Exclusions, ledger.Exclusions[0])
			},
			wantErr: "exclusion for public finding \"reviewed-exclusion\" is duplicated",
		},
		{
			name: "unknown exclusion",
			mutate: func(_ *FindingProfileIndex, ledger *FindingProfileExclusionLedger, _ *findinganalysis.PublicDetectionCatalog) {
				ledger.Exclusions[0].FindingID = "missing"
			},
			wantErr: "public finding \"missing\" is not in the catalog",
		},
		{
			name: "stale exclusion",
			mutate: func(_ *FindingProfileIndex, ledger *FindingProfileExclusionLedger, _ *findinganalysis.PublicDetectionCatalog) {
				ledger.Exclusions[0].FindingID = "rule-linked"
			},
			wantErr: "public finding \"rule-linked\" now resolves to a named profile",
		},
		{
			name: "placeholder reason",
			mutate: func(_ *FindingProfileIndex, ledger *FindingProfileExclusionLedger, _ *findinganalysis.PublicDetectionCatalog) {
				ledger.Exclusions[0].Reason = "TBD"
			},
			wantErr: "a concrete reason is required",
		},
		{
			name: "placeholder owner",
			mutate: func(_ *FindingProfileIndex, ledger *FindingProfileExclusionLedger, _ *findinganalysis.PublicDetectionCatalog) {
				ledger.Exclusions[0].Owner = "unassigned"
			},
			wantErr: "a concrete owner is required",
		},
		{
			name: "unreviewed state",
			mutate: func(_ *FindingProfileIndex, ledger *FindingProfileExclusionLedger, _ *findinganalysis.PublicDetectionCatalog) {
				ledger.Exclusions[0].ReviewState = "pending"
			},
			wantErr: "must be \"reviewed\"",
		},
		{
			name: "invalid review date",
			mutate: func(_ *FindingProfileIndex, ledger *FindingProfileExclusionLedger, _ *findinganalysis.PublicDetectionCatalog) {
				ledger.Exclusions[0].ReviewedAt = "2026-02-30"
			},
			wantErr: "must be a valid YYYY-MM-DD date",
		},
		{
			name: "uncovered public finding",
			mutate: func(_ *FindingProfileIndex, _ *FindingProfileExclusionLedger, catalog *findinganalysis.PublicDetectionCatalog) {
				catalog.Detections = append(catalog.Detections, findinganalysis.PublicDetection{ID: "uncovered"})
			},
			wantErr: "public finding \"uncovered\" has no named profile link or reviewed exclusion",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index, ledger, catalog := validFindingProfileCoverageFixture()
			tt.mutate(&index, &ledger, &catalog)
			issues := ValidateFindingProfileCoverage(index, ledger, catalog)
			if !findingProfileIssuesContain(issues, tt.wantErr) {
				t.Fatalf("ValidateFindingProfileCoverage() issues = %#v, want %q", issues, tt.wantErr)
			}
		})
	}
}

func TestValidateBuiltinFindingProfileCoverageCoversPublicCatalog(t *testing.T) {
	if err := ValidateBuiltinFindingProfileCoverage(findinganalysis.BuiltinPublicDetectionCatalog()); err != nil {
		t.Fatalf("ValidateBuiltinFindingProfileCoverage() error = %v", err)
	}
}

func validFindingProfileCoverageFixture() (FindingProfileIndex, FindingProfileExclusionLedger, findinganalysis.PublicDetectionCatalog) {
	profileMatch := FindingProfileMatch{
		ProfileID:       "security-audit",
		MappingBasis:    FindingProfileMappingDirect,
		MatchedControls: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
		DirectControls:  []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
	}
	index := FindingProfileIndex{
		MatchesByRuleID: map[string][]FindingProfileMatch{
			"rule-linked": {profileMatch},
		},
		MatchesByControl: map[string][]FindingProfileMatch{
			ControlKey(ControlRef{FrameworkName: "SOC 2", ControlID: "CC6.1"}): {profileMatch},
		},
	}
	ledger := FindingProfileExclusionLedger{
		Version:        "2026-07-14",
		CatalogVersion: "2026-05-21",
		Exclusions: []FindingProfileExclusion{{
			FindingID:   "reviewed-exclusion",
			Reason:      "The finding does not apply to a named compliance profile.",
			Owner:       "compliance-mapping",
			ReviewState: findingProfileExclusionReviewStateReviewed,
			ReviewedAt:  "2026-07-14",
		}},
	}
	catalog := findinganalysis.PublicDetectionCatalog{
		Version: "2026-05-21",
		Detections: []findinganalysis.PublicDetection{
			{ID: "rule-linked"},
			{ID: "control-linked", ControlRefs: []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}}},
			{ID: "reviewed-exclusion"},
		},
	}
	return index, ledger, catalog
}

func findingProfileIssuesContain(issues []ValidationIssue, want string) bool {
	for _, issue := range issues {
		if strings.Contains(issue.Message, want) {
			return true
		}
	}
	return false
}
