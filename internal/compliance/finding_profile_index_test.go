package compliance

import (
	"encoding/json"
	"testing"
)

func TestBuildFindingProfileIndexPreservesDirectAndCatalogBasis(t *testing.T) {
	coverage := ControlCoverageIndex{
		Version: "2026-07-14",
		Profiles: []ControlCoverageProfile{{
			ID:   "access-audit",
			Name: "Access Audit",
			Controls: []ControlCoverageControl{
				{FrameworkName: "SOC 2", ControlID: "CC6.1"},
				{FrameworkName: "Custom", ControlID: "IAM-1", MappedControlRefs: []ControlRef{{FrameworkName: "NIST", ControlID: "PR.AA-01"}}},
			},
			Rules: []ControlCoverageRule{{
				RuleID: "privileged-access",
				Controls: []ControlRef{
					{FrameworkName: "SOC 2", ControlID: "CC6.1"},
					{FrameworkName: "Custom", ControlID: "IAM-1"},
				},
			}},
		}},
	}
	index, err := BuildFindingProfileIndex(coverage, []RuleControlMapping{{
		RuleID: "privileged-access",
		ControlRefs: []ControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.1"},
			{FrameworkName: "NIST", ControlID: "PR.AA-01"},
		},
	}})
	if err != nil {
		t.Fatalf("BuildFindingProfileIndex() error = %v", err)
	}
	matches := index.MatchesByRuleID["privileged-access"]
	if len(matches) != 1 {
		t.Fatalf("rule matches = %#v, want one", matches)
	}
	match := matches[0]
	if match.MappingBasis != FindingProfileMappingDirectAndCatalog {
		t.Fatalf("mapping basis = %q, want %q", match.MappingBasis, FindingProfileMappingDirectAndCatalog)
	}
	if len(match.DirectControls) != 1 || len(match.CatalogMappedControls) != 1 || len(match.MappingPaths) != 1 {
		t.Fatalf("mapping detail = %#v", match)
	}
	if got := index.MatchesByControl[ControlKey(ControlRef{FrameworkName: "NIST", ControlID: "PR.AA-01"})]; len(got) != 1 || got[0].MappingBasis != FindingProfileMappingCatalog {
		t.Fatalf("control fallback matches = %#v", got)
	}

	content, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	loaded, err := LoadFindingProfileIndex(content)
	if err != nil {
		t.Fatalf("LoadFindingProfileIndex() error = %v", err)
	}
	if loaded.Version != coverage.Version {
		t.Fatalf("loaded version = %q, want %q", loaded.Version, coverage.Version)
	}
	resolved := ResolveFindingProfileMatches(loaded, "privileged-access", []ControlRef{{FrameworkName: "NIST", ControlID: "PR.AA-01"}})
	if len(resolved) != 1 || resolved[0].ProfileID != "access-audit" || resolved[0].MappingBasis != FindingProfileMappingDirectAndCatalog {
		t.Fatalf("ResolveFindingProfileMatches() = %#v", resolved)
	}
}

func TestBuildFindingProfileIndexRejectsUnexplainedCoverage(t *testing.T) {
	_, err := BuildFindingProfileIndex(ControlCoverageIndex{
		Version: "2026-07-14",
		Profiles: []ControlCoverageProfile{{
			ID:       "access-audit",
			Controls: []ControlCoverageControl{{FrameworkName: "Custom", ControlID: "IAM-1"}},
			Rules: []ControlCoverageRule{{
				RuleID:   "privileged-access",
				Controls: []ControlRef{{FrameworkName: "Custom", ControlID: "IAM-1"}},
			}},
		}},
	}, []RuleControlMapping{{
		RuleID:      "privileged-access",
		ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
	}})
	if err == nil {
		t.Fatal("BuildFindingProfileIndex() error = nil, want unexplained coverage error")
	}
}
