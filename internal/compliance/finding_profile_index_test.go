package compliance

import (
	"encoding/json"
	"testing"
)

func TestFindingProfileControlRefCapacityAvoidsOverflow(t *testing.T) {
	if got := findingProfileControlRefCapacity(2, 3); got != 5 {
		t.Fatalf("findingProfileControlRefCapacity(2, 3) = %d, want 5", got)
	}

	maxInt := int(^uint(0) >> 1)
	if got := findingProfileControlRefCapacity(maxInt, 1); got != 0 {
		t.Fatalf("findingProfileControlRefCapacity(maxInt, 1) = %d, want 0", got)
	}
}

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
	if loaded.SchemaVersion != FindingProfileIndexSchemaVersion || !validFindingProfileDigest(loaded.SourceDigest) || !validFindingProfileDigest(loaded.ContentRevision) {
		t.Fatalf("loaded durability metadata = schema %d source %q revision %q", loaded.SchemaVersion, loaded.SourceDigest, loaded.ContentRevision)
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

func TestFindingProfileIndexRevisionIsStableAcrossSourceOrdering(t *testing.T) {
	coverage := ControlCoverageIndex{
		Version: "2026-07-14",
		Profiles: []ControlCoverageProfile{{
			ID:   "access-audit",
			Name: "Access Audit",
			Controls: []ControlCoverageControl{
				{FrameworkName: "SOC 2", ControlID: "CC6.1"},
				{FrameworkName: "SOC 2", ControlID: "CC6.2"},
			},
			Rules: []ControlCoverageRule{
				{RuleID: "privileged-access", Controls: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}}},
				{RuleID: "stale-access", Controls: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.2"}}},
			},
		}},
	}
	rules := []RuleControlMapping{
		{RuleID: "privileged-access", ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}}},
		{RuleID: "stale-access", ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.2"}}},
	}
	first, err := BuildFindingProfileIndex(coverage, rules)
	if err != nil {
		t.Fatalf("BuildFindingProfileIndex(first) error = %v", err)
	}
	coverage.Profiles[0].Controls[0], coverage.Profiles[0].Controls[1] = coverage.Profiles[0].Controls[1], coverage.Profiles[0].Controls[0]
	coverage.Profiles[0].Rules[0], coverage.Profiles[0].Rules[1] = coverage.Profiles[0].Rules[1], coverage.Profiles[0].Rules[0]
	rules[0], rules[1] = rules[1], rules[0]
	second, err := BuildFindingProfileIndex(coverage, rules)
	if err != nil {
		t.Fatalf("BuildFindingProfileIndex(second) error = %v", err)
	}
	if first.SourceDigest != second.SourceDigest || first.ContentRevision != second.ContentRevision {
		t.Fatalf("reordered source changed revisions: first source=%q content=%q second source=%q content=%q", first.SourceDigest, first.ContentRevision, second.SourceDigest, second.ContentRevision)
	}
}

func TestLoadFindingProfileIndexRejectsInvalidDurabilityAndMappings(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*FindingProfileIndex)
		wantErr string
	}{
		{name: "unsupported schema", mutate: func(index *FindingProfileIndex) { index.SchemaVersion++ }, wantErr: "schema version"},
		{name: "missing source digest", mutate: func(index *FindingProfileIndex) { index.SourceDigest = "" }, wantErr: "source digest"},
		{name: "empty rule map", mutate: func(index *FindingProfileIndex) { index.MatchesByRuleID = map[string][]FindingProfileMatch{} }, wantErr: "rule matches are required"},
		{name: "empty control map", mutate: func(index *FindingProfileIndex) { index.MatchesByControl = map[string][]FindingProfileMatch{} }, wantErr: "control matches are required"},
		{name: "blank rule key", mutate: func(index *FindingProfileIndex) {
			index.MatchesByRuleID[""] = index.MatchesByRuleID["privileged-access"]
			delete(index.MatchesByRuleID, "privileged-access")
		}, wantErr: "match key"},
		{name: "blank profile id", mutate: func(index *FindingProfileIndex) {
			matches := index.MatchesByRuleID["privileged-access"]
			matches[0].ProfileID = ""
			index.MatchesByRuleID["privileged-access"] = matches
		}, wantErr: "profile id"},
		{name: "invalid basis", mutate: func(index *FindingProfileIndex) {
			matches := index.MatchesByRuleID["privileged-access"]
			matches[0].MappingBasis = "partial"
			index.MatchesByRuleID["privileged-access"] = matches
		}, wantErr: "mapping basis"},
		{name: "catalog control without path", mutate: func(index *FindingProfileIndex) {
			matches := index.MatchesByRuleID["privileged-access"]
			matches[0].CatalogMappedControls = append([]ControlRef(nil), matches[0].DirectControls...)
			matches[0].DirectControls = nil
			matches[0].MappingBasis = FindingProfileMappingCatalog
			matches[0].MappingPaths = nil
			index.MatchesByRuleID["privileged-access"] = matches
		}, wantErr: "has no mapping path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index := mustBuildFindingProfileIndexFixture(t)
			tt.mutate(&index)
			index.ContentRevision = ""
			revision, err := findingProfileIndexContentRevision(index)
			if err != nil {
				t.Fatalf("findingProfileIndexContentRevision() error = %v", err)
			}
			index.ContentRevision = revision
			content, err := json.Marshal(index)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if _, err := LoadFindingProfileIndex(content); err == nil {
				t.Fatalf("LoadFindingProfileIndex() error = nil for invalid %s", tt.name)
			}
		})
	}
}

func TestLoadFindingProfileIndexRejectsContentTampering(t *testing.T) {
	index := mustBuildFindingProfileIndexFixture(t)
	index.ContentRevision = findingProfileSHA256([]byte("different content"))
	content, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if _, err := LoadFindingProfileIndex(content); err == nil {
		t.Fatal("LoadFindingProfileIndex() error = nil, want content tampering rejection")
	}
}

func TestLoadBuiltinFindingProfileIndexMatchesEmbeddedSources(t *testing.T) {
	index, err := LoadBuiltinFindingProfileIndex()
	if err != nil {
		t.Fatalf("LoadBuiltinFindingProfileIndex() error = %v", err)
	}
	coverage, err := LoadBuiltinControlCoverageIndex()
	if err != nil {
		t.Fatalf("LoadBuiltinControlCoverageIndex() error = %v", err)
	}
	want, err := findingProfileIndexSourceDigest(coverage, BuiltinRuleControlMappings())
	if err != nil {
		t.Fatalf("findingProfileIndexSourceDigest() error = %v", err)
	}
	if index.SourceDigest != want {
		t.Fatalf("source digest = %q, want %q", index.SourceDigest, want)
	}
}

func TestFindingProfileIndexWireReusesIdenticalMatches(t *testing.T) {
	index := mustBuildFindingProfileIndexFixture(t)
	wire := findingProfileIndexWireFor(index)
	references := 0
	for _, indexes := range wire.MatchesByRuleID {
		references += len(indexes)
	}
	for _, indexes := range wire.MatchesByControl {
		references += len(indexes)
	}
	if references <= len(wire.Matches) {
		t.Fatalf("wire references = %d matches = %d, want repeated match records interned", references, len(wire.Matches))
	}
}

func mustBuildFindingProfileIndexFixture(t *testing.T) FindingProfileIndex {
	t.Helper()
	index, err := BuildFindingProfileIndex(ControlCoverageIndex{
		Version: "2026-07-14",
		Profiles: []ControlCoverageProfile{{
			ID:       "access-audit",
			Name:     "Access Audit",
			Controls: []ControlCoverageControl{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
			Rules: []ControlCoverageRule{{
				RuleID:   "privileged-access",
				Controls: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
			}},
		}},
	}, []RuleControlMapping{{
		RuleID:      "privileged-access",
		ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
	}})
	if err != nil {
		t.Fatalf("BuildFindingProfileIndex() error = %v", err)
	}
	return index
}
