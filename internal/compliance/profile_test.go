package compliance

import "testing"

func TestLoadControlProfileSetReadsYAML(t *testing.T) {
	set, err := LoadControlProfileSet([]byte(`
version: "2026-06-17"
profiles:
  - id: production-access
    name: Production Access
    frameworks:
      - name: Custom Framework
        controls: [IAM-1]
    include_tags: [identity]
`))
	if err != nil {
		t.Fatalf("LoadControlProfileSet() error = %v", err)
	}
	if set.Version != "2026-06-17" || len(set.Profiles) != 1 || set.Profiles[0].ID != "production-access" {
		t.Fatalf("set = %#v, want parsed profile set", set)
	}
}

func TestResolveControlProfilesValidatesProfileMetadata(t *testing.T) {
	_, issues := ResolveControlProfiles(testSelectionIndex(t), ControlProfileSet{
		Profiles: []ControlSelection{
			{ID: "duplicate", Name: "First"},
			{ID: "duplicate", Name: "Second"},
			{ID: "missing-name"},
		},
	})
	if len(issues) < 3 {
		t.Fatalf("issues = %#v, want version, duplicate id, and missing name issues", issues)
	}
	if !validationIssuesContain(issues, "control profile set version is required") {
		t.Fatalf("issues = %#v, want version issue", issues)
	}
	if !validationIssuesContain(issues, "control profile id is duplicated") {
		t.Fatalf("issues = %#v, want duplicate id issue", issues)
	}
	if !validationIssuesContain(issues, "control profile name is required") {
		t.Fatalf("issues = %#v, want missing name issue", issues)
	}
}

func TestBuildControlCoverageIndexCreditsMappedCustomControls(t *testing.T) {
	set := ControlProfileSet{
		Version: "2026-06-17",
		Profiles: []ControlSelection{{
			ID:   "customer-iam",
			Name: "Customer IAM",
			Frameworks: []FrameworkSelection{{
				ID:       "custom",
				Controls: []string{"IAM-1"},
			}},
		}},
	}

	index, issues := BuildControlCoverageIndex(testSelectionIndex(t), set, []RuleControlMapping{{
		RuleID:      "identity-mfa-required",
		ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
	}})
	if len(issues) != 0 {
		t.Fatalf("BuildControlCoverageIndex() issues = %#v, want none", issues)
	}
	if index.Version != "2026-06-17" || len(index.Profiles) != 1 {
		t.Fatalf("index = %#v, want one profile", index)
	}
	profile := index.Profiles[0]
	if profile.Summary.SelectedControls != 1 || profile.Summary.MappedControls != 1 || profile.Summary.MappedRules != 1 {
		t.Fatalf("summary = %#v, want one selected/mapped control and rule", profile.Summary)
	}
	if len(profile.Controls) != 1 || profile.Controls[0].ControlID != "IAM-1" {
		t.Fatalf("Controls = %#v, want custom IAM-1", profile.Controls)
	}
	control := profile.Controls[0]
	if control.CoverageStatus != "mapped" || control.RuleCount != 1 {
		t.Fatalf("coverage fields = status %q rule_count %d, want mapped/1", control.CoverageStatus, control.RuleCount)
	}
	if control.AuditPlan == nil || control.AuditPlan.Objective == "" || len(control.AuditPlan.AuditProcedure) != 2 || control.AuditPlan.ExceptionGuidance == "" {
		t.Fatalf("auditor guidance fields = %#v, want objective, audit procedure, and exception guidance", control)
	}
	wantProcedure := []string{
		"Review privileged production access approvals before checking MFA enrollment.",
		"Compare privileged account inventory against MFA enrollment evidence.",
	}
	for idx, want := range wantProcedure {
		if got := control.AuditPlan.AuditProcedure[idx]; got != want {
			t.Fatalf("AuditProcedure[%d] = %q, want %q", idx, got, want)
		}
	}
	if control.EvidencePlan == nil || len(control.EvidencePlan.Expectations) != 1 || control.EvidencePlan.Expectations[0].ID != "privileged-mfa-state" || !control.EvidencePlan.Expectations[0].Required {
		t.Fatalf("EvidencePlan = %#v, want required privileged-mfa-state", control.EvidencePlan)
	}
	if len(control.MappedControlRefs) != 1 || control.MappedControlRefs[0].FrameworkName != "SOC 2" || control.MappedControlRefs[0].ControlID != "CC6.1" {
		t.Fatalf("MappedControlRefs = %#v, want SOC 2 CC6.1", control.MappedControlRefs)
	}
	if got := profile.Controls[0].MappedRules; len(got) != 1 || got[0] != "identity-mfa-required" {
		t.Fatalf("MappedRules = %#v, want identity-mfa-required", got)
	}
	if len(profile.Rules) != 1 || len(profile.Rules[0].Controls) != 1 || profile.Rules[0].Controls[0].ControlID != "IAM-1" {
		t.Fatalf("Rules = %#v, want rule mapped to custom IAM-1", profile.Rules)
	}
}

func validationIssuesContain(issues []ValidationIssue, want string) bool {
	for _, issue := range issues {
		if issue.Message == want {
			return true
		}
	}
	return false
}
