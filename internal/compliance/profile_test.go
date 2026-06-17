package compliance

import "testing"

func TestLoadControlProfileSetReadsYAML(t *testing.T) {
	set, err := LoadControlProfileSet([]byte(`
version: "2026-06-17"
profiles:
  - id: production-access
    name: Production Access
    include_profiles: [identity-core]
    frameworks:
      - name: Custom Framework
        controls: [IAM-1]
    include_tags: [identity]
`))
	if err != nil {
		t.Fatalf("LoadControlProfileSet() error = %v", err)
	}
	if set.Version != "2026-06-17" || len(set.Profiles) != 1 || set.Profiles[0].ID != "production-access" || len(set.Profiles[0].IncludeProfiles) != 1 {
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

func TestResolveControlProfilesComposesIncludedProfiles(t *testing.T) {
	set := ControlProfileSet{
		Version: "2026-06-17",
		Profiles: []ControlSelection{
			{
				ID:   "soc2-access",
				Name: "SOC 2 Access",
				Frameworks: []FrameworkSelection{{
					Name:     "SOC 2",
					Controls: []string{"CC6.1"},
				}},
			},
			{
				ID:   "custom-identity",
				Name: "Custom Identity",
				Frameworks: []FrameworkSelection{{
					ID:       "custom",
					Controls: []string{"IAM-1"},
				}},
			},
			{
				ID:              "customer-audit",
				Name:            "Customer Audit",
				IncludeProfiles: []string{"soc2-access", "custom-identity"},
				ExcludeControls: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
			},
		},
	}

	resolution, issues := ResolveControlProfiles(testSelectionIndex(t), set)
	if len(issues) != 0 {
		t.Fatalf("ResolveControlProfiles() issues = %#v, want none", issues)
	}
	profile := resolvedProfileByID(t, resolution, "customer-audit")
	if len(profile.Resolution.Controls) != 1 {
		t.Fatalf("Controls = %#v, want one custom identity control after exclusion", profile.Resolution.Controls)
	}
	control := profile.Resolution.Controls[0]
	if control.FrameworkName != "Custom Framework" || control.Control.ID != "IAM-1" {
		t.Fatalf("Control = %#v, want Custom Framework IAM-1", control)
	}
}

func TestResolveControlProfilesReportsUnknownIncludedProfile(t *testing.T) {
	set := ControlProfileSet{
		Version: "2026-06-17",
		Profiles: []ControlSelection{{
			ID:              "customer-audit",
			Name:            "Customer Audit",
			IncludeProfiles: []string{"missing-profile"},
		}},
	}

	_, issues := ResolveControlProfiles(testSelectionIndex(t), set)
	if !validationIssuesContain(issues, `profile "missing-profile" is not declared`) {
		t.Fatalf("issues = %#v, want missing profile issue", issues)
	}
}

func TestResolveControlProfilesReportsIncludeCycles(t *testing.T) {
	set := ControlProfileSet{
		Version: "2026-06-17",
		Profiles: []ControlSelection{
			{ID: "profile-a", Name: "Profile A", IncludeProfiles: []string{"profile-b"}},
			{ID: "profile-b", Name: "Profile B", IncludeProfiles: []string{"profile-a"}},
		},
	}

	_, issues := ResolveControlProfiles(testSelectionIndex(t), set)
	if !validationIssuesContain(issues, "profile include cycle detected: profile-a -> profile-b -> profile-a") {
		t.Fatalf("issues = %#v, want include cycle issue", issues)
	}
}

func resolvedProfileByID(t *testing.T, resolution ControlProfileResolution, id string) ResolvedControlProfile {
	t.Helper()
	for _, profile := range resolution.Profiles {
		if profile.Profile.ID == id {
			return profile
		}
	}
	t.Fatalf("profile %q not found in %#v", id, resolution.Profiles)
	return ResolvedControlProfile{}
}

func validationIssuesContain(issues []ValidationIssue, want string) bool {
	for _, issue := range issues {
		if issue.Message == want {
			return true
		}
	}
	return false
}
