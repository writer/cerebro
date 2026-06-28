package compliance

import "testing"

func TestResolveControlEvidenceRequirementsUsesSpecificProfileAndFallback(t *testing.T) {
	catalog := loadTestCatalog(t, `
version: "2026-06-28"
frameworks:
  - name: SOC 2
    families:
      - id: CC6
        name: Logical and Physical Access
        controls:
          - id: CC6.1
            title: Logical access is restricted
  - name: ISO 27001:2022
    families:
      - id: A.7
        name: Physical Controls
        controls:
          - id: A.7.8
`)
	index, catalogIssues := BuildCatalogIndex(catalog)
	if len(catalogIssues) != 0 {
		t.Fatalf("BuildCatalogIndex() issues = %#v, want none", catalogIssues)
	}
	requirements, err := LoadControlEvidenceRequirementCatalog([]byte(`
version: "2026-06-28"
defaults:
  source_id: control_owner_review
  entity_type: control_evidence_packet
  required_fields: [control_ref, control_owner]
  freshness_window: 90d
  assessment_methods: [examine]
  auditor_grade_evidence: Evidence identifies the control owner and observed state.
profiles:
  - profile_id: identity-access
    name: Identity and Access Evidence
    applies_to:
      family_keywords: [Access]
    source_requirements:
      - source_id: okta
        entity_type: identity_user
        required_fields: [user_id, status, factors]
        freshness_window: 24h
        assessment_methods: [examine, test]
        auditor_grade_evidence: Identity evidence shows active state and factor enrollment.
  - profile_id: baseline-control-review
    name: Baseline Control Review Evidence
    fallback: true
    source_requirements:
      - source_id: control_owner_review
        entity_type: control_evidence_packet
        required_fields: [control_ref, reviewer]
        freshness_window: 90d
        assessment_methods: [examine, interview]
        auditor_grade_evidence: Baseline evidence shows reviewer action and observed state.
`))
	if err != nil {
		t.Fatalf("LoadControlEvidenceRequirementCatalog() error = %v", err)
	}
	resolution, issues := ResolveControlEvidenceRequirements(index, requirements)
	if len(issues) != 0 {
		t.Fatalf("ResolveControlEvidenceRequirements() issues = %#v, want none", issues)
	}
	if !resolvedRequirementExists(resolution.Requirements, "SOC 2", "CC6.1", "identity-access", "okta") {
		t.Fatalf("requirements = %#v, want SOC 2 CC6.1 okta identity requirement", resolution.Requirements)
	}
	if !resolvedRequirementExists(resolution.Requirements, "ISO 27001:2022", "A.7.8", "baseline-control-review", "control_owner_review") {
		t.Fatalf("requirements = %#v, want ISO A.7.8 fallback requirement", resolution.Requirements)
	}
}

func TestResolveControlEvidenceRequirementsClonesManualEvidenceAllowed(t *testing.T) {
	manualAllowed := true
	catalog := loadTestCatalog(t, `
version: "2026-06-28"
frameworks:
  - name: SOC 2
    families:
      - id: CC6
        name: Logical and Physical Access
        controls:
          - id: CC6.1
          - id: CC6.2
`)
	index, catalogIssues := BuildCatalogIndex(catalog)
	if len(catalogIssues) != 0 {
		t.Fatalf("BuildCatalogIndex() issues = %#v, want none", catalogIssues)
	}
	requirements := ControlEvidenceRequirementCatalog{
		Version: "2026-06-28",
		Defaults: ControlEvidenceRequirementDefaults{
			SourceID:              "control_owner_review",
			EntityType:            "control_evidence_packet",
			RequiredFields:        []string{"control_ref"},
			FreshnessWindow:       "90d",
			AssessmentMethods:     []string{"examine"},
			AuditorGradeEvidence:  "Evidence identifies the control and observed state.",
			ManualEvidenceAllowed: &manualAllowed,
		},
		Profiles: []ControlEvidenceRequirementProfile{{
			ID:       "baseline-control-review",
			Name:     "Baseline Control Review Evidence",
			Fallback: true,
			SourceRequirements: []ControlEvidenceSourceRequirement{{
				SourceID:             "control_owner_review",
				EntityType:           "control_evidence_packet",
				RequiredFields:       []string{"control_ref"},
				FreshnessWindow:      "90d",
				AssessmentMethods:    []string{"examine"},
				AuditorGradeEvidence: "Baseline evidence shows reviewer action.",
			}},
		}},
	}
	resolution, issues := ResolveControlEvidenceRequirements(index, requirements)
	if len(issues) != 0 {
		t.Fatalf("ResolveControlEvidenceRequirements() issues = %#v, want none", issues)
	}
	if len(resolution.Requirements) != 2 {
		t.Fatalf("requirements = %d, want 2", len(resolution.Requirements))
	}
	first := resolution.Requirements[0].ManualEvidenceAllowed
	second := resolution.Requirements[1].ManualEvidenceAllowed
	if first == nil || second == nil {
		t.Fatalf("manual evidence pointers = %#v, %#v; want non-nil", first, second)
	}
	if first == second || first == requirements.Defaults.ManualEvidenceAllowed || second == requirements.Defaults.ManualEvidenceAllowed {
		t.Fatalf("manual evidence pointers share storage")
	}
	*first = false
	if *second != true || *requirements.Defaults.ManualEvidenceAllowed != true {
		t.Fatalf("manual evidence mutation leaked: second=%v default=%v", *second, *requirements.Defaults.ManualEvidenceAllowed)
	}
}

func TestControlEvidenceRequirementFrameworksGateKeywords(t *testing.T) {
	profile := ControlEvidenceRequirementProfile{
		ID:   "privacy-rights",
		Name: "Privacy Rights Evidence",
		AppliesTo: ControlEvidenceRequirementSelector{
			Frameworks:     []string{"CCPA"},
			FamilyKeywords: []string{"Privacy"},
		},
	}
	if !controlEvidenceRequirementProfileApplies(profile, ResolvedControl{
		FrameworkName: "CCPA",
		FamilyName:    "Consumer Privacy Rights",
		Control:       Control{ID: "1798.100", Title: "Privacy notice"},
	}) {
		t.Fatal("profile did not match CCPA privacy control")
	}
	if controlEvidenceRequirementProfileApplies(profile, ResolvedControl{
		FrameworkName: "SOC 2",
		FamilyName:    "Privacy",
		Control:       Control{ID: "PI1.1", Title: "Privacy notice"},
	}) {
		t.Fatal("profile matched privacy keyword outside the selected framework")
	}
}

func TestControlEvidenceRequirementFrameworkGateAllowsKeywordOrPrefix(t *testing.T) {
	profile := ControlEvidenceRequirementProfile{
		ID:   "privacy-rights",
		Name: "Privacy Rights Evidence",
		AppliesTo: ControlEvidenceRequirementSelector{
			Frameworks:        []string{"CCPA"},
			FamilyKeywords:    []string{"Privacy"},
			ControlIDPrefixes: []string{"1798"},
		},
	}
	if !controlEvidenceRequirementProfileApplies(profile, ResolvedControl{
		FrameworkName: "CCPA",
		FamilyName:    "Consumer Rights",
		Control:       Control{ID: "1798.100", Title: "Consumer notices"},
	}) {
		t.Fatal("profile did not match selected framework plus control ID prefix")
	}
	if !controlEvidenceRequirementProfileApplies(profile, ResolvedControl{
		FrameworkName: "CCPA",
		FamilyName:    "Consumer Privacy Rights",
		Control:       Control{ID: "1888.100", Title: "Consumer notices"},
	}) {
		t.Fatal("profile did not match selected framework plus keyword")
	}
	if controlEvidenceRequirementProfileApplies(profile, ResolvedControl{
		FrameworkName: "SOC 2",
		FamilyName:    "Consumer Privacy Rights",
		Control:       Control{ID: "1798.100", Title: "Consumer notices"},
	}) {
		t.Fatal("profile matched keyword and prefix outside the selected framework")
	}
}

func TestControlEvidenceRequirementKeywordsOrPrefixesMatch(t *testing.T) {
	profile := ControlEvidenceRequirementProfile{
		ID:   "data-protection",
		Name: "Data Protection Evidence",
		AppliesTo: ControlEvidenceRequirementSelector{
			FamilyKeywords:    []string{"Confidentiality"},
			ControlIDPrefixes: []string{"A.8."},
		},
	}
	if !controlEvidenceRequirementProfileApplies(profile, ResolvedControl{
		FrameworkName: "SOC 2",
		FamilyName:    "Confidentiality",
		Control:       Control{ID: "C1.1", Title: "Confidential information is protected"},
	}) {
		t.Fatal("profile did not match family keyword")
	}
	if !controlEvidenceRequirementProfileApplies(profile, ResolvedControl{
		FrameworkName: "ISO 27001:2022",
		FamilyName:    "Technology Controls",
		Control:       Control{ID: "A.8.24", Title: "Use of cryptography"},
	}) {
		t.Fatal("profile did not match control ID prefix")
	}
	if controlEvidenceRequirementProfileApplies(profile, ResolvedControl{
		FrameworkName: "ISO 27001:2022",
		FamilyName:    "Physical Controls",
		Control:       Control{ID: "A.7.8", Title: "Equipment siting and protection"},
	}) {
		t.Fatal("profile matched without keyword or prefix")
	}
}

func TestControlEvidenceRequirementKeywordSearchMatchesExporterScope(t *testing.T) {
	profile := ControlEvidenceRequirementProfile{
		ID:   "identity-access",
		Name: "Identity and Access Evidence",
		AppliesTo: ControlEvidenceRequirementSelector{
			FamilyKeywords: []string{"Access"},
		},
	}
	if controlEvidenceRequirementProfileApplies(profile, ResolvedControl{
		FrameworkName: "SOC 2",
		FamilyID:      "access",
		FamilyName:    "Control Activities",
		EffectiveTags: []string{"access"},
		Control:       Control{ID: "CC5.1", Title: "Controls are selected and developed"},
	}) {
		t.Fatal("profile matched family ID or tags outside exporter keyword scope")
	}
}

func TestControlEvidenceRequirementKeywordMatchingUsesWholeTerms(t *testing.T) {
	loggingProfile := ControlEvidenceRequirementProfile{
		ID:   "logging-monitoring",
		Name: "Logging and Monitoring Evidence",
		AppliesTo: ControlEvidenceRequirementSelector{
			FamilyKeywords: []string{"Log"},
		},
	}
	if controlEvidenceRequirementProfileApplies(loggingProfile, ResolvedControl{
		FrameworkName: "SOC 2",
		FamilyName:    "Logical and Physical Access",
		Control:       Control{ID: "CC6.1", Title: "Logical access is restricted"},
	}) {
		t.Fatal("short keyword matched inside an unrelated word")
	}

	aiProfile := ControlEvidenceRequirementProfile{
		ID:   "ai-governance",
		Name: "AI Governance Evidence",
		AppliesTo: ControlEvidenceRequirementSelector{
			FamilyKeywords: []string{"AI"},
		},
	}
	if !controlEvidenceRequirementProfileApplies(aiProfile, ResolvedControl{
		FrameworkName: "ISO 42001",
		FamilyName:    "AI Governance",
		Control:       Control{ID: "AI-1", Title: "AI system inventory"},
	}) {
		t.Fatal("short keyword did not match a standalone term")
	}
}

func TestValidateControlEvidenceRequirementCatalogRejectsIncompleteProfiles(t *testing.T) {
	catalog, err := LoadControlEvidenceRequirementCatalog([]byte(`
version: "2026-06-28"
profiles:
  - profile_id: broken
    name: Broken
    source_requirements:
      - source_id: okta
        assessment_methods: [observe]
`))
	if err != nil {
		t.Fatalf("LoadControlEvidenceRequirementCatalog() error = %v", err)
	}
	issues := ValidateControlEvidenceRequirementCatalog(catalog)
	for _, want := range []string{
		"applies_to is required unless fallback is true",
		"entity_type is required",
		"required_fields is required",
		"assessment_methods[0] must be one of examine, interview, test",
		"at least one fallback profile is required",
	} {
		if !issueContains(issues, want) {
			t.Fatalf("issues = %#v, want %q", issues, want)
		}
	}
}

func TestBuiltinControlEvidenceRequirementsCoverCatalog(t *testing.T) {
	controlCatalog, err := LoadBuiltinControlCatalog()
	if err != nil {
		t.Fatalf("LoadBuiltinControlCatalog() error = %v", err)
	}
	index, catalogIssues := BuildCatalogIndex(controlCatalog)
	if len(catalogIssues) != 0 {
		t.Fatalf("BuildCatalogIndex() issues = %#v, want none", catalogIssues)
	}
	requirementCatalog, err := LoadBuiltinControlEvidenceRequirementCatalog()
	if err != nil {
		t.Fatalf("LoadBuiltinControlEvidenceRequirementCatalog() error = %v", err)
	}
	resolution, issues := ResolveControlEvidenceRequirements(index, requirementCatalog)
	if len(issues) != 0 {
		t.Fatalf("ResolveControlEvidenceRequirements() issues = %#v, want none", issues)
	}
	if len(resolution.Requirements) < len(index.Controls()) {
		t.Fatalf("resolved requirements = %d, controls = %d, want at least one requirement per control", len(resolution.Requirements), len(index.Controls()))
	}
	if !resolvedRequirementExists(resolution.Requirements, "SOC 2", "CC6.1", "identity-access", "okta") {
		t.Fatal("builtin requirements missing SOC 2 CC6.1 okta identity requirement")
	}
	if !resolvedRequirementExists(resolution.Requirements, "ISO 27001:2022", "A.8.24", "data-protection", "aws") {
		t.Fatal("builtin requirements missing ISO 27001:2022 A.8.24 AWS data-protection requirement")
	}
	if !resolvedRequirementExists(resolution.Requirements, "ISO 27701", "7.2.6", "privacy-rights", "data_inventory") {
		t.Fatal("builtin requirements missing ISO 27701 7.2.6 data inventory privacy requirement")
	}
	if !resolvedRequirementExists(resolution.Requirements, "ISO 27701", "7.2.6", "privacy-rights", "privacy_request_system") {
		t.Fatal("builtin requirements missing ISO 27701 7.2.6 request system privacy requirement")
	}
	for _, tc := range []struct {
		framework string
		controlID string
		profileID string
	}{
		{framework: "SOC 2", controlID: "CC1.5", profileID: "identity-access"},
		{framework: "DORA", controlID: "Art.9", profileID: "logging-monitoring"},
		{framework: "CIS Controls v8", controlID: "11", profileID: "data-protection"},
		{framework: "NIST 800-53 r5", controlID: "PA-1", profileID: "change-configuration"},
	} {
		if resolvedRequirementProfileExists(resolution.Requirements, tc.framework, tc.controlID, tc.profileID) {
			t.Fatalf("builtin requirements unexpectedly matched %s %s to %s", tc.framework, tc.controlID, tc.profileID)
		}
	}
}

func TestControlEvidenceRequirementKeywordMatchingUsesWholeTokens(t *testing.T) {
	if containsAnyKeywordFold("SOC 2 A1 Availability", []string{"AI"}) {
		t.Fatal("AI keyword matched Availability")
	}
	if containsAnyKeywordFold("SOC 2 CC6 Logical and Physical Access", []string{"Log"}) {
		t.Fatal("Log keyword matched Logical")
	}
	if !containsAnyKeywordFold("SOC 2 CC6 Logical and Physical Access", []string{"Access"}) {
		t.Fatal("Access keyword did not match access token")
	}
	if !containsAnyKeywordFold("ISO 27001:2022 A.8 Information Protection", []string{"Information Protection"}) {
		t.Fatal("Information Protection keyword did not match phrase")
	}
	if !containsAnyKeywordFold("SOC 2 CC6.1 Access Control", []string{"6.1"}) {
		t.Fatal("punctuated keyword did not match control identifier fragment")
	}
}

func resolvedRequirementExists(requirements []ResolvedControlEvidenceRequirement, framework string, controlID string, profileID string, sourceID string) bool {
	for _, requirement := range requirements {
		if requirement.FrameworkName == framework &&
			requirement.ControlID == controlID &&
			requirement.ProfileID == profileID &&
			requirement.SourceRequirement.SourceID == sourceID {
			return true
		}
	}
	return false
}

func resolvedRequirementProfileExists(requirements []ResolvedControlEvidenceRequirement, framework string, controlID string, profileID string) bool {
	for _, requirement := range requirements {
		if requirement.FrameworkName == framework &&
			requirement.ControlID == controlID &&
			requirement.ProfileID == profileID {
			return true
		}
	}
	return false
}
