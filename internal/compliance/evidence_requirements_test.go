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
