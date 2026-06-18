package compliance

import "testing"

func TestLoadControlSelectionReadsYAML(t *testing.T) {
	selection, err := LoadControlSelection([]byte(`
id: customer-audit
name: Customer Audit
frameworks:
  - name: SOC 2
    controls: [CC6.1]
include_tags: [identity]
exclude_controls:
  - framework_name: SOC 2
    control_id: CC6.2
`))
	if err != nil {
		t.Fatalf("LoadControlSelection() error = %v", err)
	}
	if selection.ID != "customer-audit" || len(selection.Frameworks) != 1 || len(selection.ExcludeControls) != 1 {
		t.Fatalf("selection = %#v, want parsed YAML selection", selection)
	}
}

func TestResolveControlSelectionSupportsFrameworkFamiliesAndExclusions(t *testing.T) {
	index := testSelectionIndex(t)
	resolution, issues := ResolveControlSelection(index, ControlSelection{
		ID: "soc2-cc6-without-cc6-2",
		Frameworks: []FrameworkSelection{{
			Name:     "SOC 2",
			Families: []string{"CC6"},
		}},
		ExcludeControls: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.2"}},
	})
	if len(issues) != 0 {
		t.Fatalf("ResolveControlSelection() issues = %#v, want none", issues)
	}
	if len(resolution.Controls) != 1 {
		t.Fatalf("len(Controls) = %d, want 1", len(resolution.Controls))
	}
	if got := resolution.Controls[0].Control.ID; got != "CC6.1" {
		t.Fatalf("selected control = %q, want CC6.1", got)
	}
}

func TestResolveControlSelectionSupportsTagOwnerAndEvidenceFilters(t *testing.T) {
	index := testSelectionIndex(t)
	resolution, issues := ResolveControlSelection(index, ControlSelection{
		ID:                   "identity-configuration",
		IncludeTags:          []string{"identity"},
		IncludeOwnerDomains:  []string{"identity"},
		IncludeEvidenceTypes: []string{"identity_configuration"},
	})
	if len(issues) != 0 {
		t.Fatalf("ResolveControlSelection() issues = %#v, want none", issues)
	}
	if len(resolution.Controls) != 1 || resolution.Controls[0].Control.ID != "IAM-1" {
		t.Fatalf("Controls = %#v, want custom IAM-1", resolution.Controls)
	}
}

func TestResolveControlSelectionSupportsControlPostureFilters(t *testing.T) {
	index := testSelectionIndex(t)
	resolution, issues := ResolveControlSelection(index, ControlSelection{
		ID:                    "automated-production-tests",
		IncludeApplicability:  []string{"production"},
		IncludeAssessments:    []string{"test"},
		Automatable:           testSelectionBool(true),
		ManualEvidenceAllowed: testSelectionBool(false),
	})
	if len(issues) != 0 {
		t.Fatalf("ResolveControlSelection() issues = %#v, want none", issues)
	}
	if len(resolution.Controls) != 1 || resolution.Controls[0].Control.ID != "IAM-1" {
		t.Fatalf("Controls = %#v, want custom IAM-1", resolution.Controls)
	}
}

func TestResolveControlSelectionSupportsReadinessFilter(t *testing.T) {
	index := testSelectionIndex(t)
	resolution, issues := ResolveControlSelection(index, ControlSelection{
		ID:               "controls-needing-enrichment",
		IncludeReadiness: []string{string(ControlReadinessNeedsEnrichment)},
	})
	if len(issues) != 0 {
		t.Fatalf("ResolveControlSelection() issues = %#v, want none", issues)
	}
	if len(resolution.Controls) != 1 || resolution.Controls[0].Control.ID != "IAM-1" {
		t.Fatalf("Controls = %#v, want custom IAM-1", resolution.Controls)
	}
}

func TestResolveControlSelectionValidatesReadinessFilter(t *testing.T) {
	_, issues := ResolveControlSelection(testSelectionIndex(t), ControlSelection{
		ID:               "invalid-readiness",
		IncludeReadiness: []string{"draft"},
	})
	if !validationIssuesContain(issues, "include_readiness[0] must be one of auditor_ready, needs_enrichment, placeholder") {
		t.Fatalf("issues = %#v, want invalid readiness issue", issues)
	}
}

func TestResolveControlSelectionRejectsProfileIncludes(t *testing.T) {
	resolution, issues := ResolveControlSelection(testSelectionIndex(t), ControlSelection{
		ID:              "composed",
		IncludeProfiles: []string{"identity-core"},
	})
	if len(resolution.Controls) != 0 {
		t.Fatalf("Controls = %#v, want none without profile-set resolver", resolution.Controls)
	}
	if !validationIssuesContain(issues, "include_profiles can only be resolved by ResolveControlProfiles") {
		t.Fatalf("issues = %#v, want include_profiles resolver issue", issues)
	}
}

func TestResolveControlSelectionMatchesEvidenceAssessmentMethods(t *testing.T) {
	index := testSelectionIndex(t)
	resolution, issues := ResolveControlSelection(index, ControlSelection{
		ID:                 "evidence-examination",
		IncludeAssessments: []string{"examine"},
	})
	if len(issues) != 0 {
		t.Fatalf("ResolveControlSelection() issues = %#v, want none", issues)
	}
	if len(resolution.Controls) != 1 || resolution.Controls[0].Control.ID != "IAM-1" {
		t.Fatalf("Controls = %#v, want custom IAM-1", resolution.Controls)
	}
}

func TestResolveRuleCoverageCreditsMappedCustomFrameworkControls(t *testing.T) {
	index := testSelectionIndex(t)
	resolution, issues := ResolveControlSelection(index, ControlSelection{
		Frameworks: []FrameworkSelection{{
			ID:       "custom",
			Controls: []string{"IAM-1"},
		}},
	})
	if len(issues) != 0 {
		t.Fatalf("ResolveControlSelection() issues = %#v, want none", issues)
	}
	coverage := ResolveRuleCoverage(resolution, []RuleControlMapping{{
		RuleID:      "identity-mfa-required",
		ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
	}})
	if coverage.SelectedControls != 1 {
		t.Fatalf("SelectedControls = %d, want 1", coverage.SelectedControls)
	}
	if len(coverage.MappedRules) != 1 || coverage.MappedRules[0] != "identity-mfa-required" {
		t.Fatalf("MappedRules = %#v, want identity-mfa-required", coverage.MappedRules)
	}
	customKey := ControlKey(ControlRef{FrameworkName: "Custom Framework", ControlID: "IAM-1"})
	if got := coverage.RulesByControl[customKey]; len(got) != 1 || got[0] != "identity-mfa-required" {
		t.Fatalf("RulesByControl[%q] = %#v, want identity-mfa-required", customKey, got)
	}
	if len(coverage.UnmappedControls) != 0 {
		t.Fatalf("UnmappedControls = %#v, want none", coverage.UnmappedControls)
	}
}

func testSelectionIndex(t *testing.T) *CatalogIndex {
	t.Helper()
	catalog := loadTestCatalog(t, `
version: "2026-06-17"
frameworks:
  - id: soc2
    name: SOC 2
    families:
      - id: CC6
        name: Logical and Physical Access
        controls:
          - id: CC6.1
            tags: [identity]
          - id: CC6.2
            tags: [identity]
  - id: custom
    name: Custom Framework
    families:
      - id: IAM
        name: Identity Controls
        controls:
          - id: IAM-1
            title: Privileged access requires MFA
            objective: Privileged production access requires strong authentication evidence.
            intent: Reduce account takeover risk for privileged production identities.
            owner_domain: identity
            freshness_sla: 30d
            applicability: [production, privileged_access]
            assessment_methods: [test]
            implementation_guidance:
              - Enforce MFA before privileged production access is granted.
            audit_procedure:
              - Review privileged production access approvals before checking MFA enrollment.
              - Compare privileged account inventory against MFA enrollment evidence.
            failure_modes:
              - Privileged account has production access without MFA evidence.
            remediation_guidance:
              - Remove privileged access until MFA is enrolled.
            exception_guidance: Exceptions require compensating monitoring and approval.
            automatable: true
            manual_evidence_allowed: false
            tags: [identity]
            evidence_expectations:
              - id: privileged-mfa-state
                title: Privileged MFA state
                type: identity_configuration
                required: true
                assessment_methods: [examine]
                accepted_from: [okta]
            maps_to:
              - framework_id: soc2
                control_id: CC6.1
`)
	index, issues := BuildCatalogIndex(catalog)
	if len(issues) != 0 {
		t.Fatalf("BuildCatalogIndex() issues = %#v, want none", issues)
	}
	return index
}

func testSelectionBool(value bool) *bool {
	return &value
}
