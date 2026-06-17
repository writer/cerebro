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
            owner_domain: identity
            tags: [identity]
            evidence_expectations:
              - id: privileged-mfa-state
                type: identity_configuration
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
