package compliance

import (
	"strings"
	"testing"
)

func TestBuildCatalogIndexAcceptsRichCustomControlPack(t *testing.T) {
	catalog := loadTestCatalog(t, `
version: "2026-06-17"
frameworks:
  - id: soc2
    name: SOC 2
    framework_version: "2022"
    families:
      - id: CC6
        name: Logical and Physical Access
        controls:
          - id: CC6.1
            title: Logical access is restricted
            assessment_methods: [examine, test]
            tags: [identity]
            evidence_expectations:
              - id: mfa-config
                type: identity_configuration
                description: MFA settings for privileged access.
                assessment_methods: [examine]
  - id: customer-audit-2026
    name: Customer Audit 2026
    families:
      - id: IAM
        name: Identity Controls
        tags: [identity]
        controls:
          - id: IAM-1
            title: Privileged access requires MFA
            objective: Privileged users authenticate with phishing-resistant MFA.
            intent: Reduce the likelihood of account takeover for administrative access.
            owner_domain: identity
            assessment_methods: [examine, test]
            evidence_expectations:
              - id: privileged-mfa-state
                type: identity_configuration
                required: true
                accepted_from: [okta, github]
            maps_to:
              - framework_name: SOC 2
                control_id: CC6.1
`)
	index, issues := BuildCatalogIndex(catalog)
	if len(issues) != 0 {
		t.Fatalf("BuildCatalogIndex() issues = %#v, want none", issues)
	}
	control, ok := index.Control(ControlRef{FrameworkID: "customer-audit-2026", ControlID: "IAM-1"})
	if !ok {
		t.Fatal("Control(Customer Audit 2026 IAM-1) not found")
	}
	if control.Control.Objective == "" || control.Control.Intent == "" {
		t.Fatalf("rich control fields were not retained: %#v", control.Control)
	}
	if !stringSliceContains(control.EffectiveTags, "identity") {
		t.Fatalf("EffectiveTags = %#v, want inherited identity tag", control.EffectiveTags)
	}
	if len(control.Evidence) != 1 || control.Evidence[0].Type != "identity_configuration" {
		t.Fatalf("Evidence = %#v, want identity_configuration expectation", control.Evidence)
	}
}

func TestBuildCatalogIndexRejectsInvalidAssessmentMethodAndMapping(t *testing.T) {
	catalog := loadTestCatalog(t, `
version: "2026-06-17"
frameworks:
  - name: Custom
    families:
      - id: IAM
        name: Identity Controls
        controls:
          - id: IAM-1
            assessment_methods: [observe]
            maps_to:
              - framework_name: Missing
                control_id: M-1
`)
	_, issues := BuildCatalogIndex(catalog)
	if !issueContains(issues, "assessment_methods[0] must be one of examine, interview, test") {
		t.Fatalf("issues = %#v, want invalid assessment method", issues)
	}
	if !issueContains(issues, "maps_to[0] Missing M-1 is not declared") {
		t.Fatalf("issues = %#v, want missing mapping target", issues)
	}
}

func TestMergeControlCatalogsAllowsCustomPacksToMapToBuiltins(t *testing.T) {
	builtin := loadTestCatalog(t, `
version: "2026-06-17"
frameworks:
  - name: SOC 2
    families:
      - id: CC6
        name: Logical and Physical Access
        controls:
          - id: CC6.1
`)
	custom := loadTestCatalog(t, `
version: "customer-2026"
frameworks:
  - name: Customer Framework
    families:
      - id: IAM
        name: Identity Controls
        controls:
          - id: IAM-1
            maps_to:
              - framework_name: SOC 2
                control_id: CC6.1
`)
	merged := MergeControlCatalogs(builtin, custom)
	index, issues := BuildCatalogIndex(merged)
	if len(issues) != 0 {
		t.Fatalf("BuildCatalogIndex() issues = %#v, want none", issues)
	}
	if !index.HasControl("Customer Framework", "IAM-1") {
		t.Fatal("merged custom control not found")
	}
}

func TestBuildCatalogIndexDoesNotMutateCallerCatalogWhenNormalizingMappings(t *testing.T) {
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
  - id: custom
    name: Custom Framework
    families:
      - id: IAM
        name: Identity Controls
        controls:
          - id: IAM-1
            maps_to:
              - framework_id: soc2
                control_id: CC6.1
`)
	index, issues := BuildCatalogIndex(catalog)
	if len(issues) != 0 {
		t.Fatalf("BuildCatalogIndex() issues = %#v, want none", issues)
	}
	stored, ok := index.Control(ControlRef{FrameworkName: "Custom Framework", ControlID: "IAM-1"})
	if !ok {
		t.Fatal("Control(Custom Framework IAM-1) not found")
	}
	if got := stored.Control.MapsTo[0].FrameworkName; got != "SOC 2" {
		t.Fatalf("stored maps_to framework_name = %q, want SOC 2", got)
	}
	original := catalog.Frameworks[1].Families[0].Controls[0].MapsTo[0]
	if original.FrameworkID != "soc2" || original.FrameworkName != "" {
		t.Fatalf("original maps_to = %#v, want caller catalog left untouched", original)
	}
}

func loadTestCatalog(t *testing.T, content string) ControlCatalog {
	t.Helper()
	catalog, err := LoadControlCatalog([]byte(content))
	if err != nil {
		t.Fatalf("LoadControlCatalog() error = %v", err)
	}
	return catalog
}

func issueContains(issues []ValidationIssue, want string) bool {
	for _, issue := range issues {
		if strings.Contains(issue.Message, want) {
			return true
		}
	}
	return false
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
