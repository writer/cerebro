package compliance

import (
	"strings"
	"testing"
	"time"
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
            implementation_guidance:
              - Require privileged identities to enroll phishing-resistant MFA before production access is granted.
            audit_procedure:
              - Compare privileged account inventory with current MFA enrollment evidence.
            failure_modes:
              - Privileged user has active production access without enrolled MFA.
            remediation_guidance:
              - Remove privileged access until MFA enrollment is complete.
            exception_guidance: Time-bound exceptions require compensating monitoring and approval.
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
	if len(control.Control.AuditProcedure) != 1 || control.Control.ExceptionGuidance == "" {
		t.Fatalf("auditor guidance fields were not retained: %#v", control.Control)
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

func TestBuildCatalogIndexAllowsUpcomingFrameworkWithoutControls(t *testing.T) {
	catalog := loadTestCatalog(t, `
version: "2026-06-17"
frameworks:
  - id: planned
    name: Planned Framework
    lifecycle: upcoming
`)
	index, issues := BuildCatalogIndex(catalog)
	if len(issues) != 0 {
		t.Fatalf("BuildCatalogIndex() issues = %#v, want none", issues)
	}
	controls, ok := index.FrameworkControls(ControlRef{FrameworkID: "planned"})
	if !ok {
		t.Fatal("FrameworkControls(planned) not found")
	}
	if len(controls) != 0 {
		t.Fatalf("FrameworkControls(planned) = %#v, want no controls", controls)
	}
}

func TestBuildCatalogIndexRejectsUnknownFrameworkLifecycle(t *testing.T) {
	catalog := loadTestCatalog(t, `
version: "2026-06-17"
frameworks:
  - id: planned
    name: Planned Framework
    lifecycle: later
`)
	_, issues := BuildCatalogIndex(catalog)
	if !issueContains(issues, "frameworks[0].lifecycle must be one of active, upcoming") {
		t.Fatalf("issues = %#v, want invalid lifecycle", issues)
	}
}

func TestBuiltinFrameworksIncludesUpcomingFrameworks(t *testing.T) {
	response, err := BuiltinFrameworks(time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("BuiltinFrameworks() error = %v", err)
	}
	var foundNIST, foundCSA bool
	for _, framework := range response.Frameworks {
		switch framework.Name {
		case "NIST AI RMF 1.0":
			foundNIST = true
			if framework.Lifecycle != FrameworkLifecycleUpcoming {
				t.Fatalf("NIST AI RMF lifecycle = %q, want upcoming", framework.Lifecycle)
			}
			if framework.ControlCount != 0 || framework.FamilyCount != 0 {
				t.Fatalf("NIST AI RMF counts = %d/%d, want 0/0", framework.FamilyCount, framework.ControlCount)
			}
		case "CSA CCM v4.0":
			foundCSA = true
			if framework.Lifecycle != FrameworkLifecycleUpcoming {
				t.Fatalf("CSA CCM lifecycle = %q, want upcoming", framework.Lifecycle)
			}
			if framework.ControlCount != 0 || framework.FamilyCount != 0 {
				t.Fatalf("CSA CCM counts = %d/%d, want 0/0", framework.FamilyCount, framework.ControlCount)
			}
		}
	}
	if !foundNIST {
		t.Fatal("NIST AI RMF 1.0 not found")
	}
	if !foundCSA {
		t.Fatal("CSA CCM v4.0 not found")
	}
}

func TestBuiltinFrameworksActiveFrameworksHaveActiveLifecycle(t *testing.T) {
	response, err := BuiltinFrameworks(time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("BuiltinFrameworks() error = %v", err)
	}
	var foundActive bool
	for _, framework := range response.Frameworks {
		if framework.Lifecycle == FrameworkLifecycleActive {
			foundActive = true
			if framework.FamilyCount == 0 {
				t.Fatalf("active framework %q has 0 families", framework.Name)
			}
		}
		if framework.Lifecycle != FrameworkLifecycleActive && framework.Lifecycle != FrameworkLifecycleUpcoming {
			t.Fatalf("framework %q lifecycle = %q, want active or upcoming", framework.Name, framework.Lifecycle)
		}
	}
	if !foundActive {
		t.Fatal("no active frameworks found")
	}
}

func TestBuiltinFrameworksIncludesMaturityAndGapActions(t *testing.T) {
	response, err := BuiltinFrameworks(time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("BuiltinFrameworks() error = %v", err)
	}
	var soc2, upcoming *FrameworkSummary
	for idx := range response.Frameworks {
		framework := &response.Frameworks[idx]
		switch framework.Name {
		case "SOC 2":
			soc2 = framework
		case "NIST AI RMF 1.0":
			upcoming = framework
		}
	}
	if soc2 == nil {
		t.Fatal("SOC 2 framework not found")
	}
	if soc2.Coverage.SelectedControls == 0 {
		t.Fatalf("SOC 2 selected controls = %d, want non-zero", soc2.Coverage.SelectedControls)
	}
	if soc2.Maturity.Status == "" || soc2.Maturity.Summary == "" {
		t.Fatalf("SOC 2 maturity = %#v, want populated status and summary", soc2.Maturity)
	}
	if len(soc2.GapActions) == 0 {
		t.Fatal("SOC 2 gap actions empty")
	}
	if upcoming == nil {
		t.Fatal("NIST AI RMF 1.0 framework not found")
	}
	if upcoming.Maturity.Status != "planning" {
		t.Fatalf("upcoming maturity status = %q, want planning", upcoming.Maturity.Status)
	}
	if len(upcoming.GapActions) != 1 || upcoming.GapActions[0].Code != "plan_framework_scope" {
		t.Fatalf("upcoming gap actions = %#v, want planning action", upcoming.GapActions)
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
