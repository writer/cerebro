package compliance

import (
	"strings"
	"testing"
)

func TestBuildControlPackPreviewGeneratesAuditorReadyCoverage(t *testing.T) {
	archetypes, err := LoadBuiltinControlArchetypeSet()
	if err != nil {
		t.Fatalf("load archetypes: %v", err)
	}
	baseCatalog, err := LoadBuiltinControlCatalog()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	baseProfiles, err := LoadBuiltinControlProfileSet()
	if err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	preview, issues, err := BuildControlPackPreview(ControlPackBuildRequest{
		FrameworkID:   "customer-security",
		FrameworkName: "Customer Security Framework",
		ProfileID:     "customer-security-audit",
		ProfileName:   "Customer Security Audit",
		ArchetypeIDs:  []string{"privileged-mfa", "critical-vulnerability-sla", "incident-response"},
	}, archetypes, baseCatalog, baseProfiles, []RuleControlMapping{{
		RuleID: "identity-privileged-account-without-mfa",
		ControlRefs: []ControlRef{{
			FrameworkName: "SOC 2",
			ControlID:     "CC6.1",
		}},
	}})
	if err != nil {
		t.Fatalf("BuildControlPackPreview error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("BuildControlPackPreview issues = %#v", issues)
	}
	if preview.Summary.Controls != 3 {
		t.Fatalf("controls = %d, want 3", preview.Summary.Controls)
	}
	if preview.Summary.AuditorReadyControls != 3 {
		t.Fatalf("auditor ready = %d, want 3", preview.Summary.AuditorReadyControls)
	}
	if preview.Summary.MappedControls == 0 || preview.Summary.MappedRules == 0 {
		t.Fatalf("summary = %#v, want mapped coverage from SOC 2 alias", preview.Summary)
	}
	if !strings.Contains(preview.Files["controls.yaml"], "Customer Security Framework") {
		t.Fatalf("controls.yaml missing framework name:\n%s", preview.Files["controls.yaml"])
	}
	if !strings.Contains(preview.Files["coverage.yaml"], "customer-security-audit") {
		t.Fatalf("coverage.yaml missing generated profile:\n%s", preview.Files["coverage.yaml"])
	}
}

func TestBuildControlPackPreviewDefaultRecommendedArchetypesValidate(t *testing.T) {
	archetypes, err := LoadBuiltinControlArchetypeSet()
	if err != nil {
		t.Fatalf("load archetypes: %v", err)
	}
	baseCatalog, err := LoadBuiltinControlCatalog()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	baseProfiles, err := LoadBuiltinControlProfileSet()
	if err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	preview, issues, err := BuildControlPackPreview(ControlPackBuildRequest{}, archetypes, baseCatalog, baseProfiles, nil)
	if err != nil {
		t.Fatalf("BuildControlPackPreview error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("BuildControlPackPreview issues = %#v", issues)
	}
	if preview.Summary.Controls == 0 {
		t.Fatal("controls = 0, want default recommended archetypes")
	}
	if preview.Summary.Controls != preview.Summary.AuditorReadyControls {
		t.Fatalf("summary = %#v, want recommended archetypes auditor ready", preview.Summary)
	}
}

func TestBuildControlPackPreviewRejectsUnknownArchetype(t *testing.T) {
	archetypes, err := LoadBuiltinControlArchetypeSet()
	if err != nil {
		t.Fatalf("load archetypes: %v", err)
	}
	baseCatalog, err := LoadBuiltinControlCatalog()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	baseProfiles, err := LoadBuiltinControlProfileSet()
	if err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	_, issues, err := BuildControlPackPreview(ControlPackBuildRequest{ArchetypeIDs: []string{"missing"}}, archetypes, baseCatalog, baseProfiles, nil)
	if err != nil {
		t.Fatalf("BuildControlPackPreview error = %v", err)
	}
	if len(issues) == 0 {
		t.Fatal("issues = 0, want unknown archetype validation issue")
	}
	if len(issues) != 1 {
		t.Fatalf("issues = %#v, want only the unknown archetype issue", issues)
	}
	if issues[0].Path != "archetype_ids[0]" {
		t.Fatalf("issue path = %q, want archetype_ids[0]", issues[0].Path)
	}
	if strings.Contains(issues[0].Message, "at least one") {
		t.Fatalf("issue = %#v, want precise unknown archetype issue", issues[0])
	}
}
