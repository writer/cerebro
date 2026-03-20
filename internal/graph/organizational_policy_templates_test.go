package graph

import (
	"slices"
	"testing"
	"time"
)

func TestOrganizationalPolicyTemplatesCatalogIncludesExpectedTemplates(t *testing.T) {
	templates := OrganizationalPolicyTemplates()
	if len(templates) != 6 {
		t.Fatalf("template count = %d, want 6", len(templates))
	}

	byID := make(map[string]OrganizationalPolicyTemplate, len(templates))
	for _, template := range templates {
		byID[template.ID] = template
		if template.Title == "" {
			t.Fatalf("template %s is missing title", template.ID)
		}
		if template.Content == "" {
			t.Fatalf("template %s is missing content", template.ID)
		}
		if template.ReviewCycleDays <= 0 {
			t.Fatalf("template %s review cycle = %d, want > 0", template.ID, template.ReviewCycleDays)
		}
		if len(template.FrameworkMappings) == 0 {
			t.Fatalf("template %s is missing framework mappings", template.ID)
		}
	}

	for _, templateID := range []string{
		"information-security-policy",
		"acceptable-use-policy",
		"incident-response-plan",
		"data-classification-policy",
		"access-control-policy",
		"change-management-policy",
	} {
		if _, ok := byID[templateID]; !ok {
			t.Fatalf("template %s not found in catalog", templateID)
		}
	}
}

func TestOrganizationalPolicyTemplatesForFrameworkFiltersCatalog(t *testing.T) {
	soc2 := OrganizationalPolicyTemplatesForFramework("SOC 2")
	soc2IDs := make([]string, 0, len(soc2))
	for _, template := range soc2 {
		soc2IDs = append(soc2IDs, template.ID)
	}
	slices.Sort(soc2IDs)
	if !slices.Equal(soc2IDs, []string{
		"acceptable-use-policy",
		"access-control-policy",
		"change-management-policy",
		"incident-response-plan",
	}) {
		t.Fatalf("soc2 template ids = %#v", soc2IDs)
	}

	pci := OrganizationalPolicyTemplatesForFramework("pci-dss")
	pciIDs := make([]string, 0, len(pci))
	for _, template := range pci {
		pciIDs = append(pciIDs, template.ID)
	}
	slices.Sort(pciIDs)
	if !slices.Equal(pciIDs, []string{
		"access-control-policy",
		"data-classification-policy",
		"incident-response-plan",
	}) {
		t.Fatalf("pci-dss template ids = %#v", pciIDs)
	}
}

func TestOrganizationalPolicyWriteRequestFromTemplateUsesDefaults(t *testing.T) {
	now := time.Date(2026, 3, 18, 16, 0, 0, 0, time.UTC)

	req, err := OrganizationalPolicyWriteRequestFromTemplate("acceptable-use-policy", OrganizationalPolicyTemplateWriteOptions{
		PolicyVersion:         "v1",
		OwnerID:               "person:owner",
		RequiredDepartmentIDs: []string{"department:engineering"},
		ObservedAt:            now,
	})
	if err != nil {
		t.Fatalf("OrganizationalPolicyWriteRequestFromTemplate returned error: %v", err)
	}

	if req.Title != "Acceptable Use Policy" {
		t.Fatalf("title = %q, want Acceptable Use Policy", req.Title)
	}
	if req.PolicyVersion != "v1" {
		t.Fatalf("policy version = %q, want v1", req.PolicyVersion)
	}
	if req.OwnerID != "person:owner" {
		t.Fatalf("owner id = %q, want person:owner", req.OwnerID)
	}
	if req.ReviewCycleDays != 365 {
		t.Fatalf("review cycle days = %d, want 365", req.ReviewCycleDays)
	}
	if !slices.Equal(req.FrameworkMappings, []string{"soc2:cc6.1", "soc2:cc6.2"}) {
		t.Fatalf("framework mappings = %#v, want default template mappings", req.FrameworkMappings)
	}
	if got := readString(req.Metadata, "policy_template_id"); got != "acceptable-use-policy" {
		t.Fatalf("policy_template_id = %q, want acceptable-use-policy", got)
	}
	if !slices.Equal(req.RequiredDepartmentIDs, []string{"department:engineering"}) {
		t.Fatalf("required departments = %#v, want [department:engineering]", req.RequiredDepartmentIDs)
	}
}

func TestOrganizationalPolicyWriteRequestFromTemplateAllowsOverrides(t *testing.T) {
	req, err := OrganizationalPolicyWriteRequestFromTemplate("incident-response-plan", OrganizationalPolicyTemplateWriteOptions{
		PolicyVersion:   "2026.04",
		Summary:         "Custom summary",
		Content:         "Custom content",
		ReviewCycleDays: 30,
		FrameworkMappings: []string{
			"soc2:cc7.5",
			"iso27001:a.5.24",
		},
		Metadata: map[string]any{"source": "test"},
	})
	if err != nil {
		t.Fatalf("OrganizationalPolicyWriteRequestFromTemplate returned error: %v", err)
	}

	if req.Summary != "Custom summary" {
		t.Fatalf("summary = %q, want custom override", req.Summary)
	}
	if req.Content != "Custom content" {
		t.Fatalf("content = %q, want custom override", req.Content)
	}
	if req.ReviewCycleDays != 30 {
		t.Fatalf("review cycle days = %d, want 30", req.ReviewCycleDays)
	}
	if !slices.Equal(req.FrameworkMappings, []string{"iso27001:a.5.24", "soc2:cc7.5"}) {
		t.Fatalf("framework mappings = %#v, want sorted override values", req.FrameworkMappings)
	}
	if got := readString(req.Metadata, "policy_template_id"); got != "incident-response-plan" {
		t.Fatalf("policy_template_id = %q, want incident-response-plan", got)
	}
	if got := readString(req.Metadata, "source"); got != "test" {
		t.Fatalf("metadata source = %q, want test", got)
	}
}

func TestOrganizationalPolicyWriteRequestFromTemplateRejectsInvalidInput(t *testing.T) {
	if _, err := OrganizationalPolicyWriteRequestFromTemplate("missing-template", OrganizationalPolicyTemplateWriteOptions{PolicyVersion: "v1"}); err == nil {
		t.Fatal("expected unknown template error")
	}
	if _, err := OrganizationalPolicyWriteRequestFromTemplate("acceptable-use-policy", OrganizationalPolicyTemplateWriteOptions{}); err == nil {
		t.Fatal("expected missing policy_version error")
	}
}
