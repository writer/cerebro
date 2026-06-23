package projectionspec

import (
	"testing"
)

func TestLoadAllTemplates(t *testing.T) {
	registry, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ids := registry.IDs()
	if len(ids) == 0 {
		t.Fatal("no projection templates loaded")
	}
	t.Logf("loaded %d templates: %v", len(ids), ids)

	// Verify every template has required fields.
	for _, id := range ids {
		template, ok := registry.Get(id)
		if !ok {
			t.Errorf("registry.Get(%q) returned false", id)
			continue
		}
		if template.Class == "" {
			t.Errorf("template %q has empty class", id)
		}
		if len(template.RequiredAttributes) == 0 {
			t.Errorf("template %q has empty required_attributes", id)
		}
		if template.Description == "" {
			t.Errorf("template %q has empty description", id)
		}
	}
}

func TestClassForReturnsExpectedMappings(t *testing.T) {
	registry, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := []struct {
		id    string
		class string
	}{
		{"asset", "asset"},
		{"cloud_resource", "asset"},
		{"endpoint_device", "asset"},
		{"repository", "asset"},
		{"finding", "finding"},
		{"vulnerability", "finding"},
		{"secret", "secret"},
		{"policy", "policy"},
		{"compliance_control", "policy"},
		{"deployment", "deployment"},
		{"alert", "alert"},
		{"identity_user", "identity_user"},
		{"identity_group", "identity_group"},
		{"group_membership", "group_membership"},
		{"audit_event", "audit_event"},
		{"evidence_cas_reference", "evidence_cas_reference"},
	}

	for _, tc := range cases {
		class, ok := registry.ClassFor(tc.id)
		if !ok {
			t.Errorf("ClassFor(%q) not found", tc.id)
			continue
		}
		if class != tc.class {
			t.Errorf("ClassFor(%q) = %q, want %q", tc.id, class, tc.class)
		}
	}
}

func TestRequiredAttributesForClass(t *testing.T) {
	registry, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	attrs := registry.RequiredAttributesFor("finding")
	if len(attrs) == 0 {
		t.Error("RequiredAttributesFor(finding) returned empty")
	}
	found := false
	for _, attr := range attrs {
		if attr == "finding_id" {
			found = true
		}
	}
	if !found {
		t.Errorf("RequiredAttributesFor(finding) missing finding_id, got %v", attrs)
	}
}
