package graph

import "testing"

func TestDefaultGraphQueryTemplates(t *testing.T) {
	templates := DefaultGraphQueryTemplates()
	if len(templates) < 4 {
		t.Fatalf("expected multiple templates, got %#v", templates)
	}
	for i, template := range templates {
		if template.ID == "" || template.Name == "" || template.Mode == "" {
			t.Fatalf("expected non-empty template fields, got %#v", template)
		}
		if i > 0 && templates[i-1].ID > template.ID {
			t.Fatalf("expected templates sorted by ID, got %#v", templates)
		}
	}
}
