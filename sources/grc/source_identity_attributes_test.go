package grc

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestReadVantaPersonEmitsEmploymentAttributes(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true

	pull, err := source.Read(context.Background(), testConfig(server.URL, familyPerson), nil)
	if err != nil {
		t.Fatalf("Read(person) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(person).Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "grc.person" {
		t.Fatalf("event.Kind = %q, want grc.person", event.Kind)
	}
	for key, want := range map[string]string{
		"department":      "Design",
		"employee_number": "E-1001",
		"job_title":       "Product Designer",
		"manager":         "manager@example.com",
		"manager_id":      "person-manager",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("Attributes[%q] = %q, want %q", key, got, want)
		}
	}
}
