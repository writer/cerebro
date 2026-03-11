package ticketing

import (
	"context"
	"reflect"
	"testing"
)

func TestNewJiraProvider_DefaultCloseTransitions(t *testing.T) {
	provider := NewJiraProvider(JiraConfig{
		BaseURL:  "https://example.atlassian.net",
		Email:    "security@example.com",
		APIToken: "token",
		Project:  "SEC",
	})

	if !reflect.DeepEqual(provider.closeTransitions, defaultJiraCloseTransitions) {
		t.Fatalf("expected default close transitions %v, got %v", defaultJiraCloseTransitions, provider.closeTransitions)
	}
}

func TestNewJiraProvider_CustomCloseTransitions(t *testing.T) {
	provider := NewJiraProvider(JiraConfig{
		BaseURL:          "https://example.atlassian.net",
		Email:            "security@example.com",
		APIToken:         "token",
		Project:          "SEC",
		CloseTransitions: []string{" Completed ", "done", "completed", "", "Closed"},
	})

	expected := []string{"Completed", "done", "Closed"}
	if !reflect.DeepEqual(provider.closeTransitions, expected) {
		t.Fatalf("expected custom close transitions %v, got %v", expected, provider.closeTransitions)
	}
}

func TestJiraProviderFindCloseTransitionID(t *testing.T) {
	provider := NewJiraProvider(JiraConfig{
		BaseURL:          "https://example.atlassian.net",
		Email:            "security@example.com",
		APIToken:         "token",
		Project:          "SEC",
		CloseTransitions: []string{"Done", "Closed"},
	})

	transitions := []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}{
		{ID: "11", Name: "In Progress"},
		{ID: "12", Name: "Resolved"},
		{ID: "13", Name: "Done"},
	}

	if got := provider.findCloseTransitionID(transitions, "Resolved"); got != "12" {
		t.Fatalf("expected resolution-specific transition id 12, got %q", got)
	}

	if got := provider.findCloseTransitionID(transitions, ""); got != "13" {
		t.Fatalf("expected configured transition id 13, got %q", got)
	}

	if got := provider.findCloseTransitionID(transitions, "NotReal"); got != "13" {
		t.Fatalf("expected fallback configured transition id 13, got %q", got)
	}
}

func TestJiraProviderValidate(t *testing.T) {
	provider := NewJiraProvider(JiraConfig{
		BaseURL:  "https://example.atlassian.net",
		Email:    "security@example.com",
		APIToken: "token",
		Project:  "SEC",
	})
	if err := provider.Validate(context.Background()); err != nil {
		t.Fatalf("expected provider config to validate, got %v", err)
	}

	invalid := NewJiraProvider(JiraConfig{
		BaseURL:  "https://example.atlassian.net",
		APIToken: "token",
		Project:  "SEC",
	})
	if err := invalid.Validate(context.Background()); err == nil {
		t.Fatal("expected missing email to fail validation")
	}
}
