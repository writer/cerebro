package ticketing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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

func TestJiraProviderMappings(t *testing.T) {
	provider := NewJiraProvider(JiraConfig{
		BaseURL:  "https://example.atlassian.net",
		Email:    "security@example.com",
		APIToken: "token",
		Project:  "SEC",
	})

	if got := provider.issueType("incident"); got != "Bug" {
		t.Fatalf("expected incident issue type to map to Bug, got %q", got)
	}
	if got := provider.issueType("finding"); got != "Task" {
		t.Fatalf("expected finding issue type to map to Task, got %q", got)
	}
	if got := provider.priorityName("critical"); got != "Highest" {
		t.Fatalf("expected critical priority to map to Highest, got %q", got)
	}
	if got := provider.priorityName("unknown"); got != "Medium" {
		t.Fatalf("expected unknown priority to default to Medium, got %q", got)
	}
}

func TestJiraProviderGetTicket(t *testing.T) {
	var authEmail, authToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/issue/SEC-1" {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		authEmail, authToken, _ = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":  "10001",
			"key": "SEC-1",
			"fields": map[string]any{
				"summary": "Broken auth flow",
				"status":  map[string]any{"name": "In Progress"},
				"labels":  []string{"security", "auth"},
				"assignee": map[string]any{
					"displayName": "Alice",
				},
				"reporter": map[string]any{
					"displayName": "Bob",
				},
			},
		})
	}))
	defer server.Close()

	provider := NewJiraProvider(JiraConfig{
		BaseURL:  server.URL,
		Email:    "security@example.com",
		APIToken: "token",
		Project:  "SEC",
	})
	provider.client = server.Client()

	ticket, err := provider.GetTicket(context.Background(), "SEC-1")
	if err != nil {
		t.Fatalf("GetTicket failed: %v", err)
	}

	if authEmail != "security@example.com" || authToken != "token" {
		t.Fatalf("unexpected basic auth credentials %q/%q", authEmail, authToken)
	}
	if ticket.ID != "10001" || ticket.ExternalID != "SEC-1" {
		t.Fatalf("unexpected ticket ids: %+v", ticket)
	}
	if ticket.Title != "Broken auth flow" || ticket.Status != "In Progress" {
		t.Fatalf("unexpected ticket core fields: %+v", ticket)
	}
	if ticket.Assignee != "Alice" || ticket.Reporter != "Bob" {
		t.Fatalf("unexpected ticket people fields: %+v", ticket)
	}
	if ticket.ExternalURL != server.URL+"/browse/SEC-1" {
		t.Fatalf("unexpected external URL %q", ticket.ExternalURL)
	}
}

func TestJiraProviderListTicketsBuildsExpectedQuery(t *testing.T) {
	var seenJQL string
	var seenMaxResults string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/search" {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		seenJQL = r.URL.Query().Get("jql")
		seenMaxResults = r.URL.Query().Get("maxResults")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issues": []map[string]any{
				{
					"id":  "10002",
					"key": "SEC-2",
					"fields": map[string]any{
						"summary":  "Privilege escalation",
						"status":   map[string]any{"name": "Open"},
						"labels":   []string{"critical"},
						"reporter": map[string]any{"displayName": "Carol"},
					},
				},
			},
		})
	}))
	defer server.Close()

	provider := NewJiraProvider(JiraConfig{
		BaseURL:  server.URL,
		Email:    "security@example.com",
		APIToken: "token",
		Project:  "SEC",
	})
	provider.client = server.Client()

	tickets, err := provider.ListTickets(context.Background(), TicketFilter{
		Status:   "Open",
		Priority: "critical",
		Limit:    25,
	})
	if err != nil {
		t.Fatalf("ListTickets failed: %v", err)
	}

	if len(tickets) != 1 || tickets[0].ExternalID != "SEC-2" {
		t.Fatalf("unexpected list result: %+v", tickets)
	}
	if seenMaxResults != "25" {
		t.Fatalf("expected maxResults=25, got %q", seenMaxResults)
	}
	if !strings.Contains(seenJQL, "project = SEC") {
		t.Fatalf("expected project filter in JQL, got %q", seenJQL)
	}
	if !strings.Contains(seenJQL, "status = \"Open\"") {
		t.Fatalf("expected status filter in JQL, got %q", seenJQL)
	}
	if !strings.Contains(seenJQL, "priority = \"Highest\"") {
		t.Fatalf("expected priority filter in JQL, got %q", seenJQL)
	}
}

func TestJiraProviderAddComment(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/issue/SEC-3/comment" {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		body = string(raw)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	provider := NewJiraProvider(JiraConfig{
		BaseURL:  server.URL,
		Email:    "security@example.com",
		APIToken: "token",
		Project:  "SEC",
	})
	provider.client = server.Client()

	if err := provider.AddComment(context.Background(), "SEC-3", &Comment{Body: "Needs immediate attention"}); err != nil {
		t.Fatalf("AddComment failed: %v", err)
	}
	if !strings.Contains(body, "Needs immediate attention") {
		t.Fatalf("expected comment body in request payload, got %q", body)
	}
}

func TestJiraProviderCloseUsesMatchedTransition(t *testing.T) {
	var transitionID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/issue/SEC-4/transitions":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"transitions": []map[string]any{
					{"id": "11", "name": "In Progress"},
					{"id": "12", "name": "Resolved"},
					{"id": "13", "name": "Done"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue/SEC-4/transitions":
			var payload struct {
				Transition struct {
					ID string `json:"id"`
				} `json:"transition"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("failed to decode transition payload: %v", err)
			}
			transitionID = payload.Transition.ID
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	provider := NewJiraProvider(JiraConfig{
		BaseURL:          server.URL,
		Email:            "security@example.com",
		APIToken:         "token",
		Project:          "SEC",
		CloseTransitions: []string{"Done"},
	})
	provider.client = server.Client()

	if err := provider.Close(context.Background(), "SEC-4", "Resolved"); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if transitionID != "12" {
		t.Fatalf("expected resolved transition id 12, got %q", transitionID)
	}
}
