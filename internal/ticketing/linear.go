package ticketing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// LinearProvider implements ticketing for Linear
type LinearProvider struct {
	apiKey string
	teamID string
	client *http.Client
}

type LinearConfig struct {
	APIKey string
	TeamID string
}

func NewLinearProvider(cfg LinearConfig) *LinearProvider {
	return &LinearProvider{
		apiKey: cfg.APIKey,
		teamID: cfg.TeamID,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (l *LinearProvider) Name() string {
	return "linear"
}

type graphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type graphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

func (l *LinearProvider) CreateTicket(ctx context.Context, ticket *Ticket) (*Ticket, error) {
	query := `
		mutation CreateIssue($input: IssueCreateInput!) {
			issueCreate(input: $input) {
				success
				issue {
					id
					identifier
					title
					description
					url
					priority
					state { name }
					assignee { name }
					labels { nodes { name } }
					createdAt
					updatedAt
				}
			}
		}
	`

	variables := map[string]interface{}{
		"input": map[string]interface{}{
			"teamId":      l.teamID,
			"title":       ticket.Title,
			"description": ticket.Description,
			"priority":    l.priorityValue(ticket.Priority),
		},
	}

	resp, err := l.graphQL(ctx, query, variables)
	if err != nil {
		return nil, err
	}

	var result struct {
		IssueCreate struct {
			Success bool `json:"success"`
			Issue   struct {
				ID         string `json:"id"`
				Identifier string `json:"identifier"`
				Title      string `json:"title"`
				URL        string `json:"url"`
				CreatedAt  string `json:"createdAt"`
			} `json:"issue"`
		} `json:"issueCreate"`
	}

	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}

	if !result.IssueCreate.Success {
		return nil, fmt.Errorf("linear: failed to create issue")
	}

	ticket.ID = result.IssueCreate.Issue.ID
	ticket.ExternalID = result.IssueCreate.Issue.Identifier
	ticket.ExternalURL = result.IssueCreate.Issue.URL
	ticket.CreatedAt = time.Now()
	ticket.UpdatedAt = time.Now()

	return ticket, nil
}

func (l *LinearProvider) UpdateTicket(ctx context.Context, id string, update *TicketUpdate) (*Ticket, error) {
	query := `
		mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) {
			issueUpdate(id: $id, input: $input) {
				success
				issue {
					id
					identifier
					title
					url
				}
			}
		}
	`

	input := make(map[string]interface{})
	if update.Title != nil {
		input["title"] = *update.Title
	}
	if update.Description != nil {
		input["description"] = *update.Description
	}
	if update.Priority != nil {
		input["priority"] = l.priorityValue(*update.Priority)
	}

	variables := map[string]interface{}{
		"id":    id,
		"input": input,
	}

	_, err := l.graphQL(ctx, query, variables)
	if err != nil {
		return nil, err
	}

	return l.GetTicket(ctx, id)
}

func (l *LinearProvider) GetTicket(ctx context.Context, id string) (*Ticket, error) {
	query := `
		query GetIssue($id: String!) {
			issue(id: $id) {
				id
				identifier
				title
				description
				url
				priority
				state { name }
				assignee { name }
				labels { nodes { name } }
				createdAt
				updatedAt
			}
		}
	`

	resp, err := l.graphQL(ctx, query, map[string]interface{}{"id": id})
	if err != nil {
		return nil, err
	}

	var result struct {
		Issue struct {
			ID          string `json:"id"`
			Identifier  string `json:"identifier"`
			Title       string `json:"title"`
			Description string `json:"description"`
			URL         string `json:"url"`
			Priority    int    `json:"priority"`
			State       struct {
				Name string `json:"name"`
			} `json:"state"`
			Assignee *struct {
				Name string `json:"name"`
			} `json:"assignee"`
			Labels struct {
				Nodes []struct {
					Name string `json:"name"`
				} `json:"nodes"`
			} `json:"labels"`
			CreatedAt string `json:"createdAt"`
			UpdatedAt string `json:"updatedAt"`
		} `json:"issue"`
	}

	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}

	ticket := &Ticket{
		ID:          result.Issue.ID,
		ExternalID:  result.Issue.Identifier,
		Title:       result.Issue.Title,
		Description: result.Issue.Description,
		Priority:    l.priorityName(result.Issue.Priority),
		Status:      result.Issue.State.Name,
		ExternalURL: result.Issue.URL,
	}

	if result.Issue.Assignee != nil {
		ticket.Assignee = result.Issue.Assignee.Name
	}

	for _, label := range result.Issue.Labels.Nodes {
		ticket.Labels = append(ticket.Labels, label.Name)
	}

	return ticket, nil
}

func (l *LinearProvider) ListTickets(ctx context.Context, filter TicketFilter) ([]*Ticket, error) {
	query := `
		query ListIssues($teamId: String!, $first: Int) {
			team(id: $teamId) {
				issues(first: $first) {
					nodes {
						id
						identifier
						title
						url
						priority
						state { name }
					}
				}
			}
		}
	`

	limit := filter.Limit
	if limit == 0 {
		limit = 50
	}

	resp, err := l.graphQL(ctx, query, map[string]interface{}{
		"teamId": l.teamID,
		"first":  limit,
	})
	if err != nil {
		return nil, err
	}

	var result struct {
		Team struct {
			Issues struct {
				Nodes []struct {
					ID         string `json:"id"`
					Identifier string `json:"identifier"`
					Title      string `json:"title"`
					URL        string `json:"url"`
					Priority   int    `json:"priority"`
					State      struct {
						Name string `json:"name"`
					} `json:"state"`
				} `json:"nodes"`
			} `json:"issues"`
		} `json:"team"`
	}

	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}

	tickets := make([]*Ticket, len(result.Team.Issues.Nodes))
	for i, issue := range result.Team.Issues.Nodes {
		tickets[i] = &Ticket{
			ID:          issue.ID,
			ExternalID:  issue.Identifier,
			Title:       issue.Title,
			Priority:    l.priorityName(issue.Priority),
			Status:      issue.State.Name,
			ExternalURL: issue.URL,
		}
	}

	return tickets, nil
}

func (l *LinearProvider) AddComment(ctx context.Context, ticketID string, comment *Comment) error {
	query := `
		mutation CreateComment($input: CommentCreateInput!) {
			commentCreate(input: $input) {
				success
			}
		}
	`

	variables := map[string]interface{}{
		"input": map[string]interface{}{
			"issueId": ticketID,
			"body":    comment.Body,
		},
	}

	resp, err := l.graphQL(ctx, query, variables)
	if err != nil {
		return err
	}

	var result struct {
		CommentCreate struct {
			Success bool `json:"success"`
		} `json:"commentCreate"`
	}

	if err := json.Unmarshal(resp, &result); err != nil {
		return err
	}

	if !result.CommentCreate.Success {
		return fmt.Errorf("linear: failed to create comment")
	}

	return nil
}

func (l *LinearProvider) Close(ctx context.Context, id string, resolution string) error {
	// First add resolution comment
	if resolution != "" {
		_ = l.AddComment(ctx, id, &Comment{Body: "Resolution: " + resolution})
	}

	// Get completed state ID
	query := `
		query GetStates($teamId: String!) {
			team(id: $teamId) {
				states {
					nodes {
						id
						name
						type
					}
				}
			}
		}
	`

	resp, err := l.graphQL(ctx, query, map[string]interface{}{"teamId": l.teamID})
	if err != nil {
		return err
	}

	var states struct {
		Team struct {
			States struct {
				Nodes []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"nodes"`
			} `json:"states"`
		} `json:"team"`
	}

	if decErr := json.Unmarshal(resp, &states); decErr != nil {
		return decErr
	}

	var completedStateID string
	for _, s := range states.Team.States.Nodes {
		if s.Type == "completed" {
			completedStateID = s.ID
			break
		}
	}

	if completedStateID == "" {
		return fmt.Errorf("no completed state found")
	}

	// Update issue state
	updateQuery := `
		mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) {
			issueUpdate(id: $id, input: $input) {
				success
			}
		}
	`

	_, err = l.graphQL(ctx, updateQuery, map[string]interface{}{
		"id":    id,
		"input": map[string]interface{}{"stateId": completedStateID},
	})

	return err
}

func (l *LinearProvider) graphQL(ctx context.Context, query string, variables map[string]interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(graphQLRequest{Query: query, Variables: variables})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.linear.app/graphql", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", l.apiKey)

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("linear API error %d: %s", resp.StatusCode, string(body))
	}

	var gqlResp graphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
		return nil, err
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("linear graphql error: %s", gqlResp.Errors[0].Message)
	}

	return gqlResp.Data, nil
}

func (l *LinearProvider) priorityValue(p string) int {
	switch p {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	default:
		return 3
	}
}

func (l *LinearProvider) priorityName(v int) string {
	switch v {
	case 1:
		return "critical"
	case 2:
		return "high"
	case 3:
		return "medium"
	case 4:
		return "low"
	default:
		return "medium"
	}
}
