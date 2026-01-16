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

// JiraProvider implements ticketing for Atlassian Jira
type JiraProvider struct {
	baseURL  string
	email    string
	apiToken string
	project  string
	client   *http.Client
}

type JiraConfig struct {
	BaseURL  string // e.g., https://yourcompany.atlassian.net
	Email    string
	APIToken string
	Project  string // Project key, e.g., "SEC"
}

func NewJiraProvider(cfg JiraConfig) *JiraProvider {
	return &JiraProvider{
		baseURL:  cfg.BaseURL,
		email:    cfg.Email,
		apiToken: cfg.APIToken,
		project:  cfg.Project,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (j *JiraProvider) Name() string {
	return "jira"
}

type jiraIssue struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Self   string `json:"self"`
	Fields struct {
		Summary     string `json:"summary"`
		Description struct {
			Type    string `json:"type"`
			Version int    `json:"version"`
			Content []struct {
				Type    string `json:"type"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"content"`
		} `json:"description"`
		Priority struct {
			Name string `json:"name"`
		} `json:"priority"`
		Status struct {
			Name string `json:"name"`
		} `json:"status"`
		Assignee *struct {
			AccountID   string `json:"accountId"`
			DisplayName string `json:"displayName"`
		} `json:"assignee"`
		Reporter struct {
			AccountID   string `json:"accountId"`
			DisplayName string `json:"displayName"`
		} `json:"reporter"`
		Labels  []string `json:"labels"`
		Created string   `json:"created"`
		Updated string   `json:"updated"`
	} `json:"fields"`
}

func (j *JiraProvider) CreateTicket(ctx context.Context, ticket *Ticket) (*Ticket, error) {
	body := map[string]interface{}{
		"fields": map[string]interface{}{
			"project": map[string]string{
				"key": j.project,
			},
			"summary": ticket.Title,
			"description": map[string]interface{}{
				"type":    "doc",
				"version": 1,
				"content": []map[string]interface{}{
					{
						"type": "paragraph",
						"content": []map[string]interface{}{
							{"type": "text", "text": ticket.Description},
						},
					},
				},
			},
			"issuetype": map[string]string{
				"name": j.issueType(ticket.Type),
			},
			"priority": map[string]string{
				"name": j.priorityName(ticket.Priority),
			},
			"labels": ticket.Labels,
		},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", j.baseURL+"/rest/api/3/issue", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	j.setHeaders(req)

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jira API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID   string `json:"id"`
		Key  string `json:"key"`
		Self string `json:"self"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	ticket.ID = result.ID
	ticket.ExternalID = result.Key
	ticket.ExternalURL = fmt.Sprintf("%s/browse/%s", j.baseURL, result.Key)
	ticket.CreatedAt = time.Now()
	ticket.UpdatedAt = time.Now()

	return ticket, nil
}

func (j *JiraProvider) UpdateTicket(ctx context.Context, id string, update *TicketUpdate) (*Ticket, error) {
	fields := make(map[string]interface{})

	if update.Title != nil {
		fields["summary"] = *update.Title
	}
	if update.Priority != nil {
		fields["priority"] = map[string]string{"name": j.priorityName(*update.Priority)}
	}
	if update.Labels != nil {
		fields["labels"] = update.Labels
	}

	body := map[string]interface{}{"fields": fields}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", j.baseURL+"/rest/api/3/issue/"+id, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	j.setHeaders(req)

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jira API error %d: %s", resp.StatusCode, string(body))
	}

	return j.GetTicket(ctx, id)
}

func (j *JiraProvider) GetTicket(ctx context.Context, id string) (*Ticket, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", j.baseURL+"/rest/api/3/issue/"+id, nil)
	if err != nil {
		return nil, err
	}

	j.setHeaders(req)

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jira API error %d", resp.StatusCode)
	}

	var issue jiraIssue
	if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
		return nil, err
	}

	return j.convertIssue(&issue), nil
}

func (j *JiraProvider) ListTickets(ctx context.Context, filter TicketFilter) ([]*Ticket, error) {
	jql := fmt.Sprintf("project = %s", j.project)
	if filter.Status != "" {
		jql += fmt.Sprintf(" AND status = \"%s\"", filter.Status)
	}
	if filter.Priority != "" {
		jql += fmt.Sprintf(" AND priority = \"%s\"", j.priorityName(filter.Priority))
	}

	req, err := http.NewRequestWithContext(ctx, "GET", j.baseURL+"/rest/api/3/search", nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Set("jql", jql)
	q.Set("maxResults", fmt.Sprintf("%d", filter.Limit))
	req.URL.RawQuery = q.Encode()

	j.setHeaders(req)

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Issues []jiraIssue `json:"issues"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	tickets := make([]*Ticket, len(result.Issues))
	for i, issue := range result.Issues {
		tickets[i] = j.convertIssue(&issue)
	}

	return tickets, nil
}

func (j *JiraProvider) AddComment(ctx context.Context, ticketID string, comment *Comment) error {
	body := map[string]interface{}{
		"body": map[string]interface{}{
			"type":    "doc",
			"version": 1,
			"content": []map[string]interface{}{
				{
					"type": "paragraph",
					"content": []map[string]interface{}{
						{"type": "text", "text": comment.Body},
					},
				},
			},
		},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", j.baseURL+"/rest/api/3/issue/"+ticketID+"/comment", bytes.NewReader(data))
	if err != nil {
		return err
	}

	j.setHeaders(req)

	resp, err := j.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("jira API error %d", resp.StatusCode)
	}

	return nil
}

func (j *JiraProvider) Close(ctx context.Context, id string, resolution string) error {
	// Get available transitions
	req, err := http.NewRequestWithContext(ctx, "GET", j.baseURL+"/rest/api/3/issue/"+id+"/transitions", nil)
	if err != nil {
		return err
	}
	j.setHeaders(req)

	resp, err := j.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var transitions struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"transitions"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&transitions); decErr != nil {
		return decErr
	}

	// Find "Done" or "Closed" transition
	var transitionID string
	for _, t := range transitions.Transitions {
		if t.Name == "Done" || t.Name == "Closed" || t.Name == "Resolve Issue" {
			transitionID = t.ID
			break
		}
	}

	if transitionID == "" {
		return fmt.Errorf("no close transition found")
	}

	// Execute transition
	body := map[string]interface{}{
		"transition": map[string]string{"id": transitionID},
	}
	data, _ := json.Marshal(body)

	req, err = http.NewRequestWithContext(ctx, "POST", j.baseURL+"/rest/api/3/issue/"+id+"/transitions", bytes.NewReader(data))
	if err != nil {
		return err
	}
	j.setHeaders(req)

	resp, err = j.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jira API error %d", resp.StatusCode)
	}

	return nil
}

func (j *JiraProvider) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(j.email, j.apiToken)
}

func (j *JiraProvider) issueType(t string) string {
	switch t {
	case "incident":
		return "Bug"
	case "finding":
		return "Task"
	default:
		return "Task"
	}
}

func (j *JiraProvider) priorityName(p string) string {
	switch p {
	case "critical":
		return "Highest"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Medium"
	}
}

func (j *JiraProvider) convertIssue(issue *jiraIssue) *Ticket {
	ticket := &Ticket{
		ID:          issue.ID,
		ExternalID:  issue.Key,
		Title:       issue.Fields.Summary,
		Status:      issue.Fields.Status.Name,
		Labels:      issue.Fields.Labels,
		ExternalURL: fmt.Sprintf("%s/browse/%s", j.baseURL, issue.Key),
	}

	if issue.Fields.Assignee != nil {
		ticket.Assignee = issue.Fields.Assignee.DisplayName
	}
	ticket.Reporter = issue.Fields.Reporter.DisplayName

	return ticket
}
