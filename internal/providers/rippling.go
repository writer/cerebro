package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RipplingProvider syncs HR data from Rippling HRIS
type RipplingProvider struct {
	*BaseProvider
	apiURL   string
	apiToken string
	client   *http.Client
}

func NewRipplingProvider() *RipplingProvider {
	return &RipplingProvider{
		BaseProvider: NewBaseProvider("rippling", ProviderTypeIdentity),
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (r *RipplingProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := r.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	r.apiURL = r.GetConfigString("api_url")
	if r.apiURL == "" {
		r.apiURL = "https://api.rippling.com"
	}

	r.apiToken = r.GetConfigString("api_token")
	if r.apiToken == "" {
		return fmt.Errorf("rippling api_token required")
	}

	return nil
}

func (r *RipplingProvider) Test(ctx context.Context) error {
	_, err := r.request(ctx, "/platform/api/employees?limit=1")
	return err
}

func (r *RipplingProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "rippling_employees",
			Description: "Rippling employee records",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "work_email", Type: "string"},
				{Name: "personal_email", Type: "string"},
				{Name: "first_name", Type: "string"},
				{Name: "last_name", Type: "string"},
				{Name: "display_name", Type: "string"},
				{Name: "employment_type", Type: "string"},
				{Name: "employment_status", Type: "string"},
				{Name: "start_date", Type: "date"},
				{Name: "end_date", Type: "date"},
				{Name: "termination_date", Type: "date"},
				{Name: "department", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "manager_id", Type: "string"},
				{Name: "location", Type: "string"},
				{Name: "is_active", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "rippling_departments",
			Description: "Rippling departments",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "parent_id", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "rippling_terminations",
			Description: "Rippling employee terminations",
			Columns: []ColumnSchema{
				{Name: "employee_id", Type: "string", Required: true},
				{Name: "termination_date", Type: "date", Required: true},
				{Name: "termination_reason", Type: "string"},
				{Name: "last_work_day", Type: "date"},
				{Name: "is_voluntary", Type: "boolean"},
				{Name: "offboarding_status", Type: "string"},
			},
			PrimaryKey: []string{"employee_id"},
		},
		{
			Name:        "rippling_groups",
			Description: "Rippling groups/teams",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "member_count", Type: "integer"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (r *RipplingProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  r.Name(),
		StartedAt: start,
	}

	// Sync employees
	employees, err := r.syncEmployees(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "employees: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *employees)
		result.TotalRows += employees.Rows
	}

	// Sync departments
	departments, err := r.syncDepartments(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "departments: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *departments)
		result.TotalRows += departments.Rows
	}

	// Sync terminations (recent)
	terminations, err := r.syncTerminations(ctx, opts)
	if err != nil {
		result.Errors = append(result.Errors, "terminations: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *terminations)
		result.TotalRows += terminations.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (r *RipplingProvider) syncEmployees(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "rippling_employees"}

	employees, err := r.listAll(ctx, "/platform/api/employees")
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(employees))
	result.Inserted = result.Rows
	return result, nil
}

func (r *RipplingProvider) syncDepartments(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "rippling_departments"}

	body, err := r.request(ctx, "/platform/api/departments")
	if err != nil {
		return result, err
	}

	var departments []map[string]interface{}
	if err := json.Unmarshal(body, &departments); err != nil {
		return result, err
	}

	result.Rows = int64(len(departments))
	result.Inserted = result.Rows
	return result, nil
}

func (r *RipplingProvider) syncTerminations(ctx context.Context, opts SyncOptions) (*TableResult, error) {
	result := &TableResult{Name: "rippling_terminations"}

	// Filter for terminated employees in the last 90 days by default
	employees, err := r.listAll(ctx, "/platform/api/employees?employment_status=TERMINATED")
	if err != nil {
		return result, err
	}

	// Filter to recent terminations
	var terminations []map[string]interface{}
	cutoff := time.Now().AddDate(0, 0, -90)
	for _, emp := range employees {
		if termDate, ok := emp["termination_date"].(string); ok {
			t, err := time.Parse("2006-01-02", termDate)
			if err == nil && t.After(cutoff) {
				terminations = append(terminations, emp)
			}
		}
	}

	result.Rows = int64(len(terminations))
	result.Inserted = result.Rows
	return result, nil
}

func (r *RipplingProvider) listAll(ctx context.Context, path string) ([]map[string]interface{}, error) {
	var allItems []map[string]interface{}
	cursor := ""

	for {
		url := path
		if cursor != "" {
			url += "&cursor=" + cursor
		}
		if !contains(url, "?") {
			url = path + "?limit=100"
		} else {
			url += "&limit=100"
		}

		body, err := r.request(ctx, url)
		if err != nil {
			return nil, err
		}

		var resp struct {
			Data       []map[string]interface{} `json:"data"`
			NextCursor string                   `json:"next_cursor"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			// Try direct array response
			var items []map[string]interface{}
			if err := json.Unmarshal(body, &items); err != nil {
				return nil, fmt.Errorf("parse response: %w", err)
			}
			return items, nil
		}

		allItems = append(allItems, resp.Data...)

		if resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
	}

	return allItems, nil
}

func (r *RipplingProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := r.apiURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+r.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("rippling API error %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// GetTerminatedEmployees returns employees terminated within the specified days
func (r *RipplingProvider) GetTerminatedEmployees(employees []map[string]interface{}, withinDays int) []map[string]interface{} {
	cutoff := time.Now().AddDate(0, 0, -withinDays)
	var terminated []map[string]interface{}

	for _, emp := range employees {
		status, _ := emp["employment_status"].(string)
		if status != "TERMINATED" {
			continue
		}

		if termDate, ok := emp["termination_date"].(string); ok {
			t, err := time.Parse("2006-01-02", termDate)
			if err == nil && t.After(cutoff) {
				terminated = append(terminated, emp)
			}
		}
	}

	return terminated
}
