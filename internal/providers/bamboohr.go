package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	bambooHRDefaultPageSize = 200
	bambooHRMaxPages        = 500
)

// BambooHRProvider syncs BambooHR employee and organization metadata.
type BambooHRProvider struct {
	*BaseProvider
	baseURL string
	token   string
	client  *http.Client
}

func NewBambooHRProvider() *BambooHRProvider {
	return &BambooHRProvider{
		BaseProvider: NewBaseProvider("bamboohr", ProviderTypeSaaS),
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (b *BambooHRProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := b.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	b.baseURL = strings.TrimSpace(b.GetConfigString("url"))
	if b.baseURL == "" {
		b.baseURL = strings.TrimSpace(b.GetConfigString("base_url"))
	}
	if b.baseURL == "" {
		b.baseURL = strings.TrimSpace(b.GetConfigString("instance_url"))
	}
	b.baseURL = strings.TrimSuffix(b.baseURL, "/")
	if b.baseURL == "" {
		return fmt.Errorf("bamboohr url required")
	}
	if !strings.Contains(strings.ToLower(b.baseURL), "/v1") {
		b.baseURL += "/v1"
	}

	b.token = strings.TrimSpace(b.GetConfigString("token"))
	if b.token == "" {
		b.token = strings.TrimSpace(b.GetConfigString("api_token"))
	}
	if b.token == "" {
		b.token = strings.TrimSpace(b.GetConfigString("api_key"))
	}
	if b.token == "" {
		return fmt.Errorf("bamboohr token required")
	}

	if err := validateBambooHRURL(b.baseURL); err != nil {
		return err
	}

	return nil
}

func (b *BambooHRProvider) Test(ctx context.Context) error {
	_, err := b.request(ctx, addQueryParams("/employees/directory", map[string]string{
		"page":  "1",
		"limit": "1",
	}))
	return err
}

func (b *BambooHRProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "bamboohr_employees",
			Description: "BambooHR employee directory records",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "employee_number", Type: "string"},
				{Name: "first_name", Type: "string"},
				{Name: "last_name", Type: "string"},
				{Name: "display_name", Type: "string"},
				{Name: "work_email", Type: "string"},
				{Name: "department", Type: "string"},
				{Name: "location", Type: "string"},
				{Name: "job_title", Type: "string"},
				{Name: "manager_id", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "hire_date", Type: "timestamp"},
				{Name: "terminated_date", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "bamboohr_departments",
			Description: "BambooHR departments",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "parent_id", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "bamboohr_locations",
			Description: "BambooHR locations",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "city", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "country", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (b *BambooHRProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(b.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (b *BambooHRProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  b.Name(),
		StartedAt: start,
	}

	syncTable := func(name string, fn func(context.Context) (*TableResult, error)) {
		table, err := fn(ctx)
		if err != nil {
			result.Errors = append(result.Errors, name+": "+err.Error())
			return
		}
		result.Tables = append(result.Tables, *table)
		result.TotalRows += table.Rows
	}

	syncTable("employees", b.syncEmployees)
	syncTable("departments", b.syncDepartments)
	syncTable("locations", b.syncLocations)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (b *BambooHRProvider) syncEmployees(ctx context.Context) (*TableResult, error) {
	schema, err := b.schemaFor("bamboohr_employees")
	result := &TableResult{Name: "bamboohr_employees"}
	if err != nil {
		return result, err
	}

	employees, err := b.listEmployees(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(employees))
	for _, employee := range employees {
		normalized := normalizeBambooHRRow(employee)

		employeeID := firstBambooHRString(normalized, "id", "employee_id")
		if employeeID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":              employeeID,
			"employee_number": firstBambooHRValue(normalized, "employee_number", "employee_no", "employee_num"),
			"first_name":      firstBambooHRValue(normalized, "first_name", "firstname"),
			"last_name":       firstBambooHRValue(normalized, "last_name", "lastname"),
			"display_name":    firstBambooHRValue(normalized, "display_name", "preferred_name", "name"),
			"work_email":      firstBambooHRValue(normalized, "work_email", "email", "work_email_address"),
			"department":      firstBambooHRValue(normalized, "department", "department_name"),
			"location":        firstBambooHRValue(normalized, "location", "location_name"),
			"job_title":       firstBambooHRValue(normalized, "job_title", "title"),
			"manager_id":      firstBambooHRValue(normalized, "supervisor_e_id", "manager_id", "supervisor_id", "reports_to"),
			"status":          firstBambooHRValue(normalized, "status", "employment_status"),
			"hire_date":       firstBambooHRValue(normalized, "hire_date", "date_hired"),
			"terminated_date": firstBambooHRValue(normalized, "termination_date", "date_terminated"),
			"updated_at":      firstBambooHRValue(normalized, "last_changed", "last_changed_date", "updated_at"),
		})
	}

	return b.syncTable(ctx, schema, rows)
}

func (b *BambooHRProvider) syncDepartments(ctx context.Context) (*TableResult, error) {
	schema, err := b.schemaFor("bamboohr_departments")
	result := &TableResult{Name: "bamboohr_departments"}
	if err != nil {
		return result, err
	}

	departments, err := b.listMetaCollection(ctx, "/meta/departments", "departments")
	if err != nil {
		if isBambooHRIgnorableError(err) {
			return b.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(departments))
	for _, department := range departments {
		normalized := normalizeBambooHRRow(department)

		departmentID := firstBambooHRString(normalized, "id", "department_id", "value")
		if departmentID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":        departmentID,
			"name":      firstBambooHRValue(normalized, "name", "label"),
			"parent_id": firstBambooHRValue(normalized, "parent_id", "parent_department_id", "parent"),
		})
	}

	return b.syncTable(ctx, schema, rows)
}

func (b *BambooHRProvider) syncLocations(ctx context.Context) (*TableResult, error) {
	schema, err := b.schemaFor("bamboohr_locations")
	result := &TableResult{Name: "bamboohr_locations"}
	if err != nil {
		return result, err
	}

	locations, err := b.listMetaCollection(ctx, "/meta/locations", "locations")
	if err != nil {
		if isBambooHRIgnorableError(err) {
			return b.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(locations))
	for _, location := range locations {
		normalized := normalizeBambooHRRow(location)

		locationID := firstBambooHRString(normalized, "id", "location_id", "value")
		if locationID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":      locationID,
			"name":    firstBambooHRValue(normalized, "name", "label"),
			"city":    firstBambooHRValue(normalized, "city"),
			"state":   firstBambooHRValue(normalized, "state", "province"),
			"country": firstBambooHRValue(normalized, "country"),
		})
	}

	return b.syncTable(ctx, schema, rows)
}

func (b *BambooHRProvider) listEmployees(ctx context.Context) ([]map[string]interface{}, error) {
	rows := make([]map[string]interface{}, 0)
	seenPageSignatures := make(map[string]struct{})

	for page := 1; page <= bambooHRMaxPages; page++ {
		requestPath := addQueryParams("/employees/directory", map[string]string{
			"page":  strconv.Itoa(page),
			"limit": strconv.Itoa(bambooHRDefaultPageSize),
		})

		body, err := b.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}

		employees := bambooHRExtractCollection(normalizeBambooHRRow(payload), "employees", "data", "result", "results", "items")
		if len(employees) == 0 {
			break
		}

		firstID := firstBambooHRString(normalizeBambooHRRow(employees[0]), "id", "employee_id", "employee_number")
		signature := fmt.Sprintf("%s:%d", firstID, len(employees))
		if _, exists := seenPageSignatures[signature]; exists {
			return nil, fmt.Errorf("bamboohr pagination loop detected for employees")
		}
		seenPageSignatures[signature] = struct{}{}

		for _, employee := range employees {
			rows = append(rows, normalizeBambooHRRow(employee))
		}

		if len(employees) < bambooHRDefaultPageSize {
			break
		}
	}

	return rows, nil
}

func (b *BambooHRProvider) listMetaCollection(ctx context.Context, path string, keys ...string) ([]map[string]interface{}, error) {
	body, err := b.request(ctx, path)
	if err != nil {
		return nil, err
	}

	var payload interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	normalized := normalizeMapKeys(payload)
	switch typed := normalized.(type) {
	case map[string]interface{}:
		searchKeys := append(append([]string{}, keys...), "data", "result", "results", "items")
		return bambooHRExtractCollection(typed, searchKeys...), nil
	case []interface{}:
		return bambooHRMapSlice(typed), nil
	default:
		return nil, nil
	}
}

func (b *BambooHRProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL, err := bambooHRResolveRequestURL(b.baseURL, path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(b.token, "x")
	req.Header.Set("Accept", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("bamboohr API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func bambooHRResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("bamboohr request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid bamboohr URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid bamboohr base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) || !strings.EqualFold(baseParsed.Host, resolved.Host) {
			return "", fmt.Errorf("bamboohr request URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func validateBambooHRURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid bamboohr url %q", rawURL)
	}
	return nil
}

func normalizeBambooHRRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func bambooHRMapSlice(value interface{}) []map[string]interface{} {
	switch typed := value.(type) {
	case []map[string]interface{}:
		return typed
	case []interface{}:
		rows := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			if normalized, ok := normalizeMapKeys(item).(map[string]interface{}); ok {
				rows = append(rows, normalized)
			}
		}
		return rows
	default:
		return nil
	}
}

func bambooHRExtractCollection(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if rows := bambooHRMapSlice(payload[key]); len(rows) > 0 {
			return rows
		}
		if rows := bambooHRIDNameMapToSlice(payload[key]); len(rows) > 0 {
			return rows
		}
	}

	if rows := bambooHRMapSlice(payload["employees"]); len(rows) > 0 {
		return rows
	}
	if rows := bambooHRMapSlice(payload["departments"]); len(rows) > 0 {
		return rows
	}
	if rows := bambooHRMapSlice(payload["locations"]); len(rows) > 0 {
		return rows
	}

	if firstBambooHRString(payload, "id", "employee_id", "department_id", "location_id") != "" {
		return []map[string]interface{}{payload}
	}

	return nil
}

func bambooHRIDNameMapToSlice(value interface{}) []map[string]interface{} {
	mapped, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}

	rows := make([]map[string]interface{}, 0, len(mapped))
	for key, val := range mapped {
		if row, ok := normalizeMapKeys(val).(map[string]interface{}); ok {
			if _, present := row["id"]; !present {
				row["id"] = key
			}
			rows = append(rows, row)
			continue
		}

		text := strings.TrimSpace(providerStringValue(val))
		if text == "" {
			continue
		}
		rows = append(rows, map[string]interface{}{
			"id":   key,
			"name": text,
		})
	}

	return rows
}

func firstBambooHRString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := row[key]
		if !ok {
			continue
		}
		if text := strings.TrimSpace(providerStringValue(value)); text != "" {
			return text
		}
	}
	return ""
}

func firstBambooHRValue(row map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		value, ok := row[key]
		if !ok || value == nil {
			continue
		}
		if strings.TrimSpace(providerStringValue(value)) == "" {
			continue
		}
		return value
	}
	return nil
}

func isBambooHRIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}
