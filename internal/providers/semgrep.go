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
	semgrepDefaultAPIURL = "https://semgrep.dev/api/v1"
	semgrepPageSize      = 100
	semgrepMaxPages      = 500
)

// SemgrepProvider syncs Semgrep deployment, project, and finding metadata.
type SemgrepProvider struct {
	*BaseProvider
	token          string
	baseURL        string
	deploymentSlug string
	client         *http.Client
}

func NewSemgrepProvider() *SemgrepProvider {
	return &SemgrepProvider{
		BaseProvider: NewBaseProvider("semgrep", ProviderTypeSaaS),
		baseURL:      semgrepDefaultAPIURL,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *SemgrepProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := s.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	s.token = strings.TrimSpace(s.GetConfigString("token"))
	if s.token == "" {
		s.token = strings.TrimSpace(s.GetConfigString("api_token"))
	}
	if s.token == "" {
		return fmt.Errorf("semgrep token required")
	}

	if baseURL := strings.TrimSpace(s.GetConfigString("base_url")); baseURL != "" {
		s.baseURL = strings.TrimSuffix(baseURL, "/")
		if !strings.Contains(strings.ToLower(s.baseURL), "/api/") {
			s.baseURL = strings.TrimSuffix(s.baseURL, "/") + "/api/v1"
		}
	}
	if err := validateSemgrepURL(s.baseURL); err != nil {
		return err
	}

	s.deploymentSlug = strings.TrimSpace(s.GetConfigString("deployment"))
	return nil
}

func (s *SemgrepProvider) Test(ctx context.Context) error {
	_, err := s.request(ctx, addQueryParams("/deployments", map[string]string{"page": "0", "page_size": "1"}))
	return err
}

func (s *SemgrepProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "semgrep_deployments",
			Description: "Semgrep deployments",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "slug", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "findings_url", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "semgrep_projects",
			Description: "Semgrep projects",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "deployment_slug", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "repository", Type: "string"},
				{Name: "branch", Type: "string"},
				{Name: "last_scan_at", Type: "timestamp"},
				{Name: "archived", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "semgrep_findings",
			Description: "Semgrep findings",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "deployment_slug", Type: "string"},
				{Name: "project_id", Type: "string"},
				{Name: "project_name", Type: "string"},
				{Name: "rule_id", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "confidence", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "triage_state", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "path", Type: "string"},
				{Name: "line", Type: "integer"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (s *SemgrepProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(s.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (s *SemgrepProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  s.Name(),
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

	syncTable("deployments", s.syncDeployments)
	syncTable("projects", s.syncProjects)
	syncTable("findings", s.syncFindings)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (s *SemgrepProvider) syncDeployments(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("semgrep_deployments")
	result := &TableResult{Name: "semgrep_deployments"}
	if err != nil {
		return result, err
	}

	deployments, err := s.listDeployments(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(deployments))
	for _, deployment := range deployments {
		normalized := normalizeSemgrepRow(deployment)
		findings := semgrepMap(normalized["findings"])

		deploymentID := firstSemgrepString(normalized, "id", "slug", "name")
		if deploymentID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":           deploymentID,
			"slug":         firstSemgrepValue(normalized, "slug"),
			"name":         firstSemgrepValue(normalized, "name"),
			"findings_url": firstSemgrepValue(findings, "url"),
		})
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SemgrepProvider) syncProjects(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("semgrep_projects")
	result := &TableResult{Name: "semgrep_projects"}
	if err != nil {
		return result, err
	}

	deployments, err := s.listDeployments(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	for _, deployment := range deployments {
		normalizedDeployment := normalizeSemgrepRow(deployment)
		deploymentSlug := firstSemgrepString(normalizedDeployment, "slug", "id")
		if deploymentSlug == "" {
			continue
		}

		projects, err := s.listProjectsForDeployment(ctx, deploymentSlug)
		if err != nil {
			if isSemgrepIgnorableError(err) {
				continue
			}
			return result, err
		}

		for _, project := range projects {
			normalizedProject := normalizeSemgrepRow(project)
			repository := semgrepMap(normalizedProject["repository"])

			projectID := firstSemgrepString(normalizedProject, "id", "slug", "name")
			if projectID == "" {
				continue
			}

			rows = append(rows, map[string]interface{}{
				"id":              projectID,
				"deployment_slug": deploymentSlug,
				"name":            firstSemgrepValue(normalizedProject, "name", "project_name"),
				"repository": firstNonNilSemgrepValue(
					firstSemgrepValue(normalizedProject, "repository_name", "repo_name", "repository_url", "url"),
					firstSemgrepValue(repository, "name", "url"),
				),
				"branch": firstSemgrepValue(normalizedProject, "branch", "default_branch", "ref"),
				"last_scan_at": firstSemgrepValue(
					normalizedProject,
					"last_scan_at",
					"last_scanned_at",
					"last_seen_at",
					"updated_at",
				),
				"archived": firstSemgrepValue(normalizedProject, "archived", "is_archived"),
			})
		}
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SemgrepProvider) syncFindings(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("semgrep_findings")
	result := &TableResult{Name: "semgrep_findings"}
	if err != nil {
		return result, err
	}

	deployments, err := s.listDeployments(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	for _, deployment := range deployments {
		normalizedDeployment := normalizeSemgrepRow(deployment)
		deploymentSlug := firstSemgrepString(normalizedDeployment, "slug", "id")
		if deploymentSlug == "" {
			continue
		}

		findings, err := s.listFindingsForDeployment(ctx, deploymentSlug)
		if err != nil {
			if isSemgrepIgnorableError(err) {
				continue
			}
			return result, err
		}

		for _, finding := range findings {
			normalizedFinding := normalizeSemgrepRow(finding)
			project := semgrepMap(normalizedFinding["project"])
			rule := semgrepMap(normalizedFinding["rule"])
			location := semgrepMap(normalizedFinding["location"])

			findingID := firstSemgrepString(normalizedFinding, "id", "finding_id", "uuid", "match_based_id")
			if findingID == "" {
				continue
			}

			rows = append(rows, map[string]interface{}{
				"id":              findingID,
				"deployment_slug": deploymentSlug,
				"project_id": firstNonNilSemgrepValue(
					firstSemgrepValue(normalizedFinding, "project_id"),
					firstSemgrepValue(project, "id"),
				),
				"project_name": firstNonNilSemgrepValue(
					firstSemgrepValue(normalizedFinding, "project_name"),
					firstSemgrepValue(project, "name", "slug"),
				),
				"rule_id": firstNonNilSemgrepValue(
					firstSemgrepValue(normalizedFinding, "rule_id", "check_id"),
					firstSemgrepValue(rule, "id", "rule_id", "check_id"),
				),
				"severity": firstNonNilSemgrepValue(
					firstSemgrepValue(normalizedFinding, "severity"),
					firstSemgrepValue(rule, "severity"),
				),
				"confidence": firstSemgrepValue(normalizedFinding, "confidence"),
				"state":      firstSemgrepValue(normalizedFinding, "state", "status"),
				"triage_state": firstSemgrepValue(
					normalizedFinding,
					"triage_state",
					"triage_status",
				),
				"title": firstNonNilSemgrepValue(
					firstSemgrepValue(normalizedFinding, "title", "message", "description"),
					firstSemgrepValue(rule, "name", "message"),
				),
				"path": firstNonNilSemgrepValue(
					firstSemgrepValue(normalizedFinding, "path", "file_path"),
					firstSemgrepValue(location, "path", "file_path"),
				),
				"line": firstNonNilSemgrepValue(
					firstSemgrepValue(normalizedFinding, "line"),
					firstSemgrepValue(location, "start_line", "line"),
				),
				"created_at": firstSemgrepValue(normalizedFinding, "created_at", "found_at", "first_seen_at"),
				"updated_at": firstSemgrepValue(normalizedFinding, "updated_at", "last_seen_at", "triaged_at"),
			})
		}
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SemgrepProvider) listDeployments(ctx context.Context) ([]map[string]interface{}, error) {
	path := "/deployments"
	if s.deploymentSlug != "" {
		path = "/deployments/" + url.PathEscape(s.deploymentSlug)
	}

	items, err := s.listCollection(ctx, path, "deployments", "deployment", "data", "results")
	if err != nil {
		return nil, err
	}

	if len(items) == 0 && s.deploymentSlug != "" {
		body, err := s.request(ctx, path)
		if err != nil {
			return nil, err
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}
		normalized := normalizeSemgrepRow(payload)
		if len(normalized) > 0 {
			items = append(items, normalized)
		}
	}

	return items, nil
}

func (s *SemgrepProvider) listProjectsForDeployment(ctx context.Context, deploymentSlug string) ([]map[string]interface{}, error) {
	candidatePaths := []string{
		"/deployments/" + url.PathEscape(deploymentSlug) + "/projects",
		"/deployments/" + url.PathEscape(deploymentSlug) + "/repos",
		"/deployments/" + url.PathEscape(deploymentSlug) + "/repositories",
	}

	var lastErr error
	for _, path := range candidatePaths {
		items, err := s.listCollection(ctx, path, "projects", "repos", "repositories", "data", "results")
		if err == nil {
			return items, nil
		}
		lastErr = err
		if !isSemgrepIgnorableError(err) {
			return nil, err
		}
	}

	if lastErr == nil {
		return nil, nil
	}
	return nil, lastErr
}

func (s *SemgrepProvider) listFindingsForDeployment(ctx context.Context, deploymentSlug string) ([]map[string]interface{}, error) {
	basePath := "/deployments/" + url.PathEscape(deploymentSlug) + "/findings"
	rows := make([]map[string]interface{}, 0)

	for page := 0; page < semgrepMaxPages; page++ {
		requestPath := addQueryParams(basePath, map[string]string{
			"page":      strconv.Itoa(page),
			"page_size": strconv.Itoa(semgrepPageSize),
		})

		body, err := s.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}

		normalized := normalizeSemgrepRow(payload)
		items := semgrepExtractItems(normalized, "findings", "results", "data")
		for _, item := range items {
			rows = append(rows, normalizeSemgrepRow(item))
		}

		if len(items) < semgrepPageSize {
			break
		}
	}

	return rows, nil
}

func (s *SemgrepProvider) listCollection(ctx context.Context, path string, itemKeys ...string) ([]map[string]interface{}, error) {
	body, err := s.request(ctx, path)
	if err != nil {
		return nil, err
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	normalized := normalizeSemgrepRow(payload)
	items := semgrepExtractItems(normalized, itemKeys...)
	rows := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		rows = append(rows, normalizeSemgrepRow(item))
	}
	return rows, nil
}

func (s *SemgrepProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL, err := semgrepResolveRequestURL(s.baseURL, path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("semgrep API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func semgrepResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("semgrep request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid semgrep URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid semgrep base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) || !strings.EqualFold(baseParsed.Host, resolved.Host) {
			return "", fmt.Errorf("semgrep request URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func validateSemgrepURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid semgrep base_url %q", rawURL)
	}
	return nil
}

func normalizeSemgrepRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func semgrepMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func semgrepMapSlice(value interface{}) []map[string]interface{} {
	switch typed := value.(type) {
	case []map[string]interface{}:
		return typed
	case []interface{}:
		rows := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			if m, ok := normalizeMapKeys(item).(map[string]interface{}); ok {
				rows = append(rows, m)
			}
		}
		return rows
	default:
		return nil
	}
}

func semgrepExtractItems(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if items := semgrepMapSlice(payload[key]); len(items) > 0 {
			return items
		}

		nested := semgrepMap(payload[key])
		if len(nested) > 0 {
			if items := semgrepMapSlice(nested["items"]); len(items) > 0 {
				return items
			}
			if items := semgrepMapSlice(nested["data"]); len(items) > 0 {
				return items
			}
		}
	}
	return nil
}

func firstSemgrepString(row map[string]interface{}, keys ...string) string {
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

func firstSemgrepValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilSemgrepValue(values ...interface{}) interface{} {
	for _, value := range values {
		if value == nil {
			continue
		}
		if strings.TrimSpace(providerStringValue(value)) == "" {
			continue
		}
		return value
	}
	return nil
}

func isSemgrepIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}
