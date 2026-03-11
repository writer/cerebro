package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const terraformCloudDefaultAPIURL = "https://app.terraform.io/api/v2"

// TerraformCloudProvider syncs Terraform Cloud organization, workspace, and run metadata.
type TerraformCloudProvider struct {
	*BaseProvider
	token   string
	baseURL string
	client  *http.Client
}

func NewTerraformCloudProvider() *TerraformCloudProvider {
	return &TerraformCloudProvider{
		BaseProvider: NewBaseProvider("terraform_cloud", ProviderTypeSaaS),
		baseURL:      terraformCloudDefaultAPIURL,
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (t *TerraformCloudProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := t.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	t.token = strings.TrimSpace(t.GetConfigString("token"))
	if t.token == "" {
		t.token = strings.TrimSpace(t.GetConfigString("api_token"))
	}
	if t.token == "" {
		return fmt.Errorf("terraform_cloud token required")
	}

	if baseURL := strings.TrimSpace(t.GetConfigString("base_url")); baseURL != "" {
		t.baseURL = strings.TrimSuffix(baseURL, "/")
	}
	if err := validateTerraformCloudURL(t.baseURL); err != nil {
		return err
	}

	return nil
}

func (t *TerraformCloudProvider) Test(ctx context.Context) error {
	_, err := t.request(ctx, addQueryParams("/organizations", map[string]string{"page[size]": "1"}))
	return err
}

func (t *TerraformCloudProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "terraform_cloud_organizations",
			Description: "Terraform Cloud organizations",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "external_id", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "terraform_cloud_workspaces",
			Description: "Terraform Cloud workspaces",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "organization_name", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "terraform_version", Type: "string"},
				{Name: "execution_mode", Type: "string"},
				{Name: "auto_apply", Type: "boolean"},
				{Name: "locked", Type: "boolean"},
				{Name: "resource_count", Type: "integer"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "terraform_cloud_runs",
			Description: "Terraform Cloud runs",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "workspace_id", Type: "string"},
				{Name: "organization_name", Type: "string"},
				{Name: "workspace_name", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "message", Type: "string"},
				{Name: "is_destroy", Type: "boolean"},
				{Name: "trigger_reason", Type: "string"},
				{Name: "source", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (t *TerraformCloudProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(t.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (t *TerraformCloudProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  t.Name(),
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

	syncTable("organizations", t.syncOrganizations)
	syncTable("workspaces", t.syncWorkspaces)
	syncTable("runs", t.syncRuns)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (t *TerraformCloudProvider) syncOrganizations(ctx context.Context) (*TableResult, error) {
	schema, err := t.schemaFor("terraform_cloud_organizations")
	result := &TableResult{Name: "terraform_cloud_organizations"}
	if err != nil {
		return result, err
	}

	organizations, err := t.listOrganizations(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(organizations))
	for _, org := range organizations {
		normalized := normalizeTerraformCloudRow(org)
		attrs := terraformCloudMap(normalized["attributes"])

		orgID := firstTerraformCloudString(normalized, "id")
		orgName := firstTerraformCloudString(attrs, "name")
		if orgID == "" {
			orgID = orgName
		}
		if orgID == "" {
			continue
		}
		if orgName == "" {
			orgName = orgID
		}

		rows = append(rows, map[string]interface{}{
			"id":          orgID,
			"name":        orgName,
			"email":       firstTerraformCloudValue(attrs, "email"),
			"external_id": firstTerraformCloudValue(attrs, "external_id"),
			"created_at":  firstTerraformCloudValue(attrs, "created_at"),
		})
	}

	return t.syncTable(ctx, schema, rows)
}

func (t *TerraformCloudProvider) syncWorkspaces(ctx context.Context) (*TableResult, error) {
	schema, err := t.schemaFor("terraform_cloud_workspaces")
	result := &TableResult{Name: "terraform_cloud_workspaces"}
	if err != nil {
		return result, err
	}

	organizations, err := t.listOrganizations(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	for _, org := range organizations {
		normalizedOrg := normalizeTerraformCloudRow(org)
		orgAttrs := terraformCloudMap(normalizedOrg["attributes"])
		organizationName := firstTerraformCloudString(orgAttrs, "name")
		if organizationName == "" {
			organizationName = firstTerraformCloudString(normalizedOrg, "id")
		}
		if organizationName == "" {
			continue
		}

		workspaces, err := t.listWorkspacesForOrganization(ctx, organizationName)
		if err != nil {
			if isTerraformCloudIgnorableError(err) {
				continue
			}
			return result, err
		}

		for _, workspace := range workspaces {
			normalizedWorkspace := normalizeTerraformCloudRow(workspace)
			workspaceAttrs := terraformCloudMap(normalizedWorkspace["attributes"])

			workspaceID := firstTerraformCloudString(normalizedWorkspace, "id")
			if workspaceID == "" {
				continue
			}

			workspaceName := firstTerraformCloudString(workspaceAttrs, "name")
			if workspaceName == "" {
				workspaceName = workspaceID
			}

			rows = append(rows, map[string]interface{}{
				"id":                workspaceID,
				"organization_name": organizationName,
				"name":              workspaceName,
				"terraform_version": firstTerraformCloudValue(workspaceAttrs, "terraform_version"),
				"execution_mode":    firstTerraformCloudValue(workspaceAttrs, "execution_mode"),
				"auto_apply":        firstTerraformCloudValue(workspaceAttrs, "auto_apply"),
				"locked":            firstTerraformCloudValue(workspaceAttrs, "locked"),
				"resource_count":    firstTerraformCloudValue(workspaceAttrs, "resource_count"),
				"created_at":        firstTerraformCloudValue(workspaceAttrs, "created_at"),
				"updated_at":        firstTerraformCloudValue(workspaceAttrs, "updated_at"),
			})
		}
	}

	return t.syncTable(ctx, schema, rows)
}

func (t *TerraformCloudProvider) syncRuns(ctx context.Context) (*TableResult, error) {
	schema, err := t.schemaFor("terraform_cloud_runs")
	result := &TableResult{Name: "terraform_cloud_runs"}
	if err != nil {
		return result, err
	}

	organizations, err := t.listOrganizations(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	for _, org := range organizations {
		normalizedOrg := normalizeTerraformCloudRow(org)
		orgAttrs := terraformCloudMap(normalizedOrg["attributes"])
		organizationName := firstTerraformCloudString(orgAttrs, "name")
		if organizationName == "" {
			organizationName = firstTerraformCloudString(normalizedOrg, "id")
		}
		if organizationName == "" {
			continue
		}

		workspaces, err := t.listWorkspacesForOrganization(ctx, organizationName)
		if err != nil {
			if isTerraformCloudIgnorableError(err) {
				continue
			}
			return result, err
		}

		for _, workspace := range workspaces {
			normalizedWorkspace := normalizeTerraformCloudRow(workspace)
			workspaceAttrs := terraformCloudMap(normalizedWorkspace["attributes"])
			workspaceID := firstTerraformCloudString(normalizedWorkspace, "id")
			if workspaceID == "" {
				continue
			}
			workspaceName := firstTerraformCloudString(workspaceAttrs, "name")
			if workspaceName == "" {
				workspaceName = workspaceID
			}

			runs, err := t.listRunsForWorkspace(ctx, workspaceID)
			if err != nil {
				if isTerraformCloudIgnorableError(err) {
					continue
				}
				return result, err
			}

			for _, run := range runs {
				normalizedRun := normalizeTerraformCloudRow(run)
				runAttrs := terraformCloudMap(normalizedRun["attributes"])

				runID := firstTerraformCloudString(normalizedRun, "id")
				if runID == "" {
					continue
				}

				runWorkspaceID := workspaceID
				if runWorkspaceID == "" {
					relationships := terraformCloudMap(normalizedRun["relationships"])
					workspaceRelationship := terraformCloudMap(relationships["workspace"])
					workspaceData := terraformCloudMap(workspaceRelationship["data"])
					runWorkspaceID = firstTerraformCloudString(workspaceData, "id")
				}

				rows = append(rows, map[string]interface{}{
					"id":                runID,
					"workspace_id":      runWorkspaceID,
					"organization_name": organizationName,
					"workspace_name":    workspaceName,
					"status":            firstTerraformCloudValue(runAttrs, "status"),
					"message":           firstTerraformCloudValue(runAttrs, "message"),
					"is_destroy":        firstTerraformCloudValue(runAttrs, "is_destroy", "is_destroy_run"),
					"trigger_reason":    firstTerraformCloudValue(runAttrs, "trigger_reason"),
					"source":            firstTerraformCloudValue(runAttrs, "source"),
					"created_at":        firstTerraformCloudValue(runAttrs, "created_at"),
				})
			}
		}
	}

	return t.syncTable(ctx, schema, rows)
}

func (t *TerraformCloudProvider) listOrganizations(ctx context.Context) ([]map[string]interface{}, error) {
	return t.listCollection(ctx, "/organizations")
}

func (t *TerraformCloudProvider) listWorkspacesForOrganization(ctx context.Context, organization string) ([]map[string]interface{}, error) {
	path := "/organizations/" + url.PathEscape(organization) + "/workspaces"
	return t.listCollection(ctx, path)
}

func (t *TerraformCloudProvider) listRunsForWorkspace(ctx context.Context, workspaceID string) ([]map[string]interface{}, error) {
	path := "/workspaces/" + url.PathEscape(workspaceID) + "/runs"
	return t.listCollection(ctx, path)
}

func (t *TerraformCloudProvider) listCollection(ctx context.Context, path string) ([]map[string]interface{}, error) {
	nextPath := addQueryParams(path, map[string]string{"page[size]": "100"})
	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for {
		body, err := t.request(ctx, nextPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}

		normalized := normalizeTerraformCloudRow(payload)
		items := terraformCloudExtractItems(normalized["data"])
		for _, item := range items {
			rows = append(rows, normalizeTerraformCloudRow(item))
		}

		next := terraformCloudNextLink(normalized)
		if next == "" {
			break
		}
		if _, exists := seen[next]; exists {
			return nil, fmt.Errorf("terraform_cloud pagination loop detected for %s", path)
		}
		seen[next] = struct{}{}
		nextPath = next
	}

	return rows, nil
}

func (t *TerraformCloudProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL, err := terraformCloudResolveRequestURL(t.baseURL, path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("Accept", "application/vnd.api+json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("terraform_cloud API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func terraformCloudResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("terraform_cloud request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid terraform_cloud URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid terraform_cloud base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) || !strings.EqualFold(baseParsed.Host, resolved.Host) {
			return "", fmt.Errorf("terraform_cloud pagination URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func validateTerraformCloudURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid terraform_cloud base_url %q", rawURL)
	}
	return nil
}

func normalizeTerraformCloudRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func terraformCloudMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func terraformCloudExtractItems(value interface{}) []map[string]interface{} {
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

func terraformCloudNextLink(payload map[string]interface{}) string {
	links := terraformCloudMap(payload["links"])
	if len(links) == 0 {
		return ""
	}
	return strings.TrimSpace(providerStringValue(links["next"]))
}

func firstTerraformCloudString(row map[string]interface{}, keys ...string) string {
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

func firstTerraformCloudValue(row map[string]interface{}, keys ...string) interface{} {
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

func isTerraformCloudIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}
