package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type snykProject struct {
	ID              string
	Name            string
	Origin          string
	Type            string
	TargetReference string
	Branch          string
	Created         string
	OrgID           string
}

type snykSeverityCounts struct {
	Critical int
	High     int
}

// SnykProvider syncs vulnerability and code security data from Snyk
type SnykProvider struct {
	*BaseProvider
	apiToken string
	orgID    string
	baseURL  string
	client   *http.Client
}

func NewSnykProvider() *SnykProvider {
	return &SnykProvider{
		BaseProvider: NewBaseProvider("snyk", ProviderTypeSaaS),
		baseURL:      "https://api.snyk.io",
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (s *SnykProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := s.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	s.apiToken = s.GetConfigString("api_token")
	s.orgID = s.GetConfigString("org_id")
	if baseURL := s.GetConfigString("base_url"); baseURL != "" {
		s.baseURL = strings.TrimRight(baseURL, "/")
	}

	return nil
}

func (s *SnykProvider) Test(ctx context.Context) error {
	_, err := s.request(ctx, fmt.Sprintf("/rest/orgs/%s?version=2024-01-04", s.orgID))
	return err
}

func (s *SnykProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "snyk_projects",
			Description: "Snyk projects (monitored repositories/targets)",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "origin", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "target_reference", Type: "string"},
				{Name: "branch", Type: "string"},
				{Name: "created", Type: "timestamp"},
				{Name: "org_id", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "snyk_issues",
			Description: "Snyk vulnerability issues",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "project_id", Type: "string"},
				{Name: "issue_type", Type: "string"},
				{Name: "pkg_name", Type: "string"},
				{Name: "pkg_version", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "cve", Type: "string"},
				{Name: "cvss_score", Type: "float"},
				{Name: "exploit_maturity", Type: "string"},
				{Name: "is_fixable", Type: "boolean"},
				{Name: "introduced_date", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "snyk_dependencies",
			Description: "Snyk project dependencies",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "project_id", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "is_direct", Type: "boolean"},
				{Name: "licenses", Type: "array"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "snyk_code_issues",
			Description: "Snyk Code (SAST) issues",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "project_id", Type: "string"},
				{Name: "rule_id", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "file_path", Type: "string"},
				{Name: "line_number", Type: "integer"},
				{Name: "cwe", Type: "array"},
				{Name: "is_ignored", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "snyk_container_images",
			Description: "Snyk Container scanned images",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "project_id", Type: "string"},
				{Name: "image_name", Type: "string"},
				{Name: "image_tag", Type: "string"},
				{Name: "platform", Type: "string"},
				{Name: "base_image", Type: "string"},
				{Name: "dockerfile_path", Type: "string"},
				{Name: "critical_count", Type: "integer"},
				{Name: "high_count", Type: "integer"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "snyk_iac_issues",
			Description: "Snyk IaC (Infrastructure as Code) issues",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "project_id", Type: "string"},
				{Name: "rule_id", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "file_path", Type: "string"},
				{Name: "resource_type", Type: "string"},
				{Name: "resource_name", Type: "string"},
				{Name: "is_ignored", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (s *SnykProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	_ = opts

	start := time.Now()
	result := &SyncResult{
		Provider:  s.Name(),
		StartedAt: start,
	}

	schemas := s.Schema()
	syncTable := func(name string, rows []map[string]interface{}) {
		schema, ok := schemaByName(schemas, name)
		if !ok {
			result.Errors = append(result.Errors, name+": schema not found")
			return
		}

		tableResult, err := s.syncTable(ctx, schema, rows)
		if err != nil {
			result.Errors = append(result.Errors, name+": "+err.Error())
			return
		}

		result.Tables = append(result.Tables, *tableResult)
		result.TotalRows += tableResult.Rows
	}

	projectPayloads, err := s.fetchProjects(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "projects: "+err.Error())
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(start)
		return result, fmt.Errorf("snyk projects sync failed: %w", err)
	}

	projects := make([]snykProject, 0, len(projectPayloads))
	projectRows := make([]map[string]interface{}, 0, len(projectPayloads))
	seenProjectIDs := make(map[string]struct{}, len(projectPayloads))
	for _, payload := range projectPayloads {
		project := parseSnykProject(payload, s.orgID)
		if project.ID == "" {
			continue
		}
		if _, exists := seenProjectIDs[project.ID]; exists {
			continue
		}
		seenProjectIDs[project.ID] = struct{}{}
		projects = append(projects, project)
		projectRows = append(projectRows, project.row())
	}

	syncTable("snyk_projects", projectRows)

	issueRows := make([]map[string]interface{}, 0)
	dependencyRows := make([]map[string]interface{}, 0)
	codeRows := make([]map[string]interface{}, 0)
	iacRows := make([]map[string]interface{}, 0)
	severityByProject := make(map[string]snykSeverityCounts, len(projects))

	for _, project := range projects {
		issues, err := s.fetchProjectIssues(ctx, project.ID)
		if err != nil {
			if isSnykIgnorableError(err) {
				continue
			}
			result.Errors = append(result.Errors, fmt.Sprintf("issues[%s]: %s", project.ID, err.Error()))
			continue
		}

		projectIssueRows, severityCounts := buildSnykIssueRows(project.ID, issues)
		severityByProject[project.ID] = severityCounts
		issueRows = append(issueRows, projectIssueRows...)

		dependencyRows = append(dependencyRows, buildSnykDependencyRows(project.ID, issues)...)
		codeRows = append(codeRows, buildSnykCodeIssueRows(project.ID, issues)...)
		iacRows = append(iacRows, buildSnykIACIssueRows(project.ID, issues)...)
	}

	containerRows := buildSnykContainerRows(projects, severityByProject)

	syncTable("snyk_issues", issueRows)
	syncTable("snyk_dependencies", dependencyRows)
	syncTable("snyk_code_issues", codeRows)
	syncTable("snyk_container_images", containerRows)
	syncTable("snyk_iac_issues", iacRows)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	if len(result.Errors) > 0 {
		return result, fmt.Errorf("snyk sync finished with %d error(s)", len(result.Errors))
	}

	return result, nil
}

func (s *SnykProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := s.baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+s.apiToken)
	req.Header.Set("Content-Type", "application/vnd.api+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("snyk API error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (s *SnykProvider) fetchProjects(ctx context.Context) ([]map[string]interface{}, error) {
	nextPath := fmt.Sprintf("/rest/orgs/%s/projects?version=2024-01-04&limit=100", s.orgID)
	allProjects := make([]map[string]interface{}, 0)
	seenPaths := make(map[string]struct{})

	for nextPath != "" {
		if _, exists := seenPaths[nextPath]; exists {
			return nil, fmt.Errorf("snyk projects pagination loop detected at %q", nextPath)
		}
		seenPaths[nextPath] = struct{}{}

		body, err := s.request(ctx, nextPath)
		if err != nil {
			return nil, err
		}

		projects, nextLink, err := parseSnykProjectPage(body)
		if err != nil {
			return nil, err
		}
		allProjects = append(allProjects, projects...)

		nextPath, err = snykNextPagePath(s.baseURL, nextLink)
		if err != nil {
			return nil, err
		}
	}

	return allProjects, nil
}

func (s *SnykProvider) fetchProjectIssues(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	path := fmt.Sprintf("/v1/org/%s/project/%s/aggregated-issues", s.orgID, projectID)
	body, err := s.request(ctx, path)
	if err != nil {
		return nil, err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	normalized := normalizeSnykMap(response)
	return extractSnykIssues(normalized), nil
}

func parseSnykProject(payload map[string]interface{}, fallbackOrgID string) snykProject {
	normalized := normalizeSnykMap(payload)
	attributes := snykMap(normalized["attributes"])

	return snykProject{
		ID:              firstNonEmptyString(asString(normalized["id"]), asString(attributes["id"])),
		Name:            firstNonEmptyString(asString(attributes["name"]), asString(normalized["name"])),
		Origin:          firstNonEmptyString(asString(attributes["origin"]), asString(normalized["origin"])),
		Type:            firstNonEmptyString(asString(attributes["type"]), asString(normalized["type"])),
		TargetReference: firstNonEmptyString(asString(attributes["target_reference"]), asString(normalized["target_reference"])),
		Branch:          firstNonEmptyString(asString(attributes["branch"]), asString(normalized["branch"])),
		Created:         firstNonEmptyString(asString(attributes["created"]), asString(attributes["created_at"]), asString(normalized["created"])),
		OrgID: firstNonEmptyString(
			getNestedString(normalized, "relationships", "organization", "data", "id"),
			asString(attributes["org_id"]),
			asString(normalized["org_id"]),
			fallbackOrgID,
		),
	}
}

func parseSnykProjectPage(body []byte) ([]map[string]interface{}, string, error) {
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", err
	}

	normalized := normalizeSnykMap(payload)
	projects := snykMapSlice(normalized["data"])
	if len(projects) == 0 {
		projects = snykMapSlice(normalized["projects"])
	}

	nextLink := firstNonEmptyString(
		getNestedString(normalized, "links", "next"),
		asString(normalized["next"]),
	)

	return projects, nextLink, nil
}

func snykNextPagePath(baseURL, nextLink string) (string, error) {
	nextLink = strings.TrimSpace(nextLink)
	if nextLink == "" {
		return "", nil
	}
	if strings.HasPrefix(nextLink, "/") {
		return nextLink, nil
	}

	parsedNext, err := url.Parse(nextLink)
	if err != nil {
		return "", fmt.Errorf("invalid Snyk pagination link %q: %w", nextLink, err)
	}

	if parsedNext.Scheme == "" && parsedNext.Host == "" {
		path := parsedNext.Path
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if parsedNext.RawQuery != "" {
			path += "?" + parsedNext.RawQuery
		}
		return path, nil
	}

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid Snyk base URL %q: %w", baseURL, err)
	}
	if !strings.EqualFold(parsedBase.Host, parsedNext.Host) {
		return "", fmt.Errorf("unexpected Snyk pagination host %q", parsedNext.Host)
	}
	if parsedNext.Scheme != "" && !strings.EqualFold(parsedBase.Scheme, parsedNext.Scheme) {
		return "", fmt.Errorf("unexpected Snyk pagination scheme %q", parsedNext.Scheme)
	}

	path := parsedNext.Path
	if path == "" {
		path = "/"
	}
	if parsedNext.RawQuery != "" {
		path += "?" + parsedNext.RawQuery
	}

	return path, nil
}

func (p snykProject) row() map[string]interface{} {
	return map[string]interface{}{
		"id":               p.ID,
		"name":             p.Name,
		"origin":           p.Origin,
		"type":             p.Type,
		"target_reference": p.TargetReference,
		"branch":           p.Branch,
		"created":          p.Created,
		"org_id":           p.OrgID,
	}
}

func buildSnykIssueRows(projectID string, issues []map[string]interface{}) ([]map[string]interface{}, snykSeverityCounts) {
	rows := make([]map[string]interface{}, 0, len(issues))
	seen := make(map[string]struct{}, len(issues))
	counts := snykSeverityCounts{}

	for _, payload := range issues {
		normalized := normalizeSnykMap(payload)
		baseID := snykIssueBaseID(normalized)
		if baseID == "" {
			continue
		}

		id := snykCompositeID(projectID, baseID)
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}

		severity := strings.ToLower(strings.TrimSpace(asString(normalized["severity"])))
		switch severity {
		case "critical":
			counts.Critical++
		case "high":
			counts.High++
		}

		issueType := strings.ToLower(strings.TrimSpace(firstNonEmptyString(
			asString(normalized["issue_type"]),
			asString(normalized["type"]),
			asString(normalized["problem_type"]),
		)))

		pkgName := firstNonEmptyString(
			asString(normalized["pkg_name"]),
			asString(normalized["package_name"]),
			getNestedString(normalized, "package", "name"),
		)
		pkgVersion := firstNonEmptyString(
			asString(normalized["pkg_version"]),
			snykFirstString(normalized["pkg_versions"]),
			getNestedString(normalized, "package", "version"),
		)
		cve := firstNonEmptyString(
			asString(normalized["cve"]),
			snykFirstString(getNestedValue(normalized, "identifiers", "cve")),
			snykFirstString(getNestedValue(normalized, "identifiers", "cves")),
		)

		cvss, cvssOK := asFloat(snykFirstNonNil(
			normalized["cvss_score"],
			getNestedValue(normalized, "cvss_score", "value"),
			getNestedValue(normalized, "cvss_v3"),
		))

		row := map[string]interface{}{
			"id":               id,
			"project_id":       projectID,
			"issue_type":       issueType,
			"pkg_name":         pkgName,
			"pkg_version":      pkgVersion,
			"severity":         severity,
			"title":            asString(normalized["title"]),
			"cve":              cve,
			"exploit_maturity": asString(normalized["exploit_maturity"]),
			"is_fixable":       snykIsFixable(normalized),
			"introduced_date": firstNonEmptyString(
				asString(normalized["introduced_date"]),
				asString(normalized["disclosure_time"]),
			),
		}
		if cvssOK {
			row["cvss_score"] = cvss
		}

		rows = append(rows, row)
	}

	return rows, counts
}

func buildSnykDependencyRows(projectID string, issues []map[string]interface{}) []map[string]interface{} {
	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, payload := range issues {
		normalized := normalizeSnykMap(payload)

		name := firstNonEmptyString(
			asString(normalized["pkg_name"]),
			asString(normalized["package_name"]),
			getNestedString(normalized, "package", "name"),
		)
		if strings.TrimSpace(name) == "" {
			continue
		}

		version := firstNonEmptyString(
			asString(normalized["pkg_version"]),
			snykFirstString(normalized["pkg_versions"]),
			getNestedString(normalized, "package", "version"),
		)
		id := snykCompositeID(projectID, name, version)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}

		rows = append(rows, map[string]interface{}{
			"id":         id,
			"project_id": projectID,
			"name":       name,
			"version":    version,
			"type": firstNonEmptyString(
				asString(normalized["package_manager"]),
				asString(normalized["language"]),
				asString(normalized["ecosystem"]),
			),
			"is_direct": snykIsDirectDependency(normalized),
			"licenses":  snykInterfaceSlice(normalized["licenses"]),
		})
	}

	return rows
}

func buildSnykCodeIssueRows(projectID string, issues []map[string]interface{}) []map[string]interface{} {
	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, payload := range issues {
		normalized := normalizeSnykMap(payload)
		issueType := strings.ToLower(strings.TrimSpace(firstNonEmptyString(
			asString(normalized["issue_type"]),
			asString(normalized["type"]),
			asString(normalized["problem_type"]),
		)))
		if !snykIssueTypeMatches(issueType, "code", "sast") {
			continue
		}

		baseID := snykIssueBaseID(normalized)
		if baseID == "" {
			continue
		}
		id := snykCompositeID(projectID, "code", baseID)
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}

		row := map[string]interface{}{
			"id":         id,
			"project_id": projectID,
			"rule_id": firstNonEmptyString(
				asString(normalized["rule_id"]),
				asString(normalized["id"]),
			),
			"severity": asString(normalized["severity"]),
			"title":    asString(normalized["title"]),
			"file_path": firstNonEmptyString(
				asString(normalized["file_path"]),
				asString(normalized["display_target_file"]),
				asString(normalized["target_file"]),
			),
			"cwe": snykInterfaceSlice(snykFirstNonNil(
				getNestedValue(normalized, "identifiers", "cwe"),
				getNestedValue(normalized, "identifiers", "cwes"),
			)),
			"is_ignored": asBool(snykFirstNonNil(normalized["is_ignored"], normalized["ignored"])),
		}

		lineNumber := snykLineNumber(normalized)
		if lineNumber > 0 {
			row["line_number"] = lineNumber
		}

		rows = append(rows, row)
	}

	return rows
}

func buildSnykIACIssueRows(projectID string, issues []map[string]interface{}) []map[string]interface{} {
	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, payload := range issues {
		normalized := normalizeSnykMap(payload)
		issueType := strings.ToLower(strings.TrimSpace(firstNonEmptyString(
			asString(normalized["issue_type"]),
			asString(normalized["type"]),
			asString(normalized["problem_type"]),
		)))
		if !snykIssueTypeMatches(issueType, "iac", "configuration", "config", "policy") {
			continue
		}

		baseID := snykIssueBaseID(normalized)
		if baseID == "" {
			continue
		}
		id := snykCompositeID(projectID, "iac", baseID)
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}

		rows = append(rows, map[string]interface{}{
			"id":         id,
			"project_id": projectID,
			"rule_id": firstNonEmptyString(
				asString(normalized["rule_id"]),
				asString(normalized["id"]),
			),
			"severity": asString(normalized["severity"]),
			"title":    asString(normalized["title"]),
			"file_path": firstNonEmptyString(
				asString(normalized["file_path"]),
				asString(normalized["target_file"]),
			),
			"resource_type": firstNonEmptyString(
				asString(normalized["resource_type"]),
				getNestedString(normalized, "resource", "type"),
			),
			"resource_name": firstNonEmptyString(
				asString(normalized["resource_name"]),
				getNestedString(normalized, "resource", "name"),
			),
			"is_ignored": asBool(snykFirstNonNil(normalized["is_ignored"], normalized["ignored"])),
		})
	}

	return rows
}

func buildSnykContainerRows(projects []snykProject, severityByProject map[string]snykSeverityCounts) []map[string]interface{} {
	rows := make([]map[string]interface{}, 0)
	for _, project := range projects {
		if !snykIsContainerProject(project) {
			continue
		}

		imageName, imageTag := snykSplitImageReference(project.TargetReference)
		counts := severityByProject[project.ID]

		rows = append(rows, map[string]interface{}{
			"id":              project.ID,
			"project_id":      project.ID,
			"image_name":      imageName,
			"image_tag":       imageTag,
			"platform":        firstNonEmptyString(project.Type, project.Origin),
			"base_image":      "",
			"dockerfile_path": "",
			"critical_count":  counts.Critical,
			"high_count":      counts.High,
		})
	}

	return rows
}

func extractSnykIssues(payload map[string]interface{}) []map[string]interface{} {
	if issues := snykMapSlice(payload["issues"]); len(issues) > 0 {
		return issues
	}

	if grouped, ok := payload["issues"].(map[string]interface{}); ok {
		keys := make([]string, 0, len(grouped))
		for key := range grouped {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		rows := make([]map[string]interface{}, 0)
		for _, key := range keys {
			rows = append(rows, snykMapSlice(grouped[key])...)
		}
		if len(rows) > 0 {
			return rows
		}
	}

	if data := snykMapSlice(payload["data"]); len(data) > 0 {
		return data
	}

	return nil
}

func snykIssueBaseID(issue map[string]interface{}) string {
	return firstNonEmptyString(
		asString(issue["id"]),
		asString(issue["issue_id"]),
		asString(issue["key"]),
		asString(issue["title"]),
	)
}

func snykIsFixable(issue map[string]interface{}) bool {
	if asBool(snykFirstNonNil(issue["is_fixable"], issue["is_upgradable"], issue["is_patchable"])) {
		return true
	}

	return strings.TrimSpace(firstNonEmptyString(
		asString(issue["fixed_in"]),
		snykFirstString(issue["fixed_in"]),
	)) != ""
}

func snykIsDirectDependency(issue map[string]interface{}) bool {
	if value := snykFirstNonNil(issue["is_direct"], issue["direct_dependency"]); value != nil {
		return asBool(value)
	}

	fromPath := snykStringSlice(issue["from"])
	if len(fromPath) == 0 {
		return false
	}

	return len(fromPath) <= 2
}

func snykLineNumber(issue map[string]interface{}) int {
	value := snykFirstNonNil(
		issue["line_number"],
		issue["line"],
		getNestedValue(issue, "line_numbers", "begin"),
	)
	if line, ok := asFloat(value); ok && line > 0 {
		return int(line)
	}
	return 0
}

func snykIsContainerProject(project snykProject) bool {
	for _, candidate := range []string{project.Type, project.Origin, project.TargetReference} {
		normalized := strings.ToLower(strings.TrimSpace(candidate))
		if normalized == "" {
			continue
		}
		if strings.Contains(normalized, "container") || strings.Contains(normalized, "docker") {
			return true
		}
	}
	return false
}

func snykSplitImageReference(reference string) (string, string) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return "", ""
	}

	if idx := strings.LastIndex(reference, "|"); idx >= 0 {
		reference = strings.TrimSpace(reference[idx+1:])
	}
	if idx := strings.Index(reference, "@"); idx >= 0 {
		reference = reference[:idx]
	}

	lastSlash := strings.LastIndex(reference, "/")
	lastColon := strings.LastIndex(reference, ":")
	if lastColon > lastSlash {
		return reference[:lastColon], reference[lastColon+1:]
	}

	return reference, ""
}

func snykIssueTypeMatches(issueType string, substrings ...string) bool {
	normalized := strings.ToLower(strings.TrimSpace(issueType))
	if normalized == "" {
		return false
	}

	for _, candidate := range substrings {
		if strings.Contains(normalized, strings.ToLower(candidate)) {
			return true
		}
	}

	return false
}

func snykCompositeID(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		filtered = append(filtered, trimmed)
	}

	if len(filtered) == 0 {
		return ""
	}

	return strings.Join(filtered, "|")
}

func snykMap(value interface{}) map[string]interface{} {
	typed, ok := value.(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalizeSnykMap(typed)
}

func snykMapSlice(value interface{}) []map[string]interface{} {
	switch typed := value.(type) {
	case []map[string]interface{}:
		rows := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			rows = append(rows, normalizeSnykMap(item))
		}
		return rows
	case []interface{}:
		rows := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			if asMap, ok := item.(map[string]interface{}); ok {
				rows = append(rows, normalizeSnykMap(asMap))
			}
		}
		return rows
	default:
		return nil
	}
}

func snykInterfaceSlice(value interface{}) []interface{} {
	switch typed := value.(type) {
	case nil:
		return nil
	case []interface{}:
		return typed
	case []string:
		items := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
		return items
	case map[string]interface{}:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		items := make([]interface{}, 0, len(keys))
		for _, key := range keys {
			items = append(items, key)
		}
		return items
	default:
		return []interface{}{typed}
	}
}

func snykStringSlice(value interface{}) []string {
	items := snykInterfaceSlice(value)
	if len(items) == 0 {
		return nil
	}

	result := make([]string, 0, len(items))
	for _, item := range items {
		if text := strings.TrimSpace(asString(item)); text != "" {
			result = append(result, text)
		}
	}
	return result
}

func snykFirstString(value interface{}) string {
	for _, item := range snykStringSlice(value) {
		return item
	}
	return ""
}

func snykFirstNonNil(values ...interface{}) interface{} {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func normalizeSnykMap(value map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func isSnykIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "snyk API error 403") || strings.Contains(message, "snyk API error 404")
}
