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

// AtlassianProvider syncs Jira Cloud identity and project metadata.
type AtlassianProvider struct {
	*BaseProvider
	baseURL  string
	email    string
	apiToken string
	client   *http.Client

	issueActivityLoaded bool
	issueActivityRows   []map[string]interface{}
	issueCommentRows    []map[string]interface{}
	issueChangelogRows  []map[string]interface{}
	issueActivityErr    error
}

const atlassianIssueLookbackDays = 180

func NewAtlassianProvider() *AtlassianProvider {
	return &AtlassianProvider{
		BaseProvider: NewBaseProvider("atlassian", ProviderTypeSaaS),
		client:       newProviderHTTPClient(60 * time.Second),
	}
}

func (a *AtlassianProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := a.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	a.baseURL = strings.TrimSuffix(strings.TrimSpace(a.GetConfigString("base_url")), "/")
	if a.baseURL == "" {
		a.baseURL = strings.TrimSuffix(strings.TrimSpace(a.GetConfigString("api_url")), "/")
	}
	if a.baseURL == "" {
		return fmt.Errorf("atlassian base_url required")
	}

	parsed, err := url.Parse(a.baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid atlassian base_url %q", a.baseURL)
	}

	a.email = strings.TrimSpace(a.GetConfigString("email"))
	if a.email == "" {
		return fmt.Errorf("atlassian email required")
	}

	a.apiToken = strings.TrimSpace(a.GetConfigString("api_token"))
	if a.apiToken == "" {
		return fmt.Errorf("atlassian api_token required")
	}

	a.resetIssueActivityCache()

	return nil
}

func (a *AtlassianProvider) Test(ctx context.Context) error {
	_, err := a.request(ctx, "/rest/api/3/myself")
	return err
}

func (a *AtlassianProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "atlassian_projects",
			Description: "Atlassian Jira projects",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "key", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "project_type_key", Type: "string"},
				{Name: "simplified", Type: "boolean"},
				{Name: "style", Type: "string"},
				{Name: "is_private", Type: "boolean"},
				{Name: "archived", Type: "boolean"},
				{Name: "lead_account_id", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "atlassian_users",
			Description: "Atlassian Jira users",
			Columns: []ColumnSchema{
				{Name: "account_id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "email_address", Type: "string"},
				{Name: "account_type", Type: "string"},
				{Name: "active", Type: "boolean"},
				{Name: "time_zone", Type: "string"},
				{Name: "locale", Type: "string"},
			},
			PrimaryKey: []string{"account_id"},
		},
		{
			Name:        "atlassian_groups",
			Description: "Atlassian Jira groups",
			Columns: []ColumnSchema{
				{Name: "group_id", Type: "string", Required: true},
				{Name: "name", Type: "string", Required: true},
				{Name: "self", Type: "string"},
			},
			PrimaryKey: []string{"group_id"},
		},
		{
			Name:        "atlassian_group_memberships",
			Description: "Atlassian Jira group memberships",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "group_id", Type: "string", Required: true},
				{Name: "group_name", Type: "string"},
				{Name: "account_id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "email_address", Type: "string"},
				{Name: "active", Type: "boolean"},
				{Name: "account_type", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "atlassian_issues",
			Description: "Atlassian Jira issues",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "key", Type: "string", Required: true},
				{Name: "project_key", Type: "string"},
				{Name: "project_name", Type: "string"},
				{Name: "summary", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "status_category", Type: "string"},
				{Name: "issue_type", Type: "string"},
				{Name: "priority", Type: "string"},
				{Name: "assignee_account_id", Type: "string"},
				{Name: "assignee_email", Type: "string"},
				{Name: "reporter_account_id", Type: "string"},
				{Name: "reporter_email", Type: "string"},
				{Name: "created", Type: "timestamp"},
				{Name: "updated", Type: "timestamp"},
				{Name: "resolved", Type: "timestamp"},
				{Name: "due_date", Type: "timestamp"},
				{Name: "labels", Type: "array"},
				{Name: "components", Type: "array"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "atlassian_issue_comments",
			Description: "Atlassian Jira issue comments",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "issue_id", Type: "string", Required: true},
				{Name: "issue_key", Type: "string", Required: true},
				{Name: "author_account_id", Type: "string"},
				{Name: "author_email", Type: "string"},
				{Name: "created", Type: "timestamp"},
				{Name: "updated", Type: "timestamp"},
			},
			PrimaryKey: []string{"issue_id", "id"},
		},
		{
			Name:        "atlassian_issue_changelogs",
			Description: "Atlassian Jira issue changelog entries",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "issue_id", Type: "string", Required: true},
				{Name: "issue_key", Type: "string", Required: true},
				{Name: "author_account_id", Type: "string"},
				{Name: "author_email", Type: "string"},
				{Name: "field", Type: "string"},
				{Name: "from_value", Type: "string"},
				{Name: "to_value", Type: "string"},
				{Name: "created", Type: "timestamp"},
			},
			PrimaryKey: []string{"issue_id", "id"},
		},
	}
}

func (a *AtlassianProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(a.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (a *AtlassianProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	a.resetIssueActivityCache()

	result := &SyncResult{
		Provider:  a.Name(),
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

	syncTable("projects", a.syncProjects)
	syncTable("users", a.syncUsers)
	syncTable("groups", a.syncGroups)
	syncTable("group_memberships", a.syncGroupMemberships)
	syncTable("issues", a.syncIssues)
	syncTable("issue_comments", a.syncIssueComments)
	syncTable("issue_changelogs", a.syncIssueChangelogs)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (a *AtlassianProvider) syncProjects(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("atlassian_projects")
	result := &TableResult{Name: "atlassian_projects"}
	if err != nil {
		return result, err
	}

	projects, err := a.listProjects(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(projects))
	for _, project := range projects {
		row := normalizeAtlassianRow(project)
		if id := firstAtlassianString(row, "id", "project_id", "key"); id != "" {
			row["id"] = id
		}
		if key := firstAtlassianString(row, "key", "project_key"); key != "" {
			row["key"] = key
		}
		if row["lead_account_id"] == nil {
			if lead := atlassianMap(row["lead"]); len(lead) > 0 {
				row["lead_account_id"] = firstAtlassianValue(lead, "account_id", "id")
			}
		}
		rows = append(rows, row)
	}

	return a.syncTable(ctx, schema, rows)
}

func (a *AtlassianProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("atlassian_users")
	result := &TableResult{Name: "atlassian_users"}
	if err != nil {
		return result, err
	}

	users, err := a.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		row := normalizeAtlassianRow(user)
		if accountID := firstAtlassianString(row, "account_id", "accountid", "id"); accountID != "" {
			row["account_id"] = accountID
		}
		rows = append(rows, row)
	}

	return a.syncTable(ctx, schema, rows)
}

func (a *AtlassianProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("atlassian_groups")
	result := &TableResult{Name: "atlassian_groups"}
	if err != nil {
		return result, err
	}

	groups, err := a.listGroups(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		row := normalizeAtlassianRow(group)
		if groupID := firstAtlassianString(row, "group_id", "id", "name"); groupID != "" {
			row["group_id"] = groupID
		}
		if row["name"] == nil {
			row["name"] = firstAtlassianValue(row, "name", "group_name")
		}
		rows = append(rows, row)
	}

	return a.syncTable(ctx, schema, rows)
}

func (a *AtlassianProvider) syncGroupMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("atlassian_group_memberships")
	result := &TableResult{Name: "atlassian_group_memberships"}
	if err != nil {
		return result, err
	}

	groups, err := a.listGroups(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, group := range groups {
		normalizedGroup := normalizeAtlassianRow(group)
		groupID := firstAtlassianString(normalizedGroup, "group_id", "id", "name")
		if groupID == "" {
			continue
		}
		groupName := firstAtlassianString(normalizedGroup, "name", "group_name")

		members, err := a.listGroupMembers(ctx, groupID)
		if err != nil {
			if isAtlassianIgnorableError(err) {
				continue
			}
			return result, err
		}

		for _, member := range members {
			normalizedMember := normalizeAtlassianRow(member)
			accountID := firstAtlassianString(normalizedMember, "account_id", "accountid", "id")
			if accountID == "" {
				continue
			}

			membershipID := groupID + "|" + accountID
			if _, ok := seen[membershipID]; ok {
				continue
			}
			seen[membershipID] = struct{}{}

			rows = append(rows, map[string]interface{}{
				"id":           membershipID,
				"group_id":     groupID,
				"group_name":   groupName,
				"account_id":   accountID,
				"display_name": firstAtlassianValue(normalizedMember, "display_name"),
				"email_address": firstAtlassianValue(normalizedMember,
					"email_address", "email"),
				"active":       firstAtlassianValue(normalizedMember, "active"),
				"account_type": firstAtlassianValue(normalizedMember, "account_type"),
			})
		}
	}

	return a.syncTable(ctx, schema, rows)
}

func (a *AtlassianProvider) syncIssues(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("atlassian_issues")
	result := &TableResult{Name: "atlassian_issues"}
	if err != nil {
		return result, err
	}

	if err := a.ensureIssueActivityRows(ctx); err != nil {
		return result, err
	}

	return a.syncTable(ctx, schema, a.issueActivityRows)
}

func (a *AtlassianProvider) syncIssueComments(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("atlassian_issue_comments")
	result := &TableResult{Name: "atlassian_issue_comments"}
	if err != nil {
		return result, err
	}

	if err := a.ensureIssueActivityRows(ctx); err != nil {
		return result, err
	}

	return a.syncTable(ctx, schema, a.issueCommentRows)
}

func (a *AtlassianProvider) syncIssueChangelogs(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("atlassian_issue_changelogs")
	result := &TableResult{Name: "atlassian_issue_changelogs"}
	if err != nil {
		return result, err
	}

	if err := a.ensureIssueActivityRows(ctx); err != nil {
		return result, err
	}

	return a.syncTable(ctx, schema, a.issueChangelogRows)
}

func (a *AtlassianProvider) ensureIssueActivityRows(ctx context.Context) error {
	if a.issueActivityLoaded {
		return a.issueActivityErr
	}

	lookback := time.Now().AddDate(0, 0, -atlassianIssueLookbackDays)
	a.issueActivityRows, a.issueCommentRows, a.issueChangelogRows, a.issueActivityErr = a.listIssueActivity(ctx, lookback)
	a.issueActivityLoaded = true
	return a.issueActivityErr
}

func (a *AtlassianProvider) listProjects(ctx context.Context) ([]map[string]interface{}, error) {
	pageSize := 50
	startAt := 0
	all := make([]map[string]interface{}, 0)

	for {
		path := addQueryParams("/rest/api/3/project/search", map[string]string{
			"startAt":    strconv.Itoa(startAt),
			"maxResults": strconv.Itoa(pageSize),
		})

		body, err := a.request(ctx, path)
		if err != nil {
			return nil, err
		}

		items, isLast, respStartAt, respMaxResults, err := decodeAtlassianValuesPage(body)
		if err != nil {
			return nil, err
		}

		all = append(all, items...)
		if isLast || len(items) == 0 {
			break
		}

		next := respStartAt + respMaxResults
		if next <= startAt {
			next = startAt + len(items)
		}
		if next <= startAt {
			break
		}
		startAt = next
	}

	return all, nil
}

func (a *AtlassianProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	pageSize := 100
	startAt := 0
	all := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for {
		path := addQueryParams("/rest/api/3/users/search", map[string]string{
			"startAt":    strconv.Itoa(startAt),
			"maxResults": strconv.Itoa(pageSize),
		})

		body, err := a.request(ctx, path)
		if err != nil {
			return nil, err
		}

		var users []map[string]interface{}
		if err := json.Unmarshal(body, &users); err != nil {
			return nil, err
		}
		if len(users) == 0 {
			break
		}

		for _, user := range users {
			normalized := normalizeAtlassianRow(user)
			id := firstAtlassianString(normalized, "account_id", "accountid", "id")
			if id != "" {
				if _, ok := seen[id]; ok {
					continue
				}
				seen[id] = struct{}{}
			}
			all = append(all, normalized)
		}

		if len(users) < pageSize {
			break
		}
		startAt += len(users)
	}

	return all, nil
}

func (a *AtlassianProvider) listGroups(ctx context.Context) ([]map[string]interface{}, error) {
	pageSize := 100
	startAt := 0
	all := make([]map[string]interface{}, 0)

	for {
		path := addQueryParams("/rest/api/3/group/bulk", map[string]string{
			"startAt":    strconv.Itoa(startAt),
			"maxResults": strconv.Itoa(pageSize),
		})

		body, err := a.request(ctx, path)
		if err != nil {
			return nil, err
		}

		items, isLast, respStartAt, respMaxResults, err := decodeAtlassianValuesPage(body)
		if err != nil {
			return nil, err
		}

		all = append(all, items...)
		if isLast || len(items) == 0 {
			break
		}

		next := respStartAt + respMaxResults
		if next <= startAt {
			next = startAt + len(items)
		}
		if next <= startAt {
			break
		}
		startAt = next
	}

	return all, nil
}

func (a *AtlassianProvider) listGroupMembers(ctx context.Context, groupID string) ([]map[string]interface{}, error) {
	pageSize := 100
	startAt := 0
	all := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for {
		path := addQueryParams("/rest/api/3/group/member", map[string]string{
			"groupId":    groupID,
			"startAt":    strconv.Itoa(startAt),
			"maxResults": strconv.Itoa(pageSize),
		})

		body, err := a.request(ctx, path)
		if err != nil {
			return nil, err
		}

		items, isLast, respStartAt, respMaxResults, err := decodeAtlassianValuesPage(body)
		if err != nil {
			return nil, err
		}

		for _, item := range items {
			normalized := normalizeAtlassianRow(item)
			accountID := firstAtlassianString(normalized, "account_id", "accountid", "id")
			if accountID != "" {
				if _, ok := seen[accountID]; ok {
					continue
				}
				seen[accountID] = struct{}{}
			}
			all = append(all, normalized)
		}

		if isLast || len(items) == 0 {
			break
		}

		next := respStartAt + respMaxResults
		if next <= startAt {
			next = startAt + len(items)
		}
		if next <= startAt {
			break
		}
		startAt = next
	}

	return all, nil
}

func (a *AtlassianProvider) listIssueActivity(ctx context.Context, since time.Time) ([]map[string]interface{}, []map[string]interface{}, []map[string]interface{}, error) {
	pageSize := 50
	startAt := 0
	issues := make([]map[string]interface{}, 0)
	comments := make([]map[string]interface{}, 0)
	changelogs := make([]map[string]interface{}, 0)

	for {
		params := map[string]string{
			"startAt":    strconv.Itoa(startAt),
			"maxResults": strconv.Itoa(pageSize),
			"expand":     "changelog",
			"fields": strings.Join([]string{
				"project",
				"summary",
				"status",
				"issuetype",
				"priority",
				"assignee",
				"reporter",
				"created",
				"updated",
				"resolutiondate",
				"duedate",
				"labels",
				"components",
				"comment",
			}, ","),
		}
		if !since.IsZero() {
			params["jql"] = fmt.Sprintf("updated >= \"%s\" ORDER BY updated DESC", since.UTC().Format("2006-01-02"))
		}

		path := addQueryParams("/rest/api/3/search", params)
		body, err := a.request(ctx, path)
		if err != nil {
			if isAtlassianIgnorableError(err) {
				return nil, nil, nil, nil
			}
			return nil, nil, nil, err
		}

		pageIssues, respStartAt, total, err := decodeAtlassianIssueSearchPage(body)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(pageIssues) == 0 {
			break
		}

		for _, issue := range pageIssues {
			normalizedIssue := normalizeAtlassianRow(issue)
			issueID := firstAtlassianString(normalizedIssue, "id")
			issueKey := firstAtlassianString(normalizedIssue, "key")
			if issueID == "" || issueKey == "" {
				continue
			}

			fields := atlassianMap(normalizedIssue["fields"])
			project := atlassianMap(fields["project"])
			status := atlassianMap(fields["status"])
			statusCategory := atlassianMap(status["status_category"])
			issueType := atlassianMap(fields["issue_type"])
			priority := atlassianMap(fields["priority"])
			assignee := atlassianMap(fields["assignee"])
			reporter := atlassianMap(fields["reporter"])

			issueRow := map[string]interface{}{
				"id":              issueID,
				"key":             issueKey,
				"project_key":     firstAtlassianValue(project, "key"),
				"project_name":    firstAtlassianValue(project, "name"),
				"summary":         firstAtlassianValue(fields, "summary"),
				"status":          firstAtlassianValue(status, "name"),
				"status_category": firstAtlassianValue(statusCategory, "name"),
				"issue_type":      firstAtlassianValue(issueType, "name"),
				"priority":        firstAtlassianValue(priority, "name"),
				"assignee_account_id": firstAtlassianValue(assignee,
					"account_id", "id"),
				"assignee_email": firstAtlassianValue(assignee,
					"email_address", "email"),
				"reporter_account_id": firstAtlassianValue(reporter,
					"account_id", "id"),
				"reporter_email": firstAtlassianValue(reporter,
					"email_address", "email"),
				"created":    firstAtlassianValue(fields, "created"),
				"updated":    firstAtlassianValue(fields, "updated"),
				"resolved":   firstAtlassianValue(fields, "resolutiondate", "resolved"),
				"due_date":   firstAtlassianValue(fields, "duedate", "due_date"),
				"labels":     atlassianStringArray(fields["labels"]),
				"components": atlassianComponentNames(fields["components"]),
			}
			issues = append(issues, issueRow)

			commentData := atlassianMap(fields["comment"])
			commentItems, _ := commentData["comments"].([]interface{})
			for _, comment := range commentItems {
				normalizedComment := atlassianMap(comment)
				commentID := firstAtlassianString(normalizedComment, "id")
				if commentID == "" {
					continue
				}
				author := atlassianMap(normalizedComment["author"])
				comments = append(comments, map[string]interface{}{
					"id":        commentID,
					"issue_id":  issueID,
					"issue_key": issueKey,
					"author_account_id": firstAtlassianValue(author,
						"account_id", "id"),
					"author_email": firstAtlassianValue(author,
						"email_address", "email"),
					"created": firstAtlassianValue(normalizedComment,
						"created"),
					"updated": firstAtlassianValue(normalizedComment,
						"updated"),
				})
			}

			changelogData := atlassianMap(normalizedIssue["changelog"])
			historyItems, _ := changelogData["histories"].([]interface{})
			for historyIndex, history := range historyItems {
				normalizedHistory := atlassianMap(history)
				author := atlassianMap(normalizedHistory["author"])
				historyID := firstAtlassianString(normalizedHistory, "id")
				if historyID == "" {
					historyID = fmt.Sprintf("history-%d", historyIndex)
				}

				items, _ := normalizedHistory["items"].([]interface{})
				for itemIndex, item := range items {
					normalizedItem := atlassianMap(item)
					changelogs = append(changelogs, map[string]interface{}{
						"id":        fmt.Sprintf("%s-%d", historyID, itemIndex),
						"issue_id":  issueID,
						"issue_key": issueKey,
						"author_account_id": firstAtlassianValue(author,
							"account_id", "id"),
						"author_email": firstAtlassianValue(author,
							"email_address", "email"),
						"field": firstAtlassianValue(normalizedItem,
							"field"),
						"from_value": firstAtlassianValue(normalizedItem,
							"from_string", "from"),
						"to_value": firstAtlassianValue(normalizedItem,
							"to_string", "to"),
						"created": firstAtlassianValue(normalizedHistory,
							"created"),
					})
				}
			}
		}

		next := respStartAt + len(pageIssues)
		if total > 0 && next >= total {
			break
		}
		if len(pageIssues) < pageSize {
			break
		}
		if next <= startAt {
			break
		}
		startAt = next
	}

	return issues, comments, changelogs, nil
}

func decodeAtlassianValuesPage(body []byte) ([]map[string]interface{}, bool, int, int, error) {
	var page struct {
		Values     []map[string]interface{} `json:"values"`
		IsLast     bool                     `json:"isLast"`
		StartAt    int                      `json:"startAt"`
		MaxResults int                      `json:"maxResults"`
	}
	if err := json.Unmarshal(body, &page); err == nil && (page.Values != nil || page.IsLast || page.StartAt > 0 || page.MaxResults > 0) {
		if page.MaxResults <= 0 {
			page.MaxResults = len(page.Values)
		}
		return page.Values, page.IsLast, page.StartAt, page.MaxResults, nil
	}

	var list []map[string]interface{}
	if err := json.Unmarshal(body, &list); err == nil {
		return list, true, 0, len(list), nil
	}

	return nil, false, 0, 0, fmt.Errorf("failed to parse atlassian paginated response")
}

func decodeAtlassianIssueSearchPage(body []byte) ([]map[string]interface{}, int, int, error) {
	var page struct {
		Issues  []map[string]interface{} `json:"issues"`
		StartAt int                      `json:"startAt"`
		Total   int                      `json:"total"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to parse atlassian issue search response: %w", err)
	}
	return page.Issues, page.StartAt, page.Total, nil
}

func (a *AtlassianProvider) request(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(a.email, a.apiToken)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("atlassian API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func normalizeAtlassianRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func atlassianMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func firstAtlassianString(row map[string]interface{}, keys ...string) string {
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

func firstAtlassianValue(row map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		value, ok := row[key]
		if !ok || value == nil {
			continue
		}
		if text := strings.TrimSpace(providerStringValue(value)); text == "" {
			continue
		}
		return value
	}
	return nil
}

func isAtlassianIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

func (a *AtlassianProvider) resetIssueActivityCache() {
	a.issueActivityLoaded = false
	a.issueActivityRows = nil
	a.issueCommentRows = nil
	a.issueChangelogRows = nil
	a.issueActivityErr = nil
}

func atlassianStringArray(value interface{}) []string {
	switch typed := value.(type) {
	case []interface{}:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(providerStringValue(item))
			if text == "" {
				continue
			}
			items = append(items, text)
		}
		return items
	case []string:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(item)
			if text == "" {
				continue
			}
			items = append(items, text)
		}
		return items
	default:
		return nil
	}
}

func atlassianComponentNames(value interface{}) []string {
	components, ok := value.([]interface{})
	if !ok {
		return nil
	}
	names := make([]string, 0, len(components))
	for _, component := range components {
		normalized := atlassianMap(component)
		name := firstAtlassianString(normalized, "name")
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	return names
}
