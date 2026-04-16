package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OktaProvider syncs identity data from Okta
type OktaProvider struct {
	*BaseProvider
	domain   string
	apiToken string
	client   *http.Client
}

const (
	oktaFanoutWorkers    = 10
	oktaProgressLogEvery = 50
)

func NewOktaProvider() *OktaProvider {
	return &OktaProvider{
		BaseProvider: NewBaseProvider("okta", ProviderTypeIdentity),
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (o *OktaProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := o.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	o.domain = o.GetConfigString("domain")
	o.apiToken = o.GetConfigString("api_token")
	o.client = o.NewHTTPClient(30 * time.Second)

	return nil
}

func (o *OktaProvider) Test(ctx context.Context) error {
	_, err := o.request(ctx, "/api/v1/users?limit=1")
	return err
}

func (o *OktaProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "okta_users",
			Description: "Okta users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "login", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "first_name", Type: "string"},
				{Name: "last_name", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "created", Type: "timestamp"},
				{Name: "last_login", Type: "timestamp"},
				{Name: "is_admin", Type: "boolean"},
				{Name: "mfa_enrolled", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "okta_groups",
			Description: "Okta groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "created", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "okta_group_memberships",
			Description: "Okta group memberships",
			Columns: []ColumnSchema{
				{Name: "group_id", Type: "string", Required: true},
				{Name: "user_id", Type: "string", Required: true},
				{Name: "user_login", Type: "string"},
				{Name: "user_email", Type: "string"},
			},
			PrimaryKey: []string{"group_id", "user_id"},
		},
		{
			Name:        "okta_applications",
			Description: "Okta applications",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "label", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "sign_on_mode", Type: "string"},
				{Name: "sign_on_policy", Type: "object"},
				{Name: "created", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "okta_app_assignments",
			Description: "Okta app assignments",
			Columns: []ColumnSchema{
				{Name: "app_id", Type: "string", Required: true},
				{Name: "app_label", Type: "string"},
				{Name: "assignee_id", Type: "string", Required: true},
				{Name: "assignee_type", Type: "string", Required: true},
				{Name: "status", Type: "string"},
				{Name: "created", Type: "timestamp"},
			},
			PrimaryKey: []string{"app_id", "assignee_id", "assignee_type"},
		},
		{
			Name:        "okta_app_grants",
			Description: "Okta application OAuth scope consent grants",
			Columns: []ColumnSchema{
				{Name: "app_id", Type: "string", Required: true},
				{Name: "app_label", Type: "string"},
				{Name: "grant_id", Type: "string", Required: true},
				{Name: "issuer", Type: "string"},
				{Name: "scope_id", Type: "string"},
				{Name: "source", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "user_id", Type: "string"},
				{Name: "created", Type: "timestamp"},
				{Name: "last_updated", Type: "timestamp"},
			},
			PrimaryKey: []string{"app_id", "grant_id"},
		},
		{
			Name:        "okta_admin_roles",
			Description: "Okta admin role assignments",
			Columns: []ColumnSchema{
				{Name: "user_id", Type: "string", Required: true},
				{Name: "user_login", Type: "string"},
				{Name: "role_type", Type: "string", Required: true},
				{Name: "role_label", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "created", Type: "timestamp"},
			},
			PrimaryKey: []string{"user_id", "role_type", "role_label"},
		},
		{
			Name:        "okta_policy_passwords",
			Description: "Okta password policies",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "settings", Type: "object"},
				{Name: "created", Type: "timestamp"},
				{Name: "last_updated", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "okta_system_logs",
			Description: "Okta system log events",
			Columns: []ColumnSchema{
				{Name: "uuid", Type: "string", Required: true},
				{Name: "event_type", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "actor_id", Type: "string"},
				{Name: "actor_type", Type: "string"},
				{Name: "target_id", Type: "string"},
				{Name: "target_type", Type: "string"},
				{Name: "target_app_id", Type: "string"},
				{Name: "target_app_label", Type: "string"},
				{Name: "outcome", Type: "string"},
				{Name: "published", Type: "timestamp"},
			},
			PrimaryKey: []string{"uuid"},
		},
	}
}

func (o *OktaProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(o.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (o *OktaProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  o.Name(),
		StartedAt: start,
	}

	// Sync users
	users, err := o.syncUsers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "users: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *users)
		result.TotalRows += users.Rows
	}

	// Sync admin role assignments
	adminRoles, err := o.syncAdminRoles(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "admin_roles: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *adminRoles)
		result.TotalRows += adminRoles.Rows
	}

	// Sync groups
	groups, err := o.syncGroups(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "groups: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *groups)
		result.TotalRows += groups.Rows
	}

	// Sync group memberships
	groupMemberships, err := o.syncGroupMemberships(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "group_memberships: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *groupMemberships)
		result.TotalRows += groupMemberships.Rows
	}

	// Sync applications
	apps, err := o.syncApplications(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "applications: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *apps)
		result.TotalRows += apps.Rows
	}

	// Sync app assignments
	appAssignments, err := o.syncAppAssignments(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "app_assignments: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *appAssignments)
		result.TotalRows += appAssignments.Rows
	}

	appGrants, err := o.syncAppGrants(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "app_grants: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *appGrants)
		result.TotalRows += appGrants.Rows
	}

	// Sync password policies
	passwordPolicies, err := o.syncPasswordPolicies(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "password_policies: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *passwordPolicies)
		result.TotalRows += passwordPolicies.Rows
	}

	if opts.FullSync || opts.Since != nil {
		logs, err := o.syncSystemLogs(ctx, opts)
		if err != nil {
			result.Errors = append(result.Errors, "system_logs: "+err.Error())
		} else {
			result.Tables = append(result.Tables, *logs)
			result.TotalRows += logs.Rows
		}
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (o *OktaProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := o.schemaFor("okta_users")
	result := &TableResult{Name: "okta_users"}
	if err != nil {
		return result, err
	}

	users, err := o.requestAll(ctx, "/api/v1/users?limit=200")
	if err != nil {
		return result, err
	}

	adminSet := o.fetchAdminUserSet(ctx)

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		rows = append(rows, normalizeOktaUser(user))
	}

	type mfaResult struct {
		index    int
		enrolled bool
		ok       bool
	}

	workerCount := oktaFanoutWorkers
	if len(rows) < workerCount {
		workerCount = len(rows)
	}
	jobs := make(chan int, len(rows))
	results := make(chan mfaResult, len(rows))

	var wg sync.WaitGroup
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				id := asString(rows[i]["id"])
				if id == "" {
					continue
				}
				enrolled, ok := o.fetchUserMFAFactors(ctx, id)
				results <- mfaResult{index: i, enrolled: enrolled, ok: ok}
			}
		}()
	}

	for i := range rows {
		jobs <- i
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.ok {
			rows[r.index]["mfa_enrolled"] = r.enrolled
		}
	}

	for i, row := range rows {
		id := asString(row["id"])
		if id != "" {
			rows[i]["is_admin"] = adminSet[id]
		}
	}

	return o.syncTable(ctx, schema, rows)
}

// fetchAdminUserSet returns a set of user IDs that have admin role assignments,
// using the bulk endpoint instead of per-user calls.
func (o *OktaProvider) fetchAdminUserSet(ctx context.Context) map[string]bool {
	adminSet := make(map[string]bool)
	assignees, err := o.requestAll(ctx, "/api/v1/iam/assignees/users?limit=200")
	if err != nil {
		return adminSet
	}
	for _, assignee := range assignees {
		normalized := normalizeOktaRow(assignee)
		id := extractOktaAdminID(normalized)
		if id != "" {
			adminSet[id] = true
		}
	}
	return adminSet
}

func extractOktaAdminID(assignee map[string]interface{}) string {
	return firstNonEmptyString(
		getNestedString(assignee, "user", "id"),
		getNestedString(assignee, "assignee", "id"),
		asString(assignee["user_id"]),
		asString(assignee["id"]),
	)
}

// fetchUserMFAFactors checks MFA enrollment for a single user.
// This must remain per-user as there is no bulk Okta factors endpoint.
func (o *OktaProvider) fetchUserMFAFactors(ctx context.Context, userID string) (bool, bool) {
	factors, err := o.requestAll(ctx, fmt.Sprintf("/api/v1/users/%s/factors", userID))
	if err != nil {
		return false, false
	}
	if len(factors) == 0 {
		return false, true
	}
	for _, factor := range factors {
		normalized := normalizeOktaRow(factor)
		status := strings.ToLower(asString(normalized["status"]))
		if status == "" || status == "active" || status == "enrolled" || status == "enabled" {
			return true, true
		}
	}
	return false, true
}

func (o *OktaProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := o.schemaFor("okta_groups")
	result := &TableResult{Name: "okta_groups"}
	if err != nil {
		return result, err
	}

	groups, err := o.requestAll(ctx, "/api/v1/groups?limit=200")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		rows = append(rows, normalizeOktaGroup(group))
	}

	return o.syncTable(ctx, schema, rows)
}

func oktaWorkerCount(total int) int {
	if total <= 0 {
		return 0
	}
	workers := oktaFanoutWorkers
	if total < workers {
		workers = total
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func logOktaFanoutProgress(scope string, processed, total int64) {
	if total <= 0 {
		return
	}
	if processed%oktaProgressLogEvery != 0 && processed != total {
		return
	}
	slog.Info("okta sync progress", "scope", scope, "processed", processed, "total", total)
}

func (o *OktaProvider) syncGroupMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := o.schemaFor("okta_group_memberships")
	result := &TableResult{Name: "okta_group_memberships"}
	if err != nil {
		return result, err
	}

	groups, err := o.requestAll(ctx, "/api/v1/groups?limit=200")
	if err != nil {
		return result, err
	}

	if len(groups) == 0 {
		return o.syncTable(ctx, schema, nil)
	}

	type groupMembershipJob struct {
		groupID string
	}

	jobs := make(chan groupMembershipJob, len(groups))
	rows := make([]map[string]interface{}, 0, len(groups))
	workerCount := oktaWorkerCount(len(groups))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var processed int64
	total := int64(len(groups))

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				users, err := o.requestAll(ctx, fmt.Sprintf("/api/v1/groups/%s/users?limit=200", url.PathEscape(job.groupID)))
				if err != nil {
					slog.Warn("okta group membership sync failed", "group_id", job.groupID, "error", err)
					current := atomic.AddInt64(&processed, 1)
					logOktaFanoutProgress("group_memberships", current, total)
					continue
				}

				groupRows := make([]map[string]interface{}, 0, len(users))
				for _, user := range users {
					normalized := normalizeOktaRow(user)
					userID := asString(normalized["id"])
					if userID == "" {
						continue
					}
					groupRows = append(groupRows, map[string]interface{}{
						"group_id":   job.groupID,
						"user_id":    userID,
						"user_login": getNestedString(normalized, "profile", "login"),
						"user_email": getNestedString(normalized, "profile", "email"),
					})
				}

				if len(groupRows) > 0 {
					mu.Lock()
					rows = append(rows, groupRows...)
					mu.Unlock()
				}

				current := atomic.AddInt64(&processed, 1)
				logOktaFanoutProgress("group_memberships", current, total)
			}
		}()
	}

	for _, group := range groups {
		normalized := normalizeOktaRow(group)
		groupID := asString(normalized["id"])
		if groupID == "" {
			continue
		}
		jobs <- groupMembershipJob{groupID: groupID}
	}
	close(jobs)
	wg.Wait()

	return o.syncTable(ctx, schema, rows)
}

func (o *OktaProvider) syncAppAssignments(ctx context.Context) (*TableResult, error) {
	schema, err := o.schemaFor("okta_app_assignments")
	result := &TableResult{Name: "okta_app_assignments"}
	if err != nil {
		return result, err
	}

	apps, err := o.requestAll(ctx, "/api/v1/apps?limit=200")
	if err != nil {
		return result, err
	}

	if len(apps) == 0 {
		return o.syncTable(ctx, schema, nil)
	}

	type appAssignmentJob struct {
		appID    string
		appLabel string
	}

	jobs := make(chan appAssignmentJob, len(apps))
	rows := make([]map[string]interface{}, 0, len(apps))
	workerCount := oktaWorkerCount(len(apps))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var processed int64
	total := int64(len(apps))

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				appRows := make([]map[string]interface{}, 0)

				userAssignments, err := o.requestAll(ctx, fmt.Sprintf("/api/v1/apps/%s/users?limit=200", url.PathEscape(job.appID)))
				if err != nil {
					slog.Warn("okta app user assignment sync failed", "app_id", job.appID, "error", err)
				} else {
					for _, assignment := range userAssignments {
						normalized := normalizeOktaRow(assignment)
						assigneeID := asString(normalized["id"])
						if assigneeID == "" {
							continue
						}
						appRows = append(appRows, map[string]interface{}{
							"app_id":        job.appID,
							"app_label":     job.appLabel,
							"assignee_id":   assigneeID,
							"assignee_type": "USER",
							"status":        asString(normalized["status"]),
							"created":       firstNonEmptyString(asString(normalized["created"]), asString(normalized["last_updated"])),
						})
					}
				}

				groupAssignments, err := o.requestAll(ctx, fmt.Sprintf("/api/v1/apps/%s/groups?limit=200", url.PathEscape(job.appID)))
				if err != nil {
					slog.Warn("okta app group assignment sync failed", "app_id", job.appID, "error", err)
				} else {
					for _, assignment := range groupAssignments {
						normalized := normalizeOktaRow(assignment)
						assigneeID := asString(normalized["id"])
						if assigneeID == "" {
							continue
						}
						appRows = append(appRows, map[string]interface{}{
							"app_id":        job.appID,
							"app_label":     job.appLabel,
							"assignee_id":   assigneeID,
							"assignee_type": "GROUP",
							"status":        asString(normalized["status"]),
							"created":       firstNonEmptyString(asString(normalized["created"]), asString(normalized["last_updated"])),
						})
					}
				}

				if len(appRows) > 0 {
					mu.Lock()
					rows = append(rows, appRows...)
					mu.Unlock()
				}

				current := atomic.AddInt64(&processed, 1)
				logOktaFanoutProgress("app_assignments", current, total)
			}
		}()
	}

	for _, app := range apps {
		normalized := normalizeOktaRow(app)
		appID := asString(normalized["id"])
		if appID == "" {
			continue
		}
		jobs <- appAssignmentJob{
			appID:    appID,
			appLabel: asString(normalized["label"]),
		}
	}
	close(jobs)
	wg.Wait()

	return o.syncTable(ctx, schema, rows)
}

func (o *OktaProvider) syncAppGrants(ctx context.Context) (*TableResult, error) {
	schema, err := o.schemaFor("okta_app_grants")
	result := &TableResult{Name: "okta_app_grants"}
	if err != nil {
		return result, err
	}

	apps, err := o.requestAll(ctx, "/api/v1/apps?limit=200")
	if err != nil {
		return result, err
	}

	if len(apps) == 0 {
		return o.syncTable(ctx, schema, nil)
	}

	type appGrantJob struct {
		appID    string
		appLabel string
	}

	jobs := make(chan appGrantJob, len(apps))
	rows := make([]map[string]interface{}, 0, len(apps))
	workerCount := oktaWorkerCount(len(apps))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var processed int64
	total := int64(len(apps))

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				grants, err := o.requestAll(ctx, fmt.Sprintf("/api/v1/apps/%s/grants?limit=200&expand=scope", url.PathEscape(job.appID)))
				if err != nil {
					slog.Warn("okta app grant sync failed", "app_id", job.appID, "error", err)
					current := atomic.AddInt64(&processed, 1)
					logOktaFanoutProgress("app_grants", current, total)
					continue
				}

				appRows := make([]map[string]interface{}, 0, len(grants))
				for _, grant := range grants {
					row := normalizeOktaAppGrant(grant)
					if asString(row["grant_id"]) == "" {
						continue
					}
					row["app_id"] = job.appID
					row["app_label"] = job.appLabel
					appRows = append(appRows, row)
				}

				if len(appRows) > 0 {
					mu.Lock()
					rows = append(rows, appRows...)
					mu.Unlock()
				}

				current := atomic.AddInt64(&processed, 1)
				logOktaFanoutProgress("app_grants", current, total)
			}
		}()
	}

	for _, app := range apps {
		normalized := normalizeOktaRow(app)
		appID := asString(normalized["id"])
		if appID == "" {
			continue
		}
		jobs <- appGrantJob{
			appID:    appID,
			appLabel: asString(normalized["label"]),
		}
	}
	close(jobs)
	wg.Wait()

	return o.syncTable(ctx, schema, rows)
}

func (o *OktaProvider) syncAdminRoles(ctx context.Context) (*TableResult, error) {
	schema, err := o.schemaFor("okta_admin_roles")
	result := &TableResult{Name: "okta_admin_roles"}
	if err != nil {
		return result, err
	}

	adminSet := o.fetchAdminUserSet(ctx)
	if len(adminSet) == 0 {
		return o.syncTable(ctx, schema, nil)
	}

	users, err := o.requestAll(ctx, "/api/v1/users?limit=200")
	if err != nil {
		return result, err
	}

	userLoginByID := make(map[string]string, len(users))
	for _, user := range users {
		normalized := normalizeOktaRow(user)
		userID := asString(normalized["id"])
		if userID == "" {
			continue
		}
		userLoginByID[userID] = getNestedString(normalized, "profile", "login")
	}

	userIDs := make([]string, 0, len(adminSet))
	for userID := range adminSet {
		if userID == "" {
			continue
		}
		userIDs = append(userIDs, userID)
	}
	sort.Strings(userIDs)

	jobs := make(chan string, len(userIDs))
	rows := make([]map[string]interface{}, 0, len(userIDs))
	workerCount := oktaWorkerCount(len(userIDs))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var processed int64
	total := int64(len(userIDs))

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for userID := range jobs {
				roles, err := o.requestAll(ctx, fmt.Sprintf("/api/v1/users/%s/roles?limit=200", url.PathEscape(userID)))
				if err != nil {
					slog.Warn("okta admin role sync failed", "user_id", userID, "error", err)
					current := atomic.AddInt64(&processed, 1)
					logOktaFanoutProgress("admin_roles", current, total)
					continue
				}

				roleRows := make([]map[string]interface{}, 0, len(roles))
				for _, role := range roles {
					normalized := normalizeOktaRow(role)
					roleType := firstNonEmptyString(asString(normalized["type"]), asString(normalized["role_type"]))
					if roleType == "" {
						continue
					}
					roleRows = append(roleRows, map[string]interface{}{
						"user_id":    userID,
						"user_login": userLoginByID[userID],
						"role_type":  roleType,
						"role_label": firstNonEmptyString(asString(normalized["label"]), asString(normalized["display_name"]), asString(normalized["name"]), roleType),
						"status":     asString(normalized["status"]),
						"created":    firstNonEmptyString(asString(normalized["created"]), asString(normalized["last_updated"])),
					})
				}

				if len(roleRows) > 0 {
					mu.Lock()
					rows = append(rows, roleRows...)
					mu.Unlock()
				}

				current := atomic.AddInt64(&processed, 1)
				logOktaFanoutProgress("admin_roles", current, total)
			}
		}()
	}

	for _, userID := range userIDs {
		jobs <- userID
	}
	close(jobs)
	wg.Wait()

	return o.syncTable(ctx, schema, rows)
}

func (o *OktaProvider) syncApplications(ctx context.Context) (*TableResult, error) {
	schema, err := o.schemaFor("okta_applications")
	result := &TableResult{Name: "okta_applications"}
	if err != nil {
		return result, err
	}

	apps, err := o.requestAll(ctx, "/api/v1/apps?limit=200")
	if err != nil {
		return result, err
	}

	policyRulesMap := o.prefetchAccessPolicies(ctx)

	rows := make([]map[string]interface{}, 0, len(apps))
	for _, app := range apps {
		row := normalizeOktaApplication(app)
		id := asString(row["id"])
		if id != "" {
			if rules, ok := policyRulesMap[id]; ok {
				row["sign_on_policy"] = map[string]interface{}{"rules": rules}
			}
		}
		rows = append(rows, row)
	}

	return o.syncTable(ctx, schema, rows)
}

// prefetchAccessPolicies fetches all ACCESS_POLICY policies in one call,
// batch-fetches rules per policy, then builds a map of app ID -> rules.
// This turns N*M per-app calls into P+1 calls where P is the policy count.
func (o *OktaProvider) prefetchAccessPolicies(ctx context.Context) map[string][]interface{} {
	result := make(map[string][]interface{})

	policies, err := o.requestAll(ctx, "/api/v1/policies?type=ACCESS_POLICY")
	if err != nil {
		return result
	}

	for _, policy := range policies {
		normalized := normalizeOktaRow(policy)
		policyID := asString(normalized["id"])
		if policyID == "" {
			continue
		}

		rules, err := o.requestAll(ctx, fmt.Sprintf("/api/v1/policies/%s/rules", policyID))
		if err != nil {
			continue
		}

		normalizedRules := make([]interface{}, 0, len(rules))
		for _, rule := range rules {
			normalizedRules = append(normalizedRules, normalizeOktaRow(rule))
		}

		appIDs := extractOktaPolicyAppIDs(normalized)
		for _, appID := range appIDs {
			if appID == "" {
				continue
			}
			result[appID] = append(result[appID], normalizedRules...)
		}
	}

	return result
}

func extractOktaPolicyAppIDs(policy map[string]interface{}) []string {
	options := []interface{}{
		getNestedValue(policy, "conditions", "apps", "include"),
		getNestedValue(policy, "conditions", "app", "include"),
	}
	for _, value := range options {
		if value == nil {
			continue
		}
		ids := oktaStringSlice(value)
		if len(ids) > 0 {
			return ids
		}
	}
	return nil
}

func oktaStringSlice(value interface{}) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []interface{}:
		values := make([]string, 0, len(typed))
		for _, entry := range typed {
			switch item := entry.(type) {
			case string:
				if item != "" {
					values = append(values, item)
				}
			case map[string]interface{}:
				id := asString(item["id"])
				if id != "" {
					values = append(values, id)
				}
			default:
				value := asString(item)
				if value != "" {
					values = append(values, value)
				}
			}
		}
		return values
	case map[string]interface{}:
		if id := asString(typed["id"]); id != "" {
			return []string{id}
		}
	case string:
		if typed != "" {
			return []string{typed}
		}
	}
	return nil
}

func (o *OktaProvider) syncPasswordPolicies(ctx context.Context) (*TableResult, error) {
	schema, err := o.schemaFor("okta_policy_passwords")
	result := &TableResult{Name: "okta_policy_passwords"}
	if err != nil {
		return result, err
	}

	policies, err := o.requestAll(ctx, "/api/v1/policies?type=PASSWORD")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(policies))
	for _, policy := range policies {
		rows = append(rows, normalizeOktaPasswordPolicy(policy))
	}

	return o.syncTable(ctx, schema, rows)
}

func (o *OktaProvider) syncSystemLogs(ctx context.Context, opts SyncOptions) (*TableResult, error) {
	schema, err := o.schemaFor("okta_system_logs")
	result := &TableResult{Name: "okta_system_logs"}
	if err != nil {
		return result, err
	}

	path := "/api/v1/logs?limit=200"
	if opts.Since != nil {
		path = fmt.Sprintf("%s&since=%s", path, opts.Since.UTC().Format(time.RFC3339))
	}

	logs, err := o.requestAll(ctx, path)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(logs))
	for _, logEntry := range logs {
		rows = append(rows, normalizeOktaLog(logEntry))
	}

	return o.syncTable(ctx, schema, rows)
}

func normalizeOktaUser(user map[string]interface{}) map[string]interface{} {
	normalized := normalizeOktaRow(user)
	return map[string]interface{}{
		"id":         normalized["id"],
		"login":      getNestedString(normalized, "profile", "login"),
		"email":      getNestedString(normalized, "profile", "email"),
		"first_name": getNestedString(normalized, "profile", "first_name"),
		"last_name":  getNestedString(normalized, "profile", "last_name"),
		"status":     normalized["status"],
		"created":    normalized["created"],
		"last_login": normalized["last_login"],
	}
}

func normalizeOktaGroup(group map[string]interface{}) map[string]interface{} {
	normalized := normalizeOktaRow(group)
	return map[string]interface{}{
		"id":          normalized["id"],
		"name":        getNestedString(normalized, "profile", "name"),
		"description": getNestedString(normalized, "profile", "description"),
		"type":        normalized["type"],
		"created":     normalized["created"],
	}
}

func normalizeOktaApplication(app map[string]interface{}) map[string]interface{} {
	normalized := normalizeOktaRow(app)
	return map[string]interface{}{
		"id":           normalized["id"],
		"name":         normalized["name"],
		"label":        normalized["label"],
		"status":       normalized["status"],
		"sign_on_mode": normalized["sign_on_mode"],
		"created":      normalized["created"],
	}
}

func normalizeOktaAppGrant(grant map[string]interface{}) map[string]interface{} {
	normalized := normalizeOktaRow(grant)
	return map[string]interface{}{
		"grant_id":     normalized["id"],
		"issuer":       normalized["issuer"],
		"scope_id":     normalized["scope_id"],
		"source":       normalized["source"],
		"status":       normalized["status"],
		"user_id":      normalized["user_id"],
		"created":      normalized["created"],
		"last_updated": normalized["last_updated"],
	}
}

func normalizeOktaPasswordPolicy(policy map[string]interface{}) map[string]interface{} {
	normalized := normalizeOktaRow(policy)
	return map[string]interface{}{
		"id":           normalized["id"],
		"name":         normalized["name"],
		"description":  normalized["description"],
		"status":       normalized["status"],
		"settings":     normalized["settings"],
		"created":      normalized["created"],
		"last_updated": normalized["last_updated"],
	}
}

func normalizeOktaLog(entry map[string]interface{}) map[string]interface{} {
	normalized := normalizeOktaRow(entry)
	actorID := getNestedString(normalized, "actor", "id")
	actorType := getNestedString(normalized, "actor", "type")
	targetValue := getNestedValue(normalized, "target")
	targetID, targetType := extractOktaTarget(targetValue)
	targetAppID, targetAppLabel := extractOktaAppTarget(targetValue)
	outcome := getNestedString(normalized, "outcome", "result")
	if outcome == "" {
		outcome = asString(normalized["outcome"])
	}

	return map[string]interface{}{
		"uuid":             normalized["uuid"],
		"event_type":       normalized["event_type"],
		"severity":         normalized["severity"],
		"actor_id":         actorID,
		"actor_type":       actorType,
		"target_id":        targetID,
		"target_type":      targetType,
		"target_app_id":    targetAppID,
		"target_app_label": targetAppLabel,
		"outcome":          outcome,
		"published":        normalized["published"],
	}
}

func normalizeOktaRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func extractOktaTarget(value interface{}) (string, string) {
	switch typed := value.(type) {
	case []interface{}:
		for _, entry := range typed {
			target, ok := entry.(map[string]interface{})
			if !ok {
				continue
			}
			id := asString(target["id"])
			targetType := asString(target["type"])
			if id != "" || targetType != "" {
				return id, targetType
			}
		}
	case map[string]interface{}:
		return asString(typed["id"]), asString(typed["type"])
	}
	return "", ""
}

func extractOktaAppTarget(value interface{}) (string, string) {
	switch typed := value.(type) {
	case []interface{}:
		for _, entry := range typed {
			target, ok := entry.(map[string]interface{})
			if !ok {
				continue
			}
			targetType := strings.ToLower(strings.TrimSpace(asString(target["type"])))
			if !isOktaAppTargetType(targetType) {
				continue
			}
			return asString(target["id"]), firstNonEmptyString(asString(target["display_name"]), asString(target["alternate_id"]), asString(target["name"]))
		}
	case map[string]interface{}:
		targetType := strings.ToLower(strings.TrimSpace(asString(typed["type"])))
		if !isOktaAppTargetType(targetType) {
			return "", ""
		}
		return asString(typed["id"]), firstNonEmptyString(asString(typed["display_name"]), asString(typed["alternate_id"]), asString(typed["name"]))
	}

	return "", ""
}

func isOktaAppTargetType(targetType string) bool {
	switch strings.ToLower(strings.TrimSpace(targetType)) {
	case "app", "application", "appinstance", "oauth2client", "oauth_client":
		return true
	default:
		return false
	}
}

func (o *OktaProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := fmt.Sprintf("https://%s%s", o.domain, path)
	body, _, err := o.requestWithResponse(ctx, url)
	return body, err
}

func (o *OktaProvider) requestAll(ctx context.Context, path string) ([]map[string]interface{}, error) {
	nextURL := fmt.Sprintf("https://%s%s", o.domain, path)
	items := make([]map[string]interface{}, 0)
	guard := newPaginationGuard("okta", path)

	for nextURL != "" {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := guard.nextPage(); err != nil {
			return nil, err
		}

		body, headers, err := o.requestWithResponse(ctx, nextURL)
		if err != nil {
			return nil, err
		}

		var page []map[string]interface{}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}

		items = append(items, page...)
		nextURL = parseNextLink(headers.Get("Link"))
		if err := guard.nextToken(nextURL); err != nil {
			return nil, err
		}
	}

	return items, nil
}

func (o *OktaProvider) requestWithResponse(ctx context.Context, url string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Authorization", "SSWS "+o.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("okta API error %d: %s", resp.StatusCode, string(body))
	}

	o.waitForRateLimit(ctx, resp.Header)
	return body, resp.Header, nil
}

func (o *OktaProvider) waitForRateLimit(ctx context.Context, headers http.Header) {
	remaining, err := strconv.Atoi(headers.Get("X-Rate-Limit-Remaining"))
	if err != nil || remaining > 1 {
		return
	}
	wait, ok := rateLimitResetDelay(headers)
	if !ok || wait <= 0 {
		return
	}
	_ = o.sleepWithContext(ctx, wait)
}

func (o *OktaProvider) sleepWithContext(ctx context.Context, wait time.Duration) bool {
	if wait <= 0 {
		return true
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func parseNextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}

	links := strings.Split(linkHeader, ",")
	for _, link := range links {
		parts := strings.Split(strings.TrimSpace(link), ";")
		if len(parts) < 2 {
			continue
		}
		if !strings.Contains(parts[1], "rel=\"next\"") {
			continue
		}
		url := strings.TrimSpace(parts[0])
		url = strings.TrimPrefix(url, "<")
		url = strings.TrimSuffix(url, ">")
		return url
	}

	return ""
}
