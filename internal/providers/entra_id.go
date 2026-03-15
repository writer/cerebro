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

// EntraIDProvider syncs identity data from Microsoft Entra ID (Azure AD)
type EntraIDProvider struct {
	*BaseProvider
	tenantID     string
	clientID     string
	clientSecret string
	accessToken  string
	tokenExpiry  time.Time
	client       *http.Client
}

func NewEntraIDProvider() *EntraIDProvider {
	return &EntraIDProvider{
		BaseProvider: NewBaseProvider("entra_id", ProviderTypeIdentity),
		client:       newProviderHTTPClient(60 * time.Second),
	}
}

func (e *EntraIDProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := e.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	e.tenantID = e.GetConfigString("tenant_id")
	if e.tenantID == "" {
		return fmt.Errorf("entra_id tenant_id required")
	}

	e.clientID = e.GetConfigString("client_id")
	e.clientSecret = e.GetConfigString("client_secret")

	if e.clientID == "" || e.clientSecret == "" {
		return fmt.Errorf("entra_id client_id and client_secret required")
	}

	return nil
}

func (e *EntraIDProvider) Test(ctx context.Context) error {
	if err := e.ensureToken(ctx); err != nil {
		return err
	}
	_, err := e.request(ctx, "/v1.0/organization")
	return err
}

func (e *EntraIDProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "entra_users",
			Description: "Entra ID users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "user_principal_name", Type: "string"},
				{Name: "display_name", Type: "string"},
				{Name: "given_name", Type: "string"},
				{Name: "surname", Type: "string"},
				{Name: "mail", Type: "string"},
				{Name: "job_title", Type: "string"},
				{Name: "department", Type: "string"},
				{Name: "office_location", Type: "string"},
				{Name: "account_enabled", Type: "boolean"},
				{Name: "user_type", Type: "string"},
				{Name: "created_datetime", Type: "timestamp"},
				{Name: "last_sign_in_datetime", Type: "timestamp"},
				{Name: "on_premises_sync_enabled", Type: "boolean"},
				{Name: "mfa_registered", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "entra_groups",
			Description: "Entra ID groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "mail", Type: "string"},
				{Name: "mail_enabled", Type: "boolean"},
				{Name: "security_enabled", Type: "boolean"},
				{Name: "group_types", Type: "array"},
				{Name: "membership_rule", Type: "string"},
				{Name: "created_datetime", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "entra_service_principals",
			Description: "Entra ID service principals (apps)",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "app_id", Type: "string"},
				{Name: "display_name", Type: "string"},
				{Name: "service_principal_type", Type: "string"},
				{Name: "account_enabled", Type: "boolean"},
				{Name: "app_owner_organization_id", Type: "string"},
				{Name: "app_role_assignment_required", Type: "boolean"},
				{Name: "publisher_name", Type: "string"},
				{Name: "verified_publisher_display_name", Type: "string"},
				{Name: "verified_publisher_id", Type: "string"},
				{Name: "verified_publisher_added_datetime", Type: "timestamp"},
				{Name: "created_datetime", Type: "timestamp"},
				{Name: "tags", Type: "array"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "entra_oauth2_permission_grants",
			Description: "Entra ID delegated OAuth permission grants",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "client_id", Type: "string"},
				{Name: "consent_type", Type: "string"},
				{Name: "principal_id", Type: "string"},
				{Name: "resource_id", Type: "string"},
				{Name: "scope", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "entra_conditional_access_policies",
			Description: "Entra ID conditional access policies",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "created_datetime", Type: "timestamp"},
				{Name: "modified_datetime", Type: "timestamp"},
				{Name: "conditions", Type: "json"},
				{Name: "grant_controls", Type: "json"},
				{Name: "session_controls", Type: "json"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "entra_sign_in_logs",
			Description: "Entra ID sign-in logs",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "user_id", Type: "string"},
				{Name: "user_principal_name", Type: "string"},
				{Name: "app_id", Type: "string"},
				{Name: "app_display_name", Type: "string"},
				{Name: "ip_address", Type: "string"},
				{Name: "client_app_used", Type: "string"},
				{Name: "conditional_access_status", Type: "string"},
				{Name: "is_interactive", Type: "boolean"},
				{Name: "risk_level_aggregated", Type: "string"},
				{Name: "risk_state", Type: "string"},
				{Name: "status", Type: "json"},
				{Name: "created_datetime", Type: "timestamp"},
				{Name: "location", Type: "json"},
				{Name: "device_detail", Type: "json"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "entra_risky_users",
			Description: "Entra ID risky users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "user_principal_name", Type: "string"},
				{Name: "user_display_name", Type: "string"},
				{Name: "risk_level", Type: "string"},
				{Name: "risk_state", Type: "string"},
				{Name: "risk_detail", Type: "string"},
				{Name: "risk_last_updated_datetime", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "entra_directory_roles",
			Description: "Entra ID directory roles and assignments",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "is_built_in", Type: "boolean"},
				{Name: "is_enabled", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "entra_role_assignments",
			Description: "Entra ID role assignments",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "principal_id", Type: "string"},
				{Name: "role_definition_id", Type: "string"},
				{Name: "directory_scope_id", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "entra_audit_logs",
			Description: "Entra ID directory audit logs",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "activity_display_name", Type: "string"},
				{Name: "activity_datetime", Type: "timestamp"},
				{Name: "logged_by_service", Type: "string"},
				{Name: "operation_type", Type: "string"},
				{Name: "result", Type: "string"},
				{Name: "result_reason", Type: "string"},
				{Name: "category", Type: "string"},
				{Name: "correlation_id", Type: "string"},
				{Name: "initiated_by", Type: "json"},
				{Name: "target_resources", Type: "json"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "entra_sign_ins",
			Description: "Entra ID sign-in activity logs",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "created_datetime", Type: "timestamp"},
				{Name: "user_display_name", Type: "string"},
				{Name: "user_principal_name", Type: "string"},
				{Name: "user_id", Type: "string"},
				{Name: "app_id", Type: "string"},
				{Name: "app_display_name", Type: "string"},
				{Name: "ip_address", Type: "string"},
				{Name: "client_app_used", Type: "string"},
				{Name: "conditional_access_status", Type: "string"},
				{Name: "is_interactive", Type: "boolean"},
				{Name: "risk_detail", Type: "string"},
				{Name: "risk_level_aggregated", Type: "string"},
				{Name: "risk_level_during_signin", Type: "string"},
				{Name: "risk_state", Type: "string"},
				{Name: "resource_display_name", Type: "string"},
				{Name: "status", Type: "json"},
				{Name: "device_detail", Type: "json"},
				{Name: "location", Type: "json"},
				{Name: "mfa_detail", Type: "json"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "entra_app_role_assignments",
			Description: "Entra ID app role assignments",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "app_role_id", Type: "string"},
				{Name: "created_datetime", Type: "timestamp"},
				{Name: "principal_display_name", Type: "string"},
				{Name: "principal_id", Type: "string"},
				{Name: "principal_type", Type: "string"},
				{Name: "resource_display_name", Type: "string"},
				{Name: "resource_id", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (e *EntraIDProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(e.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (e *EntraIDProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  e.Name(),
		StartedAt: start,
	}

	if err := e.ensureToken(ctx); err != nil {
		result.Errors = append(result.Errors, "auth: "+err.Error())
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(start)
		return result, err
	}

	// Sync users
	users, err := e.syncUsers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "users: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *users)
		result.TotalRows += users.Rows
	}

	// Sync groups
	groups, err := e.syncGroups(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "groups: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *groups)
		result.TotalRows += groups.Rows
	}

	// Sync service principals
	servicePrincipals, err := e.syncServicePrincipals(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "service_principals: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *servicePrincipals)
		result.TotalRows += servicePrincipals.Rows
	}

	// Sync delegated OAuth permission grants
	oauth2PermissionGrants, err := e.syncOAuth2PermissionGrants(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "oauth2_permission_grants: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *oauth2PermissionGrants)
		result.TotalRows += oauth2PermissionGrants.Rows
	}

	// Sync conditional access policies
	caPolicies, err := e.syncConditionalAccessPolicies(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "conditional_access_policies: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *caPolicies)
		result.TotalRows += caPolicies.Rows
	}

	// Sync risky users
	riskyUsers, err := e.syncRiskyUsers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "risky_users: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *riskyUsers)
		result.TotalRows += riskyUsers.Rows
	}

	// Sync directory roles
	roles, err := e.syncDirectoryRoles(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "directory_roles: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *roles)
		result.TotalRows += roles.Rows
	}

	// Sync role assignments
	roleAssignments, err := e.syncRoleAssignments(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "role_assignments: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *roleAssignments)
		result.TotalRows += roleAssignments.Rows
	}

	// Sync audit logs (last 7 days)
	auditLogs, err := e.syncAuditLogs(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "audit_logs: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *auditLogs)
		result.TotalRows += auditLogs.Rows
	}

	// Sync sign-in logs (last 7 days)
	signInLogs, err := e.syncSignInLogs(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "sign_in_logs: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *signInLogs)
		result.TotalRows += signInLogs.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (e *EntraIDProvider) ensureToken(ctx context.Context) error {
	if e.accessToken != "" && time.Now().Before(e.tokenExpiry) {
		return nil
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", e.tenantID)

	data := url.Values{}
	data.Set("client_id", e.clientID)
	data.Set("client_secret", e.clientSecret)
	data.Set("scope", "https://graph.microsoft.com/.default")
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("entra ID auth error %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return err
	}

	e.accessToken = tokenResp.AccessToken
	e.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)

	return nil
}

func (e *EntraIDProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := e.schemaFor("entra_users")
	result := &TableResult{Name: "entra_users"}
	if err != nil {
		return result, err
	}

	users, err := e.listAll(ctx, "/v1.0/users?$select=id,userPrincipalName,displayName,givenName,surname,mail,jobTitle,department,officeLocation,accountEnabled,userType,createdDateTime,signInActivity,onPremisesSyncEnabled")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		row := normalizeEntraRow(user)
		rows = append(rows, row)
	}

	return e.syncTable(ctx, schema, rows)
}

func (e *EntraIDProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := e.schemaFor("entra_groups")
	result := &TableResult{Name: "entra_groups"}
	if err != nil {
		return result, err
	}

	groups, err := e.listAll(ctx, "/v1.0/groups?$select=id,displayName,description,mail,mailEnabled,securityEnabled,groupTypes,membershipRule,createdDateTime")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		rows = append(rows, normalizeEntraRow(group))
	}

	return e.syncTable(ctx, schema, rows)
}

func (e *EntraIDProvider) syncServicePrincipals(ctx context.Context) (*TableResult, error) {
	schema, err := e.schemaFor("entra_service_principals")
	result := &TableResult{Name: "entra_service_principals"}
	if err != nil {
		return result, err
	}

	sps, err := e.listAll(ctx, "/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,appRoleAssignmentRequired,publisherName,verifiedPublisher,createdDateTime,tags")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(sps))
	for _, sp := range sps {
		rows = append(rows, normalizeEntraRow(sp))
	}

	return e.syncTable(ctx, schema, rows)
}

func (e *EntraIDProvider) syncOAuth2PermissionGrants(ctx context.Context) (*TableResult, error) {
	schema, err := e.schemaFor("entra_oauth2_permission_grants")
	result := &TableResult{Name: "entra_oauth2_permission_grants"}
	if err != nil {
		return result, err
	}

	grants, err := e.listAll(ctx, "/v1.0/oauth2PermissionGrants?$select=id,clientId,consentType,principalId,resourceId,scope")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(grants))
	for _, grant := range grants {
		rows = append(rows, normalizeEntraRow(grant))
	}

	return e.syncTable(ctx, schema, rows)
}

func (e *EntraIDProvider) syncConditionalAccessPolicies(ctx context.Context) (*TableResult, error) {
	schema, err := e.schemaFor("entra_conditional_access_policies")
	result := &TableResult{Name: "entra_conditional_access_policies"}
	if err != nil {
		return result, err
	}

	policies, err := e.listAll(ctx, "/v1.0/identity/conditionalAccess/policies")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(policies))
	for _, policy := range policies {
		rows = append(rows, normalizeEntraRow(policy))
	}

	return e.syncTable(ctx, schema, rows)
}

func (e *EntraIDProvider) syncRiskyUsers(ctx context.Context) (*TableResult, error) {
	schema, err := e.schemaFor("entra_risky_users")
	result := &TableResult{Name: "entra_risky_users"}
	if err != nil {
		return result, err
	}

	users, err := e.listAll(ctx, "/v1.0/identityProtection/riskyUsers?$filter=riskState ne 'dismissed' and riskState ne 'remediated'")
	if err != nil {
		// This may fail if Identity Protection is not licensed
		return e.syncTable(ctx, schema, nil)
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		rows = append(rows, normalizeEntraRow(user))
	}

	return e.syncTable(ctx, schema, rows)
}

func (e *EntraIDProvider) syncDirectoryRoles(ctx context.Context) (*TableResult, error) {
	schema, err := e.schemaFor("entra_directory_roles")
	result := &TableResult{Name: "entra_directory_roles"}
	if err != nil {
		return result, err
	}

	roles, err := e.listAll(ctx, "/v1.0/directoryRoles")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(roles))
	for _, role := range roles {
		rows = append(rows, normalizeEntraRow(role))
	}

	return e.syncTable(ctx, schema, rows)
}

func (e *EntraIDProvider) syncRoleAssignments(ctx context.Context) (*TableResult, error) {
	schema, err := e.schemaFor("entra_role_assignments")
	result := &TableResult{Name: "entra_role_assignments"}
	if err != nil {
		return result, err
	}

	assignments, err := e.listAll(ctx, "/v1.0/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(assignments))
	for _, assignment := range assignments {
		rows = append(rows, normalizeEntraRow(assignment))
	}

	return e.syncTable(ctx, schema, rows)
}

func (e *EntraIDProvider) syncAuditLogs(ctx context.Context) (*TableResult, error) {
	schema, err := e.schemaFor("entra_audit_logs")
	result := &TableResult{Name: "entra_audit_logs"}
	if err != nil {
		return result, err
	}

	// Get audit logs from last 7 days
	sevenDaysAgo := time.Now().AddDate(0, 0, -7).Format("2006-01-02T15:04:05Z")
	path := fmt.Sprintf("/v1.0/auditLogs/directoryAudits?$filter=activityDateTime ge %s&$top=500", sevenDaysAgo)

	logs, err := e.listAll(ctx, path)
	if err != nil {
		// May fail if not licensed for audit logs
		return e.syncTable(ctx, schema, nil)
	}

	rows := make([]map[string]interface{}, 0, len(logs))
	for _, logEntry := range logs {
		rows = append(rows, normalizeEntraRow(logEntry))
	}

	return e.syncTable(ctx, schema, rows)
}

func (e *EntraIDProvider) syncSignInLogs(ctx context.Context) (*TableResult, error) {
	schema, err := e.schemaFor("entra_sign_ins")
	result := &TableResult{Name: "entra_sign_ins"}
	if err != nil {
		return result, err
	}

	// Get sign-in logs from last 7 days
	sevenDaysAgo := time.Now().AddDate(0, 0, -7).Format("2006-01-02T15:04:05Z")
	path := fmt.Sprintf("/v1.0/auditLogs/signIns?$filter=createdDateTime ge %s&$top=500", sevenDaysAgo)

	logs, err := e.listAll(ctx, path)
	if err != nil {
		// May fail if not licensed for sign-in logs
		return e.syncTable(ctx, schema, nil)
	}

	rows := make([]map[string]interface{}, 0, len(logs))
	for _, logEntry := range logs {
		rows = append(rows, normalizeEntraRow(logEntry))
	}

	return e.syncTable(ctx, schema, rows)
}

func (e *EntraIDProvider) listAll(ctx context.Context, path string) ([]map[string]interface{}, error) {
	var allItems []map[string]interface{}
	nextLink := path

	for nextLink != "" {
		body, err := e.request(ctx, nextLink)
		if err != nil {
			return nil, err
		}

		var resp struct {
			Value    []map[string]interface{} `json:"value"`
			NextLink string                   `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		allItems = append(allItems, resp.Value...)

		// Handle pagination
		if resp.NextLink != "" {
			nextLink = strings.TrimPrefix(resp.NextLink, "https://graph.microsoft.com")
		} else {
			nextLink = ""
		}
	}

	return allItems, nil
}

func (e *EntraIDProvider) request(ctx context.Context, path string) ([]byte, error) {
	if err := e.ensureToken(ctx); err != nil {
		return nil, err
	}

	urlStr := "https://graph.microsoft.com" + path
	if strings.HasPrefix(path, "https://") {
		urlStr = path
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+e.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("entra ID API error %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func normalizeEntraRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}

	if signInActivity, ok := normalized["sign_in_activity"].(map[string]interface{}); ok {
		if lastSignIn, ok := signInActivity["last_sign_in_datetime"]; ok {
			normalized["last_sign_in_datetime"] = lastSignIn
		}
	}
	if verifiedPublisher, ok := normalized["verified_publisher"].(map[string]interface{}); ok {
		if displayName, ok := verifiedPublisher["display_name"]; ok {
			normalized["verified_publisher_display_name"] = displayName
		}
		if verifiedPublisherID, ok := verifiedPublisher["verified_publisher_id"]; ok {
			normalized["verified_publisher_id"] = verifiedPublisherID
		}
		if addedDateTime, ok := verifiedPublisher["added_date_time"]; ok {
			normalized["verified_publisher_added_datetime"] = addedDateTime
		}
	}

	return normalized
}

// GetUsersWithoutMFA returns users without MFA registered
func (e *EntraIDProvider) GetUsersWithoutMFA(users []map[string]interface{}) []map[string]interface{} {
	var noMFA []map[string]interface{}

	for _, user := range users {
		// Skip disabled accounts
		if enabled, _ := user["accountEnabled"].(bool); !enabled {
			continue
		}

		// Check MFA registration
		if mfa, _ := user["mfaRegistered"].(bool); !mfa {
			noMFA = append(noMFA, user)
		}
	}

	return noMFA
}

// GetStaleUsers returns users who haven't signed in recently
func (e *EntraIDProvider) GetStaleUsers(users []map[string]interface{}, staleDays int) []map[string]interface{} {
	cutoff := time.Now().AddDate(0, 0, -staleDays)
	var stale []map[string]interface{}

	for _, user := range users {
		// Skip disabled accounts
		if enabled, _ := user["accountEnabled"].(bool); !enabled {
			continue
		}

		signInActivity, _ := user["signInActivity"].(map[string]interface{})
		if signInActivity == nil {
			stale = append(stale, user)
			continue
		}

		lastSignIn, _ := signInActivity["lastSignInDateTime"].(string)
		if lastSignIn == "" {
			stale = append(stale, user)
			continue
		}

		t, err := time.Parse(time.RFC3339, lastSignIn)
		if err == nil && t.Before(cutoff) {
			stale = append(stale, user)
		}
	}

	return stale
}

// GetGlobalAdmins returns users with Global Administrator role
func (e *EntraIDProvider) GetGlobalAdmins(roleAssignments []map[string]interface{}, globalAdminRoleID string) []string {
	var adminIDs []string

	for _, assignment := range roleAssignments {
		roleID, _ := assignment["roleDefinitionId"].(string)
		if roleID == globalAdminRoleID {
			if principalID, ok := assignment["principalId"].(string); ok {
				adminIDs = append(adminIDs, principalID)
			}
		}
	}

	return adminIDs
}
