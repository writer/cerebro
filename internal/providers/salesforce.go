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

// SalesforceProvider syncs data from Salesforce
type SalesforceProvider struct {
	*BaseProvider
	instanceURL   string
	clientID      string
	clientSecret  string
	username      string
	password      string
	securityToken string
	accessToken   string
	client        *http.Client
}

func NewSalesforceProvider() *SalesforceProvider {
	return &SalesforceProvider{
		BaseProvider: NewBaseProvider("salesforce", ProviderTypeSaaS),
		client:       &http.Client{Timeout: 60 * time.Second},
	}
}

func (s *SalesforceProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := s.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	s.instanceURL = s.GetConfigString("instance_url")
	if s.instanceURL == "" {
		return fmt.Errorf("salesforce instance_url required")
	}

	s.clientID = s.GetConfigString("client_id")
	s.clientSecret = s.GetConfigString("client_secret")
	s.username = s.GetConfigString("username")
	s.password = s.GetConfigString("password")
	s.securityToken = s.GetConfigString("security_token")

	if s.clientID == "" || s.clientSecret == "" {
		return fmt.Errorf("salesforce client_id and client_secret required")
	}

	return nil
}

func (s *SalesforceProvider) Test(ctx context.Context) error {
	if err := s.ensureToken(ctx); err != nil {
		return err
	}
	_, err := s.request(ctx, "/services/data/v59.0/")
	return err
}

func (s *SalesforceProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "salesforce_users",
			Description: "Salesforce user accounts",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "username", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "first_name", Type: "string"},
				{Name: "last_name", Type: "string"},
				{Name: "is_active", Type: "boolean"},
				{Name: "user_type", Type: "string"},
				{Name: "profile_id", Type: "string"},
				{Name: "profile_name", Type: "string"},
				{Name: "role_id", Type: "string"},
				{Name: "role_name", Type: "string"},
				{Name: "last_login_date", Type: "timestamp"},
				{Name: "created_date", Type: "timestamp"},
				{Name: "last_modified_date", Type: "timestamp"},
				{Name: "federation_identifier", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "salesforce_profiles",
			Description: "Salesforce user profiles",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "user_license_id", Type: "string"},
				{Name: "user_type", Type: "string"},
				{Name: "permissions_api_enabled", Type: "boolean"},
				{Name: "permissions_view_all_data", Type: "boolean"},
				{Name: "permissions_modify_all_data", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "salesforce_permission_sets",
			Description: "Salesforce permission sets",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "label", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "is_custom", Type: "boolean"},
				{Name: "permissions_api_enabled", Type: "boolean"},
				{Name: "permissions_view_all_data", Type: "boolean"},
				{Name: "permissions_modify_all_data", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "salesforce_permission_set_assignments",
			Description: "Salesforce permission set assignments to users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "assignee_id", Type: "string"},
				{Name: "permission_set_id", Type: "string"},
				{Name: "permission_set_name", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "salesforce_login_history",
			Description: "Salesforce user login history",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "user_id", Type: "string"},
				{Name: "login_time", Type: "timestamp"},
				{Name: "login_type", Type: "string"},
				{Name: "source_ip", Type: "string"},
				{Name: "login_url", Type: "string"},
				{Name: "browser", Type: "string"},
				{Name: "platform", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "application", Type: "string"},
				{Name: "client_version", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "salesforce_connected_apps",
			Description: "Salesforce connected applications",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "contact_email", Type: "string"},
				{Name: "options_allow_admin_approved_users_only", Type: "boolean"},
				{Name: "options_refresh_token_validity_metric", Type: "string"},
				{Name: "created_date", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "salesforce_setup_audit_trail",
			Description: "Salesforce setup audit trail for admin changes",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "action", Type: "string"},
				{Name: "section", Type: "string"},
				{Name: "created_by_id", Type: "string"},
				{Name: "created_date", Type: "timestamp"},
				{Name: "display", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (s *SalesforceProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  s.Name(),
		StartedAt: start,
	}

	if err := s.ensureToken(ctx); err != nil {
		result.Errors = append(result.Errors, "auth: "+err.Error())
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(start)
		return result, err
	}

	// Sync users
	users, err := s.syncUsers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "users: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *users)
		result.TotalRows += users.Rows
	}

	// Sync profiles
	profiles, err := s.syncProfiles(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "profiles: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *profiles)
		result.TotalRows += profiles.Rows
	}

	// Sync permission sets
	permSets, err := s.syncPermissionSets(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "permission_sets: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *permSets)
		result.TotalRows += permSets.Rows
	}

	// Sync login history
	logins, err := s.syncLoginHistory(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "login_history: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *logins)
		result.TotalRows += logins.Rows
	}

	// Sync setup audit trail
	audit, err := s.syncSetupAuditTrail(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "setup_audit_trail: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *audit)
		result.TotalRows += audit.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (s *SalesforceProvider) ensureToken(ctx context.Context) error {
	if s.accessToken != "" {
		return nil
	}

	tokenURL := "https://login.salesforce.com/services/oauth2/token"

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", s.clientID)
	data.Set("client_secret", s.clientSecret)
	data.Set("username", s.username)
	data.Set("password", s.password+s.securityToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("salesforce auth error %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		InstanceURL string `json:"instance_url"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return err
	}

	s.accessToken = tokenResp.AccessToken
	if tokenResp.InstanceURL != "" {
		s.instanceURL = tokenResp.InstanceURL
	}

	return nil
}

func (s *SalesforceProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "salesforce_users"}

	query := "SELECT Id, Username, Email, Name, FirstName, LastName, IsActive, UserType, ProfileId, Profile.Name, UserRoleId, UserRole.Name, LastLoginDate, CreatedDate, LastModifiedDate, FederationIdentifier FROM User"
	records, err := s.queryAll(ctx, query)
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(records))
	result.Inserted = result.Rows
	return result, nil
}

func (s *SalesforceProvider) syncProfiles(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "salesforce_profiles"}

	query := "SELECT Id, Name, Description, UserLicenseId, UserType, PermissionsApiEnabled, PermissionsViewAllData, PermissionsModifyAllData FROM Profile"
	records, err := s.queryAll(ctx, query)
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(records))
	result.Inserted = result.Rows
	return result, nil
}

func (s *SalesforceProvider) syncPermissionSets(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "salesforce_permission_sets"}

	query := "SELECT Id, Name, Label, Description, IsCustom, PermissionsApiEnabled, PermissionsViewAllData, PermissionsModifyAllData FROM PermissionSet"
	records, err := s.queryAll(ctx, query)
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(records))
	result.Inserted = result.Rows
	return result, nil
}

func (s *SalesforceProvider) syncLoginHistory(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "salesforce_login_history"}

	// Get login history from last 30 days
	query := "SELECT Id, UserId, LoginTime, LoginType, SourceIp, LoginUrl, Browser, Platform, Status, Application, ClientVersion FROM LoginHistory WHERE LoginTime >= LAST_N_DAYS:30 ORDER BY LoginTime DESC LIMIT 10000"
	records, err := s.queryAll(ctx, query)
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(records))
	result.Inserted = result.Rows
	return result, nil
}

func (s *SalesforceProvider) syncSetupAuditTrail(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "salesforce_setup_audit_trail"}

	// Get audit trail from last 30 days
	query := "SELECT Id, Action, Section, CreatedById, CreatedDate, Display FROM SetupAuditTrail WHERE CreatedDate >= LAST_N_DAYS:30 ORDER BY CreatedDate DESC LIMIT 10000"
	records, err := s.queryAll(ctx, query)
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(records))
	result.Inserted = result.Rows
	return result, nil
}

func (s *SalesforceProvider) queryAll(ctx context.Context, query string) ([]map[string]interface{}, error) {
	var allRecords []map[string]interface{}
	nextURL := "/services/data/v59.0/query?q=" + url.QueryEscape(query)

	for nextURL != "" {
		body, err := s.request(ctx, nextURL)
		if err != nil {
			return nil, err
		}

		var resp struct {
			Records        []map[string]interface{} `json:"records"`
			NextRecordsURL string                   `json:"nextRecordsUrl"`
			Done           bool                     `json:"done"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		allRecords = append(allRecords, resp.Records...)

		if resp.Done || resp.NextRecordsURL == "" {
			break
		}
		nextURL = resp.NextRecordsURL
	}

	return allRecords, nil
}

func (s *SalesforceProvider) request(ctx context.Context, path string) ([]byte, error) {
	if err := s.ensureToken(ctx); err != nil {
		return nil, err
	}

	urlStr := s.instanceURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+s.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("salesforce API error %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetUsersWithExcessivePermissions returns users with ViewAllData or ModifyAllData permissions
func (s *SalesforceProvider) GetUsersWithExcessivePermissions(users []map[string]interface{}) []map[string]interface{} {
	var excessive []map[string]interface{}

	for _, user := range users {
		if active, _ := user["IsActive"].(bool); !active {
			continue
		}

		profile, _ := user["Profile"].(map[string]interface{})
		if profile != nil {
			viewAll, _ := profile["PermissionsViewAllData"].(bool)
			modifyAll, _ := profile["PermissionsModifyAllData"].(bool)
			if viewAll || modifyAll {
				excessive = append(excessive, user)
			}
		}
	}

	return excessive
}

// GetInactiveUsers returns users who haven't logged in within the specified days
func (s *SalesforceProvider) GetInactiveUsers(users []map[string]interface{}, inactiveDays int) []map[string]interface{} {
	cutoff := time.Now().AddDate(0, 0, -inactiveDays)
	var inactive []map[string]interface{}

	for _, user := range users {
		if active, _ := user["IsActive"].(bool); !active {
			continue
		}

		lastLogin, _ := user["LastLoginDate"].(string)
		if lastLogin == "" {
			inactive = append(inactive, user)
			continue
		}

		t, err := time.Parse(time.RFC3339, lastLogin)
		if err == nil && t.Before(cutoff) {
			inactive = append(inactive, user)
		}
	}

	return inactive
}
