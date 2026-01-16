package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WizProvider syncs cloud security data from Wiz
type WizProvider struct {
	*BaseProvider
	clientID     string
	clientSecret string
	authURL      string
	apiURL       string
	token        string
	tokenExpiry  time.Time
	client       *http.Client
}

func NewWizProvider() *WizProvider {
	return &WizProvider{
		BaseProvider: NewBaseProvider("wiz", ProviderTypeSaaS),
		authURL:      "https://auth.app.wiz.io/oauth/token",
		apiURL:       "https://api.us20.app.wiz.io/graphql",
		client:       &http.Client{Timeout: 60 * time.Second},
	}
}

func (w *WizProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := w.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	w.clientID = w.GetConfigString("client_id")
	w.clientSecret = w.GetConfigString("client_secret")
	if authURL := w.GetConfigString("auth_url"); authURL != "" {
		w.authURL = authURL
	}
	if apiURL := w.GetConfigString("api_url"); apiURL != "" {
		w.apiURL = apiURL
	}

	return nil
}

func (w *WizProvider) Test(ctx context.Context) error {
	_, err := w.authenticate(ctx)
	return err
}

func (w *WizProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "wiz_cloud_resources",
			Description: "Wiz discovered cloud resources",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "cloud_platform", Type: "string"},
				{Name: "cloud_provider_id", Type: "string"},
				{Name: "subscription_id", Type: "string"},
				{Name: "region", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "is_public", Type: "boolean"},
				{Name: "is_internet_facing", Type: "boolean"},
				{Name: "exposure_level", Type: "string"},
				{Name: "has_high_privilege", Type: "boolean"},
				{Name: "has_admin_role", Type: "boolean"},
				{Name: "has_sensitive_data_access", Type: "boolean"},
				{Name: "tags", Type: "object"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "wiz_issues",
			Description: "Wiz security issues",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "type", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "resource_id", Type: "string"},
				{Name: "resource_type", Type: "string"},
				{Name: "control_id", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "remediation", Type: "string"},
				{Name: "risks", Type: "array"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "wiz_vulnerabilities",
			Description: "Wiz vulnerability findings",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "cve_id", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "cvss_score", Type: "float"},
				{Name: "package_name", Type: "string"},
				{Name: "package_version", Type: "string"},
				{Name: "fixed_version", Type: "string"},
				{Name: "resource_id", Type: "string"},
				{Name: "exploitability", Type: "string"},
				{Name: "has_exploit", Type: "boolean"},
				{Name: "is_initial_access", Type: "boolean"},
				{Name: "is_common_dependency", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "wiz_security_graph",
			Description: "Wiz Security Graph relationships",
			Columns: []ColumnSchema{
				{Name: "source_id", Type: "string", Required: true},
				{Name: "target_id", Type: "string", Required: true},
				{Name: "relationship", Type: "string"},
				{Name: "properties", Type: "object"},
			},
			PrimaryKey: []string{"source_id", "target_id", "relationship"},
		},
		{
			Name:        "wiz_cloud_configurations",
			Description: "Wiz cloud configuration findings",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "control_id", Type: "string"},
				{Name: "framework", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "resource_id", Type: "string"},
				{Name: "resource_type", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "evidence", Type: "object"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "wiz_attack_paths",
			Description: "Wiz attack path analysis",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "severity", Type: "string"},
				{Name: "source_resource_id", Type: "string"},
				{Name: "target_resource_id", Type: "string"},
				{Name: "target_is_admin", Type: "boolean"},
				{Name: "target_is_cross_account", Type: "boolean"},
				{Name: "path_steps", Type: "array"},
				{Name: "risk_factors", Type: "array"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "wiz_secrets",
			Description: "Wiz secrets/credentials detection findings",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "resource_id", Type: "string"},
				{Name: "secret_type", Type: "string"},
				{Name: "is_cleartext", Type: "boolean"},
				{Name: "grants_high_privilege", Type: "boolean"},
				{Name: "grants_admin", Type: "boolean"},
				{Name: "grants_sensitive_data_access", Type: "boolean"},
				{Name: "cross_account_access", Type: "boolean"},
				{Name: "validated_exposed", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "wiz_identities",
			Description: "Wiz identity findings (users, service accounts)",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "type", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "cloud_platform", Type: "string"},
				{Name: "is_third_party", Type: "boolean"},
				{Name: "has_admin_role", Type: "boolean"},
				{Name: "has_high_privilege", Type: "boolean"},
				{Name: "has_sensitive_data_access", Type: "boolean"},
				{Name: "mfa_enabled", Type: "boolean"},
				{Name: "last_activity_days_ago", Type: "integer"},
				{Name: "access_key_count", Type: "integer"},
				{Name: "access_key_last_rotated_days_ago", Type: "integer"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "wiz_data_findings",
			Description: "Wiz sensitive data findings",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "resource_id", Type: "string"},
				{Name: "data_type", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "classification", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (w *WizProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  w.Name(),
		StartedAt: start,
	}

	token, err := w.authenticate(ctx)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}
	w.token = token

	// Sync cloud resources
	resources, err := w.syncCloudResources(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "cloud_resources: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *resources)
		result.TotalRows += resources.Rows
	}

	// Sync issues
	issues, err := w.syncIssues(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "issues: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *issues)
		result.TotalRows += issues.Rows
	}

	// Sync vulnerabilities
	vulns, err := w.syncVulnerabilities(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "vulnerabilities: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *vulns)
		result.TotalRows += vulns.Rows
	}

	// Sync secrets
	secrets, err := w.syncSecrets(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "secrets: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *secrets)
		result.TotalRows += secrets.Rows
	}

	// Sync identities
	identities, err := w.syncIdentities(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "identities: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *identities)
		result.TotalRows += identities.Rows
	}

	// Sync attack paths
	attackPaths, err := w.syncAttackPaths(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "attack_paths: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *attackPaths)
		result.TotalRows += attackPaths.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	if len(result.Errors) > 0 {
		return result, fmt.Errorf("sync completed with %d errors", len(result.Errors))
	}

	return result, nil
}

func (w *WizProvider) authenticate(ctx context.Context) (string, error) {
	if w.token != "" && time.Now().Before(w.tokenExpiry) {
		return w.token, nil
	}

	body := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     w.clientID,
		"client_secret": w.clientSecret,
		"audience":      "wiz-api",
	}
	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", w.authURL, bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth failed: %s", string(respBody))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	w.token = result.AccessToken
	w.tokenExpiry = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return w.token, nil
}

func (w *WizProvider) graphQLQuery(ctx context.Context, query string, variables map[string]interface{}) ([]byte, error) {
	body := map[string]interface{}{
		"query":     query,
		"variables": variables,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", w.apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("wiz API error %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (w *WizProvider) syncCloudResources(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "wiz_cloud_resources"}

	query := `
		query CloudResources($first: Int) {
			cloudResources(first: $first) {
				nodes {
					id
					name
					type
					cloudPlatform
					cloudProviderID
					subscriptionExternalId
					region
					status
					tags
				}
				pageInfo { hasNextPage endCursor }
			}
		}
	`

	body, err := w.graphQLQuery(ctx, query, map[string]interface{}{"first": 500})
	if err != nil {
		return result, err
	}

	var response struct {
		Data struct {
			CloudResources struct {
				Nodes []map[string]interface{} `json:"nodes"`
			} `json:"cloudResources"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Data.CloudResources.Nodes))
	result.Inserted = result.Rows
	return result, nil
}

func (w *WizProvider) syncIssues(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "wiz_issues"}

	query := `
		query Issues($first: Int) {
			issues(first: $first, filterBy: {status: [OPEN, IN_PROGRESS]}) {
				nodes {
					id
					type
					severity
					status
					entitySnapshot { id type }
					control { id }
					createdAt
				}
				pageInfo { hasNextPage endCursor }
			}
		}
	`

	body, err := w.graphQLQuery(ctx, query, map[string]interface{}{"first": 500})
	if err != nil {
		return result, err
	}

	var response struct {
		Data struct {
			Issues struct {
				Nodes []map[string]interface{} `json:"nodes"`
			} `json:"issues"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Data.Issues.Nodes))
	result.Inserted = result.Rows
	return result, nil
}

func (w *WizProvider) syncVulnerabilities(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "wiz_vulnerabilities"}

	query := `
		query Vulnerabilities($first: Int) {
			vulnerabilityFindings(first: $first) {
				nodes {
					id
					name
					CVEDescription
					score
					severity
					exploitabilityScore
					hasExploit
					vendorSeverity
					version
					fixedVersion
				}
				pageInfo { hasNextPage endCursor }
			}
		}
	`

	body, err := w.graphQLQuery(ctx, query, map[string]interface{}{"first": 500})
	if err != nil {
		return result, err
	}

	var response struct {
		Data struct {
			VulnerabilityFindings struct {
				Nodes []map[string]interface{} `json:"nodes"`
			} `json:"vulnerabilityFindings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Data.VulnerabilityFindings.Nodes))
	result.Inserted = result.Rows
	return result, nil
}

func (w *WizProvider) syncAttackPaths(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "wiz_attack_paths"}

	query := `
		query AttackPaths($first: Int) {
			attackPaths(first: $first) {
				nodes {
					id
					severity
					sourceResource { id type }
					targetResource { id type isAdmin }
					pathSteps { description }
					riskFactors
				}
				pageInfo { hasNextPage endCursor }
			}
		}
	`

	body, err := w.graphQLQuery(ctx, query, map[string]interface{}{"first": 500})
	if err != nil {
		return result, err
	}

	var response struct {
		Data struct {
			AttackPaths struct {
				Nodes []map[string]interface{} `json:"nodes"`
			} `json:"attackPaths"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Data.AttackPaths.Nodes))
	result.Inserted = result.Rows
	return result, nil
}

func (w *WizProvider) syncSecrets(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "wiz_secrets"}

	query := `
		query SecretFindings($first: Int) {
			secretFindings(first: $first) {
				nodes {
					id
					resource { id type }
					secretType
					isCleartext
					properties {
						grantsHighPrivilege
						grantsAdmin
						grantsSensitiveDataAccess
						crossAccountAccess
						validatedExposed
					}
				}
				pageInfo { hasNextPage endCursor }
			}
		}
	`

	body, err := w.graphQLQuery(ctx, query, map[string]interface{}{"first": 500})
	if err != nil {
		return result, err
	}

	var response struct {
		Data struct {
			SecretFindings struct {
				Nodes []map[string]interface{} `json:"nodes"`
			} `json:"secretFindings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Data.SecretFindings.Nodes))
	result.Inserted = result.Rows
	return result, nil
}

func (w *WizProvider) syncIdentities(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "wiz_identities"}

	query := `
		query CloudIdentities($first: Int) {
			cloudIdentities(first: $first) {
				nodes {
					id
					type
					name
					email
					cloudPlatform
					isThirdParty
					hasAdminRole
					hasHighPrivilege
					hasSensitiveDataAccess
					mfaEnabled
					lastActivityDaysAgo
					accessKeyCount
					accessKeyLastRotatedDaysAgo
				}
				pageInfo { hasNextPage endCursor }
			}
		}
	`

	body, err := w.graphQLQuery(ctx, query, map[string]interface{}{"first": 500})
	if err != nil {
		return result, err
	}

	var response struct {
		Data struct {
			CloudIdentities struct {
				Nodes []map[string]interface{} `json:"nodes"`
			} `json:"cloudIdentities"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Data.CloudIdentities.Nodes))
	result.Inserted = result.Rows
	return result, nil
}
