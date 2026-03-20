package client

import (
	"context"
	"net/http"
	"strings"

	nativesync "github.com/writer/cerebro/internal/sync"
)

type RelationshipBackfillStats struct {
	Scanned int64 `json:"scanned"`
	Updated int64 `json:"updated"`
	Deleted int64 `json:"deleted"`
	Skipped int64 `json:"skipped"`
}

func (c *Client) BackfillRelationshipIDs(ctx context.Context, batchSize int) (*RelationshipBackfillStats, error) {
	var reqBody map[string]interface{}
	if batchSize > 0 {
		reqBody = map[string]interface{}{"batch_size": batchSize}
	}

	var resp RelationshipBackfillStats
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sync/backfill-relationships", nil, reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type AzureSyncRequest struct {
	Subscription            string
	Subscriptions           []string
	ManagementGroup         string
	Concurrency             int
	SubscriptionConcurrency int
	Tables                  []string
	Validate                bool
}

type SyncRunResponse struct {
	Provider                   string                  `json:"provider"`
	Validate                   bool                    `json:"validate"`
	Results                    []nativesync.SyncResult `json:"results"`
	AccountErrors              []string                `json:"account_errors,omitempty"`
	RelationshipsExtracted     int64                   `json:"relationships_extracted,omitempty"`
	RelationshipsSkippedReason string                  `json:"relationships_skipped_reason,omitempty"`
}

func (c *Client) RunAzureSync(ctx context.Context, req AzureSyncRequest) (*SyncRunResponse, error) {
	var reqBody map[string]interface{}
	if sub := strings.TrimSpace(req.Subscription); sub != "" {
		reqBody = map[string]interface{}{"subscription": sub}
	}
	if len(req.Subscriptions) > 0 {
		subscriptions := make([]string, 0, len(req.Subscriptions))
		for _, subscriptionID := range req.Subscriptions {
			if trimmed := strings.TrimSpace(subscriptionID); trimmed != "" {
				subscriptions = append(subscriptions, trimmed)
			}
		}
		singleExplicitSubscription := len(subscriptions) == 1 &&
			strings.TrimSpace(req.Subscription) != "" &&
			strings.EqualFold(subscriptions[0], strings.TrimSpace(req.Subscription))
		if len(subscriptions) > 0 && !singleExplicitSubscription {
			if reqBody == nil {
				reqBody = make(map[string]interface{}, 1)
			}
			reqBody["subscriptions"] = subscriptions
		}
	}
	if managementGroup := strings.TrimSpace(req.ManagementGroup); managementGroup != "" {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["management_group"] = managementGroup
	}
	if req.Concurrency > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["concurrency"] = req.Concurrency
	}
	if req.SubscriptionConcurrency > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["subscription_concurrency"] = req.SubscriptionConcurrency
	}
	if len(req.Tables) > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["tables"] = req.Tables
	}
	if req.Validate {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["validate"] = true
	}

	var resp SyncRunResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sync/azure", nil, reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type AWSSyncRequest struct {
	Profile                                string
	Region                                 string
	MultiRegion                            bool
	Concurrency                            int
	Tables                                 []string
	Validate                               bool
	PermissionUsageLookbackDays            int
	PermissionRemovalThresholdDays         int
	AWSIdentityCenterPermissionSetsInclude []string
	AWSIdentityCenterPermissionSetsExclude []string
}

func (c *Client) RunAWSSync(ctx context.Context, req AWSSyncRequest) (*SyncRunResponse, error) {
	var reqBody map[string]interface{}
	if profile := strings.TrimSpace(req.Profile); profile != "" {
		reqBody = map[string]interface{}{"profile": profile}
	}
	if region := strings.TrimSpace(req.Region); region != "" {
		if reqBody == nil {
			reqBody = map[string]interface{}{"region": region}
		} else {
			reqBody["region"] = region
		}
	}
	if req.MultiRegion {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["multi_region"] = true
	}
	if req.Concurrency > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["concurrency"] = req.Concurrency
	}
	if len(req.Tables) > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["tables"] = req.Tables
	}
	if req.Validate {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["validate"] = true
	}
	if req.PermissionUsageLookbackDays > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["permission_usage_lookback_days"] = req.PermissionUsageLookbackDays
	}
	if req.PermissionRemovalThresholdDays > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["permission_removal_threshold_days"] = req.PermissionRemovalThresholdDays
	}
	if len(req.AWSIdentityCenterPermissionSetsInclude) > 0 {
		include := make([]string, 0, len(req.AWSIdentityCenterPermissionSetsInclude))
		for _, value := range req.AWSIdentityCenterPermissionSetsInclude {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				include = append(include, trimmed)
			}
		}
		if len(include) > 0 {
			if reqBody == nil {
				reqBody = make(map[string]interface{}, 1)
			}
			reqBody["aws_identity_center_permission_sets_include"] = include
		}
	}
	if len(req.AWSIdentityCenterPermissionSetsExclude) > 0 {
		exclude := make([]string, 0, len(req.AWSIdentityCenterPermissionSetsExclude))
		for _, value := range req.AWSIdentityCenterPermissionSetsExclude {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				exclude = append(exclude, trimmed)
			}
		}
		if len(exclude) > 0 {
			if reqBody == nil {
				reqBody = make(map[string]interface{}, 1)
			}
			reqBody["aws_identity_center_permission_sets_exclude"] = exclude
		}
	}

	var resp SyncRunResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sync/aws", nil, reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type AWSOrgSyncRequest struct {
	Profile                                string
	Region                                 string
	MultiRegion                            bool
	Concurrency                            int
	Tables                                 []string
	Validate                               bool
	OrgRole                                string
	IncludeAccounts                        []string
	ExcludeAccounts                        []string
	AccountConcurrency                     int
	PermissionUsageLookbackDays            int
	PermissionRemovalThresholdDays         int
	AWSIdentityCenterPermissionSetsInclude []string
	AWSIdentityCenterPermissionSetsExclude []string
}

func (c *Client) RunAWSOrgSync(ctx context.Context, req AWSOrgSyncRequest) (*SyncRunResponse, error) {
	var reqBody map[string]interface{}
	if profile := strings.TrimSpace(req.Profile); profile != "" {
		reqBody = map[string]interface{}{"profile": profile}
	}
	if region := strings.TrimSpace(req.Region); region != "" {
		if reqBody == nil {
			reqBody = map[string]interface{}{"region": region}
		} else {
			reqBody["region"] = region
		}
	}
	if req.MultiRegion {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["multi_region"] = true
	}
	if req.Concurrency > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["concurrency"] = req.Concurrency
	}
	if len(req.Tables) > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["tables"] = req.Tables
	}
	if req.Validate {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["validate"] = true
	}
	if orgRole := strings.TrimSpace(req.OrgRole); orgRole != "" {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["org_role"] = orgRole
	}
	if len(req.IncludeAccounts) > 0 {
		accounts := make([]string, 0, len(req.IncludeAccounts))
		for _, accountID := range req.IncludeAccounts {
			if trimmed := strings.TrimSpace(accountID); trimmed != "" {
				accounts = append(accounts, trimmed)
			}
		}
		if len(accounts) > 0 {
			if reqBody == nil {
				reqBody = make(map[string]interface{}, 1)
			}
			reqBody["include_accounts"] = accounts
		}
	}
	if len(req.ExcludeAccounts) > 0 {
		accounts := make([]string, 0, len(req.ExcludeAccounts))
		for _, accountID := range req.ExcludeAccounts {
			if trimmed := strings.TrimSpace(accountID); trimmed != "" {
				accounts = append(accounts, trimmed)
			}
		}
		if len(accounts) > 0 {
			if reqBody == nil {
				reqBody = make(map[string]interface{}, 1)
			}
			reqBody["exclude_accounts"] = accounts
		}
	}
	if req.AccountConcurrency > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["account_concurrency"] = req.AccountConcurrency
	}
	if req.PermissionUsageLookbackDays > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["permission_usage_lookback_days"] = req.PermissionUsageLookbackDays
	}
	if req.PermissionRemovalThresholdDays > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["permission_removal_threshold_days"] = req.PermissionRemovalThresholdDays
	}
	if len(req.AWSIdentityCenterPermissionSetsInclude) > 0 {
		include := make([]string, 0, len(req.AWSIdentityCenterPermissionSetsInclude))
		for _, value := range req.AWSIdentityCenterPermissionSetsInclude {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				include = append(include, trimmed)
			}
		}
		if len(include) > 0 {
			if reqBody == nil {
				reqBody = make(map[string]interface{}, 1)
			}
			reqBody["aws_identity_center_permission_sets_include"] = include
		}
	}
	if len(req.AWSIdentityCenterPermissionSetsExclude) > 0 {
		exclude := make([]string, 0, len(req.AWSIdentityCenterPermissionSetsExclude))
		for _, value := range req.AWSIdentityCenterPermissionSetsExclude {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				exclude = append(exclude, trimmed)
			}
		}
		if len(exclude) > 0 {
			if reqBody == nil {
				reqBody = make(map[string]interface{}, 1)
			}
			reqBody["aws_identity_center_permission_sets_exclude"] = exclude
		}
	}

	var resp SyncRunResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sync/aws-org", nil, reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type GCPSyncRequest struct {
	Project                        string
	Concurrency                    int
	Tables                         []string
	Validate                       bool
	PermissionUsageLookbackDays    int
	PermissionRemovalThresholdDays int
	GCPIAMTargetGroups             []string
}

func (c *Client) RunGCPSync(ctx context.Context, req GCPSyncRequest) (*SyncRunResponse, error) {
	var reqBody map[string]interface{}
	if project := strings.TrimSpace(req.Project); project != "" {
		reqBody = map[string]interface{}{"project": project}
	}
	if req.Concurrency > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["concurrency"] = req.Concurrency
	}
	if len(req.Tables) > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["tables"] = req.Tables
	}
	if req.Validate {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["validate"] = true
	}
	if req.PermissionUsageLookbackDays > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["permission_usage_lookback_days"] = req.PermissionUsageLookbackDays
	}
	if req.PermissionRemovalThresholdDays > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["permission_removal_threshold_days"] = req.PermissionRemovalThresholdDays
	}
	if len(req.GCPIAMTargetGroups) > 0 {
		targetGroups := make([]string, 0, len(req.GCPIAMTargetGroups))
		for _, value := range req.GCPIAMTargetGroups {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				targetGroups = append(targetGroups, trimmed)
			}
		}
		if len(targetGroups) > 0 {
			if reqBody == nil {
				reqBody = make(map[string]interface{}, 1)
			}
			reqBody["gcp_iam_target_groups"] = targetGroups
		}
	}

	var resp SyncRunResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sync/gcp", nil, reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type GCPAssetSyncRequest struct {
	Projects     []string
	Organization string
	Concurrency  int
	Tables       []string
	Validate     bool
}

func (c *Client) RunGCPAssetSync(ctx context.Context, req GCPAssetSyncRequest) (*SyncRunResponse, error) {
	var reqBody map[string]interface{}
	organization := strings.TrimSpace(req.Organization)
	if len(req.Projects) > 0 {
		projects := make([]string, 0, len(req.Projects))
		for _, project := range req.Projects {
			if trimmed := strings.TrimSpace(project); trimmed != "" {
				projects = append(projects, trimmed)
			}
		}
		if len(projects) > 0 {
			reqBody = map[string]interface{}{"projects": projects}
		}
	} else if organization != "" {
		reqBody = map[string]interface{}{"projects": []string{}}
	}
	if organization != "" {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["organization"] = organization
	}
	if req.Concurrency > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["concurrency"] = req.Concurrency
	}
	if len(req.Tables) > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["tables"] = req.Tables
	}
	if req.Validate {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["validate"] = true
	}

	var resp SyncRunResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sync/gcp-asset", nil, reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type K8sSyncRequest struct {
	Kubeconfig  string
	Context     string
	Namespace   string
	Concurrency int
	Tables      []string
	Validate    bool
}

func (c *Client) RunK8sSync(ctx context.Context, req K8sSyncRequest) (*SyncRunResponse, error) {
	var reqBody map[string]interface{}
	if kubeconfig := strings.TrimSpace(req.Kubeconfig); kubeconfig != "" {
		reqBody = map[string]interface{}{"kubeconfig": kubeconfig}
	}
	if kubeCtx := strings.TrimSpace(req.Context); kubeCtx != "" {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["context"] = kubeCtx
	}
	if namespace := strings.TrimSpace(req.Namespace); namespace != "" {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["namespace"] = namespace
	}
	if req.Concurrency > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["concurrency"] = req.Concurrency
	}
	if len(req.Tables) > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["tables"] = req.Tables
	}
	if req.Validate {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["validate"] = true
	}

	var resp SyncRunResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sync/k8s", nil, reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
