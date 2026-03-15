package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/snowflake"
	nativesync "github.com/writer/cerebro/internal/sync"
	"golang.org/x/sync/errgroup"
)

var postSyncGraphUpdateTimeout = 30 * time.Minute

func (s *Server) backfillRelationshipIDs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BatchSize int `json:"batch_size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.BatchSize <= 0 {
		req.BatchSize = 200
	}

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	extractor := nativesync.NewRelationshipExtractor(s.app.Snowflake, s.app.Logger)
	stats, err := extractor.BackfillNormalizedRelationshipIDs(r.Context(), req.BatchSize)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"scanned": stats.Scanned,
		"updated": stats.Updated,
		"deleted": stats.Deleted,
		"skipped": stats.Skipped,
	})
}

type azureSyncRequest struct {
	Subscription            string   `json:"subscription"`
	Subscriptions           []string `json:"subscriptions"`
	ManagementGroup         string   `json:"management_group"`
	Concurrency             int      `json:"concurrency"`
	SubscriptionConcurrency int      `json:"subscription_concurrency"`
	Tables                  []string `json:"tables"`
	Validate                bool     `json:"validate"`
}

var runAzureSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req azureSyncRequest) ([]nativesync.SyncResult, error) {
	opts := []nativesync.AzureEngineOption{}
	switch len(req.Subscriptions) {
	case 1:
		opts = append(opts, nativesync.WithAzureSubscription(req.Subscriptions[0]))
	case 0:
		// let the engine discover all enabled subscriptions if no explicit scope is provided
	default:
		opts = append(opts, nativesync.WithAzureSubscriptions(req.Subscriptions))
	}
	if req.ManagementGroup != "" {
		opts = append(opts, nativesync.WithAzureManagementGroup(req.ManagementGroup))
	}
	if req.Concurrency > 0 {
		opts = append(opts, nativesync.WithAzureConcurrency(req.Concurrency))
	}
	if req.SubscriptionConcurrency > 0 {
		opts = append(opts, nativesync.WithAzureSubscriptionConcurrency(req.SubscriptionConcurrency))
	}
	if len(req.Tables) > 0 {
		opts = append(opts, nativesync.WithAzureTableFilter(req.Tables))
	}

	syncer, err := nativesync.NewAzureSyncEngine(client, slog.Default(), opts...)
	if err != nil {
		return nil, fmt.Errorf("create azure sync engine: %w", err)
	}

	if req.Validate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return results, nil
	}

	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}
	return results, nil
}

func (s *Server) syncAzure(w http.ResponseWriter, r *http.Request) {
	var req azureSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Subscription = strings.TrimSpace(req.Subscription)
	req.Subscriptions = nativesync.NormalizeAzureSubscriptionIDs(append(req.Subscriptions, req.Subscription))
	req.ManagementGroup = strings.TrimSpace(req.ManagementGroup)
	req.Tables = normalizeSyncTables(req.Tables)
	if req.ManagementGroup != "" && len(req.Subscriptions) > 0 {
		s.error(w, http.StatusBadRequest, "management_group cannot be combined with subscription or subscriptions")
		return
	}

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	results, err := runAzureSyncWithOptions(r.Context(), s.app.Snowflake, req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	resp := map[string]interface{}{
		"provider": "azure",
		"validate": req.Validate,
		"results":  results,
	}
	if graphUpdate := s.applySecurityGraphUpdateAfterSync(r.Context(), "azure", req.Validate); graphUpdate != nil {
		resp["graph_update"] = graphUpdate
	}
	s.json(w, http.StatusOK, resp)
}

type k8sSyncRequest struct {
	Kubeconfig  string   `json:"kubeconfig"`
	Context     string   `json:"context"`
	Namespace   string   `json:"namespace"`
	Concurrency int      `json:"concurrency"`
	Tables      []string `json:"tables"`
	Validate    bool     `json:"validate"`
}

var runK8sSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req k8sSyncRequest) ([]nativesync.SyncResult, error) {
	opts := []nativesync.K8sEngineOption{}
	if req.Kubeconfig != "" {
		opts = append(opts, nativesync.WithK8sKubeconfig(req.Kubeconfig))
	}
	if req.Context != "" {
		opts = append(opts, nativesync.WithK8sContext(req.Context))
	}
	if req.Namespace != "" {
		opts = append(opts, nativesync.WithK8sNamespace(req.Namespace))
	}
	if req.Concurrency > 0 {
		opts = append(opts, nativesync.WithK8sConcurrency(req.Concurrency))
	}
	if len(req.Tables) > 0 {
		opts = append(opts, nativesync.WithK8sTableFilter(req.Tables))
	}

	syncer := nativesync.NewK8sSyncEngine(client, slog.Default(), opts...)
	if req.Validate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return results, nil
	}

	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}
	return results, nil
}

func (s *Server) syncK8s(w http.ResponseWriter, r *http.Request) {
	var req k8sSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Kubeconfig = strings.TrimSpace(req.Kubeconfig)
	req.Context = strings.TrimSpace(req.Context)
	req.Namespace = strings.TrimSpace(req.Namespace)
	req.Tables = normalizeSyncTables(req.Tables)

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	results, err := runK8sSyncWithOptions(r.Context(), s.app.Snowflake, req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	resp := map[string]interface{}{
		"provider": "k8s",
		"validate": req.Validate,
		"results":  results,
	}
	if graphUpdate := s.applySecurityGraphUpdateAfterSync(r.Context(), "k8s", req.Validate); graphUpdate != nil {
		resp["graph_update"] = graphUpdate
	}
	s.json(w, http.StatusOK, resp)
}

type awsSyncRequest struct {
	Profile                                string   `json:"profile"`
	Region                                 string   `json:"region"`
	MultiRegion                            bool     `json:"multi_region"`
	Concurrency                            int      `json:"concurrency"`
	Tables                                 []string `json:"tables"`
	Validate                               bool     `json:"validate"`
	PermissionUsageLookbackDays            int      `json:"permission_usage_lookback_days"`
	PermissionRemovalThresholdDays         int      `json:"permission_removal_threshold_days"`
	AWSIdentityCenterPermissionSetsInclude []string `json:"aws_identity_center_permission_sets_include"`
	AWSIdentityCenterPermissionSetsExclude []string `json:"aws_identity_center_permission_sets_exclude"`
}

type awsSyncOutcome struct {
	Results                    []nativesync.SyncResult
	RelationshipsExtracted     int64
	RelationshipsSkippedReason string
}

var runAWSSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsSyncRequest) (*awsSyncOutcome, error) {
	loadOptions := make([]func(*config.LoadOptions) error, 0, 2)
	if req.Profile != "" {
		loadOptions = append(loadOptions, config.WithSharedConfigProfile(req.Profile))
	}
	if req.Region != "" {
		loadOptions = append(loadOptions, config.WithRegion(req.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	opts := []nativesync.EngineOption{}
	if req.Concurrency > 0 {
		opts = append(opts, nativesync.WithConcurrency(req.Concurrency))
	}
	if len(req.Tables) > 0 {
		opts = append(opts, nativesync.WithTableFilter(req.Tables))
	}
	if req.MultiRegion {
		opts = append(opts, nativesync.WithRegions(nativesync.DefaultAWSRegions))
	} else {
		region := req.Region
		if region == "" {
			region = awsCfg.Region
		}
		if region == "" {
			region = "us-east-1"
		}
		opts = append(opts, nativesync.WithRegions([]string{region}))
	}
	opts = appendAWSPermissionUsageRequestOptions(opts, req.PermissionUsageLookbackDays, req.PermissionRemovalThresholdDays, req.AWSIdentityCenterPermissionSetsInclude, req.AWSIdentityCenterPermissionSetsExclude)

	syncer := nativesync.NewSyncEngine(client, slog.Default(), opts...)
	if req.Validate {
		results, err := syncer.ValidateTablesWithConfig(ctx, awsCfg)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return &awsSyncOutcome{Results: results}, nil
	}

	results, err := syncer.SyncAllWithConfig(ctx, awsCfg)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}

	outcome := &awsSyncOutcome{Results: results}
	if len(req.Tables) > 0 {
		outcome.RelationshipsSkippedReason = "table filter is set"
		return outcome, nil
	}

	allowed, reason := nativesync.CanExtractRelationships(results, nil)
	if !allowed {
		outcome.RelationshipsSkippedReason = reason
		return outcome, nil
	}

	extractor := nativesync.NewRelationshipExtractor(client, slog.Default())
	relCount, err := extractor.ExtractAndPersist(ctx)
	if err != nil {
		outcome.RelationshipsSkippedReason = fmt.Sprintf("relationship extraction failed: %v", err)
		return outcome, nil
	}
	outcome.RelationshipsExtracted = int64(relCount)

	return outcome, nil
}

func (s *Server) syncAWS(w http.ResponseWriter, r *http.Request) {
	var req awsSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Profile = strings.TrimSpace(req.Profile)
	req.Region = strings.TrimSpace(req.Region)
	req.Tables = normalizeSyncTables(req.Tables)
	req.AWSIdentityCenterPermissionSetsInclude = normalizeSyncStrings(req.AWSIdentityCenterPermissionSetsInclude)
	req.AWSIdentityCenterPermissionSetsExclude = normalizeSyncStrings(req.AWSIdentityCenterPermissionSetsExclude)

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	outcome, err := runAWSSyncWithOptions(r.Context(), s.app.Snowflake, req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if outcome == nil {
		outcome = &awsSyncOutcome{}
	}

	resp := map[string]interface{}{
		"provider":                "aws",
		"validate":                req.Validate,
		"results":                 outcome.Results,
		"relationships_extracted": outcome.RelationshipsExtracted,
	}
	if outcome.RelationshipsSkippedReason != "" {
		resp["relationships_skipped_reason"] = outcome.RelationshipsSkippedReason
	}
	if graphUpdate := s.applySecurityGraphUpdateAfterSync(r.Context(), "aws", req.Validate); graphUpdate != nil {
		resp["graph_update"] = graphUpdate
	}

	s.json(w, http.StatusOK, resp)
}

type awsOrgSyncRequest struct {
	Profile                                string   `json:"profile"`
	Region                                 string   `json:"region"`
	MultiRegion                            bool     `json:"multi_region"`
	Concurrency                            int      `json:"concurrency"`
	Tables                                 []string `json:"tables"`
	Validate                               bool     `json:"validate"`
	OrgRole                                string   `json:"org_role"`
	IncludeAccounts                        []string `json:"include_accounts"`
	ExcludeAccounts                        []string `json:"exclude_accounts"`
	AccountConcurrency                     int      `json:"account_concurrency"`
	PermissionUsageLookbackDays            int      `json:"permission_usage_lookback_days"`
	PermissionRemovalThresholdDays         int      `json:"permission_removal_threshold_days"`
	AWSIdentityCenterPermissionSetsInclude []string `json:"aws_identity_center_permission_sets_include"`
	AWSIdentityCenterPermissionSetsExclude []string `json:"aws_identity_center_permission_sets_exclude"`
}

type awsOrgSyncOutcome struct {
	Results       []nativesync.SyncResult
	AccountErrors []string
}

var runAWSOrgSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsOrgSyncRequest) (*awsOrgSyncOutcome, error) {
	loadOptions := make([]func(*config.LoadOptions) error, 0, 2)
	if req.Profile != "" {
		loadOptions = append(loadOptions, config.WithSharedConfigProfile(req.Profile))
	}
	if req.Region != "" {
		loadOptions = append(loadOptions, config.WithRegion(req.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	region := req.Region
	if region == "" {
		region = awsCfg.Region
	}
	if region == "" {
		region = "us-east-1"
	}

	orgCfg := awsCfg.Copy()
	if strings.TrimSpace(orgCfg.Region) == "" {
		orgCfg.Region = "us-east-1"
	}
	includeSet := buildSyncStringSet(req.IncludeAccounts)
	excludeSet := buildSyncStringSet(req.ExcludeAccounts)
	accountIDs, err := listAWSOrgSyncAccountIDs(ctx, orgCfg, includeSet, excludeSet)
	if err != nil {
		return nil, fmt.Errorf("list organization accounts: %w", err)
	}
	if len(accountIDs) == 0 {
		return nil, fmt.Errorf("no AWS organization accounts matched filters")
	}

	if req.Validate {
		options := buildAWSEngineOptionsForRequest(region, req)
		syncer := nativesync.NewSyncEngine(client, slog.Default(), options...)
		results, err := syncer.ValidateTablesWithConfig(ctx, awsCfg)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return &awsOrgSyncOutcome{Results: results}, nil
	}

	managementAccountID, err := getAWSOrgSyncManagementAccountID(ctx, awsCfg)
	if err != nil {
		return nil, fmt.Errorf("get management account ID: %w", err)
	}

	accountConcurrency := req.AccountConcurrency
	if accountConcurrency <= 0 {
		accountConcurrency = 4
	}

	options := buildAWSEngineOptionsForRequest(region, req)
	results := make([]nativesync.SyncResult, 0, len(accountIDs))
	accountErrors := make([]string, 0)
	var mu sync.Mutex
	var group errgroup.Group
	group.SetLimit(accountConcurrency)

	for _, accountID := range accountIDs {
		accountID := accountID
		group.Go(func() error {
			accountCfg := awsCfg
			if accountID != managementAccountID {
				roleArn, err := buildAWSOrgSyncRoleARN(accountID, req.OrgRole, region)
				if err != nil {
					mu.Lock()
					accountErrors = append(accountErrors, fmt.Sprintf("account %s: %v", accountID, err))
					mu.Unlock()
					return nil
				}

				assumedCfg, err := assumeAWSOrgAccountConfig(ctx, awsCfg, roleArn, fmt.Sprintf("cerebro-sync-%s", accountID))
				if err != nil {
					mu.Lock()
					accountErrors = append(accountErrors, fmt.Sprintf("account %s: %v", accountID, err))
					mu.Unlock()
					return nil
				}
				accountCfg = assumedCfg
			}

			syncer := nativesync.NewSyncEngine(client, slog.Default(), options...)
			accountResults, syncErr := syncer.SyncAllWithConfig(ctx, accountCfg)

			mu.Lock()
			results = append(results, accountResults...)
			if syncErr != nil {
				accountErrors = append(accountErrors, fmt.Sprintf("account %s: %v", accountID, syncErr))
			}
			mu.Unlock()
			return nil
		})
	}
	_ = group.Wait()
	sort.Strings(accountErrors)

	return &awsOrgSyncOutcome{
		Results:       results,
		AccountErrors: accountErrors,
	}, nil
}

func (s *Server) syncAWSOrg(w http.ResponseWriter, r *http.Request) {
	var req awsOrgSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Profile = strings.TrimSpace(req.Profile)
	req.Region = strings.TrimSpace(req.Region)
	req.Tables = normalizeSyncTables(req.Tables)
	req.OrgRole = strings.TrimSpace(req.OrgRole)
	if req.OrgRole == "" {
		req.OrgRole = "OrganizationAccountAccessRole"
	}
	req.IncludeAccounts = normalizeSyncAccountIDs(req.IncludeAccounts)
	req.ExcludeAccounts = normalizeSyncAccountIDs(req.ExcludeAccounts)
	req.AWSIdentityCenterPermissionSetsInclude = normalizeSyncStrings(req.AWSIdentityCenterPermissionSetsInclude)
	req.AWSIdentityCenterPermissionSetsExclude = normalizeSyncStrings(req.AWSIdentityCenterPermissionSetsExclude)
	if req.AccountConcurrency <= 0 {
		req.AccountConcurrency = 4
	}

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	outcome, err := runAWSOrgSyncWithOptions(r.Context(), s.app.Snowflake, req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if outcome == nil {
		outcome = &awsOrgSyncOutcome{}
	}

	resp := map[string]interface{}{
		"provider": "aws_org",
		"validate": req.Validate,
		"results":  outcome.Results,
	}
	if len(outcome.AccountErrors) > 0 {
		resp["account_errors"] = outcome.AccountErrors
	}
	if graphUpdate := s.applySecurityGraphUpdateAfterSync(r.Context(), "aws_org", req.Validate); graphUpdate != nil {
		resp["graph_update"] = graphUpdate
	}

	s.json(w, http.StatusOK, resp)
}

func buildAWSEngineOptionsForRequest(region string, req awsOrgSyncRequest) []nativesync.EngineOption {
	options := make([]nativesync.EngineOption, 0, 3)
	if req.Concurrency > 0 {
		options = append(options, nativesync.WithConcurrency(req.Concurrency))
	}
	if len(req.Tables) > 0 {
		options = append(options, nativesync.WithTableFilter(req.Tables))
	}
	if req.MultiRegion {
		options = append(options, nativesync.WithRegions(nativesync.DefaultAWSRegions))
	} else {
		options = append(options, nativesync.WithRegions([]string{region}))
	}
	return appendAWSPermissionUsageRequestOptions(options, req.PermissionUsageLookbackDays, req.PermissionRemovalThresholdDays, req.AWSIdentityCenterPermissionSetsInclude, req.AWSIdentityCenterPermissionSetsExclude)
}

func appendAWSPermissionUsageRequestOptions(options []nativesync.EngineOption, lookbackDays int, removalThresholdDays int, include, exclude []string) []nativesync.EngineOption {
	if lookbackDays > 0 {
		options = append(options, nativesync.WithAWSPermissionUsageLookbackDays(lookbackDays))
	}
	if removalThresholdDays > 0 {
		options = append(options, nativesync.WithAWSPermissionRemovalThresholdDays(removalThresholdDays))
	}
	if len(include) > 0 || len(exclude) > 0 {
		options = append(options, nativesync.WithAWSIdentityCenterPermissionSetFilters(include, exclude))
	}
	return options
}

func buildSyncStringSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

func listAWSOrgSyncAccountIDs(ctx context.Context, cfg aws.Config, include, exclude map[string]struct{}) ([]string, error) {
	client := organizations.NewFromConfig(cfg)
	pager := organizations.NewListAccountsPaginator(client, &organizations.ListAccountsInput{})
	accountIDs := make([]string, 0)

	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, account := range page.Accounts {
			if account.Status != orgtypes.AccountStatusActive {
				continue
			}
			id := strings.TrimSpace(aws.ToString(account.Id))
			if id == "" {
				continue
			}
			if len(include) > 0 {
				if _, ok := include[id]; !ok {
					continue
				}
			}
			if _, ok := exclude[id]; ok {
				continue
			}
			accountIDs = append(accountIDs, id)
		}
	}

	sort.Strings(accountIDs)
	return accountIDs, nil
}

func getAWSOrgSyncManagementAccountID(ctx context.Context, cfg aws.Config) (string, error) {
	client := sts.NewFromConfig(cfg)
	resp, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(aws.ToString(resp.Account)), nil
}

func buildAWSOrgSyncRoleARN(accountID, roleName, region string) (string, error) {
	if roleName == "" {
		return "", fmt.Errorf("aws org role name is required")
	}
	if strings.Contains(roleName, "{account_id}") {
		return strings.ReplaceAll(roleName, "{account_id}", accountID), nil
	}
	if strings.HasPrefix(roleName, "arn:") {
		return roleName, nil
	}
	partition := awsOrgPartitionForRegion(region)
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, accountID, roleName), nil
}

func awsOrgPartitionForRegion(region string) string {
	if strings.HasPrefix(region, "us-gov-") {
		return "aws-us-gov"
	}
	if strings.HasPrefix(region, "cn-") {
		return "aws-cn"
	}
	return "aws"
}

func assumeAWSOrgAccountConfig(ctx context.Context, baseCfg aws.Config, roleARN, sessionName string) (aws.Config, error) {
	assumedCfg := baseCfg.Copy()
	stsClient := sts.NewFromConfig(baseCfg)
	assumeProvider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(options *stscreds.AssumeRoleOptions) {
		options.RoleSessionName = sessionName
	})
	assumedCfg.Credentials = aws.NewCredentialsCache(assumeProvider)
	if _, err := assumedCfg.Credentials.Retrieve(ctx); err != nil {
		return baseCfg, err
	}
	return assumedCfg, nil
}

type gcpSyncRequest struct {
	Project                        string   `json:"project"`
	Concurrency                    int      `json:"concurrency"`
	Tables                         []string `json:"tables"`
	Validate                       bool     `json:"validate"`
	PermissionUsageLookbackDays    int      `json:"permission_usage_lookback_days"`
	PermissionRemovalThresholdDays int      `json:"permission_removal_threshold_days"`
	GCPIAMTargetGroups             []string `json:"gcp_iam_target_groups"`
}

type gcpSyncOutcome struct {
	Results                    []nativesync.SyncResult
	RelationshipsExtracted     int64
	RelationshipsSkippedReason string
}

var runGCPSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req gcpSyncRequest) (*gcpSyncOutcome, error) {
	if req.Project == "" {
		return nil, fmt.Errorf("project is required")
	}

	opts := []nativesync.GCPEngineOption{nativesync.WithGCPProject(req.Project)}
	if req.Concurrency > 0 {
		opts = append(opts, nativesync.WithGCPConcurrency(req.Concurrency))
	}
	if len(req.Tables) > 0 {
		opts = append(opts, nativesync.WithGCPTableFilter(req.Tables))
	}
	opts = appendGCPPermissionUsageRequestOptions(opts, req.PermissionUsageLookbackDays, req.PermissionRemovalThresholdDays, req.GCPIAMTargetGroups)

	syncer := nativesync.NewGCPSyncEngine(client, slog.Default(), opts...)
	if req.Validate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return &gcpSyncOutcome{Results: results}, nil
	}

	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}

	outcome := &gcpSyncOutcome{Results: results}
	if len(req.Tables) > 0 {
		outcome.RelationshipsSkippedReason = "table filter is set"
		return outcome, nil
	}

	extractor := nativesync.NewRelationshipExtractor(client, slog.Default())
	relCount, err := extractor.ExtractAndPersist(ctx)
	if err != nil {
		outcome.RelationshipsSkippedReason = fmt.Sprintf("relationship extraction failed: %v", err)
		return outcome, nil
	}
	outcome.RelationshipsExtracted = int64(relCount)

	return outcome, nil
}

func (s *Server) syncGCP(w http.ResponseWriter, r *http.Request) {
	var req gcpSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Project = strings.TrimSpace(req.Project)
	req.Tables = normalizeSyncTables(req.Tables)
	req.GCPIAMTargetGroups = normalizeSyncStrings(req.GCPIAMTargetGroups)
	if req.Project == "" {
		s.error(w, http.StatusBadRequest, "project is required")
		return
	}

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	outcome, err := runGCPSyncWithOptions(r.Context(), s.app.Snowflake, req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if outcome == nil {
		outcome = &gcpSyncOutcome{}
	}

	resp := map[string]interface{}{
		"provider":                "gcp",
		"validate":                req.Validate,
		"results":                 outcome.Results,
		"relationships_extracted": outcome.RelationshipsExtracted,
	}
	if outcome.RelationshipsSkippedReason != "" {
		resp["relationships_skipped_reason"] = outcome.RelationshipsSkippedReason
	}
	if graphUpdate := s.applySecurityGraphUpdateAfterSync(r.Context(), "gcp", req.Validate); graphUpdate != nil {
		resp["graph_update"] = graphUpdate
	}

	s.json(w, http.StatusOK, resp)
}

func appendGCPPermissionUsageRequestOptions(options []nativesync.GCPEngineOption, lookbackDays int, removalThresholdDays int, targetGroups []string) []nativesync.GCPEngineOption {
	if lookbackDays > 0 {
		options = append(options, nativesync.WithGCPPermissionUsageLookbackDays(lookbackDays))
	}
	if removalThresholdDays > 0 {
		options = append(options, nativesync.WithGCPPermissionRemovalThresholdDays(removalThresholdDays))
	}
	if len(targetGroups) > 0 {
		options = append(options, nativesync.WithGCPIAMTargetGroups(targetGroups))
	}
	return options
}

type gcpAssetSyncRequest struct {
	Projects     []string `json:"projects"`
	Organization string   `json:"organization"`
	Concurrency  int      `json:"concurrency"`
	Tables       []string `json:"tables"`
	Validate     bool     `json:"validate"`
}

var runGCPAssetSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req gcpAssetSyncRequest) ([]nativesync.SyncResult, error) {
	organization := strings.TrimSpace(req.Organization)
	if len(req.Projects) == 0 && organization == "" {
		return nil, fmt.Errorf("projects or organization are required")
	}

	opts := make([]nativesync.GCPAssetOption, 0, 3)
	if organization != "" {
		opts = append(opts, nativesync.WithAssetScope("organizations/"+organization))
	} else {
		opts = append(opts, nativesync.WithProjects(req.Projects))
	}
	if req.Concurrency > 0 {
		opts = append(opts, nativesync.WithAssetConcurrency(req.Concurrency))
	}
	if len(req.Tables) > 0 {
		opts = append(opts, nativesync.WithAssetTypeFilter(req.Tables))
	}

	syncer := nativesync.NewGCPAssetInventoryEngine(client, slog.Default(), opts...)
	if req.Validate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return results, nil
	}

	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}
	return results, nil
}

func (s *Server) syncGCPAsset(w http.ResponseWriter, r *http.Request) {
	var req gcpAssetSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Projects = normalizeSyncProjects(req.Projects)
	req.Organization = strings.TrimSpace(req.Organization)
	req.Tables = normalizeSyncTables(req.Tables)
	if req.Organization != "" && len(req.Projects) > 0 {
		s.error(w, http.StatusBadRequest, "organization cannot be combined with projects")
		return
	}
	if len(req.Projects) == 0 && req.Organization == "" {
		s.error(w, http.StatusBadRequest, "projects or organization are required")
		return
	}

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	results, err := runGCPAssetSyncWithOptions(r.Context(), s.app.Snowflake, req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	resp := map[string]interface{}{
		"provider": "gcp_asset",
		"validate": req.Validate,
		"results":  results,
	}
	if graphUpdate := s.applySecurityGraphUpdateAfterSync(r.Context(), "gcp_asset", req.Validate); graphUpdate != nil {
		resp["graph_update"] = graphUpdate
	}
	s.json(w, http.StatusOK, resp)
}

func normalizeSyncProjects(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, project := range raw {
		name := strings.TrimSpace(project)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, name)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizeSyncStrings(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func (s *Server) applySecurityGraphUpdateAfterSync(ctx context.Context, provider string, validate bool) map[string]any {
	if validate || s == nil || s.app == nil || s.app.SecurityGraphBuilder == nil {
		return nil
	}

	trigger := "sync_" + strings.ToLower(strings.TrimSpace(provider))
	graphCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), postSyncGraphUpdateTimeout)
	defer cancel()

	summary, applied, err := s.app.TryApplySecurityGraphChanges(graphCtx, trigger)
	if !applied {
		return map[string]any{
			"status":     "busy",
			"trigger":    trigger,
			"error":      "graph update already in progress",
			"error_code": "GRAPH_UPDATE_BUSY",
		}
	}
	if err != nil {
		s.app.Logger.Warn("post-sync graph update failed", "provider", provider, "error", err)
		return map[string]any{
			"status":     "failed",
			"trigger":    trigger,
			"error":      "graph update failed",
			"error_code": "GRAPH_UPDATE_FAILED",
		}
	}

	status := "noop"
	if summary.Mode == graph.GraphMutationModeFullRebuild || summary.HasChanges() {
		status = "applied"
	}
	return map[string]any{
		"status":  status,
		"trigger": trigger,
		"summary": summary.Payload(trigger),
	}
}

func normalizeSyncAccountIDs(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, accountID := range raw {
		id := strings.TrimSpace(accountID)
		if id == "" {
			continue
		}
		key := strings.ToLower(id)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, id)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizeSyncTables(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, table := range raw {
		name := strings.ToLower(strings.TrimSpace(table))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}
