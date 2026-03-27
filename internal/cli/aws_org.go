package cli

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/sync/errgroup"

	apiclient "github.com/writer/cerebro/internal/client"
	nativesync "github.com/writer/cerebro/internal/sync"
)

type awsOrgAccount struct {
	ID    string
	Name  string
	Email string
}

func runAWSOrgSync(ctx context.Context, start time.Time) error {
	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	supportsAPI, apiReason := syncSupportsAWSOrgAPIMode()
	if mode != cliExecutionModeDirect && supportsAPI {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			return runAWSOrgSyncViaAPI(ctx, start, apiClient, mode)
		}
	}

	if mode == cliExecutionModeAPI && !supportsAPI {
		return fmt.Errorf("aws org sync API mode unsupported: %s", apiReason)
	}
	if mode != cliExecutionModeDirect && !supportsAPI {
		Warning("API sync mode skipped; using direct mode: %s", apiReason)
	}

	return runAWSOrgSyncDirectFn(ctx, start)
}

func runAWSOrgSyncViaAPI(ctx context.Context, start time.Time, apiClient *apiclient.Client, mode cliExecutionMode) error {
	permissionSetInclude := parseCommaSeparatedValues(syncAWSPSInclude)
	permissionSetExclude := parseCommaSeparatedValues(syncAWSPSExclude)
	resp, err := apiClient.RunAWSOrgSync(ctx, apiclient.AWSOrgSyncRequest{
		Profile:                                strings.TrimSpace(syncAWSProfile),
		Region:                                 strings.TrimSpace(syncRegion),
		MultiRegion:                            syncMultiRegion,
		Concurrency:                            syncConcurrency,
		Tables:                                 parseTableFilter(syncTable),
		Validate:                               syncValidate,
		OrgRole:                                strings.TrimSpace(syncAWSOrgRole),
		IncludeAccounts:                        parseCommaSeparatedValues(syncAWSOrgInclude),
		ExcludeAccounts:                        parseCommaSeparatedValues(syncAWSOrgExclude),
		AccountConcurrency:                     syncAWSOrgConcurrency,
		PermissionUsageLookbackDays:            syncPermissionLookback,
		PermissionRemovalThresholdDays:         syncPermissionRemovalThreshold,
		AWSIdentityCenterPermissionSetsInclude: permissionSetInclude,
		AWSIdentityCenterPermissionSetsExclude: permissionSetExclude,
	})
	if err != nil {
		if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
			return fmt.Errorf("aws org sync via api failed: %w", err)
		}
		Warning("API unavailable; using direct mode: %v", err)
		return runAWSOrgSyncDirectFn(ctx, start)
	}

	provider := "AWS Org"
	if syncValidate || (resp != nil && resp.Validate) {
		provider = "AWS Org (validate)"
	}

	var results []nativesync.SyncResult
	var accountErrors []string
	if resp != nil {
		results = resp.Results
		accountErrors = resp.AccountErrors
	}

	if len(accountErrors) > 0 && len(results) == 0 {
		Warning("%d account(s) reported errors", len(accountErrors))
		syncErrs := make([]error, 0, len(accountErrors))
		for _, accountErr := range accountErrors {
			syncErrs = append(syncErrs, fmt.Errorf("%s", accountErr))
		}
		return summarizeSyncRunErrors("AWS org sync", syncErrs)
	}

	if err := printSyncResults(results, start, provider); err != nil {
		return err
	}

	if len(accountErrors) > 0 {
		Warning("%d account(s) reported errors", len(accountErrors))
		syncErrs := make([]error, 0, len(accountErrors))
		for _, accountErr := range accountErrors {
			syncErrs = append(syncErrs, fmt.Errorf("%s", accountErr))
		}
		return summarizeSyncRunErrors("AWS org sync", syncErrs)
	}

	return nil
}

func syncSupportsAWSOrgAPIMode() (bool, string) {
	return syncSupportsAWSAPIMode()
}

var runAWSOrgSyncDirectFn = runAWSOrgSyncDirect

func runAWSOrgSyncDirect(ctx context.Context, start time.Time) error {
	awsCfg, err := loadAWSConfig(ctx, syncAWSProfile)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	awsCfg, err = applyAWSAssumeRoleOverride(ctx, awsCfg)
	if err != nil {
		return err
	}

	region := syncRegion
	if region == "" {
		region = awsCfg.Region
	}
	if region == "" {
		region = "us-east-1"
	}

	orgCfg := awsCfg.Copy()
	if orgCfg.Region == "" {
		orgCfg.Region = "us-east-1"
	}

	includeSet := buildStringSet(parseTableFilter(syncAWSOrgInclude))
	excludeSet := buildStringSet(parseTableFilter(syncAWSOrgExclude))
	accounts, err := listAWSOrgAccounts(ctx, orgCfg, includeSet, excludeSet)
	if err != nil {
		return fmt.Errorf("list organization accounts: %w", err)
	}
	if len(accounts) == 0 {
		return fmt.Errorf("no AWS organization accounts matched filters")
	}

	managementAccountID, err := getAWSAccountID(ctx, awsCfg)
	if err != nil {
		return fmt.Errorf("get management account ID: %w", err)
	}

	mfaSerial := strings.TrimSpace(syncAWSRoleMFASerial)
	mfaToken := strings.TrimSpace(syncAWSRoleMFAToken)
	if mfaToken != "" && mfaSerial == "" {
		return fmt.Errorf("--aws-role-mfa-token requires --aws-role-mfa-serial")
	}

	durationSeconds, err := parseBoundedPositiveIntDirective(syncAWSRoleDuration, "--aws-role-duration-seconds", 900, 43200)
	if err != nil {
		return err
	}

	tags, transitiveTagKeys, err := parseAWSSessionTagDirectives(
		parseCommaSeparatedValues(syncAWSRoleTags),
		parseCommaSeparatedValues(syncAWSRoleTransitive),
	)
	if err != nil {
		return err
	}

	externalID := strings.TrimSpace(syncAWSRoleExternalID)
	sourceIdentity := strings.TrimSpace(syncAWSRoleSourceID)

	if syncValidate {
		return runAWSOrgValidation(ctx, start, awsCfg, region)
	}

	if syncMultiRegion {
		if syncRegion != "" {
			Warning("Ignoring --region because --multi-region is set")
		}
		Info("Starting AWS org sync for %d accounts (%d regions, concurrency=%d, account-concurrency=%d)...", len(accounts), len(nativesync.DefaultAWSRegions), syncConcurrency, max(1, syncAWSOrgConcurrency))
	} else {
		Info("Starting AWS org sync for %d accounts (region=%s, concurrency=%d, account-concurrency=%d)...", len(accounts), region, syncConcurrency, max(1, syncAWSOrgConcurrency))
	}

	tableFilter := parseTableFilter(syncTable)
	if len(tableFilter) > 0 {
		Info("Filtering AWS tables: %s", strings.Join(tableFilter, ", "))
	}

	opts := buildAWSEngineOptions(region, tableFilter)
	accountConcurrency := max(1, syncAWSOrgConcurrency)

	results := make([]nativesync.SyncResult, 0, len(accounts))
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	group.SetLimit(accountConcurrency)

	for _, account := range accounts {
		account := account
		group.Go(func() error {
			accountStart := time.Now()
			accountCfg := awsCfg
			if account.ID != managementAccountID {
				roleArn, arnErr := buildAWSOrgRoleARN(account.ID, syncAWSOrgRole, region)
				if arnErr != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("account %s: %w", account.ID, arnErr))
					mu.Unlock()
					Warning("Skipping account %s: %v", account.ID, arnErr)
					return nil
				}

				assumedCfg, assumeErr := assumeRoleConfigWithScheduledOptions(
					ctx,
					awsCfg,
					roleArn,
					fmt.Sprintf("cerebro-sync-%s", account.ID),
					externalID,
					mfaSerial,
					mfaToken,
					sourceIdentity,
					durationSeconds,
					tags,
					transitiveTagKeys,
				)
				if assumeErr != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("account %s: %w", account.ID, assumeErr))
					mu.Unlock()
					Warning("Failed to assume role for account %s: %v", account.ID, assumeErr)
					return nil
				}
				accountCfg = assumedCfg
			}

			store, err := openSyncWarehouseFn(ctx)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("account %s: open warehouse: %w", account.ID, err))
				mu.Unlock()
				Warning("Failed to open warehouse for account %s: %v", account.ID, err)
				return nil
			}
			defer func() { _ = closeSyncWarehouse(store) }()

			syncer := nativesync.NewSyncEngine(store, slog.Default(), opts...)
			accountResults, syncErr := syncer.SyncAllWithConfig(ctx, accountCfg)
			mu.Lock()
			results = append(results, accountResults...)
			mu.Unlock()
			if syncErr != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("account %s: %w", account.ID, syncErr))
				mu.Unlock()
				Warning("Sync failed for account %s: %v", account.ID, syncErr)
				return nil
			}

			Success("Account %s synced in %s", account.ID, time.Since(accountStart).Round(time.Second))
			return nil
		})
	}

	_ = group.Wait()

	if len(errs) > 0 {
		if len(results) == 0 {
			Warning("%d account(s) reported errors", len(errs))
			return summarizeSyncRunErrors("AWS org sync", errs)
		}
	}

	if err := printSyncResults(results, start, fmt.Sprintf("AWS Org (%d accounts)", len(accounts))); err != nil {
		return err
	}

	if len(errs) > 0 {
		Warning("%d account(s) reported errors", len(errs))
		return summarizeSyncRunErrors("AWS org sync", errs)
	}

	return nil
}

func runAWSOrgValidation(ctx context.Context, start time.Time, cfg aws.Config, region string) error {
	Info("Validating AWS tables for organization sync")

	tableFilter := parseTableFilter(syncTable)
	if len(tableFilter) > 0 {
		Info("Filtering AWS tables: %s", strings.Join(tableFilter, ", "))
	}

	store, err := openSyncWarehouseFn(ctx)
	if err != nil {
		return fmt.Errorf("open warehouse: %w", err)
	}
	defer func() { _ = closeSyncWarehouse(store) }()

	opts := buildAWSEngineOptions(region, tableFilter)
	syncer := nativesync.NewSyncEngine(store, slog.Default(), opts...)
	results, err := syncer.ValidateTablesWithConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	return printSyncResults(results, start, "AWS Org (validate)")
}

func buildAWSEngineOptions(region string, tableFilter []string) []nativesync.EngineOption {
	opts := []nativesync.EngineOption{}
	if syncConcurrency > 0 {
		opts = append(opts, nativesync.WithConcurrency(syncConcurrency))
	}
	if len(tableFilter) > 0 {
		opts = append(opts, nativesync.WithTableFilter(tableFilter))
	}
	if syncMultiRegion {
		opts = append(opts, nativesync.WithRegions(nativesync.DefaultAWSRegions))
	} else {
		opts = append(opts, nativesync.WithRegions([]string{region}))
	}
	return appendAWSPermissionUsageOptions(opts)
}

func listAWSOrgAccounts(ctx context.Context, cfg aws.Config, include, exclude map[string]struct{}) ([]awsOrgAccount, error) {
	client := organizations.NewFromConfig(cfg)
	pager := organizations.NewListAccountsPaginator(client, &organizations.ListAccountsInput{})
	accounts := make([]awsOrgAccount, 0)

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
			accounts = append(accounts, awsOrgAccount{
				ID:    id,
				Name:  aws.ToString(account.Name),
				Email: aws.ToString(account.Email),
			})
		}
	}

	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].ID < accounts[j].ID
	})
	return accounts, nil
}

func buildAWSOrgRoleARN(accountID, roleName, region string) (string, error) {
	if roleName == "" {
		return "", fmt.Errorf("aws org role name is required")
	}
	if strings.Contains(roleName, "{account_id}") {
		return strings.ReplaceAll(roleName, "{account_id}", accountID), nil
	}
	if strings.HasPrefix(roleName, "arn:") {
		return roleName, nil
	}
	partition := awsPartitionForRegion(region)
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, accountID, roleName), nil
}

func awsPartitionForRegion(region string) string {
	if strings.HasPrefix(region, "us-gov-") {
		return "aws-us-gov"
	}
	if strings.HasPrefix(region, "cn-") {
		return "aws-cn"
	}
	return "aws"
}

func getAWSAccountID(ctx context.Context, cfg aws.Config) (string, error) {
	client := sts.NewFromConfig(cfg)
	resp, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return aws.ToString(resp.Account), nil
}

func buildStringSet(values []string) map[string]struct{} {
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
