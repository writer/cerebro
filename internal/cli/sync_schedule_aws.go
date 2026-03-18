package cli

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/snowflake"
	nativesync "github.com/writer/cerebro/internal/sync"
	"golang.org/x/sync/errgroup"
)

func executeAWSSync(ctx context.Context, client *snowflake.Client, schedule *SyncSchedule) error {
	Info("[%s] Executing AWS sync...", schedule.Name)
	spec := parseScheduledSyncSpec(schedule.Table)

	if spec.AWSProfile != "" {
		Info("[%s] AWS auth override: profile=%s", schedule.Name, spec.AWSProfile)
	}
	if spec.AWSWebIdentityRoleARN != "" {
		Info("[%s] AWS auth override: web_identity_role_arn=%s", schedule.Name, spec.AWSWebIdentityRoleARN)
	}
	if spec.AWSRoleARN != "" {
		Info("[%s] AWS auth override: role_arn=%s", schedule.Name, spec.AWSRoleARN)
	}
	if spec.AWSRoleSourceIdentity != "" {
		Info("[%s] AWS auth override: role_source_identity=%s", schedule.Name, spec.AWSRoleSourceIdentity)
	}
	if strings.TrimSpace(spec.AWSRoleDurationSeconds) != "" {
		Info("[%s] AWS auth override: role_duration_seconds=%s", schedule.Name, strings.TrimSpace(spec.AWSRoleDurationSeconds))
	}
	if len(spec.AWSRoleSessionTags) > 0 {
		Info("[%s] AWS auth override: role_session_tags=%d", schedule.Name, len(spec.AWSRoleSessionTags))
	}
	if len(spec.AWSRoleTransitiveTagKeys) > 0 {
		Info("[%s] AWS auth override: role_transitive_tag_keys=%d", schedule.Name, len(spec.AWSRoleTransitiveTagKeys))
	}

	authMethod := scheduledAWSAuthMethod(spec)
	slog.Default().Info("scheduled_sync_audit",
		"event", "auth_override",
		"schedule", schedule.Name,
		"provider", "aws",
		"auth_method", authMethod,
		"profile", strings.TrimSpace(spec.AWSProfile),
		"role_arn", strings.TrimSpace(spec.AWSRoleARN),
		"web_identity_role_arn", strings.TrimSpace(spec.AWSWebIdentityRoleARN),
	)

	awsCfg, err := loadScheduledAWSConfigFn(ctx, spec)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}
	if err := preflightScheduledAWSAuthFn(ctx, schedule, spec, awsCfg); err != nil {
		return err
	}
	if spec.AWSOrg {
		return runScheduledAWSOrgSyncFn(ctx, client, awsCfg, spec)
	}

	return runScheduledAWSNativeSyncFn(ctx, client, awsCfg, spec.TableFilter)
}

func runScheduledAWSNativeSync(ctx context.Context, client *snowflake.Client, awsCfg aws.Config, tableFilter []string) error {
	var opts []nativesync.EngineOption
	if len(tableFilter) > 0 {
		opts = append(opts, nativesync.WithTableFilter(tableFilter))
	}

	syncer := nativesync.NewSyncEngine(client, slog.Default(), opts...)
	_, err := syncer.SyncAllWithConfig(ctx, awsCfg)
	return err
}

func runScheduledAWSOrgSync(ctx context.Context, client *snowflake.Client, awsCfg aws.Config, spec scheduledSyncSpec) error {
	orgCfg := awsCfg.Copy()
	if strings.TrimSpace(orgCfg.Region) == "" {
		orgCfg.Region = "us-east-1"
	}
	region := strings.TrimSpace(awsCfg.Region)
	if region == "" {
		region = orgCfg.Region
	}
	if region == "" {
		region = "us-east-1"
	}

	includeSet := buildStringSet(spec.AWSOrgIncludeAccounts)
	excludeSet := buildStringSet(spec.AWSOrgExcludeAccounts)
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

	accountConcurrency, err := parseAWSOrgAccountConcurrency(spec.AWSOrgAccountConcurrency)
	if err != nil {
		return err
	}
	if accountConcurrency == 0 {
		accountConcurrency = 4
	}

	roleName := strings.TrimSpace(spec.AWSOrgRole)
	if roleName == "" {
		roleName = "OrganizationAccountAccessRole"
	}

	mfaSerial := strings.TrimSpace(spec.AWSRoleMFASerial)
	mfaToken := strings.TrimSpace(spec.AWSRoleMFAToken)
	if mfaToken != "" && mfaSerial == "" {
		return fmt.Errorf("aws_role_mfa_token requires aws_role_mfa_serial")
	}
	durationSeconds, err := parseBoundedPositiveIntDirective(spec.AWSRoleDurationSeconds, "aws_role_duration_seconds", 900, 43200)
	if err != nil {
		return err
	}
	tags, transitiveTagKeys, err := parseAWSSessionTagDirectives(spec.AWSRoleSessionTags, spec.AWSRoleTransitiveTagKeys)
	if err != nil {
		return err
	}

	var opts []nativesync.EngineOption
	if len(spec.TableFilter) > 0 {
		opts = append(opts, nativesync.WithTableFilter(spec.TableFilter))
	}

	Info("Syncing AWS organization accounts: %d (account_concurrency=%d)", len(accounts), accountConcurrency)

	results := make([]nativesync.SyncResult, 0, len(accounts))
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	group.SetLimit(accountConcurrency)

	for _, account := range accounts {
		account := account
		group.Go(func() error {
			accountCfg := awsCfg
			if account.ID != managementAccountID {
				roleArn, err := buildAWSOrgRoleARN(account.ID, roleName, region)
				if err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("account %s: %w", account.ID, err))
					mu.Unlock()
					return nil
				}
				assumedCfg, err := assumeRoleConfigWithScheduledOptions(
					ctx,
					awsCfg,
					roleArn,
					fmt.Sprintf("cerebro-sync-%s", account.ID),
					strings.TrimSpace(spec.AWSRoleExternalID),
					mfaSerial,
					mfaToken,
					strings.TrimSpace(spec.AWSRoleSourceIdentity),
					durationSeconds,
					tags,
					transitiveTagKeys,
				)
				if err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("account %s: %w", account.ID, err))
					mu.Unlock()
					return nil
				}
				accountCfg = assumedCfg
			}

			syncer := nativesync.NewSyncEngine(client, slog.Default(), opts...)
			accountResults, syncErr := syncer.SyncAllWithConfig(ctx, accountCfg)

			mu.Lock()
			results = append(results, accountResults...)
			if syncErr != nil {
				errs = append(errs, fmt.Errorf("account %s: %w", account.ID, syncErr))
			}
			mu.Unlock()
			return nil
		})
	}

	_ = group.Wait()
	if len(errs) > 0 {
		return summarizeSyncRunErrors("AWS org scheduled sync", errs)
	}
	return nil
}

func parseAWSOrgAccountConcurrency(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("aws_org_account_concurrency must be an integer: %w", err)
	}
	if value < 1 || value > 256 {
		return 0, fmt.Errorf("aws_org_account_concurrency must be between 1 and 256")
	}
	return value, nil
}

func loadScheduledAWSConfig(ctx context.Context, spec scheduledSyncSpec) (aws.Config, error) {
	loadOptions := make([]func(*config.LoadOptions) error, 0, 4)
	envSnapshots := make(map[string]envSnapshot)
	defer restoreEnvSnapshot(envSnapshots)
	roleARN := strings.TrimSpace(spec.AWSRoleARN)
	if roleARN == "" {
		if strings.TrimSpace(spec.AWSRoleDurationSeconds) != "" || len(spec.AWSRoleSessionTags) > 0 || len(spec.AWSRoleTransitiveTagKeys) > 0 || strings.TrimSpace(spec.AWSRoleSourceIdentity) != "" {
			return aws.Config{}, fmt.Errorf("aws_role_duration_seconds/aws_role_session_tags/aws_role_transitive_tag_keys/aws_role_source_identity require aws_role_arn")
		}
	}

	webIdentityToken := strings.TrimSpace(spec.AWSWebIdentityTokenFile)
	webIdentityRole := strings.TrimSpace(spec.AWSWebIdentityRoleARN)
	webIdentitySession := strings.TrimSpace(spec.AWSWebIdentitySession)
	if webIdentityToken != "" || webIdentityRole != "" {
		if webIdentityToken == "" || webIdentityRole == "" {
			return aws.Config{}, fmt.Errorf("aws_web_identity_token_file and aws_web_identity_role_arn must be set together")
		}
		if err := validateReadableFile(webIdentityToken, "aws_web_identity_token_file"); err != nil {
			return aws.Config{}, err
		}
		if err := setEnvWithSnapshot(envSnapshots, "AWS_WEB_IDENTITY_TOKEN_FILE", webIdentityToken); err != nil {
			return aws.Config{}, fmt.Errorf("set AWS_WEB_IDENTITY_TOKEN_FILE: %w", err)
		}
		if err := setEnvWithSnapshot(envSnapshots, "AWS_ROLE_ARN", webIdentityRole); err != nil {
			return aws.Config{}, fmt.Errorf("set AWS_ROLE_ARN: %w", err)
		}
		if webIdentitySession != "" {
			if err := setEnvWithSnapshot(envSnapshots, "AWS_ROLE_SESSION_NAME", webIdentitySession); err != nil {
				return aws.Config{}, fmt.Errorf("set AWS_ROLE_SESSION_NAME: %w", err)
			}
		}
	}

	if profile := strings.TrimSpace(spec.AWSProfile); profile != "" {
		loadOptions = append(loadOptions, config.WithSharedConfigProfile(profile))
	}

	if configFile := strings.TrimSpace(spec.AWSConfigFile); configFile != "" {
		if err := validateReadableFile(configFile, "aws_config_file"); err != nil {
			return aws.Config{}, err
		}
		loadOptions = append(loadOptions, config.WithSharedConfigFiles([]string{configFile}))
	}

	if credentialsFile := strings.TrimSpace(spec.AWSSharedCredentialsFile); credentialsFile != "" {
		if err := validateReadableFile(credentialsFile, "aws_shared_credentials_file"); err != nil {
			return aws.Config{}, err
		}
		loadOptions = append(loadOptions, config.WithSharedCredentialsFiles([]string{credentialsFile}))
	}

	if credentialProcess := strings.TrimSpace(spec.AWSCredentialProcess); credentialProcess != "" {
		if err := validateAWSCredentialProcess(credentialProcess, "aws_credential_process"); err != nil {
			return aws.Config{}, err
		}
		loadOptions = append(loadOptions, config.WithCredentialsProvider(aws.NewCredentialsCache(processcreds.NewProvider(credentialProcess))))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return aws.Config{}, err
	}

	if roleARN == "" {
		return cfg, nil
	}

	mfaSerial := strings.TrimSpace(spec.AWSRoleMFASerial)
	mfaToken := strings.TrimSpace(spec.AWSRoleMFAToken)
	if mfaToken != "" && mfaSerial == "" {
		return aws.Config{}, fmt.Errorf("aws_role_mfa_token requires aws_role_mfa_serial")
	}

	durationSeconds, err := parseBoundedPositiveIntDirective(spec.AWSRoleDurationSeconds, "aws_role_duration_seconds", 900, 43200)
	if err != nil {
		return aws.Config{}, err
	}

	tags, transitiveTagKeys, err := parseAWSSessionTagDirectives(spec.AWSRoleSessionTags, spec.AWSRoleTransitiveTagKeys)
	if err != nil {
		return aws.Config{}, err
	}

	assumedCfg, err := assumeRoleConfigWithScheduledOptions(
		ctx,
		cfg,
		roleARN,
		strings.TrimSpace(spec.AWSRoleSession),
		strings.TrimSpace(spec.AWSRoleExternalID),
		mfaSerial,
		mfaToken,
		strings.TrimSpace(spec.AWSRoleSourceIdentity),
		durationSeconds,
		tags,
		transitiveTagKeys,
	)
	if err != nil {
		return aws.Config{}, err
	}

	return assumedCfg, nil
}

func assumeRoleConfigWithScheduledOptions(
	ctx context.Context,
	cfg aws.Config,
	roleArn,
	sessionName,
	externalID,
	mfaSerial,
	mfaToken string,
	sourceIdentity string,
	durationSeconds int,
	tags []ststypes.Tag,
	transitiveTagKeys []string,
) (aws.Config, error) {
	if roleArn == "" {
		return cfg, fmt.Errorf("role ARN is required")
	}
	if sessionName == "" {
		sessionName = "cerebro-sync"
	}

	stsClient := sts.NewFromConfig(cfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleArn, func(options *stscreds.AssumeRoleOptions) {
		options.RoleSessionName = sessionName
		if externalID != "" {
			options.ExternalID = aws.String(externalID)
		}
		if sourceIdentity != "" {
			options.SourceIdentity = aws.String(sourceIdentity)
		}
		if mfaSerial != "" {
			options.SerialNumber = aws.String(mfaSerial)
			if mfaToken != "" {
				token := mfaToken
				options.TokenProvider = func() (string, error) {
					return token, nil
				}
			}
		}
		if durationSeconds > 0 {
			options.Duration = time.Duration(durationSeconds) * time.Second
		}
		if len(tags) > 0 {
			options.Tags = tags
		}
		if len(transitiveTagKeys) > 0 {
			options.TransitiveTagKeys = transitiveTagKeys
		}
	})

	assumed := cfg.Copy()
	assumed.Credentials = aws.NewCredentialsCache(provider)
	return assumed, nil
}

func parseAWSSessionTagDirectives(rawTags, rawTransitiveTagKeys []string) ([]ststypes.Tag, []string, error) {
	if len(rawTags) == 0 && len(rawTransitiveTagKeys) == 0 {
		return nil, nil, nil
	}

	tags := make([]ststypes.Tag, 0, len(rawTags))
	keysSeen := map[string]struct{}{}
	for _, rawTag := range rawTags {
		trimmed := strings.TrimSpace(rawTag)
		if trimmed == "" {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("aws_role_session_tags entries must be key=value (got %q)", trimmed)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, nil, fmt.Errorf("aws_role_session_tags entry %q has an empty key", trimmed)
		}
		if _, exists := keysSeen[strings.ToLower(key)]; exists {
			return nil, nil, fmt.Errorf("aws_role_session_tags contains duplicate key %q", key)
		}
		keysSeen[strings.ToLower(key)] = struct{}{}
		tags = append(tags, ststypes.Tag{Key: aws.String(key), Value: aws.String(value)})
	}

	transitiveTagKeys := make([]string, 0, len(rawTransitiveTagKeys))
	for _, rawKey := range rawTransitiveTagKeys {
		key := strings.TrimSpace(rawKey)
		if key == "" {
			continue
		}
		if _, exists := keysSeen[strings.ToLower(key)]; !exists {
			return nil, nil, fmt.Errorf("aws_role_transitive_tag_keys includes %q without a corresponding aws_role_session_tags entry", key)
		}
		transitiveTagKeys = append(transitiveTagKeys, key)
	}

	if len(tags) == 0 {
		tags = nil
	}
	if len(transitiveTagKeys) == 0 {
		transitiveTagKeys = nil
	}
	return tags, transitiveTagKeys, nil
}

func scheduledAWSAuthMethod(spec scheduledSyncSpec) string {
	switch {
	case strings.TrimSpace(spec.AWSRoleARN) != "":
		return "assume_role"
	case strings.TrimSpace(spec.AWSWebIdentityRoleARN) != "":
		return "web_identity"
	case strings.TrimSpace(spec.AWSCredentialProcess) != "":
		return "credential_process"
	case strings.TrimSpace(spec.AWSProfile) != "":
		return "profile"
	default:
		return "default"
	}
}

func preflightScheduledAWSAuth(ctx context.Context, schedule *SyncSchedule, spec scheduledSyncSpec, awsCfg aws.Config) error {
	authMethod := scheduledAWSAuthMethod(spec)
	identity, err := sts.NewFromConfig(awsCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		metrics.RecordScheduledAuthPreflight("aws", authMethod, false)
		return fmt.Errorf("[%s] AWS auth preflight failed: %w", schedule.Name, err)
	}
	metrics.RecordScheduledAuthPreflight("aws", authMethod, true)

	slog.Default().Info("scheduled_sync_audit",
		"event", "auth_preflight",
		"schedule", schedule.Name,
		"provider", "aws",
		"auth_method", authMethod,
		"status", "success",
		"account", aws.ToString(identity.Account),
		"arn", aws.ToString(identity.Arn),
	)
	Info("[%s] AWS auth preflight succeeded: account=%s arn=%s", schedule.Name, aws.ToString(identity.Account), aws.ToString(identity.Arn))
	return nil
}
