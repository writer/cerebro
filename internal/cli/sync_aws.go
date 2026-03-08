package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	apiclient "github.com/evalops/cerebro/internal/client"
	nativesync "github.com/evalops/cerebro/internal/sync"
)

func runAWSPreflightOnly(ctx context.Context, start time.Time) error {
	report := syncPreflightReport{
		Mode:      "preflight",
		Provider:  "aws",
		AuthMode:  syncAuthMode,
		AuthChain: describeCurrentAWSAuthChain(),
		StartedAt: start.UTC(),
	}

	checks := make([]syncPreflightCheck, 0, 16)
	errs := make([]error, 0)
	record := func(name, okDetail string, err error) {
		if err != nil {
			checks = append(checks, syncPreflightCheck{Name: name, Status: "failed", Detail: err.Error()})
			errs = append(errs, err)
			return
		}
		detail := strings.TrimSpace(okDetail)
		if detail == "" {
			detail = "ok"
		}
		checks = append(checks, syncPreflightCheck{Name: name, Status: "passed", Detail: detail})
	}

	profiles := []string{strings.TrimSpace(syncAWSProfile)}
	if syncAWSProfiles != "" {
		profiles = parseCommaSeparatedValues(syncAWSProfiles)
		if len(profiles) == 0 {
			record("profiles", "", fmt.Errorf("--aws-profiles did not include any valid profile names"))
		}
		if strings.TrimSpace(syncAWSProfile) != "" {
			record("profiles", "", fmt.Errorf("--aws-profile cannot be combined with --aws-profiles"))
		}
	}
	if len(profiles) == 0 {
		profiles = []string{""}
	}

	for _, profile := range profiles {
		spec := buildScheduledAWSSpecFromSyncFlags(profile)
		profileLabel := strings.TrimSpace(profile)
		if profileLabel == "" {
			profileLabel = "default"
		}

		awsCfg, err := loadScheduledAWSConfigFn(ctx, spec)
		if err != nil {
			record(fmt.Sprintf("profile.%s.config", profileLabel), "", fmt.Errorf("load config: %w", err))
			continue
		}
		record(fmt.Sprintf("profile.%s.config", profileLabel), "config loaded", nil)

		schedule := &SyncSchedule{Name: fmt.Sprintf("sync-preflight-aws-%s", profileLabel), Provider: "aws"}
		if err := preflightScheduledAWSAuthFn(ctx, schedule, spec, awsCfg); err != nil {
			record(fmt.Sprintf("profile.%s.identity", profileLabel), "", err)
			continue
		}
		record(fmt.Sprintf("profile.%s.identity", profileLabel), "caller identity confirmed", nil)

		if syncAWSOrg {
			includeSet := buildStringSet(parseTableFilter(syncAWSOrgInclude))
			excludeSet := buildStringSet(parseTableFilter(syncAWSOrgExclude))
			orgCfg := awsCfg.Copy()
			if strings.TrimSpace(orgCfg.Region) == "" {
				orgCfg.Region = "us-east-1"
			}
			accounts, err := listAWSOrgAccounts(ctx, orgCfg, includeSet, excludeSet)
			if err != nil {
				record(fmt.Sprintf("profile.%s.organizations", profileLabel), "", fmt.Errorf("list organization accounts: %w", err))
				continue
			}
			if len(accounts) == 0 {
				record(fmt.Sprintf("profile.%s.organizations", profileLabel), "", fmt.Errorf("no AWS organization accounts matched filters"))
				continue
			}
			record(fmt.Sprintf("profile.%s.organizations", profileLabel), fmt.Sprintf("%d organization accounts accessible", len(accounts)), nil)
		}
	}

	report.Checks = checks
	report.Duration = time.Since(start).Round(time.Millisecond).String()
	report.Success = len(errs) == 0
	if err := printSyncPreflightReport(report); err != nil {
		return err
	}
	if len(errs) > 0 {
		return summarizeSyncRunErrors("AWS preflight", errs)
	}
	return nil
}

func buildScheduledAWSSpecFromSyncFlags(profile string) scheduledSyncSpec {
	resolvedProfile := strings.TrimSpace(profile)
	if resolvedProfile == "" {
		resolvedProfile = strings.TrimSpace(syncAWSProfile)
	}
	return scheduledSyncSpec{
		TableFilter:              parseTableFilter(syncTable),
		AWSProfile:               resolvedProfile,
		AWSConfigFile:            strings.TrimSpace(syncAWSConfigFile),
		AWSSharedCredentialsFile: strings.TrimSpace(syncAWSSharedCredsFile),
		AWSCredentialProcess:     strings.TrimSpace(syncAWSCredentialProc),
		AWSWebIdentityTokenFile:  strings.TrimSpace(syncAWSWebIDTokenFile),
		AWSWebIdentityRoleARN:    strings.TrimSpace(syncAWSWebIDRoleARN),
		AWSRoleARN:               strings.TrimSpace(syncAWSRoleARN),
		AWSRoleSession:           strings.TrimSpace(syncAWSRoleSession),
		AWSRoleExternalID:        strings.TrimSpace(syncAWSRoleExternalID),
		AWSRoleMFASerial:         strings.TrimSpace(syncAWSRoleMFASerial),
		AWSRoleMFAToken:          strings.TrimSpace(syncAWSRoleMFAToken),
		AWSRoleSourceIdentity:    strings.TrimSpace(syncAWSRoleSourceID),
		AWSRoleDurationSeconds:   strings.TrimSpace(syncAWSRoleDuration),
		AWSRoleSessionTags:       parseCommaSeparatedValues(syncAWSRoleTags),
		AWSRoleTransitiveTagKeys: parseCommaSeparatedValues(syncAWSRoleTransitive),
	}
}

func runMultiAccountAWSSync(ctx context.Context, start time.Time) error {
	profiles := parseCommaSeparatedValues(syncAWSProfiles)
	if len(profiles) == 0 {
		return fmt.Errorf("--aws-profiles did not include any valid profile names")
	}

	Info("Starting multi-account AWS sync (%d profiles)...", len(profiles))
	var totalResults []nativesync.SyncResult
	var syncErrs []error

	for _, profile := range profiles {
		Info("Syncing AWS profile: %s", profile)
		profileStart := time.Now()

		awsCfg, err := loadAWSConfig(ctx, profile)
		if err != nil {
			Warning("Failed to load config for profile %s: %v", profile, err)
			syncErrs = append(syncErrs, fmt.Errorf("profile %s: load config: %w", profile, err))
			continue
		}
		awsCfg, err = applyAWSAssumeRoleOverride(ctx, awsCfg)
		if err != nil {
			Warning("Failed to assume role for profile %s: %v", profile, err)
			syncErrs = append(syncErrs, fmt.Errorf("profile %s: %w", profile, err))
			continue
		}

		tableFilter := parseTableFilter(syncTable)
		region := syncRegion
		if region == "" {
			region = awsCfg.Region
		}
		if region == "" {
			region = "us-east-1"
		}

		sfClient, err := createSnowflakeClient()
		if err != nil {
			Warning("Failed to create Snowflake client for profile %s: %v", profile, err)
			syncErrs = append(syncErrs, fmt.Errorf("profile %s: create snowflake client: %w", profile, err))
			continue
		}

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

		syncer := nativesync.NewSyncEngine(sfClient, slog.Default(), opts...)
		results, err := syncer.SyncAllWithConfig(ctx, awsCfg)
		_ = sfClient.Close()
		totalResults = append(totalResults, results...)

		if err != nil {
			Warning("Sync failed for profile %s: %v", profile, err)
			syncErrs = append(syncErrs, fmt.Errorf("profile %s: %w", profile, err))
			continue
		}

		Success("Profile %s synced in %s", profile, time.Since(profileStart).Round(time.Second))
	}

	if len(syncErrs) > 0 {
		if len(totalResults) == 0 {
			Warning("%d profile(s) had errors", len(syncErrs))
			return summarizeSyncRunErrors("multi-account AWS sync", syncErrs)
		}
	}

	if err := printSyncResults(totalResults, start, fmt.Sprintf("AWS (%d profiles)", len(profiles))); err != nil {
		return err
	}

	if len(syncErrs) > 0 {
		Warning("%d profile(s) had errors", len(syncErrs))
		return summarizeSyncRunErrors("multi-account AWS sync", syncErrs)
	}

	return nil
}

func runNativeSync(ctx context.Context, start time.Time) error {
	tableFilter := parseTableFilter(syncTable)

	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	supportsAPI, apiReason := syncSupportsAWSAPIMode()
	if mode != cliExecutionModeDirect && supportsAPI {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			resp, err := apiClient.RunAWSSync(ctx, apiclient.AWSSyncRequest{
				Region:      strings.TrimSpace(syncRegion),
				MultiRegion: syncMultiRegion,
				Concurrency: syncConcurrency,
				Tables:      tableFilter,
				Validate:    syncValidate,
			})
			if err == nil {
				provider := "AWS"
				if syncValidate || (resp != nil && resp.Validate) {
					provider = "AWS (validate)"
				}

				var results []nativesync.SyncResult
				if resp != nil {
					results = resp.Results
				}
				if err := printSyncResults(results, start, provider); err != nil {
					return err
				}

				if !syncValidate {
					if len(tableFilter) > 0 {
						Info("Skipping relationship extraction because --table filter is set")
					} else if resp != nil {
						if reason := strings.TrimSpace(resp.RelationshipsSkippedReason); reason != "" {
							Info("Skipping relationship extraction: %s", reason)
						} else {
							Info("Extracted %d relationships", resp.RelationshipsExtracted)
						}
					}
				}

				if syncScanAfter && !syncValidate {
					Info("Triggering policy scan...")
					if err := runPostSyncScan(ctx, tableFilter); err != nil {
						Warning("Post-sync scan failed: %v", err)
					}
				}

				return nil
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("aws sync via api failed: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	if mode == cliExecutionModeAPI && !supportsAPI {
		return fmt.Errorf("aws sync API mode unsupported: %s", apiReason)
	}
	if mode != cliExecutionModeDirect && !supportsAPI {
		Warning("API sync mode skipped; using direct mode: %s", apiReason)
	}

	return runNativeSyncDirectFn(ctx, start)
}

func syncSupportsAWSAPIMode() (bool, string) {
	if strings.TrimSpace(syncAWSProfile) != "" {
		return false, "--aws-profile requires direct mode"
	}
	if strings.TrimSpace(syncAWSConfigFile) != "" {
		return false, "--aws-config-file requires direct mode"
	}
	if strings.TrimSpace(syncAWSSharedCredsFile) != "" {
		return false, "--aws-shared-credentials-file requires direct mode"
	}
	if strings.TrimSpace(syncAWSCredentialProc) != "" {
		return false, "--aws-credential-process requires direct mode"
	}
	if strings.TrimSpace(syncAWSWebIDTokenFile) != "" || strings.TrimSpace(syncAWSWebIDRoleARN) != "" {
		return false, "--aws-web-identity-* flags require direct mode"
	}
	if strings.TrimSpace(syncAWSRoleARN) != "" || strings.TrimSpace(syncAWSRoleExternalID) != "" || strings.TrimSpace(syncAWSRoleMFASerial) != "" || strings.TrimSpace(syncAWSRoleMFAToken) != "" || strings.TrimSpace(syncAWSRoleSourceID) != "" || strings.TrimSpace(syncAWSRoleDuration) != "" || strings.TrimSpace(syncAWSRoleTags) != "" || strings.TrimSpace(syncAWSRoleTransitive) != "" {
		return false, "--aws-role-* flags require direct mode"
	}
	return true, ""
}

var runNativeSyncDirectFn = runNativeSyncDirect

func runNativeSyncDirect(ctx context.Context, start time.Time) error {
	awsCfg, err := loadAWSConfig(ctx, syncAWSProfile)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}
	awsCfg, err = applyAWSAssumeRoleOverride(ctx, awsCfg)
	if err != nil {
		return err
	}

	tableFilter := parseTableFilter(syncTable)

	region := syncRegion
	if region == "" {
		region = awsCfg.Region
	}
	if region == "" {
		region = "us-east-1"
	}

	if syncMultiRegion {
		if syncRegion != "" {
			Warning("Ignoring --region because --multi-region is set")
		}
		Info("Starting multi-region AWS sync (%d regions, concurrency=%d)...", len(nativesync.DefaultAWSRegions), syncConcurrency)
	} else {
		Info("Starting native AWS sync (region=%s, concurrency=%d)...", region, syncConcurrency)
	}
	if len(tableFilter) > 0 {
		Info("Filtering AWS tables: %s", strings.Join(tableFilter, ", "))
	}

	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

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

	syncer := nativesync.NewSyncEngine(client, slog.Default(), opts...)
	if syncValidate {
		results, err := syncer.ValidateTablesWithConfig(ctx, awsCfg)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		return printSyncResults(results, start, "AWS (validate)")
	}

	results, err := syncer.SyncAllWithConfig(ctx, awsCfg)
	if err := handleSyncRunResults(results, start, "AWS", err); err != nil {
		return err
	}

	if len(tableFilter) == 0 {
		allowed, reason := nativesync.CanExtractRelationships(results, nil)
		if !allowed {
			Info("Skipping relationship extraction: %s", reason)
		} else {
			// Extract resource relationships for graph building.
			Info("Extracting resource relationships...")
			relExtractor := nativesync.NewRelationshipExtractor(client, slog.Default())
			relCount, err := relExtractor.ExtractAndPersist(ctx)
			if err != nil {
				Warning("Relationship extraction failed: %v", err)
			} else {
				Info("Extracted %d relationships", relCount)
			}
		}
	} else {
		Info("Skipping relationship extraction because --table filter is set")
	}

	if syncScanAfter {
		Info("Triggering policy scan...")
		if err := runPostSyncScan(ctx, tableFilter); err != nil {
			Warning("Post-sync scan failed: %v", err)
		}
	}

	return nil
}

func loadAWSConfig(ctx context.Context, profile string) (aws.Config, error) {
	cleanup := sanitizeAWSAuthEnv()
	defer cleanup()

	trimmed := strings.TrimSpace(profile)
	loadOptions := make([]func(*config.LoadOptions) error, 0, 5)

	if trimmed != "" {
		loadOptions = append(loadOptions, config.WithSharedConfigProfile(trimmed))
	}

	configFile := strings.TrimSpace(syncAWSConfigFile)
	if configFile != "" {
		if err := validateReadableFile(configFile, "--aws-config-file"); err != nil {
			return aws.Config{}, err
		}
		loadOptions = append(loadOptions, config.WithSharedConfigFiles([]string{configFile}))
	}

	credentialsFile := strings.TrimSpace(syncAWSSharedCredsFile)
	if credentialsFile != "" {
		if err := validateReadableFile(credentialsFile, "--aws-shared-credentials-file"); err != nil {
			return aws.Config{}, err
		}
		loadOptions = append(loadOptions, config.WithSharedCredentialsFiles([]string{credentialsFile}))
	}

	credentialProcess := strings.TrimSpace(syncAWSCredentialProc)
	if credentialProcess != "" {
		if err := validateAWSCredentialProcess(credentialProcess, "--aws-credential-process"); err != nil {
			return aws.Config{}, err
		}
		loadOptions = append(loadOptions, config.WithCredentialsProvider(aws.NewCredentialsCache(processcreds.NewProvider(credentialProcess))))
	}

	return config.LoadDefaultConfig(ctx, loadOptions...)
}

func sanitizeAWSAuthEnv() func() {
	envSnapshots := make(map[string]envSnapshot)

	keys := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_PROFILE",
		"AWS_ROLE_ARN",
		"AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_CONFIG_FILE",
		"AWS_SHARED_CREDENTIALS_FILE",
	}

	removed := 0
	for _, key := range keys {
		value, present := os.LookupEnv(key)
		if !present {
			continue
		}

		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}

		if !shouldSanitizeAWSEnvValue(key, trimmed) {
			continue
		}

		envSnapshots[key] = envSnapshot{value: value, present: true}
		_ = os.Unsetenv(key)
		removed++
	}

	if removed > 0 {
		Warning("Ignoring %d placeholder/invalid AWS auth env var(s) during config load", removed)
	}

	return func() {
		restoreEnvSnapshot(envSnapshots)
	}
}

func shouldSanitizeAWSEnvValue(key, value string) bool {
	if looksLikePlaceholderValue(value) {
		return true
	}

	switch key {
	case "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE":
		if _, err := os.Stat(value); err != nil {
			return true
		}
	}

	return false
}

func looksLikePlaceholderValue(value string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if normalized == "" {
		return false
	}

	return strings.Contains(normalized, "PLACEHOLDER") ||
		strings.Contains(normalized, "REPLACE_ME") ||
		strings.Contains(normalized, "CHANGE_ME") ||
		strings.Contains(normalized, "CHANGEME")
}

func applyAWSAuthOverrides() (func(), error) {
	envSnapshots := make(map[string]envSnapshot)
	cleanup := func() {
		restoreEnvSnapshot(envSnapshots)
	}

	if profile := strings.TrimSpace(syncAWSProfile); profile != "" {
		if err := setEnvWithSnapshot(envSnapshots, "AWS_PROFILE", profile); err != nil {
			return cleanup, fmt.Errorf("set AWS_PROFILE: %w", err)
		}
	}

	webIdentityToken := strings.TrimSpace(syncAWSWebIDTokenFile)
	webIdentityRole := strings.TrimSpace(syncAWSWebIDRoleARN)
	if webIdentityToken == "" && webIdentityRole == "" {
		return cleanup, nil
	}
	if webIdentityToken == "" || webIdentityRole == "" {
		return cleanup, fmt.Errorf("--aws-web-identity-token-file and --aws-web-identity-role-arn must be set together")
	}
	if err := validateReadableFile(webIdentityToken, "--aws-web-identity-token-file"); err != nil {
		return cleanup, err
	}

	if err := setEnvWithSnapshot(envSnapshots, "AWS_WEB_IDENTITY_TOKEN_FILE", webIdentityToken); err != nil {
		return cleanup, fmt.Errorf("set AWS_WEB_IDENTITY_TOKEN_FILE: %w", err)
	}
	if err := setEnvWithSnapshot(envSnapshots, "AWS_ROLE_ARN", webIdentityRole); err != nil {
		return cleanup, fmt.Errorf("set AWS_ROLE_ARN: %w", err)
	}

	roleSession := strings.TrimSpace(syncAWSRoleSession)
	if roleSession != "" {
		if err := setEnvWithSnapshot(envSnapshots, "AWS_ROLE_SESSION_NAME", roleSession); err != nil {
			return cleanup, fmt.Errorf("set AWS_ROLE_SESSION_NAME: %w", err)
		}
	}

	return cleanup, nil
}

func applyAWSAssumeRoleOverride(ctx context.Context, cfg aws.Config) (aws.Config, error) {
	roleARN := strings.TrimSpace(syncAWSRoleARN)
	sourceIdentity := strings.TrimSpace(syncAWSRoleSourceID)
	durationRaw := strings.TrimSpace(syncAWSRoleDuration)
	roleTags := parseCommaSeparatedValues(syncAWSRoleTags)
	transitiveTagKeys := parseCommaSeparatedValues(syncAWSRoleTransitive)
	if roleARN == "" {
		if durationRaw != "" || len(roleTags) > 0 || len(transitiveTagKeys) > 0 || sourceIdentity != "" {
			return cfg, fmt.Errorf("--aws-role-duration-seconds/--aws-role-session-tags/--aws-role-transitive-tag-keys/--aws-role-source-identity require --aws-role-arn")
		}
		return cfg, nil
	}

	mfaSerial := strings.TrimSpace(syncAWSRoleMFASerial)
	mfaToken := strings.TrimSpace(syncAWSRoleMFAToken)
	if mfaToken != "" && mfaSerial == "" {
		return cfg, fmt.Errorf("--aws-role-mfa-token requires --aws-role-mfa-serial")
	}

	durationSeconds, err := parseBoundedPositiveIntDirective(syncAWSRoleDuration, "--aws-role-duration-seconds", 900, 43200)
	if err != nil {
		return cfg, err
	}

	tags, transitiveTagKeys, err := parseAWSSessionTagDirectives(roleTags, transitiveTagKeys)
	if err != nil {
		return cfg, err
	}

	assumedCfg, err := assumeRoleConfigWithScheduledOptions(
		ctx,
		cfg,
		roleARN,
		strings.TrimSpace(syncAWSRoleSession),
		strings.TrimSpace(syncAWSRoleExternalID),
		mfaSerial,
		mfaToken,
		sourceIdentity,
		durationSeconds,
		tags,
		transitiveTagKeys,
	)
	if err != nil {
		return cfg, fmt.Errorf("assume AWS role %q: %w", roleARN, err)
	}

	return assumedCfg, nil
}
