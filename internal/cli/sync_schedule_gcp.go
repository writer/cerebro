package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/snowflake"
	nativesync "github.com/writer/cerebro/internal/sync"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type scheduledGCPAuthConfig struct {
	Cleanup         func()
	Summary         string
	ClientOptions   []option.ClientOption
	CredentialsFile string
	CredentialsJSON []byte
}

type gcpProjectPreflightSpec struct {
	ProjectID      string
	OrgID          string
	RunNativeSync  bool
	RunSecurity    bool
	SecurityFilter []string
	ClientOptions  []option.ClientOption
}

func executeGCPSync(ctx context.Context, client *snowflake.Client, schedule *SyncSchedule) error {
	spec := parseScheduledSyncSpec(schedule.Table)
	authConfig, err := applyScheduledGCPAuthFn(spec)
	if err != nil {
		return err
	}
	if authConfig == nil {
		authConfig = &scheduledGCPAuthConfig{Cleanup: func() {}}
	}
	if authConfig.Cleanup != nil {
		defer authConfig.Cleanup()
	}

	if authConfig.Summary != "" {
		Info("[%s] GCP auth override: %s", schedule.Name, authConfig.Summary)
		slog.Default().Info("scheduled_sync_audit", "event", "auth_override", "schedule", schedule.Name, "provider", "gcp", "summary", authConfig.Summary)
	}

	syncCtx := ctx
	if len(authConfig.ClientOptions) > 0 {
		syncCtx = nativesync.WithGCPClientOptions(ctx, authConfig.ClientOptions...)
	}

	if err := preflightScheduledGCPAuthFn(syncCtx, schedule, spec, authConfig); err != nil {
		return err
	}

	projectTimeout := defaultGCPProjectTimeout
	if timeoutSeconds, err := parseBoundedPositiveIntDirective(spec.GCPProjectTimeoutSeconds, "gcp_project_timeout_seconds", minGCPProjectTimeoutSeconds, maxGCPProjectTimeoutSeconds); err != nil {
		return err
	} else if timeoutSeconds > 0 {
		projectTimeout = time.Duration(timeoutSeconds) * time.Second
	}

	nativeFilter, securityFilter := splitGCPScheduledTableFilters(spec.TableFilter)
	runNativeSync := len(spec.TableFilter) == 0 || len(nativeFilter) > 0
	runSecuritySync := len(spec.TableFilter) == 0 || len(securityFilter) > 0
	requiresProjectScope := runNativeSync || gcpSecurityFiltersRequireProject(securityFilter)

	projects := append([]string{}, spec.GCPProjects...)
	projects = append(projects, parseTableFilter(firstNonEmptyEnv("CEREBRO_GCP_PROJECTS", "GCP_PROJECTS"))...)
	if project := firstNonEmptyEnv("CEREBRO_GCP_PROJECT", "GCP_PROJECT", "GOOGLE_CLOUD_PROJECT"); project != "" {
		projects = append(projects, project)
	}
	projects = uniqueNonEmpty(projects)

	orgID := spec.GCPOrg
	if orgID == "" {
		orgID = firstNonEmptyEnv("CEREBRO_GCP_ORG", "GCP_ORG_ID")
	}
	if orgID != "" && requiresProjectScope {
		orgProjects, err := listOrganizationProjectsFn(syncCtx, orgID)
		if err != nil {
			return fmt.Errorf("discover GCP projects for org %q: %w", orgID, err)
		}
		projects = uniqueNonEmpty(append(projects, orgProjects...))
	}

	if len(projects) == 0 && !requiresProjectScope {
		projects = []string{""}
	}

	if len(projects) == 0 {
		return fmt.Errorf("scheduled GCP sync requires project scope for native and project-level security tables; set project=<id>/projects=<id|id2>/org=<id> in --table or configure CEREBRO_GCP_PROJECT, GCP_PROJECT, or GOOGLE_CLOUD_PROJECT")
	}

	Info("[%s] Executing GCP sync for %d project(s)...", schedule.Name, len(projects))
	if len(spec.TableFilter) > 0 {
		Info("[%s] Filtering GCP tables: %s", schedule.Name, strings.Join(spec.TableFilter, ", "))
		if len(nativeFilter) > 0 {
			Info("[%s] Native GCP table filter: %s", schedule.Name, strings.Join(nativeFilter, ", "))
		}
		if len(securityFilter) > 0 {
			Info("[%s] GCP security table filter: %s", schedule.Name, strings.Join(securityFilter, ", "))
		}
	}

	var errs []error
	for _, projectID := range projects {
		projectCtx, cancel := context.WithTimeout(syncCtx, projectTimeout)
		nativeTimedOut := false
		projectLabel := gcpProjectScopeLabel(projectID)

		if runNativeSync {
			if err := preflightGCPProjectAccessFn(projectCtx, gcpProjectPreflightSpec{
				ProjectID:      projectID,
				OrgID:          orgID,
				RunNativeSync:  true,
				RunSecurity:    false,
				SecurityFilter: securityFilter,
				ClientOptions:  authConfig.ClientOptions,
			}); err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(projectCtx.Err(), context.DeadlineExceeded) {
					errs = append(errs, fmt.Errorf("project %s native preflight timed out after %s", projectLabel, projectTimeout.Round(time.Second)))
				} else {
					errs = append(errs, fmt.Errorf("project %s native preflight: %w", projectLabel, err))
				}
				cancel()
				continue
			}

			if err := runScheduledGCPNativeSyncFn(projectCtx, client, projectID, nativeFilter); err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(projectCtx.Err(), context.DeadlineExceeded) {
					nativeTimedOut = true
					errs = append(errs, fmt.Errorf("project %s native sync timed out after %s", projectLabel, projectTimeout.Round(time.Second)))
				} else {
					errs = append(errs, fmt.Errorf("project %s native sync: %w", projectLabel, err))
				}
			}
		}

		if runNativeSync && (nativeTimedOut || projectCtx.Err() != nil) {
			cancel()
			continue
		}

		if runSecuritySync {
			if err := preflightGCPProjectAccessFn(projectCtx, gcpProjectPreflightSpec{
				ProjectID:      projectID,
				OrgID:          orgID,
				RunNativeSync:  false,
				RunSecurity:    true,
				SecurityFilter: securityFilter,
				ClientOptions:  authConfig.ClientOptions,
			}); err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(projectCtx.Err(), context.DeadlineExceeded) {
					errs = append(errs, fmt.Errorf("project %s security preflight timed out after %s", projectLabel, projectTimeout.Round(time.Second)))
				} else {
					errs = append(errs, fmt.Errorf("project %s security preflight: %w", projectLabel, err))
				}
				cancel()
				continue
			}

			if err := runScheduledGCPSecuritySyncFn(projectCtx, client, projectID, orgID, securityFilter); err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(projectCtx.Err(), context.DeadlineExceeded) {
					errs = append(errs, fmt.Errorf("project %s security sync timed out after %s", projectLabel, projectTimeout.Round(time.Second)))
				} else {
					errs = append(errs, fmt.Errorf("project %s security sync: %w", projectLabel, err))
				}
			}
		}

		cancel()
	}

	return summarizeSyncRunErrors("scheduled GCP sync", errs)
}

func scheduledGCPAuthMethod(spec scheduledSyncSpec, authCfg *scheduledGCPAuthConfig) string {
	if strings.TrimSpace(spec.GCPImpersonateServiceAccount) != "" {
		return "service_account_impersonation"
	}
	if authCfg != nil && strings.TrimSpace(authCfg.CredentialsFile) != "" {
		return "credentials_file"
	}
	return "adc"
}

func applyScheduledGCPAuth(spec scheduledSyncSpec) (*scheduledGCPAuthConfig, error) {
	authCfg := &scheduledGCPAuthConfig{}
	envSnapshots := make(map[string]envSnapshot)
	tempCredentialsFile := ""
	authCfg.Cleanup = func() {
		if tempCredentialsFile != "" {
			_ = os.Remove(tempCredentialsFile)
		}
		restoreEnvSnapshot(envSnapshots)
	}

	credentialsFile := strings.TrimSpace(spec.GCPCredentialsFile)
	if credentialsFile == "" {
		credentialsFile = firstNonEmptyEnv("CEREBRO_GCP_CREDENTIALS_FILE")
	}
	if credentialsFile != "" {
		if err := validateReadableFile(credentialsFile, "gcp_credentials_file"); err != nil {
			authCfg.Cleanup()
			return nil, err
		}
	}

	impersonateServiceAccount := strings.TrimSpace(spec.GCPImpersonateServiceAccount)
	if impersonateServiceAccount == "" {
		impersonateServiceAccount = firstNonEmptyEnv("CEREBRO_GCP_IMPERSONATE_SERVICE_ACCOUNT")
	}

	delegates := uniqueNonEmpty(spec.GCPImpersonateDelegates)
	if len(delegates) == 0 {
		delegates = uniqueNonEmpty(parseCommaSeparatedValues(firstNonEmptyEnv("CEREBRO_GCP_IMPERSONATE_DELEGATES")))
	}

	tokenLifetimeDirective := strings.TrimSpace(spec.GCPImpersonateTokenLifetime)
	if tokenLifetimeDirective == "" {
		tokenLifetimeDirective = firstNonEmptyEnv("CEREBRO_GCP_IMPERSONATE_TOKEN_LIFETIME_SECONDS")
	}
	tokenLifetimeSeconds, err := parseBoundedPositiveIntDirective(tokenLifetimeDirective, "gcp_impersonate_token_lifetime_seconds", 600, 43200)
	if err != nil {
		authCfg.Cleanup()
		return nil, err
	}

	wifAudience := strings.TrimSpace(firstNonEmptyEnv("CEREBRO_GCP_WIF_AUDIENCE"))

	if impersonateServiceAccount == "" {
		if len(delegates) > 0 {
			authCfg.Cleanup()
			return nil, fmt.Errorf("gcp_impersonate_delegates requires gcp_impersonate_service_account")
		}
		if tokenLifetimeSeconds > 0 {
			authCfg.Cleanup()
			return nil, fmt.Errorf("gcp_impersonate_token_lifetime_seconds requires gcp_impersonate_service_account")
		}
	}

	if credentialsFile == "" && wifAudience != "" {
		if err := ensureAWSEnvCredentials(context.Background(), envSnapshots); err != nil {
			authCfg.Cleanup()
			return nil, fmt.Errorf("resolve AWS credentials for gcp_wif_audience: %w", err)
		}

		tempCredentialsFile, err = writeWIFExternalAccountCredentials(wifAudience, impersonateServiceAccount, delegates)
		if err != nil {
			authCfg.Cleanup()
			return nil, err
		}

		if err := setEnvWithSnapshot(envSnapshots, "GOOGLE_APPLICATION_CREDENTIALS", tempCredentialsFile); err != nil {
			authCfg.Cleanup()
			return nil, fmt.Errorf("set GOOGLE_APPLICATION_CREDENTIALS: %w", err)
		}

		encoded, readErr := os.ReadFile(tempCredentialsFile)
		if readErr != nil {
			authCfg.Cleanup()
			return nil, fmt.Errorf("read temporary WIF credentials file %q: %w", tempCredentialsFile, readErr)
		}

		clientOpt, optionErr := gcpAuthOptionFromCredentialJSON(encoded, "gcp_wif_audience")
		if optionErr != nil {
			authCfg.Cleanup()
			return nil, optionErr
		}

		authCfg.CredentialsFile = tempCredentialsFile
		authCfg.CredentialsJSON = encoded
		authCfg.ClientOptions = []option.ClientOption{clientOpt}
		authCfg.Summary = fmt.Sprintf("wif_audience=%s", wifAudience)
		if impersonateServiceAccount != "" {
			authCfg.Summary = fmt.Sprintf("%s impersonate_service_account=%s delegates=%d", authCfg.Summary, impersonateServiceAccount, len(delegates))
		}
		return authCfg, nil
	}

	if impersonateServiceAccount == "" {
		if credentialsFile == "" {
			return authCfg, nil
		}

		credentialsData, readErr := os.ReadFile(credentialsFile) // #nosec G304 -- credentials file path is validated by validateReadableFile
		if readErr != nil {
			authCfg.Cleanup()
			return nil, fmt.Errorf("read gcp_credentials_file %q: %w", credentialsFile, readErr)
		}
		clientOpt, optionErr := gcpAuthOptionFromCredentialJSON(credentialsData, "gcp_credentials_file")
		if optionErr != nil {
			authCfg.Cleanup()
			return nil, optionErr
		}

		authCfg.Summary = fmt.Sprintf("credentials_file=%s", credentialsFile)
		authCfg.CredentialsFile = credentialsFile
		authCfg.CredentialsJSON = credentialsData
		authCfg.ClientOptions = []option.ClientOption{clientOpt}
		return authCfg, nil
	}

	sourcePath, err := resolveGCPSourceCredentialsPath(credentialsFile)
	if err != nil {
		authCfg.Cleanup()
		return nil, err
	}

	sourceData, err := os.ReadFile(sourcePath) // #nosec G304 -- sourcePath is resolved/validated before read
	if err != nil {
		authCfg.Cleanup()
		return nil, fmt.Errorf("read GCP source credentials %q: %w", sourcePath, err)
	}

	var sourceCredentials map[string]interface{}
	if err := json.Unmarshal(sourceData, &sourceCredentials); err != nil {
		authCfg.Cleanup()
		return nil, fmt.Errorf("parse GCP source credentials %q: %w", sourcePath, err)
	}
	if len(sourceCredentials) == 0 {
		authCfg.Cleanup()
		return nil, fmt.Errorf("GCP source credentials %q are empty", sourcePath)
	}

	impersonationURL := fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken", url.PathEscape(impersonateServiceAccount))
	payload := map[string]interface{}{
		"type":                              "impersonated_service_account",
		"service_account_impersonation_url": impersonationURL,
		"source_credentials":                sourceCredentials,
	}
	if tokenLifetimeSeconds > 0 {
		payload["token_lifetime_seconds"] = tokenLifetimeSeconds
	}
	if len(delegates) > 0 {
		payload["delegates"] = delegates
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		authCfg.Cleanup()
		return nil, fmt.Errorf("marshal impersonated GCP credentials: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "cerebro-scheduled-gcp-impersonated-*.json")
	if err != nil {
		authCfg.Cleanup()
		return nil, fmt.Errorf("create temporary GCP impersonation credentials file: %w", err)
	}
	tempCredentialsFile = tmpFile.Name()
	if _, err := tmpFile.Write(encoded); err != nil {
		_ = tmpFile.Close()
		authCfg.Cleanup()
		return nil, fmt.Errorf("write temporary GCP impersonation credentials file: %w", err)
	}
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		authCfg.Cleanup()
		return nil, fmt.Errorf("set permissions on temporary GCP impersonation credentials file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		authCfg.Cleanup()
		return nil, fmt.Errorf("close temporary GCP impersonation credentials file: %w", err)
	}
	clientOpt, optionErr := gcpAuthOptionFromCredentialJSON(encoded, "gcp_impersonate_service_account")
	if optionErr != nil {
		authCfg.Cleanup()
		return nil, optionErr
	}

	authCfg.CredentialsFile = tempCredentialsFile
	authCfg.CredentialsJSON = encoded
	authCfg.ClientOptions = []option.ClientOption{clientOpt}
	authCfg.Summary = fmt.Sprintf("impersonate_service_account=%s delegates=%d", impersonateServiceAccount, len(delegates))
	if tokenLifetimeSeconds > 0 {
		authCfg.Summary = fmt.Sprintf("%s token_lifetime_seconds=%d", authCfg.Summary, tokenLifetimeSeconds)
	}

	return authCfg, nil
}

func preflightScheduledGCPAuth(ctx context.Context, schedule *SyncSchedule, spec scheduledSyncSpec, authCfg *scheduledGCPAuthConfig) error {
	authMethod := scheduledGCPAuthMethod(spec, authCfg)
	recordFailure := func(format string, args ...interface{}) error {
		metrics.RecordScheduledAuthPreflight("gcp", authMethod, false)
		return fmt.Errorf(format, args...)
	}

	var (
		credentials *google.Credentials
		err         error
	)

	if authCfg != nil && len(authCfg.CredentialsJSON) > 0 {
		credentials, err = google.CredentialsFromJSON(ctx, authCfg.CredentialsJSON, "https://www.googleapis.com/auth/cloud-platform")
	} else if authCfg != nil && strings.TrimSpace(authCfg.CredentialsFile) != "" {
		encoded, readErr := os.ReadFile(strings.TrimSpace(authCfg.CredentialsFile))
		if readErr != nil {
			return recordFailure("[%s] GCP auth preflight failed: read credentials file %q: %w", schedule.Name, authCfg.CredentialsFile, readErr)
		}
		credentials, err = google.CredentialsFromJSON(ctx, encoded, "https://www.googleapis.com/auth/cloud-platform")
	} else {
		credentials, err = google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	}
	if err != nil {
		return recordFailure("[%s] GCP auth preflight failed: %w", schedule.Name, err)
	}

	token, err := credentials.TokenSource.Token()
	if err != nil {
		return recordFailure("[%s] GCP auth preflight token retrieval failed: %w", schedule.Name, err)
	}
	metrics.RecordScheduledAuthPreflight("gcp", authMethod, true)

	principal := strings.TrimSpace(spec.GCPImpersonateServiceAccount)
	if principal == "" {
		principal = "default"
	}

	attrs := []any{
		"event", "auth_preflight",
		"schedule", schedule.Name,
		"provider", "gcp",
		"auth_method", authMethod,
		"principal", principal,
		"status", "success",
	}
	if authCfg != nil && strings.TrimSpace(authCfg.CredentialsFile) != "" {
		attrs = append(attrs, "credentials_file", authCfg.CredentialsFile)
	}
	if !token.Expiry.IsZero() {
		attrs = append(attrs, "token_expiry", token.Expiry.UTC().Format(time.RFC3339))
	}
	slog.Default().Info("scheduled_sync_audit", attrs...)

	if token.Expiry.IsZero() {
		Info("[%s] GCP auth preflight succeeded: method=%s principal=%s", schedule.Name, authMethod, principal)
		return nil
	}

	Info("[%s] GCP auth preflight succeeded: method=%s principal=%s token_expiry=%s", schedule.Name, authMethod, principal, token.Expiry.UTC().Format(time.RFC3339))
	return nil
}

func preflightGCPProjectAccess(ctx context.Context, spec gcpProjectPreflightSpec) error {
	if spec.RunNativeSync {
		projectID := strings.TrimSpace(spec.ProjectID)
		if projectID == "" {
			return fmt.Errorf("native GCP sync preflight requires project scope")
		}
		if err := probeGCPCloudAssetAccessFn(ctx, projectID, spec.ClientOptions); err != nil {
			return fmt.Errorf("cloud asset preflight failed: %w", err)
		}
	}

	if spec.RunSecurity && gcpSecurityFilterIncludesSCC(spec.SecurityFilter) {
		orgID := strings.TrimSpace(spec.OrgID)
		if orgID == "" {
			return fmt.Errorf("security command center preflight requires gcp-org scope (org=<id> or CEREBRO_GCP_ORG/GCP_ORG_ID)")
		}
		if err := probeGCPSCCAccessFn(ctx, orgID, spec.ClientOptions); err != nil {
			return fmt.Errorf("security command center preflight failed: %w", err)
		}
	}

	return nil
}

func gcpSecurityFilterIncludesSCC(filters []string) bool {
	if len(filters) == 0 {
		return true
	}

	for _, filter := range filters {
		switch strings.ToLower(strings.TrimSpace(filter)) {
		case "gcp_scc_findings", "scc_findings", "security_command_center_findings":
			return true
		}
	}

	return false
}

func probeGCPCloudAssetAccess(ctx context.Context, projectID string, clientOptions []option.ClientOption) error {
	client, err := asset.NewClient(ctx, clientOptions...)
	if err != nil {
		return fmt.Errorf("create cloud asset client: %w", err)
	}
	defer func() { _ = client.Close() }()

	req := &assetpb.SearchAllResourcesRequest{
		Scope:      fmt.Sprintf("projects/%s", projectID),
		AssetTypes: []string{"cloudresourcemanager.googleapis.com/Project"},
		PageSize:   1,
	}

	iter := client.SearchAllResources(ctx, req)
	if _, err := iter.Next(); err != nil && !errors.Is(err, iterator.Done) {
		return fmt.Errorf("search resources for projects/%s: %w", projectID, err)
	}

	return nil
}

func probeGCPSCCAccess(ctx context.Context, orgID string, clientOptions []option.ClientOption) error {
	client, err := securitycenter.NewClient(ctx, clientOptions...)
	if err != nil {
		return fmt.Errorf("create security center client: %w", err)
	}
	defer func() { _ = client.Close() }()

	req := &securitycenterpb.ListFindingsRequest{
		Parent:   fmt.Sprintf("organizations/%s/sources/-", orgID),
		Filter:   `state="ACTIVE"`,
		PageSize: 1,
	}

	iter := client.ListFindings(ctx, req)
	if _, err := iter.Next(); err != nil && !errors.Is(err, iterator.Done) {
		return fmt.Errorf("list findings for organizations/%s: %w", orgID, err)
	}

	return nil
}

func gcpProjectScopeLabel(projectID string) string {
	trimmed := strings.TrimSpace(projectID)
	if trimmed == "" {
		return "organization_scope"
	}
	return trimmed
}

func gcpAuthOptionFromCredentialJSON(raw []byte, source string) (option.ClientOption, error) {
	credType, err := detectGCPCredentialsType(raw, source)
	if err != nil {
		return nil, err
	}
	return option.WithAuthCredentialsJSON(credType, raw), nil
}

func detectGCPCredentialsType(raw []byte, source string) (option.CredentialsType, error) {
	var payload struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("parse %s JSON credentials: %w", source, err)
	}

	switch strings.TrimSpace(payload.Type) {
	case "service_account":
		return option.ServiceAccount, nil
	case "authorized_user":
		return option.AuthorizedUser, nil
	case "external_account", "external_account_authorized_user":
		return option.ExternalAccount, nil
	case "impersonated_service_account":
		return option.ImpersonatedServiceAccount, nil
	default:
		return "", fmt.Errorf("%s has unsupported credentials type %q", source, payload.Type)
	}
}

func runScheduledGCPNativeSync(ctx context.Context, client *snowflake.Client, projectID string, tableFilter []string) error {
	client, closeClient, err := ensureSnowflakeClientForDirectScheduledSync(client, "gcp")
	if err != nil {
		return err
	}
	defer closeClient()

	opts := []nativesync.GCPEngineOption{nativesync.WithGCPProject(projectID)}
	if len(tableFilter) > 0 {
		opts = append(opts, nativesync.WithGCPTableFilter(tableFilter))
	}
	syncer := nativesync.NewGCPSyncEngine(client, slog.Default(), opts...)
	_, err = syncer.SyncAll(ctx)
	return err
}

func runScheduledGCPSecuritySync(ctx context.Context, client *snowflake.Client, projectID, orgID string, tableFilter []string) error {
	client, closeClient, err := ensureSnowflakeClientForDirectScheduledSync(client, "gcp")
	if err != nil {
		return err
	}
	defer closeClient()

	secOpts := []nativesync.GCPSecurityOption{}
	if len(tableFilter) > 0 {
		secOpts = append(secOpts, nativesync.WithGCPSecurityTableFilter(tableFilter))
	}
	securitySyncer := nativesync.NewGCPSecuritySync(client, slog.Default(), projectID, orgID, secOpts...)
	return securitySyncer.SyncAll(ctx)
}

func splitGCPScheduledTableFilters(tables []string) (native []string, security []string) {
	if len(tables) == 0 {
		return nil, nil
	}

	native = make([]string, 0, len(tables))
	security = make([]string, 0, len(tables))
	for _, table := range tables {
		normalized := strings.ToLower(strings.TrimSpace(table))
		if normalized == "" {
			continue
		}
		if _, ok := gcpScheduledSecurityTableAliases[normalized]; ok {
			security = append(security, normalized)
			continue
		}
		native = append(native, normalized)
	}

	if len(native) == 0 {
		native = nil
	}
	if len(security) == 0 {
		security = nil
	}

	return native, security
}

func gcpSecurityFiltersRequireProject(filters []string) bool {
	if len(filters) == 0 {
		return true
	}

	for _, filter := range filters {
		normalized := strings.ToLower(strings.TrimSpace(filter))
		if normalized == "" {
			continue
		}
		if normalized == "gcp_scc_findings" || normalized == "scc_findings" || normalized == "security_command_center_findings" {
			continue
		}
		return true
	}

	return false
}
