package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/writerinternal/cerebro/internal/snowflake"
)

func TestParseScheduledSyncSpec(t *testing.T) {
	spec := parseScheduledSyncSpec("project=proj-a,projects=proj-b|proj-c,org:org-123,subscription=sub-123,gcp_compute_instances, azure_compute_virtual_machines")

	if spec.GCPOrg != "org-123" {
		t.Fatalf("expected org-123, got %q", spec.GCPOrg)
	}
	if spec.AzureSubscription != "sub-123" {
		t.Fatalf("expected sub-123, got %q", spec.AzureSubscription)
	}
	if len(spec.GCPProjects) != 3 {
		t.Fatalf("expected 3 projects, got %d (%v)", len(spec.GCPProjects), spec.GCPProjects)
	}
	if !slices.Contains(spec.GCPProjects, "proj-a") || !slices.Contains(spec.GCPProjects, "proj-b") || !slices.Contains(spec.GCPProjects, "proj-c") {
		t.Fatalf("unexpected project set: %v", spec.GCPProjects)
	}
	if len(spec.TableFilter) != 2 {
		t.Fatalf("expected 2 table filters, got %d (%v)", len(spec.TableFilter), spec.TableFilter)
	}
	if spec.TableFilter[0] != "gcp_compute_instances" || spec.TableFilter[1] != "azure_compute_virtual_machines" {
		t.Fatalf("unexpected table filters: %v", spec.TableFilter)
	}
}

func TestParseScheduledSyncSpec_AuthDirectives(t *testing.T) {
	spec := parseScheduledSyncSpec("aws_profile=prod,aws_role_arn=arn:aws:iam::123456789012:role/SyncRole,aws_role_external_id=ext-123,aws_config_file=/tmp/config,aws_shared_credentials_file=/tmp/creds,aws_credential_process=/opt/bin/creds,aws_role_duration_seconds=1800,aws_role_session_tags=env=prod|owner=platform,aws_role_transitive_tag_keys=env,gcp_credentials_file=/tmp/gcp.json,gcp_impersonate_service_account=svc@test.iam.gserviceaccount.com,gcp_impersonate_delegates=delegate-a|delegate-b,gcp_impersonate_token_lifetime_seconds=2400,aws_iam_roles")

	if spec.AWSProfile != "prod" {
		t.Fatalf("expected aws profile prod, got %q", spec.AWSProfile)
	}
	if spec.AWSRoleARN != "arn:aws:iam::123456789012:role/SyncRole" {
		t.Fatalf("unexpected role arn: %q", spec.AWSRoleARN)
	}
	if spec.AWSRoleExternalID != "ext-123" {
		t.Fatalf("unexpected external id: %q", spec.AWSRoleExternalID)
	}
	if spec.AWSConfigFile != "/tmp/config" {
		t.Fatalf("unexpected aws config file: %q", spec.AWSConfigFile)
	}
	if spec.AWSSharedCredentialsFile != "/tmp/creds" {
		t.Fatalf("unexpected aws shared credentials file: %q", spec.AWSSharedCredentialsFile)
	}
	if spec.AWSCredentialProcess != "/opt/bin/creds" {
		t.Fatalf("unexpected aws credential process: %q", spec.AWSCredentialProcess)
	}
	if spec.AWSRoleDurationSeconds != "1800" {
		t.Fatalf("unexpected aws role duration: %q", spec.AWSRoleDurationSeconds)
	}
	if len(spec.AWSRoleSessionTags) != 2 {
		t.Fatalf("unexpected aws role session tags: %v", spec.AWSRoleSessionTags)
	}
	if len(spec.AWSRoleTransitiveTagKeys) != 1 || spec.AWSRoleTransitiveTagKeys[0] != "env" {
		t.Fatalf("unexpected aws transitive tag keys: %v", spec.AWSRoleTransitiveTagKeys)
	}
	if spec.GCPCredentialsFile != "/tmp/gcp.json" {
		t.Fatalf("unexpected gcp credentials file: %q", spec.GCPCredentialsFile)
	}
	if spec.GCPImpersonateServiceAccount != "svc@test.iam.gserviceaccount.com" {
		t.Fatalf("unexpected gcp impersonation service account: %q", spec.GCPImpersonateServiceAccount)
	}
	if len(spec.GCPImpersonateDelegates) != 2 {
		t.Fatalf("expected two delegates, got %v", spec.GCPImpersonateDelegates)
	}
	if spec.GCPImpersonateTokenLifetime != "2400" {
		t.Fatalf("unexpected gcp impersonate token lifetime: %q", spec.GCPImpersonateTokenLifetime)
	}
	if spec.TableFilter == nil || len(spec.TableFilter) != 1 || spec.TableFilter[0] != "aws_iam_roles" {
		t.Fatalf("unexpected table filters: %v", spec.TableFilter)
	}
}

func TestValidScheduleProviders(t *testing.T) {
	providers := validScheduleProviders()
	if !slices.Contains(providers, "aws") || !slices.Contains(providers, "gcp") || !slices.Contains(providers, "azure") {
		t.Fatalf("expected native providers in valid list: %v", providers)
	}
	if !slices.Contains(providers, "github") {
		t.Fatalf("expected github in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "wiz") {
		t.Fatalf("expected wiz in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "auth0") {
		t.Fatalf("expected auth0 in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "terraform_cloud") {
		t.Fatalf("expected terraform_cloud in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "splunk") {
		t.Fatalf("expected splunk in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "semgrep") {
		t.Fatalf("expected semgrep in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "servicenow") {
		t.Fatalf("expected servicenow in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "workday") {
		t.Fatalf("expected workday in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "bamboohr") {
		t.Fatalf("expected bamboohr in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "onelogin") {
		t.Fatalf("expected onelogin in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "jumpcloud") {
		t.Fatalf("expected jumpcloud in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "duo") {
		t.Fatalf("expected duo in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "pingidentity") {
		t.Fatalf("expected pingidentity in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "cyberark") {
		t.Fatalf("expected cyberark in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "sailpoint") {
		t.Fatalf("expected sailpoint in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "saviynt") {
		t.Fatalf("expected saviynt in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "forgerock") {
		t.Fatalf("expected forgerock in valid providers: %v", providers)
	}
	if !slices.Contains(providers, "oracle_idcs") {
		t.Fatalf("expected oracle_idcs in valid providers: %v", providers)
	}
}

func TestExecuteScheduledSync_RoutesByProvider(t *testing.T) {
	t.Setenv("JOB_QUEUE_URL", "")
	t.Setenv("JOB_TABLE_NAME", "")

	originalAWSSync := executeAWSSyncFn
	originalGCPSync := executeGCPSyncFn
	originalAzureSync := executeAzureSyncFn
	originalProviderSync := executeProviderSyncFn
	originalEnqueue := enqueueScheduledNativeSyncFn
	t.Cleanup(func() {
		executeAWSSyncFn = originalAWSSync
		executeGCPSyncFn = originalGCPSync
		executeAzureSyncFn = originalAzureSync
		executeProviderSyncFn = originalProviderSync
		enqueueScheduledNativeSyncFn = originalEnqueue
	})

	called := ""
	executeAWSSyncFn = func(context.Context, *snowflake.Client, *SyncSchedule) error {
		called = "aws"
		return nil
	}
	executeGCPSyncFn = func(context.Context, *snowflake.Client, *SyncSchedule) error {
		called = "gcp"
		return nil
	}
	executeAzureSyncFn = func(context.Context, *snowflake.Client, *SyncSchedule) error {
		called = "azure"
		return nil
	}
	executeProviderSyncFn = func(context.Context, *snowflake.Client, *SyncSchedule) error {
		called = "provider"
		return nil
	}
	enqueueScheduledNativeSyncFn = func(context.Context, *SyncSchedule) error {
		called = "enqueue"
		return nil
	}

	tests := []struct {
		provider string
		want     string
	}{
		{provider: "aws", want: "aws"},
		{provider: "gcp", want: "gcp"},
		{provider: "azure", want: "azure"},
		{provider: "okta", want: "provider"},
		{provider: "GiThUb", want: "provider"},
	}

	for _, tt := range tests {
		called = ""
		err := executeScheduledSync(context.Background(), nil, &SyncSchedule{Provider: tt.provider})
		if err != nil {
			t.Fatalf("provider %s: unexpected error: %v", tt.provider, err)
		}
		if called != tt.want {
			t.Fatalf("provider %s: expected route %s, got %s", tt.provider, tt.want, called)
		}
	}
}

func TestExecuteScheduledSync_UsesWorkerForNativeProviders(t *testing.T) {
	t.Setenv("JOB_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789012/test")
	t.Setenv("JOB_TABLE_NAME", "jobs")

	originalAWSSync := executeAWSSyncFn
	originalGCPSync := executeGCPSyncFn
	originalAzureSync := executeAzureSyncFn
	originalProviderSync := executeProviderSyncFn
	originalEnqueue := enqueueScheduledNativeSyncFn
	t.Cleanup(func() {
		executeAWSSyncFn = originalAWSSync
		executeGCPSyncFn = originalGCPSync
		executeAzureSyncFn = originalAzureSync
		executeProviderSyncFn = originalProviderSync
		enqueueScheduledNativeSyncFn = originalEnqueue
	})

	directCalled := false
	executeAWSSyncFn = func(context.Context, *snowflake.Client, *SyncSchedule) error {
		directCalled = true
		return nil
	}

	enqueueCalled := 0
	enqueueScheduledNativeSyncFn = func(_ context.Context, schedule *SyncSchedule) error {
		enqueueCalled++
		if schedule.Provider != "aws" {
			return fmt.Errorf("unexpected provider %q", schedule.Provider)
		}
		return nil
	}

	if err := executeScheduledSync(context.Background(), nil, &SyncSchedule{Provider: "aws"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if directCalled {
		t.Fatalf("expected direct aws sync to be skipped when worker queue is configured")
	}
	if enqueueCalled != 1 {
		t.Fatalf("expected one enqueue call, got %d", enqueueCalled)
	}

	providerCalled := 0
	executeProviderSyncFn = func(context.Context, *snowflake.Client, *SyncSchedule) error {
		providerCalled++
		return nil
	}
	if err := executeScheduledSync(context.Background(), nil, &SyncSchedule{Provider: "okta"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if providerCalled != 1 {
		t.Fatalf("expected provider sync call for non-native provider, got %d", providerCalled)
	}
}

func TestExecuteAWSSync_UsesScheduledAuthDirectives(t *testing.T) {
	originalLoad := loadScheduledAWSConfigFn
	originalPreflight := preflightScheduledAWSAuthFn
	originalRun := runScheduledAWSNativeSyncFn
	t.Cleanup(func() {
		loadScheduledAWSConfigFn = originalLoad
		preflightScheduledAWSAuthFn = originalPreflight
		runScheduledAWSNativeSyncFn = originalRun
	})

	loadCalled := false
	preflightCalled := false
	runCalled := false

	loadScheduledAWSConfigFn = func(_ context.Context, spec scheduledSyncSpec) (aws.Config, error) {
		loadCalled = true
		if spec.AWSProfile != "prod" {
			return aws.Config{}, fmt.Errorf("expected aws profile prod, got %q", spec.AWSProfile)
		}
		if spec.AWSRoleARN == "" {
			return aws.Config{}, fmt.Errorf("expected aws role arn")
		}
		if spec.AWSRoleDurationSeconds != "1800" {
			return aws.Config{}, fmt.Errorf("expected aws role duration 1800, got %q", spec.AWSRoleDurationSeconds)
		}
		if len(spec.AWSRoleSessionTags) != 1 || spec.AWSRoleSessionTags[0] != "env=prod" {
			return aws.Config{}, fmt.Errorf("unexpected aws role session tags: %v", spec.AWSRoleSessionTags)
		}
		return aws.Config{}, nil
	}
	preflightScheduledAWSAuthFn = func(context.Context, *SyncSchedule, scheduledSyncSpec, aws.Config) error {
		preflightCalled = true
		return nil
	}
	runScheduledAWSNativeSyncFn = func(_ context.Context, _ *snowflake.Client, _ aws.Config, tableFilter []string) error {
		runCalled = true
		if len(tableFilter) != 1 || tableFilter[0] != "aws_iam_roles" {
			return fmt.Errorf("unexpected aws table filter: %v", tableFilter)
		}
		return nil
	}

	err := executeAWSSync(context.Background(), nil, &SyncSchedule{
		Name:  "aws-auth",
		Table: "aws_profile=prod,aws_role_arn=arn:aws:iam::123456789012:role/SyncRole,aws_role_duration_seconds=1800,aws_role_session_tags=env=prod,aws_iam_roles",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !loadCalled {
		t.Fatal("expected loadScheduledAWSConfigFn to be called")
	}
	if !preflightCalled {
		t.Fatal("expected preflightScheduledAWSAuthFn to be called")
	}
	if !runCalled {
		t.Fatal("expected runScheduledAWSNativeSyncFn to be called")
	}
}

func TestParseScheduledNativeSyncJobResult(t *testing.T) {
	t.Run("empty payload", func(t *testing.T) {
		parsed, err := parseScheduledNativeSyncJobResult("  ")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed != nil {
			t.Fatalf("expected nil parsed result, got %#v", parsed)
		}
	})

	t.Run("valid payload with failures", func(t *testing.T) {
		raw, err := json.Marshal(map[string]any{
			"provider":             "aws",
			"table":                "aws_iam_accounts",
			"schedule_name":        "hourly",
			"additional_providers": []string{"okta"},
			"failed_additional_providers": []map[string]string{
				{"provider": "sentinelone", "error": "404"},
			},
		})
		if err != nil {
			t.Fatalf("marshal fixture: %v", err)
		}

		parsed, parseErr := parseScheduledNativeSyncJobResult(string(raw))
		if parseErr != nil {
			t.Fatalf("unexpected parse error: %v", parseErr)
		}
		if parsed == nil {
			t.Fatal("expected parsed result")
		}
		if parsed.Provider != "aws" {
			t.Fatalf("expected provider aws, got %q", parsed.Provider)
		}
		if len(parsed.FailedAdditionalProviders) != 1 || parsed.FailedAdditionalProviders[0].Provider != "sentinelone" {
			t.Fatalf("unexpected failed additional providers: %#v", parsed.FailedAdditionalProviders)
		}
	})

	t.Run("invalid payload", func(t *testing.T) {
		if _, err := parseScheduledNativeSyncJobResult("{not-json"); err == nil {
			t.Fatal("expected parse error for invalid payload")
		}
	})
}

func TestRunScheduledSync_RetryAndStatus(t *testing.T) {
	originalExecute := executeScheduledSyncFn
	originalSave := saveScheduleFn
	originalSleep := scheduleSleepFn
	originalNow := scheduleNowFn
	t.Cleanup(func() {
		executeScheduledSyncFn = originalExecute
		saveScheduleFn = originalSave
		scheduleSleepFn = originalSleep
		scheduleNowFn = originalNow
	})

	t.Run("succeeds after retry", func(t *testing.T) {
		attempts := 0
		saves := 0
		executeScheduledSyncFn = func(context.Context, *snowflake.Client, *SyncSchedule) error {
			attempts++
			if attempts < 2 {
				return errors.New("temporary failure")
			}
			return nil
		}
		saveScheduleFn = func(context.Context, *snowflake.Client, *SyncSchedule) error {
			saves++
			return nil
		}
		scheduleSleepFn = func(time.Duration) {}
		now := time.Date(2026, 2, 24, 12, 0, 0, 0, time.UTC)
		scheduleNowFn = func() time.Time {
			return now
		}

		schedule := &SyncSchedule{Name: "hourly", Provider: "aws", Retry: 3, Cron: "0 * * * *"}
		runScheduledSync(nil, schedule)

		if attempts != 2 {
			t.Fatalf("expected 2 attempts, got %d", attempts)
		}
		if saves != 2 {
			t.Fatalf("expected 2 schedule saves, got %d", saves)
		}
		if !strings.HasPrefix(schedule.LastStatus, "success") {
			t.Fatalf("expected success status, got %q", schedule.LastStatus)
		}
	})

	t.Run("fails after all retries", func(t *testing.T) {
		attempts := 0
		executeScheduledSyncFn = func(context.Context, *snowflake.Client, *SyncSchedule) error {
			attempts++
			return errors.New("hard failure")
		}
		saveScheduleFn = func(context.Context, *snowflake.Client, *SyncSchedule) error { return nil }
		scheduleSleepFn = func(time.Duration) {}
		now := time.Date(2026, 2, 24, 12, 0, 0, 0, time.UTC)
		scheduleNowFn = func() time.Time {
			return now
		}

		schedule := &SyncSchedule{Name: "daily", Provider: "gcp", Retry: 2, Cron: "0 0 * * *"}
		runScheduledSync(nil, schedule)

		if attempts != 2 {
			t.Fatalf("expected 2 attempts, got %d", attempts)
		}
		if !strings.HasPrefix(schedule.LastStatus, "failed:") {
			t.Fatalf("expected failed status, got %q", schedule.LastStatus)
		}
	})
}

func TestSplitGCPScheduledTableFilters(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		native, security := splitGCPScheduledTableFilters(nil)
		if native != nil || security != nil {
			t.Fatalf("expected nil filters, got native=%v security=%v", native, security)
		}
	})

	t.Run("mixed native and security aliases", func(t *testing.T) {
		native, security := splitGCPScheduledTableFilters([]string{"gcp_compute_instances", "SCC_FINDINGS", "artifact_images"})
		if len(native) != 1 || native[0] != "gcp_compute_instances" {
			t.Fatalf("unexpected native filter: %v", native)
		}
		if len(security) != 2 || security[0] != "scc_findings" || security[1] != "artifact_images" {
			t.Fatalf("unexpected security filter: %v", security)
		}
	})

	t.Run("security only", func(t *testing.T) {
		native, security := splitGCPScheduledTableFilters([]string{"gcp_scc_findings"})
		if native != nil {
			t.Fatalf("expected nil native filter, got %v", native)
		}
		if len(security) != 1 || security[0] != "gcp_scc_findings" {
			t.Fatalf("unexpected security filter: %v", security)
		}
	})
}

func TestGCPSecurityFiltersRequireProject(t *testing.T) {
	tests := []struct {
		name    string
		filters []string
		want    bool
	}{
		{name: "default security tables", filters: nil, want: true},
		{name: "scc only", filters: []string{"gcp_scc_findings"}, want: false},
		{name: "scc alias", filters: []string{"security_command_center_findings"}, want: false},
		{name: "vulnerabilities", filters: []string{"gcp_container_vulnerabilities"}, want: true},
		{name: "mixed security tables", filters: []string{"scc_findings", "artifact_images"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gcpSecurityFiltersRequireProject(tt.filters); got != tt.want {
				t.Fatalf("expected %v, got %v for filters %v", tt.want, got, tt.filters)
			}
		})
	}
}

func TestExecuteGCPSync_AppliesScheduledAuthDirectives(t *testing.T) {
	originalNative := runScheduledGCPNativeSyncFn
	originalSecurity := runScheduledGCPSecuritySyncFn
	originalApplyAuth := applyScheduledGCPAuthFn
	originalPreflight := preflightScheduledGCPAuthFn
	t.Cleanup(func() {
		runScheduledGCPNativeSyncFn = originalNative
		runScheduledGCPSecuritySyncFn = originalSecurity
		applyScheduledGCPAuthFn = originalApplyAuth
		preflightScheduledGCPAuthFn = originalPreflight
	})

	applyCalled := false
	preflightCalled := false

	applyScheduledGCPAuthFn = func(spec scheduledSyncSpec) (func(), string, error) {
		applyCalled = true
		if spec.GCPCredentialsFile != "/tmp/gcp.json" {
			return nil, "", fmt.Errorf("unexpected gcp credentials file %q", spec.GCPCredentialsFile)
		}
		if spec.GCPImpersonateServiceAccount != "svc@test.iam.gserviceaccount.com" {
			return nil, "", fmt.Errorf("unexpected gcp impersonation service account %q", spec.GCPImpersonateServiceAccount)
		}
		if len(spec.GCPImpersonateDelegates) != 2 {
			return nil, "", fmt.Errorf("unexpected gcp delegates %v", spec.GCPImpersonateDelegates)
		}
		if spec.GCPImpersonateTokenLifetime != "2400" {
			return nil, "", fmt.Errorf("unexpected gcp impersonate token lifetime %q", spec.GCPImpersonateTokenLifetime)
		}
		return func() {}, "impersonate_service_account=svc@test.iam.gserviceaccount.com delegates=2", nil
	}
	preflightScheduledGCPAuthFn = func(context.Context, *SyncSchedule, scheduledSyncSpec) error {
		preflightCalled = true
		return nil
	}
	runScheduledGCPNativeSyncFn = func(context.Context, *snowflake.Client, string, []string) error {
		return nil
	}
	runScheduledGCPSecuritySyncFn = func(context.Context, *snowflake.Client, string, string, []string) error {
		return fmt.Errorf("security sync should not run")
	}

	err := executeGCPSync(context.Background(), nil, &SyncSchedule{
		Name:  "gcp-auth",
		Table: "project=proj-1,gcp_credentials_file=/tmp/gcp.json,gcp_impersonate_service_account=svc@test.iam.gserviceaccount.com,gcp_impersonate_delegates=delegate-a|delegate-b,gcp_impersonate_token_lifetime_seconds=2400,gcp_compute_instances",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !applyCalled {
		t.Fatal("expected applyScheduledGCPAuthFn to be called")
	}
	if !preflightCalled {
		t.Fatal("expected preflightScheduledGCPAuthFn to be called")
	}
}

func TestApplyScheduledGCPAuth_WithCredentialsFile(t *testing.T) {
	originalEnv := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	t.Cleanup(func() {
		_ = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", originalEnv)
	})

	source, err := os.CreateTemp("", "scheduled-gcp-source-*.json")
	if err != nil {
		t.Fatalf("create temp credentials file: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(source.Name())
	})

	if _, err := source.WriteString(`{"type":"service_account"}`); err != nil {
		t.Fatalf("write temp credentials file: %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("close temp credentials file: %v", err)
	}

	if err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/original-gcp-credentials.json"); err != nil {
		t.Fatalf("set env: %v", err)
	}

	cleanup, summary, err := applyScheduledGCPAuth(scheduledSyncSpec{GCPCredentialsFile: source.Name()})
	if err != nil {
		t.Fatalf("unexpected apply error: %v", err)
	}
	if !strings.Contains(summary, "credentials_file=") {
		t.Fatalf("expected credentials file summary, got %q", summary)
	}
	if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != source.Name() {
		t.Fatalf("expected GOOGLE_APPLICATION_CREDENTIALS to be set to source file, got %q", got)
	}

	cleanup()
	if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != "/tmp/original-gcp-credentials.json" {
		t.Fatalf("expected GOOGLE_APPLICATION_CREDENTIALS to be restored, got %q", got)
	}
}

func TestApplyScheduledGCPAuth_WithImpersonation(t *testing.T) {
	originalEnv := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	t.Cleanup(func() {
		_ = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", originalEnv)
	})

	source, err := os.CreateTemp("", "scheduled-gcp-impersonation-source-*.json")
	if err != nil {
		t.Fatalf("create temp credentials file: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(source.Name())
	})

	if _, err := source.WriteString(`{"type":"service_account","client_email":"source@test.iam.gserviceaccount.com"}`); err != nil {
		t.Fatalf("write source credentials: %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("close source credentials: %v", err)
	}

	cleanup, summary, err := applyScheduledGCPAuth(scheduledSyncSpec{
		GCPCredentialsFile:           source.Name(),
		GCPImpersonateServiceAccount: "impersonated@test.iam.gserviceaccount.com",
		GCPImpersonateDelegates:      []string{"delegate-a@test.iam.gserviceaccount.com", "delegate-b@test.iam.gserviceaccount.com"},
		GCPImpersonateTokenLifetime:  "2400",
	})
	if err != nil {
		t.Fatalf("unexpected apply error: %v", err)
	}
	if !strings.Contains(summary, "impersonate_service_account=impersonated@test.iam.gserviceaccount.com") {
		t.Fatalf("unexpected summary: %q", summary)
	}
	if !strings.Contains(summary, "token_lifetime_seconds=2400") {
		t.Fatalf("expected token lifetime in summary, got %q", summary)
	}

	impersonatedPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if impersonatedPath == "" {
		t.Fatal("expected GOOGLE_APPLICATION_CREDENTIALS to be set")
	}
	if impersonatedPath == source.Name() {
		t.Fatalf("expected impersonated credentials file, got source file %q", impersonatedPath)
	}

	encoded, err := os.ReadFile(impersonatedPath)
	if err != nil {
		t.Fatalf("read impersonated credentials file: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("parse impersonated credentials payload: %v", err)
	}
	if got := payload["type"]; got != "impersonated_service_account" {
		t.Fatalf("expected impersonated_service_account payload type, got %v", got)
	}
	delegates, ok := payload["delegates"].([]any)
	if !ok || len(delegates) != 2 {
		t.Fatalf("unexpected delegates payload: %#v", payload["delegates"])
	}
	if got := payload["token_lifetime_seconds"]; got != float64(2400) {
		t.Fatalf("unexpected token_lifetime_seconds payload: %v", got)
	}

	cleanup()
	if _, err := os.Stat(impersonatedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected impersonated credentials file to be removed, stat err=%v", err)
	}
}

func TestApplyScheduledGCPAuth_ImpersonationRequiresSourceCredentials(t *testing.T) {
	_, _, err := applyScheduledGCPAuth(scheduledSyncSpec{
		GCPCredentialsFile:           "/tmp/definitely-missing-scheduled-gcp-credentials.json",
		GCPImpersonateServiceAccount: "impersonated@test.iam.gserviceaccount.com",
	})
	if err == nil {
		t.Fatal("expected error when impersonation is set with an unreadable credentials source")
	}
	if !strings.Contains(err.Error(), "gcp_credentials_file") {
		t.Fatalf("expected gcp_credentials_file validation error, got %v", err)
	}
}

func TestApplyScheduledGCPAuth_TokenLifetimeRequiresImpersonation(t *testing.T) {
	source, err := os.CreateTemp("", "scheduled-gcp-source-token-lifetime-*.json")
	if err != nil {
		t.Fatalf("create temp credentials file: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(source.Name())
	})

	if _, err := source.WriteString(`{"type":"service_account"}`); err != nil {
		t.Fatalf("write source credentials: %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("close source credentials: %v", err)
	}

	_, _, err = applyScheduledGCPAuth(scheduledSyncSpec{
		GCPCredentialsFile:          source.Name(),
		GCPImpersonateTokenLifetime: "2400",
	})
	if err == nil {
		t.Fatal("expected token lifetime to require impersonation")
	}
	if !strings.Contains(err.Error(), "requires gcp_impersonate_service_account") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseAWSSessionTagDirectives(t *testing.T) {
	tags, transitive, err := parseAWSSessionTagDirectives([]string{"env=prod", "owner=platform"}, []string{"env"})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(tags))
	}
	if len(transitive) != 1 || transitive[0] != "env" {
		t.Fatalf("unexpected transitive tag keys: %v", transitive)
	}

	if _, _, err := parseAWSSessionTagDirectives([]string{"invalid"}, nil); err == nil {
		t.Fatal("expected parse error for non key=value aws_role_session_tags entry")
	}
	if _, _, err := parseAWSSessionTagDirectives([]string{"env=prod"}, []string{"owner"}); err == nil {
		t.Fatal("expected parse error when transitive key does not exist in session tags")
	}
}

func TestParseBoundedPositiveIntDirective(t *testing.T) {
	value, err := parseBoundedPositiveIntDirective("1800", "aws_role_duration_seconds", 900, 43200)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if value != 1800 {
		t.Fatalf("expected 1800, got %d", value)
	}

	if _, err := parseBoundedPositiveIntDirective("not-a-number", "aws_role_duration_seconds", 900, 43200); err == nil {
		t.Fatal("expected integer parse error")
	}
	if _, err := parseBoundedPositiveIntDirective("100", "aws_role_duration_seconds", 900, 43200); err == nil {
		t.Fatal("expected bounds error")
	}
}

func TestExecuteGCPSync_FilterRouting(t *testing.T) {
	originalNative := runScheduledGCPNativeSyncFn
	originalSecurity := runScheduledGCPSecuritySyncFn
	originalListOrgProjects := listOrganizationProjectsFn
	originalApplyAuth := applyScheduledGCPAuthFn
	originalPreflight := preflightScheduledGCPAuthFn
	t.Cleanup(func() {
		runScheduledGCPNativeSyncFn = originalNative
		runScheduledGCPSecuritySyncFn = originalSecurity
		listOrganizationProjectsFn = originalListOrgProjects
		applyScheduledGCPAuthFn = originalApplyAuth
		preflightScheduledGCPAuthFn = originalPreflight
	})

	applyScheduledGCPAuthFn = func(scheduledSyncSpec) (func(), string, error) {
		return func() {}, "", nil
	}
	preflightScheduledGCPAuthFn = func(context.Context, *SyncSchedule, scheduledSyncSpec) error {
		return nil
	}

	t.Run("security-only filter skips native sync", func(t *testing.T) {
		t.Setenv("CEREBRO_GCP_PROJECTS", "")
		t.Setenv("GCP_PROJECTS", "")
		t.Setenv("CEREBRO_GCP_PROJECT", "")
		t.Setenv("GCP_PROJECT", "")
		t.Setenv("GOOGLE_CLOUD_PROJECT", "")
		t.Setenv("CEREBRO_GCP_ORG", "")
		t.Setenv("GCP_ORG_ID", "")

		nativeCalls := 0
		securityCalls := 0
		var securityFilters []string

		runScheduledGCPNativeSyncFn = func(context.Context, *snowflake.Client, string, []string) error {
			nativeCalls++
			return nil
		}
		runScheduledGCPSecuritySyncFn = func(_ context.Context, _ *snowflake.Client, projectID, orgID string, tableFilter []string) error {
			securityCalls++
			if projectID != "proj-1" {
				return fmt.Errorf("unexpected project id %q", projectID)
			}
			if orgID != "" {
				return fmt.Errorf("unexpected org id %q", orgID)
			}
			securityFilters = append([]string(nil), tableFilter...)
			return nil
		}

		err := executeGCPSync(context.Background(), nil, &SyncSchedule{
			Name:  "security-only",
			Table: "project=proj-1,gcp_scc_findings",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nativeCalls != 0 {
			t.Fatalf("expected no native sync calls, got %d", nativeCalls)
		}
		if securityCalls != 1 {
			t.Fatalf("expected one security sync call, got %d", securityCalls)
		}
		if len(securityFilters) != 1 || securityFilters[0] != "gcp_scc_findings" {
			t.Fatalf("unexpected security filter: %v", securityFilters)
		}
	})

	t.Run("scc-only org filter avoids project discovery", func(t *testing.T) {
		t.Setenv("CEREBRO_GCP_PROJECTS", "")
		t.Setenv("GCP_PROJECTS", "")
		t.Setenv("CEREBRO_GCP_PROJECT", "")
		t.Setenv("GCP_PROJECT", "")
		t.Setenv("GOOGLE_CLOUD_PROJECT", "")
		t.Setenv("CEREBRO_GCP_ORG", "")
		t.Setenv("GCP_ORG_ID", "")

		nativeCalls := 0
		securityCalls := 0
		listCalls := 0

		runScheduledGCPNativeSyncFn = func(context.Context, *snowflake.Client, string, []string) error {
			nativeCalls++
			return nil
		}
		runScheduledGCPSecuritySyncFn = func(_ context.Context, _ *snowflake.Client, projectID, orgID string, tableFilter []string) error {
			securityCalls++
			if projectID != "" {
				return fmt.Errorf("expected empty project id, got %q", projectID)
			}
			if orgID != "org-123" {
				return fmt.Errorf("expected org-123, got %q", orgID)
			}
			if len(tableFilter) != 1 || tableFilter[0] != "gcp_scc_findings" {
				return fmt.Errorf("unexpected security filter: %v", tableFilter)
			}
			return nil
		}
		listOrganizationProjectsFn = func(context.Context, string) ([]string, error) {
			listCalls++
			return nil, fmt.Errorf("unexpected org project discovery")
		}

		err := executeGCPSync(context.Background(), nil, &SyncSchedule{
			Name:  "scc-org-only",
			Table: "org=org-123,gcp_scc_findings",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nativeCalls != 0 {
			t.Fatalf("expected no native sync calls, got %d", nativeCalls)
		}
		if securityCalls != 1 {
			t.Fatalf("expected one security sync call, got %d", securityCalls)
		}
		if listCalls != 0 {
			t.Fatalf("expected no org project discovery calls, got %d", listCalls)
		}
	})

	t.Run("mixed filter runs native and security with split filters", func(t *testing.T) {
		t.Setenv("CEREBRO_GCP_PROJECTS", "")
		t.Setenv("GCP_PROJECTS", "")
		t.Setenv("CEREBRO_GCP_PROJECT", "")
		t.Setenv("GCP_PROJECT", "")
		t.Setenv("GOOGLE_CLOUD_PROJECT", "")
		t.Setenv("CEREBRO_GCP_ORG", "")
		t.Setenv("GCP_ORG_ID", "")

		nativeCalls := 0
		securityCalls := 0
		var nativeFilters []string
		var securityFilters []string

		runScheduledGCPNativeSyncFn = func(_ context.Context, _ *snowflake.Client, _ string, tableFilter []string) error {
			nativeCalls++
			nativeFilters = append([]string(nil), tableFilter...)
			return nil
		}
		runScheduledGCPSecuritySyncFn = func(_ context.Context, _ *snowflake.Client, _ string, _ string, tableFilter []string) error {
			securityCalls++
			securityFilters = append([]string(nil), tableFilter...)
			return nil
		}

		err := executeGCPSync(context.Background(), nil, &SyncSchedule{
			Name:  "mixed",
			Table: "project=proj-1,gcp_compute_instances,gcp_scc_findings",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nativeCalls != 1 {
			t.Fatalf("expected one native sync call, got %d", nativeCalls)
		}
		if securityCalls != 1 {
			t.Fatalf("expected one security sync call, got %d", securityCalls)
		}
		if len(nativeFilters) != 1 || nativeFilters[0] != "gcp_compute_instances" {
			t.Fatalf("unexpected native filter: %v", nativeFilters)
		}
		if len(securityFilters) != 1 || securityFilters[0] != "gcp_scc_findings" {
			t.Fatalf("unexpected security filter: %v", securityFilters)
		}
	})
}
