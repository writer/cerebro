package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/writer/cerebro/internal/app"
	providerregistry "github.com/writer/cerebro/internal/providers"
	"github.com/writer/cerebro/internal/snowflake"
	"google.golang.org/api/option"
)

func TestParseScheduledSyncSpec(t *testing.T) {
	spec := parseScheduledSyncSpec("project=proj-a,projects=proj-b|proj-c,org:org-123,subscription=sub-123,subscriptions=sub-234|sub-345,subscription_concurrency=5,gcp_compute_instances, azure_compute_virtual_machines")

	if spec.GCPOrg != "org-123" {
		t.Fatalf("expected org-123, got %q", spec.GCPOrg)
	}
	if spec.AzureSubscription != "sub-123" {
		t.Fatalf("expected sub-123, got %q", spec.AzureSubscription)
	}
	if len(spec.AzureSubscriptions) != 2 || !slices.Contains(spec.AzureSubscriptions, "sub-234") || !slices.Contains(spec.AzureSubscriptions, "sub-345") {
		t.Fatalf("unexpected Azure subscriptions: %v", spec.AzureSubscriptions)
	}
	if spec.AzureSubscriptionConcurrency != "5" {
		t.Fatalf("expected Azure subscription concurrency 5, got %q", spec.AzureSubscriptionConcurrency)
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

func TestParseScheduledSyncSpec_AzureManagementGroupAndAWSOrg(t *testing.T) {
	spec := parseScheduledSyncSpec("management_group=mg-platform,aws_org=true,aws_org_role=SecurityAuditRole,aws_org_include_accounts=111111111111|222222222222,aws_org_exclude_accounts=333333333333,aws_org_account_concurrency=8,aws_iam_roles")

	if spec.AzureManagementGroup != "mg-platform" {
		t.Fatalf("expected Azure management group mg-platform, got %q", spec.AzureManagementGroup)
	}
	if !spec.AWSOrg {
		t.Fatal("expected AWS org directive to be enabled")
	}
	if spec.AWSOrgRole != "SecurityAuditRole" {
		t.Fatalf("unexpected AWS org role: %q", spec.AWSOrgRole)
	}
	if len(spec.AWSOrgIncludeAccounts) != 2 || !slices.Contains(spec.AWSOrgIncludeAccounts, "111111111111") || !slices.Contains(spec.AWSOrgIncludeAccounts, "222222222222") {
		t.Fatalf("unexpected AWS org include accounts: %v", spec.AWSOrgIncludeAccounts)
	}
	if len(spec.AWSOrgExcludeAccounts) != 1 || spec.AWSOrgExcludeAccounts[0] != "333333333333" {
		t.Fatalf("unexpected AWS org exclude accounts: %v", spec.AWSOrgExcludeAccounts)
	}
	if spec.AWSOrgAccountConcurrency != "8" {
		t.Fatalf("unexpected AWS org account concurrency: %q", spec.AWSOrgAccountConcurrency)
	}
}

func TestParseScheduledSyncSpec_AuthDirectives(t *testing.T) {
	spec := parseScheduledSyncSpec("sync_timeout_seconds=1200,worker_wait_timeout_seconds=900,gcp_project_timeout_seconds=600,aws_profile=prod,aws_web_identity_token_file=/tmp/oidc-token,aws_web_identity_role_arn=arn:aws:iam::123456789012:role/WebIdentityRole,aws_web_identity_role_session_name=web-session,aws_role_arn=arn:aws:iam::123456789012:role/SyncRole,aws_role_external_id=ext-123,aws_config_file=/tmp/config,aws_shared_credentials_file=/tmp/creds,aws_credential_process=/opt/bin/creds,aws_role_source_identity=cerebro-scheduler,aws_role_duration_seconds=1800,aws_role_session_tags=env=prod|owner=platform,aws_role_transitive_tag_keys=env,gcp_credentials_file=/tmp/gcp.json,gcp_impersonate_service_account=svc@test.iam.gserviceaccount.com,gcp_impersonate_delegates=delegate-a|delegate-b,gcp_impersonate_token_lifetime_seconds=2400,aws_iam_roles")

	if spec.SyncTimeoutSeconds != "1200" {
		t.Fatalf("unexpected sync timeout directive: %q", spec.SyncTimeoutSeconds)
	}
	if spec.WorkerWaitTimeoutSeconds != "900" {
		t.Fatalf("unexpected worker wait timeout directive: %q", spec.WorkerWaitTimeoutSeconds)
	}
	if spec.GCPProjectTimeoutSeconds != "600" {
		t.Fatalf("unexpected gcp project timeout directive: %q", spec.GCPProjectTimeoutSeconds)
	}

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
	if spec.AWSWebIdentityTokenFile != "/tmp/oidc-token" {
		t.Fatalf("unexpected aws web identity token file: %q", spec.AWSWebIdentityTokenFile)
	}
	if spec.AWSWebIdentityRoleARN != "arn:aws:iam::123456789012:role/WebIdentityRole" {
		t.Fatalf("unexpected aws web identity role arn: %q", spec.AWSWebIdentityRoleARN)
	}
	if spec.AWSWebIdentitySession != "web-session" {
		t.Fatalf("unexpected aws web identity session: %q", spec.AWSWebIdentitySession)
	}
	if spec.AWSRoleSourceIdentity != "cerebro-scheduler" {
		t.Fatalf("unexpected aws role source identity: %q", spec.AWSRoleSourceIdentity)
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
	if !slices.Contains(providers, "s3") {
		t.Fatalf("expected s3 in valid providers: %v", providers)
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
	t.Setenv("JOB_DATABASE_URL", "postgres://localhost:5432/jobs")
	t.Setenv("NATS_URLS", "nats://localhost:4222")

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

func TestExecuteProviderSync_APIModeSkipsDirectInitialization(t *testing.T) {
	originalNewScheduleApp := newScheduleAppFn
	t.Cleanup(func() {
		newScheduleAppFn = originalNewScheduleApp
	})

	calledNewApp := false
	newScheduleAppFn = func(context.Context) (*app.App, error) {
		calledNewApp = true
		return nil, fmt.Errorf("should not initialize app in api mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/providers/okta/sync" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var payload struct {
			FullSync bool     `json:"full_sync"`
			Tables   []string `json:"tables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request payload: %v", err)
		}
		if !payload.FullSync {
			t.Fatalf("expected full_sync=true, got %+v", payload)
		}
		if len(payload.Tables) != 0 {
			t.Fatalf("expected no tables for empty schedule filter, got %+v", payload.Tables)
		}
		_, _ = w.Write([]byte(`{"provider":"okta","errors":[]}`))
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)

	err := executeProviderSync(context.Background(), nil, &SyncSchedule{Name: "nightly-okta", Provider: "okta"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calledNewApp {
		t.Fatal("expected direct app initialization to be skipped in api mode")
	}
}

func TestExecuteProviderSync_AutoModeFallbacksToDirectOnTransportError(t *testing.T) {
	originalNewScheduleApp := newScheduleAppFn
	t.Cleanup(func() {
		newScheduleAppFn = originalNewScheduleApp
	})

	provider := &testWorkerProvider{name: "okta"}
	registry := providerregistry.NewRegistry()
	registry.Register(provider)

	newScheduleAppFn = func(context.Context) (*app.App, error) {
		return &app.App{Providers: registry}, nil
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")

	err := executeProviderSync(context.Background(), nil, &SyncSchedule{
		Name:     "nightly-okta",
		Provider: "okta",
		Table:    "okta_users,okta_groups",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("expected direct fallback sync call, got %d", provider.calls)
	}
	if !provider.last.FullSync {
		t.Fatalf("expected direct fallback to request full sync, got %+v", provider.last)
	}
	if !slices.Equal(provider.last.Tables, []string{"okta_users", "okta_groups"}) {
		t.Fatalf("expected table-filter fallback in direct mode, got %+v", provider.last.Tables)
	}
}

func TestExecuteProviderSync_AutoModeDoesNotFallbackOnUnauthorized(t *testing.T) {
	originalNewScheduleApp := newScheduleAppFn
	t.Cleanup(func() {
		newScheduleAppFn = originalNewScheduleApp
	})

	calledNewApp := false
	newScheduleAppFn = func(context.Context) (*app.App, error) {
		calledNewApp = true
		return nil, fmt.Errorf("should not initialize app on unauthorized api response")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","code":"unauthorized"}`))
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)

	err := executeProviderSync(context.Background(), nil, &SyncSchedule{Name: "nightly-okta", Provider: "okta"})
	if err == nil {
		t.Fatal("expected unauthorized api error")
	}
	if !strings.Contains(err.Error(), "sync via api failed") {
		t.Fatalf("expected api failure context, got %v", err)
	}
	if calledNewApp {
		t.Fatal("did not expect direct fallback on unauthorized api response")
	}
}

func TestExecuteProviderSync_APIModePassesTableFilterInRequest(t *testing.T) {
	originalNewScheduleApp := newScheduleAppFn
	t.Cleanup(func() {
		newScheduleAppFn = originalNewScheduleApp
	})

	calledNewApp := false
	newScheduleAppFn = func(context.Context) (*app.App, error) {
		calledNewApp = true
		return nil, fmt.Errorf("should not initialize app in api mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/providers/okta/sync" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var payload struct {
			FullSync bool     `json:"full_sync"`
			Tables   []string `json:"tables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request payload: %v", err)
		}
		if !payload.FullSync {
			t.Fatalf("expected full_sync=true, got %+v", payload)
		}
		if !slices.Equal(payload.Tables, []string{"okta_users", "okta_groups"}) {
			t.Fatalf("expected table filters in api payload, got %+v", payload.Tables)
		}
		_, _ = w.Write([]byte(`{"provider":"okta","errors":[]}`))
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)

	err := executeProviderSync(context.Background(), nil, &SyncSchedule{
		Name:     "nightly-okta",
		Provider: "okta",
		Table:    "okta_users,okta_groups",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calledNewApp {
		t.Fatal("expected direct app initialization to be skipped in api mode")
	}
}

func TestExecuteAWSSync_UsesScheduledAuthDirectives(t *testing.T) {
	originalLoad := loadScheduledAWSConfigFn
	originalPreflight := preflightScheduledAWSAuthFn
	originalRun := runScheduledAWSNativeSyncFn
	originalOrgRun := runScheduledAWSOrgSyncFn
	t.Cleanup(func() {
		loadScheduledAWSConfigFn = originalLoad
		preflightScheduledAWSAuthFn = originalPreflight
		runScheduledAWSNativeSyncFn = originalRun
		runScheduledAWSOrgSyncFn = originalOrgRun
	})

	loadCalled := false
	preflightCalled := false
	runCalled := false

	loadScheduledAWSConfigFn = func(_ context.Context, spec scheduledSyncSpec) (aws.Config, error) {
		loadCalled = true
		if spec.AWSProfile != "prod" {
			return aws.Config{}, fmt.Errorf("expected aws profile prod, got %q", spec.AWSProfile)
		}
		if spec.AWSWebIdentityRoleARN != "arn:aws:iam::123456789012:role/WebIdentityRole" {
			return aws.Config{}, fmt.Errorf("expected aws web identity role arn, got %q", spec.AWSWebIdentityRoleARN)
		}
		if spec.AWSRoleARN == "" {
			return aws.Config{}, fmt.Errorf("expected aws role arn")
		}
		if spec.AWSRoleSourceIdentity != "cerebro-scheduler" {
			return aws.Config{}, fmt.Errorf("expected aws role source identity, got %q", spec.AWSRoleSourceIdentity)
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
		Table: "aws_profile=prod,aws_web_identity_token_file=/tmp/token,aws_web_identity_role_arn=arn:aws:iam::123456789012:role/WebIdentityRole,aws_role_arn=arn:aws:iam::123456789012:role/SyncRole,aws_role_source_identity=cerebro-scheduler,aws_role_duration_seconds=1800,aws_role_session_tags=env=prod,aws_iam_roles",
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

func TestExecuteAWSSync_UsesAWSOrgDirectives(t *testing.T) {
	originalLoad := loadScheduledAWSConfigFn
	originalPreflight := preflightScheduledAWSAuthFn
	originalRun := runScheduledAWSNativeSyncFn
	originalOrgRun := runScheduledAWSOrgSyncFn
	t.Cleanup(func() {
		loadScheduledAWSConfigFn = originalLoad
		preflightScheduledAWSAuthFn = originalPreflight
		runScheduledAWSNativeSyncFn = originalRun
		runScheduledAWSOrgSyncFn = originalOrgRun
	})

	loadScheduledAWSConfigFn = func(_ context.Context, spec scheduledSyncSpec) (aws.Config, error) {
		if !spec.AWSOrg {
			t.Fatal("expected AWS org directive to be set")
		}
		if spec.AWSOrgRole != "SecurityAuditRole" {
			t.Fatalf("unexpected AWS org role: %q", spec.AWSOrgRole)
		}
		return aws.Config{}, nil
	}
	preflightScheduledAWSAuthFn = func(context.Context, *SyncSchedule, scheduledSyncSpec, aws.Config) error {
		return nil
	}
	runScheduledAWSNativeSyncFn = func(_ context.Context, _ *snowflake.Client, _ aws.Config, _ []string) error {
		t.Fatal("did not expect single-account scheduled sync to run")
		return nil
	}

	orgRunCalled := false
	runScheduledAWSOrgSyncFn = func(_ context.Context, _ *snowflake.Client, _ aws.Config, spec scheduledSyncSpec) error {
		orgRunCalled = true
		if len(spec.AWSOrgIncludeAccounts) != 1 || spec.AWSOrgIncludeAccounts[0] != "111111111111" {
			t.Fatalf("unexpected include accounts: %v", spec.AWSOrgIncludeAccounts)
		}
		if spec.AWSOrgAccountConcurrency != "8" {
			t.Fatalf("unexpected org account concurrency: %q", spec.AWSOrgAccountConcurrency)
		}
		return nil
	}

	err := executeAWSSync(context.Background(), nil, &SyncSchedule{
		Name:  "aws-org",
		Table: "aws_org=true,aws_org_role=SecurityAuditRole,aws_org_include_accounts=111111111111,aws_org_account_concurrency=8,aws_iam_roles",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !orgRunCalled {
		t.Fatal("expected AWS org scheduled sync to be called")
	}
}

func TestParseAzureSubscriptionConcurrency(t *testing.T) {
	value, err := parseAzureSubscriptionConcurrency("6")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if value != 6 {
		t.Fatalf("expected 6, got %d", value)
	}

	if _, err := parseAzureSubscriptionConcurrency("0"); err == nil {
		t.Fatal("expected bounds error")
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

func TestRunScheduledSync_RejectsInvalidTimeoutDirective(t *testing.T) {
	originalExecute := executeScheduledSyncFn
	originalSave := saveScheduleFn
	t.Cleanup(func() {
		executeScheduledSyncFn = originalExecute
		saveScheduleFn = originalSave
	})

	executeCalls := 0
	executeScheduledSyncFn = func(context.Context, *snowflake.Client, *SyncSchedule) error {
		executeCalls++
		return nil
	}
	saveScheduleFn = func(context.Context, *snowflake.Client, *SyncSchedule) error { return nil }

	schedule := &SyncSchedule{Name: "invalid-timeout", Provider: "aws", Retry: 1, Table: "sync_timeout_seconds=5"}
	runScheduledSync(nil, schedule)

	if executeCalls != 0 {
		t.Fatalf("expected sync execution to be skipped, got %d calls", executeCalls)
	}
	if !strings.HasPrefix(schedule.LastStatus, "failed:") || !strings.Contains(schedule.LastStatus, "sync_timeout_seconds") {
		t.Fatalf("expected timeout directive validation failure status, got %q", schedule.LastStatus)
	}
}

func TestRunScheduledSync_SkipsOverlappingRuns(t *testing.T) {
	originalExecute := executeScheduledSyncFn
	originalSave := saveScheduleFn
	originalSleep := scheduleSleepFn
	t.Cleanup(func() {
		executeScheduledSyncFn = originalExecute
		saveScheduleFn = originalSave
		scheduleSleepFn = originalSleep
		scheduledSyncInFlight.Delete("overlap-test")
	})

	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})

	executeScheduledSyncFn = func(context.Context, *snowflake.Client, *SyncSchedule) error {
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
		return nil
	}
	saveScheduleFn = func(context.Context, *snowflake.Client, *SyncSchedule) error { return nil }
	scheduleSleepFn = func(time.Duration) {}

	first := &SyncSchedule{Name: "overlap-test", Provider: "aws", Retry: 1}
	go func() {
		runScheduledSync(nil, first)
		close(finished)
	}()

	<-started

	second := &SyncSchedule{Name: "overlap-test", Provider: "aws", Retry: 1}
	runScheduledSync(nil, second)

	if second.LastStatus != "skipped: previous run still active" {
		t.Fatalf("expected overlap skip status, got %q", second.LastStatus)
	}

	close(release)
	<-finished
}

func TestExecuteGCPSync_InvalidProjectTimeoutDirective(t *testing.T) {
	originalNative := runScheduledGCPNativeSyncFn
	originalSecurity := runScheduledGCPSecuritySyncFn
	originalApplyAuth := applyScheduledGCPAuthFn
	originalPreflight := preflightScheduledGCPAuthFn
	originalProjectPreflight := preflightGCPProjectAccessFn
	t.Cleanup(func() {
		runScheduledGCPNativeSyncFn = originalNative
		runScheduledGCPSecuritySyncFn = originalSecurity
		applyScheduledGCPAuthFn = originalApplyAuth
		preflightScheduledGCPAuthFn = originalPreflight
		preflightGCPProjectAccessFn = originalProjectPreflight
	})

	applyScheduledGCPAuthFn = func(scheduledSyncSpec) (*scheduledGCPAuthConfig, error) {
		return &scheduledGCPAuthConfig{Cleanup: func() {}}, nil
	}
	preflightScheduledGCPAuthFn = func(context.Context, *SyncSchedule, scheduledSyncSpec, *scheduledGCPAuthConfig) error {
		return nil
	}
	preflightGCPProjectAccessFn = func(context.Context, gcpProjectPreflightSpec) error {
		return nil
	}
	runScheduledGCPNativeSyncFn = func(context.Context, *snowflake.Client, string, []string) error { return nil }
	runScheduledGCPSecuritySyncFn = func(context.Context, *snowflake.Client, string, string, []string) error { return nil }

	err := executeGCPSync(context.Background(), nil, &SyncSchedule{
		Name:  "invalid-project-timeout",
		Table: "project=proj-1,gcp_project_timeout_seconds=10,gcp_compute_instances",
	})
	if err == nil {
		t.Fatal("expected project timeout validation error")
	}
	if !strings.Contains(err.Error(), "gcp_project_timeout_seconds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteGCPSync_SkipsSecurityWhenNativeProjectTimesOut(t *testing.T) {
	originalNative := runScheduledGCPNativeSyncFn
	originalSecurity := runScheduledGCPSecuritySyncFn
	originalApplyAuth := applyScheduledGCPAuthFn
	originalPreflight := preflightScheduledGCPAuthFn
	originalProjectPreflight := preflightGCPProjectAccessFn
	t.Cleanup(func() {
		runScheduledGCPNativeSyncFn = originalNative
		runScheduledGCPSecuritySyncFn = originalSecurity
		applyScheduledGCPAuthFn = originalApplyAuth
		preflightScheduledGCPAuthFn = originalPreflight
		preflightGCPProjectAccessFn = originalProjectPreflight
	})

	applyScheduledGCPAuthFn = func(scheduledSyncSpec) (*scheduledGCPAuthConfig, error) {
		return &scheduledGCPAuthConfig{Cleanup: func() {}}, nil
	}
	preflightScheduledGCPAuthFn = func(context.Context, *SyncSchedule, scheduledSyncSpec, *scheduledGCPAuthConfig) error {
		return nil
	}
	preflightGCPProjectAccessFn = func(context.Context, gcpProjectPreflightSpec) error {
		return nil
	}
	runScheduledGCPNativeSyncFn = func(context.Context, *snowflake.Client, string, []string) error {
		return context.DeadlineExceeded
	}
	securityCalls := 0
	runScheduledGCPSecuritySyncFn = func(context.Context, *snowflake.Client, string, string, []string) error {
		securityCalls++
		return nil
	}

	err := executeGCPSync(context.Background(), nil, &SyncSchedule{
		Name:  "timeout-short-circuit",
		Table: "project=proj-1,gcp_project_timeout_seconds=600,gcp_compute_instances,gcp_scc_findings",
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "native sync timed out") {
		t.Fatalf("unexpected error: %v", err)
	}
	if securityCalls != 0 {
		t.Fatalf("expected security sync to be skipped after native timeout, got %d calls", securityCalls)
	}
}

func TestExecuteGCPSync_PreflightFailureSkipsNativeAndSecurity(t *testing.T) {
	originalNative := runScheduledGCPNativeSyncFn
	originalSecurity := runScheduledGCPSecuritySyncFn
	originalApplyAuth := applyScheduledGCPAuthFn
	originalPreflight := preflightScheduledGCPAuthFn
	originalProjectPreflight := preflightGCPProjectAccessFn
	t.Cleanup(func() {
		runScheduledGCPNativeSyncFn = originalNative
		runScheduledGCPSecuritySyncFn = originalSecurity
		applyScheduledGCPAuthFn = originalApplyAuth
		preflightScheduledGCPAuthFn = originalPreflight
		preflightGCPProjectAccessFn = originalProjectPreflight
	})

	applyScheduledGCPAuthFn = func(scheduledSyncSpec) (*scheduledGCPAuthConfig, error) {
		return &scheduledGCPAuthConfig{Cleanup: func() {}}, nil
	}
	preflightScheduledGCPAuthFn = func(context.Context, *SyncSchedule, scheduledSyncSpec, *scheduledGCPAuthConfig) error {
		return nil
	}
	preflightGCPProjectAccessFn = func(context.Context, gcpProjectPreflightSpec) error {
		return fmt.Errorf("cloud asset denied")
	}

	nativeCalls := 0
	securityCalls := 0
	runScheduledGCPNativeSyncFn = func(context.Context, *snowflake.Client, string, []string) error {
		nativeCalls++
		return nil
	}
	runScheduledGCPSecuritySyncFn = func(context.Context, *snowflake.Client, string, string, []string) error {
		securityCalls++
		return nil
	}

	err := executeGCPSync(context.Background(), nil, &SyncSchedule{
		Name:  "preflight-fail",
		Table: "project=proj-1,gcp_compute_instances,gcp_scc_findings",
	})
	if err == nil {
		t.Fatal("expected preflight error")
	}
	if !strings.Contains(err.Error(), "preflight") {
		t.Fatalf("unexpected error: %v", err)
	}
	if nativeCalls != 0 {
		t.Fatalf("expected no native sync calls, got %d", nativeCalls)
	}
	if securityCalls != 0 {
		t.Fatalf("expected no security sync calls, got %d", securityCalls)
	}
}

func TestEnqueueScheduledNativeSync_InvalidWorkerWaitTimeoutDirective(t *testing.T) {
	err := enqueueScheduledNativeSync(context.Background(), &SyncSchedule{
		Name:     "worker-wait-timeout",
		Provider: "aws",
		Table:    "worker_wait_timeout_seconds=10",
	})
	if err == nil {
		t.Fatal("expected worker wait timeout validation error")
	}
	if !strings.Contains(err.Error(), "worker_wait_timeout_seconds") {
		t.Fatalf("unexpected error: %v", err)
	}
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

func TestPreflightGCPProjectAccess_RequiresOrgForSCC(t *testing.T) {
	err := preflightGCPProjectAccess(context.Background(), gcpProjectPreflightSpec{
		ProjectID:      "proj-1",
		RunNativeSync:  false,
		RunSecurity:    true,
		SecurityFilter: []string{"gcp_scc_findings"},
	})
	if err == nil {
		t.Fatal("expected SCC org validation error")
	}
	if !strings.Contains(err.Error(), "gcp-org") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPreflightGCPProjectAccess_InvokesCloudAssetAndSCCProbes(t *testing.T) {
	originalAssetProbe := probeGCPCloudAssetAccessFn
	originalSCCProbe := probeGCPSCCAccessFn
	t.Cleanup(func() {
		probeGCPCloudAssetAccessFn = originalAssetProbe
		probeGCPSCCAccessFn = originalSCCProbe
	})

	assetCalled := false
	sccCalled := false
	probeGCPCloudAssetAccessFn = func(_ context.Context, projectID string, _ []option.ClientOption) error {
		assetCalled = true
		if projectID != "proj-1" {
			return fmt.Errorf("unexpected project id %q", projectID)
		}
		return nil
	}
	probeGCPSCCAccessFn = func(_ context.Context, orgID string, _ []option.ClientOption) error {
		sccCalled = true
		if orgID != "org-123" {
			return fmt.Errorf("unexpected org id %q", orgID)
		}
		return nil
	}

	err := preflightGCPProjectAccess(context.Background(), gcpProjectPreflightSpec{
		ProjectID:      "proj-1",
		OrgID:          "org-123",
		RunNativeSync:  true,
		RunSecurity:    true,
		SecurityFilter: []string{"gcp_scc_findings"},
	})
	if err != nil {
		t.Fatalf("unexpected preflight error: %v", err)
	}
	if !assetCalled {
		t.Fatal("expected cloud asset probe to be called")
	}
	if !sccCalled {
		t.Fatal("expected scc probe to be called")
	}
}

func TestExecuteGCPSync_AppliesScheduledAuthDirectives(t *testing.T) {
	originalNative := runScheduledGCPNativeSyncFn
	originalSecurity := runScheduledGCPSecuritySyncFn
	originalApplyAuth := applyScheduledGCPAuthFn
	originalPreflight := preflightScheduledGCPAuthFn
	originalProjectPreflight := preflightGCPProjectAccessFn
	t.Cleanup(func() {
		runScheduledGCPNativeSyncFn = originalNative
		runScheduledGCPSecuritySyncFn = originalSecurity
		applyScheduledGCPAuthFn = originalApplyAuth
		preflightScheduledGCPAuthFn = originalPreflight
		preflightGCPProjectAccessFn = originalProjectPreflight
	})

	applyCalled := false
	preflightCalled := false

	applyScheduledGCPAuthFn = func(spec scheduledSyncSpec) (*scheduledGCPAuthConfig, error) {
		applyCalled = true
		if spec.GCPCredentialsFile != "/tmp/gcp.json" {
			return nil, fmt.Errorf("unexpected gcp credentials file %q", spec.GCPCredentialsFile)
		}
		if spec.GCPImpersonateServiceAccount != "svc@test.iam.gserviceaccount.com" {
			return nil, fmt.Errorf("unexpected gcp impersonation service account %q", spec.GCPImpersonateServiceAccount)
		}
		if len(spec.GCPImpersonateDelegates) != 2 {
			return nil, fmt.Errorf("unexpected gcp delegates %v", spec.GCPImpersonateDelegates)
		}
		if spec.GCPImpersonateTokenLifetime != "2400" {
			return nil, fmt.Errorf("unexpected gcp impersonate token lifetime %q", spec.GCPImpersonateTokenLifetime)
		}
		return &scheduledGCPAuthConfig{
			Cleanup:         func() {},
			Summary:         "impersonate_service_account=svc@test.iam.gserviceaccount.com delegates=2",
			CredentialsFile: "/tmp/gcp.json",
		}, nil
	}
	preflightScheduledGCPAuthFn = func(_ context.Context, _ *SyncSchedule, _ scheduledSyncSpec, cfg *scheduledGCPAuthConfig) error {
		if cfg == nil || cfg.CredentialsFile != "/tmp/gcp.json" {
			return fmt.Errorf("unexpected auth cfg: %#v", cfg)
		}
		preflightCalled = true
		return nil
	}
	preflightGCPProjectAccessFn = func(context.Context, gcpProjectPreflightSpec) error {
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

	cfg, err := applyScheduledGCPAuth(scheduledSyncSpec{GCPCredentialsFile: source.Name()})
	if err != nil {
		t.Fatalf("unexpected apply error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected auth config")
	}
	if cfg.Cleanup == nil {
		t.Fatal("expected cleanup func")
	}
	if cfg.CredentialsFile != source.Name() {
		t.Fatalf("expected credentials file %q, got %q", source.Name(), cfg.CredentialsFile)
	}
	if len(cfg.ClientOptions) != 1 {
		t.Fatalf("expected one client option, got %d", len(cfg.ClientOptions))
	}
	if !strings.Contains(cfg.Summary, "credentials_file=") {
		t.Fatalf("expected credentials file summary, got %q", cfg.Summary)
	}
	cfg.Cleanup()

	if _, statErr := os.Stat(source.Name()); statErr != nil {
		t.Fatalf("expected source credentials file to remain, stat err=%v", statErr)
	}
}

func TestApplyScheduledGCPAuth_WithImpersonation(t *testing.T) {
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

	cfg, err := applyScheduledGCPAuth(scheduledSyncSpec{
		GCPCredentialsFile:           source.Name(),
		GCPImpersonateServiceAccount: "impersonated@test.iam.gserviceaccount.com",
		GCPImpersonateDelegates:      []string{"delegate-a@test.iam.gserviceaccount.com", "delegate-b@test.iam.gserviceaccount.com"},
		GCPImpersonateTokenLifetime:  "2400",
	})
	if err != nil {
		t.Fatalf("unexpected apply error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected auth config")
	}
	if !strings.Contains(cfg.Summary, "impersonate_service_account=impersonated@test.iam.gserviceaccount.com") {
		t.Fatalf("unexpected summary: %q", cfg.Summary)
	}
	if !strings.Contains(cfg.Summary, "token_lifetime_seconds=2400") {
		t.Fatalf("expected token lifetime in summary, got %q", cfg.Summary)
	}

	impersonatedPath := cfg.CredentialsFile
	if impersonatedPath == "" {
		t.Fatal("expected temporary impersonated credentials file path")
	}
	if impersonatedPath == source.Name() {
		t.Fatalf("expected impersonated credentials file, got source file %q", impersonatedPath)
	}
	if len(cfg.ClientOptions) != 1 {
		t.Fatalf("expected one client option, got %d", len(cfg.ClientOptions))
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

	cfg.Cleanup()
	if _, err := os.Stat(impersonatedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected impersonated credentials file to be removed, stat err=%v", err)
	}
}

func TestApplyScheduledGCPAuth_ImpersonationRequiresSourceCredentials(t *testing.T) {
	_, err := applyScheduledGCPAuth(scheduledSyncSpec{
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

	_, err = applyScheduledGCPAuth(scheduledSyncSpec{
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

func TestApplyScheduledGCPAuth_DelegatesRequireImpersonation(t *testing.T) {
	source, err := os.CreateTemp("", "scheduled-gcp-source-delegates-*.json")
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

	_, err = applyScheduledGCPAuth(scheduledSyncSpec{
		GCPCredentialsFile:      source.Name(),
		GCPImpersonateDelegates: []string{"delegate-a@test.iam.gserviceaccount.com"},
	})
	if err == nil {
		t.Fatal("expected delegates to require impersonation")
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

func TestLoadScheduledAWSConfig_EnterpriseAuthValidation(t *testing.T) {
	t.Run("web identity requires token and role together", func(t *testing.T) {
		_, err := loadScheduledAWSConfig(context.Background(), scheduledSyncSpec{AWSWebIdentityTokenFile: "/tmp/token"})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "aws_web_identity_token_file and aws_web_identity_role_arn must be set together") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("web identity token file must be readable", func(t *testing.T) {
		_, err := loadScheduledAWSConfig(context.Background(), scheduledSyncSpec{
			AWSWebIdentityTokenFile: "/tmp/definitely-missing-web-identity-token",
			AWSWebIdentityRoleARN:   "arn:aws:iam::123456789012:role/WebIdentityRole",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "aws_web_identity_token_file") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("source identity requires role arn", func(t *testing.T) {
		_, err := loadScheduledAWSConfig(context.Background(), scheduledSyncSpec{AWSRoleSourceIdentity: "cerebro-scheduler"})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "aws_role_source_identity") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("validates credential process even when profile is set", func(t *testing.T) {
		_, err := loadScheduledAWSConfig(context.Background(), scheduledSyncSpec{
			AWSProfile:           "prod",
			AWSCredentialProcess: "credential-helper --profile prod",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "absolute executable path") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestExecuteGCPSync_FilterRouting(t *testing.T) {
	originalNative := runScheduledGCPNativeSyncFn
	originalSecurity := runScheduledGCPSecuritySyncFn
	originalListOrgProjects := listOrganizationProjectsFn
	originalApplyAuth := applyScheduledGCPAuthFn
	originalPreflight := preflightScheduledGCPAuthFn
	originalProjectPreflight := preflightGCPProjectAccessFn
	t.Cleanup(func() {
		runScheduledGCPNativeSyncFn = originalNative
		runScheduledGCPSecuritySyncFn = originalSecurity
		listOrganizationProjectsFn = originalListOrgProjects
		applyScheduledGCPAuthFn = originalApplyAuth
		preflightScheduledGCPAuthFn = originalPreflight
		preflightGCPProjectAccessFn = originalProjectPreflight
	})

	applyScheduledGCPAuthFn = func(scheduledSyncSpec) (*scheduledGCPAuthConfig, error) {
		return &scheduledGCPAuthConfig{Cleanup: func() {}}, nil
	}
	preflightScheduledGCPAuthFn = func(context.Context, *SyncSchedule, scheduledSyncSpec, *scheduledGCPAuthConfig) error {
		return nil
	}
	preflightGCPProjectAccessFn = func(context.Context, gcpProjectPreflightSpec) error {
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

func TestExecuteGCPSync_AppliesWIFAuth(t *testing.T) {
	originalNative := runScheduledGCPNativeSyncFn
	originalSecurity := runScheduledGCPSecuritySyncFn
	originalPreflight := preflightScheduledGCPAuthFn
	originalProjectPreflight := preflightGCPProjectAccessFn
	t.Cleanup(func() {
		runScheduledGCPNativeSyncFn = originalNative
		runScheduledGCPSecuritySyncFn = originalSecurity
		preflightScheduledGCPAuthFn = originalPreflight
		preflightGCPProjectAccessFn = originalProjectPreflight
	})

	preflightScheduledGCPAuthFn = func(context.Context, *SyncSchedule, scheduledSyncSpec, *scheduledGCPAuthConfig) error {
		return nil
	}
	preflightGCPProjectAccessFn = func(context.Context, gcpProjectPreflightSpec) error {
		return nil
	}

	t.Setenv("CEREBRO_GCP_PROJECTS", "")
	t.Setenv("GCP_PROJECTS", "")
	t.Setenv("CEREBRO_GCP_PROJECT", "")
	t.Setenv("GCP_PROJECT", "")
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")
	t.Setenv("CEREBRO_GCP_ORG", "")
	t.Setenv("GCP_ORG_ID", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	t.Setenv("CEREBRO_GCP_WIF_AUDIENCE", "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov")
	t.Setenv("CEREBRO_GCP_IMPERSONATE_SERVICE_ACCOUNT", "scanner@proj.iam.gserviceaccount.com")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	var observedGAC string
	runScheduledGCPNativeSyncFn = func(_ context.Context, _ *snowflake.Client, _ string, _ []string) error {
		observedGAC = os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
		return nil
	}
	runScheduledGCPSecuritySyncFn = func(_ context.Context, _ *snowflake.Client, _, _ string, _ []string) error {
		return nil
	}

	err := executeGCPSync(context.Background(), nil, &SyncSchedule{
		Name:  "wif-test",
		Table: "project=proj-1,gcp_compute_instances",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if observedGAC == "" {
		t.Fatal("expected GOOGLE_APPLICATION_CREDENTIALS to be set during GCP sync")
	}

	if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != "" {
		t.Fatalf("expected GOOGLE_APPLICATION_CREDENTIALS restored to empty after cleanup, got %q", got)
	}
}

func TestExecuteGCPSync_WIFCredsContent(t *testing.T) {
	originalNative := runScheduledGCPNativeSyncFn
	originalSecurity := runScheduledGCPSecuritySyncFn
	originalPreflight := preflightScheduledGCPAuthFn
	originalProjectPreflight := preflightGCPProjectAccessFn
	t.Cleanup(func() {
		runScheduledGCPNativeSyncFn = originalNative
		runScheduledGCPSecuritySyncFn = originalSecurity
		preflightScheduledGCPAuthFn = originalPreflight
		preflightGCPProjectAccessFn = originalProjectPreflight
	})

	preflightScheduledGCPAuthFn = func(context.Context, *SyncSchedule, scheduledSyncSpec, *scheduledGCPAuthConfig) error {
		return nil
	}
	preflightGCPProjectAccessFn = func(context.Context, gcpProjectPreflightSpec) error {
		return nil
	}

	t.Setenv("CEREBRO_GCP_PROJECTS", "")
	t.Setenv("GCP_PROJECTS", "")
	t.Setenv("CEREBRO_GCP_PROJECT", "")
	t.Setenv("GCP_PROJECT", "")
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")
	t.Setenv("CEREBRO_GCP_ORG", "")
	t.Setenv("GCP_ORG_ID", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	t.Setenv("CEREBRO_GCP_WIF_AUDIENCE", "//iam.googleapis.com/test-audience")
	t.Setenv("CEREBRO_GCP_IMPERSONATE_SERVICE_ACCOUNT", "scanner@proj.iam.gserviceaccount.com")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	var capturedPayload map[string]interface{}
	runScheduledGCPNativeSyncFn = func(_ context.Context, _ *snowflake.Client, _ string, _ []string) error {
		gac := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
		data, err := os.ReadFile(gac)
		if err != nil {
			return fmt.Errorf("read temp creds: %w", err)
		}
		return json.Unmarshal(data, &capturedPayload)
	}
	runScheduledGCPSecuritySyncFn = func(_ context.Context, _ *snowflake.Client, _, _ string, _ []string) error {
		return nil
	}

	err := executeGCPSync(context.Background(), nil, &SyncSchedule{
		Name:  "wif-content",
		Table: "project=proj-1,gcp_compute_instances",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedPayload == nil {
		t.Fatal("expected to capture WIF credentials payload")
	}
	if capturedPayload["type"] != "external_account" {
		t.Fatalf("expected external_account type, got %v", capturedPayload["type"])
	}
	if capturedPayload["audience"] != "//iam.googleapis.com/test-audience" {
		t.Fatalf("unexpected audience: %v", capturedPayload["audience"])
	}
	impURL, _ := capturedPayload["service_account_impersonation_url"].(string)
	if !strings.Contains(impURL, "scanner") {
		t.Fatalf("expected impersonation URL with scanner SA, got %q", impURL)
	}
}

func TestExecuteGCPSync_OrgDiscoveryUsesScheduledAuthContext(t *testing.T) {
	originalNative := runScheduledGCPNativeSyncFn
	originalSecurity := runScheduledGCPSecuritySyncFn
	originalListOrgProjects := listOrganizationProjectsFn
	originalApplyAuth := applyScheduledGCPAuthFn
	originalPreflight := preflightScheduledGCPAuthFn
	originalProjectPreflight := preflightGCPProjectAccessFn
	t.Cleanup(func() {
		runScheduledGCPNativeSyncFn = originalNative
		runScheduledGCPSecuritySyncFn = originalSecurity
		listOrganizationProjectsFn = originalListOrgProjects
		applyScheduledGCPAuthFn = originalApplyAuth
		preflightScheduledGCPAuthFn = originalPreflight
		preflightGCPProjectAccessFn = originalProjectPreflight
	})

	baseCtx := context.Background()
	preflightCalled := false
	orgDiscoveryUsedAuthCtx := false

	applyScheduledGCPAuthFn = func(scheduledSyncSpec) (*scheduledGCPAuthConfig, error) {
		return &scheduledGCPAuthConfig{
			Cleanup:       func() {},
			ClientOptions: []option.ClientOption{option.WithUserAgent("cerebro-test")},
		}, nil
	}
	preflightScheduledGCPAuthFn = func(ctx context.Context, _ *SyncSchedule, _ scheduledSyncSpec, _ *scheduledGCPAuthConfig) error {
		preflightCalled = true
		if ctx == baseCtx {
			t.Fatal("expected preflight to receive auth-wrapped context")
		}
		return nil
	}
	preflightGCPProjectAccessFn = func(context.Context, gcpProjectPreflightSpec) error {
		return nil
	}
	listOrganizationProjectsFn = func(ctx context.Context, orgID string) ([]string, error) {
		if orgID != "org-123" {
			return nil, fmt.Errorf("unexpected org id %q", orgID)
		}
		orgDiscoveryUsedAuthCtx = ctx != baseCtx
		return []string{"proj-1"}, nil
	}

	nativeCalls := 0
	runScheduledGCPNativeSyncFn = func(context.Context, *snowflake.Client, string, []string) error {
		nativeCalls++
		return nil
	}
	runScheduledGCPSecuritySyncFn = func(context.Context, *snowflake.Client, string, string, []string) error {
		return nil
	}

	err := executeGCPSync(baseCtx, nil, &SyncSchedule{
		Name:  "org-auth",
		Table: "org=org-123,gcp_compute_instances",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !preflightCalled {
		t.Fatal("expected preflight to be called")
	}
	if !orgDiscoveryUsedAuthCtx {
		t.Fatal("expected org project discovery to use auth-wrapped context")
	}
	if nativeCalls != 1 {
		t.Fatalf("expected one native sync call, got %d", nativeCalls)
	}
}
