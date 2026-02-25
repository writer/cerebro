package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

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
	if slices.Contains(providers, "semgrep") {
		t.Fatalf("did not expect stub provider semgrep in valid providers: %v", providers)
	}
}

func TestExecuteScheduledSync_RoutesByProvider(t *testing.T) {
	originalAWSSync := executeAWSSyncFn
	originalGCPSync := executeGCPSyncFn
	originalAzureSync := executeAzureSyncFn
	originalProviderSync := executeProviderSyncFn
	t.Cleanup(func() {
		executeAWSSyncFn = originalAWSSync
		executeGCPSyncFn = originalGCPSync
		executeAzureSyncFn = originalAzureSync
		executeProviderSyncFn = originalProviderSync
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

func TestExecuteGCPSync_FilterRouting(t *testing.T) {
	originalNative := runScheduledGCPNativeSyncFn
	originalSecurity := runScheduledGCPSecuritySyncFn
	originalListOrgProjects := listOrganizationProjectsFn
	t.Cleanup(func() {
		runScheduledGCPNativeSyncFn = originalNative
		runScheduledGCPSecuritySyncFn = originalSecurity
		listOrganizationProjectsFn = originalListOrgProjects
	})

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
