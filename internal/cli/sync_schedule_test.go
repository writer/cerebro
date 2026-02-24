package cli

import (
	"context"
	"errors"
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
	if slices.Contains(providers, "auth0") {
		t.Fatalf("did not expect stub provider auth0 in valid providers: %v", providers)
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
