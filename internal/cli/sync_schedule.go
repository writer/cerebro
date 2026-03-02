package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	assetpb "cloud.google.com/go/asset/apiv1/assetpb"
	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	securitycenterpb "cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/jobs"
	"github.com/writerinternal/cerebro/internal/metrics"
	providerregistry "github.com/writerinternal/cerebro/internal/providers"
	"github.com/writerinternal/cerebro/internal/snowflake"
	nativesync "github.com/writerinternal/cerebro/internal/sync"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

var syncScheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Manage sync schedules",
	Long: `Manage scheduled sync jobs for automatic data synchronization.

Examples:
  cerebro sync schedule list                                    # List all schedules
  cerebro sync schedule create --name daily-s1 --cron "0 2 * * *" --provider sentinelone
  cerebro sync schedule create --name hourly-aws --cron "0 * * * *" --provider aws
  cerebro sync schedule delete daily-s1                         # Delete a schedule
  cerebro sync schedule run                                     # Run the scheduler daemon`,
}

var scheduleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all sync schedules",
	RunE:  runScheduleList,
}

var scheduleCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new sync schedule",
	RunE:  runScheduleCreate,
}

var scheduleDeleteCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Delete a sync schedule",
	Args:  cobra.ExactArgs(1),
	RunE:  runScheduleDelete,
}

var scheduleRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the scheduler daemon",
	Long: `Start the scheduler daemon to execute scheduled sync jobs.

The daemon runs in the foreground and executes sync jobs based on their cron schedules.
Use Ctrl+C to stop the daemon gracefully.`,
	RunE: runScheduleDaemon,
}

var scheduleShowCmd = &cobra.Command{
	Use:   "show [name]",
	Short: "Show details of a schedule",
	Args:  cobra.ExactArgs(1),
	RunE:  runScheduleShow,
}

var (
	scheduleName       string
	scheduleCron       string
	scheduleProvider   string
	scheduleEnabled    bool
	scheduleTable      string
	scheduleScanAfter  bool
	scheduleRetry      int
	scheduleOutputJSON bool

	executeScheduledSyncFn = executeScheduledSync
	saveScheduleFn         = saveSchedule
	scheduleSleepFn        = time.Sleep
	scheduleNowFn          = time.Now

	executeAWSSyncFn             = executeAWSSync
	executeGCPSyncFn             = executeGCPSync
	executeAzureSyncFn           = executeAzureSync
	executeProviderSyncFn        = executeProviderSync
	enqueueScheduledNativeSyncFn = enqueueScheduledNativeSync
	runScheduledAWSNativeSyncFn  = runScheduledAWSNativeSync

	runScheduledGCPNativeSyncFn   = runScheduledGCPNativeSync
	runScheduledGCPSecuritySyncFn = runScheduledGCPSecuritySync
	preflightGCPProjectAccessFn   = preflightGCPProjectAccess
	probeGCPCloudAssetAccessFn    = probeGCPCloudAssetAccess
	probeGCPSCCAccessFn           = probeGCPSCCAccess
	listOrganizationProjectsFn    = nativesync.ListOrganizationProjects
	loadScheduledAWSConfigFn      = loadScheduledAWSConfig
	preflightScheduledAWSAuthFn   = preflightScheduledAWSAuth
	applyScheduledGCPAuthFn       = applyScheduledGCPAuth
	preflightScheduledGCPAuthFn   = preflightScheduledGCPAuth
	waitForScheduledJobsFn        = waitForScheduledJobs

	newScheduleAppFn = app.New

	scheduledSyncInFlight sync.Map
)

const (
	defaultScheduledSyncTimeout    = 30 * time.Minute
	defaultNativeWorkerWaitTimeout = 30 * time.Minute
	defaultGCPProjectTimeout       = 10 * time.Minute
	minScheduledTimeoutSeconds     = 30
	maxScheduledTimeoutSeconds     = 86400
	minWorkerWaitTimeoutSeconds    = 30
	maxWorkerWaitTimeoutSeconds    = 86400
	minGCPProjectTimeoutSeconds    = 30
	maxGCPProjectTimeoutSeconds    = 86400
)

func init() {
	syncCmd.AddCommand(syncScheduleCmd)
	syncScheduleCmd.AddCommand(scheduleListCmd)
	syncScheduleCmd.AddCommand(scheduleCreateCmd)
	syncScheduleCmd.AddCommand(scheduleDeleteCmd)
	syncScheduleCmd.AddCommand(scheduleRunCmd)
	syncScheduleCmd.AddCommand(scheduleShowCmd)

	// List flags
	scheduleListCmd.Flags().BoolVar(&scheduleOutputJSON, "json", false, "Output in JSON format")

	// Create flags
	scheduleCreateCmd.Flags().StringVar(&scheduleName, "name", "", "Schedule name (required)")
	scheduleCreateCmd.Flags().StringVar(&scheduleCron, "cron", "", "Cron expression (required, e.g., '0 * * * *' for hourly)")
	scheduleCreateCmd.Flags().StringVar(&scheduleProvider, "provider", "", "Provider to sync: aws, gcp, azure, sentinelone, okta, github, etc.")
	scheduleCreateCmd.Flags().BoolVar(&scheduleEnabled, "enabled", true, "Whether the schedule is enabled")
	scheduleCreateCmd.Flags().StringVar(&scheduleTable, "table", "", "Specific table(s) to sync (comma-separated)")
	scheduleCreateCmd.Flags().BoolVar(&scheduleScanAfter, "scan-after", false, "Run policy scan after sync")
	scheduleCreateCmd.Flags().IntVar(&scheduleRetry, "retry", 3, "Number of retries on failure")
	_ = scheduleCreateCmd.MarkFlagRequired("name")
	_ = scheduleCreateCmd.MarkFlagRequired("cron")
	_ = scheduleCreateCmd.MarkFlagRequired("provider")
}

// SyncSchedule represents a scheduled sync job
type SyncSchedule struct {
	Name       string    `json:"name"`
	Cron       string    `json:"cron"`
	Provider   string    `json:"provider"`
	Table      string    `json:"table,omitempty"`
	Enabled    bool      `json:"enabled"`
	ScanAfter  bool      `json:"scan_after"`
	Retry      int       `json:"retry"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastRun    time.Time `json:"last_run,omitempty"`
	LastStatus string    `json:"last_status,omitempty"`
	NextRun    time.Time `json:"next_run,omitempty"`
}

func runScheduleList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	client, err := createSnowflakeClientForSchedule()
	if err != nil {
		return fmt.Errorf("failed to connect to Snowflake: %w", err)
	}
	defer func() { _ = client.Close() }()

	schedules, err := listSchedules(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to list schedules: %w", err)
	}

	if scheduleOutputJSON {
		return JSONOutput(schedules)
	}

	if len(schedules) == 0 {
		fmt.Println("No sync schedules configured.")
		fmt.Println("\nCreate one with:")
		fmt.Println("  cerebro sync schedule create --name daily-sync --cron \"0 2 * * *\" --provider sentinelone")
		return nil
	}

	fmt.Println("Sync Schedules:")
	fmt.Println("─────────────────────────────────────────────────────────────────────────────")
	fmt.Printf("%-20s %-15s %-15s %-8s %-20s %-20s\n", "NAME", "CRON", "PROVIDER", "ENABLED", "LAST RUN", "NEXT RUN")
	fmt.Println("─────────────────────────────────────────────────────────────────────────────")

	for _, s := range schedules {
		enabled := "yes"
		if !s.Enabled {
			enabled = "no"
		}
		lastRun := "-"
		if !s.LastRun.IsZero() {
			lastRun = s.LastRun.Format("2006-01-02 15:04")
		}
		nextRun := "-"
		if !s.NextRun.IsZero() {
			nextRun = s.NextRun.Format("2006-01-02 15:04")
		}
		fmt.Printf("%-20s %-15s %-15s %-8s %-20s %-20s\n",
			truncate(s.Name, 20),
			truncate(s.Cron, 15),
			truncate(s.Provider, 15),
			enabled,
			lastRun,
			nextRun,
		)
	}

	return nil
}

func runScheduleCreate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Validate cron expression
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	cronSched, err := parser.Parse(scheduleCron)
	if err != nil {
		return fmt.Errorf("invalid cron expression %q: %w", scheduleCron, err)
	}

	// Validate provider
	validProviders := validScheduleProviders()
	providerValid := false
	for _, p := range validProviders {
		if strings.EqualFold(scheduleProvider, p) {
			scheduleProvider = p
			providerValid = true
			break
		}
	}
	if !providerValid {
		return fmt.Errorf("invalid provider %q; valid providers: %s", scheduleProvider, strings.Join(validProviders, ", "))
	}

	client, err := createSnowflakeClientForSchedule()
	if err != nil {
		return fmt.Errorf("failed to connect to Snowflake: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Check if schedule already exists
	existing, _ := getSchedule(ctx, client, scheduleName)
	if existing != nil {
		return fmt.Errorf("schedule %q already exists; delete it first or use a different name", scheduleName)
	}

	schedule := &SyncSchedule{
		Name:      scheduleName,
		Cron:      scheduleCron,
		Provider:  scheduleProvider,
		Table:     scheduleTable,
		Enabled:   scheduleEnabled,
		ScanAfter: scheduleScanAfter,
		Retry:     scheduleRetry,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		NextRun:   cronSched.Next(time.Now()),
	}

	if err := saveSchedule(ctx, client, schedule); err != nil {
		return fmt.Errorf("failed to save schedule: %w", err)
	}

	Success("Created schedule %q", scheduleName)
	fmt.Printf("  Provider: %s\n", scheduleProvider)
	fmt.Printf("  Cron: %s\n", scheduleCron)
	fmt.Printf("  Next run: %s\n", schedule.NextRun.Format(time.RFC3339))

	return nil
}

func runScheduleDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	name := args[0]

	client, err := createSnowflakeClientForSchedule()
	if err != nil {
		return fmt.Errorf("failed to connect to Snowflake: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Check if schedule exists
	existing, err := getSchedule(ctx, client, name)
	if err != nil {
		return fmt.Errorf("failed to get schedule: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("schedule %q not found", name)
	}

	if err := deleteSchedule(ctx, client, name); err != nil {
		return fmt.Errorf("failed to delete schedule: %w", err)
	}

	Success("Deleted schedule %q", name)
	return nil
}

func runScheduleShow(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	name := args[0]

	client, err := createSnowflakeClientForSchedule()
	if err != nil {
		return fmt.Errorf("failed to connect to Snowflake: %w", err)
	}
	defer func() { _ = client.Close() }()

	schedule, err := getSchedule(ctx, client, name)
	if err != nil {
		return fmt.Errorf("failed to get schedule: %w", err)
	}
	if schedule == nil {
		return fmt.Errorf("schedule %q not found", name)
	}

	if scheduleOutputJSON {
		return JSONOutput(schedule)
	}

	fmt.Printf("Schedule: %s\n", schedule.Name)
	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Provider:   %s\n", schedule.Provider)
	fmt.Printf("  Cron:       %s\n", schedule.Cron)
	fmt.Printf("  Enabled:    %t\n", schedule.Enabled)
	if schedule.Table != "" {
		fmt.Printf("  Tables:     %s\n", schedule.Table)
	}
	fmt.Printf("  Scan After: %t\n", schedule.ScanAfter)
	fmt.Printf("  Retry:      %d\n", schedule.Retry)
	fmt.Printf("  Created:    %s\n", schedule.CreatedAt.Format(time.RFC3339))
	fmt.Printf("  Updated:    %s\n", schedule.UpdatedAt.Format(time.RFC3339))
	if !schedule.LastRun.IsZero() {
		fmt.Printf("  Last Run:   %s (%s)\n", schedule.LastRun.Format(time.RFC3339), schedule.LastStatus)
	}
	if !schedule.NextRun.IsZero() {
		fmt.Printf("  Next Run:   %s\n", schedule.NextRun.Format(time.RFC3339))
	}

	return nil
}

func runScheduleDaemon(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	client, err := createSnowflakeClientForSchedule()
	if err != nil {
		return fmt.Errorf("failed to connect to Snowflake: %w", err)
	}
	defer func() { _ = client.Close() }()

	Info("Starting sync schedule daemon...")

	// Ensure schedule table exists
	if err := ensureScheduleTable(ctx, client); err != nil {
		return fmt.Errorf("failed to ensure schedule table: %w", err)
	}

	// Create cron scheduler
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	cronScheduler := cron.New(cron.WithParser(parser))

	// Load schedules from database
	schedules, err := listSchedules(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to load schedules: %w", err)
	}

	if len(schedules) == 0 {
		Warning("No schedules found. Create one with: cerebro sync schedule create")
		Info("Waiting for schedules to be created...")
	}

	registerSchedules := func(schedules []SyncSchedule) int {
		registered := 0
		for _, s := range schedules {
			if !s.Enabled {
				Info("Skipping disabled schedule: %s", s.Name)
				continue
			}
			schedule := s // capture for closure
			_, err := cronScheduler.AddFunc(schedule.Cron, func() {
				runScheduledSync(client, &schedule)
			})
			if err != nil {
				Warning("Failed to register schedule %s: %v", schedule.Name, err)
				continue
			}
			Info("Registered schedule: %s (%s) -> %s", schedule.Name, schedule.Cron, schedule.Provider)
			registered++
		}
		return registered
	}

	registerSchedules(schedules)
	activeSchedules := schedules

	cronScheduler.Start()
	Info("Scheduler running. Press Ctrl+C to stop.")

	// Periodically reload schedules from the database
	reloadTicker := time.NewTicker(60 * time.Second)
	defer reloadTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			goto shutdown
		case <-reloadTicker.C:
			updated, err := listSchedules(ctx, client)
			if err != nil {
				Warning("Failed to reload schedules: %v", err)
				continue
			}
			if schedulesEqual(activeSchedules, updated) {
				continue
			}
			// Stop existing cron entries and re-register
			cronCtx := cronScheduler.Stop()
			<-cronCtx.Done()
			cronScheduler = cron.New(cron.WithParser(parser))
			count := registerSchedules(updated)
			activeSchedules = updated
			cronScheduler.Start()
			Info("Reloaded schedules (%d active)", count)
		}
	}

shutdown:

	Info("Shutting down scheduler...")
	cronCtx := cronScheduler.Stop()
	select {
	case <-cronCtx.Done():
		Info("All jobs completed")
	case <-time.After(30 * time.Second):
		Warning("Shutdown timed out")
	}

	return nil
}

func runScheduledSync(client *snowflake.Client, schedule *SyncSchedule) {
	start := scheduleNowFn()
	persistCtx := context.Background()
	scheduleKey := strings.ToLower(strings.TrimSpace(schedule.Name))
	if scheduleKey == "" {
		scheduleKey = fmt.Sprintf("unnamed-%p", schedule)
	}

	if _, loaded := scheduledSyncInFlight.LoadOrStore(scheduleKey, struct{}{}); loaded {
		schedule.LastRun = start
		schedule.LastStatus = "skipped: previous run still active"
		schedule.UpdatedAt = scheduleNowFn().UTC()
		_ = saveScheduleFn(persistCtx, client, schedule)
		Warning("[%s] Skipping scheduled sync: previous run is still active", schedule.Name)
		slog.Default().Info("scheduled_sync_audit", "event", "skip_overlap", "schedule", schedule.Name, "provider", strings.ToLower(strings.TrimSpace(schedule.Provider)))
		return
	}
	defer scheduledSyncInFlight.Delete(scheduleKey)

	spec := parseScheduledSyncSpec(schedule.Table)
	jobTimeout := defaultScheduledSyncTimeout
	if timeoutSeconds, err := parseBoundedPositiveIntDirective(spec.SyncTimeoutSeconds, "sync_timeout_seconds", minScheduledTimeoutSeconds, maxScheduledTimeoutSeconds); err != nil {
		schedule.LastRun = start
		schedule.LastStatus = fmt.Sprintf("failed: %v", err)
		schedule.UpdatedAt = scheduleNowFn().UTC()
		_ = saveScheduleFn(persistCtx, client, schedule)
		Warning("[%s] Scheduled sync configuration invalid: %v", schedule.Name, err)
		slog.Default().Error("scheduled_sync_audit", "event", "config_error", "schedule", schedule.Name, "provider", strings.ToLower(strings.TrimSpace(schedule.Provider)), "error", err)
		return
	} else if timeoutSeconds > 0 {
		jobTimeout = time.Duration(timeoutSeconds) * time.Second
	}

	runCtx, cancel := context.WithTimeout(context.Background(), jobTimeout)
	defer cancel()

	Info("[%s] Starting scheduled sync for %s", schedule.Name, schedule.Provider)
	slog.Default().Info("scheduled_sync_audit", "event", "start", "schedule", schedule.Name, "provider", strings.ToLower(strings.TrimSpace(schedule.Provider)), "timeout_seconds", int(jobTimeout/time.Second))

	// Update last run time
	schedule.LastRun = start
	schedule.LastStatus = "running"
	_ = saveScheduleFn(persistCtx, client, schedule)

	// Build sync command args based on provider
	var syncErr error
	attemptLimit := schedule.Retry
	if attemptLimit <= 0 {
		attemptLimit = 1
	}
	attempts := 0
	for attempt := 1; attempt <= attemptLimit; attempt++ {
		attempts = attempt
		syncErr = executeScheduledSyncFn(runCtx, client, schedule)
		if syncErr == nil {
			break
		}
		if errors.Is(syncErr, context.DeadlineExceeded) || errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			break
		}
		if attempt < attemptLimit {
			Warning("[%s] Attempt %d failed, retrying: %v", schedule.Name, attempt, syncErr)
			scheduleSleepFn(time.Duration(attempt*5) * time.Second)
		}
	}

	// Update status
	duration := time.Since(start)
	if syncErr != nil {
		if errors.Is(syncErr, context.DeadlineExceeded) || errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			schedule.LastStatus = fmt.Sprintf("failed: timed out after %s", jobTimeout.Round(time.Second))
			Warning("[%s] Sync timed out after %s", schedule.Name, jobTimeout.Round(time.Second))
		} else {
			schedule.LastStatus = fmt.Sprintf("failed: %v", syncErr)
			Warning("[%s] Sync failed after %d attempts: %v", schedule.Name, attemptLimit, syncErr)
		}
	} else {
		schedule.LastStatus = fmt.Sprintf("success (%s)", duration.Round(time.Second))
		Success("[%s] Sync completed in %s", schedule.Name, duration.Round(time.Second))
	}

	// Calculate next run
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	if cronSched, err := parser.Parse(schedule.Cron); err == nil {
		schedule.NextRun = cronSched.Next(scheduleNowFn())
	}

	schedule.UpdatedAt = scheduleNowFn().UTC()
	_ = saveScheduleFn(persistCtx, client, schedule)

	attrs := []any{
		"event", "finish",
		"schedule", schedule.Name,
		"provider", strings.ToLower(strings.TrimSpace(schedule.Provider)),
		"status", schedule.LastStatus,
		"attempts", attempts,
		"duration_ms", duration.Milliseconds(),
	}
	if syncErr != nil {
		attrs = append(attrs, "error", syncErr.Error())
	}
	slog.Default().Info("scheduled_sync_audit", attrs...)
}

func executeScheduledSync(ctx context.Context, client *snowflake.Client, schedule *SyncSchedule) error {
	provider := strings.ToLower(strings.TrimSpace(schedule.Provider))
	if isNativeScheduleProvider(provider) && nativeSyncWorkerConfigured() {
		return enqueueScheduledNativeSyncFn(ctx, schedule)
	}

	switch provider {
	case "aws":
		return executeAWSSyncFn(ctx, client, schedule)
	case "gcp":
		return executeGCPSyncFn(ctx, client, schedule)
	case "azure":
		return executeAzureSyncFn(ctx, client, schedule)
	default:
		return executeProviderSyncFn(ctx, client, schedule)
	}
}

func isNativeScheduleProvider(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aws", "gcp", "azure":
		return true
	default:
		return false
	}
}

func nativeSyncWorkerConfigured() bool {
	return firstNonEmptyEnv("JOB_QUEUE_URL") != "" && firstNonEmptyEnv("JOB_TABLE_NAME") != ""
}

func enqueueScheduledNativeSync(ctx context.Context, schedule *SyncSchedule) error {
	spec := parseScheduledSyncSpec(schedule.Table)
	waitTimeout := defaultNativeWorkerWaitTimeout
	if timeoutSeconds, err := parseBoundedPositiveIntDirective(spec.WorkerWaitTimeoutSeconds, "worker_wait_timeout_seconds", minWorkerWaitTimeoutSeconds, maxWorkerWaitTimeoutSeconds); err != nil {
		return err
	} else if timeoutSeconds > 0 {
		waitTimeout = time.Duration(timeoutSeconds) * time.Second
	}

	queueURL := firstNonEmptyEnv("JOB_QUEUE_URL")
	tableName := firstNonEmptyEnv("JOB_TABLE_NAME")
	if queueURL == "" || tableName == "" {
		return fmt.Errorf("JOB_QUEUE_URL and JOB_TABLE_NAME are required for worker native sync")
	}

	region := firstNonEmptyEnv("JOB_REGION", "AWS_REGION")
	awsCfg, err := jobs.LoadAWSConfig(ctx, region)
	if err != nil {
		return fmt.Errorf("load worker queue AWS config: %w", err)
	}

	queue := jobs.NewSQSQueue(awsCfg, queueURL)
	store := jobs.NewDynamoStore(awsCfg, tableName)
	manager := jobs.NewManager(queue, store, slog.Default())

	job, err := manager.EnqueueNativeSync(ctx, jobs.NativeSyncPayload{
		Provider:     strings.ToLower(strings.TrimSpace(schedule.Provider)),
		Table:        schedule.Table,
		ScheduleName: schedule.Name,
	}, jobs.EnqueueOptions{
		GroupID:     schedule.Name,
		MaxAttempts: 1,
	})
	if err != nil {
		return fmt.Errorf("enqueue native sync job: %w", err)
	}

	Info("[%s] Native sync delegated to worker job %s", schedule.Name, job.ID)
	slog.Default().Info("scheduled_sync_audit", "event", "delegated_to_worker", "schedule", schedule.Name, "provider", strings.ToLower(strings.TrimSpace(schedule.Provider)), "job_id", job.ID, "wait_timeout_seconds", int(waitTimeout/time.Second))

	waitCtx, cancel := context.WithTimeout(ctx, waitTimeout)
	defer cancel()

	results, err := waitForScheduledJobsFn(waitCtx, manager, []string{job.ID}, 5*time.Second)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("wait for worker native sync job %s timed out after %s", job.ID, waitTimeout.Round(time.Second))
		}
		return fmt.Errorf("wait for worker native sync job %s: %w", job.ID, err)
	}
	if len(results) == 0 || results[0] == nil {
		return fmt.Errorf("worker native sync job %s returned no status", job.ID)
	}

	result := results[0]
	switch result.Status {
	case jobs.StatusSucceeded:
		parsed, parseErr := parseScheduledNativeSyncJobResult(result.Result)
		if parseErr != nil {
			Warning("[%s] Worker native sync job %s succeeded but result payload could not be parsed: %v", schedule.Name, result.ID, parseErr)
			return nil
		}
		if parsed != nil && len(parsed.FailedAdditionalProviders) > 0 {
			Warning("[%s] Worker native sync completed with %d additional provider failure(s)", schedule.Name, len(parsed.FailedAdditionalProviders))
			for _, failure := range parsed.FailedAdditionalProviders {
				Warning("[%s] Additional provider sync failed: provider=%s error=%s", schedule.Name, failure.Provider, failure.Error)
			}
		}
		return nil
	case jobs.StatusFailed:
		if strings.TrimSpace(result.Error) != "" {
			return fmt.Errorf("worker native sync failed: %s", result.Error)
		}
		return fmt.Errorf("worker native sync job %s failed", result.ID)
	default:
		return fmt.Errorf("worker native sync job %s finished with status %s", result.ID, result.Status)
	}
}

func waitForScheduledJobs(ctx context.Context, manager *jobs.Manager, jobIDs []string, pollInterval time.Duration) ([]*jobs.Job, error) {
	return manager.WaitForJobs(ctx, jobIDs, pollInterval)
}

type scheduledNativeSyncProviderFailure struct {
	Provider string `json:"provider"`
	Error    string `json:"error"`
}

type scheduledNativeSyncJobResult struct {
	Provider                  string                               `json:"provider"`
	Table                     string                               `json:"table"`
	ScheduleName              string                               `json:"schedule_name"`
	AdditionalProviders       []string                             `json:"additional_providers"`
	FailedAdditionalProviders []scheduledNativeSyncProviderFailure `json:"failed_additional_providers"`
}

func parseScheduledNativeSyncJobResult(raw string) (*scheduledNativeSyncJobResult, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	var result scheduledNativeSyncJobResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

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

	return runScheduledAWSNativeSyncFn(ctx, client, awsCfg, spec.TableFilter)
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

func runScheduledAWSNativeSync(ctx context.Context, client *snowflake.Client, awsCfg aws.Config, tableFilter []string) error {
	var opts []nativesync.EngineOption
	if len(tableFilter) > 0 {
		opts = append(opts, nativesync.WithTableFilter(tableFilter))
	}

	syncer := nativesync.NewSyncEngine(client, slog.Default(), opts...)
	_, err := syncer.SyncAllWithConfig(ctx, awsCfg)
	return err
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

func parseBoundedPositiveIntDirective(raw, name string, min, max int) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}

	value, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", name, err)
	}
	if value < min || value > max {
		return 0, fmt.Errorf("%s must be between %d and %d seconds", name, min, max)
	}
	return value, nil
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

func scheduledGCPAuthMethod(spec scheduledSyncSpec, authCfg *scheduledGCPAuthConfig) string {
	if strings.TrimSpace(spec.GCPImpersonateServiceAccount) != "" {
		return "service_account_impersonation"
	}
	if authCfg != nil && strings.TrimSpace(authCfg.CredentialsFile) != "" {
		return "credentials_file"
	}
	return "adc"
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

type scheduledGCPAuthConfig struct {
	Cleanup         func()
	Summary         string
	ClientOptions   []option.ClientOption
	CredentialsFile string
	CredentialsJSON []byte
}

func applyScheduledGCPAuth(spec scheduledSyncSpec) (*scheduledGCPAuthConfig, error) {
	authCfg := &scheduledGCPAuthConfig{Cleanup: func() {}}
	tempCredentialsFile := ""
	authCfg.Cleanup = func() {
		if tempCredentialsFile != "" {
			_ = os.Remove(tempCredentialsFile)
		}
	}

	credentialsFile := strings.TrimSpace(spec.GCPCredentialsFile)
	if credentialsFile != "" {
		if err := validateReadableFile(credentialsFile, "gcp_credentials_file"); err != nil {
			authCfg.Cleanup()
			return nil, err
		}
	}

	impersonateServiceAccount := strings.TrimSpace(spec.GCPImpersonateServiceAccount)
	delegates := uniqueNonEmpty(spec.GCPImpersonateDelegates)
	tokenLifetimeSeconds, err := parseBoundedPositiveIntDirective(spec.GCPImpersonateTokenLifetime, "gcp_impersonate_token_lifetime_seconds", 600, 43200)
	if err != nil {
		authCfg.Cleanup()
		return nil, err
	}

	if impersonateServiceAccount == "" {
		if len(delegates) > 0 {
			authCfg.Cleanup()
			return nil, fmt.Errorf("gcp_impersonate_delegates requires gcp_impersonate_service_account")
		}
		if tokenLifetimeSeconds > 0 {
			authCfg.Cleanup()
			return nil, fmt.Errorf("gcp_impersonate_token_lifetime_seconds requires gcp_impersonate_service_account")
		}
		if credentialsFile == "" {
			return authCfg, nil
		}

		credentialsData, readErr := os.ReadFile(credentialsFile)
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

	sourceData, err := os.ReadFile(sourcePath)
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

type gcpProjectPreflightSpec struct {
	ProjectID      string
	OrgID          string
	RunNativeSync  bool
	RunSecurity    bool
	SecurityFilter []string
	ClientOptions  []option.ClientOption
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
	if _, err := iter.Next(); err != nil && err != iterator.Done {
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
	if _, err := iter.Next(); err != nil && err != iterator.Done {
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
	opts := []nativesync.GCPEngineOption{nativesync.WithGCPProject(projectID)}
	if len(tableFilter) > 0 {
		opts = append(opts, nativesync.WithGCPTableFilter(tableFilter))
	}
	syncer := nativesync.NewGCPSyncEngine(client, slog.Default(), opts...)
	_, err := syncer.SyncAll(ctx)
	return err
}

func runScheduledGCPSecuritySync(ctx context.Context, client *snowflake.Client, projectID, orgID string, tableFilter []string) error {
	secOpts := []nativesync.GCPSecurityOption{}
	if len(tableFilter) > 0 {
		secOpts = append(secOpts, nativesync.WithGCPSecurityTableFilter(tableFilter))
	}
	securitySyncer := nativesync.NewGCPSecuritySync(client, slog.Default(), projectID, orgID, secOpts...)
	return securitySyncer.SyncAll(ctx)
}

func executeAzureSync(ctx context.Context, client *snowflake.Client, schedule *SyncSchedule) error {
	spec := parseScheduledSyncSpec(schedule.Table)
	subscriptionID := spec.AzureSubscription
	if subscriptionID == "" {
		subscriptionID = firstNonEmptyEnv("CEREBRO_AZURE_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID")
	}

	if subscriptionID != "" {
		Info("[%s] Executing Azure sync for subscription %s...", schedule.Name, subscriptionID)
	} else {
		Info("[%s] Executing Azure sync (auto-discovering subscription)...", schedule.Name)
	}
	if len(spec.TableFilter) > 0 {
		Info("[%s] Filtering Azure tables: %s", schedule.Name, strings.Join(spec.TableFilter, ", "))
	}

	opts := []nativesync.AzureEngineOption{}
	if subscriptionID != "" {
		opts = append(opts, nativesync.WithAzureSubscription(subscriptionID))
	}
	if len(spec.TableFilter) > 0 {
		opts = append(opts, nativesync.WithAzureTableFilter(spec.TableFilter))
	}

	syncer, err := nativesync.NewAzureSyncEngine(client, slog.Default(), opts...)
	if err != nil {
		return fmt.Errorf("create Azure sync engine: %w", err)
	}
	_, err = syncer.SyncAll(ctx)
	return err
}

func executeProviderSync(ctx context.Context, _ *snowflake.Client, schedule *SyncSchedule) error {
	providerName := strings.ToLower(strings.TrimSpace(schedule.Provider))
	Info("[%s] Executing provider sync for %s...", schedule.Name, providerName)

	application, err := newScheduleAppFn(ctx)
	if err != nil {
		return fmt.Errorf("initialize app for provider sync: %w", err)
	}
	defer func() {
		if closeErr := application.Close(); closeErr != nil {
			Warning("[%s] Failed to close app after provider sync: %v", schedule.Name, closeErr)
		}
	}()

	if application.Providers == nil {
		return fmt.Errorf("provider registry unavailable")
	}

	p, ok := application.Providers.Get(providerName)
	if !ok {
		metadata := providerregistry.ProviderMetadataFor(providerName)
		if providerregistry.IsProviderIncomplete(providerName) {
			return fmt.Errorf("provider %q is marked %s and cannot be scheduled", providerName, metadata.Maturity)
		}
		return fmt.Errorf("provider %q is not configured or not registered", providerName)
	}

	spec := parseScheduledSyncSpec(schedule.Table)
	opts := providerregistry.SyncOptions{FullSync: true, Tables: spec.TableFilter}

	_, err = p.Sync(ctx, opts)
	if err != nil {
		return fmt.Errorf("provider %q sync failed: %w", providerName, err)
	}

	return nil
}

type scheduledSyncSpec struct {
	TableFilter              []string
	GCPProjects              []string
	GCPOrg                   string
	AzureSubscription        string
	SyncTimeoutSeconds       string
	WorkerWaitTimeoutSeconds string
	GCPProjectTimeoutSeconds string

	AWSProfile               string
	AWSConfigFile            string
	AWSSharedCredentialsFile string
	AWSCredentialProcess     string
	AWSWebIdentityTokenFile  string
	AWSWebIdentityRoleARN    string
	AWSWebIdentitySession    string
	AWSRoleARN               string
	AWSRoleSession           string
	AWSRoleExternalID        string
	AWSRoleMFASerial         string
	AWSRoleMFAToken          string
	AWSRoleSourceIdentity    string
	AWSRoleDurationSeconds   string
	AWSRoleSessionTags       []string
	AWSRoleTransitiveTagKeys []string

	GCPCredentialsFile           string
	GCPImpersonateServiceAccount string
	GCPImpersonateDelegates      []string
	GCPImpersonateTokenLifetime  string
}

var gcpScheduledSecurityTableAliases = map[string]struct{}{
	"gcp_container_vulnerabilities":    {},
	"container_vulnerabilities":        {},
	"vulnerabilities":                  {},
	"gcp_artifact_registry_images":     {},
	"artifact_registry_images":         {},
	"artifact_images":                  {},
	"gcp_scc_findings":                 {},
	"scc_findings":                     {},
	"security_command_center_findings": {},
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

func validScheduleProviders() []string {
	set := map[string]struct{}{
		"aws":   {},
		"gcp":   {},
		"azure": {},
	}
	for _, name := range providerregistry.PublicProviderNames() {
		set[name] = struct{}{}
	}
	providers := make([]string, 0, len(set))
	for name := range set {
		providers = append(providers, name)
	}
	sort.Strings(providers)
	return providers
}

func parseScheduledSyncSpec(raw string) scheduledSyncSpec {
	parts := parseTableFilter(raw)
	spec := scheduledSyncSpec{TableFilter: make([]string, 0, len(parts))}

	for _, part := range parts {
		if value, ok := directiveValue(part, "sync_timeout_seconds"); ok {
			spec.SyncTimeoutSeconds = value
			continue
		}
		if value, ok := directiveValue(part, "worker_wait_timeout_seconds"); ok {
			spec.WorkerWaitTimeoutSeconds = value
			continue
		}
		if value, ok := directiveValue(part, "gcp_project_timeout_seconds"); ok {
			spec.GCPProjectTimeoutSeconds = value
			continue
		}
		if value, ok := directiveValue(part, "project"); ok {
			spec.GCPProjects = append(spec.GCPProjects, value)
			continue
		}
		if value, ok := directiveValue(part, "projects"); ok {
			spec.GCPProjects = append(spec.GCPProjects, splitDirectiveList(value)...)
			continue
		}
		if value, ok := directiveValue(part, "org"); ok {
			spec.GCPOrg = value
			continue
		}
		if value, ok := directiveValue(part, "organization"); ok {
			spec.GCPOrg = value
			continue
		}
		if value, ok := directiveValue(part, "subscription"); ok {
			spec.AzureSubscription = value
			continue
		}
		if value, ok := directiveValue(part, "aws_profile"); ok {
			spec.AWSProfile = value
			continue
		}
		if value, ok := directiveValue(part, "aws_config_file"); ok {
			spec.AWSConfigFile = value
			continue
		}
		if value, ok := directiveValue(part, "aws_shared_credentials_file"); ok {
			spec.AWSSharedCredentialsFile = value
			continue
		}
		if value, ok := directiveValue(part, "aws_credential_process"); ok {
			spec.AWSCredentialProcess = value
			continue
		}
		if value, ok := directiveValue(part, "aws_web_identity_token_file"); ok {
			spec.AWSWebIdentityTokenFile = value
			continue
		}
		if value, ok := directiveValue(part, "aws_web_identity_role_arn"); ok {
			spec.AWSWebIdentityRoleARN = value
			continue
		}
		if value, ok := directiveValue(part, "aws_web_identity_role_session_name"); ok {
			spec.AWSWebIdentitySession = value
			continue
		}
		if value, ok := directiveValue(part, "aws_role_arn"); ok {
			spec.AWSRoleARN = value
			continue
		}
		if value, ok := directiveValue(part, "aws_role_session_name"); ok {
			spec.AWSRoleSession = value
			continue
		}
		if value, ok := directiveValue(part, "aws_role_external_id"); ok {
			spec.AWSRoleExternalID = value
			continue
		}
		if value, ok := directiveValue(part, "aws_role_mfa_serial"); ok {
			spec.AWSRoleMFASerial = value
			continue
		}
		if value, ok := directiveValue(part, "aws_role_mfa_token"); ok {
			spec.AWSRoleMFAToken = value
			continue
		}
		if value, ok := directiveValue(part, "aws_role_source_identity"); ok {
			spec.AWSRoleSourceIdentity = value
			continue
		}
		if value, ok := directiveValue(part, "aws_role_duration_seconds"); ok {
			spec.AWSRoleDurationSeconds = value
			continue
		}
		if value, ok := directiveValue(part, "aws_role_session_tags"); ok {
			spec.AWSRoleSessionTags = append(spec.AWSRoleSessionTags, splitDirectiveList(value)...)
			continue
		}
		if value, ok := directiveValue(part, "aws_role_transitive_tag_keys"); ok {
			spec.AWSRoleTransitiveTagKeys = append(spec.AWSRoleTransitiveTagKeys, splitDirectiveList(value)...)
			continue
		}
		if value, ok := directiveValue(part, "gcp_credentials_file"); ok {
			spec.GCPCredentialsFile = value
			continue
		}
		if value, ok := directiveValue(part, "gcp_impersonate_service_account"); ok {
			spec.GCPImpersonateServiceAccount = value
			continue
		}
		if value, ok := directiveValue(part, "gcp_impersonate_delegates"); ok {
			spec.GCPImpersonateDelegates = append(spec.GCPImpersonateDelegates, splitDirectiveList(value)...)
			continue
		}
		if value, ok := directiveValue(part, "gcp_impersonate_token_lifetime_seconds"); ok {
			spec.GCPImpersonateTokenLifetime = value
			continue
		}
		spec.TableFilter = append(spec.TableFilter, part)
	}

	spec.GCPProjects = uniqueNonEmpty(spec.GCPProjects)
	spec.AWSRoleTransitiveTagKeys = uniqueNonEmpty(spec.AWSRoleTransitiveTagKeys)
	spec.GCPImpersonateDelegates = uniqueNonEmpty(spec.GCPImpersonateDelegates)
	if len(spec.TableFilter) == 0 {
		spec.TableFilter = nil
	}

	return spec
}

func directiveValue(raw, key string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	lower := strings.ToLower(trimmed)
	for _, sep := range []string{"=", ":"} {
		prefix := key + sep
		if strings.HasPrefix(lower, prefix) {
			value := strings.TrimSpace(trimmed[len(prefix):])
			if value == "" {
				return "", false
			}
			return value, true
		}
	}
	return "", false
}

func splitDirectiveList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '|' || r == ';'
	})
	if len(parts) == 0 {
		return nil
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func uniqueNonEmpty(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Database functions for schedule persistence

// schedulesEqual returns true if two schedule lists have the same config-relevant fields.
func schedulesEqual(a, b []SyncSchedule) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]SyncSchedule, len(a))
	for _, s := range a {
		m[s.Name] = s
	}
	for _, s := range b {
		prev, ok := m[s.Name]
		if !ok {
			return false
		}
		if prev.Cron != s.Cron || prev.Provider != s.Provider || prev.Table != s.Table || prev.Enabled != s.Enabled || prev.Retry != s.Retry || prev.ScanAfter != s.ScanAfter {
			return false
		}
	}
	return true
}

func ensureScheduleTable(ctx context.Context, client *snowflake.Client) error {
	query := `CREATE TABLE IF NOT EXISTS sync_schedules (
		name VARCHAR PRIMARY KEY,
		cron VARCHAR NOT NULL,
		provider VARCHAR NOT NULL,
		table_filter VARCHAR,
		enabled BOOLEAN DEFAULT TRUE,
		scan_after BOOLEAN DEFAULT FALSE,
		retry INTEGER DEFAULT 3,
		created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
		updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
		last_run TIMESTAMP_NTZ,
		last_status VARCHAR,
		next_run TIMESTAMP_NTZ
	)`
	_, err := client.Exec(ctx, query)
	return err
}

func listSchedules(ctx context.Context, client *snowflake.Client) ([]SyncSchedule, error) {
	if err := ensureScheduleTable(ctx, client); err != nil {
		return nil, err
	}

	query := `SELECT name, cron, provider, COALESCE(table_filter, ''), enabled, 
	          scan_after, retry, created_at, updated_at, 
	          COALESCE(last_run, '1970-01-01'::TIMESTAMP_NTZ), 
	          COALESCE(last_status, ''),
	          COALESCE(next_run, '1970-01-01'::TIMESTAMP_NTZ)
	          FROM sync_schedules ORDER BY name`

	result, err := client.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	var schedules []SyncSchedule
	for _, row := range result.Rows {
		s := SyncSchedule{
			Name:       getString(row, "NAME"),
			Cron:       getString(row, "CRON"),
			Provider:   getString(row, "PROVIDER"),
			Table:      getString(row, "COALESCE(TABLE_FILTER, '')"),
			Enabled:    getBool(row, "ENABLED"),
			ScanAfter:  getBool(row, "SCAN_AFTER"),
			Retry:      getInt(row, "RETRY"),
			CreatedAt:  getTime(row, "CREATED_AT"),
			UpdatedAt:  getTime(row, "UPDATED_AT"),
			LastRun:    getTime(row, "COALESCE(LAST_RUN, '1970-01-01'::TIMESTAMP_NTZ)"),
			LastStatus: getString(row, "COALESCE(LAST_STATUS, '')"),
			NextRun:    getTime(row, "COALESCE(NEXT_RUN, '1970-01-01'::TIMESTAMP_NTZ)"),
		}
		// Reset zero times
		if s.LastRun.Year() == 1970 {
			s.LastRun = time.Time{}
		}
		if s.NextRun.Year() == 1970 {
			s.NextRun = time.Time{}
		}
		schedules = append(schedules, s)
	}

	// Sort by name
	sort.Slice(schedules, func(i, j int) bool {
		return schedules[i].Name < schedules[j].Name
	})

	return schedules, nil
}

func getSchedule(ctx context.Context, client *snowflake.Client, name string) (*SyncSchedule, error) {
	if err := ensureScheduleTable(ctx, client); err != nil {
		return nil, err
	}

	query := `SELECT name, cron, provider, COALESCE(table_filter, ''), enabled, 
	          scan_after, retry, created_at, updated_at, 
	          COALESCE(last_run, '1970-01-01'::TIMESTAMP_NTZ), 
	          COALESCE(last_status, ''),
	          COALESCE(next_run, '1970-01-01'::TIMESTAMP_NTZ)
	          FROM sync_schedules WHERE name = ?`

	result, err := client.Query(ctx, query, name)
	if err != nil {
		return nil, err
	}

	if len(result.Rows) == 0 {
		return nil, nil
	}

	row := result.Rows[0]
	s := &SyncSchedule{
		Name:       getString(row, "NAME"),
		Cron:       getString(row, "CRON"),
		Provider:   getString(row, "PROVIDER"),
		Table:      getString(row, "COALESCE(TABLE_FILTER, '')"),
		Enabled:    getBool(row, "ENABLED"),
		ScanAfter:  getBool(row, "SCAN_AFTER"),
		Retry:      getInt(row, "RETRY"),
		CreatedAt:  getTime(row, "CREATED_AT"),
		UpdatedAt:  getTime(row, "UPDATED_AT"),
		LastRun:    getTime(row, "COALESCE(LAST_RUN, '1970-01-01'::TIMESTAMP_NTZ)"),
		LastStatus: getString(row, "COALESCE(LAST_STATUS, '')"),
		NextRun:    getTime(row, "COALESCE(NEXT_RUN, '1970-01-01'::TIMESTAMP_NTZ)"),
	}
	if s.LastRun.Year() == 1970 {
		s.LastRun = time.Time{}
	}
	if s.NextRun.Year() == 1970 {
		s.NextRun = time.Time{}
	}

	return s, nil
}

func saveSchedule(ctx context.Context, client *snowflake.Client, schedule *SyncSchedule) error {
	if err := ensureScheduleTable(ctx, client); err != nil {
		return err
	}

	query := `MERGE INTO sync_schedules t
	          USING (SELECT ? as name) s
	          ON t.name = s.name
	          WHEN MATCHED THEN UPDATE SET
	            cron = ?,
	            provider = ?,
	            table_filter = ?,
	            enabled = ?,
	            scan_after = ?,
	            retry = ?,
	            updated_at = ?,
	            last_run = ?,
	            last_status = ?,
	            next_run = ?
	          WHEN NOT MATCHED THEN INSERT 
	            (name, cron, provider, table_filter, enabled, scan_after, retry, created_at, updated_at, last_run, last_status, next_run)
	            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var lastRun, nextRun interface{}
	if !schedule.LastRun.IsZero() {
		lastRun = schedule.LastRun
	}
	if !schedule.NextRun.IsZero() {
		nextRun = schedule.NextRun
	}

	_, err := client.Exec(ctx, query,
		schedule.Name,
		schedule.Cron, schedule.Provider, schedule.Table, schedule.Enabled, schedule.ScanAfter, schedule.Retry,
		schedule.UpdatedAt, lastRun, schedule.LastStatus, nextRun,
		schedule.Name, schedule.Cron, schedule.Provider, schedule.Table, schedule.Enabled, schedule.ScanAfter, schedule.Retry,
		schedule.CreatedAt, schedule.UpdatedAt, lastRun, schedule.LastStatus, nextRun,
	)
	return err
}

func deleteSchedule(ctx context.Context, client *snowflake.Client, name string) error {
	query := `DELETE FROM sync_schedules WHERE name = ?`
	_, err := client.Exec(ctx, query, name)
	return err
}

func createSnowflakeClientForSchedule() (*snowflake.Client, error) {
	cfg := snowflake.DSNConfigFromEnv()
	if missing := cfg.MissingFields(); len(missing) > 0 {
		return nil, fmt.Errorf("snowflake not configured: set %s", strings.Join(missing, ", "))
	}

	return snowflake.NewClient(snowflake.ClientConfig{
		Account:    cfg.Account,
		User:       cfg.User,
		PrivateKey: cfg.PrivateKey,
		Database:   cfg.Database,
		Schema:     cfg.Schema,
		Warehouse:  cfg.Warehouse,
		Role:       cfg.Role,
	})
}

// Helper functions for extracting values from query results

func getString(row map[string]interface{}, key string) string {
	if v, ok := row[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getBool(row map[string]interface{}, key string) bool {
	if v, ok := row[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func getInt(row map[string]interface{}, key string) int {
	if v, ok := row[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
	}
	return 0
}

func getTime(row map[string]interface{}, key string) time.Time {
	if v, ok := row[key]; ok {
		if t, ok := v.(time.Time); ok {
			return t
		}
		if s, ok := v.(string); ok {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}
