package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/app"
	apiclient "github.com/writer/cerebro/internal/client"
	"github.com/writer/cerebro/internal/jobs"
	providerregistry "github.com/writer/cerebro/internal/providers"
	"github.com/writer/cerebro/internal/snowflake"
	nativesync "github.com/writer/cerebro/internal/sync"
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
	runScheduledAWSOrgSyncFn     = runScheduledAWSOrgSync

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

func executeProviderSync(ctx context.Context, _ *snowflake.Client, schedule *SyncSchedule) error {
	providerName := strings.ToLower(strings.TrimSpace(schedule.Provider))
	Info("[%s] Executing provider sync for %s...", schedule.Name, providerName)

	spec := parseScheduledSyncSpec(schedule.Table)
	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	if mode != cliExecutionModeDirect {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("[%s] API client configuration invalid; using direct mode: %v", schedule.Name, err)
		} else {
			fullSync := true
			result, err := apiClient.SyncProviderWithOptions(ctx, providerName, apiclient.ProviderSyncOptions{
				FullSync: &fullSync,
				Tables:   spec.TableFilter,
			})
			if err == nil {
				if result != nil && len(result.Errors) > 0 {
					return fmt.Errorf("provider %q sync reported errors: %s", providerName, strings.Join(result.Errors, "; "))
				}
				return nil
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("provider %q sync via api failed: %w", providerName, err)
			}
			Warning("[%s] API unavailable; using direct mode for provider sync: %v", schedule.Name, err)
		}
	}

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

	opts := providerregistry.SyncOptions{FullSync: true, Tables: spec.TableFilter}

	_, err = p.Sync(ctx, opts)
	if err != nil {
		return fmt.Errorf("provider %q sync failed: %w", providerName, err)
	}

	return nil
}

type scheduledSyncSpec struct {
	TableFilter                  []string
	GCPProjects                  []string
	GCPOrg                       string
	AzureSubscription            string
	AzureSubscriptions           []string
	AzureManagementGroup         string
	AzureSubscriptionConcurrency string
	SyncTimeoutSeconds           string
	WorkerWaitTimeoutSeconds     string
	GCPProjectTimeoutSeconds     string

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
	AWSOrg                   bool
	AWSOrgRole               string
	AWSOrgIncludeAccounts    []string
	AWSOrgExcludeAccounts    []string
	AWSOrgAccountConcurrency string

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
		if value, ok := directiveValue(part, "subscriptions"); ok {
			spec.AzureSubscriptions = append(spec.AzureSubscriptions, splitDirectiveList(value)...)
			continue
		}
		if value, ok := directiveValue(part, "azure_subscriptions"); ok {
			spec.AzureSubscriptions = append(spec.AzureSubscriptions, splitDirectiveList(value)...)
			continue
		}
		if value, ok := directiveValue(part, "management_group"); ok {
			spec.AzureManagementGroup = value
			continue
		}
		if value, ok := directiveValue(part, "management-group"); ok {
			spec.AzureManagementGroup = value
			continue
		}
		if value, ok := directiveValue(part, "azure_management_group"); ok {
			spec.AzureManagementGroup = value
			continue
		}
		if value, ok := directiveValue(part, "subscription_concurrency"); ok {
			spec.AzureSubscriptionConcurrency = value
			continue
		}
		if value, ok := directiveValue(part, "azure_subscription_concurrency"); ok {
			spec.AzureSubscriptionConcurrency = value
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
		if strings.EqualFold(strings.TrimSpace(part), "aws_org") {
			spec.AWSOrg = true
			continue
		}
		if value, ok := directiveValue(part, "aws_org"); ok {
			if parsed, parseOK := parseDirectiveBool(value); parseOK {
				spec.AWSOrg = parsed
				continue
			}
		}
		if value, ok := directiveValue(part, "aws_org_role"); ok {
			spec.AWSOrgRole = value
			continue
		}
		if value, ok := directiveValue(part, "aws_org_include_accounts"); ok {
			spec.AWSOrgIncludeAccounts = append(spec.AWSOrgIncludeAccounts, splitDirectiveList(value)...)
			continue
		}
		if value, ok := directiveValue(part, "aws_org_exclude_accounts"); ok {
			spec.AWSOrgExcludeAccounts = append(spec.AWSOrgExcludeAccounts, splitDirectiveList(value)...)
			continue
		}
		if value, ok := directiveValue(part, "aws_org_account_concurrency"); ok {
			spec.AWSOrgAccountConcurrency = value
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
	spec.AzureSubscriptions = uniqueNonEmpty(spec.AzureSubscriptions)
	spec.AWSRoleTransitiveTagKeys = uniqueNonEmpty(spec.AWSRoleTransitiveTagKeys)
	spec.AWSOrgIncludeAccounts = uniqueNonEmpty(spec.AWSOrgIncludeAccounts)
	spec.AWSOrgExcludeAccounts = uniqueNonEmpty(spec.AWSOrgExcludeAccounts)
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

func parseDirectiveBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on":
		return true, true
	case "0", "false", "no", "n", "off":
		return false, true
	default:
		return false, false
	}
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
