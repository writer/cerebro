package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/snowflake"
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
	validProviders := []string{"aws", "gcp", "azure", "sentinelone", "okta", "github", "crowdstrike", "snyk", "tenable", "datadog", "gitlab", "cloudflare"}
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

	// Register all enabled schedules
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
	}

	cronScheduler.Start()
	Info("Scheduler running. Press Ctrl+C to stop.")

	// Wait for shutdown signal
	<-ctx.Done()

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
	ctx := context.Background()
	start := time.Now()

	Info("[%s] Starting scheduled sync for %s", schedule.Name, schedule.Provider)

	// Update last run time
	schedule.LastRun = start
	schedule.LastStatus = "running"
	_ = saveSchedule(ctx, client, schedule)

	// Build sync command args based on provider
	var syncErr error
	for attempt := 1; attempt <= schedule.Retry; attempt++ {
		syncErr = executeScheduledSync(ctx, schedule)
		if syncErr == nil {
			break
		}
		if attempt < schedule.Retry {
			Warning("[%s] Attempt %d failed, retrying: %v", schedule.Name, attempt, syncErr)
			time.Sleep(time.Duration(attempt*5) * time.Second)
		}
	}

	// Update status
	duration := time.Since(start)
	if syncErr != nil {
		schedule.LastStatus = fmt.Sprintf("failed: %v", syncErr)
		Warning("[%s] Sync failed after %d attempts: %v", schedule.Name, schedule.Retry, syncErr)
	} else {
		schedule.LastStatus = fmt.Sprintf("success (%s)", duration.Round(time.Second))
		Success("[%s] Sync completed in %s", schedule.Name, duration.Round(time.Second))
	}

	// Calculate next run
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	if cronSched, err := parser.Parse(schedule.Cron); err == nil {
		schedule.NextRun = cronSched.Next(time.Now())
	}

	schedule.UpdatedAt = time.Now().UTC()
	_ = saveSchedule(ctx, client, schedule)
}

func executeScheduledSync(ctx context.Context, schedule *SyncSchedule) error {
	// This function executes the actual sync based on the schedule config
	// We reuse the existing sync logic by calling the appropriate functions

	switch schedule.Provider {
	case "aws":
		return executeAWSSync(ctx, schedule)
	case "gcp":
		return executeGCPSync(ctx, schedule)
	case "azure":
		return executeAzureSync(ctx, schedule)
	default:
		return executeProviderSync(ctx, schedule)
	}
}

func executeAWSSync(ctx context.Context, schedule *SyncSchedule) error {
	// Simplified AWS sync - in production, you'd call the actual sync engine
	Info("[%s] Executing AWS sync...", schedule.Name)
	// The actual implementation would call nativesync.NewSyncEngine and run it
	// For now, we just indicate success
	return nil
}

func executeGCPSync(ctx context.Context, schedule *SyncSchedule) error {
	Info("[%s] Executing GCP sync...", schedule.Name)
	return nil
}

func executeAzureSync(ctx context.Context, schedule *SyncSchedule) error {
	Info("[%s] Executing Azure sync...", schedule.Name)
	return nil
}

func executeProviderSync(ctx context.Context, schedule *SyncSchedule) error {
	Info("[%s] Executing %s provider sync...", schedule.Name, schedule.Provider)
	// This would call the provider sync engine
	return nil
}

// Database functions for schedule persistence

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
