package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/app"
	providerregistry "github.com/writerinternal/cerebro/internal/providers"
	"github.com/writerinternal/cerebro/internal/snowflake"
	nativesync "github.com/writerinternal/cerebro/internal/sync"
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

	executeAWSSyncFn      = executeAWSSync
	executeGCPSyncFn      = executeGCPSync
	executeAzureSyncFn    = executeAzureSync
	executeProviderSyncFn = executeProviderSync

	runScheduledGCPNativeSyncFn   = runScheduledGCPNativeSync
	runScheduledGCPSecuritySyncFn = runScheduledGCPSecuritySync

	newScheduleAppFn = app.New
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
	ctx := context.Background()
	start := scheduleNowFn()

	Info("[%s] Starting scheduled sync for %s", schedule.Name, schedule.Provider)

	// Update last run time
	schedule.LastRun = start
	schedule.LastStatus = "running"
	_ = saveScheduleFn(ctx, client, schedule)

	// Build sync command args based on provider
	var syncErr error
	for attempt := 1; attempt <= schedule.Retry; attempt++ {
		syncErr = executeScheduledSyncFn(ctx, client, schedule)
		if syncErr == nil {
			break
		}
		if attempt < schedule.Retry {
			Warning("[%s] Attempt %d failed, retrying: %v", schedule.Name, attempt, syncErr)
			scheduleSleepFn(time.Duration(attempt*5) * time.Second)
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
		schedule.NextRun = cronSched.Next(scheduleNowFn())
	}

	schedule.UpdatedAt = scheduleNowFn().UTC()
	_ = saveScheduleFn(ctx, client, schedule)
}

func executeScheduledSync(ctx context.Context, client *snowflake.Client, schedule *SyncSchedule) error {
	switch strings.ToLower(strings.TrimSpace(schedule.Provider)) {
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

func executeAWSSync(ctx context.Context, client *snowflake.Client, schedule *SyncSchedule) error {
	Info("[%s] Executing AWS sync...", schedule.Name)

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	spec := parseScheduledSyncSpec(schedule.Table)

	var opts []nativesync.EngineOption
	if len(spec.TableFilter) > 0 {
		opts = append(opts, nativesync.WithTableFilter(spec.TableFilter))
	}

	syncer := nativesync.NewSyncEngine(client, slog.Default(), opts...)
	_, err = syncer.SyncAllWithConfig(ctx, awsCfg)
	return err
}

func executeGCPSync(ctx context.Context, client *snowflake.Client, schedule *SyncSchedule) error {
	spec := parseScheduledSyncSpec(schedule.Table)
	nativeFilter, securityFilter := splitGCPScheduledTableFilters(spec.TableFilter)
	runNativeSync := len(spec.TableFilter) == 0 || len(nativeFilter) > 0
	runSecuritySync := len(spec.TableFilter) == 0 || len(securityFilter) > 0

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
	if orgID != "" {
		orgProjects, err := nativesync.ListOrganizationProjects(ctx, orgID)
		if err != nil {
			return fmt.Errorf("discover GCP projects for org %q: %w", orgID, err)
		}
		projects = uniqueNonEmpty(append(projects, orgProjects...))
	}

	if len(projects) == 0 {
		return fmt.Errorf("scheduled GCP sync requires project scope; set project=<id>/projects=<id|id2>/org=<id> in --table or configure CEREBRO_GCP_PROJECT, GCP_PROJECT, or GOOGLE_CLOUD_PROJECT")
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
		if runNativeSync {
			if err := runScheduledGCPNativeSyncFn(ctx, client, projectID, nativeFilter); err != nil {
				errs = append(errs, fmt.Errorf("project %s native sync: %w", projectID, err))
			}
		}

		if runSecuritySync {
			if err := runScheduledGCPSecuritySyncFn(ctx, client, projectID, orgID, securityFilter); err != nil {
				errs = append(errs, fmt.Errorf("project %s security sync: %w", projectID, err))
			}
		}
	}

	return summarizeSyncRunErrors("scheduled GCP sync", errs)
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
	TableFilter       []string
	GCPProjects       []string
	GCPOrg            string
	AzureSubscription string
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
		spec.TableFilter = append(spec.TableFilter, part)
	}

	spec.GCPProjects = uniqueNonEmpty(spec.GCPProjects)
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
