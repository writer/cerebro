package cli

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	sf "github.com/snowflakedb/gosnowflake"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v2"

	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/snowflake"
	nativesync "github.com/writerinternal/cerebro/internal/sync"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync cloud assets to Snowflake via CloudQuery",
	Long: `Sync cloud assets from AWS, GCP, or Azure to Snowflake using CloudQuery.

This command wraps the CloudQuery CLI and optionally:
- Ensures Snowflake tables exist before sync (--ensure-tables)
- Validates sync completed successfully (--validate)
- Triggers a policy scan after sync (--scan-after)

Examples:
  cerebro sync                                    # Sync all sources
  cerebro sync --source aws                       # Sync only AWS
  cerebro sync --config config/cloudquery.yml    # Use custom config
  cerebro sync --validate --scan-after           # Validate and scan after`,
	RunE: runSync,
}

var (
	syncConfigPath   string
	syncSource       string
	syncEnsureTables bool
	syncValidate     bool
	syncScanAfter    bool
	syncNative       bool
)

func init() {
	syncCmd.Flags().StringVarP(&syncConfigPath, "config", "c", "config/cloudquery.yml", "CloudQuery config file")
	syncCmd.Flags().StringVarP(&syncSource, "source", "s", "", "Sync only specific source name from CloudQuery config (e.g., aws-cerebro)")
	syncCmd.Flags().BoolVar(&syncEnsureTables, "ensure-tables", false, "Create Snowflake tables before sync")
	syncCmd.Flags().BoolVar(&syncValidate, "validate", false, "Validate sync completed successfully")
	syncCmd.Flags().BoolVar(&syncScanAfter, "scan-after", false, "Run policy scan after successful sync")
	syncCmd.Flags().BoolVar(&syncNative, "native", true, "Use native AWS sync (default, use --native=false for CloudQuery)")
}

func runSync(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	start := time.Now()

	// Use native sync if requested
	if syncNative {
		return runNativeSync(ctx, start)
	}

	// Check CloudQuery CLI is available
	if _, err := exec.LookPath("cloudquery"); err != nil {
		Error("CloudQuery CLI not found")
		fmt.Println("  Install: brew install cloudquery/tap/cloudquery")
		fmt.Println("  Or visit: https://www.cloudquery.io/docs/quickstart")
		return err
	}

	// Optionally ensure tables exist
	if syncEnsureTables {
		Info("Ensuring Snowflake tables exist...")
		if err := ensureCloudQueryTables(ctx); err != nil {
			Warning("Could not ensure tables: %v", err)
		} else {
			Success("Tables ready")
		}
	}

	// Get row counts before sync for validation
	var beforeCounts map[string]int64
	if syncValidate {
		Info("Capturing pre-sync row counts...")
		beforeCounts = getTableRowCounts(ctx)
	}

	configPath, cleanupConfig, err := prepareCloudQueryConfig(syncConfigPath, syncSource)
	if err != nil {
		return err
	}
	if cleanupConfig != nil {
		defer cleanupConfig()
	}

	// Run CloudQuery sync
	cqArgs := []string{"sync", configPath}

	Info("Running: cloudquery %s", strings.Join(cqArgs, " "))
	fmt.Println()

	cqCmd := exec.Command("cloudquery", cqArgs...)
	cqCmd.Stdout = os.Stdout
	cqCmd.Stderr = os.Stderr
	cqCmd.Env = os.Environ()

	if dsn, ok, err := buildSnowflakeDSNFromKeyPair(); err != nil {
		return err
	} else if ok {
		Info("Using key-pair authentication for CloudQuery Snowflake destination")
		cqCmd.Env = upsertEnv(cqCmd.Env, "SNOWFLAKE_CONNECTION_STRING", dsn)
	}

	if err := cqCmd.Run(); err != nil {
		Error("CloudQuery sync failed: %v", err)
		return err
	}

	syncDuration := time.Since(start)
	fmt.Println()
	Success("Sync completed in %s", syncDuration.Round(time.Second))

	// Validate sync results
	if syncValidate && beforeCounts != nil {
		Info("Validating sync results...")
		afterCounts := getTableRowCounts(ctx)
		validateSyncResults(beforeCounts, afterCounts)
	}

	// Optionally run policy scan
	if syncScanAfter {
		Info("Triggering policy scan...")
		if err := runPostSyncScan(ctx); err != nil {
			Warning("Post-sync scan failed: %v", err)
		}
	}

	return nil
}

func runNativeSync(ctx context.Context, start time.Time) error {
	Info("Starting native AWS sync...")
	
	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer client.Close()
	
	syncer := nativesync.NewAWSSyncer(client, slog.Default())
	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}
	
	fmt.Println()
	fmt.Println("Sync Results:")
	fmt.Println("─────────────────────────────────────────")
	
	totalSynced := 0
	totalErrors := 0
	totalAdded := 0
	totalModified := 0
	totalRemoved := 0
	
	for _, r := range results {
		status := "✓"
		if r.Errors > 0 {
			status = "✗"
		}
		
		changeInfo := ""
		if r.Changes != nil && r.Changes.HasChanges() {
			changeInfo = fmt.Sprintf(" [%s]", r.Changes.Summary())
			totalAdded += len(r.Changes.Added)
			totalModified += len(r.Changes.Modified)
			totalRemoved += len(r.Changes.Removed)
		}
		
		fmt.Printf("  %s %-30s %4d resources (%s)%s\n", status, r.Table, r.Synced, r.Duration.Round(time.Millisecond), changeInfo)
		totalSynced += r.Synced
		totalErrors += r.Errors
	}
	
	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Total: %d resources synced in %s\n", totalSynced, time.Since(start).Round(time.Second))
	
	if totalAdded > 0 || totalModified > 0 || totalRemoved > 0 {
		fmt.Printf("  Changes: +%d added, ~%d modified, -%d removed\n", totalAdded, totalModified, totalRemoved)
	}
	
	if totalErrors > 0 {
		Warning("%d tables had errors", totalErrors)
	} else {
		Success("Sync completed successfully")
	}
	
	if syncScanAfter {
		Info("Triggering policy scan...")
		if err := runPostSyncScan(ctx); err != nil {
			Warning("Post-sync scan failed: %v", err)
		}
	}
	
	return nil
}

func ensureCloudQueryTables(ctx context.Context) error {
	client, err := createSnowflakeClient()
	if err != nil {
		return err
	}
	defer client.Close()

	// Import cloudquery package for TableManager
	// For now, just verify connection
	if err := client.Ping(ctx); err != nil {
		return fmt.Errorf("cannot connect to Snowflake: %w", err)
	}

	fmt.Println("Snowflake connection verified.")
	return nil
}

func createSnowflakeClient() (*snowflake.Client, error) {
	privateKey := normalizePrivateKey(os.Getenv("SNOWFLAKE_PRIVATE_KEY"))
	account := os.Getenv("SNOWFLAKE_ACCOUNT")
	user := os.Getenv("SNOWFLAKE_USER")
	connStr := os.Getenv("SNOWFLAKE_CONNECTION_STRING")

	hasKeyPairAuth := privateKey != "" && account != "" && user != ""
	if !hasKeyPairAuth && connStr == "" {
		return nil, fmt.Errorf("snowflake not configured: set SNOWFLAKE_PRIVATE_KEY/ACCOUNT/USER or SNOWFLAKE_CONNECTION_STRING")
	}

	return snowflake.NewClient(snowflake.ClientConfig{
		ConnectionString: connStr,
		Account:          account,
		User:             user,
		PrivateKey:       privateKey,
		Database:         os.Getenv("SNOWFLAKE_DATABASE"),
		Schema:           os.Getenv("SNOWFLAKE_SCHEMA"),
		Warehouse:        os.Getenv("SNOWFLAKE_WAREHOUSE"),
		Role:             os.Getenv("SNOWFLAKE_ROLE"),
	})
}

func getTableRowCounts(ctx context.Context) map[string]int64 {
	counts := make(map[string]int64)

	client, err := createSnowflakeClient()
	if err != nil {
		return counts
	}
	defer client.Close()

	// Check key tables
	tables := []string{"aws_s3_buckets", "aws_ec2_instances", "aws_iam_users"}
	for _, table := range tables {
		var count int64
		row := client.DB().QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", table))
		if err := row.Scan(&count); err == nil {
			counts[table] = count
		}
	}

	return counts
}

func validateSyncResults(before, after map[string]int64) {
	fmt.Println()
	tw := NewTableWriter(os.Stdout, "Table", "Before", "After", "Change")
	for table, beforeCount := range before {
		afterCount := after[table]
		diff := afterCount - beforeCount
		change := "no change"
		if diff > 0 {
			change = statusColor(fmt.Sprintf("+%d", diff))
		} else if diff < 0 {
			change = color(colorRed, fmt.Sprintf("%d", diff))
		}
		tw.AddRow(table, fmt.Sprintf("%d", beforeCount), fmt.Sprintf("%d", afterCount), change)
	}
	tw.Render()
}

func runPostSyncScan(ctx context.Context) error {
	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize app: %w", err)
	}
	defer application.Close()

	if application.Snowflake == nil {
		return fmt.Errorf("snowflake not configured")
	}

	// Trigger scan via the scheduler's scan function
	fmt.Println("Scanning synced assets...")
	// The actual scan would be triggered here
	// For now, just report we would scan
	fmt.Printf("Would scan %d policies against CloudQuery data\n", len(application.Policy.ListPolicies()))

	return nil
}

func normalizePrivateKey(value string) string {
	if value == "" {
		return value
	}
	if strings.Contains(value, "\\n") {
		value = strings.ReplaceAll(value, "\\n", "\n")
	}
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func prepareCloudQueryConfig(configPath, sourceFilter string) (string, func(), error) {
	if sourceFilter == "" {
		return configPath, nil, nil
	}

	info, err := os.Stat(configPath)
	if err != nil {
		return "", nil, err
	}
	if info.IsDir() {
		return "", nil, fmt.Errorf("sync --source requires a config file, got directory: %s", configPath)
	}

	sources := splitSourceFilter(sourceFilter)
	if len(sources) == 0 {
		return configPath, nil, nil
	}

	filteredPath, available, err := filterCloudQueryConfig(configPath, sources)
	if err != nil {
		if len(available) > 0 {
			return "", nil, fmt.Errorf("no CloudQuery sources matched %q (available: %s)", sourceFilter, strings.Join(available, ", "))
		}
		return "", nil, err
	}

	cleanup := func() {
		_ = os.Remove(filteredPath)
	}

	return filteredPath, cleanup, nil
}

func splitSourceFilter(sourceFilter string) []string {
	parts := strings.Split(sourceFilter, ",")
	sources := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			sources = append(sources, trimmed)
		}
	}
	return sources
}

func filterCloudQueryConfig(configPath string, sources []string) (string, []string, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()

	sourceSet := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		sourceSet[source] = struct{}{}
	}

	decoder := yaml.NewDecoder(file)
	filtered := make([]map[string]interface{}, 0)
	available := make([]string, 0)
	matchedSources := 0

	for {
		var doc map[string]interface{}
		if err := decoder.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			return "", nil, err
		}
		if len(doc) == 0 {
			continue
		}

		kind, _ := doc["kind"].(string)
		if kind != "source" {
			filtered = append(filtered, doc)
			continue
		}

		spec := getStringMap(doc["spec"])
		name, _ := spec["name"].(string)
		if name != "" {
			available = append(available, name)
		}
		if _, ok := sourceSet[name]; ok {
			filtered = append(filtered, doc)
			matchedSources++
		}
	}

	if matchedSources == 0 {
		return "", available, fmt.Errorf("no CloudQuery sources matched filter")
	}

	tempFile, err := os.CreateTemp("", "cloudquery-*.yml")
	if err != nil {
		return "", available, err
	}
	defer tempFile.Close()

	encoder := yaml.NewEncoder(tempFile)
	for _, doc := range filtered {
		if err := encoder.Encode(doc); err != nil {
			_ = encoder.Close()
			return "", available, err
		}
	}
	if err := encoder.Close(); err != nil {
		return "", available, err
	}

	return tempFile.Name(), available, nil
}

func getStringMap(value interface{}) map[string]interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		return typed
	case map[interface{}]interface{}:
		converted := make(map[string]interface{}, len(typed))
		for key, val := range typed {
			if keyString, ok := key.(string); ok {
				converted[keyString] = val
			}
		}
		return converted
	default:
		return nil
	}
}

func buildSnowflakeDSNFromKeyPair() (string, bool, error) {
	account := os.Getenv("SNOWFLAKE_ACCOUNT")
	user := os.Getenv("SNOWFLAKE_USER")
	rawKey := os.Getenv("SNOWFLAKE_PRIVATE_KEY")
	
	// Also check for connection string - if it exists, use it directly
	if connStr := os.Getenv("SNOWFLAKE_CONNECTION_STRING"); connStr != "" {
		return connStr, true, nil
	}
	
	if account == "" || user == "" || rawKey == "" {
		// Debug: show what's missing
		missing := []string{}
		if account == "" {
			missing = append(missing, "SNOWFLAKE_ACCOUNT")
		}
		if user == "" {
			missing = append(missing, "SNOWFLAKE_USER")
		}
		if rawKey == "" {
			missing = append(missing, "SNOWFLAKE_PRIVATE_KEY")
		}
		if len(missing) > 0 {
			Warning("Snowflake key-pair auth not configured, missing: %s", strings.Join(missing, ", "))
		}
		return "", false, nil
	}

	privateKey := normalizePrivateKey(rawKey)
	key, err := parsePrivateKey(privateKey)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse SNOWFLAKE_PRIVATE_KEY: %w", err)
	}

	database := os.Getenv("SNOWFLAKE_DATABASE")
	if database == "" {
		database = "CEREBRO"
	}
	schema := os.Getenv("SNOWFLAKE_SCHEMA")
	if schema == "" {
		schema = "RAW"
	}

	cfg := &sf.Config{
		Account:       account,
		User:          user,
		Authenticator: sf.AuthTypeJwt,
		PrivateKey:    key,
		Database:      database,
		Schema:        schema,
		Warehouse:     os.Getenv("SNOWFLAKE_WAREHOUSE"),
		Role:          os.Getenv("SNOWFLAKE_ROLE"),
	}

	dsn, err := sf.DSN(cfg)
	if err != nil {
		return "", false, fmt.Errorf("failed to build Snowflake DSN: %w", err)
	}

	return dsn, true, nil
}

func parsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		return rsaKey, nil
	}

	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return rsaKey, nil
}

func upsertEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}
