package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/app"
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Initialize Snowflake schema and tables",
	Long: `Bootstrap creates the Cerebro schema and all required tables in Snowflake.

This command should be run once when setting up a new Cerebro installation.
It is safe to run multiple times as it uses CREATE IF NOT EXISTS.

Tables created:
- findings, tickets, access_reviews, review_items
- attack_path_nodes, attack_path_edges, attack_paths
- agent_sessions, agent_messages, provider_syncs
- audit_log, webhooks, webhook_deliveries

Examples:
  cerebro bootstrap                    # Create schema and tables
  cerebro bootstrap --drop             # Drop and recreate (WARNING: data loss)`,
	RunE: runBootstrap,
}

var (
	bootstrapDrop bool
)

func init() {
	bootstrapCmd.Flags().BoolVar(&bootstrapDrop, "drop", false, "Drop existing schema before creating (WARNING: destroys all data)")
}

func runBootstrap(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize application: %w", err)
	}
	defer func() { _ = application.Close() }()

	if application.Snowflake == nil {
		Error("Snowflake not configured")
		fmt.Println("  Set SNOWFLAKE_PRIVATE_KEY, SNOWFLAKE_ACCOUNT, and SNOWFLAKE_USER environment variables")
		return fmt.Errorf("snowflake not configured")
	}

	if bootstrapDrop {
		Warning("Dropping existing schema (all data will be lost)...")
		if err := application.Snowflake.DropSchema(ctx); err != nil {
			Error("Failed to drop schema: %v", err)
			return err
		}
		Success("Schema dropped")
	}

	Info("Creating schema and tables...")
	if err := application.Snowflake.Bootstrap(ctx); err != nil {
		Error("Failed to bootstrap: %v", err)
		return err
	}

	Success("Bootstrap complete")
	fmt.Println()
	fmt.Println("Tables created:")
	tables := []string{
		"findings", "tickets", "access_reviews", "review_items",
		"attack_path_nodes", "attack_path_edges", "attack_paths",
		"agent_sessions", "agent_messages", "provider_syncs",
		"audit_log", "webhooks", "webhook_deliveries",
	}
	for _, t := range tables {
		fmt.Printf("  %s %s\n", color(colorGreen, "✓"), t)
	}

	return nil
}
